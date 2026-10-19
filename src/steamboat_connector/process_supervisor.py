"""Own fixed Linux role children and their delegated cgroups."""

import json
import math
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .policy import validate_policy
from .resources import CgroupV2Controller, ResourceError
from .storage import (StorageError, atomic_write_private, read_private_json)
from .validation import json_bytes


ROLE_MODULES = {
    "host": "steamboat_connector.role_worker",
    "coordinator": "steamboat_connector.role_coordinator",
}
READY_TIMEOUT_SECONDS = 30.0
READY_LINE_MAX = 64
ROLE_CONFIG_MAX_BYTES = 65_536
STOP_GRACE_MAX_SECONDS = 15.0
SIGKILL = getattr(signal, "SIGKILL", 9)
_CHILD_ENV = {"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1"}


@dataclass
class _OwnedProcess:
    role: str
    process: object
    group: Path
    started_at: float
    starting: bool = True
    ready: bool = False
    stopping: bool = False
    stop_lock: object = field(default_factory=threading.Lock)
    reclaimed: bool = False
    stop_deadline: float = None
    term_deadline: float = None
    start_intent: object = None
    attached: bool = False
    escalation_lock: object = field(default_factory=threading.Lock)


@dataclass
class _StartIntent:
    cancelled: threading.Event = field(default_factory=threading.Event)
    cancel_deadline: float = None
    term_deadline: float = None
    group: Path = None
    finished: bool = False
    final_stop_requested: bool = False


@dataclass
class _StopWatchdog:
    role: str
    generation: object
    stop_deadline: float
    term_deadline: float
    wake: object = field(default_factory=threading.Event)
    thread: object = None


class ProcessRoleBackend:
    """Start only the fixed worker/coordinator modules under cgroup-v2."""

    def __init__(self, state_directory, cgroup, clock=time.monotonic):
        if not sys.platform.startswith("linux"):
            raise ResourceError("role process supervision requires Linux")
        self.state_directory = Path(state_directory)
        self.cgroup = cgroup or CgroupV2Controller()
        self.clock = clock
        self._lock = threading.RLock()
        self._owned = {}
        self._start_intents = {}
        self._watchdog_lock = threading.Lock()
        self._stop_watchdogs = {}

    @property
    def secure_runtime_ready(self):
        # Process readiness alone does not establish admission or artifact
        # integrity; parent wiring must combine those checks separately.
        return False

    def _config_path(self, role):
        return self.state_directory / f"{role}-runtime.json"

    @staticmethod
    def _encode_config(role, config, policy=None):
        document = {"version": 1, "role": role, "config": config}
        if policy is not None:
            document["policy"] = policy
        return json_bytes(document, maximum_bytes=ROLE_CONFIG_MAX_BYTES)

    def configure_role(self, role, config):
        """Persist bounded opaque role settings with fixed role metadata."""
        if role not in ROLE_MODULES or type(config) is not dict:
            return False
        try:
            encoded = self._encode_config(role, config)
        except (TypeError, ValueError):
            return False
        with self._lock:
            if role in self._owned or role in self._start_intents:
                return False
            try:
                atomic_write_private(self._config_path(role), encoded)
            except (OSError, StorageError):
                return False
            return True

    def _configured_role(self, role):
        try:
            document = read_private_json(self._config_path(role),
                                         maximum_size=ROLE_CONFIG_MAX_BYTES)
        except (OSError, StorageError):
            return None
        if (type(document) is not dict
                or set(document) not in ({"version", "role", "config"},
                                        {"version", "role", "config", "policy"})
                or type(document.get("version")) is not int
                or document["version"] != 1 or document.get("role") != role
                or type(document.get("config")) is not dict):
            return None
        return document["config"]

    @staticmethod
    def _read_ready(process, timeout, cancelled=None):
        stream = process.stdout
        if stream is None:
            return False
        selector = selectors.DefaultSelector()
        data = bytearray()
        deadline = time.monotonic() + timeout
        try:
            selector.register(stream, selectors.EVENT_READ)
            while len(data) <= READY_LINE_MAX:
                remaining = deadline - time.monotonic()
                if cancelled is not None and cancelled():
                    return False
                if remaining <= 0:
                    return False
                if not selector.select(min(remaining, 0.05 if cancelled else remaining)):
                    continue
                chunk = os.read(stream.fileno(), READY_LINE_MAX + 1 - len(data))
                if not chunk:
                    return False
                data.extend(chunk)
                newline = data.find(b"\n")
                if newline >= 0:
                    return newline == len(data) - 1 and data == b"READY\n"
            return False
        except (OSError, ValueError):
            return False
        finally:
            selector.close()
            try:
                stream.close()
            except OSError:
                pass

    @staticmethod
    def _events_populated(group):
        try:
            fields = {}
            for line in (Path(group) / "cgroup.events").read_text(
                    encoding="ascii").splitlines():
                parts = line.split()
                if (len(parts) != 2 or parts[0] not in ("populated", "frozen")
                        or parts[0] in fields or parts[1] not in ("0", "1")):
                    return False
                fields[parts[0]] = parts[1]
            return fields.get("populated") == "0"
        except (OSError, ValueError):
            return False

    def _wait_empty(self, owned, deadline):
        while True:
            if self._events_populated(owned.group):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(0.025, max(0.0, deadline - time.monotonic())))

    def _signal_tree(self, owned, sig):
        # cgroup.kill includes descendants even when the process-group leader
        # has exited. Fall back to the owned session group only if unavailable.
        kill_file = owned.group / "cgroup.kill"
        try:
            if sig == SIGKILL and kill_file.exists():
                kill_file.write_text("1", encoding="ascii")
                return
        except OSError:
            pass
        try:
            os.killpg(owned.process.pid, sig)
        except ProcessLookupError:
            pass
        except OSError:
            # Unknown signal state is surfaced by the subsequent empty check.
            pass

    @staticmethod
    def _cancelled(intent, cancel_event):
        return intent.cancelled.is_set() or (
            cancel_event is not None and cancel_event.is_set())

    def _forget_start_intent(self, role, intent):
        deadline = time.monotonic() + STOP_GRACE_MAX_SECONDS
        if not self._acquire_until(self._lock, deadline):
            return False
        try:
            if self._start_intents.get(role) is intent and intent.group is None:
                del self._start_intents[role]
                return True
            return False
        finally:
            self._lock.release()

    @staticmethod
    def _cancel_intent(intent, deadline=None, term_deadline=None):
        now = time.monotonic()
        requested_deadline = (deadline if deadline is not None else
                              now + STOP_GRACE_MAX_SECONDS)
        requested_term = (term_deadline if term_deadline is not None else
                          now + STOP_GRACE_MAX_SECONDS * 0.5)
        intent.cancel_deadline = (requested_deadline if intent.cancel_deadline is None else
                                  min(intent.cancel_deadline, requested_deadline))
        intent.term_deadline = (requested_term if intent.term_deadline is None else
                                min(intent.term_deadline, requested_term))
        intent.cancelled.set()

    def _register_stop_watchdog(self, role, generation, stop_deadline, term_deadline):
        with self._watchdog_lock:
            current = self._stop_watchdogs.get(role)
            if current is not None and current.generation is generation:
                current.stop_deadline = min(current.stop_deadline, stop_deadline)
                current.term_deadline = min(current.term_deadline, term_deadline,
                                            current.stop_deadline)
                current.wake.set()
                if current.thread.is_alive():
                    return True
                watchdog = current
            else:
                if current is not None and current.thread.is_alive():
                    return False
                watchdog = _StopWatchdog(role, generation, stop_deadline,
                                         min(term_deadline, stop_deadline))
                self._stop_watchdogs[role] = watchdog
            thread = threading.Thread(target=self._run_stop_watchdog,
                                      args=(watchdog,),
                                      name=f"participant-stop-{role}", daemon=True)
            watchdog.thread = thread
            self._stop_watchdogs[role] = watchdog
            try:
                thread.start()
            except RuntimeError:
                self._stop_watchdogs.pop(role, None)
                return False
            return True

    def _stop_watchdog_owner(self, watchdog):
        intent = watchdog.generation
        owned = self._owned.get(watchdog.role)
        if owned is not None and owned.start_intent is intent and not owned.reclaimed:
            return owned, False
        if intent.finished and intent.group is None:
            return None, True
        return None, False

    @staticmethod
    def _group_populated(group):
        try:
            values = {}
            for line in (Path(group) / "cgroup.events").read_text(
                    encoding="ascii").splitlines():
                name, value = line.split()
                if name == "populated" and name not in values and value in ("0", "1"):
                    values[name] = value
            if "populated" not in values:
                return None
            return values["populated"] == "1"
        except (OSError, ValueError):
            return None

    def _watchdog_kill(self, owned):
        """Escalate without lifecycle/global locks or a stale PID fallback."""
        with owned.escalation_lock:
            process = owned.process
            if process is None or owned.reclaimed or self._owned.get(owned.role) is not owned:
                return
            kill_file = owned.group / "cgroup.kill"
            if owned.attached:
                try:
                    if kill_file.exists():
                        kill_file.write_text("1", encoding="ascii")
                        return
                except OSError:
                    pass
            # Before cgroup attachment the session leader is the only available
            # safe target. Afterward, only use the pgid while the cgroup proves a
            # live member remains (preventing a reaped/reused PID signal).
            if process.poll() is None or (owned.attached and
                                          self._group_populated(owned.group) is True):
                try:
                    os.killpg(process.pid, SIGKILL)
                except OSError:
                    pass

    def _signal_owned_term(self, owned):
        with owned.escalation_lock:
            process = owned.process
            if process is None or owned.reclaimed or self._owned.get(owned.role) is not owned:
                return
            if (process.poll() is None
                    or self._group_populated(owned.group) is True):
                self._signal_tree(owned, signal.SIGTERM)

    def _run_stop_watchdog(self, watchdog):
        while True:
            with self._watchdog_lock:
                if self._stop_watchdogs.get(watchdog.role) is not watchdog:
                    return
                if watchdog.wake.is_set():
                    watchdog.wake.clear()
                term_deadline = watchdog.term_deadline
            owner, finished = self._stop_watchdog_owner(watchdog)
            if finished:
                with self._watchdog_lock:
                    if self._stop_watchdogs.get(watchdog.role) is watchdog:
                        self._stop_watchdogs.pop(watchdog.role, None)
                return
            now = time.monotonic()
            if now < term_deadline:
                watchdog.wake.wait(min(term_deadline - now, 0.05))
                continue
            if owner is not None:
                self._watchdog_kill(owner)
                if (owner.process is not None and owner.process.poll() is not None
                        and self._group_populated(owner.group) is False):
                    watchdog.wake.wait(0.05)
                else:
                    watchdog.wake.wait(0.05)
                continue
            # A canceled launch may not have published Popen yet. Keep this
            # bounded per-role watchdog alive until its intent resolves.
            watchdog.wake.wait(0.05)

    def _retire_stop_watchdog(self, role, generation):
        with self._watchdog_lock:
            watchdog = self._stop_watchdogs.get(role)
            if watchdog is None or watchdog.generation is not generation:
                return
            watchdog.wake.set()
        if watchdog.thread is not threading.current_thread():
            watchdog.thread.join(timeout=0.2)
        with self._watchdog_lock:
            if (self._stop_watchdogs.get(role) is watchdog
                    and not watchdog.thread.is_alive()):
                self._stop_watchdogs.pop(role, None)

    def start(self, role, policy, *, cancel_event=None):
        if (cancel_event is not None
                and not callable(getattr(cancel_event, "is_set", None))):
            return False
        if cancel_event is not None and cancel_event.is_set():
            return False
        if role not in ROLE_MODULES:
            return False
        if not sys.platform.startswith("linux"):
            return False
        try:
            policy = validate_policy(policy)
        except (OSError, ValueError, ResourceError, StorageError):
            return False

        # Claim the role before config I/O or cgroup creation so a duplicate
        # start cannot mutate its config or create an unowned process.
        with self._lock:
            if ((cancel_event is not None and cancel_event.is_set())
                    or role in self._owned or role in self._start_intents):
                return False
            with self._watchdog_lock:
                prior_watchdog = self._stop_watchdogs.get(role)
                if prior_watchdog is not None and prior_watchdog.thread.is_alive():
                    return False
                if prior_watchdog is not None:
                    self._stop_watchdogs.pop(role, None)
            intent = _StartIntent()
            self._start_intents[role] = intent

        group = None
        read_fd = write_fd = -1
        process = None
        owned = None
        try:
            if self._cancelled(intent, cancel_event):
                return False
            role_config = self._configured_role(role)
            if role_config is None or self._cancelled(intent, cancel_event):
                return False
            atomic_write_private(self._config_path(role),
                                 self._encode_config(role, role_config, policy))
            if self._cancelled(intent, cancel_event):
                return False
            group = self.cgroup.create_group(
                f"participant-{role}-{uuid.uuid4().hex[:12]}", policy, role)
            intent.group = Path(group)
            if self._cancelled(intent, cancel_event):
                return False
            read_fd, write_fd = os.pipe()
            bootstrap = Path(__file__).with_name("process_bootstrap.py").resolve()
            command = [sys.executable, "-I", "-S", os.fspath(bootstrap), role,
                       os.fspath(self._config_path(role)), str(read_fd)]
            # Spawn and publish as one ownership transition. stop() either
            # cancels the intent first or observes the published process.
            with self._lock:
                if (self._cancelled(intent, cancel_event)
                        or self._start_intents.get(role) is not intent):
                    return False
                owned = _OwnedProcess(role, None, Path(group), self.clock(),
                                      start_intent=intent)
                self._owned[role] = owned
                if self._cancelled(intent, cancel_event):
                    del self._owned[role]
                    owned = None
                    return False
                try:
                    process = subprocess.Popen(
                        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, close_fds=True, pass_fds=(read_fd,),
                        start_new_session=True, env=dict(_CHILD_ENV), bufsize=0)
                except BaseException:
                    if self._owned.get(role) is owned:
                        del self._owned[role]
                    owned = None
                    raise
                owned.process = process
                if intent.cancelled.is_set() or (
                        cancel_event is not None and cancel_event.is_set()):
                    self._cancel_intent(intent)
                    self._mark_stopping(owned, intent.cancel_deadline,
                                        intent.term_deadline)
                    if time.monotonic() >= intent.term_deadline:
                        self._watchdog_kill(owned)
                    else:
                        self._signal_owned_term(owned)
            os.close(read_fd)
            read_fd = -1
            self.cgroup.attach_child(group, process)
            owned.attached = True
            with self._lock:
                cancelled = self._cancelled(intent, cancel_event) or owned.stopping
                if not cancelled and os.write(write_fd, b"R") != 1:
                    raise OSError("startup gate release failed")
            if cancelled:
                self._cancel_intent(intent)
                if not intent.final_stop_requested:
                    self._stop_owned(owned, STOP_GRACE_MAX_SECONDS)
                return False
            os.close(write_fd)
            write_fd = -1
            ready = self._read_ready(
                process, READY_TIMEOUT_SECONDS,
                cancelled=lambda: self._cancelled(intent, cancel_event)
                or owned.stopping)
            with self._lock:
                current = self._owned.get(role)
                cancelled_before_ready = (current is not owned or owned.stopping
                                          or self._cancelled(intent, cancel_event))
                if not cancelled_before_ready:
                    owned.starting = False
                    owned.ready = bool(ready and process.poll() is None)
            if cancelled_before_ready:
                self._cancel_intent(intent)
                if not intent.final_stop_requested:
                    self._stop_owned(owned, STOP_GRACE_MAX_SECONDS)
                return False
            if not owned.ready:
                self._cancel_intent(intent)
                self._stop_owned(owned, STOP_GRACE_MAX_SECONDS)
                return False
            return True
        except Exception as error:
            self._cancel_intent(intent)
            if group is None:
                group = getattr(error, "retained_group", None)
                if group is not None:
                    intent.group = Path(group)
            if owned is not None and not intent.final_stop_requested:
                self._stop_owned(owned, STOP_GRACE_MAX_SECONDS)
            elif owned is None and process is not None:
                try:
                    os.killpg(process.pid, SIGKILL)
                except OSError:
                    pass
                try:
                    process.wait(timeout=1)
                except Exception:
                    pass
            return False
        finally:
            if read_fd >= 0:
                try:
                    os.close(read_fd)
                except OSError:
                    pass
            if write_fd >= 0:
                try:
                    os.close(write_fd)
                except OSError:
                    pass
            intent.finished = True
            if owned is not None:
                # Published process ownership now carries the cgroup path,
                # whether it was reclaimed or remains live/uncertain.
                intent.group = None
            elif group is not None and owned is None:
                if self._remove_empty_group(group):
                    intent.group = None
            self._forget_start_intent(role, intent)

    def _remove_empty_group(self, group):
        # False means populated/unknown state or failed disposal; callers must
        # retain ownership and the resource reservation in either case.
        if not self._events_populated(group):
            return False
        remover = getattr(self.cgroup, "remove_empty_group", None)
        try:
            if callable(remover):
                return remover(group) is True
            Path(group).rmdir()
            return not Path(group).exists()
        except OSError:
            return False

    @staticmethod
    def _acquire_until(lock, deadline):
        return lock.acquire(timeout=max(0.0, deadline - time.monotonic()))

    @staticmethod
    def _mark_stopping(owned, deadline=None, term_deadline=None):
        # Cleanup caps are immutable once established, except that a later
        # request may tighten them. Drain cutoffs must never be passed here.
        if deadline is not None:
            owned.stop_deadline = (deadline if owned.stop_deadline is None else
                                   min(owned.stop_deadline, deadline))
        if term_deadline is not None:
            owned.term_deadline = (term_deadline if owned.term_deadline is None else
                                   min(owned.term_deadline, term_deadline))
        owned.stopping = True
        owned.ready = False

    @staticmethod
    def _bounded_grace(grace_seconds):
        if type(grace_seconds) not in (int, float):
            return None
        grace = float(grace_seconds)
        if not math.isfinite(grace) or grace < 0:
            return None
        return min(STOP_GRACE_MAX_SECONDS, grace)

    def _stop_many(self, entries, deadline, term_deadline, *, send_term=True):
        results = {}
        acquired = []
        for role, owned in entries:
            stop_deadline = owned.stop_deadline if owned.stop_deadline is not None else deadline
            if not self._acquire_until(owned.stop_lock, min(deadline, stop_deadline)):
                results[role] = False
                continue
            acquired.append((role, owned))

        try:
            active = []
            if not self._acquire_until(self._lock, deadline):
                for role, owned in acquired:
                    intent = self._start_intents.get(role)
                    if intent is not None:
                        self._cancel_intent(intent, deadline, term_deadline)
                    current = self._owned.get(role)
                    if current is owned:
                        owned.stopping = True
                        owned.ready = False
                        if owned.process is not None:
                            self._signal_owned_term(owned)
                    results[role] = False
                return results
            try:
                for role, owned in acquired:
                    if self._owned.get(role) is not owned:
                        results[role] = owned.reclaimed
                        continue
                    stop_deadline = owned.stop_deadline
                    if stop_deadline is None:
                        self._mark_stopping(owned, deadline, term_deadline)
                    else:
                        self._mark_stopping(owned)
                    active.append((role, owned))
            finally:
                self._lock.release()

            # Signal every independent process before waiting on any one of them.
            if send_term:
                for _, owned in active:
                    self._signal_owned_term(owned)
            for _, owned in active:
                own_term_deadline = (owned.term_deadline if owned.term_deadline is not None
                                     else term_deadline)
                remaining = max(0.0, min(deadline, own_term_deadline) - time.monotonic())
                try:
                    owned.process.wait(timeout=remaining)
                except (subprocess.TimeoutExpired, TimeoutError, OSError):
                    pass

            # Escalate every still-populated tree before beginning final waits.
            for _, owned in active:
                if (not self._events_populated(owned.group)
                        or owned.process.poll() is None):
                    self._watchdog_kill(owned)

            for role, owned in active:
                own_deadline = min(deadline, owned.stop_deadline or deadline)
                empty = self._wait_empty(owned, own_deadline)
                remaining = max(0.0, own_deadline - time.monotonic())
                try:
                    owned.process.wait(timeout=remaining)
                except (subprocess.TimeoutExpired, TimeoutError, OSError):
                    empty = False
                reclaimed = empty and owned.process.poll() is not None
                if reclaimed:
                    if not self._acquire_until(self._lock, own_deadline):
                        reclaimed = False
                    else:
                        try:
                            with owned.escalation_lock:
                                # Recheck while excluding watchdog signals so a
                                # stale PID cannot be targeted after reaping.
                                reclaimed = (self._owned.get(role) is owned
                                             and owned.process.poll() is not None
                                             and self._events_populated(owned.group))
                                if reclaimed and self._remove_empty_group(owned.group):
                                    del self._owned[role]
                                    owned.reclaimed = True
                                else:
                                    reclaimed = owned.reclaimed
                        finally:
                            self._lock.release()
                if reclaimed:
                    self._retire_stop_watchdog(role, owned.start_intent)
                    results[role] = True
                else:
                    results[role] = False
            return results
        finally:
            for _, owned in acquired:
                owned.stop_lock.release()

    def _stop_owned(self, owned, grace_seconds):
        grace = self._bounded_grace(grace_seconds)
        if grace is None:
            return False
        started = time.monotonic()
        requested_deadline = started + grace
        deadline = (requested_deadline if owned.stop_deadline is None else
                    min(owned.stop_deadline, requested_deadline))
        requested_term_deadline = min(deadline, started + grace * 0.5)
        term_deadline = (requested_term_deadline if owned.term_deadline is None else
                         min(owned.term_deadline, requested_term_deadline))
        self._mark_stopping(owned, deadline, term_deadline)
        return self._stop_many([(owned.role, owned)], deadline,
                               term_deadline).get(owned.role, False)

    def stop(self, roles, grace_seconds):
        grace = self._bounded_grace(grace_seconds)
        if grace is None:
            return {role: False for role in roles}
        started = time.monotonic()
        deadline = started + grace
        term_deadline = started + grace * 0.5
        results = {}
        entries = []
        cleanup_intents = []
        if not self._acquire_until(self._lock, deadline):
            # Popen or another ownership transition may be in progress. Cancel
            # intents without waiting; retain reservations until that transition
            # publishes and the caller can perform final bounded reclamation.
            for role in roles:
                intent = self._start_intents.get(role)
                if intent is not None:
                    self._cancel_intent(intent, deadline, term_deadline)
                owned = self._owned.get(role)
                if owned is not None:
                    self._mark_stopping(owned, deadline, term_deadline)
                    if owned.process is not None:
                        self._signal_owned_term(owned)
                results[role] = False
            return results
        try:
            for role in roles:
                if role not in ROLE_MODULES:
                    results[role] = False
                    continue
                intent = self._start_intents.get(role)
                if intent is not None:
                    self._cancel_intent(intent, deadline, term_deadline)
                owned = self._owned.get(role)
                if owned is None:
                    # A launch intent may still be in cgroup creation or Popen.
                    if intent is None:
                        results[role] = True
                    elif intent.finished and intent.group is not None:
                        cleanup_intents.append((role, intent))
                        results[role] = False
                    elif intent.finished and intent.group is None:
                        # A previous cleanup removed the cgroup but could not
                        # reacquire the ledger lock to forget its intent.
                        del self._start_intents[role]
                        results[role] = True
                    else:
                        results[role] = False
                    continue
                self._mark_stopping(owned, deadline, term_deadline)
                entries.append((role, owned))
        finally:
            self._lock.release()

        for role, intent in cleanup_intents:
            if self._remove_empty_group(intent.group):
                intent.group = None
                if self._acquire_until(self._lock, deadline):
                    try:
                        if (self._start_intents.get(role) is intent
                                and intent.finished and intent.group is None):
                            del self._start_intents[role]
                            results[role] = True
                    finally:
                        self._lock.release()

        stopped = self._stop_many(entries, deadline, term_deadline)
        results.update(stopped)
        return results

    def request_stop(self, roles):
        """Fence starts, send TERM, and install bounded independent escalation."""
        results = {}
        for role in roles:
            if role not in ROLE_MODULES:
                results[role] = False
                continue
            # These dictionary lookups and event/set-flag writes are nonblocking;
            # ownership itself remains reconciled by stop() on the lifecycle queue.
            intent = self._start_intents.get(role)
            now = time.monotonic()
            requested_deadline = now + STOP_GRACE_MAX_SECONDS
            requested_term = now + STOP_GRACE_MAX_SECONDS * 0.5
            if intent is not None:
                intent.final_stop_requested = True
                self._cancel_intent(intent, requested_deadline, requested_term)
            owned = self._owned.get(role)
            generation = intent
            if owned is not None:
                generation = owned.start_intent
                deadline = requested_deadline
                term_deadline = requested_term
                if intent is not None:
                    deadline = min(deadline, intent.cancel_deadline)
                    term_deadline = min(term_deadline, intent.term_deadline)
                self._mark_stopping(owned, deadline, term_deadline)
                deadline = owned.stop_deadline
                term_deadline = owned.term_deadline
            elif intent is not None:
                deadline = intent.cancel_deadline
                term_deadline = intent.term_deadline
            else:
                deadline = term_deadline = None
            if generation is not None:
                if owned is not None:
                    self._signal_owned_term(owned)
                self._register_stop_watchdog(role, generation, deadline, term_deadline)
            results[role] = intent is not None or owned is not None
        return results

    def request_drain(self, roles):
        """Fence starts and disable admission without terminating live roles.

        This hook is intentionally nonblocking for management pre-ack use;
        full runtime drain and cleanup remain on the lifecycle queue.
        """
        results = {}
        for role in roles:
            if role not in ROLE_MODULES:
                results[role] = False
                continue
            intent = self._start_intents.get(role)
            if intent is not None:
                now = time.monotonic()
                self._cancel_intent(intent, now + STOP_GRACE_MAX_SECONDS,
                                    now + STOP_GRACE_MAX_SECONDS * 0.5)
            owned = self._owned.get(role)
            if owned is not None:
                # Admission is disabled while existing work drains. Do not
                # signal a healthy loaded process from the pre-ack hook.
                owned.stopping = True
                owned.ready = False
            results[role] = intent is not None or owned is not None
        return results

    def drain(self, roles, deadline, cancel_event):
        if not self._acquire_until(self._lock, deadline):
            for role in roles:
                intent = self._start_intents.get(role)
                if intent is not None:
                    now = time.monotonic()
                    self._cancel_intent(intent, now + STOP_GRACE_MAX_SECONDS,
                                        now + STOP_GRACE_MAX_SECONDS * 0.5)
            return {"drained": False, "reclaimed": False}
        try:
            live = [role for role in roles
                    if role in self._owned or role in self._start_intents]
            for role in live:
                intent = self._start_intents.get(role)
                if intent is not None:
                    now = time.monotonic()
                    self._cancel_intent(
                        intent, now + STOP_GRACE_MAX_SECONDS,
                        now + STOP_GRACE_MAX_SECONDS * 0.5)
                owned = self._owned.get(role)
                if owned is not None:
                    owned.ready = False
                    # Drain is an admission/runtime cutoff, not a process
                    # termination deadline. A later stop establishes its own
                    # bounded cleanup cap.
                    owned.stopping = True
        finally:
            self._lock.release()
        remaining = max(0.0, deadline - self.clock())
        if cancel_event.wait(min(remaining, 0.01)):
            return {"drained": False, "reclaimed": False}
        # These fixed services have no external request queue API yet. A live
        # process cannot be represented as drained until the runtime is wired.
        if live:
            return {"drained": False, "reclaimed": False}
        return {"drained": True, "reclaimed": True}

    def status(self):
        with self._lock:
            result = {role: {"owned": True, "ready": item.ready,
                            "starting": item.starting, "stopping": item.stopping,
                            "pid": item.process.pid if item.process is not None else None,
                            "cgroup_populated": not self._events_populated(item.group)}
                      for role, item in sorted(self._owned.items())}
            for role, intent in sorted(self._start_intents.items()):
                if role in result:
                    continue
                result[role] = {
                    "owned": True, "ready": False,
                    "starting": not intent.finished,
                    "stopping": intent.cancelled.is_set(), "pid": None,
                    "cgroup_populated": (None if intent.group is None else
                                         not self._events_populated(intent.group)),
                    "cleanup_pending": intent.group is not None,
                }
            return result
