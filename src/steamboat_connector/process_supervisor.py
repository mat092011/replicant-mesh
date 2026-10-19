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


@dataclass
class _StartIntent:
    cancelled: threading.Event = field(default_factory=threading.Event)


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
    def _read_ready(process, timeout):
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
                if remaining <= 0 or not selector.select(remaining):
                    return False
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
            if sig == signal.SIGKILL and kill_file.exists():
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
        with self._lock:
            if self._start_intents.get(role) is intent:
                del self._start_intents[role]

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
                owned = _OwnedProcess(role, None, Path(group), self.clock())
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
            os.close(read_fd)
            read_fd = -1
            if self._cancelled(intent, cancel_event):
                self._stop_owned(owned, STOP_GRACE_MAX_SECONDS)
                return False
            self.cgroup.attach_child(group, process)
            with self._lock:
                cancelled = self._cancelled(intent, cancel_event) or owned.stopping
                if not cancelled and os.write(write_fd, b"R") != 1:
                    raise OSError("startup gate release failed")
            if cancelled:
                self._stop_owned(owned, STOP_GRACE_MAX_SECONDS)
                return False
            os.close(write_fd)
            write_fd = -1
            ready = self._read_ready(process, READY_TIMEOUT_SECONDS)
            with self._lock:
                current = self._owned.get(role)
                cancelled_before_ready = (current is not owned or owned.stopping
                                          or self._cancelled(intent, cancel_event))
                if not cancelled_before_ready:
                    owned.starting = False
                    owned.ready = bool(ready and process.poll() is None)
            if cancelled_before_ready:
                intent.cancelled.set()
                self._stop_owned(owned, STOP_GRACE_MAX_SECONDS)
                return False
            if not owned.ready:
                intent.cancelled.set()
                self._stop_owned(owned, STOP_GRACE_MAX_SECONDS)
                return False
            return True
        except Exception:
            intent.cancelled.set()
            if owned is not None:
                self._stop_owned(owned, STOP_GRACE_MAX_SECONDS)
            elif process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
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
            self._forget_start_intent(role, intent)
            if group is not None and owned is None:
                self._remove_empty_group(group)

    @staticmethod
    def _remove_empty_group(group):
        if not ProcessRoleBackend._events_populated(group):
            try:
                Path(group).rmdir()
            except OSError:
                pass

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
            remaining = max(0.0, deadline - time.monotonic())
            if not owned.stop_lock.acquire(timeout=remaining):
                results[role] = False
                continue
            acquired.append((role, owned))

        try:
            active = []
            with self._lock:
                for role, owned in acquired:
                    if self._owned.get(role) is not owned:
                        results[role] = owned.reclaimed
                        continue
                    owned.stopping = True
                    owned.ready = False
                    active.append((role, owned))

            # Signal every independent process before waiting on any one of them.
            if send_term:
                for _, owned in active:
                    self._signal_tree(owned, signal.SIGTERM)
            for _, owned in active:
                remaining = max(0.0, term_deadline - time.monotonic())
                try:
                    owned.process.wait(timeout=remaining)
                except (subprocess.TimeoutExpired, TimeoutError, OSError):
                    pass

            # Escalate every still-populated tree before beginning final waits.
            for _, owned in active:
                if (not self._events_populated(owned.group)
                        or owned.process.poll() is None):
                    self._signal_tree(owned, signal.SIGKILL)

            for role, owned in active:
                empty = self._wait_empty(owned, deadline)
                remaining = max(0.0, deadline - time.monotonic())
                try:
                    owned.process.wait(timeout=remaining)
                except (subprocess.TimeoutExpired, TimeoutError, OSError):
                    empty = False
                reclaimed = empty and owned.process.poll() is not None
                if reclaimed:
                    with self._lock:
                        if self._owned.get(role) is owned:
                            del self._owned[role]
                        owned.reclaimed = True
                    self._remove_empty_group(owned.group)
                results[role] = reclaimed
            return results
        finally:
            for _, owned in acquired:
                owned.stop_lock.release()

    def _stop_owned(self, owned, grace_seconds):
        grace = self._bounded_grace(grace_seconds)
        if grace is None:
            return False
        started = time.monotonic()
        return self._stop_many([(owned.role, owned)], started + grace,
                               started + grace * 0.5).get(owned.role, False)

    def stop(self, roles, grace_seconds):
        grace = self._bounded_grace(grace_seconds)
        if grace is None:
            return {role: False for role in roles}
        started = time.monotonic()
        deadline = started + grace
        term_deadline = started + grace * 0.5
        results = {}
        entries = []
        with self._lock:
            for role in roles:
                if role not in ROLE_MODULES:
                    results[role] = False
                    continue
                intent = self._start_intents.get(role)
                if intent is not None:
                    intent.cancelled.set()
                owned = self._owned.get(role)
                if owned is None:
                    # A launch intent may still be in cgroup creation or Popen.
                    results[role] = intent is None
                    continue
                owned.stopping = True
                owned.ready = False
                entries.append((role, owned))

        stopped = self._stop_many(entries, deadline, term_deadline)
        results.update(stopped)
        return results

    def request_stop(self, roles):
        """Fence in-flight starts and send TERM without waiting for reclamation."""
        results = {}
        for role in roles:
            if role not in ROLE_MODULES:
                results[role] = False
                continue
            # These dictionary lookups and event/set-flag writes are nonblocking;
            # ownership itself remains reconciled by stop() on the lifecycle queue.
            intent = self._start_intents.get(role)
            if intent is not None:
                intent.cancelled.set()
            owned = self._owned.get(role)
            if owned is not None and owned.process is not None:
                owned.stopping = True
                owned.ready = False
                self._signal_tree(owned, signal.SIGTERM)
            results[role] = intent is not None or owned is not None
        return results

    def drain(self, roles, deadline, cancel_event):
        with self._lock:
            live = [role for role in roles if role in self._owned]
            for role in live:
                self._owned[role].ready = False
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
            return {role: {"owned": True, "ready": item.ready,
                           "starting": item.starting, "stopping": item.stopping,
                           "pid": item.process.pid,
                           "cgroup_populated": not self._events_populated(item.group)}
                    for role, item in sorted(self._owned.items())}
