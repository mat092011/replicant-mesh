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
import base64
import hashlib
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
ATTACH_PID_LOCK_TIMEOUT_SECONDS = 1.0
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
    term_sent: bool = False
    leader_reaped: bool = False
    reaped_event: object = field(default_factory=threading.Event)
    deadline_lock: object = field(default_factory=threading.Lock)
    force_cleanup: object = field(default_factory=threading.Event)
    artifact_pin: object = None
    group_removed: bool = False


@dataclass
class _StartIntent:
    cancelled: threading.Event = field(default_factory=threading.Event)
    cancel_deadline: float = None
    term_deadline: float = None
    group: Path = None
    finished: bool = False
    final_stop_requested: bool = False
    deadline_lock: object = field(default_factory=threading.Lock)
    force_cleanup: object = field(default_factory=threading.Event)


@dataclass
class _StopWatchdog:
    role: str
    armed: object = field(default_factory=threading.Event)
    wake: object = field(default_factory=threading.Event)
    thread: object = None
    closing: bool = False


class _PinReleaseMonitor:
    """Prestarted owner that performs potentially slow pin fsync outside locks."""

    def __init__(self, pin):
        self.pin = pin
        self.armed = threading.Event()
        self.completed = threading.Event()
        self.success = None
        self.error = None
        self.thread = threading.Thread(target=self._run,
                                       name="artifact-pin-release", daemon=True)
        self.thread.start()

    def _run(self):
        self.armed.wait()
        try:
            self.pin.release()
        except BaseException as error:
            self.error = error
            self.success = False
        else:
            self.success = True
        finally:
            self.completed.set()

    def arm(self):
        self.armed.set()

    def wait_until(self, deadline):
        return self.completed.wait(max(0.0, deadline - time.monotonic()))


class ProcessRoleBackend:
    """Own fixed role children under cgroup-v2 on the pinned CPython 3.12 runtime.

    The private Popen._waitpid_lock is held over numeric PID placement into a
    cgroup. This prevents poll/wait from reaping and freeing that PID between
    reading it and writing cgroup.procs. Unsupported runtimes fail closed.
    """

    def __init__(self, state_directory, cgroup, clock=time.monotonic):
        if not sys.platform.startswith("linux"):
            raise ResourceError("role process supervision requires Linux")
        self.state_directory = Path(state_directory)
        self.cgroup = cgroup or CgroupV2Controller()
        self.clock = clock
        self._lock = threading.RLock()
        self._owned = {}
        # This map is intentionally process-local. A persisted JSON config is
        # never sufficient proof that its numeric descriptor values are live.
        self._pinned_roles = {}
        self._pin_cleanups = {}
        self._pin_release_blocked = set()
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
    def _encode_config(role, config, policy=None, pin_metadata=None):
        document = {"version": 1, "role": role, "config": config}
        if policy is not None:
            document["policy"] = policy
        if pin_metadata is not None:
            document["artifact_pin"] = pin_metadata
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
            if (role in self._owned or role in self._start_intents
                    or role in self._pinned_roles):
                return False
            try:
                atomic_write_private(self._config_path(role), encoded)
            except (OSError, StorageError):
                return False
            return True

    def configure_pinned_role(self, role, config, pin, *, catalog_verifier):
        """Configure one fixed role while retaining its exact artifact pin.

        This transports authority to a supervised child; it does not make the
        role ready or establish its execution adapter.
        """
        from steamboat_connector.artifact_pin import RuntimeArtifactPin
        from steamboat_connector.aggregate_artifact_pin import RuntimeArtifactGroupPin
        from steamboat_connector.catalog import CatalogVerifier

        if (role not in ROLE_MODULES or type(config) is not dict
                or type(catalog_verifier) is not CatalogVerifier):
            return False
        if role == "coordinator":
            if type(pin) is not RuntimeArtifactPin or pin.record.get("role") != role:
                return False
            if catalog_verifier.clock is not pin.clock:
                return False
            try:
                pin.assert_open_descriptors()
                catalog = catalog_verifier.verify_catalog(pin.signed_catalog)
                if hashlib.sha256(catalog.document_bytes).hexdigest() != pin.record["catalog_sha256"]:
                    return False
                assignment = catalog_verifier.verify_assignment(
                    pin.signed_assignment, catalog,
                    account_id=pin.record["account_id"],
                    device_id=pin.record["device_id"], role=role)
                if (assignment.payload["assignment_id"] != pin.record["assignment_id"]
                        or assignment.document_sha256 != pin.record["assignment_sha256"]):
                    return False
                pin_meta = {
                    "version": 1, "kind": "single", "role": role, "root": str(pin.root),
                    "uid": pin.uid, "record_path": str(pin.record_path),
                    "record": dict(pin.record), "global_fd": pin.global_fd,
                    "role_fd": pin.role_fd, "clock_domain": pin.clock_domain,
                    "captured_mono": pin.captured_mono,
                    "catalog_deadline": pin.catalog_deadline,
                    "assignment_deadline": pin.assignment_deadline,
                    "signed_catalog": base64.b64encode(pin.signed_catalog).decode("ascii"),
                    "signed_assignment": base64.b64encode(pin.signed_assignment).decode("ascii"),
                    "public_key": base64.b64encode(catalog_verifier.public_key).decode("ascii"),
                }
            except Exception:
                return False
        else:
            if type(pin) is not RuntimeArtifactGroupPin or pin.record.get("role") != role:
                return False
            if catalog_verifier.clock is not pin.clock:
                return False
            try:
                pin.assert_open_descriptors()
                from steamboat_connector.aggregate_artifact_pin import _validate_group_record
                _validate_group_record(dict(pin.record))
                catalog = catalog_verifier.verify_catalog(pin.signed_catalog)
                if hashlib.sha256(catalog.document_bytes).hexdigest() != pin.record["catalog_sha256"]:
                    return False
                assignments = []
                for entry in pin.record["assignments"]:
                    launch = pin.child_launch_metadata(entry["assignment_id"])
                    assignment = catalog_verifier.verify_assignment(
                        launch["signed_assignment"], catalog,
                        account_id=pin.record["account_id"],
                        device_id=pin.record["device_id"], role=role)
                    if (assignment.payload["assignment_id"] != entry["assignment_id"]
                            or assignment.payload["component"] != entry["component"]
                            or assignment.document_sha256 != entry["assignment_sha256"]):
                        return False
                    assignments.append({
                        "version": 1,
                        "component": launch["component"],
                        "worker_boot_id": launch["worker_boot_id"],
                        "assignment_deadline": launch["assignment_deadline"],
                        "signed_assignment": base64.b64encode(
                            launch["signed_assignment"]).decode("ascii"),
                    })
                pin_meta = {
                    "version": 1, "kind": "group", "role": role, "root": str(pin.root),
                    "uid": pin.uid, "record_path": str(pin.record_path),
                    "record": dict(pin.record), "global_fd": pin.global_fd,
                    "role_fd": pin.role_fd, "clock_domain": pin.clock_domain,
                    "captured_mono": pin.captured_mono,
                    "catalog_deadline": pin.catalog_deadline,
                    "signed_catalog": base64.b64encode(pin.signed_catalog).decode("ascii"),
                    "public_key": base64.b64encode(catalog_verifier.public_key).decode("ascii"),
                    "assignments": assignments,
                }
            except Exception:
                return False
        try:
            encoded = self._encode_config(role, config, pin_metadata=pin_meta)
        except (TypeError, ValueError):
            return False
        with self._lock:
            if (role in self._owned or role in self._start_intents
                    or role in self._pinned_roles):
                return False
            try:
                atomic_write_private(self._config_path(role), encoded)
            except (OSError, StorageError):
                return False
            try:
                cleanup = _PinReleaseMonitor(pin)
            except Exception:
                return False
            self._pinned_roles[role] = (pin, catalog_verifier, pin_meta)
            self._pin_cleanups[role] = cleanup
            return True

    def release_configured_pin(self, role):
        """Release a pin only when no start intent or process owns the role."""
        with self._lock:
            if role in self._owned or role in self._start_intents:
                return False
            entry = self._pinned_roles.get(role)
            if entry is None:
                return False
            cleanup = self._pin_cleanups.get(role)
            if cleanup is None:
                return False
            if (role in self._pin_release_blocked
                    and not (cleanup.armed.is_set()
                             and cleanup.completed.is_set()
                             and cleanup.success is True)):
                # Only the exact already-completed configured-release owner
                # can clear its own timeout fence. Launch-unknown/faulted pins
                # remain permanently fenced.
                return False
            # Fence start admission while release runs outside the ledger lock.
            self._pin_release_blocked.add(role)
        deadline = time.monotonic() + STOP_GRACE_MAX_SECONDS
        cleanup.arm()
        if not cleanup.wait_until(deadline) or not cleanup.success:
            return False
        with self._lock:
            if (role in self._owned or role in self._start_intents
                    or role not in self._pin_release_blocked
                    or self._pin_cleanups.get(role) is not cleanup
                    or self._pinned_roles.get(role) is not entry):
                return False
            self._pinned_roles.pop(role, None)
            self._pin_cleanups.pop(role, None)
            self._pin_release_blocked.discard(role)
            try:
                self._config_path(role).unlink(missing_ok=True)
            except OSError:
                # Keep a strong owner if config cleanup is uncertain; release
                # was already successful, so do not retry a descriptor close.
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
                                        {"version", "role", "config", "policy"},
                                        {"version", "role", "config", "artifact_pin"},
                                        {"version", "role", "config", "policy", "artifact_pin"})
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
        except (OSError, AttributeError):
            # Unknown signal state is surfaced by the subsequent empty check.
            pass

    @staticmethod
    def _cancelled(intent, cancel_event):
        return intent.cancelled.is_set() or intent.force_cleanup.is_set() or (
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
    def _tighten_deadlines(target, deadline_attr, term_attr, deadline, term_deadline):
        now = time.monotonic()
        requested_deadline = (deadline if deadline is not None else
                              now + STOP_GRACE_MAX_SECONDS)
        requested_term = (term_deadline if term_deadline is not None else
                          now + STOP_GRACE_MAX_SECONDS * 0.5)
        if not target.deadline_lock.acquire(blocking=False):
            target.force_cleanup.set()
            return
        try:
            if target.force_cleanup.is_set():
                requested_deadline = requested_term = now
            old_deadline = getattr(target, deadline_attr)
            old_term = getattr(target, term_attr)
            next_deadline = (requested_deadline if old_deadline is None else
                             min(old_deadline, requested_deadline))
            next_term = requested_term if old_term is None else min(old_term, requested_term)
            if target.force_cleanup.is_set():
                next_deadline = next_term = time.monotonic()
            setattr(target, deadline_attr, next_deadline)
            setattr(target, term_attr, next_term)
        finally:
            target.deadline_lock.release()

    @classmethod
    def _cancel_intent(cls, intent, deadline=None, term_deadline=None):
        cls._tighten_deadlines(intent, "cancel_deadline", "term_deadline",
                               deadline, term_deadline)
        intent.cancelled.set()

    @staticmethod
    def _effective_deadlines(target, *, intent=False):
        if target.force_cleanup.is_set():
            now = time.monotonic()
            return now, now
        deadline = target.cancel_deadline if intent else target.stop_deadline
        return deadline, target.term_deadline

    def _ensure_stop_watchdog_locked(self, role):
        """Ensure the role monitor while the caller holds _watchdog_lock."""
        current = self._stop_watchdogs.get(role)
        if current is not None and not current.closing and current.thread.is_alive():
            return True
        watchdog = _StopWatchdog(role)
        self._stop_watchdogs[role] = watchdog
        thread = threading.Thread(target=self._run_stop_watchdog,
                                  args=(watchdog,),
                                  name=f"participant-stop-{role}", daemon=True)
        watchdog.thread = thread
        try:
            thread.start()
        except RuntimeError:
            self._stop_watchdogs.pop(role, None)
            return False
        return True

    def _arm_stop_watchdog(self, role):
        watchdog = self._stop_watchdogs.get(role)
        if watchdog is not None:
            watchdog.armed.set()
            watchdog.wake.set()

    def _stop_watchdog_owner(self, watchdog):
        """Return the currently stopped generation; never adopt stale requests."""
        intent = self._start_intents.get(watchdog.role)
        owned = self._owned.get(watchdog.role)
        if owned is not None and not owned.reclaimed:
            owner_deadline, owner_term = self._effective_deadlines(owned)
            if (owned.stopping and owner_deadline is not None
                    and owner_term is not None
                    and (intent is None or owned.start_intent is intent)):
                return owned, False
            return None, False
        if intent is not None and intent.cancelled.is_set():
            return None, intent.finished and intent.group is None
        return None, intent is None

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
                        if not owned.leader_reaped and process.poll() is not None:
                            owned.leader_reaped = True
                            owned.reaped_event.set()
                        return
                except OSError:
                    pass
            if owned.leader_reaped:
                return
            if process.poll() is not None:
                owned.leader_reaped = True
                owned.reaped_event.set()
                return
            # Before cgroup attachment the session leader is the only available
            # safe target. Afterward, only use the pgid while the cgroup proves a
            # live member remains (preventing a reaped/reused PID signal).
            # A process-group ID is not reserved after its leader exits.
            # Without cgroup.kill, retain unknown descendants instead of
            # risking a signal to an unrelated process group that reused it.
            try:
                os.killpg(process.pid, SIGKILL)
            except (OSError, AttributeError):
                pass

    def _signal_owned_term(self, owned):
        with owned.escalation_lock:
            process = owned.process
            if (process is None or owned.reclaimed or owned.term_sent
                    or self._owned.get(owned.role) is not owned):
                return
            if owned.leader_reaped:
                return
            if process.poll() is not None:
                owned.leader_reaped = True
                owned.reaped_event.set()
                return
            if process is not None:
                self._signal_tree(owned, signal.SIGTERM)
                owned.term_sent = True

    @staticmethod
    def _poll_owned(owned):
        """Serialize every leader reap with process-group signaling."""
        with owned.escalation_lock:
            if owned.leader_reaped:
                return True
            process = owned.process
            if process is not None and process.poll() is not None:
                owned.leader_reaped = True
                owned.reaped_event.set()
            return owned.leader_reaped

    def _run_stop_watchdog(self, watchdog):
        watchdog.armed.wait()
        while True:
            with self._watchdog_lock:
                if self._stop_watchdogs.get(watchdog.role) is not watchdog:
                    return
            owner, finished = self._stop_watchdog_owner(watchdog)
            if finished:
                with self._watchdog_lock:
                    if self._stop_watchdogs.get(watchdog.role) is watchdog:
                        # Recheck the current generation after taking the
                        # publication lock; start() may have installed a new
                        # intent after the first observation.
                        _, still_finished = self._stop_watchdog_owner(watchdog)
                        if still_finished:
                            self._stop_watchdogs.pop(watchdog.role, None)
                            watchdog.closing = True
                            return
                continue
            if owner is not None:
                if owner.process is not None:
                    _, term_deadline = self._effective_deadlines(owner)
                    intent = owner.start_intent
                    if intent is not None:
                        _, intent_term = self._effective_deadlines(intent, intent=True)
                        if intent_term is not None:
                            term_deadline = (intent_term if term_deadline is None else
                                             min(term_deadline, intent_term))
                    now = time.monotonic()
                    if now >= (term_deadline if term_deadline is not None else now):
                        self._watchdog_kill(owner)
                    else:
                        if not owner.term_sent:
                            self._signal_owned_term(owner)
                        else:
                            with owner.escalation_lock:
                                if (not owner.leader_reaped
                                        and owner.process.poll() is not None):
                                    owner.leader_reaped = True
                                    owner.reaped_event.set()
                        watchdog.wake.wait(min(term_deadline - now, 0.05))
                        watchdog.wake.clear()
                        continue
            # Polling is deliberately fixed and bounded: request_stop never
            # allocates a worker or waits for a lifecycle/global lock.
            watchdog.wake.wait(0.05)
            watchdog.wake.clear()

    def _retire_stop_watchdog(self, role, generation):
        watchdog = self._stop_watchdogs.get(role)
        if watchdog is not None:
            watchdog.armed.set()
            watchdog.wake.set()

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

        # Publish intent and ensure its monitor under the same lock used by
        # monitor retirement, eliminating the gap where a new generation could
        # be claimed just as the old thread removes the role's sole watcher.
        with self._watchdog_lock:
            with self._lock:
                if ((cancel_event is not None and cancel_event.is_set())
                        or role in self._owned or role in self._start_intents
                        or role in self._pin_release_blocked):
                    return False
                intent = _StartIntent()
                self._start_intents[role] = intent
            if not self._ensure_stop_watchdog_locked(role):
                with self._lock:
                    if self._start_intents.get(role) is intent:
                        del self._start_intents[role]
                return False
            watchdog = self._stop_watchdogs[role]
            if cancel_event is not None and cancel_event.is_set():
                intent.cancelled.set()
                intent.finished = True
                with self._lock:
                    if self._start_intents.get(role) is intent:
                        del self._start_intents[role]
                self._stop_watchdogs.pop(role, None)
                watchdog.closing = True
                watchdog.armed.set()
                return False
            watchdog.armed.set()
            watchdog.wake.set()

        group = None
        read_fd = write_fd = -1
        process = None
        owned = None
        try:
            if self._cancelled(intent, cancel_event):
                return False
            with self._lock:
                configured_pin = self._pinned_roles.get(role)
            role_config = self._configured_role(role)
            if role_config is None or self._cancelled(intent, cancel_event):
                return False
            pin = configured_pin[0] if configured_pin is not None else None
            pin_metadata = configured_pin[2] if configured_pin is not None else None
            if configured_pin is not None:
                try:
                    pin.assert_open_descriptors()
                except Exception:
                    return False
            try:
                document = read_private_json(self._config_path(role),
                                             maximum_size=ROLE_CONFIG_MAX_BYTES)
            except (OSError, StorageError):
                return False
            if (type(document) is not dict
                    or ("artifact_pin" in document) != (pin_metadata is not None)
                    or (pin_metadata is not None
                        and document.get("artifact_pin") != pin_metadata)):
                return False
            atomic_write_private(self._config_path(role),
                                 self._encode_config(role, role_config, policy,
                                                     pin_metadata=pin_metadata))
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
                                      start_intent=intent, artifact_pin=pin)
                self._owned[role] = owned
                if self._cancelled(intent, cancel_event):
                    del self._owned[role]
                    owned = None
                    return False
                try:
                    inherited_fds = [read_fd]
                    if pin_metadata is not None:
                        inherited_fds.extend((pin_metadata["global_fd"],
                                              pin_metadata["role_fd"]))
                        # From entering Popen onward, a failed return is not
                        # proof that no child was created. Keep release sticky.
                        self._pin_release_blocked.add(role)
                    process = subprocess.Popen(
                        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, close_fds=True,
                        pass_fds=tuple(inherited_fds),
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
                    intent_deadline, intent_term = self._effective_deadlines(
                        intent, intent=True)
                    self._mark_stopping(owned, intent_deadline, intent_term)
                    if time.monotonic() >= intent_term:
                        self._watchdog_kill(owned)
                    else:
                        self._signal_owned_term(owned)
            os.close(read_fd)
            read_fd = -1
            self._attach_child_safely(group, process)
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
                    with owned.escalation_lock:
                        process_live = process.poll() is None
                        if not process_live:
                            owned.leader_reaped = True
                            owned.reaped_event.set()
                    owned.ready = bool(ready and process_live)
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

    def _attach_child_safely(self, group, process):
        if (sys.implementation.name != "cpython"
                or sys.version_info[:2] != (3, 12)):
            raise ResourceError("safe cgroup attachment requires pinned CPython 3.12")
        waitpid_lock = getattr(process, "_waitpid_lock", None)
        acquire = getattr(waitpid_lock, "acquire", None)
        release = getattr(waitpid_lock, "release", None)
        if not callable(acquire) or not callable(release):
            raise ResourceError("Popen ownership lock is unavailable")
        if not acquire(timeout=ATTACH_PID_LOCK_TIMEOUT_SECONDS):
            raise ResourceError("timed out acquiring child PID ownership lock")
        try:
            self.cgroup.attach_child(group, process)
        finally:
            release()

    @staticmethod
    def _acquire_until(lock, deadline):
        return lock.acquire(timeout=max(0.0, deadline - time.monotonic()))

    @staticmethod
    def _mark_stopping(owned, deadline=None, term_deadline=None):
        # Cleanup caps are immutable once established, except that a later
        # request may tighten them. Drain cutoffs must never be passed here.
        ProcessRoleBackend._tighten_deadlines(
            owned, "stop_deadline", "term_deadline", deadline, term_deadline)
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
            effective_stop, _ = self._effective_deadlines(owned)
            stop_deadline = effective_stop if effective_stop is not None else deadline
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
                    stop_deadline, _ = self._effective_deadlines(owned)
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
                _, effective_term = self._effective_deadlines(owned)
                own_term_deadline = (effective_term if effective_term is not None
                                     else term_deadline)
                remaining = max(0.0, min(deadline, own_term_deadline) - time.monotonic())
                owned.reaped_event.wait(remaining)

            # Escalate every still-populated tree before beginning final waits.
            for _, owned in active:
                reaped = self._poll_owned(owned)
                if not self._events_populated(owned.group) or not reaped:
                    self._watchdog_kill(owned)

            for role, owned in active:
                effective_stop, _ = self._effective_deadlines(owned)
                # Once the leader is reaped and its cgroup removed, a later
                # stop call may observe the prestarted descriptor-release
                # monitor within that call's bounded deadline. This does not
                # extend any live-process termination deadline.
                cleanup_only = (owned.artifact_pin is not None
                                and owned.leader_reaped and owned.group_removed)
                own_deadline = (deadline if cleanup_only else
                                min(deadline, effective_stop or deadline))
                empty = (owned.group_removed or self._wait_empty(owned, own_deadline))
                remaining = max(0.0, own_deadline - time.monotonic())
                owned.reaped_event.wait(remaining)
                reaped = self._poll_owned(owned)
                reclaimed = empty and reaped
                if reclaimed:
                    if not self._acquire_until(self._lock, own_deadline):
                        reclaimed = False
                    else:
                        try:
                            with owned.escalation_lock:
                                # Recheck while excluding watchdog signals so a
                                # stale PID cannot be targeted after reaping.
                                reclaimed = (self._owned.get(role) is owned
                                             and owned.leader_reaped
                                             and (owned.group_removed
                                                  or self._events_populated(owned.group)))
                                if reclaimed and not owned.group_removed:
                                    reclaimed = self._remove_empty_group(owned.group)
                                    owned.group_removed = reclaimed
                                if reclaimed and owned.artifact_pin is None:
                                    del self._owned[role]
                                    owned.reclaimed = True
                        finally:
                            self._lock.release()
                if reclaimed and owned.artifact_pin is not None:
                    # Pin release can fsync the artifact-store directory. The
                    # configured monitor owns it strongly and performs that
                    # work after both lifecycle and escalation locks are free.
                    cleanup = self._pin_cleanups.get(role)
                    if cleanup is None:
                        reclaimed = False
                    else:
                        cleanup.arm()
                        # The child/group proof is already complete. Bound this
                        # cleanup observation by the current stop invocation,
                        # even when an earlier process-termination deadline
                        # has elapsed.
                        completed = cleanup.wait_until(deadline)
                        reclaimed = bool(completed and cleanup.success)
                    if reclaimed:
                        if not self._acquire_until(self._lock, deadline):
                            reclaimed = False
                        else:
                            try:
                                reclaimed = (self._owned.get(role) is owned
                                             and owned.leader_reaped
                                             and owned.group_removed)
                                if reclaimed:
                                    self._pinned_roles.pop(role, None)
                                    self._pin_cleanups.pop(role, None)
                                    self._pin_release_blocked.discard(role)
                                    del self._owned[role]
                                    owned.reclaimed = True
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
        current_deadline, current_term = self._effective_deadlines(owned)
        deadline = (requested_deadline if current_deadline is None else
                    min(current_deadline, requested_deadline))
        requested_term_deadline = min(deadline, started + grace * 0.5)
        term_deadline = (requested_term_deadline if current_term is None else
                         min(current_term, requested_term_deadline))
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
                        # A failed/ambiguous Popen after descriptor handoff is
                        # not proof that no child inherited the pin. Without a
                        # trusted reconciliation path, keep this generation
                        # fenced and report its ownership as unknown.
                        results[role] = role not in self._pin_release_blocked
                    elif intent.finished and intent.group is not None:
                        cleanup_intents.append((role, intent))
                        results[role] = False
                    elif intent.finished and intent.group is None:
                        # A previous cleanup removed the cgroup but could not
                        # reacquire the ledger lock to forget its intent.
                        del self._start_intents[role]
                        results[role] = role not in self._pin_release_blocked
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
                            results[role] = role not in self._pin_release_blocked
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
                    intent_deadline, intent_term = self._effective_deadlines(
                        intent, intent=True)
                    deadline = min(deadline, intent_deadline)
                    term_deadline = min(term_deadline, intent_term)
                self._mark_stopping(owned, deadline, term_deadline)
                deadline, term_deadline = self._effective_deadlines(owned)
            elif intent is not None:
                deadline, term_deadline = self._effective_deadlines(intent, intent=True)
            else:
                deadline = term_deadline = None
            if generation is not None:
                self._arm_stop_watchdog(role)
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
