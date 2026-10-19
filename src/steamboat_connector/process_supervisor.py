"""Own fixed Linux role children and their delegated cgroups."""

import json
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
from .storage import StorageError, atomic_write_private


ROLE_MODULES = {
    "host": "steamboat_connector.role_worker",
    "coordinator": "steamboat_connector.role_coordinator",
}
READY_TIMEOUT_SECONDS = 30.0
READY_LINE_MAX = 64
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

    @property
    def secure_runtime_ready(self):
        # Process readiness alone does not establish admission or artifact
        # integrity; parent wiring must combine those checks separately.
        return False

    def _config_path(self, role):
        return self.state_directory / f"{role}-runtime.json"

    def _write_config(self, role, policy):
        config = {"version": 1, "role": role, "policy": policy}
        atomic_write_private(self._config_path(role),
                             json.dumps(config, sort_keys=True,
                                        separators=(",", ":")).encode("utf-8"))

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
            fields = dict(line.split() for line in
                          (Path(group) / "cgroup.events").read_text(encoding="ascii").splitlines())
            return fields.get("populated") == "0"
        except (OSError, ValueError):
            return False

    def _wait_empty(self, owned, timeout):
        deadline = time.monotonic() + max(0.0, timeout)
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

    def start(self, role, policy):
        if role not in ROLE_MODULES:
            return False
        if not sys.platform.startswith("linux"):
            return False
        try:
            policy = validate_policy(policy)
            self._write_config(role, policy)
            group = self.cgroup.create_group(
                f"participant-{role}-{uuid.uuid4().hex[:12]}", policy, role)
        except (OSError, ValueError, ResourceError, StorageError):
            return False

        read_fd, write_fd = os.pipe()
        process = None
        owned = None
        try:
            command = [sys.executable, "-I", "-S", "-m",
                       "steamboat_connector.process_bootstrap", role,
                       os.fspath(self._config_path(role)), str(read_fd)]
            process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, close_fds=True, pass_fds=(read_fd,),
                start_new_session=True, env=dict(_CHILD_ENV), bufsize=0)
            os.close(read_fd)
            read_fd = -1
            owned = _OwnedProcess(role, process, Path(group), self.clock())
            # Publish ownership before attach and before releasing the child.
            with self._lock:
                if role in self._owned:
                    raise ResourceError("role already has an owned process")
                self._owned[role] = owned
            self.cgroup.attach_child(group, process)
            os.write(write_fd, b"R")
            os.close(write_fd)
            write_fd = -1
            ready = self._read_ready(process, READY_TIMEOUT_SECONDS)
            with self._lock:
                current = self._owned.get(role)
                if current is not owned or owned.stopping:
                    return False
                owned.starting = False
                owned.ready = bool(ready and process.poll() is None)
            if not owned.ready:
                self._stop_owned(owned, STOP_GRACE_MAX_SECONDS)
                return False
            return True
        except Exception:
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
                os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)

    def _stop_owned(self, owned, grace_seconds):
        with owned.stop_lock:
            return self._stop_owned_locked(owned, grace_seconds)

    def _stop_owned_locked(self, owned, grace_seconds):
        grace = min(STOP_GRACE_MAX_SECONDS, max(0.0, float(grace_seconds)))
        with self._lock:
            if self._owned.get(owned.role) is not owned:
                return True
            owned.stopping = True
            owned.ready = False
        self._signal_tree(owned, signal.SIGTERM)
        started = time.monotonic()
        deadline = started + grace
        term_deadline = started + grace * 0.5
        try:
            owned.process.wait(timeout=max(0.0, term_deadline - time.monotonic()))
        except (subprocess.TimeoutExpired, TimeoutError, OSError):
            pass
        # Always inspect the cgroup: the leader can exit while a child lives.
        if not self._events_populated(owned.group):
            self._signal_tree(owned, signal.SIGKILL)
        remaining = max(0.0, deadline - time.monotonic())
        empty = self._wait_empty(owned, remaining)
        try:
            owned.process.wait(timeout=max(0.0, remaining))
        except (subprocess.TimeoutExpired, TimeoutError, OSError):
            empty = False
        if empty and owned.process.poll() is not None:
            with self._lock:
                if self._owned.get(owned.role) is owned:
                    del self._owned[owned.role]
            return True
        return False

    def stop(self, roles, grace_seconds):
        grace = min(STOP_GRACE_MAX_SECONDS, max(0.0, float(grace_seconds)))
        results = {}
        for role in roles:
            if role not in ROLE_MODULES:
                results[role] = False
                continue
            with self._lock:
                owned = self._owned.get(role)
            results[role] = True if owned is None else self._stop_owned(owned, grace)
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
