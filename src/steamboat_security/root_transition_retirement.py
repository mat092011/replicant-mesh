"""Protected native POSIX launches and old-process retirement evidence.

The supervisor creates processes from a protected, operator-owned manifest;
callers cannot register arbitrary ``Popen`` handles as launch provenance. READY
identifies declared roles but does not assert model readiness. Retirement
requires leader wait/exit and confirmed disappearance of the owned process
group under the explicit trusted-no-escape operator-code assumption.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import re
import select
import stat
import subprocess
import threading
import time
from dataclasses import dataclass

from .codec import canonical_json
from .errors import BindingError, StorageError
from .files import safe_read
from .root_transition_launch import (MAX_LAUNCH_ROLES, RoleLaunchSpec,
                                     canonical_role_launch_digest,
                                     parse_role_launch_spec, role_launch_document)

MAX_READY_BYTES = 16 * 1024
MAX_OWNED_PROCESSES = 16
MAX_CAPABILITIES = 16
_READY_FIELDS = frozenset({"schema_version", "event", "launch_nonce", "roles"})
MAX_LAUNCHER_MANIFEST_BYTES = 16 * 1024
MAX_LAUNCHER_SOURCE_BYTES = 1024 * 1024
MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
_MANIFEST_FIELDS = frozenset({
    "schema_version", "containment_profile", "executable_path",
    "executable_sha256", "script_path", "script_sha256",
    "configuration_path", "configuration_sha256", "argv",
})
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
TRUSTED_CONTAINMENT_PROFILE = "trusted_no_escape_v1"
RETIREMENT_EVIDENCE_PROFILE = "trusted_process_group_no_escape"


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BindingError("READY contains a duplicate field")
        result[key] = value
    return result


def _no_constant(_value):
    raise BindingError("READY contains a non-finite number")


def _no_float(_value):
    raise BindingError("launcher manifest numeric values must be integers")


@dataclass(frozen=True)
class OperatorLaunchManifest:
    containment_profile: str
    executable_path: str
    executable_sha256: str
    script_path: str
    script_sha256: str
    configuration_path: str
    configuration_sha256: str
    argv: tuple[str, ...]


def _absolute_manifest_path(value, field):
    if (type(value) is not str or not value or "\x00" in value
            or not os.path.isabs(value) or os.path.normpath(value) != value):
        raise BindingError(f"launcher manifest {field} path is invalid")
    return value


def parse_operator_launch_manifest(encoded: bytes) -> OperatorLaunchManifest:
    """Parse the exact, closed operator-owned launch profile document."""
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_LAUNCHER_MANIFEST_BYTES:
        raise BindingError("operator launch manifest exceeds its 16 KiB bound")
    try:
        raw = json.loads(encoded.decode("utf-8", errors="strict"),
                         object_pairs_hook=_pairs, parse_constant=_no_constant,
                         parse_float=_no_float)
    except BindingError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise BindingError("operator launch manifest is malformed") from error
    if type(raw) is not dict or set(raw) != _MANIFEST_FIELDS:
        raise BindingError("operator launch manifest has unknown or missing fields")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise BindingError("operator launch manifest schema version is invalid")
    if type(raw["containment_profile"]) is not str or raw["containment_profile"] != TRUSTED_CONTAINMENT_PROFILE:
        raise BindingError("operator launch containment profile is unsupported")
    hashes = ("executable_sha256", "script_sha256", "configuration_sha256")
    for name in hashes:
        if type(raw[name]) is not str or not _HEX64.fullmatch(raw[name]):
            raise BindingError(f"operator launch {name} is invalid")
    executable = _absolute_manifest_path(raw["executable_path"], "executable")
    script = _absolute_manifest_path(raw["script_path"], "script")
    config = _absolute_manifest_path(raw["configuration_path"], "configuration")
    argv = raw["argv"]
    expected_argv = (executable, "-I", script, "--config", config)
    if (type(argv) is not list or len(argv) != len(expected_argv)
            or any(type(arg) is not str for arg in argv)
            or tuple(argv) != expected_argv):
        raise BindingError("operator launch argv must exactly pin Python -I script and config")
    return OperatorLaunchManifest(
        TRUSTED_CONTAINMENT_PROFILE, executable, raw["executable_sha256"],
        script, raw["script_sha256"], config, raw["configuration_sha256"], tuple(argv))


def _hash_fd(fd: int, *, max_bytes: int) -> str:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= max_bytes:
        raise BindingError("pinned launcher file is not a bounded regular file")
    digest = hashlib.sha256()
    total = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, min(64 * 1024, max_bytes + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise BindingError("pinned launcher file exceeds its size bound")
        digest.update(chunk)
    if total != info.st_size:
        raise BindingError("pinned launcher file changed while being hashed")
    return digest.hexdigest()


def _hash_executable(path: str) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0))
        try:
            return _hash_fd(fd, max_bytes=MAX_EXECUTABLE_BYTES)
        finally:
            os.close(fd)
    except OSError as error:
        raise BindingError("pinned executable cannot be opened safely") from error


def _parse_ready(line: bytes, expected: tuple[RoleLaunchSpec, ...]) -> None:
    if type(line) is not bytes or not 1 <= len(line) <= MAX_READY_BYTES:
        raise BindingError("READY line exceeds its 16 KiB bound")
    try:
        raw = json.loads(line.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                         parse_constant=_no_constant)
    except BindingError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise BindingError("READY line is malformed JSON") from error
    if type(raw) is not dict or set(raw) != _READY_FIELDS:
        raise BindingError("READY has unknown or missing fields")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise BindingError("READY schema version is invalid")
    if type(raw["event"]) is not str or raw["event"] != "root_role_ready":
        raise BindingError("READY event is invalid")
    nonce = raw["launch_nonce"]
    if type(nonce) is not str:
        raise BindingError("READY nonce is invalid")
    roles = raw["roles"]
    if type(roles) is not list or not 1 <= len(roles) <= MAX_LAUNCH_ROLES:
        raise BindingError("READY role count is invalid")
    parsed = tuple(parse_role_launch_spec(item) for item in roles)
    identities = tuple(spec.identity for spec in parsed)
    if identities != tuple(sorted(identities)) or len(set(identities)) != len(identities):
        raise BindingError("READY roles must be sorted and unique")
    if any(spec.launch_nonce != nonce for spec in parsed):
        raise BindingError("READY roles do not share the process nonce")
    if canonical_json([role_launch_document(s) for s in parsed]) != canonical_json(
            [role_launch_document(s) for s in expected]):
        raise BindingError("READY roles differ from the expected launch declarations")


@dataclass(frozen=True, slots=True, init=False)
class ObservedLaunch:
    """Opaque historical evidence that a supervisor-launched process emitted READY.

    Use ``validate_observed_launch`` for a current live check; the observation
    itself does not remain a liveness proof after process exit or generation fence.
    """
    _supervisor: object
    _record: object
    _seal: object

    def __init__(self, supervisor, record, seal):
        object.__setattr__(self, "_supervisor", supervisor)
        object.__setattr__(self, "_record", record)
        object.__setattr__(self, "_seal", seal)


@dataclass(frozen=True, slots=True, init=False)
class RetirementCapability:
    """Local trusted-group evidence, not proof against escaped descendants.

    The operator script is trusted not to escape its own process group. This
    capability makes no kernel-containment or arbitrary-descendant claim.
    """
    _supervisor: object
    _record: object
    _seal: object

    def __init__(self, supervisor, record, seal):
        object.__setattr__(self, "_supervisor", supervisor)
        object.__setattr__(self, "_record", record)
        object.__setattr__(self, "_seal", seal)


@dataclass(frozen=True, slots=True, init=False)
class PendingOwnedLaunch:
    """Opaque registered Popen owner whose READY observation has not run."""
    _supervisor: object
    _record: object
    _seal: object

    def __init__(self, supervisor, record, seal):
        object.__setattr__(self, "_supervisor", supervisor)
        object.__setattr__(self, "_record", record)
        object.__setattr__(self, "_seal", seal)


@dataclass
class _Owned:
    process: object
    specs: tuple[RoleLaunchSpec, ...]
    pid: int
    pgid: int
    manifest: OperatorLaunchManifest
    launch_stdin_pipe_validated: bool = False
    launch_stdin_closed_after_record: bool = False
    ready_stdout_pipe_validated: bool = False
    pending: PendingOwnedLaunch | None = None
    observation_attempted: bool = False
    ready: ObservedLaunch | None = None
    leader_exited: bool = False
    group_gone: bool = False


class RetirementSupervisor:
    """Bounded owner of locally launched POSIX process groups."""

    def __init__(self):
        if os.name != "posix" or not os.path.isdir("/proc"):
            raise OSError("root transition retirement requires native POSIX /proc")
        self._seal = object()
        self._owned: list[_Owned] = []
        self._observed: list[ObservedLaunch] = []
        self._capabilities: list[RetirementCapability] = []
        self._fenced_generations: set[str] = set()
        # A single root-startup attempt may reserve this supervisor. This is
        # separate from process ownership because competing starters can race
        # before either has spawned its first child.
        self._root_startup_owner = None
        self._state_lock = threading.RLock()

    @staticmethod
    def _validate_specs(specs) -> tuple[RoleLaunchSpec, ...]:
        if type(specs) is not tuple:
            raise BindingError("expected launch specifications must be a tuple")
        canonical_role_launch_digest(specs)
        nonces = {item.launch_nonce for item in specs}
        generations = {item.generation_sha256 for item in specs}
        if len(nonces) != 1 or len(generations) != 1:
            raise BindingError("one process cohort must share nonce and generation")
        return specs

    @staticmethod
    def _parent_pid(pid: int) -> int:
        # Read stat's PPid field without trusting caller-supplied metadata.
        with open(f"/proc/{pid}/status", "rt", encoding="ascii") as stream:
            for line in stream:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
        raise OSError("process parent identity is unavailable")

    def _check_owned_process(self, process, manifest: OperatorLaunchManifest, *,
                             record: _Owned | None = None,
                             record_initial_pipes: bool = False) -> tuple[int, int]:
        """Verify only immediate, known Popen ownership after spawn.

        This deliberately does not claim that the child is the pinned Python
        executable. The full cmdline/executable/hash check belongs after the
        child has consumed its launch record and emitted the exact READY frame.
        """
        if type(process) is not subprocess.Popen:
            raise BindingError("launcher did not return an actual Popen")
        pid = process.pid
        if type(pid) is not int or pid <= 1 or process.poll() is not None:
            raise BindingError("owned process is not live")
        if self._parent_pid(pid) != os.getpid():
            raise BindingError("process is not a direct child of this supervisor")
        pgid, sid = os.getpgid(pid), os.getsid(pid)
        if pgid != pid or sid != pid:
            raise BindingError("process must own its session and process group")
        if process.stdout is None or process.stdin is None:
            raise BindingError("owned process has no launch input and READY pipes")
        if list(process.args) != list(manifest.argv):
            raise BindingError("Popen arguments or launch input pipe differ from the manifest")
        if record is None:
            record = next((item for item in self._owned if item.process is process), None)
        if (record is None or record.process is not process or record.manifest is not manifest
                or not any(item is record for item in self._owned)):
            raise BindingError("process pipes have no exact registered owner")
        try:
            if process.stdin.closed:
                if (record_initial_pipes or not record.launch_stdin_pipe_validated
                        or not record.launch_stdin_closed_after_record):
                    raise BindingError("launch input pipe was not verified before closure")
            elif not stat.S_ISFIFO(os.fstat(process.stdin.fileno()).st_mode):
                raise BindingError("owned process launch input descriptor is not a pipe")
            if not stat.S_ISFIFO(os.fstat(process.stdout.fileno()).st_mode):
                raise BindingError("owned process READY output descriptor is not a pipe")
        except (OSError, ValueError) as error:
            raise BindingError("owned process input/output pipe is unavailable") from error
        if record_initial_pipes:
            if process.stdin.closed:
                raise BindingError("new process launch input pipe is already closed")
            record.launch_stdin_pipe_validated = True
            record.ready_stdout_pipe_validated = True
        elif (not record.launch_stdin_pipe_validated
              or not record.ready_stdout_pipe_validated):
            raise BindingError("input/output pipes were not recorded at process registration")
        return pid, pgid

    def _check_process(self, process, manifest: OperatorLaunchManifest) -> tuple[int, int]:
        pid, pgid = self._check_owned_process(process, manifest)
        try:
            with open(f"/proc/{pid}/cmdline", "rb", buffering=0) as stream:
                cmdline = stream.read(64 * 1024 + 1)
            if len(cmdline) > 64 * 1024 or not cmdline.endswith(b"\0"):
                raise BindingError("process cmdline is unavailable or oversized")
            actual_argv = tuple(os.fsdecode(item) for item in cmdline[:-1].split(b"\0"))
            exe_link = os.readlink(f"/proc/{pid}/exe")
            if exe_link.endswith(" (deleted)") or os.path.realpath(exe_link) != manifest.executable_path:
                raise BindingError("running executable path differs from the protected manifest")
            executable_fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                executable_hash = _hash_fd(executable_fd, max_bytes=MAX_EXECUTABLE_BYTES)
            finally:
                os.close(executable_fd)
        except OSError as error:
            raise BindingError("running executable or argv cannot be verified") from error
        if actual_argv != manifest.argv or executable_hash != manifest.executable_sha256:
            raise BindingError("running executable or argv differs from the protected manifest")
        return pid, pgid

    def _load_manifest(self, manifest_path, protected_root, expected_uid):
        try:
            encoded = safe_read(manifest_path, root=protected_root,
                                expected_uid=expected_uid,
                                max_bytes=MAX_LAUNCHER_MANIFEST_BYTES)
            manifest = parse_operator_launch_manifest(encoded)
            for path, expected, label in (
                    (manifest.script_path, manifest.script_sha256, "script"),
                    (manifest.configuration_path, manifest.configuration_sha256,
                     "configuration")):
                contents = safe_read(path, root=protected_root,
                                     expected_uid=expected_uid,
                                     max_bytes=MAX_LAUNCHER_SOURCE_BYTES)
                if hashlib.sha256(contents).hexdigest() != expected:
                    raise BindingError(f"protected launcher {label} hash changed")
            if os.path.realpath(manifest.executable_path) != manifest.executable_path:
                raise BindingError("executable path must be canonical and symlink-free")
            if _hash_executable(manifest.executable_path) != manifest.executable_sha256:
                raise BindingError("protected launcher executable hash changed")
            return manifest
        except StorageError as error:
            raise BindingError("protected operator launcher files are unavailable") from error

    def spawn_owned_process(self, manifest_path, *, protected_root, expected_uid,
                            specs, expected_manifest=None,
                            before_popen_check=None) -> PendingOwnedLaunch:
        """Synchronously spawn and register one protected launch before READY.

        A root-startup caller may use this to keep its selected-root authority
        lock held across fresh selection validation, claim fsync, Popen and
        immediate owner registration. It must release that external lock before
        calling :meth:`observe_ready`, because the child may need selected-root
        storage during startup. A partial cohort-spawn failure consumes the
        whole external claim: already registered children remain owned and must
        be cleaned/retired as a batch, never partially retried. This method does
        not itself validate selected-root state or enforce the durable claim.
        """
        specs = self._validate_specs(specs)
        manifest = self._load_manifest(manifest_path, protected_root, expected_uid)
        if expected_manifest is not None:
            if type(expected_manifest) is not OperatorLaunchManifest:
                raise BindingError("expected launcher manifest is invalid")
            if manifest != expected_manifest:
                raise BindingError("protected launcher differs from the frozen manifest")
        if (before_popen_check is not None
                and not callable(before_popen_check)):
            raise BindingError("pre-Popen check must be a trusted synchronous callback")
        if any(item.configuration_sha256 != manifest.configuration_sha256 for item in specs):
            raise BindingError("launch specs do not pin the protected configuration")
        launch_record = canonical_json([role_launch_document(item) for item in specs])
        if len(launch_record) > MAX_READY_BYTES:
            raise BindingError("launch role record exceeds its 16 KiB bound")
        with self._state_lock:
            if any(item.generation_sha256 in self._fenced_generations for item in specs):
                raise BindingError("generation is restart fenced before spawn")
            if len(self._owned) >= MAX_OWNED_PROCESSES:
                raise BindingError("owned process registry is full")
            if sum(len(item.specs) for item in self._owned) + len(specs) > MAX_LAUNCH_ROLES:
                raise BindingError("owned role registry is full")
            if before_popen_check is not None:
                # Called only after all protected launcher I/O and immediately
                # before process creation, while ownership/fence state is locked.
                result = before_popen_check()
                if result is not None:
                    if inspect.isawaitable(result):
                        close = getattr(result, "close", None)
                        if callable(close):
                            close()
                    raise BindingError("pre-Popen check must return exactly None")
            process = subprocess.Popen(
                manifest.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
                bufsize=0)
            # Popen returned after start_new_session=True; record its exact
            # handle immediately, before any validation or asynchronous work.
            record = _Owned(process, specs, process.pid, process.pid, manifest)
            self._owned.append(record)
            pending_launch = PendingOwnedLaunch(self, record, self._seal)
            record.pending = pending_launch
            self._check_owned_process(
                process, manifest, record=record, record_initial_pipes=True)
            return pending_launch

    async def observe_ready(self, pending_launch: PendingOwnedLaunch, *,
                            ready_timeout_seconds=10) -> ObservedLaunch:
        """Make the one bounded READY observation for an already-owned process.

        The timeout starts at observation invocation. A failed, cancelled, or
        partial attempt remains consumed; the registered process owner remains
        available for explicit cleanup or retirement, never for reattachment.
        After READY returns, the root-startup caller must reacquire its selected-
        root authority lock and freshly revalidate the exact head/materials and
        current process liveness before marking overall service readiness.
        These caller obligations are not enforced by this process-group API.
        """
        if (type(ready_timeout_seconds) not in (int, float)
                or not 0 < ready_timeout_seconds <= 10):
            raise BindingError("READY timeout must be positive and at most ten seconds")
        with self._state_lock:
            if not (type(pending_launch) is PendingOwnedLaunch
                    and pending_launch._supervisor is self
                    and pending_launch._seal is self._seal
                    and any(item is pending_launch._record for item in self._owned)
                    and pending_launch._record.pending is pending_launch):
                raise BindingError("pending launch is forged or belongs to another supervisor")
            record = pending_launch._record
            if record.observation_attempted:
                raise BindingError("pending launch READY observation was already consumed")
            if any(item.generation_sha256 in self._fenced_generations for item in record.specs):
                raise BindingError("generation became restart fenced before READY observation")
            record.observation_attempted = True
            process = record.process
            manifest = record.manifest
            specs = record.specs
        launch_record = canonical_json([role_launch_document(item) for item in specs])
        deadline = time.monotonic() + float(ready_timeout_seconds)
        fdin = process.stdin.fileno()
        os.set_blocking(fdin, False)
        pending = memoryview(launch_record + b"\n")
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("owned process did not accept its bounded launch record")
            _, writable, _ = select.select([], [fdin], [], min(remaining, 0.05))
            if not writable:
                if process.poll() is not None:
                    raise BindingError("owned process exited before reading launch record")
                await asyncio.sleep(0)
                continue
            try:
                written = os.write(fdin, pending)
            except BrokenPipeError as error:
                raise BindingError("owned process closed its launch record pipe") from error
            pending = pending[written:]
        record.launch_stdin_closed_after_record = True
        process.stdin.close()
        fd = process.stdout.fileno()
        data = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("owned process did not emit READY before deadline")
            readable, _, _ = select.select([fd], [], [], min(remaining, 0.05))
            if not readable:
                if process.poll() is not None:
                    raise BindingError("owned process exited before READY")
                await asyncio.sleep(0)
                continue
            chunk = os.read(fd, min(4096, MAX_READY_BYTES + 1 - len(data)))
            if not chunk:
                raise BindingError("owned process closed stdout before READY")
            data.extend(chunk)
            if len(data) > MAX_READY_BYTES:
                raise BindingError("READY line exceeds its 16 KiB bound")
            if b"\n" in data:
                line, trailing = bytes(data).split(b"\n", 1)
                if trailing:
                    raise BindingError("READY pipe contains bytes after the READY line")
                _parse_ready(line, specs)
                capability = ObservedLaunch(self, record, self._seal)
                with self._state_lock:
                    if any(item.generation_sha256 in self._fenced_generations
                           for item in specs):
                        raise BindingError("generation became restart fenced before READY")
                    self._check_process(process, manifest)
                    record.ready = capability
                    self._observed.append(capability)
                return capability

    async def launch_owned_process(self, manifest_path, *, protected_root, expected_uid,
                                   specs, ready_timeout_seconds=10):
        """Compatibility composition of registered spawn then one READY read.

        This convenience wrapper does not provide selected-root authorization;
        callers requiring claim/Popen serialization must call ``spawn_owned_process``
        under their authority lock, then release it and call ``observe_ready``.
        The operator script is trusted not to escape its process group.
        """
        pending = self.spawn_owned_process(
            manifest_path, protected_root=protected_root, expected_uid=expected_uid,
            specs=specs)
        return await self.observe_ready(
            pending, ready_timeout_seconds=ready_timeout_seconds)

    def validate_observed_launch(self, capability: ObservedLaunch) -> bool:
        with self._state_lock:
            if not (type(capability) is ObservedLaunch
                    and capability._supervisor is self and capability._seal is self._seal
                    and any(item is capability for item in self._observed)
                    and capability._record.ready is capability
                    and not any(spec.generation_sha256 in self._fenced_generations
                                for spec in capability._record.specs)):
                return False
            try:
                self._check_process(capability._record.process,
                                    capability._record.manifest)
            except (BindingError, OSError, ValueError):
                return False
            return True

    @staticmethod
    def _group_absent(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        return False

    async def retire_cohort(self, transition_id: str, expected_old_bindings_digest: str,
                            *, timeout_seconds: float = 40) -> RetirementCapability:
        """Fence a generation and wait for exact owned leaders and groups to retire."""
        import re
        if type(transition_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", transition_id):
            raise BindingError("transition ID must be 32 lowercase hex characters")
        if type(expected_old_bindings_digest) is not str or not re.fullmatch(
                r"[0-9a-f]{64}", expected_old_bindings_digest):
            raise BindingError("old bindings digest must be lowercase SHA-256 hex")
        if (type(timeout_seconds) not in (int, float)
                or not 0 < timeout_seconds <= 40):
            raise BindingError("retirement timeout must be positive and at most forty seconds")
        with self._state_lock:
            generations = {spec.generation_sha256 for item in self._owned for spec in item.specs}
            matches = []
            for candidate_generation in generations:
                candidate = [item for item in self._owned
                             if any(spec.generation_sha256 == candidate_generation
                                    for spec in item.specs)]
                candidate_specs = tuple(sorted(
                    (spec for item in candidate for spec in item.specs),
                    key=lambda spec: spec.identity))
                try:
                    candidate_digest = canonical_role_launch_digest(candidate_specs)
                except BindingError:
                    continue
                if candidate_digest == expected_old_bindings_digest:
                    matches.append((candidate_generation, candidate, candidate_specs))
            if len(matches) != 1:
                raise BindingError("owned cohort differs from the expected old bindings")
            generation, selected, all_specs = matches[0]
            # Include retained, not-yet-ready owners too: they cannot be silently
            # excluded from the old-generation retirement cohort.
            self._fenced_generations.add(generation)  # Fence before observing termination.
        deadline = time.monotonic() + float(timeout_seconds)
        while True:
            complete = True
            for item in selected:
                if item.process.poll() is None:
                    complete = False
                else:
                    item.leader_exited = True
                item.group_gone = self._group_absent(item.pgid)
                if not item.leader_exited or not item.group_gone:
                    complete = False
            if complete:
                if len(self._capabilities) >= MAX_CAPABILITIES:
                    raise BindingError("retirement capability registry is full")
                record = (transition_id, expected_old_bindings_digest,
                          tuple(id(item) for item in selected),
                          (generation, RETIREMENT_EVIDENCE_PROFILE))
                capability = RetirementCapability(self, record, self._seal)
                self._capabilities.append(capability)
                return capability
            if time.monotonic() >= deadline:
                raise TimeoutError("owned process groups remain live or unknown")
            await asyncio.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

    def validate_retirement_capability(self, capability: RetirementCapability, *,
                                       transition_id: str,
                                       expected_old_bindings_digest: str) -> bool:
        if (type(capability) is not RetirementCapability
                or capability._supervisor is not self or capability._seal is not self._seal
                or not any(item is capability for item in self._capabilities)):
            return False
        tid, digest, owner_ids, (generation, profile) = capability._record
        generations = (generation,)
        if profile != RETIREMENT_EVIDENCE_PROFILE:
            return False
        if tid != transition_id or digest != expected_old_bindings_digest:
            return False
        owners = [item for item in self._owned if id(item) in owner_ids]
        if any(spec.generation_sha256 in generations and id(item) not in owner_ids
               for item in self._owned for spec in item.specs):
            return False
        try:
            current_specs = tuple(sorted(
                (spec for item in owners for spec in item.specs),
                key=lambda spec: spec.identity))
            current_digest = canonical_role_launch_digest(current_specs)
        except BindingError:
            return False
        if current_digest != digest:
            return False
        return (len(owners) == len(owner_ids)
                and all(item.process.poll() is not None and self._group_absent(item.pgid)
                        for item in owners)
                and all(generation in self._fenced_generations for generation in generations))

    def terminate_owned_process_group(self, process, *, timeout_seconds: float = 2) -> None:
        """Explicit test/owner cleanup for a registered, verified process group."""
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 5:
            raise BindingError("owned cleanup timeout is outside its bound")
        record = next((item for item in self._owned if item.process is process), None)
        if record is None:
            raise BindingError("cannot signal an unregistered process")
        try:
            pid, pgid = self._check_process(process, record.manifest)
        except (OSError, ValueError) as error:
            raise BindingError("owned process identity cannot be verified") from error
        if pid != record.pid or pgid != record.pgid or record.pgid != record.pid:
            raise BindingError("owned process group identity changed")
        os.killpg(record.pgid, 15)
        deadline = time.monotonic() + float(timeout_seconds)
        while time.monotonic() < deadline:
            record.process.poll()
            if self._group_absent(record.pgid):
                return
            time.sleep(0.01)
        raise TimeoutError("owned process group did not terminate")

    def terminate_owned_generation(self, generation_sha256: str, *,
                                   timeout_seconds: float = 5) -> None:
        """Explicitly clean registered groups for one generation after owner failure.

        This is useful when ``launch_owned_process`` retained a process but
        failed before returning its ObservedLaunch handle. It never signals a
        PID/group not already held and revalidated by this supervisor.
        """
        if type(generation_sha256) is not str or not _HEX64.fullmatch(generation_sha256):
            raise BindingError("generation hash is invalid")
        if (type(timeout_seconds) not in (int, float)
                or not 0 < timeout_seconds <= 5):
            raise BindingError("owned cleanup timeout is outside its bound")
        with self._state_lock:
            records = [record for record in self._owned
                       if any(spec.generation_sha256 == generation_sha256
                              for spec in record.specs)]
        if not records:
            raise BindingError("generation has no registered owned processes")
        for record in records:
            if record.process.poll() is None:
                pid, pgid = self._check_process(record.process, record.manifest)
                if pid != record.pid or pgid != record.pgid or pgid != pid:
                    raise BindingError("owned generation process group identity changed")
                os.killpg(pgid, 15)
            elif not self._group_absent(record.pgid):
                raise BindingError("exited leader has a live group; signal proof is unavailable")
        deadline = time.monotonic() + float(timeout_seconds)
        while True:
            if all(record.process.poll() is not None and self._group_absent(record.pgid)
                   for record in records):
                return
            if time.monotonic() >= deadline:
                raise TimeoutError("owned generation groups did not terminate")
            time.sleep(0.01)
