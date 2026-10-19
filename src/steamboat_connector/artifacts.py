"""Bounded, owner-local installation of signed assigned model artifacts."""

from dataclasses import dataclass
import copy
from contextlib import contextmanager
import hashlib
import math
import os
from pathlib import Path
import secrets
import shutil
import stat
import time
from typing import Protocol

from .atomic import AtomicPublishConflict, publish_directory_noreplace
from .catalog import (ARTIFACT_FILENAMES, CHUNK_BYTES, MAX_ASSIGNMENT_BYTES_TOTAL,
                      MAX_FILE_CHUNKS, CatalogError, CatalogVerifier, VerifiedDocument,
                      required_artifact_names)
from .storage import (FileLock, StorageError, atomic_write_json,
                      open_private_directory, read_private_json)
from .validation import valid_typed_id


MAX_INSTALLATIONS = 8
MIN_DISK_HEADROOM_BYTES = 16 * 1024 * 1024
INSTALL_METADATA_RESERVE_BYTES = 64 * 1024
INSTALL_STATE_FILENAME = "artifact-install-state.json"
INSTALL_LOCK_FILENAME = ".artifact-install.lock"
_STAGE_PREFIX = ".artifact-stage-"


class ArtifactInstallError(RuntimeError):
    pass


class ArtifactQuotaError(ArtifactInstallError):
    pass


class ArtifactInstallBusy(ArtifactInstallError):
    """A pinned runtime currently owns immutable artifact-store contents."""


class ArtifactRetriever(Protocol):
    def iter_chunks(self, filename, *, deadline, max_chunk_bytes):
        ...


@dataclass(frozen=True)
class InstallationResult:
    assignment_id: str
    path: Path
    catalog_revision: int
    accounted_bytes: int
    created: bool


class LocalArtifactStoreRetriever:
    def __init__(self, store_root, *, uid=None):
        self.root = Path(os.path.abspath(os.fspath(store_root)))
        self.uid = os.getuid() if uid is None else uid
        self._root_fd = open_private_directory(self.root, uid=self.uid)
        os.close(self._root_fd)

    def iter_chunks(self, filename, *, deadline, max_chunk_bytes=CHUNK_BYTES):
        if filename not in ARTIFACT_FILENAMES or "/" in filename or "\\" in filename:
            raise ArtifactInstallError("artifact source name is not approved")
        if type(max_chunk_bytes) is not int or not 1 <= max_chunk_bytes <= CHUNK_BYTES:
            raise ArtifactInstallError("artifact chunk bound is invalid")
        root_fd = open_private_directory(self.root, uid=self.uid)
        try:
            descriptor = os.open(
                filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=root_fd)
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid
                        or stat.S_IMODE(info.st_mode) & 0o022):
                    raise ArtifactInstallError("local artifact source is not a safe regular file")
                while True:
                    if time.monotonic() >= deadline:
                        raise ArtifactInstallError("artifact retrieval deadline exceeded")
                    chunk = os.read(descriptor, max_chunk_bytes)
                    if not chunk:
                        return
                    yield chunk
            finally:
                os.close(descriptor)
        except OSError as error:
            raise ArtifactInstallError("approved local artifact source is unavailable") from error
        finally:
            os.close(root_fd)


class ArtifactInstaller:
    def __init__(self, root, verifier, *, disk_ceiling_bytes, disk_headroom_bytes,
                 lock_timeout_seconds=5, install_timeout_seconds=300, uid=None,
                 wall_clock=None, monotonic_clock=None, runtime_lock_path=None,
                 read_only=False):
        if not isinstance(verifier, CatalogVerifier):
            raise TypeError("a pinned catalog verifier is required")
        if (type(disk_ceiling_bytes) is not int or not 1 <= disk_ceiling_bytes <= (1 << 40)
                or type(disk_headroom_bytes) is not int
                or disk_headroom_bytes < MIN_DISK_HEADROOM_BYTES
                or disk_headroom_bytes >= disk_ceiling_bytes):
            raise ValueError("explicit disk ceiling and at least 16 MiB protected headroom are required")
        if (type(lock_timeout_seconds) not in (int, float) or lock_timeout_seconds <= 0
                or lock_timeout_seconds > 5 or not math.isfinite(lock_timeout_seconds)
                or type(install_timeout_seconds) is not int
                or not 1 <= install_timeout_seconds <= 300):
            raise ValueError("install lock wait must be at most 5 seconds and deadline at most 300")
        self.root = Path(os.path.abspath(os.fspath(root)))
        self.uid = os.getuid() if uid is None else uid
        self.verifier = verifier
        self.disk_ceiling_bytes = disk_ceiling_bytes
        self.disk_headroom_bytes = disk_headroom_bytes
        self.lock_timeout_seconds = lock_timeout_seconds
        self.install_timeout_seconds = install_timeout_seconds
        self.wall_clock = wall_clock or (lambda: int(time.time()))
        self.monotonic_clock = monotonic_clock or time.monotonic
        self.runtime_lock_path = (Path(runtime_lock_path) if runtime_lock_path is not None
                                  else None)
        if type(read_only) is not bool:
            raise ValueError("read_only must be an explicit boolean")
        self.read_only = read_only
        root_fd = open_private_directory(self.root, create=not read_only, uid=self.uid)
        os.close(root_fd)
        if read_only:
            state = self._load_state(create=False)
            self._check_root_entries(state)
        else:
            with self._mutating():
                state = self._load_state(create=True, allow_legacy=True)
                if state["version"] == 2:
                    self._recover_reservations(state)
                self._check_root_entries(state)

    def _locked(self):
        return FileLock(self.root / INSTALL_LOCK_FILENAME, uid=self.uid,
                        timeout=self.lock_timeout_seconds)

    @contextmanager
    def _mutating(self):
        if self.read_only:
            raise ArtifactInstallError("read-only artifact view cannot mutate its store")
        from .artifact_pin import ArtifactPinBusy, artifact_store_mutation
        try:
            # Serialize mutations on the existing bounded installer gate. The
            # global EX probe MUST remain nonblocking: a runtime may already
            # hold global SH while waiting for this installer gate. On that
            # race we refuse mutation and release the gate for the runtime.
            with self._locked(), artifact_store_mutation(self.root, uid=self.uid):
                yield
        except ArtifactPinBusy as error:
            raise ArtifactInstallBusy("artifact store is pinned by a runtime") from error

    def _state_path(self):
        return self.root / INSTALL_STATE_FILENAME

    def _new_state(self):
        return {
            "version": 2,
            "trusted_key_id": self.verifier.key_id,
            "disk_ceiling_bytes": self.disk_ceiling_bytes,
            "disk_headroom_bytes": self.disk_headroom_bytes,
            "highest_catalog_revision": 0,
            "highest_catalog_sha256": None,
            "active": {"host": None, "coordinator": None},
            "host_slots": {name: None for name in ("worker-1", "worker-2", "worker-3")},
            "installations": {},
            "reservations": {},
        }

    def _validate_state(self, state, *, allow_legacy=False):
        fields = {"version", "trusted_key_id", "disk_ceiling_bytes", "disk_headroom_bytes",
                  "highest_catalog_revision", "highest_catalog_sha256", "active",
                  "installations", "reservations"}
        if (type(state) is dict and state.get("version") == 1 and allow_legacy
                and set(state) == fields):
            legacy = True
        else:
            legacy = False
        if (type(state) is dict and state.get("version") == 1 and not allow_legacy
                and set(state) == fields):
            raise ArtifactInstallError("legacy artifact state requires explicit migration")
        expected = fields if legacy else fields | {"host_slots"}
        if (type(state) is not dict or set(state) != expected
                or type(state["version"]) is not int
                or state["version"] != (1 if legacy else 2)):
            raise ArtifactInstallError("artifact install state is malformed; refusing use")
        if (state["trusted_key_id"] != self.verifier.key_id
                or state["disk_ceiling_bytes"] != self.disk_ceiling_bytes
                or state["disk_headroom_bytes"] != self.disk_headroom_bytes):
            raise ArtifactInstallError("pinned root or owner disk budget changed; explicit migration required")
        revision = state["highest_catalog_revision"]
        digest = state["highest_catalog_sha256"]
        if type(revision) is not int or revision < 0:
            raise ArtifactInstallError("artifact anti-rollback state is invalid")
        if ((revision == 0 and digest is not None)
                or (revision > 0 and (type(digest) is not str or len(digest) != 64
                                     or any(char not in "0123456789abcdef" for char in digest)))):
            raise ArtifactInstallError("artifact catalog high-water mark is invalid")
        if type(state["active"]) is not dict or set(state["active"]) != {"host", "coordinator"}:
            raise ArtifactInstallError("artifact active-role state is malformed")
        if not legacy and (type(state["host_slots"]) is not dict
                           or set(state["host_slots"]) != {"worker-1", "worker-2", "worker-3"}):
            raise ArtifactInstallError("artifact host-slot state is malformed")
        if type(state["installations"]) is not dict or len(state["installations"]) > MAX_INSTALLATIONS:
            raise ArtifactInstallError("artifact installation inventory exceeds its bound")
        if type(state["reservations"]) is not dict or len(state["reservations"]) > MAX_INSTALLATIONS:
            raise ArtifactInstallError("artifact staging inventory exceeds its bound")
        for role, assignment_id in state["active"].items():
            if assignment_id is not None:
                record = state["installations"].get(assignment_id)
                if record is None or record.get("role") != role:
                    raise ArtifactInstallError("active artifact pointer has no matching installation")
        if not legacy:
            for component, assignment_id in state["host_slots"].items():
                if assignment_id is not None:
                    record = state["installations"].get(assignment_id)
                    if record is None or record.get("role") != "host" or record.get("component") != component:
                        raise ArtifactInstallError("active host slot has no matching installation")
            if state["active"]["host"] is not None:
                active_host_ids = set(state["host_slots"].values()) - {None}
                if state["active"]["host"] not in active_host_ids:
                    raise ArtifactInstallError("legacy host pointer is not an active host slot")
        for assignment_id, record in state["installations"].items():
            if (not valid_typed_id(assignment_id, "asg") or type(record) is not dict
                    or set(record) != {"role", "component", "catalog_revision", "catalog_sha256",
                                       "assignment_sha256", "manifest_fingerprint", "directory",
                                       "files", "accounted_bytes"}):
                raise ArtifactInstallError("artifact installation record is malformed")
            if record["role"] not in {"host", "coordinator"}:
                raise ArtifactInstallError("artifact installation role is malformed")
            if (record["directory"] != _install_directory_name(assignment_id)
                    or type(record["files"]) is not list
                    or record["files"] != sorted(set(record["files"]))
                    or any(name not in ARTIFACT_FILENAMES | {"signed-catalog.json", "signed-assignment.json"}
                           for name in record["files"])):
                raise ArtifactInstallError("artifact installation path or file list is malformed")
            if record["role"] == "host":
                if record["component"] not in {"worker-1", "worker-2", "worker-3"}:
                    raise ArtifactInstallError("host installation component is malformed")
            elif record["component"] != "coordinator":
                raise ArtifactInstallError("coordinator installation component is malformed")
            if record["files"] != sorted(set(required_artifact_names(
                    record["role"], record["component"]))
                    | {"signed-catalog.json", "signed-assignment.json"}):
                raise ArtifactInstallError("installation file scope differs from its role")
            if type(record["accounted_bytes"]) is not int or record["accounted_bytes"] <= 0:
                raise ArtifactInstallError("artifact installation accounting is malformed")
            for name in ("catalog_revision",):
                if type(record[name]) is not int or record[name] < 1:
                    raise ArtifactInstallError("artifact installation revision is malformed")
            for name in ("catalog_sha256", "assignment_sha256", "manifest_fingerprint"):
                if type(record[name]) is not str or len(record[name]) != 64 \
                        or any(char not in "0123456789abcdef" for char in record[name]):
                    raise ArtifactInstallError("artifact installation digest is malformed")
            if record["catalog_revision"] > revision:
                raise ArtifactInstallError("artifact installation exceeds persisted anti-rollback state")
        for token, reservation in state["reservations"].items():
            if (type(token) is not str or len(token) != 32
                    or any(char not in "0123456789abcdef" for char in token)
                    or type(reservation) is not dict
                    or set(reservation) != {"stage_directory", "final_directory", "accounted_bytes"}
                    or reservation["stage_directory"] != _STAGE_PREFIX + token
                    or type(reservation["final_directory"]) is not str
                    or not reservation["final_directory"].startswith("install-")
                    or not valid_typed_id(reservation["final_directory"][8:], "asg")
                    or type(reservation["accounted_bytes"]) is not int
                    or reservation["accounted_bytes"] <= 0):
                raise ArtifactInstallError("artifact staging reservation is malformed")
        return state

    def _load_state(self, *, create=False, allow_legacy=False):
        try:
            state = read_private_json(self._state_path(), maximum_size=65_536, uid=self.uid)
        except FileNotFoundError:
            if not create:
                raise ArtifactInstallError("artifact install state is missing")
            state = self._new_state()
            self._write_state(state)
        except StorageError as error:
            raise ArtifactInstallError("artifact install state is unsafe or unreadable") from error
        return self._validate_state(state, allow_legacy=allow_legacy)

    def migrate_state_v1(self):
        """Explicitly migrate the legacy singleton-host state under the pin guard."""
        with self._mutating():
            try:
                state = read_private_json(self._state_path(), maximum_size=65_536, uid=self.uid)
            except (FileNotFoundError, StorageError) as error:
                raise ArtifactInstallError("legacy artifact state is unavailable") from error
            checked = self._validate_state(state, allow_legacy=True)
            if checked["version"] != 1:
                raise ArtifactInstallError("artifact state is not a legacy v1 state")
            migrated = copy.deepcopy(checked)
            migrated["version"] = 2
            migrated["host_slots"] = {name: None for name in ("worker-1", "worker-2", "worker-3")}
            old_host = migrated["active"]["host"]
            if old_host is not None:
                record = migrated["installations"].get(old_host)
                if record is None or record.get("role") != "host" or record.get("component") not in migrated["host_slots"]:
                    raise ArtifactInstallError("legacy host pointer cannot be assigned to a safe component slot")
                migrated["host_slots"][record["component"]] = old_host
            self._validate_state(migrated)
            self._write_state(migrated)
            return migrated

    def _write_state(self, state):
        try:
            atomic_write_json(self._state_path(), state, uid=self.uid)
        except StorageError as error:
            raise ArtifactInstallError("cannot persist artifact install state") from error

    def _check_root_entries(self, state):
        from .artifact_pin import ArtifactPinError, _validate_store_pin_entry
        allowed = {INSTALL_STATE_FILENAME, INSTALL_LOCK_FILENAME}
        allowed.update(record["directory"] for record in state["installations"].values())
        for reservation in state["reservations"].values():
            allowed.add(reservation["stage_directory"])
            allowed.add(reservation["final_directory"])
        root_fd = open_private_directory(self.root, uid=self.uid)
        try:
            names = set(os.listdir(root_fd))
            pin_names = set()
            for name in names - allowed:
                try:
                    if _validate_store_pin_entry(self.root, name, uid=self.uid):
                        pin_names.add(name)
                except ArtifactPinError as error:
                    raise ArtifactInstallError("unsafe artifact pin entry") from error
            if names - allowed - pin_names:
                raise ArtifactInstallError("unrecognized artifact store entry; refusing unsafe cleanup")
        finally:
            os.close(root_fd)

    def _recover_reservations(self, state):
        if not state["reservations"]:
            return
        root_fd = open_private_directory(self.root, uid=self.uid)
        try:
            for token, reservation in list(state["reservations"].items()):
                try:
                    os.stat(reservation["final_directory"], dir_fd=root_fd,
                            follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ArtifactInstallError(
                        "interrupted installation has a final directory; refusing automatic removal")
                expected_names = set(ARTIFACT_FILENAMES) | {"signed-catalog.json", "signed-assignment.json"}
                _remove_managed_directory(root_fd, reservation["stage_directory"],
                                          expected_names, self.uid, allow_absent=True)
                del state["reservations"][token]
            self._write_state(state)
        finally:
            os.close(root_fd)

    def _check_rollback(self, state, catalog):
        revision = catalog.payload["catalog_revision"]
        if revision < state["highest_catalog_revision"]:
            raise ArtifactInstallError("catalog revision rollback rejected")
        if (revision == state["highest_catalog_revision"] and revision > 0
                and catalog.document_sha256 != state["highest_catalog_sha256"]):
            raise ArtifactInstallError("catalog equivocation at an existing revision rejected")

    def _used_bytes(self, state):
        return sum(record["accounted_bytes"] for record in state["installations"].values()) + sum(
            item["accounted_bytes"] for item in state["reservations"].values())

    def _require_disk(self, state, total_bytes, bytes_written=0, *, already_reserved=False):
        additional = 0 if already_reserved else total_bytes
        if self._used_bytes(state) + additional + self.disk_headroom_bytes > self.disk_ceiling_bytes:
            raise ArtifactQuotaError("artifact store disk ceiling would be exceeded")
        try:
            free_bytes = shutil.disk_usage(self.root).free
        except OSError as error:
            raise ArtifactQuotaError("free disk space cannot be checked") from error
        remaining = total_bytes - bytes_written
        if free_bytes < remaining + self.disk_headroom_bytes:
            raise ArtifactQuotaError("disk free-space headroom is insufficient")

    def _verify_current_time(self, catalog_bytes, assignment_bytes, account_id, device_id, role):
        now = self.wall_clock()
        catalog = self.verifier.verify_catalog(catalog_bytes, now=now)
        assignment = self.verifier.verify_assignment(
            assignment_bytes, catalog, account_id=account_id, device_id=device_id,
            role=role, now=now)
        return catalog, assignment

    def install(self, catalog_bytes, assignment_bytes, retriever, *, account_id, device_id, role):
        started = self.monotonic_clock()
        deadline = started + self.install_timeout_seconds
        catalog, assignment = self._verify_current_time(
            catalog_bytes, assignment_bytes, account_id, device_id, role)
        component = assignment.payload["component"]
        names = required_artifact_names(role, component)
        if not names:
            raise ArtifactInstallError("consumer assignments have no model artifacts to install")
        files = catalog.payload["files"]
        selected_bytes = sum(files[name]["size_bytes"] for name in names)
        if selected_bytes > MAX_ASSIGNMENT_BYTES_TOTAL:
            raise ArtifactQuotaError("assigned artifact aggregate exceeds its bound")
        accounted_bytes = (selected_bytes + len(catalog.document_bytes)
                            + len(assignment.document_bytes) + INSTALL_METADATA_RESERVE_BYTES)
        if accounted_bytes > MAX_ASSIGNMENT_BYTES_TOTAL:
            raise ArtifactQuotaError("assigned artifact package exceeds its aggregate bound")
        assignment_id = assignment.payload["assignment_id"]
        final_directory = _install_directory_name(assignment_id)
        stage_token = secrets.token_hex(16)
        stage_directory = _STAGE_PREFIX + stage_token
        state = None
        root_fd = None
        renamed_to_final = False
        ambiguous_final = False
        state_commit_started = False
        with self._mutating():
            if self.monotonic_clock() >= deadline:
                raise ArtifactInstallError("artifact install deadline exceeded")
            catalog, assignment = self._verify_current_time(
                catalog_bytes, assignment_bytes, account_id, device_id, role)
            if self.monotonic_clock() >= deadline:
                raise ArtifactInstallError("artifact install deadline exceeded")
            state = self._load_state()
            self._check_root_entries(state)
            self._check_rollback(state, catalog)
            existing = state["installations"].get(assignment_id)
            if existing is not None:
                same = (existing["catalog_sha256"] == catalog.document_sha256
                        and existing["assignment_sha256"] == assignment.document_sha256
                        and existing["role"] == role and existing["component"] == component)
                active_id = (state["host_slots"].get(component) if role == "host"
                             else state["active"].get(role))
                if not same or active_id != assignment_id:
                    raise ArtifactInstallError("assignment identity already exists; explicit owner replacement required")
                if self.monotonic_clock() >= deadline:
                    raise ArtifactInstallError("artifact install deadline exceeded")
                catalog, assignment = self._verify_current_time(
                    catalog.document_bytes, assignment.document_bytes,
                    account_id, device_id, role)
                if self.monotonic_clock() >= deadline:
                    raise ArtifactInstallError("artifact install deadline exceeded")
                return InstallationResult(assignment_id, self.root / final_directory,
                                          catalog.payload["catalog_revision"],
                                          existing["accounted_bytes"], False)
            if len(state["installations"]) >= MAX_INSTALLATIONS:
                raise ArtifactQuotaError("installation history is full; remove an inactive install first")
            if len(state["reservations"]) >= MAX_INSTALLATIONS:
                raise ArtifactQuotaError("artifact staging reservation limit is full")
            self._require_disk(state, accounted_bytes)
            state["reservations"][stage_token] = {
                "stage_directory": stage_directory,
                "final_directory": final_directory,
                "accounted_bytes": accounted_bytes,
            }
            self._write_state(state)
            try:
                root_fd = open_private_directory(self.root, uid=self.uid)
                os.mkdir(stage_directory, 0o700, dir_fd=root_fd)
                os.fsync(root_fd)
                stage_fd = open_private_directory(self.root / stage_directory, uid=self.uid)
                try:
                    bytes_written = 0
                    for name in names:
                        if self.monotonic_clock() >= deadline:
                            raise ArtifactInstallError("artifact install deadline exceeded")
                        spec = files[name]
                        written = self._write_retrieved_file(
                            stage_fd, name, spec, retriever, deadline, state,
                            accounted_bytes, bytes_written)
                        bytes_written += written
                    for name, raw in (("signed-catalog.json", catalog.document_bytes),
                                      ("signed-assignment.json", assignment.document_bytes)):
                        self._require_disk(state, accounted_bytes, bytes_written,
                                           already_reserved=True)
                        self._write_bytes(stage_fd, name, raw)
                        bytes_written += len(raw)
                    if set(os.listdir(stage_fd)) != set(names) | {
                            "signed-catalog.json", "signed-assignment.json"}:
                        raise ArtifactInstallError("staging directory contains unexpected files")
                    os.fsync(stage_fd)
                finally:
                    os.close(stage_fd)
                if self.monotonic_clock() >= deadline:
                    raise ArtifactInstallError("artifact install deadline exceeded")
                catalog, assignment = self._verify_current_time(
                    catalog.document_bytes, assignment.document_bytes,
                    account_id, device_id, role)
                try:
                    publish_directory_noreplace(root_fd, stage_directory, final_directory)
                except AtomicPublishConflict as error:
                    ambiguous_final = True
                    raise ArtifactInstallError(
                        "final installation path appeared during publication; preserving it and its reservation") from error
                renamed_to_final = True
                os.fsync(root_fd)
                committed_state = copy.deepcopy(state)
                committed_state["installations"][assignment_id] = {
                    "role": role, "component": component,
                    "catalog_revision": catalog.payload["catalog_revision"],
                    "catalog_sha256": catalog.document_sha256,
                    "assignment_sha256": assignment.document_sha256,
                    "manifest_fingerprint": assignment.payload["manifest_fingerprint"],
                    "directory": final_directory,
                    "files": sorted(set(names) | {"signed-catalog.json", "signed-assignment.json"}),
                    "accounted_bytes": accounted_bytes,
                }
                if role == "host":
                    committed_state["host_slots"][component] = assignment_id
                committed_state["active"][role] = assignment_id
                committed_state["highest_catalog_revision"] = catalog.payload["catalog_revision"]
                committed_state["highest_catalog_sha256"] = catalog.document_sha256
                del committed_state["reservations"][stage_token]
                state_commit_started = True
                self._write_state(committed_state)
                state = committed_state
                return InstallationResult(assignment_id, self.root / final_directory,
                                          catalog.payload["catalog_revision"], accounted_bytes, True)
            except Exception as error:
                if state_commit_started:
                    try:
                        persisted_state = read_private_json(
                            self._state_path(), maximum_size=65_536, uid=self.uid)
                    except Exception:
                        raise
                    if persisted_state == committed_state:
                        raise
                    if persisted_state != state:
                        raise
                cleanup_error = None
                if root_fd is not None:
                    try:
                        reservation = state["reservations"].get(stage_token, {})
                        expected_names = set(ARTIFACT_FILENAMES) | {
                            "signed-catalog.json", "signed-assignment.json"}
                        _remove_managed_directory(
                            root_fd, reservation.get("stage_directory", stage_directory),
                            expected_names, self.uid, allow_absent=True)
                        if renamed_to_final:
                            _remove_managed_directory(root_fd, final_directory,
                                                      expected_names, self.uid,
                                                      allow_absent=True)
                        if not ambiguous_final:
                            state["reservations"].pop(stage_token, None)
                            self._write_state(state)
                    except Exception as cleanup_failure:
                        cleanup_error = cleanup_failure
                if cleanup_error is not None:
                    raise ArtifactInstallError(
                        "install failed and bounded staging cleanup is incomplete; reservation retained") from cleanup_error
                if isinstance(error, (ArtifactInstallError, CatalogError)):
                    raise
                if isinstance(error, OSError):
                    raise ArtifactInstallError("artifact write failed; previous installation preserved") from error
                raise
            finally:
                if root_fd is not None:
                    os.close(root_fd)

    def _write_retrieved_file(self, stage_fd, filename, spec, retriever, deadline,
                              state, reservation_bytes, bytes_written):
        digest = hashlib.sha256()
        total = 0
        chunks = 0
        source = None
        primary_error = None
        try:
            source = retriever.iter_chunks(filename, deadline=deadline,
                                           max_chunk_bytes=CHUNK_BYTES)
            descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=stage_fd)
            try:
                for chunk in source:
                    if self.monotonic_clock() >= deadline:
                        raise ArtifactInstallError("artifact install deadline exceeded")
                    chunks += 1
                    if chunks > MAX_FILE_CHUNKS:
                        raise ArtifactInstallError("artifact chunk count exceeds its bound")
                    if type(chunk) is not bytes or not 1 <= len(chunk) <= CHUNK_BYTES:
                        raise ArtifactInstallError("retriever returned an invalid chunk")
                    total += len(chunk)
                    if total > spec["size_bytes"]:
                        raise ArtifactInstallError("retrieved artifact exceeds signed size")
                    self._require_disk(state, reservation_bytes,
                                       bytes_written + total - len(chunk), already_reserved=True)
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise OSError("short artifact write")
                        view = view[written:]
                if total != spec["size_bytes"] or digest.hexdigest() != spec["sha256"]:
                    raise ArtifactInstallError("retrieved artifact size or SHA-256 mismatch")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except (ArtifactInstallError, OSError) as error:
            primary_error = error
            raise
        except Exception as error:
            primary_error = error
            raise ArtifactInstallError("approved retriever failed") from error
        except BaseException as error:
            primary_error = error
            raise
        finally:
            close_source = getattr(source, "close", None)
            if close_source is not None:
                try:
                    close_source()
                except BaseException:
                    if primary_error is None:
                        raise
        return total

    @staticmethod
    def _write_bytes(directory_fd, filename, data):
        descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory_fd)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short metadata write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def deactivate(self, role, *, compute_stopped):
        if role not in {"host", "coordinator"} or type(compute_stopped) is not bool or not compute_stopped:
            raise ArtifactInstallError("role must be stopped before deactivation")
        with self._mutating():
            state = self._load_state()
            if role == "host":
                state["host_slots"] = {name: None for name in state["host_slots"]}
            state["active"][role] = None
            self._write_state(state)

    def remove_installation(self, assignment_id, *, compute_stopped):
        if not valid_typed_id(assignment_id, "asg") or type(compute_stopped) is not bool or not compute_stopped:
            raise ArtifactInstallError("explicit stopped-compute confirmation is required for removal")
        with self._mutating():
            state = self._load_state()
            record = state["installations"].get(assignment_id)
            if record is None:
                return False
            active = (assignment_id in state["host_slots"].values()
                      if record["role"] == "host"
                      else state["active"].get(record["role"]) == assignment_id)
            if active:
                raise ArtifactInstallError("active installation cannot be removed")
            root_fd = open_private_directory(self.root, uid=self.uid)
            try:
                _remove_managed_directory(root_fd, record["directory"],
                                          set(record["files"]), self.uid, allow_absent=True)
                state["installations"].pop(assignment_id)
                self._write_state(state)
            finally:
                os.close(root_fd)
        return True

    def open_view(self, assignment_id, *, account_id, device_id, role, now=None):
        from steamboat_runtime.assigned_artifacts import AssignedArtifactView

        if not valid_typed_id(assignment_id, "asg"):
            raise ArtifactInstallError("assignment identity is malformed")
        with self._locked():
            state = self._load_state()
            record = state["installations"].get(assignment_id)
            active_id = (state["host_slots"].get(record.get("component"))
                         if record is not None and role == "host"
                         else state["active"].get(role))
            if record is None or record.get("role") != role or active_id != assignment_id:
                raise ArtifactInstallError("no active approved artifact installation for role")
            view = AssignedArtifactView(self, assignment_id, account_id=account_id,
                                        device_id=device_id, role=role, now=now)
            view._verify_unlocked(state, record)
            return view


def _install_directory_name(assignment_id):
    if not valid_typed_id(assignment_id, "asg"):
        raise ArtifactInstallError("invalid assignment directory identity")
    return "install-" + assignment_id


def _remove_managed_directory(root_fd, name, expected_files, uid, *, allow_absent):
    if (type(name) is not str or not name or "/" in name or "\\" in name
            or name in {".", ".."}):
        raise ArtifactInstallError("unsafe managed directory name")
    try:
        info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        if allow_absent:
            return
        raise ArtifactInstallError("managed artifact directory disappeared")
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise ArtifactInstallError("managed artifact directory is not an owned private directory")
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
    try:
        names = set(os.listdir(descriptor))
        if names - expected_files:
            raise ArtifactInstallError("managed directory has unrecognized files; refusing removal")
        for filename in names:
            child = os.stat(filename, dir_fd=descriptor, follow_symlinks=False)
            if (not stat.S_ISREG(child.st_mode) or child.st_uid != uid
                    or stat.S_IMODE(child.st_mode) != 0o600):
                raise ArtifactInstallError("unsafe managed artifact file; refusing removal")
        for filename in names:
            os.unlink(filename, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=root_fd)
    os.fsync(root_fd)
