"""Protected, inert runtime material for a selected C2 host component group.

This is a loader prerequisite, not startup, admission, readiness, or claim
authority. Returned identities are guarded by the binding and expire with the
short signed group policy; callers must check the guard at admission and sweep.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import serialization

from .authorization import LocalIdentity
from .certificates import (_key, _pem_certificate, certificate_sha256,
                           public_key_sha256, serial_hex, verify_leaf)
from .channel_certificates import verify_channel_certificate
from .clock import Clock
from .codec import canonical_json
from .errors import CredentialError, SnapshotError, StorageError
from .files import safe_read
from .ids import validate_boot, validate_id
from .root_c2_group_scope import (MAX_SIGNED_POLICY_BYTES,
    verify_c2_host_group_policy)
from .root_c2_selected import C2SelectedCohort, make_c2_selected_validation_callback
from .root_c2_deadlines import DeadlineFloors
from .channel_policy import _verification_key
from .root_transition_launch import RoleLaunchSpec, parse_role_launch_spec, role_launch_document
from .root_transition_storage import RootGenerationStore
from .snapshot import SnapshotStore

MAX_HEADER_BYTES = 16 * 1024
MAX_RUNTIME_CONFIGURATION_BYTES = 16 * 1024
MAX_COMPONENTS = 3
MAX_TEARDOWN_SUBSCRIBERS = 16
_HEADER_FIELDS = frozenset({"schema_version", "profile", "protected_root", "selected_root",
    "account_id", "device_id", "role", "boot_id", "credential_epoch", "admission_epoch",
    "generation_sha256", "launch_nonce", "certificate_path", "private_key_path", "model_id",
    "runtime_configuration_path", "runtime_configuration_sha256", "component_paths",
    "group_policy_path", "group_policy_sha256"})
_PATH_FIELDS = frozenset({"certificate_path", "private_key_path"})


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise CredentialError("C2 protected header has duplicate fields")
        result[k] = v
    return result


def _no_number(_value):
    raise CredentialError("C2 protected header contains a non-integer number")


def _read_json(path, *, root, uid, limit):
    raw = safe_read(path, root=root, expected_uid=uid, max_bytes=limit)
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
            parse_constant=_no_number, parse_float=_no_number)
    except CredentialError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise CredentialError("C2 protected header is malformed JSON") from exc
    if canonical_json(value) != raw:
        raise CredentialError("C2 protected header must be canonical JSON")
    return raw, value


def _header(value):
    if type(value) is not dict or set(value) != _HEADER_FIELDS:
        raise CredentialError("C2 protected header has unknown or missing fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise CredentialError("C2 protected header version is unsupported")
    if value["profile"] != "native_posix_root_c2_host_group_v1":
        raise CredentialError("C2 protected header profile is unsupported")
    for name in ("protected_root", "selected_root", "account_id", "device_id", "role",
                 "boot_id", "generation_sha256", "launch_nonce", "certificate_path",
                 "private_key_path", "model_id", "runtime_configuration_path",
                 "runtime_configuration_sha256", "group_policy_path", "group_policy_sha256"):
        if type(value[name]) is not str or not value[name]:
            raise CredentialError(f"C2 protected header {name} is invalid")
    if value["role"] != "host":
        raise CredentialError("C2 group header must identify a host")
    validate_id(value["account_id"], "acct")
    validate_id(value["device_id"], "dev")
    validate_boot(value["boot_id"])
    if len(value["launch_nonce"]) != 32 or any(c not in "0123456789abcdef" for c in value["launch_nonce"]):
        raise CredentialError("C2 protected header launch nonce is invalid")
    for name in ("credential_epoch", "admission_epoch"):
        if type(value[name]) is not int or not 1 <= value[name] <= 2**63 - 1:
            raise CredentialError(f"C2 protected header {name} is invalid")
    for name in ("generation_sha256", "runtime_configuration_sha256", "group_policy_sha256", "model_id"):
        text = value[name]
        if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
            raise CredentialError(f"C2 protected header {name} is not lowercase SHA-256")
    paths = value["component_paths"]
    if type(paths) is not dict or not 1 <= len(paths) <= MAX_COMPONENTS:
        raise CredentialError("C2 component path map has an invalid size")
    if list(paths) != sorted(paths):
        raise CredentialError("C2 component path map must be sorted")
    for name, pair in paths.items():
        if name not in ("worker-1", "worker-2", "worker-3") or type(pair) is not dict or set(pair) != _PATH_FIELDS:
            raise CredentialError("C2 component path entry is invalid")
        if any(type(pair[k]) is not str or not PurePosixPath(pair[k]).is_absolute() for k in pair):
            raise CredentialError("C2 component paths must be absolute")
    return value


def _root_path(store):
    try:
        return os.path.realpath(os.readlink(f"/proc/self/fd/{store._root_fd}"))
    except (OSError, AttributeError) as exc:
        raise StorageError("selected root path cannot be verified") from exc


def _selected(root_store, clock):
    holder = {}
    callback = make_c2_selected_validation_callback(clock=clock, capture=holder)
    selected = root_store.read_selected(validate=callback)
    cohort = holder.get("cohort")
    if type(cohort) is not C2SelectedCohort:
        raise CredentialError("C2 selected callback did not capture a validated cohort")
    return selected, cohort


def _same_spec(left, right):
    return canonical_json(role_launch_document(left)) == canonical_json(role_launch_document(right))


def _read_pinned(path, root, uid, limit, digest, label):
    if not PurePosixPath(path).is_absolute():
        raise CredentialError(f"{label} path must be absolute")
    data = safe_read(path, root=root, expected_uid=uid, max_bytes=limit)
    if hashlib.sha256(data).hexdigest() != digest:
        raise CredentialError(f"{label} differs from its selected pin")
    return data


@dataclass(frozen=True)
class C2TLSMaterials:
    certificate_pem: bytes
    private_key_pem: bytes = field(repr=False)


@dataclass(frozen=True)
class C2ComponentRuntime:
    component: str
    assignment_id: str
    _identity: LocalIdentity = field(repr=False)
    _tls: C2TLSMaterials = field(repr=False)
    _binding: "C2HostRuntimeBinding" = field(repr=False, compare=False)

    @property
    def identity(self):
        self._binding.assert_live()
        return self._identity

    @property
    def tls_materials(self):
        self._binding.assert_live()
        return self._tls


class C2HostRuntimeBinding:
    """Guarded access to an inert validated host-group binding."""
    def __init__(self, *, root_store, clock, configuration_root, header_path, header_bytes,
                 runtime_path, runtime_bytes, host_cert_path, host_cert, host_key_path,
                 host_key, policy_path, policy_bytes, policy_deadline, policy_expires,
                 channel_files, channel_deadlines, channel_expiries, spec, scope,
                 snapshot_store, components):
        self._root_store, self._clock = root_store, clock
        self._configuration_root = configuration_root
        self._header_path, self._header_bytes = header_path, header_bytes
        self._runtime_path, self._runtime_bytes = runtime_path, runtime_bytes
        self._host_cert_path, self._host_cert = host_cert_path, host_cert
        self._host_key_path, self._host_key = host_key_path, host_key
        self._policy_path, self._policy_bytes = policy_path, policy_bytes
        self._policy_deadline, self._policy_expires = policy_deadline, policy_expires
        self._channel_files, self._channel_deadlines = tuple(channel_files), tuple(channel_deadlines)
        self._channel_expiries = tuple(channel_expiries)
        self._spec, self._scope, self._snapshot_store = spec, scope, snapshot_store
        self._host_identity = LocalIdentity(host_cert, spec.boot_id, scope.model_id,
            None, spec.admission_epoch, spec.generation_sha256)
        self._host_tls = C2TLSMaterials(host_cert, host_key)
        self._components = tuple(components)
        self._lock = threading.RLock()
        self._invalid = False
        self._reason = None
        self._subscribers = []
        self._notification_faulted = False
        self._deadline_floors = DeadlineFloors()

    @property
    def components(self):
        self.assert_live()
        return self._components

    @property
    def scope(self):
        self.assert_live()
        return self._scope

    @property
    def host_identity(self):
        self.assert_live()
        return self._host_identity

    @property
    def host_tls_materials(self):
        self.assert_live()
        return self._host_tls

    def install_policy(self, encoded: bytes):
        """Install a signed head only through the selected durable C2 store."""
        self.assert_refreshable()
        try:
            view = self._snapshot_store.install(encoded)
            self.assert_live()
            return view.revision, view.policy_digest
        except BaseException as exc:
            self.invalidate(str(exc))
            raise

    def subscribe_teardown(self, callback):
        if not callable(callback):
            raise TypeError("teardown subscriber must be callable")
        if inspect.iscoroutinefunction(callback):
            raise TypeError("teardown notification must be synchronous and nonblocking")
        with self._lock:
            if self._invalid:
                reason = self._reason
                already_invalid = True
            else:
                already_invalid = False
            if not already_invalid and len(self._subscribers) >= MAX_TEARDOWN_SUBSCRIBERS:
                raise CredentialError("C2 teardown subscriber bound exceeded")
            if not already_invalid:
                self._subscribers.append(callback)
        if already_invalid:
            self._notify(callback, reason)

    def _notify(self, callback, reason):
        try:
            result = callback(reason)
            if inspect.isawaitable(result):
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                self._notification_faulted = True
        except BaseException:
            self._notification_faulted = True

    def invalidate(self, reason="C2 binding invalidated"):
        with self._lock:
            if self._invalid:
                return
            self._invalid, self._reason = True, str(reason)[:160]
            subscribers = tuple(self._subscribers)
            self._subscribers.clear()
        for callback in subscribers:
            self._notify(callback, self._reason)

    def _check_protected_files(self):
        if (safe_read(self._header_path, root=self._configuration_root,
                      expected_uid=self._root_store._uid, max_bytes=MAX_HEADER_BYTES) != self._header_bytes
                or safe_read(self._runtime_path, root=self._configuration_root,
                      expected_uid=self._root_store._uid, max_bytes=MAX_RUNTIME_CONFIGURATION_BYTES) != self._runtime_bytes
                or safe_read(self._host_cert_path, root=self._configuration_root,
                      expected_uid=self._root_store._uid, max_bytes=64*1024) != self._host_cert
                or safe_read(self._host_key_path, root=self._configuration_root,
                      expected_uid=self._root_store._uid, max_bytes=64*1024) != self._host_key
                or safe_read(self._policy_path, root=self._configuration_root,
                      expected_uid=self._root_store._uid, max_bytes=MAX_SIGNED_POLICY_BYTES) != self._policy_bytes):
            raise CredentialError("pinned C2 protected files changed; cold restart is required")
        for cert_path, cert_bytes, key_path, key_bytes in self._channel_files:
            if (safe_read(cert_path, root=self._configuration_root, expected_uid=self._root_store._uid,
                          max_bytes=64*1024) != cert_bytes
                    or safe_read(key_path, root=self._configuration_root, expected_uid=self._root_store._uid,
                                 max_bytes=64*1024) != key_bytes):
                raise CredentialError("C2 component credential changed; cold restart is required")

    def _assert_selected_policy(self, selected, sample):
        checked = SnapshotStore(
            verification_key_pem=selected.artifacts["snapshot_signer_public.pem"],
            ca_certificate_pem=selected.artifacts["ca_certificate.pem"], clock=self._clock,
            minimum_revision=selected.selector.policy_revision,
            minimum_policy_digest=selected.selector.policy_digest)
        checked.install(selected.active_policy_snapshot)
        current_sample = self._clock.sample()
        view = checked.current(sample=current_sample)
        record = view.credential(self._spec.serial)
        if (record is None or record.identity != self._spec.identity
                or record.credential_epoch != self._spec.credential_epoch
                or record.certificate_sha256 != self._spec.certificate_sha256
                or record.public_key_sha256 != self._spec.public_key_sha256):
            raise CredentialError("selected C2 host credential differs from active policy")
        verify_leaf(selected.artifacts["ca_certificate.pem"], self._host_cert,
            now=current_sample.wall, uncertainty_seconds=current_sample.uncertainty,
            account_id=record.account_id, device_id=record.device_id, role=record.role,
            serial=record.serial, public_key_hash=record.public_key_sha256,
            certificate_hash=record.certificate_sha256, ekus=record.ekus,
            dns_sans=record.dns_sans, ip_sans=record.ip_sans)
        checked.assert_credential_live(view, record, current_sample)
        _check_group_grants(view, current_sample, self._spec, self._scope)
        return checked, view

    def _check_deadlines(self, sample):
        if sample.monotonic >= self._policy_deadline or sample.latest_wall >= self._policy_expires:
            raise CredentialError("C2 signed group policy expired; cold restart is required")
        if any(sample.monotonic >= deadline or sample.latest_wall >= expiry
               for deadline, expiry in zip(self._channel_deadlines, self._channel_expiries)):
            raise CredentialError("C2 worker channel certificate expired")

    def _check_selected_identity(self, selected, cohort):
        specs = [x for x in cohort.new_specs if x.identity == self._spec.identity]
        if (len(specs) != 1 or not _same_spec(specs[0], self._spec)
                or selected.selector.generation_sha256 != self._spec.generation_sha256
                or cohort.activation_manifest_sha256 != self._activation_hash):
            raise CredentialError("selected C2 root changed; cold restart is required")

    def assert_refreshable(self):
        """Check immutable binding/lifetimes and selected policy for safe refresh."""
        self._assert_guard(require_local_head=False)

    def _assert_guard(self, *, require_local_head):
        try:
            with self._lock:
                if self._invalid:
                    raise CredentialError(self._reason or "C2 binding is invalid")
            selected, cohort = _selected(self._root_store, self._clock)
            sample = self._clock.sample()
            self._check_deadlines(sample)
            self._check_protected_files()
            self._check_selected_identity(selected, cohort)
            selected_policy_store, selected_policy_view = self._assert_selected_policy(selected, sample)
            # A local current() may wait on its store lock or durable commit. Do
            # all such work before the final selected read, protected reads, and
            # clock sample; the returned view is the one checked below.
            local_view = None
            if require_local_head:
                local_view = self._snapshot_store.current()
            final_selected, final_cohort = _selected(self._root_store, self._clock)
            self._check_selected_identity(final_selected, final_cohort)
            self._check_protected_files()
            if require_local_head:
                if (local_view is None or local_view.revision != final_selected.selector.policy_revision
                        or local_view.policy_digest != final_selected.selector.policy_digest):
                    raise _C2PolicyRefreshRequired(
                        "selected policy advanced; install the exact selected head before admission")
            with self._lock:
                if self._invalid:
                    raise CredentialError(self._reason or "C2 binding was invalidated during liveness check")
                # This is deliberately the last clock read. No filesystem or
                # store lock is acquired after it, so its bounds cover all work
                # above and the actual return decision.
                final_sample = self._clock.sample()
                self._check_deadlines(final_sample)
                retained_view = self._deadline_floors.retain(selected_policy_view, final_sample)
                if (final_sample.latest_wall >= retained_view.expires_at
                        or final_sample.monotonic >= retained_view.deadline_monotonic):
                    raise SnapshotError("selected C2 policy expired")
                selected_record = retained_view.credential(self._spec.serial)
                if selected_record is None:
                    raise CredentialError("C2 host is missing from freshly selected policy")
                selected_policy_store.assert_credential_live(retained_view, selected_record, final_sample)
                _check_group_grants(retained_view, final_sample, self._spec, self._scope)
                if require_local_head:
                    if (final_sample.latest_wall >= local_view.expires_at
                            or final_sample.monotonic >= local_view.deadline_monotonic):
                        raise SnapshotError("authorization snapshot expired")
                    record = local_view.credential(self._spec.serial)
                    if record is None:
                        raise CredentialError("C2 host is missing from current policy")
                    self._snapshot_store.assert_credential_live(local_view, record, final_sample)
                    _check_group_grants(local_view, final_sample, self._spec, self._scope)
                return None
        except _C2PolicyRefreshRequired:
            with self._lock:
                if self._invalid:
                    raise CredentialError(self._reason or "C2 binding was invalidated during liveness check")
            raise
        except BaseException as exc:
            self.invalidate(str(exc))
            if isinstance(exc, (CredentialError, StorageError, SnapshotError)):
                raise
            raise CredentialError("C2 binding liveness check failed closed") from exc

    def assert_live(self):
        self._assert_guard(require_local_head=True)


class _C2PolicyRefreshRequired(CredentialError):
    """A valid newer selected head needs installation before admission."""


def _check_group_grants(view, sample, spec, scope):
    # Validate all grants that have not expired; future grants can become active
    # during this signed snapshot's lifetime and must remain inside this closure.
    components = {(c.worker_boot_id, c.assignment_id) for c in scope.components}
    record = view.credential(spec.serial)
    if record is None or record.identity != spec.identity:
        raise CredentialError("C2 host is missing from current policy")
    matching = set()
    for grant in view.grants:
        if grant.target_serial != spec.serial or grant.target_role != "host":
            continue
        if grant.not_after <= sample.latest_wall or sample.monotonic >= view.grant_deadlines[grant.identity]:
            continue
        if (grant.target_account_id, grant.target_device_id) != (spec.account_id, spec.device_id):
            continue
        if ((grant.target_boot_id, grant.assignment_id) not in components
                or grant.model_id != scope.model_id
                or grant.target_credential_epoch != spec.credential_epoch
                or grant.target_public_key_sha256 != spec.public_key_sha256):
            raise CredentialError("current policy has a grant outside the selected C2 component tuple")
        matching.add((grant.target_boot_id, grant.assignment_id))
    if matching != components:
        raise CredentialError("current policy does not grant every selected C2 component tuple")


def load_c2_host_runtime_binding(*, root_store: RootGenerationStore, clock: Clock,
        expected_launch_spec: RoleLaunchSpec, configuration_path: str | os.PathLike,
        configuration_root: str | os.PathLike, expected_uid: int,
        operator_verification_key_pem: bytes) -> C2HostRuntimeBinding:
    """Load protected C2 host-group material bound to the selected current root."""
    if type(root_store) is not RootGenerationStore or type(clock) is not Clock:
        raise CredentialError("C2 runtime loader requires exact RootGenerationStore and Clock")
    if type(expected_launch_spec) is not RoleLaunchSpec or expected_launch_spec.role != "host":
        raise CredentialError("C2 runtime loader requires an exact host launch specification")
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise StorageError("C2 protected host-group files require POSIX no-follow support")
    if type(expected_uid) is not int or expected_uid != root_store._uid or expected_uid != os.geteuid():
        raise StorageError("C2 protected-file UID differs from selected root owner")
    if root_store._pending_faulted:
        raise StorageError("selected root store is in a faulted state")
    root = os.path.abspath(os.fspath(configuration_root))
    header_path = os.path.abspath(os.fspath(configuration_path))
    header_bytes, raw = _read_json(header_path, root=root, uid=expected_uid, limit=MAX_HEADER_BYTES)
    raw = _header(raw)
    selected, cohort = _selected(root_store, clock)
    selected_root = _root_path(root_store)
    if (raw["protected_root"] != root or raw["selected_root"] != selected_root
            or not PurePosixPath(raw["protected_root"]).is_absolute()
            or raw["protected_root"] != os.path.normpath(raw["protected_root"])):
        raise CredentialError("C2 header protected or selected root differs from trusted roots")
    spec = parse_role_launch_spec(role_launch_document(expected_launch_spec))
    matches = [x for x in cohort.new_specs if x.identity == spec.identity and _same_spec(x, spec)]
    if len(matches) != 1 or hashlib.sha256(header_bytes).hexdigest() != spec.configuration_sha256:
        raise CredentialError("C2 host launch is not an exact selected header-pinned member")
    if ((raw["account_id"], raw["device_id"], raw["role"]) != spec.identity
            or raw["boot_id"] != spec.boot_id or raw["credential_epoch"] != spec.credential_epoch
            or raw["admission_epoch"] != spec.admission_epoch
            or raw["generation_sha256"] != spec.generation_sha256
            or raw["launch_nonce"] != spec.launch_nonce or raw["model_id"] == ""):
        raise CredentialError("C2 header identity differs from selected launch")
    group_map = {(g.account_id, g.device_id, g.role): g for g in cohort.new_groups}
    scope = group_map.get(spec.identity)
    if scope is None or raw["model_id"] != scope.model_id or set(raw["component_paths"]) != {x.component for x in scope.components}:
        raise CredentialError("C2 header component paths or model differ from selected scope")
    for path_key in ("certificate_path", "private_key_path", "runtime_configuration_path",
                     "group_policy_path"):
        if not PurePosixPath(raw[path_key]).is_absolute():
            raise CredentialError(f"C2 {path_key} must be absolute")
    runtime = safe_read(raw["runtime_configuration_path"], root=root, expected_uid=expected_uid,
                        max_bytes=MAX_RUNTIME_CONFIGURATION_BYTES)
    if hashlib.sha256(runtime).hexdigest() != raw["runtime_configuration_sha256"]:
        raise CredentialError("C2 opaque runtime configuration differs from header pin")
    policy_bytes = _read_pinned(raw["group_policy_path"], root, expected_uid,
                                MAX_SIGNED_POLICY_BYTES, raw["group_policy_sha256"], "C2 group policy")
    if public_key_sha256(_verification_key(operator_verification_key_pem)) != scope.operator_public_key_sha256:
        raise CredentialError("C2 operator key differs from selected scope pin")
    verified_policy = verify_c2_host_group_policy(policy_bytes, operator_verification_key_pem, clock=clock)
    if canonical_json(verified_policy.scope.to_document()) != canonical_json(scope.to_document()):
        raise CredentialError("signed C2 group policy differs from selected scope")

    host_cert_pem = safe_read(raw["certificate_path"], root=root, expected_uid=expected_uid, max_bytes=64*1024)
    host_key_pem = safe_read(raw["private_key_path"], root=root, expected_uid=expected_uid, max_bytes=64*1024)
    host_cert, host_key = _pem_certificate(host_cert_pem), _key(host_key_pem)
    host_pub = host_cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_pub = host_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if host_pub != key_pub or (certificate_sha256(host_cert), public_key_sha256(host_cert.public_key()),
            serial_hex(host_cert.serial_number)) != (spec.certificate_sha256, spec.public_key_sha256, spec.serial):
        raise CredentialError("protected C2 host keypair differs from selected credential pins")
    # Resolve and pin every component file before constructing SnapshotStore:
    # its initial install invokes the durable callback synchronously.
    component_material, channel_deadlines, channel_expiries = [], [], []
    components = []
    policy_sample = clock.sample()
    for component in scope.components:
        paths = raw["component_paths"][component.component]
        cert_pem = safe_read(paths["certificate_path"], root=root, expected_uid=expected_uid, max_bytes=64*1024)
        key_pem = safe_read(paths["private_key_path"], root=root, expected_uid=expected_uid, max_bytes=64*1024)
        cert, key = _pem_certificate(cert_pem), _key(key_pem)
        if cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
            raise CredentialError("C2 component private key does not match its certificate")
        channel = verify_channel_certificate(cert_pem, selected.artifacts["ca_certificate.pem"],
            kind="worker_stream", expected_identity={"account_id": spec.account_id,
                "device_id": spec.device_id, "host_serial": spec.serial,
                "credential_epoch": spec.credential_epoch}, now=policy_sample.wall,
            uncertainty_seconds=policy_sample.uncertainty)
        if (channel.certificate_sha256 != component.channel_certificate_sha256
                or channel.public_key_sha256 != component.channel_public_key_sha256):
            raise CredentialError("C2 component channel certificate differs from selected scope pin")
        deadline = policy_sample.monotonic + channel.not_after.timestamp() - policy_sample.latest_wall
        channel_deadlines.append(deadline)
        channel_expiries.append(channel.not_after.timestamp())
        component_material.append((paths["certificate_path"], cert_pem, paths["private_key_path"], key_pem))
        components.append(C2ComponentRuntime(component.component, component.assignment_id,
            LocalIdentity(host_cert_pem, component.worker_boot_id, scope.model_id,
                component.assignment_id, spec.admission_epoch, spec.generation_sha256),
            C2TLSMaterials(cert_pem, key_pem), None))
    sample = clock.sample()
    pinned_artifacts = dict(selected.selector.artifact_sha256)
    expected_head = {"sha256": selected.selector_sha256}
    head_lock = threading.RLock()

    def validate_immutable(selector_value, bundle_value, active_policy_value):
        # RootGenerationStore invokes this inside its transaction. Never query
        # SnapshotStore here; that would re-enter its durable commit lock.
        if (selector_value.generation_sha256 != selected.selector.generation_sha256
                or selector_value.activation_manifest_sha256 != selected.selector.activation_manifest_sha256
                or dict(selector_value.artifact_sha256) != pinned_artifacts):
            raise CredentialError("selected C2 generation artifacts changed; cold restart is required")
        holder = {}
        callback = make_c2_selected_validation_callback(clock=clock, capture=holder)
        callback(selector_value, bundle_value, active_policy_value)
        current_cohort = holder["cohort"]
        current_spec = [x for x in current_cohort.new_specs if x.identity == spec.identity]
        current_scope = next((x for x in current_cohort.new_groups
                              if (x.account_id, x.device_id, x.role) == spec.identity), None)
        if (len(current_spec) != 1 or not _same_spec(current_spec[0], spec)
                or current_scope is None
                or canonical_json(current_scope.to_document()) != canonical_json(scope.to_document())):
            raise CredentialError("selected C2 launch or component scope changed; cold restart is required")
        if (safe_read(header_path, root=root, expected_uid=expected_uid,
                      max_bytes=MAX_HEADER_BYTES) != header_bytes
                or safe_read(raw["runtime_configuration_path"], root=root, expected_uid=expected_uid,
                      max_bytes=MAX_RUNTIME_CONFIGURATION_BYTES) != runtime
                or safe_read(raw["certificate_path"], root=root, expected_uid=expected_uid,
                      max_bytes=64*1024) != host_cert_pem
                or safe_read(raw["private_key_path"], root=root, expected_uid=expected_uid,
                      max_bytes=64*1024) != host_key_pem
                or safe_read(raw["group_policy_path"], root=root, expected_uid=expected_uid,
                      max_bytes=MAX_SIGNED_POLICY_BYTES) != policy_bytes):
            raise CredentialError("C2 immutable protected files changed; cold restart is required")
        for cert_path, cert_data, key_path, key_data in component_material:
            if (safe_read(cert_path, root=root, expected_uid=expected_uid, max_bytes=64*1024) != cert_data
                    or safe_read(key_path, root=root, expected_uid=expected_uid, max_bytes=64*1024) != key_data):
                raise CredentialError("C2 component files changed; cold restart is required")
        return None

    def durable_policy_commit(encoded, revision, policy_digest):
        with head_lock:
            checked = SnapshotStore(
                verification_key_pem=selected.artifacts["snapshot_signer_public.pem"],
                ca_certificate_pem=selected.artifacts["ca_certificate.pem"], clock=clock,
                minimum_revision=selected.selector.policy_revision,
                minimum_policy_digest=selected.selector.policy_digest)
            candidate_view = checked.install(encoded)
            if candidate_view.revision != revision or candidate_view.policy_digest != policy_digest:
                raise CredentialError("C2 candidate policy metadata differs from signed bytes")
            try:
                committed = root_store.advance_policy(encoded,
                    expected_old_selector_sha256=expected_head["sha256"], clock=clock,
                    validate=validate_immutable)
            except StorageError as stale:
                if "current selector differs from expected old selector" not in str(stale):
                    raise
                fresh, fresh_cohort = _selected(root_store, clock)
                validate_immutable(fresh.selector, fresh.artifacts,
                                   fresh.active_policy_snapshot)
                independent = SnapshotStore(
                    verification_key_pem=fresh.artifacts["snapshot_signer_public.pem"],
                    ca_certificate_pem=fresh.artifacts["ca_certificate.pem"], clock=clock,
                    minimum_revision=fresh.selector.policy_revision,
                    minimum_policy_digest=fresh.selector.policy_digest)
                fresh_view = independent.install(fresh.active_policy_snapshot)
                if (fresh.selector.generation_sha256 != selected.selector.generation_sha256
                        or fresh.selector.activation_manifest_sha256 != selected.selector.activation_manifest_sha256
                        or dict(fresh.selector.artifact_sha256) != pinned_artifacts
                        or fresh_view.revision != revision
                        or fresh_view.policy_digest != policy_digest
                        or fresh.active_policy_snapshot != encoded):
                    raise StorageError("concurrent C2 policy head is not the exact incoming signed bytes") from stale
                committed = root_store.advance_policy(encoded,
                    expected_old_selector_sha256=fresh.selector_sha256, clock=clock,
                    validate=validate_immutable)
            expected_head["sha256"] = committed
        return None

    store = SnapshotStore(verification_key_pem=selected.artifacts["snapshot_signer_public.pem"],
        ca_certificate_pem=selected.artifacts["ca_certificate.pem"], clock=clock,
        minimum_revision=selected.selector.policy_revision,
        minimum_policy_digest=selected.selector.policy_digest,
        durable_commit=durable_policy_commit)
    try:
        store.install(selected.active_policy_snapshot)
        view = store.current(sample=clock.sample())
        sample = clock.sample()
        record = view.credential(spec.serial)
        if record is None or record.identity != spec.identity or record.credential_epoch != spec.credential_epoch:
            raise CredentialError("selected C2 host credential differs from signed policy")
        verify_leaf(selected.artifacts["ca_certificate.pem"], host_cert_pem,
            now=sample.wall, uncertainty_seconds=sample.uncertainty,
            account_id=record.account_id, device_id=record.device_id, role=record.role,
            serial=record.serial, public_key_hash=record.public_key_sha256,
            certificate_hash=record.certificate_sha256, ekus=record.ekus,
            dns_sans=record.dns_sans, ip_sans=record.ip_sans)
        store.assert_credential_live(view, record, sample)
        _check_group_grants(view, sample, spec, scope)
    except SnapshotError as exc:
        raise CredentialError("selected C2 active policy is not currently valid") from exc

    binding = C2HostRuntimeBinding(root_store=root_store, clock=clock,
        configuration_root=root, header_path=header_path, header_bytes=header_bytes,
        runtime_path=raw["runtime_configuration_path"], runtime_bytes=runtime,
        host_cert_path=raw["certificate_path"], host_cert=host_cert_pem,
        host_key_path=raw["private_key_path"], host_key=host_key_pem,
        policy_path=raw["group_policy_path"], policy_bytes=policy_bytes,
        policy_deadline=verified_policy.deadline_monotonic, policy_expires=verified_policy.expires_at,
        channel_files=component_material, channel_deadlines=channel_deadlines,
        channel_expiries=channel_expiries,
        spec=spec, scope=scope, snapshot_store=store, components=())
    binding._activation_hash = cohort.activation_manifest_sha256
    binding._components = tuple(C2ComponentRuntime(c.component, c.assignment_id,
        c._identity, c._tls, binding) for c in components)
    binding.assert_live()
    return binding
