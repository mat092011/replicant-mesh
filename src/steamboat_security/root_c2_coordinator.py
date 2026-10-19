"""Guarded local PERSONAL COORDINATOR binding for the C2 selected root.

This loader returns inert role identity, private key, and opaque adapter bytes.
It does not create a channel, start a process, consume a claim, or report READY.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from cryptography.hazmat.primitives import serialization

from .authorization import LocalIdentity
from .certificates import (_key, _pem_certificate, certificate_sha256,
                           public_key_sha256, serial_hex, verify_leaf)
from .clock import Clock
from .codec import canonical_json
from .errors import CredentialError, SnapshotError, StorageError
from .files import safe_read
from .root_c2_runtime import (_selected, _same_spec, MAX_HEADER_BYTES,
                              MAX_RUNTIME_CONFIGURATION_BYTES, MAX_TEARDOWN_SUBSCRIBERS)
from .root_c2_selected import make_c2_selected_validation_callback
from .root_transition_launch import RoleLaunchSpec, parse_role_launch_spec, role_launch_document
from .root_transition_storage import RootGenerationStore
from .snapshot import SnapshotStore

_FIELDS = frozenset({"schema_version", "profile", "protected_root", "selected_root",
    "account_id", "device_id", "role", "boot_id", "credential_epoch", "admission_epoch",
    "generation_sha256", "launch_nonce", "certificate_path", "private_key_path",
    "model_id", "runtime_configuration_path", "runtime_configuration_sha256"})


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CredentialError("C2 coordinator header has duplicate fields")
        result[key] = value
    return result


def _read_header(path, root, uid):
    raw = safe_read(path, root=root, expected_uid=uid, max_bytes=MAX_HEADER_BYTES)
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise CredentialError("C2 coordinator header is malformed") from error
    if canonical_json(value) != raw or type(value) is not dict or set(value) != _FIELDS:
        raise CredentialError("C2 coordinator header is not closed canonical version 1")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["profile"] != "native_posix_root_c2_personal_coordinator_v1"
            or value["role"] != "personal_coordinator"):
        raise CredentialError("C2 coordinator profile or role is unsupported")
    for name in ("protected_root", "selected_root", "account_id", "device_id", "role",
                 "boot_id", "generation_sha256", "launch_nonce", "certificate_path",
                 "private_key_path", "runtime_configuration_path", "runtime_configuration_sha256"):
        if type(value[name]) is not str or not value[name]:
            raise CredentialError(f"C2 coordinator {name} is invalid")
    for name in ("credential_epoch", "admission_epoch"):
        if type(value[name]) is not int or value[name] < 1:
            raise CredentialError(f"C2 coordinator {name} is invalid")
    for name in ("generation_sha256", "runtime_configuration_sha256"):
        if len(value[name]) != 64 or any(c not in "0123456789abcdef" for c in value[name]):
            raise CredentialError(f"C2 coordinator {name} is invalid")
    if type(value["model_id"]) is not str or len(value["model_id"]) != 64 or any(
            c not in "0123456789abcdef" for c in value["model_id"]):
        raise CredentialError("C2 coordinator model pin is invalid")
    if len(value["launch_nonce"]) != 32 or any(c not in "0123456789abcdef" for c in value["launch_nonce"]):
        raise CredentialError("C2 coordinator launch nonce is invalid")
    for name in ("certificate_path", "private_key_path", "runtime_configuration_path"):
        if not PurePosixPath(value[name]).is_absolute():
            raise CredentialError("C2 coordinator protected paths must be absolute")
    return raw, value


@dataclass(frozen=True)
class C2CoordinatorTLSMaterials:
    certificate_pem: bytes
    private_key_pem: bytes = field(repr=False)


class C2CoordinatorRuntimeBinding:
    def __init__(self, *, root_store, clock, root, header_path, header, paths,
                 file_bytes, runtime_bytes, cert_pem, key_pem, spec, activation_hash,
                 snapshot_store, model_id):
        self._root_store, self._clock = root_store, clock
        self._root, self._header_path, self._header = root, header_path, header
        self._paths, self._file_bytes = paths, file_bytes
        self._runtime_bytes, self._cert_pem, self._key_pem = runtime_bytes, cert_pem, key_pem
        self._spec, self._activation_hash, self._snapshot_store = spec, activation_hash, snapshot_store
        self._model_id = model_id
        self._identity = None
        self._tls = C2CoordinatorTLSMaterials(cert_pem, key_pem)
        self._lock = threading.RLock()
        self._invalid = False
        self._reason = None
        self._subscribers = []
        self._notification_faulted = False

    @property
    def local_identity(self):
        self.assert_live()
        return self._identity

    @property
    def tls_materials(self):
        self.assert_live()
        return self._tls

    @property
    def runtime_configuration(self):
        self.assert_live()
        return self._runtime_bytes

    @property
    def launch_spec(self):
        self.assert_live()
        return self._spec

    def subscribe_teardown(self, callback):
        if not callable(callback) or inspect.iscoroutinefunction(callback):
            raise TypeError("teardown notification must be synchronous")
        with self._lock:
            if self._invalid:
                reason = self._reason
            else:
                if len(self._subscribers) >= MAX_TEARDOWN_SUBSCRIBERS:
                    raise CredentialError("C2 teardown subscriber bound exceeded")
                self._subscribers.append(callback)
                return
        self._notify(callback, reason)

    def _notify(self, callback, reason):
        try:
            result = callback(reason)
            if inspect.isawaitable(result):
                close = getattr(result, "close", None)
                if callable(close): close()
                self._notification_faulted = True
        except BaseException:
            self._notification_faulted = True

    def invalidate(self, reason="C2 coordinator binding invalidated"):
        with self._lock:
            if self._invalid:
                return
            self._invalid, self._reason = True, str(reason)[:160]
            callbacks, self._subscribers = tuple(self._subscribers), []
        for callback in callbacks:
            self._notify(callback, self._reason)

    def _files_unchanged(self):
        for path, data in self._file_bytes.items():
            if safe_read(path, root=self._root, expected_uid=self._root_store._uid,
                         max_bytes=MAX_HEADER_BYTES if path == self._header_path else 64 * 1024) != data:
                raise CredentialError("C2 coordinator protected material changed; cold restart required")

    def _selected_policy(self, selected):
        checked = SnapshotStore(verification_key_pem=selected.artifacts["snapshot_signer_public.pem"],
            ca_certificate_pem=selected.artifacts["ca_certificate.pem"], clock=self._clock,
            minimum_revision=selected.selector.policy_revision,
            minimum_policy_digest=selected.selector.policy_digest)
        checked.install(selected.active_policy_snapshot)
        sample = self._clock.sample()
        view = checked.current(sample=sample)
        record = view.credential(self._spec.serial)
        if (record is None or record.identity != self._spec.identity
                or record.credential_epoch != self._spec.credential_epoch
                or record.certificate_sha256 != self._spec.certificate_sha256
                or record.public_key_sha256 != self._spec.public_key_sha256):
            raise CredentialError("selected C2 coordinator credential differs from active policy")
        verify_leaf(selected.artifacts["ca_certificate.pem"], self._cert_pem,
            now=sample.wall, uncertainty_seconds=sample.uncertainty,
            account_id=record.account_id, device_id=record.device_id, role=record.role,
            serial=record.serial, public_key_hash=record.public_key_sha256,
            certificate_hash=record.certificate_sha256, ekus=record.ekus,
            dns_sans=record.dns_sans, ip_sans=record.ip_sans)
        checked.assert_credential_live(view, record, sample)
        grants = [g for g in view.active_grants(sample)
                  if ((g.actor_serial == record.serial and g.actor_boot_id == self._spec.boot_id
                       and g.actor_credential_epoch == record.credential_epoch)
                      or (g.target_serial == record.serial and g.target_boot_id == self._spec.boot_id
                          and g.target_role == "consumer" and g.assignment_id is None
                          and g.target_credential_epoch == record.credential_epoch))]
        if not grants:
            raise CredentialError("selected C2 coordinator has no current route grant")
        if any(grant.model_id != self._model_id for grant in grants):
            raise CredentialError("selected C2 coordinator route grant escapes configured model scope")
        self._identity = LocalIdentity(self._cert_pem, self._spec.boot_id, self._model_id,
                                       None, self._spec.admission_epoch, self._spec.generation_sha256)
        return checked, view, record

    def assert_live(self):
        try:
            with self._lock:
                if self._invalid:
                    raise CredentialError(self._reason or "C2 coordinator binding is invalid")
            selected, cohort = _selected(self._root_store, self._clock)
            specs = [item for item in cohort.new_specs if item.identity == self._spec.identity]
            if (len(specs) != 1 or not _same_spec(specs[0], self._spec)
                    or cohort.activation_manifest_sha256 != self._activation_hash):
                raise CredentialError("selected C2 coordinator changed; cold restart required")
            self._files_unchanged()
            store, view, record = self._selected_policy(selected)
            local_view = self._snapshot_store.current()
            final_selected, final_cohort = _selected(self._root_store, self._clock)
            final_specs = [item for item in final_cohort.new_specs if item.identity == self._spec.identity]
            if (len(final_specs) != 1 or not _same_spec(final_specs[0], self._spec)
                    or final_cohort.activation_manifest_sha256 != self._activation_hash):
                raise CredentialError("selected C2 coordinator changed during guard")
            self._files_unchanged()
            if (local_view.revision != final_selected.selector.policy_revision
                    or local_view.policy_digest != final_selected.selector.policy_digest):
                raise _PolicyRefreshRequired("selected C2 policy advanced; reconcile before admission")
            with self._lock:
                if self._invalid:
                    raise CredentialError(self._reason or "binding invalidated during guard")
                sample = self._clock.sample()
                if sample.latest_wall >= view.expires_at or sample.monotonic >= view.deadline_monotonic:
                    raise SnapshotError("selected C2 policy expired")
                local_record = local_view.credential(self._spec.serial)
                self._snapshot_store.assert_credential_live(local_view, local_record, sample)
                grants = [g for g in local_view.active_grants(sample)
                          if ((g.actor_serial == self._spec.serial and g.actor_boot_id == self._spec.boot_id
                               and g.actor_credential_epoch == self._spec.credential_epoch)
                              or (g.target_serial == self._spec.serial
                                  and g.target_boot_id == self._spec.boot_id
                                  and g.target_role == "consumer" and g.assignment_id is None
                                  and g.target_credential_epoch == self._spec.credential_epoch))]
                if not grants or any(g.model_id != self._model_id for g in grants):
                    raise CredentialError("selected C2 coordinator route authorization changed")
                return None
        except BaseException as exc:
            if isinstance(exc, _PolicyRefreshRequired):
                with self._lock:
                    if self._invalid:
                        raise CredentialError(self._reason or "binding invalidated during policy refresh")
                raise
            self.invalidate(str(exc))
            if isinstance(exc, (CredentialError, SnapshotError, StorageError)):
                raise
            raise CredentialError("C2 coordinator guard failed closed") from exc

    def install_policy(self, encoded):
        self.assert_live()
        try:
            result = self._snapshot_store.install(encoded)
            self.assert_live()
            return result.revision, result.policy_digest
        except BaseException as exc:
            self.invalidate(str(exc))
            raise

    def refresh_selected_policy(self):
        """Reconcile the exact durable selected head, then re-run admission guard."""
        with self._lock:
            if self._invalid:
                raise CredentialError(self._reason or "C2 coordinator binding is invalid")
        selected, cohort = _selected(self._root_store, self._clock)
        specs = [item for item in cohort.new_specs if item.identity == self._spec.identity]
        if len(specs) != 1 or not _same_spec(specs[0], self._spec):
            self.invalidate("selected C2 coordinator launch changed")
            raise CredentialError("selected C2 coordinator launch changed; cold restart required")
        try:
            view = self._snapshot_store.install(selected.active_policy_snapshot)
            if (view.revision != selected.selector.policy_revision
                    or view.policy_digest != selected.selector.policy_digest):
                raise CredentialError("selected C2 policy view differs after refresh")
            self.assert_live()
            return view.revision, view.policy_digest
        except BaseException as exc:
            self.invalidate(str(exc))
            raise


def load_c2_personal_coordinator_binding(*, root_store: RootGenerationStore, clock: Clock,
        expected_launch_spec: RoleLaunchSpec, configuration_path, configuration_root,
        expected_uid: int):
    if (type(root_store) is not RootGenerationStore or type(clock) is not Clock
            or type(expected_launch_spec) is not RoleLaunchSpec
            or expected_launch_spec.role != "personal_coordinator"):
        raise CredentialError("C2 coordinator loader requires exact store, Clock and coordinator spec")
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise StorageError("C2 protected coordinator files require POSIX no-follow support")
    if expected_uid != root_store._uid or expected_uid != os.geteuid():
        raise StorageError("C2 coordinator protected-file UID differs from root store")
    if root_store._pending_faulted:
        raise StorageError("selected root store is in a faulted state")
    root = os.path.abspath(os.fspath(configuration_root))
    path = os.path.abspath(os.fspath(configuration_path))
    header_bytes, raw = _read_header(path, root, expected_uid)
    selected, cohort = _selected(root_store, clock)
    if raw["protected_root"] != root or raw["selected_root"] != os.path.realpath(
            os.readlink(f"/proc/self/fd/{root_store._root_fd}")):
        raise CredentialError("C2 coordinator header roots differ from trusted roots")
    spec = parse_role_launch_spec(role_launch_document(expected_launch_spec))
    matches = [item for item in cohort.new_specs if item.identity == spec.identity and _same_spec(item, spec)]
    if len(matches) != 1 or hashlib.sha256(header_bytes).hexdigest() != spec.configuration_sha256:
        raise CredentialError("C2 coordinator is not exact header-pinned selected launch member")
    if (raw["account_id"], raw["device_id"], raw["role"]) != spec.identity or (
            raw["boot_id"], raw["credential_epoch"], raw["admission_epoch"],
            raw["generation_sha256"], raw["launch_nonce"]) != (
            spec.boot_id, spec.credential_epoch, spec.admission_epoch,
            spec.generation_sha256, spec.launch_nonce):
        raise CredentialError("C2 coordinator header identity differs from selected launch")
    paths = {"header": path, "certificate": raw["certificate_path"],
             "key": raw["private_key_path"], "runtime": raw["runtime_configuration_path"]}
    cert_pem = safe_read(paths["certificate"], root=root, expected_uid=expected_uid, max_bytes=64*1024)
    key_pem = safe_read(paths["key"], root=root, expected_uid=expected_uid, max_bytes=64*1024)
    runtime = safe_read(paths["runtime"], root=root, expected_uid=expected_uid,
                        max_bytes=MAX_RUNTIME_CONFIGURATION_BYTES)
    if hashlib.sha256(runtime).hexdigest() != raw["runtime_configuration_sha256"]:
        raise CredentialError("C2 opaque coordinator runtime bytes differ from header pin")
    cert, key = _pem_certificate(cert_pem), _key(key_pem)
    pub = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if pub != key_pub or (certificate_sha256(cert), public_key_sha256(cert.public_key()),
            serial_hex(cert.serial_number)) != (spec.certificate_sha256, spec.public_key_sha256, spec.serial):
        raise CredentialError("C2 coordinator keypair differs from selected launch pins")
    files = {path: header_bytes, paths["certificate"]: cert_pem,
             paths["key"]: key_pem, paths["runtime"]: runtime}
    sample = clock.sample()
    expected_head = {"sha256": selected.selector_sha256}
    policy_lock = threading.RLock()

    def validate_immutable(selector, bundle, active_policy):
        capture = {}
        make_c2_selected_validation_callback(clock=clock, capture=capture)(selector, bundle, active_policy)
        current = capture.get("cohort")
        selected_specs = [] if current is None else [x for x in current.new_specs if x.identity == spec.identity]
        if (selector.generation_sha256 != selected.selector.generation_sha256
                or selector.activation_manifest_sha256 != selected.selector.activation_manifest_sha256
                or dict(selector.artifact_sha256) != dict(selected.selector.artifact_sha256)
                or len(selected_specs) != 1 or not _same_spec(selected_specs[0], spec)):
            raise CredentialError("C2 coordinator selected launch changed during policy update")
        for protected_path, protected_data in files.items():
            if safe_read(protected_path, root=root, expected_uid=expected_uid,
                         max_bytes=MAX_HEADER_BYTES if protected_path == path else 64*1024) != protected_data:
                raise CredentialError("C2 coordinator protected material changed during policy update")
        return None

    def durable_policy_commit(encoded, revision, digest):
        with policy_lock:
            candidate = SnapshotStore(
                verification_key_pem=selected.artifacts["snapshot_signer_public.pem"],
                ca_certificate_pem=selected.artifacts["ca_certificate.pem"], clock=clock,
                minimum_revision=selected.selector.policy_revision,
                minimum_policy_digest=selected.selector.policy_digest)
            candidate_view = candidate.install(encoded)
            if candidate_view.revision != revision or candidate_view.policy_digest != digest:
                raise CredentialError("C2 coordinator policy metadata differs from signed bytes")
            try:
                committed = root_store.advance_policy(encoded,
                    expected_old_selector_sha256=expected_head["sha256"], clock=clock,
                    validate=validate_immutable)
            except StorageError as stale:
                if "current selector differs from expected old selector" not in str(stale):
                    raise
                fresh, _fresh_cohort = _selected(root_store, clock)
                independent = SnapshotStore(
                    verification_key_pem=fresh.artifacts["snapshot_signer_public.pem"],
                    ca_certificate_pem=fresh.artifacts["ca_certificate.pem"], clock=clock,
                    minimum_revision=fresh.selector.policy_revision,
                    minimum_policy_digest=fresh.selector.policy_digest)
                fresh_view = independent.install(fresh.active_policy_snapshot)
                if (fresh.selector.generation_sha256 != selected.selector.generation_sha256
                        or fresh.selector.activation_manifest_sha256 != selected.selector.activation_manifest_sha256
                        or dict(fresh.selector.artifact_sha256) != dict(selected.selector.artifact_sha256)
                        or fresh_view.revision != revision or fresh_view.policy_digest != digest
                        or fresh.active_policy_snapshot != encoded):
                    raise StorageError("concurrent C2 policy head is not the exact incoming bytes") from stale
                committed = fresh.selector_sha256
            expected_head["sha256"] = committed
            return None

    store = SnapshotStore(verification_key_pem=selected.artifacts["snapshot_signer_public.pem"],
        ca_certificate_pem=selected.artifacts["ca_certificate.pem"], clock=clock,
        minimum_revision=selected.selector.policy_revision,
        minimum_policy_digest=selected.selector.policy_digest,
        durable_commit=durable_policy_commit)
    store.install(selected.active_policy_snapshot)
    view = store.current(sample=sample)
    record = view.credential(spec.serial)
    if record is None or record.identity != spec.identity:
        raise CredentialError("C2 coordinator is absent from selected current policy")
    verify_leaf(selected.artifacts["ca_certificate.pem"], cert_pem, now=sample.wall,
        uncertainty_seconds=sample.uncertainty, account_id=record.account_id,
        device_id=record.device_id, role=record.role, serial=record.serial,
        public_key_hash=record.public_key_sha256, certificate_hash=record.certificate_sha256,
        ekus=record.ekus, dns_sans=record.dns_sans, ip_sans=record.ip_sans)
    store.assert_credential_live(view, record, sample)
    binding = C2CoordinatorRuntimeBinding(root_store=root_store, clock=clock, root=root,
        header_path=path, header=raw, paths=paths, file_bytes=files, runtime_bytes=runtime,
        cert_pem=cert_pem, key_pem=key_pem, spec=spec,
        activation_hash=cohort.activation_manifest_sha256, snapshot_store=store,
        model_id=raw["model_id"])
    binding.assert_live()
    return binding


class _PolicyRefreshRequired(CredentialError):
    """A newer selected head is valid but must be installed before admission."""
