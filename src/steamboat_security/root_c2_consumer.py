"""Inert, guarded C2 consumer identity binding for the selected root.

This is an admission prerequisite only. It does not create a session, load model
weights, contact a gateway, or report readiness.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import PurePosixPath

from cryptography.hazmat.primitives import serialization

from .certificates import (_key, _pem_certificate, certificate_sha256,
                           public_key_sha256, serial_hex, verify_leaf)
from .clock import Clock
from .codec import canonical_json
from .errors import CredentialError, SnapshotError, StorageError
from .files import safe_read
from .root_c2_coordinator import C2CoordinatorRuntimeBinding, _PolicyRefreshRequired
from .root_c2_runtime import MAX_HEADER_BYTES, MAX_RUNTIME_CONFIGURATION_BYTES, _same_spec, _selected
from .root_c2_selected import make_c2_selected_validation_callback
from .root_runtime import _require_current_role_grants
from .root_transition_launch import RoleLaunchSpec, parse_role_launch_spec, role_launch_document
from .root_transition_storage import RootGenerationStore
from .snapshot import SnapshotStore

_FIELDS = frozenset({"schema_version", "profile", "protected_root", "selected_root",
    "account_id", "device_id", "role", "boot_id", "credential_epoch", "admission_epoch",
    "generation_sha256", "launch_nonce", "certificate_path", "private_key_path",
    "model_id", "runtime_configuration_path", "runtime_configuration_sha256"})
_PROFILE = "native_posix_root_c2_consumer_v1"


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CredentialError("C2 consumer header has duplicate fields")
        result[key] = value
    return result


def _read_header(path, root, uid):
    raw = safe_read(path, root=root, expected_uid=uid, max_bytes=MAX_HEADER_BYTES)
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise CredentialError("C2 consumer header is malformed") from error
    if canonical_json(value) != raw or type(value) is not dict or set(value) != _FIELDS:
        raise CredentialError("C2 consumer header is not closed canonical version 1")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["profile"] != _PROFILE or value["role"] != "consumer"):
        raise CredentialError("C2 consumer profile or role is unsupported")
    for name in ("protected_root", "selected_root", "account_id", "device_id", "role",
                 "boot_id", "generation_sha256", "launch_nonce", "certificate_path",
                 "private_key_path", "runtime_configuration_path", "runtime_configuration_sha256"):
        if type(value[name]) is not str or not value[name]:
            raise CredentialError(f"C2 consumer {name} is invalid")
    for name in ("credential_epoch", "admission_epoch"):
        if type(value[name]) is not int or value[name] < 1:
            raise CredentialError(f"C2 consumer {name} is invalid")
    for name in ("generation_sha256", "runtime_configuration_sha256", "model_id"):
        field_value = value[name]
        if type(field_value) is not str or len(field_value) != 64 or any(
                char not in "0123456789abcdef" for char in field_value):
            raise CredentialError(f"C2 consumer {name} is invalid")
    if len(value["launch_nonce"]) != 32 or any(
            char not in "0123456789abcdef" for char in value["launch_nonce"]):
        raise CredentialError("C2 consumer launch nonce is invalid")
    if any(not PurePosixPath(value[name]).is_absolute()
           for name in ("certificate_path", "private_key_path", "runtime_configuration_path")):
        raise CredentialError("C2 consumer protected paths must be absolute")
    return raw, value


class C2ConsumerRuntimeBinding(C2CoordinatorRuntimeBinding):
    """Consumer-specific loader identity with the shared guarded policy lifecycle."""

    def _files_unchanged(self):
        for path, data in self._file_bytes.items():
            limit = MAX_HEADER_BYTES if path == self._header_path else (
                MAX_RUNTIME_CONFIGURATION_BYTES
                if path == self._paths["runtime"] else 64 * 1024)
            if safe_read(path, root=self._root, expected_uid=self._root_store._uid,
                         max_bytes=limit) != data:
                raise CredentialError("C2 consumer protected material changed; cold restart required")


def load_c2_consumer_binding(*, root_store: RootGenerationStore, clock: Clock,
        expected_launch_spec: RoleLaunchSpec, configuration_path, configuration_root,
        expected_uid: int) -> C2ConsumerRuntimeBinding:
    if (type(root_store) is not RootGenerationStore or type(clock) is not Clock
            or type(expected_launch_spec) is not RoleLaunchSpec
            or expected_launch_spec.role != "consumer"):
        raise CredentialError("C2 consumer loader requires exact store, Clock and consumer spec")
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise StorageError("C2 protected consumer files require POSIX no-follow support")
    if type(expected_uid) is not int or expected_uid != root_store._uid or expected_uid != os.geteuid():
        raise StorageError("C2 consumer protected-file UID differs from root store")
    if root_store._pending_faulted:
        raise StorageError("selected root store is in a faulted state")
    root = os.path.abspath(os.fspath(configuration_root))
    path = os.path.abspath(os.fspath(configuration_path))
    header_bytes, raw = _read_header(path, root, expected_uid)
    selected, cohort = _selected(root_store, clock)
    selected_root = os.path.realpath(os.readlink(f"/proc/self/fd/{root_store._root_fd}"))
    if raw["protected_root"] != root or raw["selected_root"] != selected_root:
        raise CredentialError("C2 consumer header roots differ from trusted roots")
    spec = parse_role_launch_spec(role_launch_document(expected_launch_spec))
    matches = [item for item in cohort.new_specs
               if item.identity == spec.identity and _same_spec(item, spec)]
    if len(matches) != 1 or hashlib.sha256(header_bytes).hexdigest() != spec.configuration_sha256:
        raise CredentialError("C2 consumer is not exact header-pinned selected launch member")
    if ((raw["account_id"], raw["device_id"], raw["role"]) != spec.identity
            or (raw["boot_id"], raw["credential_epoch"], raw["admission_epoch"],
                raw["generation_sha256"], raw["launch_nonce"]) !=
               (spec.boot_id, spec.credential_epoch, spec.admission_epoch,
                spec.generation_sha256, spec.launch_nonce)):
        raise CredentialError("C2 consumer header identity differs from selected launch")
    paths = {"header": path, "certificate": raw["certificate_path"],
             "key": raw["private_key_path"], "runtime": raw["runtime_configuration_path"]}
    cert_pem = safe_read(paths["certificate"], root=root, expected_uid=expected_uid, max_bytes=64 * 1024)
    key_pem = safe_read(paths["key"], root=root, expected_uid=expected_uid, max_bytes=64 * 1024)
    runtime = safe_read(paths["runtime"], root=root, expected_uid=expected_uid,
                        max_bytes=MAX_RUNTIME_CONFIGURATION_BYTES)
    if hashlib.sha256(runtime).hexdigest() != raw["runtime_configuration_sha256"]:
        raise CredentialError("C2 opaque consumer runtime bytes differ from header pin")
    cert, key = _pem_certificate(cert_pem), _key(key_pem)
    cert_public = cert.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    key_public = key.public_key().public_bytes(serialization.Encoding.DER,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
    if (cert_public != key_public or
            (certificate_sha256(cert), public_key_sha256(cert.public_key()), serial_hex(cert.serial_number))
            != (spec.certificate_sha256, spec.public_key_sha256, spec.serial)):
        raise CredentialError("C2 consumer keypair differs from selected launch pins")

    files = {path: header_bytes, paths["certificate"]: cert_pem,
             paths["key"]: key_pem, paths["runtime"]: runtime}
    expected_head = {"sha256": selected.selector_sha256}
    import threading
    policy_lock = threading.RLock()

    def validate_immutable(selector, bundle, active_policy):
        capture = {}
        make_c2_selected_validation_callback(clock=clock, capture=capture)(selector, bundle, active_policy)
        current = capture.get("cohort")
        current_specs = [] if current is None else [x for x in current.new_specs if x.identity == spec.identity]
        if (selector.generation_sha256 != selected.selector.generation_sha256
                or selector.activation_manifest_sha256 != selected.selector.activation_manifest_sha256
                or dict(selector.artifact_sha256) != dict(selected.selector.artifact_sha256)
                or len(current_specs) != 1 or not _same_spec(current_specs[0], spec)):
            raise CredentialError("C2 consumer selected launch changed during policy update")
        for protected_path, protected_data in files.items():
            limit = MAX_HEADER_BYTES if protected_path == path else (
                MAX_RUNTIME_CONFIGURATION_BYTES if protected_path == paths["runtime"] else 64 * 1024)
            if safe_read(protected_path, root=root, expected_uid=expected_uid, max_bytes=limit) != protected_data:
                raise CredentialError("C2 consumer protected material changed during policy update")

    def durable_policy_commit(encoded, revision, digest):
        with policy_lock:
            candidate = SnapshotStore(verification_key_pem=selected.artifacts["snapshot_signer_public.pem"],
                ca_certificate_pem=selected.artifacts["ca_certificate.pem"], clock=clock,
                minimum_revision=selected.selector.policy_revision,
                minimum_policy_digest=selected.selector.policy_digest)
            candidate_view = candidate.install(encoded)
            if candidate_view.revision != revision or candidate_view.policy_digest != digest:
                raise CredentialError("C2 consumer policy metadata differs from signed bytes")
            try:
                committed = root_store.advance_policy(encoded,
                    expected_old_selector_sha256=expected_head["sha256"], clock=clock,
                    validate=validate_immutable)
            except StorageError as stale:
                if "current selector differs from expected old selector" not in str(stale):
                    raise
                fresh, _ = _selected(root_store, clock)
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
                    raise StorageError("concurrent C2 consumer policy head is not the exact incoming bytes") from stale
                committed = fresh.selector_sha256
            expected_head["sha256"] = committed

    store = SnapshotStore(verification_key_pem=selected.artifacts["snapshot_signer_public.pem"],
        ca_certificate_pem=selected.artifacts["ca_certificate.pem"], clock=clock,
        minimum_revision=selected.selector.policy_revision,
        minimum_policy_digest=selected.selector.policy_digest,
        durable_commit=durable_policy_commit)
    store.install(selected.active_policy_snapshot)
    sample = clock.sample()
    view = store.current(sample=sample)
    record = view.credential(spec.serial)
    if record is None or record.identity != spec.identity:
        raise CredentialError("C2 consumer is absent from selected current policy")
    verify_leaf(selected.artifacts["ca_certificate.pem"], cert_pem, now=sample.wall,
        uncertainty_seconds=sample.uncertainty, account_id=record.account_id,
        device_id=record.device_id, role=record.role, serial=record.serial,
        public_key_hash=record.public_key_sha256, certificate_hash=record.certificate_sha256,
        ekus=record.ekus, dns_sans=record.dns_sans, ip_sans=record.ip_sans)
    store.assert_credential_live(view, record, sample)
    _require_current_role_grants(view, sample, record, spec,
        {"model_id": raw["model_id"], "assignment_id": None})
    binding = C2ConsumerRuntimeBinding(root_store=root_store, clock=clock, root=root,
        header_path=path, header=raw, paths=paths, file_bytes=files, runtime_bytes=runtime,
        cert_pem=cert_pem, key_pem=key_pem, spec=spec,
        activation_hash=cohort.activation_manifest_sha256, snapshot_store=store,
        model_id=raw["model_id"])
    binding.assert_live()
    return binding
