"""Bind a protected local role credential to the selected root generation.

This is a binding seam, not process activation or readiness evidence. It does
not consume claims, create a fresh incarnation, spawn a process, or establish
that a worker/coordinator loaded its runtime or is ready. The returned nested
runtime configuration remains inert bytes for a fixed role-specific adapter.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .authorization import LocalIdentity
from .certificates import (_key, _pem_certificate, certificate_sha256,
                           public_key_sha256, serial_hex, verify_leaf)
from .clock import Clock
from .codec import canonical_json
from .errors import CredentialError, SnapshotError, StorageError
from .files import safe_read
from .ids import validate_id
from .root_transition_launch import (RoleLaunchSpec, canonical_role_launch_digest,
                                     parse_role_launch_spec, role_launch_document)
from .root_transition_policy import ACTIVATION_MANIFEST_DOMAIN
from .root_transition_storage import RootGenerationStore
from .snapshot import SnapshotStore, canonical_policy_digest

MAX_HEADER_BYTES = 16 * 1024
MAX_RUNTIME_CONFIGURATION_BYTES = 16 * 1024
_FIELDS = frozenset({
    "schema_version", "profile", "protected_root", "selected_root",
    "account_id", "device_id", "role", "boot_id", "credential_epoch",
    "admission_epoch", "generation_sha256", "launch_nonce",
    "certificate_path", "private_key_path", "model_id", "assignment_id",
    "runtime_configuration_path", "runtime_configuration_sha256",
})
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_HEX32 = re.compile(r"^[0-9a-f]{32}$", re.ASCII)


@dataclass(frozen=True)
class TLSMaterials:
    certificate_pem: bytes
    private_key_pem: bytes = field(repr=False)


@dataclass(frozen=True)
class RootRuntimeBinding:
    """A live binding whose caller-owned RootGenerationStore must remain open."""
    local_identity: LocalIdentity
    snapshot_store: SnapshotStore
    tls_materials: TLSMaterials
    runtime_configuration: bytes = field(repr=False)
    launch_spec: RoleLaunchSpec
    configuration_header: bytes = field(repr=False)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CredentialError("role configuration contains a duplicate field")
        result[key] = value
    return result


def _reject_number(_value):
    raise CredentialError("role configuration has a non-integer numeric value")


def _root_path(store: RootGenerationStore) -> str:
    try:
        path = os.readlink(f"/proc/self/fd/{store._root_fd}")
    except (OSError, AttributeError) as error:
        raise StorageError("root store path cannot be verified on this platform") from error
    return os.path.realpath(path)


def _read_json(path, *, root, expected_uid, limit, label):
    raw = safe_read(path, root=root, expected_uid=expected_uid, max_bytes=limit)
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"),
                           object_pairs_hook=_pairs, parse_constant=_reject_number,
                           parse_float=_reject_number)
    except CredentialError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise CredentialError(f"{label} is malformed JSON") from error
    if canonical_json(value) != raw:
        raise CredentialError(f"{label} is not canonical JSON")
    return raw, value


def _configuration_header(raw):
    if type(raw) is not dict or set(raw) != _FIELDS:
        raise CredentialError("role configuration header has unknown or missing fields")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise CredentialError("role configuration schema version is invalid")
    if type(raw["profile"]) is not str or raw["profile"] != "native_posix_root_role_v1":
        raise CredentialError("role configuration profile is unsupported")
    for key in ("protected_root", "selected_root", "certificate_path", "private_key_path",
                "runtime_configuration_path", "account_id", "device_id", "role",
                "boot_id", "launch_nonce", "generation_sha256", "runtime_configuration_sha256",
                "model_id"):
        if type(raw[key]) is not str or not raw[key]:
            raise CredentialError(f"role configuration {key} is invalid")
    for key in ("credential_epoch", "admission_epoch"):
        if type(raw[key]) is not int or raw[key] < 1:
            raise CredentialError(f"role configuration {key} is invalid")
    if raw["assignment_id"] is not None and type(raw["assignment_id"]) is not str:
        raise CredentialError("role configuration assignment ID is invalid")
    if not _HEX32.fullmatch(raw["launch_nonce"]):
        raise CredentialError("role configuration launch nonce is invalid")
    if any(not _HEX64.fullmatch(raw[k]) for k in
           ("generation_sha256", "runtime_configuration_sha256", "model_id")):
        raise CredentialError("role configuration hash field is invalid")
    return raw


def _selected_binding(selector, bundle, active_policy):
    """Trusted store callback: verify manifest and exact selected launch cohort."""
    try:
        manifest = json.loads(bundle["activation_manifest.json"].decode("utf-8"))
        expected_fields = {
            "domain", "version", "transition_id", "preparation_intent_sha256",
            "issuance_manifest_sha256", "old_ca_sha256", "new_ca_sha256",
            "old_snapshot_key_sha256", "new_snapshot_key_sha256", "old_launch_digest",
            "new_launch_digest", "old_launch_specs", "new_launch_specs",
            "policy_revision", "policy_digest", "policy_payload_sha256", "new_certificates",
        }
        if (type(manifest) is not dict or manifest.get("domain") != ACTIVATION_MANIFEST_DOMAIN
                or set(manifest) != expected_fields
                or type(manifest.get("version")) is not int or manifest["version"] != 1
                or canonical_json(manifest) != bundle["activation_manifest.json"]):
            raise CredentialError("selected activation manifest is malformed")
        baseline_envelope = json.loads(bundle["policy_snapshot.json"].decode("utf-8"))
        baseline_payload = baseline_envelope.get("payload") if type(baseline_envelope) is dict else None
        if (type(baseline_payload) is not dict
                or type(baseline_payload.get("revision")) is not int
                or type(manifest.get("policy_revision")) is not int
                or type(manifest.get("policy_digest")) is not str
                or manifest.get("policy_revision") != baseline_payload.get("revision")
                or manifest.get("policy_digest") != canonical_policy_digest(baseline_payload)
                or manifest.get("policy_payload_sha256") != hashlib.sha256(
                    canonical_json(baseline_payload)).hexdigest()
                or manifest.get("new_launch_digest") is None):
            raise CredentialError("selected activation manifest differs from selector pins")
        ca = _pem_certificate(bundle["ca_certificate.pem"])
        signer = serialization.load_pem_public_key(bundle["snapshot_signer_public.pem"])
        if (manifest.get("new_ca_sha256") != certificate_sha256(ca)
                or manifest.get("new_snapshot_key_sha256") != public_key_sha256(signer)):
            raise CredentialError("selected authorities differ from activation manifest pins")
        launch_raw = json.loads(bundle["new_launch_specs.json"].decode("utf-8"))
        if type(launch_raw) is not list:
            raise CredentialError("selected launch plan is malformed")
        specs = tuple(parse_role_launch_spec(item) for item in launch_raw)
        digest = canonical_role_launch_digest(specs)
        documents = [role_launch_document(item) for item in specs]
        if (digest != manifest["new_launch_digest"]
                or canonical_json(manifest["new_launch_specs"]) != canonical_json(documents)):
            raise CredentialError("selected launch plan differs from activation manifest")
        if any(item.generation_sha256 != selector.generation_sha256 for item in specs):
            raise CredentialError("selected launch plan generation differs from selector")
        if canonical_json([role_launch_document(item) for item in specs]) != bundle["new_launch_specs.json"]:
            raise CredentialError("selected launch plan is not canonical")
        old_raw = json.loads(bundle["old_launch_specs.json"].decode("utf-8"))
        if type(old_raw) is not list:
            raise CredentialError("selected previous launch plan is malformed")
        old_specs = tuple(parse_role_launch_spec(item) for item in old_raw)
        if (canonical_role_launch_digest(old_specs) != manifest["old_launch_digest"]
                or canonical_json(manifest["old_launch_specs"])
                    != canonical_json([role_launch_document(item) for item in old_specs])
                or canonical_json([role_launch_document(item) for item in old_specs])
                    != bundle["old_launch_specs.json"]):
            raise CredentialError("selected previous launch plan differs from activation manifest")
        expected_new_certs = [{
            "identity": list(item.identity), "serial": item.serial,
            "certificate_sha256": item.certificate_sha256,
            "public_key_sha256": item.public_key_sha256,
        } for item in specs]
        if canonical_json(manifest["new_certificates"]) != canonical_json(expected_new_certs):
            raise CredentialError("selected certificate pins differ from launch plan")
        return specs
    except CredentialError:
        raise
    except (KeyError, UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise CredentialError("selected root activation data is malformed") from error


def load_root_runtime_binding(*, root_store: RootGenerationStore, clock: Clock,
                              expected_launch_spec: RoleLaunchSpec,
                              configuration_path: str | os.PathLike,
                              configuration_root: str | os.PathLike,
                              expected_uid: int) -> RootRuntimeBinding:
    """Load protected local credentials and bind them to selected current policy.

    The caller supplies declarations; this function checks them against the
    selected durable generation and current signed policy. The caller must keep
    ``root_store`` open for the returned binding's lifetime. It makes no claim
    that a supervisor consumed a launch claim or that a process is ready.
    """
    if type(root_store) is not RootGenerationStore or type(clock) is not Clock:
        raise CredentialError("root runtime loader requires exact store and Clock objects")
    if type(expected_launch_spec) is not RoleLaunchSpec:
        raise CredentialError("root runtime loader requires an exact launch specification")
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise StorageError("root-bound role files require POSIX no-follow support")
    if (type(expected_uid) is not int or expected_uid != root_store._uid
            or expected_uid != os.geteuid()):
        raise StorageError("configuration UID differs from selected root store owner")
    if root_store._pending_faulted:
        raise StorageError("selected root store is in a faulted transaction state")
    config_root = os.path.abspath(os.fspath(configuration_root))
    raw_bytes, raw = _read_json(configuration_path, root=config_root,
                                expected_uid=expected_uid, limit=MAX_HEADER_BYTES,
                                label="role configuration header")
    raw = _configuration_header(raw)
    selected_root_path = _root_path(root_store)
    if (not Path(raw["protected_root"]).is_absolute()
            or raw["protected_root"] != os.path.normpath(raw["protected_root"])
            or os.path.abspath(raw["protected_root"]) != config_root):
        raise CredentialError("role protected root differs from configuration root")

    selected_holder = {}
    def validate_selected(selector, bundle, active_policy):
        specs = _selected_binding(selector, bundle, active_policy)
        selected_holder["selector"] = selector
        selected_holder["bundle"] = bundle
        selected_holder["specs"] = specs
    selected = root_store.read_selected(validate=validate_selected)
    selector = selected.selector
    if (not Path(raw["selected_root"]).is_absolute()
            or raw["selected_root"] != os.path.normpath(raw["selected_root"])
            or os.path.abspath(raw["selected_root"]) != selected_root_path):
        raise CredentialError("configuration names a different selected generation")
    spec = parse_role_launch_spec(role_launch_document(expected_launch_spec))
    selected_specs = selected_holder["specs"]
    members = [item for item in selected_specs if item.identity == spec.identity]
    if len(members) != 1 or canonical_json(role_launch_document(members[0])) != canonical_json(
            role_launch_document(spec)):
        raise CredentialError("caller launch specification is not an exact selected-plan member")
    if (spec.generation_sha256 != selector.generation_sha256
            or spec.configuration_sha256 != hashlib.sha256(raw_bytes).hexdigest()):
        raise CredentialError("role configuration hash or generation differs from selected launch")
    config_identity = (raw["account_id"], raw["device_id"], raw["role"])
    if (config_identity != spec.identity or raw["boot_id"] != spec.boot_id
            or raw["credential_epoch"] != spec.credential_epoch
            or raw["admission_epoch"] != spec.admission_epoch
            or raw["generation_sha256"] != spec.generation_sha256
            or raw["launch_nonce"] != spec.launch_nonce):
        raise CredentialError("role configuration identity differs from selected launch")
    if raw["assignment_id"] is not None and not re.fullmatch(r"asg_[0-9a-f]{32}", raw["assignment_id"]):
        raise CredentialError("role assignment ID is invalid")
    validate_id(raw["account_id"], "acct")
    validate_id(raw["device_id"], "dev")
    if raw["assignment_id"] is not None:
        validate_id(raw["assignment_id"], "asg")
    for key in ("certificate_path", "private_key_path", "runtime_configuration_path"):
        if not Path(raw[key]).is_absolute():
            raise CredentialError(f"role configuration {key} must be absolute")
    cert_pem = safe_read(raw["certificate_path"], root=config_root,
                         expected_uid=expected_uid, max_bytes=64 * 1024)
    key_pem = safe_read(raw["private_key_path"], root=config_root,
                        expected_uid=expected_uid, max_bytes=64 * 1024)
    runtime_bytes = safe_read(raw["runtime_configuration_path"], root=config_root,
                              expected_uid=expected_uid,
                              max_bytes=MAX_RUNTIME_CONFIGURATION_BYTES)
    if hashlib.sha256(runtime_bytes).hexdigest() != raw["runtime_configuration_sha256"]:
        raise CredentialError("runtime configuration bytes differ from protected pin")
    cert = _pem_certificate(cert_pem)
    key = _key(key_pem)
    cert_key = cert.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    key_public = key.public_key().public_bytes(serialization.Encoding.DER,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert_key != key_public:
        raise CredentialError("protected private key does not match role certificate")
    if (certificate_sha256(cert) != spec.certificate_sha256
            or public_key_sha256(cert.public_key()) != spec.public_key_sha256
            or serial_hex(cert.serial_number) != spec.serial):
        raise CredentialError("protected leaf differs from selected launch pins")

    # The runtime verifier and the protected selector share one durable policy
    # head.  RootGenerationStore is caller-owned and must outlive this binding.
    # The callback below only validates immutable generation material; it must
    # never query this SnapshotStore while its durable hook is running.
    expected_head = {"sha256": selected.selector_sha256}
    head_lock = threading.RLock()

    def validate_immutable(selector_value, bundle_value, active_policy_value):
        # The selected generation may advance its policy only while this exact
        # protected local role configuration and its referenced files remain.
        if (safe_read(configuration_path, root=config_root, expected_uid=expected_uid,
                       max_bytes=MAX_HEADER_BYTES) != raw_bytes
                or safe_read(raw["runtime_configuration_path"], root=config_root,
                             expected_uid=expected_uid,
                             max_bytes=MAX_RUNTIME_CONFIGURATION_BYTES) != runtime_bytes
                or safe_read(raw["certificate_path"], root=config_root,
                             expected_uid=expected_uid, max_bytes=64 * 1024) != cert_pem
                or safe_read(raw["private_key_path"], root=config_root,
                             expected_uid=expected_uid, max_bytes=64 * 1024) != key_pem):
            raise CredentialError("protected local role configuration changed; cold restart is required")
        specs_value = _selected_binding(selector_value, bundle_value, active_policy_value)
        if (selector_value.generation_sha256 != selector.generation_sha256
                or selector_value.activation_manifest_sha256 != selector.activation_manifest_sha256
                or dict(selector_value.artifact_sha256) != dict(selector.artifact_sha256)
                or canonical_json([role_launch_document(item) for item in specs_value])
                    != canonical_json([role_launch_document(item) for item in selected_specs])):
            raise CredentialError("root generation or launch plan changed; cold restart is required")
        return None

    def durable_policy_commit(encoded, revision, policy_digest):
        try:
            with head_lock:
                # Authenticate the exact candidate under the pinned selected
                # authorities.  This store is private and never published.
                checked = SnapshotStore(
                    verification_key_pem=selected.artifacts["snapshot_signer_public.pem"],
                    ca_certificate_pem=selected.artifacts["ca_certificate.pem"],
                    clock=clock, minimum_revision=selector.policy_revision,
                    minimum_policy_digest=selector.policy_digest)
                candidate_view = checked.install(encoded)
                if (candidate_view.revision != revision
                        or candidate_view.policy_digest != policy_digest):
                    raise CredentialError("candidate policy metadata differs from signed bytes")

                try:
                    committed = root_store.advance_policy(
                        encoded, expected_old_selector_sha256=expected_head["sha256"],
                        clock=clock, validate=validate_immutable)
                except StorageError as stale:
                    # A single competing binding may have committed the same
                    # canonical policy.  Reconcile only that exact head.
                    if "current selector differs from expected old selector" not in str(stale):
                        raise
                    fresh = root_store.read_selected(validate=validate_immutable)
                    independent = SnapshotStore(
                        verification_key_pem=fresh.artifacts["snapshot_signer_public.pem"],
                        ca_certificate_pem=fresh.artifacts["ca_certificate.pem"],
                        clock=clock, minimum_revision=fresh.selector.policy_revision,
                        minimum_policy_digest=fresh.selector.policy_digest)
                    fresh_view = independent.install(fresh.active_policy_snapshot)
                    if (fresh.selector.generation_sha256 != selector.generation_sha256
                            or fresh.selector.activation_manifest_sha256 != selector.activation_manifest_sha256
                            or dict(fresh.selector.artifact_sha256) != dict(selector.artifact_sha256)
                            or fresh_view.revision != revision
                            or fresh_view.policy_digest != policy_digest):
                        raise StorageError("concurrent policy head is not the exact incoming policy") from stale
                    committed = root_store.advance_policy(
                        encoded, expected_old_selector_sha256=fresh.selector_sha256,
                        clock=clock, validate=validate_immutable)
                # A returned selector hash is the durable commit confirmation.
                expected_head["sha256"] = committed
                return None
        except (StorageError, CredentialError):
            raise
        except BaseException as error:
            raise StorageError("durable root policy update failed closed") from error

    store = SnapshotStore(
        verification_key_pem=selected.artifacts["snapshot_signer_public.pem"],
        ca_certificate_pem=selected.artifacts["ca_certificate.pem"], clock=clock,
        minimum_revision=selector.policy_revision,
        minimum_policy_digest=selector.policy_digest,
        durable_commit=durable_policy_commit)
    try:
        view = store.install(selected.active_policy_snapshot)
        sample = clock.sample()
        view = store.current(sample=sample)
        record = view.credentials_by_serial.get(spec.serial)
        if record is None or record.identity != spec.identity:
            raise CredentialError("role leaf is absent from selected current policy")
        if (record.credential_epoch != spec.credential_epoch
                or record.certificate_sha256 != spec.certificate_sha256
                or record.public_key_sha256 != spec.public_key_sha256
                or record.serial != spec.serial):
            raise CredentialError("current policy role record differs from selected launch")
        verify_leaf(selected.artifacts["ca_certificate.pem"], cert_pem,
                    now=sample.wall, uncertainty_seconds=sample.uncertainty,
                    account_id=record.account_id, device_id=record.device_id,
                    role=record.role, serial=record.serial,
                    public_key_hash=record.public_key_sha256,
                    certificate_hash=record.certificate_sha256, ekus=record.ekus,
                    dns_sans=record.dns_sans, ip_sans=record.ip_sans)
        if (int(cert.not_valid_before_utc.timestamp()) != record.not_before
                or int(cert.not_valid_after_utc.timestamp()) != record.not_after):
            raise CredentialError("current policy validity differs from protected role leaf")
        store.assert_credential_live(view, record, sample)
        _require_current_role_grants(view, sample, record, spec, raw)
    except SnapshotError as error:
        raise CredentialError("selected signed policy failed current verification") from error

    final_holder = {}
    def validate_final(selector_value, bundle_value, active_policy_value):
        _selected_binding(selector_value, bundle_value, active_policy_value)
        final_holder["selector_sha256"] = hashlib.sha256(
            canonical_json({
                "schema_version": 2, "purpose": "root_generation_selector",
                "generation_sha256": selector_value.generation_sha256,
                "activation_manifest_sha256": selector_value.activation_manifest_sha256,
                "policy_revision": selector_value.policy_revision,
                "policy_digest": selector_value.policy_digest,
                "active_policy_snapshot_sha256": selector_value.active_policy_snapshot_sha256,
                "artifact_sha256": dict(selector_value.artifact_sha256),
            })).hexdigest()
    root_store.read_selected(validate=validate_final)
    if final_holder.get("selector_sha256") != selected.selector_sha256:
        raise CredentialError("selected root generation changed during local role binding")
    final_sample = clock.sample()
    try:
        final_view = store.current(sample=final_sample)
        if (final_view.policy_digest != view.policy_digest
                or final_view.revision != view.revision):
            raise CredentialError("selected policy changed during local role binding")
        final_record = final_view.credentials_by_serial.get(spec.serial)
        if final_record != record:
            raise CredentialError("selected role credential changed during local binding")
        store.assert_credential_live(final_view, final_record, final_sample)
        _require_current_role_grants(final_view, final_sample, final_record, spec, raw)
    except SnapshotError as error:
        raise CredentialError("selected role policy expired during local binding") from error
    identity = LocalIdentity(cert_pem, spec.boot_id, raw["model_id"], raw["assignment_id"],
                             spec.admission_epoch, spec.generation_sha256)
    return RootRuntimeBinding(identity, store, TLSMaterials(cert_pem, key_pem),
                              runtime_bytes, spec, raw_bytes)


def _require_current_role_grants(view, sample, record, spec, raw):
    """Check only grants relevant to this role/direction and configured scope."""
    active = view.active_grants(sample)
    if spec.role == "host":
        grants = [g for g in active if g.target_serial == record.serial
                  and g.target_boot_id == spec.boot_id
                  and g.model_id == raw["model_id"]
                  and g.assignment_id == raw["assignment_id"]]
        if not grants:
            raise CredentialError("host target grants differ from configured model, assignment, or boot")
    elif spec.role == "consumer":
        if raw["assignment_id"] is not None:
            raise CredentialError("consumer configuration cannot carry a worker assignment")
        grants = [g for g in active if g.actor_serial == record.serial
                  and g.actor_boot_id is None and g.assignment_id is None
                  and g.model_id == raw["model_id"]]
        if not grants:
            raise CredentialError("consumer grants differ from configured model scope")
    else:
        target_grants = [g for g in active if g.target_serial == record.serial
                         and g.target_boot_id == spec.boot_id and g.role == "consumer"
                         and g.assignment_id is None and g.model_id == raw["model_id"]]
        actor_grants = [g for g in active if g.actor_serial == record.serial
                        and g.actor_boot_id == spec.boot_id and g.model_id == raw["model_id"]]
        grants = target_grants + actor_grants
        if not grants or raw["assignment_id"] is not None:
            raise CredentialError("coordinator grants differ from configured model or boot scope")
