"""Cold root-transition activation composition.

This operation atomically selects a fully validated public generation. It does
not start workers, consume launch claims, establish readiness, or claim that a
new service is available.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Mapping, Sequence

from .certificates import _pem_certificate, public_key_sha256, verify_ca
from .clock import Clock
from .codec import canonical_json
from .errors import BindingError, CredentialError, SnapshotError, StorageError
from .files import safe_read
from .root_transition_final_approval import (
    FinalApprovalPrincipalInput, validate_final_activation_approval,
)
from .root_transition_launch import (
    RoleLaunchSpec, canonical_role_launch_digest, parse_role_launch_spec,
    role_launch_document,
)
from .root_transition_policy import (
    PreparedActivationCandidate, expected_transition_generation_sha256,
)
from .root_transition_preparation import (
    PreparationIntent, load_protected_preparation_intent,
)
from .root_transition_retirement import RetirementCapability, RetirementSupervisor
from .root_transition_storage import (
    RootGenerationSelector, RootGenerationStore, SelectedRootGeneration,
    _authenticate_policy_snapshot, parse_root_generation_selector,
    root_generation_selector_document,
)
from .snapshot import SnapshotStore, canonical_policy_digest

_ARTIFACTS = (
    "activation_manifest.json", "policy_snapshot.json", "ca_certificate.pem",
    "snapshot_signer_public.pem", "credential_bundle.json", "issuance_manifest.json",
    "final_approval.json", "preparation_intent.json", "public_csr_bundle.json",
    "old_possession_proofs.json", "retirement_receipt.json",
    "old_launch_specs.json", "new_launch_specs.json",
)


@dataclass(frozen=True)
class RootTransitionActivationResult:
    """Durable selector evidence; not a process-readiness capability."""
    selector_sha256: str
    generation_sha256: str
    activation_manifest_sha256: str
    policy_revision: int
    policy_digest: str


def _read(path, root, uid, maximum, label):
    try:
        return safe_read(path, root=root, expected_uid=uid, max_bytes=maximum)
    except (OSError, StorageError) as error:
        raise CredentialError(f"protected {label} could not be read") from error


def _old_specs(encoded: bytes, generation: str) -> tuple[RoleLaunchSpec, ...]:
    if type(encoded) is not bytes or not 1 <= len(encoded) <= 64 * 1024:
        raise CredentialError("selected current launch plan is outside its byte bound")
    try:
        raw = json.loads(encoded.decode("utf-8", errors="strict"))
        if type(raw) is not list or not 1 <= len(raw) <= 16:
            raise ValueError("shape")
        parsed = tuple(parse_role_launch_spec(item) for item in raw)
        ordered = tuple(sorted(parsed, key=lambda x: x.identity))
        if (parsed != ordered or len({x.identity for x in parsed}) != len(parsed)
                or any(item.generation_sha256 != generation for item in parsed)
                or canonical_json([role_launch_document(x) for x in parsed]) != encoded):
            raise ValueError("canonical bindings")
        return parsed
    except (UnicodeError, ValueError, TypeError, RecursionError, BindingError) as error:
        raise CredentialError("selected old launch plan is malformed or noncanonical") from error


def _selected_old_store(selected: SelectedRootGeneration, clock: Clock) -> SnapshotStore:
    selector, artifacts = selected.selector, selected.artifacts
    ca = artifacts["ca_certificate.pem"]
    signer = artifacts["snapshot_signer_public.pem"]
    if hashlib.sha256(artifacts["activation_manifest.json"]).hexdigest() != selector.activation_manifest_sha256:
        raise CredentialError("selected activation manifest pin is inconsistent")
    sample = clock.sample()
    verify_ca(ca, now=sample.wall, uncertainty_seconds=sample.uncertainty)
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_public_key(signer)
    if public_key_sha256(key) == public_key_sha256(_pem_certificate(ca).public_key()):
        raise CredentialError("selected CA and snapshot signer are not independent")
    payload, _records, _grants = _authenticate_policy_snapshot(
        selected.active_policy_snapshot, ca_pem=ca, signer_pem=signer, sample=sample)
    digest = canonical_policy_digest(payload)
    if (type(payload.get("revision")) is not int
            or payload["revision"] != selector.policy_revision
            or digest != selector.policy_digest):
        raise CredentialError("selected active policy differs from its selector floor")
    store = SnapshotStore(verification_key_pem=signer, ca_certificate_pem=ca,
                          clock=clock, minimum_revision=selector.policy_revision,
                          minimum_policy_digest=selector.policy_digest)
    view = store.install(selected.active_policy_snapshot)
    if view.policy_digest != selector.policy_digest:
        raise CredentialError("selected signed policy digest changed on installation")
    return store


def _proof_documents(principal_inputs: Sequence[FinalApprovalPrincipalInput]):
    ordered = sorted(principal_inputs, key=lambda x: x.principal.identity)
    csrs = [{"identity": list(item.principal.identity),
             "csr_pem_base64": base64.b64encode(item.new_csr_pem).decode("ascii")}
            for item in ordered]
    proofs = [{"identity": list(item.principal.identity),
               "proof_base64": base64.b64encode(item.possession_proof).decode("ascii")}
              for item in ordered]
    return canonical_json(csrs), canonical_json(proofs)


def _bundle(*, intent, candidate, intent_bytes, approval_bytes, new_ca, new_signer,
            principal_inputs):
    issued = {item.identity: item for item in candidate.issuance_candidate.principals}
    ordered = sorted(principal_inputs, key=lambda x: x.principal.identity)
    credentials = []
    for item in ordered:
        identity = item.principal.identity
        if identity not in issued:
            raise CredentialError("final approval inputs do not match issued cohort")
        credentials.append({
            "identity": list(identity),
            "old_certificate_pem_base64": base64.b64encode(item.old_certificate_pem).decode("ascii"),
            "new_certificate_pem_base64": base64.b64encode(issued[identity].certificate_pem).decode("ascii"),
        })
    csr_bytes, proof_bytes = _proof_documents(ordered)
    receipt = canonical_json({
        "schema_version": 1, "purpose": "root_transition_retirement",
        "transition_id": intent.transition_id,
        "old_generation_sha256": candidate.old_launch_specs[0].generation_sha256,
        "old_launch_digest": candidate.old_launch_digest,
        "containment_scope": "trusted_process_group_no_escape",
    })
    return {
        "activation_manifest.json": candidate.activation_manifest,
        "policy_snapshot.json": candidate.signed_snapshot,
        "ca_certificate.pem": new_ca,
        "snapshot_signer_public.pem": new_signer,
        "credential_bundle.json": canonical_json({"schema_version": 1,
            "purpose": "root_transition_credentials", "credentials": credentials}),
        "issuance_manifest.json": candidate.issuance_candidate.manifest,
        "final_approval.json": approval_bytes,
        "preparation_intent.json": intent_bytes,
        "public_csr_bundle.json": csr_bytes,
        "old_possession_proofs.json": proof_bytes,
        "retirement_receipt.json": receipt,
        "old_launch_specs.json": canonical_json(
            [role_launch_document(x) for x in candidate.old_launch_specs]),
        "new_launch_specs.json": canonical_json(
            [role_launch_document(x) for x in candidate.new_launch_specs]),
    }


def activate_root_transition(*, root_store: RootGenerationStore,
        expected_old_selector_sha256: str, preparation_path, preparation_root,
        approval_path, approval_root, expected_uid: int, clock: Clock,
        candidate: PreparedActivationCandidate, new_ca_certificate_pem: bytes,
        new_snapshot_public_key_pem: bytes, new_csr_by_identity: dict,
        principal_inputs: Sequence[FinalApprovalPrincipalInput],
        retirement_supervisor: RetirementSupervisor,
        retirement_capability: RetirementCapability) -> RootTransitionActivationResult:
    """Validate the protected transition and atomically select its public bytes.

    The supervisor capability is checked before any write and at every store
    validation boundary. The storage CAS protects against a changed selected
    head while this function validates outside the store lock. This is cold
    selection only; callers must separately claim and launch new processes.
    """
    if type(root_store) is not RootGenerationStore or type(clock) is not Clock:
        raise TypeError("activation requires exact root store and configured Clock")
    geteuid = getattr(os, "geteuid", None)
    if (type(expected_uid) is not int or not callable(geteuid)
            or expected_uid != geteuid() or expected_uid != root_store._uid):
        raise CredentialError("activation UID must exactly match the root-store owner")
    if type(retirement_supervisor) is not RetirementSupervisor:
        raise TypeError("activation requires the exact owning retirement supervisor")
    if type(candidate) is not PreparedActivationCandidate:
        raise CredentialError("activation candidate has an unsupported type")
    if type(principal_inputs) not in (tuple, list) or not 1 <= len(principal_inputs) <= 16:
        raise CredentialError("activation proof inputs must be a bounded exact sequence")
    principal_inputs = tuple(principal_inputs)
    if any(type(item) is not FinalApprovalPrincipalInput
           or type(item.old_certificate_pem) is not bytes
           or type(item.new_csr_pem) is not bytes
           or type(item.possession_proof) is not bytes
           for item in principal_inputs):
        raise CredentialError("activation proof inputs must be immutable exact public bytes")
    if (type(new_csr_by_identity) is not dict or len(new_csr_by_identity) > 16
            or any(type(key) is not tuple or len(key) != 3
                   or any(type(part) is not str for part in key)
                   or type(value) is not bytes
                   for key, value in new_csr_by_identity.items())):
        raise CredentialError("activation CSR map must be a bounded exact immutable-byte mapping")
    new_csr_by_identity = dict(new_csr_by_identity)

    def validate_transition(intent, selected, old_store):
        old_specs = _old_specs(selected.artifacts["new_launch_specs.json"],
                               selected.selector.generation_sha256)
        if (old_specs != candidate.old_launch_specs
                or canonical_role_launch_digest(old_specs) != candidate.old_launch_digest):
            raise CredentialError("selected old launch plan differs from prepared transition")
        if not retirement_supervisor.validate_retirement_capability(
                retirement_capability, transition_id=intent.transition_id,
                expected_old_bindings_digest=candidate.old_launch_digest):
            raise CredentialError("retirement capability is not valid for selected old cohort")
        validate_final_activation_approval(
            approval_path=approval_path, approval_root=approval_root,
            expected_uid=expected_uid, clock=clock, intent=intent,
            candidate=candidate, old_snapshot_store=old_store,
            new_ca_certificate_pem=new_ca_certificate_pem,
            new_snapshot_public_key_pem=new_snapshot_public_key_pem,
            new_csr_by_identity=new_csr_by_identity,
            principal_inputs=principal_inputs)
        if (candidate.transition_id != intent.transition_id
                or expected_transition_generation_sha256(intent)
                    != candidate.new_launch_specs[0].generation_sha256
                or any(spec.generation_sha256 != candidate.new_launch_specs[0].generation_sha256
                       for spec in candidate.new_launch_specs)):
            raise CredentialError("candidate generation differs from transition intent")
        return None

    def read_inputs():
        loaded = load_protected_preparation_intent(
            preparation_path, root=preparation_root,
            expected_uid=expected_uid, clock=clock)
        intent = loaded.intent
        selected = root_store.read_selected(validate_selected)
        old_store = _selected_old_store(selected, clock)
        validate_transition(intent, selected, old_store)
        return intent, selected, old_store

    def validate_selected(selector, artifacts, active_policy):
        if hashlib.sha256(artifacts["activation_manifest.json"]).hexdigest() != selector.activation_manifest_sha256:
            raise CredentialError("selected activation manifest pin differs")
        _selected_old_store(SelectedRootGeneration(selector, artifacts, "0" * 64,
                                                    active_policy), clock)

    intent, selected, old_store = read_inputs()
    approval_bytes = _read(approval_path, approval_root, expected_uid, 64 * 1024,
                           "final activation approval")
    intent_bytes = _read(preparation_path, preparation_root, expected_uid,
                         64 * 1024, "preparation intent")
    bundle = _bundle(intent=intent, candidate=candidate, intent_bytes=intent_bytes,
                     approval_bytes=approval_bytes,
                     new_ca=new_ca_certificate_pem,
                     new_signer=new_snapshot_public_key_pem,
                     principal_inputs=principal_inputs)
    if set(bundle) != set(_ARTIFACTS):
        raise CredentialError("activation bundle is incomplete")
    artifacts = {name: hashlib.sha256(data).hexdigest() for name, data in bundle.items()}
    selector = parse_root_generation_selector(canonical_json({
        "schema_version": 2, "purpose": "root_generation_selector",
        "generation_sha256": expected_transition_generation_sha256(intent),
        "activation_manifest_sha256": hashlib.sha256(candidate.activation_manifest).hexdigest(),
        "policy_revision": candidate.declaration.next_minimum_revision,
        "policy_digest": candidate.policy_digest,
        "active_policy_snapshot_sha256": hashlib.sha256(candidate.signed_snapshot).hexdigest(),
        "artifact_sha256": artifacts,
    }))
    if (candidate.activation_manifest_sha256 != selector.activation_manifest_sha256
            or hashlib.sha256(bundle["activation_manifest.json"]).hexdigest()
                != selector.activation_manifest_sha256):
        raise CredentialError("candidate activation manifest bytes differ from its pin")
    new_store = SnapshotStore(verification_key_pem=new_snapshot_public_key_pem,
        ca_certificate_pem=new_ca_certificate_pem, clock=clock,
        minimum_revision=selector.policy_revision,
        minimum_policy_digest=selector.policy_digest)
    new_view = new_store.install(candidate.signed_snapshot)
    if (new_view.revision != selector.policy_revision
            or new_view.policy_digest != selector.policy_digest):
        raise CredentialError("new signed policy differs from derived selector")

    def validate_new(actual_selector, actual_bundle: Mapping[str, bytes], active_policy):
        if (canonical_json(root_generation_selector_document(actual_selector))
                != canonical_json(root_generation_selector_document(selector))
                or dict(actual_bundle) != bundle or active_policy != candidate.signed_snapshot):
            raise CredentialError("activation selector or public bundle differs from validated bytes")
        if (_read(preparation_path, preparation_root, expected_uid,
                  64 * 1024, "preparation intent") != bundle["preparation_intent.json"]
                or _read(approval_path, approval_root, expected_uid,
                         64 * 1024, "final activation approval")
                    != bundle["final_approval.json"]):
            raise CredentialError("protected approval inputs changed during activation")
        current = load_protected_preparation_intent(
            preparation_path, root=preparation_root,
            expected_uid=expected_uid, clock=clock).intent
        if current != intent:
            raise CredentialError("protected preparation intent changed during activation")
        validate_transition(current, selected, old_store)
        current_sample = clock.sample()
        current_new_view = new_store.current(sample=current_sample)
        for record in current_new_view.credentials_by_serial.values():
            new_store.assert_credential_live(current_new_view, record, current_sample)
        required_grants = current_new_view.grants
        active_grants = current_new_view.active_grants(current_sample)
        if (len(active_grants) != len(required_grants)
                or active_grants != required_grants):
            raise CredentialError("new policy grant set is not fully live under its original monotonic caps")
        if not retirement_supervisor.validate_retirement_capability(
                retirement_capability, transition_id=intent.transition_id,
                expected_old_bindings_digest=candidate.old_launch_digest):
            raise CredentialError("old cohort retirement capability became invalid")

    committed = root_store.commit(selector, bundle,
        active_policy_snapshot=candidate.signed_snapshot,
        expected_old_selector_sha256=expected_old_selector_sha256,
        validate=validate_new)
    return RootTransitionActivationResult(committed, selector.generation_sha256,
        selector.activation_manifest_sha256, selector.policy_revision,
        selector.policy_digest)
