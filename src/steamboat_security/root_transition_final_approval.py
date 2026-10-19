"""Protected final owner-approval parser for a cold root transition.

Parsing and protected loading establish only exact content, file ownership and
clock overlap. They do not authorize activation or prove process retirement.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass
from os import PathLike
from typing import Sequence

from .certificates import (ROLE_EKUS, _csr, _pem_certificate, _validate_sans,
                           certificate_sha256, identity_uri, public_key_sha256,
                           serial_hex, verify_leaf)
from .clock import Clock
from .codec import canonical_json
from .errors import CredentialError, SnapshotError, StorageError
from .files import safe_read
from .root_transition import (AffectedPrincipal, MAX_TRANSITION_APPROVAL_BYTES,
                              RootTransitionDeclaration,
                              parse_root_transition_declaration)
from .root_transition_policy import (PreparedActivationCandidate,
                                     _check_old_policy, _intent_hash,
                                     _revalidate_issuance,
                                     validate_prepared_activation_candidate)
from .root_transition_preparation import PreparationIntent
from .root_transition_issuance import PrincipalIssuanceInput
from .root_transition_proof import verify_old_role_key_possession_proof
from .snapshot import SnapshotStore

FINAL_APPROVAL_PURPOSE = "activate_root_transition"
MAX_FINAL_APPROVAL_BYTES = 64 * 1024
_HEX32 = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FIELDS = frozenset({"schema_version", "purpose", "transition_id",
                     "preparation_intent_sha256", "issuance_manifest_sha256",
                     "activation_manifest_sha256", "declaration"})


@dataclass(frozen=True)
class FinalActivationApproval:
    schema_version: int
    purpose: str
    transition_id: str
    preparation_intent_sha256: str
    issuance_manifest_sha256: str
    activation_manifest_sha256: str
    declaration: RootTransitionDeclaration


@dataclass(frozen=True)
class LoadedFinalActivationApproval:
    approval: FinalActivationApproval


@dataclass(frozen=True)
class FinalApprovalPrincipalInput:
    principal: AffectedPrincipal
    old_certificate_pem: bytes
    new_csr_pem: bytes
    possession_proof: bytes


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError("final activation approval has a duplicate field")
        result[key] = value
    return result


def _reject_constant(_value):
    raise SnapshotError("final activation approval has a non-finite number")


def _reject_float(value):
    try:
        math.isfinite(float(value))
    except (TypeError, ValueError, OverflowError):
        pass
    raise SnapshotError("final activation numeric fields must be integers")


def parse_final_activation_approval(encoded: bytes) -> FinalActivationApproval:
    """Parse a closed, canonical final approval; parsing grants no authority."""
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_FINAL_APPROVAL_BYTES:
        raise SnapshotError("final activation approval exceeds its 64 KiB bound")
    try:
        raw = json.loads(encoded.decode("utf-8", errors="strict"),
                         object_pairs_hook=_pairs, parse_constant=_reject_constant,
                         parse_float=_reject_float)
    except SnapshotError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise SnapshotError("final activation approval is malformed JSON") from error
    if type(raw) is not dict or set(raw) != _FIELDS:
        raise SnapshotError("final activation approval has unknown or missing fields")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise SnapshotError("final activation approval schema version is invalid")
    if type(raw["purpose"]) is not str or raw["purpose"] != FINAL_APPROVAL_PURPOSE:
        raise SnapshotError("final activation approval purpose is invalid")
    transition_id = raw["transition_id"]
    if type(transition_id) is not str or not _HEX32.fullmatch(transition_id):
        raise SnapshotError("final activation transition ID is invalid")
    hashes = []
    for field in ("preparation_intent_sha256", "issuance_manifest_sha256",
                  "activation_manifest_sha256"):
        value = raw[field]
        if type(value) is not str or not _HEX64.fullmatch(value):
            raise SnapshotError(f"final activation {field} is invalid")
        hashes.append(value)
    declaration_raw = raw["declaration"]
    if type(declaration_raw) is not dict:
        raise SnapshotError("final activation declaration must be an object")
    declaration = parse_root_transition_declaration(canonical_json(declaration_raw))
    if declaration.transition_id != transition_id:
        raise SnapshotError("final approval and declaration transition IDs differ")
    approval = FinalActivationApproval(
        1, FINAL_APPROVAL_PURPOSE, transition_id, *hashes, declaration)
    try:
        if canonical_json(final_activation_approval_document(approval)) != encoded:
            raise SnapshotError("final activation approval is not canonical JSON")
    except (TypeError, ValueError) as error:
        raise SnapshotError("final activation approval is malformed") from error
    return approval


def final_activation_approval_document(approval: FinalActivationApproval) -> dict:
    declaration = approval.declaration
    return {
        "schema_version": approval.schema_version, "purpose": approval.purpose,
        "transition_id": approval.transition_id,
        "preparation_intent_sha256": approval.preparation_intent_sha256,
        "issuance_manifest_sha256": approval.issuance_manifest_sha256,
        "activation_manifest_sha256": approval.activation_manifest_sha256,
        "declaration": {
            "schema_version": declaration.schema_version,
            "transition_id": declaration.transition_id,
            "old_ca_sha256": declaration.old_ca_sha256,
            "new_ca_sha256": declaration.new_ca_sha256,
            "old_snapshot_key_sha256": declaration.old_snapshot_key_sha256,
            "new_snapshot_key_sha256": declaration.new_snapshot_key_sha256,
            "overlap_not_before": declaration.overlap_not_before,
            "overlap_not_after": declaration.overlap_not_after,
            "old_policy_revision": declaration.old_policy_revision,
            "old_policy_digest": declaration.old_policy_digest,
            "next_minimum_revision": declaration.next_minimum_revision,
            "new_policy_digest": declaration.new_policy_digest,
            "affected_principals": [
                {"account_id": p.account_id, "device_id": p.device_id,
                 "role": p.role, "old_boot_id": p.old_boot_id,
                 "old_serial": p.old_serial,
                 "old_certificate_sha256": p.old_certificate_sha256,
                 "old_public_key_sha256": p.old_public_key_sha256,
                 "old_credential_epoch": p.old_credential_epoch,
                 "old_admission_epoch": p.old_admission_epoch,
                 "new_csr_sha256": p.new_csr_sha256,
                 "dns_sans": list(p.dns_sans), "ip_sans": list(p.ip_sans)}
                for p in declaration.affected_principals],
        },
    }


def load_protected_final_activation_approval(
        path: str | PathLike, *, root: str | PathLike,
        expected_uid: int, clock: Clock) -> LoadedFinalActivationApproval:
    """Load a 0600 approval below a daemon-owned 0700 root and check overlap."""
    raw = safe_read(path, root=root, expected_uid=expected_uid,
                    max_bytes=MAX_FINAL_APPROVAL_BYTES)
    approval = parse_final_activation_approval(raw)
    sample = clock.sample()
    if (sample.earliest_wall < approval.declaration.overlap_not_before
            or sample.latest_wall >= approval.declaration.overlap_not_after):
        raise SnapshotError("final activation approval is outside transition overlap")
    return LoadedFinalActivationApproval(approval)


def _approval_matches_intent(approval: FinalActivationApproval,
                             intent: PreparationIntent,
                             candidate: PreparedActivationCandidate) -> None:
    declaration = approval.declaration
    principals = tuple(declaration.affected_principals)
    expected = tuple(intent.affected_principals)
    common = (
        declaration.transition_id == intent.transition_id == approval.transition_id,
        declaration.old_ca_sha256 == intent.old_ca_sha256,
        declaration.new_ca_sha256 == intent.new_ca_sha256,
        declaration.old_snapshot_key_sha256 == intent.old_snapshot_key_sha256,
        declaration.new_snapshot_key_sha256 == intent.new_snapshot_key_sha256,
        declaration.overlap_not_before == intent.overlap_not_before,
        declaration.overlap_not_after == intent.overlap_not_after,
        declaration.old_policy_revision == intent.old_policy_revision,
        declaration.old_policy_digest == intent.old_policy_digest,
        declaration.next_minimum_revision == intent.next_minimum_revision,
        principals == expected,
        declaration.new_policy_digest == candidate.policy_digest,
        approval.preparation_intent_sha256 == _intent_hash(intent),
        approval.issuance_manifest_sha256 == candidate.issuance_manifest_sha256,
        approval.activation_manifest_sha256 == candidate.activation_manifest_sha256,
        declaration == candidate.declaration,
    )
    if not all(common):
        raise CredentialError("final approval is not bound to the prepared candidate and intent")


def validate_final_activation_approval(
        *, approval_path: str | PathLike, approval_root: str | PathLike,
        expected_uid: int, clock: Clock, intent: PreparationIntent,
        candidate: PreparedActivationCandidate,
        old_snapshot_store: SnapshotStore,
        new_ca_certificate_pem: bytes,
        new_snapshot_public_key_pem: bytes,
        new_csr_by_identity: dict,
        principal_inputs: Sequence[FinalApprovalPrincipalInput]) -> FinalActivationApproval:
    """Validate final approval and every exact old-role proof; never activates.

    Supervisor-observed process retirement, ready new processes, admission and
    durable high-water state remain responsibilities of a later activation
    transaction. This validator does not infer them from launch declarations.
    """
    if type(intent) is not PreparationIntent or type(candidate) is not PreparedActivationCandidate:
        raise CredentialError("final approval validation requires typed prepared inputs")
    if old_snapshot_store.clock is not clock:
        raise CredentialError("approval and old snapshot must share the configured clock")
    loaded = load_protected_final_activation_approval(
        approval_path, root=approval_root, expected_uid=expected_uid, clock=clock)
    approval = loaded.approval
    _approval_matches_intent(approval, intent, candidate)
    validate_prepared_activation_candidate(
        candidate=candidate, intent=intent, old_snapshot_store=old_snapshot_store,
        new_ca_certificate_pem=new_ca_certificate_pem,
        new_snapshot_public_key_pem=new_snapshot_public_key_pem,
        new_csr_by_identity=new_csr_by_identity, clock=clock)
    sample = clock.sample()
    if (sample.earliest_wall < intent.overlap_not_before
            or sample.latest_wall >= intent.overlap_not_after):
        raise CredentialError("trusted clock interval is outside transition overlap")
    old_view, old_records = _check_old_policy(intent, old_snapshot_store, sample)
    issued = _revalidate_issuance(intent, candidate.issuance_candidate,
                                  new_ca_certificate_pem, sample)
    from .root_transition_policy import _validate_csr_bindings
    _validate_csr_bindings(intent, issued, new_csr_by_identity)
    if type(principal_inputs) not in (tuple, list) or len(principal_inputs) != len(intent.affected_principals):
        raise CredentialError("final proof inputs must exactly cover the affected cohort")
    by_identity = {p.identity: p for p in approval.declaration.affected_principals}
    seen = set()
    for item in principal_inputs:
        if type(item) is not FinalApprovalPrincipalInput:
            raise CredentialError("final proof input has an unsupported type")
        principal = item.principal
        if type(principal) is not AffectedPrincipal:
            raise CredentialError("final proof input principal has an unsupported type")
        identity = principal.identity
        member = by_identity.get(identity)
        try:
            equal_fields = (member is not None
                            and canonical_json(asdict(principal)) == canonical_json(asdict(member)))
        except (TypeError, ValueError, RecursionError):
            equal_fields = False
        if not equal_fields or identity in seen:
            raise CredentialError("final proof input principal is not an exact unique member")
        # Normalize to the authoritative declaration member so the existing
        # proof verifier's exact object-membership requirement remains intact.
        principal = member
        seen.add(identity)
        matching_intent = next((p for p in intent.affected_principals
                                if p.identity == identity), None)
        old_record = old_records.get(identity)
        if matching_intent is None or old_record is None:
            raise CredentialError("old proof principal lacks current credential")
        if (type(item.old_certificate_pem) is not bytes
                or type(item.new_csr_pem) is not bytes
                or type(item.possession_proof) is not bytes):
            raise CredentialError("final proof bytes are malformed")
        if new_csr_by_identity.get(identity) != item.new_csr_pem:
            raise CredentialError("final proof CSR differs from independently validated CSR map")
        cert = _pem_certificate(item.old_certificate_pem)
        if (serial_hex(cert.serial_number) != matching_intent.old_serial
                or certificate_sha256(cert) != matching_intent.old_certificate_sha256
                or public_key_sha256(cert.public_key()) != matching_intent.old_public_key_sha256):
            raise CredentialError("old certificate differs from final declaration pins")
        if old_record.not_after - sample.latest_wall > 300:
            raise CredentialError("old credential is outside the 300-second renewal window")
        verify_leaf(
            old_snapshot_store.ca_certificate_pem, item.old_certificate_pem,
            now=sample.wall, uncertainty_seconds=sample.uncertainty,
            account_id=old_record.account_id, device_id=old_record.device_id,
            role=old_record.role, serial=old_record.serial,
            public_key_hash=old_record.public_key_sha256,
            certificate_hash=old_record.certificate_sha256, ekus=old_record.ekus,
            dns_sans=old_record.dns_sans, ip_sans=old_record.ip_sans)
        verify_old_role_key_possession_proof(
            item.possession_proof, approval.declaration, principal,
            old_certificate_pem=item.old_certificate_pem,
            new_csr_pem=item.new_csr_pem)
        csr = _csr(item.new_csr_pem)
        uri, csr_dns, csr_ips = _validate_sans(csr)
        issued_record = next(record for record in issued
                             if record.identity == identity).record
        if (uri != identity_uri(principal.account_id, principal.device_id, principal.role)
                or public_key_sha256(csr.public_key()) != issued_record.public_key_sha256
                or tuple(csr_dns) != issued_record.dns_sans
                or tuple(csr_ips) != issued_record.ip_sans):
            raise CredentialError("final proof CSR does not exactly match the issued leaf")
    if seen != set(by_identity):
        raise CredentialError("final proof inputs omit an affected principal")
    final_sample = clock.sample()
    if (final_sample.earliest_wall < intent.overlap_not_before
            or final_sample.latest_wall >= intent.overlap_not_after):
        raise CredentialError("trusted clock interval left transition overlap")
    final_view, final_records = _check_old_policy(intent, old_snapshot_store, final_sample)
    if final_view.policy_digest != old_view.policy_digest or final_records != old_records:
        raise CredentialError("old policy or credentials changed during final approval validation")
    # Revalidate proofs at the boundary with the same unchanged public inputs.
    for item in principal_inputs:
        member = by_identity[item.principal.identity]
        verify_old_role_key_possession_proof(
            item.possession_proof, approval.declaration, member,
            old_certificate_pem=item.old_certificate_pem,
            new_csr_pem=item.new_csr_pem)
    validate_prepared_activation_candidate(
        candidate=candidate, intent=intent, old_snapshot_store=old_snapshot_store,
        new_ca_certificate_pem=new_ca_certificate_pem,
        new_snapshot_public_key_pem=new_snapshot_public_key_pem,
        new_csr_by_identity=new_csr_by_identity, clock=clock)
    return approval
