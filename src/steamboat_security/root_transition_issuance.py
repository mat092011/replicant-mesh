"""Private, uncommitted whole-cohort certificate preparation for root changes.

This primitive reloads protected preparation intent, validates every old
credential, scoped grant, new authority, CSR and possession proof before it
signs any leaf, then rechecks current policy, time and authorization before it
returns. Its immutable result is only a private issuance candidate and a
canonical issuance manifest. It publishes no files, admits no credential and
does not authorize activation. A later serialized staging operation and a
separate owner approval must bind the actual certificates and resulting policy
manifest. Repeating this intent grants no additional authority.

The installed snapshot has no admission-epoch field. Accordingly, the
preparation intent's old admission epoch is only an operator-approved,
proof-bound pin here; final activation must validate the actual retired-role
epoch. Consumer grants intentionally have no actor boot pin, so the old boot
pin for such an actor is likewise not independently established by that grant.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from os import PathLike
from typing import Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .certificates import (ROLE_EKUS, _csr, _key, _pem_certificate, _validate_sans,
                          certificate_sha256, identity_uri, issue_leaf,
                          public_key_sha256, serial_hex, verify_ca, verify_leaf)
from .clock import Clock
from .codec import canonical_json
from .errors import BindingError, CredentialError, SnapshotError
from .operator import _record_from_leaf
from .root_transition import AffectedPrincipal
from .root_transition_preparation import (
    PreparationIntent, _check_clock, _intent_document,
    load_protected_preparation_intent, verify_preparation_possession_proof,
)
from .snapshot import CredentialRecord, SnapshotStore


MAX_COHORT_PRINCIPALS = 16
MAX_ISSUANCE_LIFETIME_SECONDS = 900
ISSUANCE_MANIFEST_DOMAIN = "steamboat.root-transition.private-issuance-manifest.v1"


@dataclass(frozen=True)
class PrincipalIssuanceInput:
    principal: AffectedPrincipal
    old_certificate_pem: bytes
    new_csr_pem: bytes
    preparation_proof: bytes


@dataclass(frozen=True)
class IssuedPrincipal:
    identity: tuple[str, str, str]
    certificate_pem: bytes
    record: CredentialRecord


@dataclass(frozen=True)
class RootTransitionIssuanceCandidate:
    transition_id: str
    intent_sha256: str
    old_ca_sha256: str
    new_ca_sha256: str
    old_snapshot_key_sha256: str
    new_snapshot_key_sha256: str
    principals: tuple[IssuedPrincipal, ...]
    manifest: bytes


@dataclass(frozen=True)
class _ValidatedInput:
    principal: AffectedPrincipal
    csr_pem: bytes
    csr_key_hash: str
    account_id: str
    device_id: str
    role: str
    not_before: int
    not_after: int
    credential_epoch: int
    dns_sans: tuple[str, ...]
    ip_sans: tuple[str, ...]


def _public_key(pem: bytes, label: str):
    if type(pem) is not bytes or not 1 <= len(pem) <= 4096:
        raise CredentialError(f"{label} public key input is malformed")
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as error:
        raise CredentialError(f"{label} public key input is malformed") from error
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise CredentialError(f"{label} public key must be ECDSA P-256")
    return key


def _grant_matches(grant, principal: AffectedPrincipal, record: CredentialRecord) -> bool:
    actor = grant.actor_serial == record.serial
    target = grant.target_serial == record.serial
    if actor:
        if ((grant.account_id, grant.device_id, grant.role) != record.identity
                or grant.actor_public_key_sha256 != record.public_key_sha256
                or grant.actor_credential_epoch != record.credential_epoch):
            return False
        if grant.actor_boot_id is not None and grant.actor_boot_id != principal.old_boot_id:
            return False
        return True
    if target:
        return ((grant.target_account_id, grant.target_device_id, grant.target_role)
                == record.identity
                and grant.target_public_key_sha256 == record.public_key_sha256
                and grant.target_credential_epoch == record.credential_epoch
                and grant.target_boot_id == principal.old_boot_id)
    return False


def _current_authorization(snapshot_store: SnapshotStore, intent: PreparationIntent,
                           inputs: tuple[PrincipalIssuanceInput, ...], sample):
    view = snapshot_store.current(sample=sample)
    if view.revision != intent.old_policy_revision or view.policy_digest != intent.old_policy_digest:
        raise CredentialError("current old snapshot differs from the preparation policy pin")
    records = {}
    active_grants = view.active_grants(sample)
    for item in inputs:
        principal = item.principal
        record = view.credentials_by_serial.get(principal.old_serial)
        if record is None:
            raise CredentialError("declared old credential is absent from current snapshot")
        expected = (
            principal.account_id, principal.device_id, principal.role,
            principal.old_serial, principal.old_public_key_sha256,
            principal.old_certificate_sha256, principal.old_credential_epoch,
            tuple(sorted(ROLE_EKUS[principal.role])), principal.dns_sans,
            principal.ip_sans)
        actual = (record.account_id, record.device_id, record.role, record.serial,
                  record.public_key_sha256, record.certificate_sha256,
                  record.credential_epoch, record.ekus, record.dns_sans, record.ip_sans)
        if actual != expected:
            raise CredentialError("old snapshot credential differs from declared pins")
        snapshot_store.assert_credential_live(view, record, sample)
        matching = [grant for grant in active_grants if _grant_matches(grant, principal, record)]
        if not matching:
            raise CredentialError("old credential has no current scoped active grant")
        records[principal.identity] = record
    return view, records


def _principal_shape_is_exact(principal: AffectedPrincipal) -> bool:
    string_fields = (
        "account_id", "device_id", "role", "old_boot_id", "old_serial",
        "old_certificate_sha256", "old_public_key_sha256", "new_csr_sha256")
    if any(type(getattr(principal, field)) is not str for field in string_fields):
        return False
    if (type(principal.old_credential_epoch) is not int
            or type(principal.old_admission_epoch) is not int):
        return False
    for field in ("dns_sans", "ip_sans"):
        values = getattr(principal, field)
        if type(values) is not tuple or any(type(value) is not str for value in values):
            return False
    return True


def _authority_keys(snapshot_store: SnapshotStore, intent: PreparationIntent,
                    new_ca_pem: bytes, new_ca_private_key_pem: bytes,
                    new_snapshot_public_key_pem: bytes, sample):
    try:
        old_ca = verify_ca(snapshot_store.ca_certificate_pem, now=sample.wall,
                           uncertainty_seconds=sample.uncertainty)
        new_ca = verify_ca(new_ca_pem, now=sample.wall,
                           uncertainty_seconds=sample.uncertainty)
        new_signer = _key(new_ca_private_key_pem)
        new_snapshot_key = _public_key(new_snapshot_public_key_pem, "new snapshot")
    except (CredentialError, SnapshotError):
        raise
    old_ca_hash = certificate_sha256(old_ca)
    new_ca_hash = certificate_sha256(new_ca)
    old_signer_hash = public_key_sha256(snapshot_store._verification_key)
    new_signer_hash = public_key_sha256(new_snapshot_key)
    old_ca_key_hash = public_key_sha256(old_ca.public_key())
    new_ca_key_hash = public_key_sha256(new_ca.public_key())
    if (old_ca_hash != intent.old_ca_sha256 or new_ca_hash != intent.new_ca_sha256
            or old_signer_hash != intent.old_snapshot_key_sha256
            or new_signer_hash != intent.new_snapshot_key_sha256):
        raise CredentialError("root transition authority differs from preparation pins")
    if new_signer.public_key().public_numbers() != new_ca.public_key().public_numbers():
        raise CredentialError("new CA signing key does not match the pinned new CA")
    if (old_ca_key_hash in (old_signer_hash, new_signer_hash)
            or new_ca_key_hash in (old_signer_hash, new_signer_hash)):
        raise CredentialError("CA signing keys must remain separate from snapshot signing keys")
    return old_ca, new_ca, new_signer, new_ca_key_hash, new_signer_hash


def _validate_batch(intent: PreparationIntent, snapshot_store: SnapshotStore,
                    inputs: Sequence[PrincipalIssuanceInput], new_ca_pem: bytes,
                    new_ca_private_key_pem: bytes, new_snapshot_public_key_pem: bytes,
                    sample, leaf_lifetime_seconds: int):
    if type(inputs) not in (tuple, list) or not 1 <= len(inputs) <= MAX_COHORT_PRINCIPALS:
        raise CredentialError("issuance inputs must be a bounded nonempty sequence")
    if type(leaf_lifetime_seconds) is not int or not 1 <= leaf_lifetime_seconds <= MAX_ISSUANCE_LIFETIME_SECONDS:
        raise CredentialError("requested leaf lifetime must be an integer from 1 to 900 seconds")
    if type(intent) is not PreparationIntent:
        raise CredentialError("issuance requires a loaded preparation intent")
    declared = {principal.identity: principal for principal in intent.affected_principals}
    if len(inputs) != len(declared):
        raise CredentialError("issuance must include the complete affected-principal cohort")
    seen = set()
    normalized = []
    for item in inputs:
        if type(item) is not PrincipalIssuanceInput:
            raise CredentialError("issuance input has an unsupported type")
        principal = item.principal
        if type(principal) is not AffectedPrincipal or not _principal_shape_is_exact(principal):
            raise CredentialError("issuance input principal fields have invalid exact types")
        authoritative = declared.get(principal.identity)
        if authoritative is None:
            raise CredentialError("issuance input principal is not a declared member")
        try:
            same_fields = canonical_json(asdict(principal)) == canonical_json(asdict(authoritative))
        except (BindingError, TypeError, ValueError, RecursionError) as error:
            raise CredentialError("issuance input principal fields are malformed") from error
        if not same_fields:
            raise CredentialError("issuance input principal differs from freshly loaded declaration")
        if principal.identity in seen:
            raise CredentialError("issuance input contains a duplicate principal")
        seen.add(principal.identity)
        normalized.append(PrincipalIssuanceInput(
            authoritative, item.old_certificate_pem, item.new_csr_pem,
            item.preparation_proof))
    if seen != set(declared):
        raise CredentialError("issuance input does not match the complete declared cohort")
    inputs = tuple(sorted(normalized, key=lambda item: item.principal.identity))

    view, records = _current_authorization(snapshot_store, intent, tuple(inputs), sample)
    old_ca, new_ca, new_signer, new_ca_key_hash, new_signer_hash = _authority_keys(
        snapshot_store, intent, new_ca_pem, new_ca_private_key_pem,
        new_snapshot_public_key_pem, sample)
    del old_ca, new_signer
    _check_clock(intent, snapshot_store.clock)
    not_before = int(sample.earliest_wall)
    authority_expiry = int(new_ca.not_valid_after_utc.timestamp())
    not_after = min(not_before + leaf_lifetime_seconds, authority_expiry,
                    intent.overlap_not_after)
    if not_after <= sample.latest_wall:
        raise CredentialError("new authority or overlap has insufficient conservative validity")

    current_key_hashes = {record.public_key_sha256 for record in view.credentials_by_serial.values()}
    authority_key_hashes = {
        new_ca_key_hash, new_signer_hash,
        public_key_sha256(snapshot_store._verification_key),
        public_key_sha256(_pem_certificate(snapshot_store.ca_certificate_pem).public_key()),
    }
    if authority_key_hashes.intersection(current_key_hashes):
        raise CredentialError("new CA and snapshot authority keys must be separate from every live role key")
    validated = []
    new_key_hashes = set()
    for item in inputs:
        principal = item.principal
        record = records[principal.identity]
        old_certificate = _pem_certificate(item.old_certificate_pem)
        if (certificate_sha256(old_certificate) != principal.old_certificate_sha256
                or public_key_sha256(old_certificate.public_key()) != principal.old_public_key_sha256
                or serial_hex(old_certificate.serial_number) != principal.old_serial):
            raise CredentialError("old certificate bytes differ from preparation pins")
        old_leaf = verify_leaf(
            snapshot_store.ca_certificate_pem, item.old_certificate_pem,
            now=sample.wall, uncertainty_seconds=sample.uncertainty,
            account_id=record.account_id, device_id=record.device_id, role=record.role,
            serial=record.serial, public_key_hash=record.public_key_sha256,
            certificate_hash=record.certificate_sha256, ekus=record.ekus,
            dns_sans=record.dns_sans, ip_sans=record.ip_sans)
        if (int(old_leaf.not_valid_before_utc.timestamp()) != record.not_before
                or int(old_leaf.not_valid_after_utc.timestamp()) != record.not_after):
            raise CredentialError("old snapshot validity differs from its pinned certificate")
        if record.not_after - sample.latest_wall > 300:
            raise CredentialError("old credential is outside the 300-second renewal window")
        csr = _csr(item.new_csr_pem)
        uri, dns_sans, ip_sans = _validate_sans(csr)
        if uri != identity_uri(principal.account_id, principal.device_id, principal.role):
            raise CredentialError("new CSR changes declared identity or role")
        if (not set(dns_sans).issubset(principal.dns_sans)
                or not set(ip_sans).issubset(principal.ip_sans)
                or not set(dns_sans).issubset(record.dns_sans)
                or not set(ip_sans).issubset(record.ip_sans)):
            raise CredentialError("new CSR expands DNS or IP scope")
        key_hash = public_key_sha256(csr.public_key())
        if (key_hash in new_key_hashes or key_hash in current_key_hashes
                or key_hash in authority_key_hashes):
            raise CredentialError("new role keys must be unique, fresh, and separate from authorities")
        new_key_hashes.add(key_hash)
        verify_preparation_possession_proof(
            item.preparation_proof, intent, principal,
            old_certificate_pem=item.old_certificate_pem,
            new_csr_pem=item.new_csr_pem)
        validated.append(_ValidatedInput(
            principal, item.new_csr_pem, key_hash, record.account_id,
            record.device_id, record.role, not_before, not_after,
            record.credential_epoch + 1, tuple(dns_sans), tuple(ip_sans)))
    return tuple(validated), records, not_after, view


def prepare_root_transition_issuance(
        *, approval_path: str | PathLike, approval_root: str | PathLike,
        expected_uid: int, clock: Clock, old_snapshot_store: SnapshotStore,
        new_ca_certificate_pem: bytes, new_ca_private_key_pem: bytes,
        new_snapshot_public_key_pem: bytes,
        principal_inputs: Sequence[PrincipalIssuanceInput],
        leaf_lifetime_seconds: int = 900) -> RootTransitionIssuanceCandidate:
    """Validate and sign one complete private candidate cohort, without publishing.

    All caller-provided inputs are validated before the first leaf signature.
    Current policy, time and grants are rechecked after signing; if they changed,
    the uncommitted output is discarded by raising an error.
    """
    if type(old_snapshot_store) is not SnapshotStore:
        raise TypeError("issuance requires the current old SnapshotStore")
    loaded = load_protected_preparation_intent(
        approval_path, root=approval_root, expected_uid=expected_uid, clock=clock)
    intent = loaded.intent
    if old_snapshot_store.clock is not clock:
        raise CredentialError("approval and old snapshot must share the configured clock")
    sample = clock.sample()
    # Validate the entire batch, authority pair, certificate scope and proofs
    # before any call to issue_leaf.
    validated, records, not_after, view = _validate_batch(
        intent, old_snapshot_store, principal_inputs, new_ca_certificate_pem,
        new_ca_private_key_pem, new_snapshot_public_key_pem, sample,
        leaf_lifetime_seconds)
    intent_document = _intent_document(intent)
    intent_hash = hashlib.sha256(canonical_json(intent_document)).hexdigest()
    issued = []
    manifest_principals = []
    candidate_serials = {principal.old_serial for principal in intent.affected_principals}
    for item in validated:
        pem = issue_leaf(
            new_ca_certificate_pem, new_ca_private_key_pem, item.csr_pem,
            account_id=item.account_id, device_id=item.device_id, role=item.role,
            not_before=item.not_before, not_after=item.not_after,
            ekus=ROLE_EKUS[item.role])
        raw_record = _record_from_leaf(
            pem, account_id=item.account_id, device_id=item.device_id,
            role=item.role, credential_epoch=item.credential_epoch)
        record = CredentialRecord(
            raw_record["account_id"], raw_record["device_id"], raw_record["role"],
            raw_record["serial"], raw_record["public_key_sha256"],
            raw_record["certificate_sha256"], raw_record["credential_epoch"],
            raw_record["not_before"], raw_record["not_after"],
            tuple(raw_record["ekus"]), tuple(raw_record["dns_sans"]),
            tuple(raw_record["ip_sans"]))
        if record.public_key_sha256 != item.csr_key_hash:
            raise CredentialError("issued leaf does not preserve its validated CSR key")
        if (record.not_before != item.not_before or record.not_after != not_after
                or record.credential_epoch != item.credential_epoch):
            raise CredentialError("issued leaf validity or epoch differs from candidate")
        if record.serial in candidate_serials:
            raise CredentialError("issued serial collides with another cohort credential")
        candidate_serials.add(record.serial)
        verify_leaf(
            new_ca_certificate_pem, pem, now=sample.wall,
            uncertainty_seconds=sample.uncertainty,
            account_id=item.account_id, device_id=item.device_id, role=item.role,
            serial=record.serial, public_key_hash=item.csr_key_hash,
            certificate_hash=record.certificate_sha256, ekus=ROLE_EKUS[item.role],
            dns_sans=item.dns_sans, ip_sans=item.ip_sans)
        issued.append(IssuedPrincipal(item.principal.identity, pem, record))
        manifest_principals.append({
            "account_id": item.account_id, "device_id": item.device_id,
            "role": item.role, "old_serial": item.principal.old_serial,
            "old_credential_epoch": item.principal.old_credential_epoch,
            "old_admission_epoch": item.principal.old_admission_epoch,
            "new_serial": record.serial,
            "new_certificate_sha256": record.certificate_sha256,
            "new_public_key_sha256": record.public_key_sha256,
            "new_credential_epoch": record.credential_epoch,
            "new_csr_sha256": item.principal.new_csr_sha256,
            "dns_sans": list(record.dns_sans), "ip_sans": list(record.ip_sans),
            "ekus": list(record.ekus), "not_before": record.not_before,
            "not_after": record.not_after,
        })

    # Ensure the protected intent and old authorization remain current before
    # exposing any candidate bytes to the caller.
    reloaded = load_protected_preparation_intent(
        approval_path, root=approval_root, expected_uid=expected_uid, clock=clock)
    if reloaded.intent != intent:
        raise CredentialError("preparation intent changed while signing candidate")
    final_sample = clock.sample()
    if (final_sample.earliest_wall < intent.overlap_not_before
            or final_sample.latest_wall >= intent.overlap_not_after):
        raise CredentialError("trusted clock interval left the preparation overlap while signing")
    final_view, final_records = _current_authorization(
        old_snapshot_store, intent,
        tuple(PrincipalIssuanceInput(item.principal, b"", b"", b"")
              for item in validated), final_sample)
    if final_view.policy_digest != view.policy_digest or final_view.revision != view.revision:
        raise CredentialError("old snapshot policy changed while signing candidate")
    if any(final_records[key] != records[key] for key in records):
        raise CredentialError("old credentials changed while signing candidate")
    _, final_new_ca, _, _, _ = _authority_keys(
        old_snapshot_store, intent, new_ca_certificate_pem,
        new_ca_private_key_pem, new_snapshot_public_key_pem, final_sample)
    final_authority_expiry = int(final_new_ca.not_valid_after_utc.timestamp())
    final_not_after = min(int(final_sample.earliest_wall) + leaf_lifetime_seconds,
                          final_authority_expiry, intent.overlap_not_after)
    if final_not_after <= final_sample.latest_wall:
        raise CredentialError("new authority or overlap expired while signing candidate")
    for item, issued_item in zip(validated, issued):
        record = issued_item.record
        if (record.not_before != item.not_before or record.not_after != not_after
                or record.not_after <= final_sample.latest_wall):
            raise CredentialError("issued leaf expired or changed validity while signing")
        verify_leaf(
            new_ca_certificate_pem, issued_item.certificate_pem,
            now=final_sample.wall, uncertainty_seconds=final_sample.uncertainty,
            account_id=item.account_id, device_id=item.device_id, role=item.role,
            serial=record.serial, public_key_hash=item.csr_key_hash,
            certificate_hash=record.certificate_sha256, ekus=ROLE_EKUS[item.role],
            dns_sans=item.dns_sans, ip_sans=item.ip_sans)
    manifest = canonical_json({
        "domain": ISSUANCE_MANIFEST_DOMAIN, "version": 1,
        "transition_id": intent.transition_id,
        "intent_sha256": intent_hash,
        "old_ca_sha256": intent.old_ca_sha256,
        "new_ca_sha256": intent.new_ca_sha256,
        "old_snapshot_key_sha256": intent.old_snapshot_key_sha256,
        "new_snapshot_key_sha256": intent.new_snapshot_key_sha256,
        "principals": manifest_principals,
    })
    return RootTransitionIssuanceCandidate(
        intent.transition_id, intent_hash, intent.old_ca_sha256,
        intent.new_ca_sha256, intent.old_snapshot_key_sha256,
        intent.new_snapshot_key_sha256, tuple(issued), manifest)
