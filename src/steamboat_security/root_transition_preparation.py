"""Protected preparation intent and old-role-key proof for cold root changes.

PreparationIntent is a distinct, closed operator input. It deliberately has no
new policy digest: certificate issuance must first create the staged cohort
whose manifest determines that digest. Parsing and loading this intent do not
approve activation. A possession proof binds an old role key to this exact
intent, certificate, and CSR; it is an input to later authorized validation
and private staging and grants no authority by itself. Final activation still
requires the actual staged certificate manifest, its computed new policy digest,
final full-declaration proofs, and
exact common-field checks. No approval is inferred here. This module does not
issue certificates, establish liveness, validate policy narrowing, or activate
a transition.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
from dataclasses import dataclass
from os import PathLike

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .certificates import (MAX_CERTIFICATE_BYTES, ROLE_EKUS, _DNS, _key,
                          _pem_certificate, certificate_sha256,
                          public_key_sha256, serial_hex)
from .clock import Clock
from .codec import canonical_json
from .errors import BindingError, CredentialError, SnapshotError, StorageError
from .files import safe_read
from .ids import validate_boot, validate_id
from .root_transition import (MAX_TRANSITION_APPROVAL_BYTES,
                              MAX_TRANSITION_PRINCIPALS, MAX_TRANSITION_SANS,
                              AffectedPrincipal)


PREPARATION_PURPOSE = "prepare_root_transition"
MAX_PREPARATION_PROOF_BYTES = 4096
PREPARATION_PROOF_DOMAIN = "steamboat.root-transition.preparation.old-role-key-possession.v1"
_HEX32 = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SERIAL = re.compile(r"^[1-9a-f][0-9a-f]{0,39}$", re.ASCII)
_FIELDS = frozenset({
    "purpose", "schema_version", "transition_id", "old_ca_sha256",
    "new_ca_sha256", "old_snapshot_key_sha256", "new_snapshot_key_sha256",
    "overlap_not_before", "overlap_not_after", "old_policy_revision",
    "old_policy_digest", "next_minimum_revision", "affected_principals",
})
_PRINCIPAL_FIELDS = frozenset({
    "account_id", "device_id", "role", "old_boot_id", "old_serial",
    "old_certificate_sha256", "old_public_key_sha256", "old_credential_epoch",
    "old_admission_epoch", "new_csr_sha256", "dns_sans", "ip_sans",
})
_PROOF_FIELDS = frozenset({
    "domain", "version", "intent_sha256", "transition_id", "old_ca_sha256",
    "new_ca_sha256", "old_snapshot_key_sha256", "new_snapshot_key_sha256",
    "old_serial", "old_certificate_sha256", "old_credential_epoch",
    "old_admission_epoch", "new_csr_sha256",
})
_ENVELOPE_FIELDS = frozenset({"payload", "signature"})


@dataclass(frozen=True)
class PreparationIntent:
    purpose: str
    schema_version: int
    transition_id: str
    old_ca_sha256: str
    new_ca_sha256: str
    old_snapshot_key_sha256: str
    new_snapshot_key_sha256: str
    overlap_not_before: int
    overlap_not_after: int
    old_policy_revision: int
    old_policy_digest: str
    next_minimum_revision: int
    affected_principals: tuple[AffectedPrincipal, ...]


@dataclass(frozen=True)
class LoadedPreparationIntent:
    """Protected-file and overlap-checked operator preparation input only."""

    intent: PreparationIntent


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError("preparation intent contains a duplicate field")
        result[key] = value
    return result


def _reject_constant(_value):
    raise SnapshotError("preparation intent contains a non-finite number")


def _reject_float(value):
    try:
        finite = math.isfinite(float(value))
    except (TypeError, ValueError, OverflowError):
        finite = False
    if not finite:
        raise SnapshotError("preparation intent contains a non-finite number")
    raise SnapshotError("preparation intent numeric fields must be integers")


def _exact_int(value, field: str, *, minimum: int) -> int:
    if type(value) is not int or value < minimum:
        raise SnapshotError(f"preparation intent {field} is invalid")
    return value


def _hash(value, field: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise SnapshotError(f"preparation intent {field} must be lowercase SHA-256 hex")
    return value


def _sans(value, field: str, *, dns: bool) -> tuple[str, ...]:
    if type(value) is not list or len(value) > MAX_TRANSITION_SANS:
        raise SnapshotError(f"preparation intent {field} exceeds its bound")
    if any(type(item) is not str for item in value):
        raise SnapshotError(f"preparation intent {field} must contain strings")
    if value != sorted(value) or len(value) != len(set(value)):
        raise SnapshotError(f"preparation intent {field} must be sorted and unique")
    if dns:
        if any(item != item.lower() or not _DNS.fullmatch(item) or "*" in item
               for item in value):
            raise SnapshotError("preparation intent DNS SAN is invalid")
    else:
        try:
            if any(str(ipaddress.ip_address(item)) != item for item in value):
                raise SnapshotError("preparation intent IP SAN must be canonical")
        except ValueError as error:
            raise SnapshotError("preparation intent IP SAN is invalid") from error
    return tuple(value)


def _principal(raw) -> AffectedPrincipal:
    if type(raw) is not dict or set(raw) != _PRINCIPAL_FIELDS:
        raise SnapshotError("preparation intent principal has unknown or missing fields")
    try:
        account_id = validate_id(raw["account_id"], "acct")
        device_id = validate_id(raw["device_id"], "dev")
        old_boot_id = validate_boot(raw["old_boot_id"])
    except BindingError as error:
        raise SnapshotError("preparation intent principal identity is invalid") from error
    role = raw["role"]
    if type(role) is not str or role not in ROLE_EKUS:
        raise SnapshotError("preparation intent role is invalid")
    serial = raw["old_serial"]
    if type(serial) is not str or not _SERIAL.fullmatch(serial):
        raise SnapshotError("preparation intent old serial is invalid")
    return AffectedPrincipal(
        account_id, device_id, role, old_boot_id, serial,
        _hash(raw["old_certificate_sha256"], "old certificate hash"),
        _hash(raw["old_public_key_sha256"], "old public key hash"),
        _exact_int(raw["old_credential_epoch"], "old credential epoch", minimum=1),
        _exact_int(raw["old_admission_epoch"], "old admission epoch", minimum=1),
        _hash(raw["new_csr_sha256"], "new CSR hash"),
        _sans(raw["dns_sans"], "DNS SANs", dns=True),
        _sans(raw["ip_sans"], "IP SANs", dns=False),
    )


def parse_preparation_intent(encoded: bytes) -> PreparationIntent:
    """Parse a closed v1 preparation intent; parsing alone grants no authority."""
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_TRANSITION_APPROVAL_BYTES:
        raise SnapshotError("preparation intent exceeds its 16 KiB bound")
    try:
        raw = json.loads(encoded.decode("utf-8", errors="strict"),
                         object_pairs_hook=_pairs, parse_constant=_reject_constant,
                         parse_float=_reject_float)
    except SnapshotError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise SnapshotError("preparation intent is malformed JSON") from error
    if type(raw) is not dict or set(raw) != _FIELDS:
        raise SnapshotError("preparation intent has unknown or missing fields")
    if type(raw["purpose"]) is not str or raw["purpose"] != PREPARATION_PURPOSE:
        raise SnapshotError("preparation intent purpose is invalid")
    if _exact_int(raw["schema_version"], "schema version", minimum=1) != 1:
        raise SnapshotError("unsupported preparation intent schema version")
    transition_id = raw["transition_id"]
    if type(transition_id) is not str or not _HEX32.fullmatch(transition_id):
        raise SnapshotError("preparation intent ID must be 32 lowercase hex characters")
    old_ca = _hash(raw["old_ca_sha256"], "old CA fingerprint")
    new_ca = _hash(raw["new_ca_sha256"], "new CA fingerprint")
    old_key = _hash(raw["old_snapshot_key_sha256"], "old snapshot key fingerprint")
    new_key = _hash(raw["new_snapshot_key_sha256"], "new snapshot key fingerprint")
    if old_ca == new_ca and old_key == new_key:
        raise SnapshotError("preparation intent must change an authority fingerprint")
    start = _exact_int(raw["overlap_not_before"], "overlap start", minimum=0)
    end = _exact_int(raw["overlap_not_after"], "overlap end", minimum=1)
    if end <= start or end - start > 300:
        raise SnapshotError("preparation intent overlap must be positive and at most 300 seconds")
    old_revision = _exact_int(raw["old_policy_revision"], "old policy revision", minimum=1)
    next_revision = _exact_int(raw["next_minimum_revision"], "next minimum revision", minimum=1)
    if next_revision != old_revision + 1:
        raise SnapshotError("preparation intent minimum revision must advance by one")
    old_digest = _hash(raw["old_policy_digest"], "old policy digest")
    principals_raw = raw["affected_principals"]
    if (type(principals_raw) is not list
            or not 1 <= len(principals_raw) <= MAX_TRANSITION_PRINCIPALS):
        raise SnapshotError("preparation intent principal count is outside its bound")
    principals = tuple(_principal(item) for item in principals_raw)
    identities = tuple(item.identity for item in principals)
    if identities != tuple(sorted(identities)) or len(set(identities)) != len(identities):
        raise SnapshotError("preparation intent principals must be sorted and unique")
    for label, pins in (
            ("serial", tuple(item.old_serial for item in principals)),
            ("certificate", tuple(item.old_certificate_sha256 for item in principals)),
            ("CSR", tuple(item.new_csr_sha256 for item in principals))):
        if len(pins) != len(set(pins)):
            raise SnapshotError(f"preparation intent {label} pins must be unique")
    return PreparationIntent(
        PREPARATION_PURPOSE, 1, transition_id, old_ca, new_ca, old_key, new_key,
        start, end, old_revision, old_digest, next_revision, principals)


def _intent_document(intent: PreparationIntent) -> dict:
    return {
        "purpose": intent.purpose,
        "schema_version": intent.schema_version,
        "transition_id": intent.transition_id,
        "old_ca_sha256": intent.old_ca_sha256,
        "new_ca_sha256": intent.new_ca_sha256,
        "old_snapshot_key_sha256": intent.old_snapshot_key_sha256,
        "new_snapshot_key_sha256": intent.new_snapshot_key_sha256,
        "overlap_not_before": intent.overlap_not_before,
        "overlap_not_after": intent.overlap_not_after,
        "old_policy_revision": intent.old_policy_revision,
        "old_policy_digest": intent.old_policy_digest,
        "next_minimum_revision": intent.next_minimum_revision,
        "affected_principals": [
            {"account_id": p.account_id, "device_id": p.device_id, "role": p.role,
             "old_boot_id": p.old_boot_id, "old_serial": p.old_serial,
             "old_certificate_sha256": p.old_certificate_sha256,
             "old_public_key_sha256": p.old_public_key_sha256,
             "old_credential_epoch": p.old_credential_epoch,
             "old_admission_epoch": p.old_admission_epoch,
             "new_csr_sha256": p.new_csr_sha256,
             "dns_sans": list(p.dns_sans), "ip_sans": list(p.ip_sans)}
            for p in intent.affected_principals],
    }


def _check_clock(intent: PreparationIntent, clock: Clock) -> None:
    if not isinstance(clock, Clock):
        raise TypeError("preparation intent loader requires the configured Clock")
    sample = clock.sample()
    if (sample.earliest_wall < intent.overlap_not_before
            or sample.latest_wall >= intent.overlap_not_after):
        raise SnapshotError("trusted clock interval is outside the preparation overlap")


def load_protected_preparation_intent(
        path: str | PathLike, *, root: str | PathLike, expected_uid: int,
        clock: Clock) -> LoadedPreparationIntent:
    """Load protected local preparation input and check its conservative overlap.

    This establishes no activation approval and does not perform issuance,
    liveness, narrowing, or staged-manifest checks.
    """
    encoded = safe_read(path, root=root, expected_uid=expected_uid,
                        max_bytes=MAX_TRANSITION_APPROVAL_BYTES)
    intent = parse_preparation_intent(encoded)
    _check_clock(intent, clock)
    return LoadedPreparationIntent(intent)


def _proof_context(intent: PreparationIntent, principal: AffectedPrincipal) -> tuple[str, AffectedPrincipal]:
    if type(intent) is not PreparationIntent:
        raise CredentialError("preparation proof requires a parsed preparation intent")
    if type(principal) is not AffectedPrincipal:
        raise CredentialError("preparation proof requires an exact affected principal")
    try:
        member = any(item is principal for item in intent.affected_principals)
        encoded = canonical_json(_intent_document(intent))
        checked = parse_preparation_intent(encoded)
    except (BindingError, SnapshotError, AttributeError, TypeError, ValueError,
            RecursionError) as error:
        raise CredentialError("preparation intent is invalid") from error
    if not member or checked != intent:
        raise CredentialError("principal is not an exact member of the preparation intent")
    return hashlib.sha256(encoded).hexdigest(), principal


def _bound_inputs(principal: AffectedPrincipal, certificate_pem: bytes, csr_pem: bytes):
    if type(csr_pem) is not bytes or not 1 <= len(csr_pem) <= MAX_CERTIFICATE_BYTES:
        raise CredentialError("new CSR bytes are outside the certificate input bound")
    certificate = _pem_certificate(certificate_pem)
    public_key = certificate.public_key()
    if (not isinstance(public_key, ec.EllipticCurvePublicKey)
            or not isinstance(public_key.curve, ec.SECP256R1)):
        raise CredentialError("old role certificate must contain an ECDSA P-256 key")
    actual = (serial_hex(certificate.serial_number), certificate_sha256(certificate),
              public_key_sha256(public_key), hashlib.sha256(csr_pem).hexdigest())
    expected = (principal.old_serial, principal.old_certificate_sha256,
                principal.old_public_key_sha256, principal.new_csr_sha256)
    if actual != expected:
        raise CredentialError("old certificate or exact CSR does not match preparation pins")
    return public_key, actual


def _proof_payload(intent: PreparationIntent, principal: AffectedPrincipal,
                   intent_hash: str, actual) -> dict:
    serial, cert_hash, _key_hash, csr_hash = actual
    return {
        "domain": PREPARATION_PROOF_DOMAIN, "version": 1,
        "intent_sha256": intent_hash, "transition_id": intent.transition_id,
        "old_ca_sha256": intent.old_ca_sha256, "new_ca_sha256": intent.new_ca_sha256,
        "old_snapshot_key_sha256": intent.old_snapshot_key_sha256,
        "new_snapshot_key_sha256": intent.new_snapshot_key_sha256,
        "old_serial": serial, "old_certificate_sha256": cert_hash,
        "old_credential_epoch": principal.old_credential_epoch,
        "old_admission_epoch": principal.old_admission_epoch,
        "new_csr_sha256": csr_hash,
    }


def make_preparation_possession_proof(
        intent: PreparationIntent, principal: AffectedPrincipal, *,
        old_private_key_pem: bytes, old_certificate_pem: bytes,
        new_csr_pem: bytes) -> bytes:
    """Sign exact preparation-intent possession binding; no issue/activate authority."""
    intent_hash, principal = _proof_context(intent, principal)
    public_key, actual = _bound_inputs(principal, old_certificate_pem, new_csr_pem)
    private_key = _key(old_private_key_pem)
    if private_key.public_key().public_numbers() != public_key.public_numbers():
        raise CredentialError("old private key does not match the pinned role certificate")
    payload = _proof_payload(intent, principal, intent_hash, actual)
    signature = private_key.sign(canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    encoded = canonical_json({"payload": payload,
                              "signature": base64.b64encode(signature).decode("ascii")})
    if len(encoded) > MAX_PREPARATION_PROOF_BYTES:
        raise CredentialError("preparation proof exceeds its 4 KiB bound")
    return encoded


def _proof_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CredentialError("preparation proof contains a duplicate field")
        result[key] = value
    return result


def _proof_constant(_value):
    raise CredentialError("preparation proof contains a non-finite number")


def _proof_float(_value):
    raise CredentialError("preparation proof numeric fields must be integers")


def _parse_proof(encoded: bytes) -> tuple[dict, bytes]:
    if type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_PREPARATION_PROOF_BYTES:
        raise CredentialError("preparation proof exceeds its 4 KiB bound")
    try:
        envelope = json.loads(encoded.decode("utf-8", errors="strict"),
                              object_pairs_hook=_proof_pairs,
                              parse_constant=_proof_constant, parse_float=_proof_float)
    except CredentialError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise CredentialError("preparation proof envelope is malformed") from error
    if type(envelope) is not dict or set(envelope) != _ENVELOPE_FIELDS:
        raise CredentialError("preparation proof envelope has unknown or missing fields")
    try:
        if canonical_json(envelope) != encoded:
            raise CredentialError("preparation proof envelope is not canonical JSON")
    except BindingError as error:
        raise CredentialError("preparation proof envelope is not canonical JSON") from error
    payload = envelope["payload"]
    if type(payload) is not dict or set(payload) != _PROOF_FIELDS:
        raise CredentialError("preparation proof payload has unknown or missing fields")
    if type(payload["version"]) is not int or payload["version"] != 1:
        raise CredentialError("preparation proof version is invalid")
    integers = {"version", "old_credential_epoch", "old_admission_epoch"}
    if any(type(value) is not int for key, value in payload.items() if key in integers):
        raise CredentialError("preparation proof numeric fields must be integers")
    if any(type(value) is not str for key, value in payload.items() if key not in integers):
        raise CredentialError("preparation proof payload field types are invalid")
    signature_text = envelope["signature"]
    if type(signature_text) is not str or len(signature_text) > 128:
        raise CredentialError("preparation proof signature is malformed")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (ValueError, TypeError) as error:
        raise CredentialError("preparation proof signature is malformed") from error
    if base64.b64encode(signature).decode("ascii") != signature_text:
        raise CredentialError("preparation proof signature encoding is not canonical")
    return payload, signature


def verify_preparation_possession_proof(
        encoded: bytes, intent: PreparationIntent, principal: AffectedPrincipal, *,
        old_certificate_pem: bytes, new_csr_pem: bytes) -> None:
    """Verify possession binding only; it grants no issuance or activation authority."""
    intent_hash, principal = _proof_context(intent, principal)
    public_key, actual = _bound_inputs(principal, old_certificate_pem, new_csr_pem)
    payload, signature = _parse_proof(encoded)
    expected = _proof_payload(intent, principal, intent_hash, actual)
    if payload != expected:
        raise CredentialError("preparation proof is bound to different intent inputs")
    try:
        public_key.verify(signature, canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError) as error:
        raise CredentialError("preparation proof signature is invalid") from error
