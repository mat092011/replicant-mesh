"""Domain-separated old-role-key possession proofs for cold root transitions.

These proofs bind a holder of an affected old role key to one exact parsed
transition declaration and CSR. They do not establish protected operator
approval, live authorization, overlap validity, policy narrowing, issuance
authority, or activation. A caller must perform those checks independently;
this proof is not an issuance authorization token.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .certificates import (MAX_CERTIFICATE_BYTES, _key, _pem_certificate,
                           certificate_sha256, public_key_sha256, serial_hex)
from .codec import canonical_json
from .errors import BindingError, CredentialError, SnapshotError
from .root_transition import (AffectedPrincipal, RootTransitionDeclaration,
                              parse_root_transition_declaration)


MAX_ROOT_TRANSITION_PROOF_BYTES = 4096
ROOT_TRANSITION_PROOF_DOMAIN = "steamboat.root-transition.old-role-key-possession.v1"
_ENVELOPE_FIELDS = frozenset({"payload", "signature"})
_PROOF_FIELDS = frozenset({
    "domain", "version", "declaration_sha256", "transition_id",
    "old_ca_sha256", "new_ca_sha256", "old_snapshot_key_sha256",
    "new_snapshot_key_sha256", "old_serial", "old_certificate_sha256",
    "old_credential_epoch", "old_admission_epoch", "new_csr_sha256",
})


def _declaration_document(declaration: RootTransitionDeclaration) -> dict[str, Any]:
    return {
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
            {
                "account_id": principal.account_id,
                "device_id": principal.device_id,
                "role": principal.role,
                "old_boot_id": principal.old_boot_id,
                "old_serial": principal.old_serial,
                "old_certificate_sha256": principal.old_certificate_sha256,
                "old_public_key_sha256": principal.old_public_key_sha256,
                "old_credential_epoch": principal.old_credential_epoch,
                "old_admission_epoch": principal.old_admission_epoch,
                "new_csr_sha256": principal.new_csr_sha256,
                "dns_sans": list(principal.dns_sans),
                "ip_sans": list(principal.ip_sans),
            }
            for principal in declaration.affected_principals
        ],
    }


def _context(declaration: RootTransitionDeclaration,
             principal: AffectedPrincipal) -> tuple[str, AffectedPrincipal]:
    if type(declaration) is not RootTransitionDeclaration:
        raise CredentialError("root transition proof requires a parsed declaration")
    if type(principal) is not AffectedPrincipal:
        raise CredentialError("root transition proof requires an exact affected principal")
    try:
        member = any(item is principal for item in declaration.affected_principals)
        encoded = canonical_json(_declaration_document(declaration))
        checked = parse_root_transition_declaration(encoded)
    except (BindingError, SnapshotError, AttributeError, TypeError, ValueError,
            RecursionError) as error:
        raise CredentialError("root transition declaration is invalid") from error
    if not member or checked != declaration:
        raise CredentialError("principal is not an exact member of the transition declaration")
    return hashlib.sha256(encoded).hexdigest(), principal


def _bound_inputs(principal: AffectedPrincipal, old_certificate_pem: bytes,
                  new_csr_pem: bytes):
    if (type(new_csr_pem) is not bytes
            or not 1 <= len(new_csr_pem) <= MAX_CERTIFICATE_BYTES):
        raise CredentialError("new CSR bytes are outside the certificate input bound")
    try:
        certificate = _pem_certificate(old_certificate_pem)
    except CredentialError:
        raise
    public_key = certificate.public_key()
    if (not isinstance(public_key, ec.EllipticCurvePublicKey)
            or not isinstance(public_key.curve, ec.SECP256R1)):
        raise CredentialError("old role certificate must contain an ECDSA P-256 key")
    actual = (
        serial_hex(certificate.serial_number),
        certificate_sha256(certificate),
        public_key_sha256(public_key),
        hashlib.sha256(new_csr_pem).hexdigest(),
    )
    expected = (
        principal.old_serial,
        principal.old_certificate_sha256,
        principal.old_public_key_sha256,
        principal.new_csr_sha256,
    )
    if actual != expected:
        raise CredentialError("old certificate or exact CSR does not match the declaration pins")
    return certificate, public_key, actual


def _proof_payload(declaration: RootTransitionDeclaration, principal: AffectedPrincipal,
                   declaration_sha256: str, actual) -> dict[str, Any]:
    serial, certificate_hash, _public_key_hash, csr_hash = actual
    return {
        "domain": ROOT_TRANSITION_PROOF_DOMAIN,
        "version": 1,
        "declaration_sha256": declaration_sha256,
        "transition_id": declaration.transition_id,
        "old_ca_sha256": declaration.old_ca_sha256,
        "new_ca_sha256": declaration.new_ca_sha256,
        "old_snapshot_key_sha256": declaration.old_snapshot_key_sha256,
        "new_snapshot_key_sha256": declaration.new_snapshot_key_sha256,
        "old_serial": serial,
        "old_certificate_sha256": certificate_hash,
        "old_credential_epoch": principal.old_credential_epoch,
        "old_admission_epoch": principal.old_admission_epoch,
        "new_csr_sha256": csr_hash,
    }


def make_old_role_key_possession_proof(
        declaration: RootTransitionDeclaration, principal: AffectedPrincipal, *,
        old_private_key_pem: bytes, old_certificate_pem: bytes,
        new_csr_pem: bytes) -> bytes:
    """Sign a declaration-bound proof with the exact affected old role key.

    This proves possession and input binding only. It grants no approval or
    authority to issue a certificate or activate a transition.
    """
    declaration_sha256, principal = _context(declaration, principal)
    certificate, certificate_public_key, actual = _bound_inputs(
        principal, old_certificate_pem, new_csr_pem)
    del certificate
    private_key = _key(old_private_key_pem)
    if private_key.public_key().public_numbers() != certificate_public_key.public_numbers():
        raise CredentialError("old private key does not match the pinned old role certificate")
    payload = _proof_payload(declaration, principal, declaration_sha256, actual)
    signature = private_key.sign(canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    encoded = canonical_json({
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    })
    if len(encoded) > MAX_ROOT_TRANSITION_PROOF_BYTES:
        raise CredentialError("root transition proof exceeds its 4 KiB bound")
    return encoded


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CredentialError("root transition proof contains a duplicate field")
        result[key] = value
    return result


def _reject_constant(_value):
    raise CredentialError("root transition proof contains a non-finite number")


def _reject_float(_value):
    raise CredentialError("root transition proof numeric fields must be integers")


def _parse_proof(encoded: bytes) -> tuple[dict, bytes]:
    if (type(encoded) is not bytes
            or not 1 <= len(encoded) <= MAX_ROOT_TRANSITION_PROOF_BYTES):
        raise CredentialError("root transition proof exceeds its 4 KiB bound")
    try:
        envelope = json.loads(encoded.decode("utf-8", errors="strict"),
                              object_pairs_hook=_pairs, parse_constant=_reject_constant,
                              parse_float=_reject_float)
    except CredentialError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise CredentialError("root transition proof envelope is malformed") from error
    if type(envelope) is not dict or set(envelope) != _ENVELOPE_FIELDS:
        raise CredentialError("root transition proof envelope has unknown or missing fields")
    try:
        if canonical_json(envelope) != encoded:
            raise CredentialError("root transition proof envelope is not canonical JSON")
    except BindingError as error:
        raise CredentialError("root transition proof envelope is not canonical JSON") from error
    payload = envelope["payload"]
    if type(payload) is not dict or set(payload) != _PROOF_FIELDS:
        raise CredentialError("root transition proof payload has unknown or missing fields")
    if type(payload["version"]) is not int or payload["version"] != 1:
        raise CredentialError("root transition proof version is invalid")
    integer_fields = {"version", "old_credential_epoch", "old_admission_epoch"}
    if any(type(value) is not int for key, value in payload.items()
           if key in integer_fields):
        raise CredentialError("root transition proof numeric fields must be integers")
    if any(type(value) is not str for key, value in payload.items()
           if key not in integer_fields):
        raise CredentialError("root transition proof payload field types are invalid")
    signature_text = envelope["signature"]
    if type(signature_text) is not str or len(signature_text) > 128:
        raise CredentialError("root transition proof signature is malformed")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (ValueError, TypeError) as error:
        raise CredentialError("root transition proof signature is malformed") from error
    if base64.b64encode(signature).decode("ascii") != signature_text:
        raise CredentialError("root transition proof signature encoding is not canonical")
    return payload, signature


def verify_old_role_key_possession_proof(
        encoded: bytes, declaration: RootTransitionDeclaration,
        principal: AffectedPrincipal, *, old_certificate_pem: bytes,
        new_csr_pem: bytes) -> None:
    """Verify the proof using only the public old certificate and exact CSR.

    Success establishes possession and exact declaration binding only. It does
    not establish approval, current policy, overlap validity, issuance authority,
    or activation.
    """
    declaration_sha256, principal = _context(declaration, principal)
    _certificate, public_key, actual = _bound_inputs(
        principal, old_certificate_pem, new_csr_pem)
    payload, signature = _parse_proof(encoded)
    expected = _proof_payload(declaration, principal, declaration_sha256, actual)
    if payload != expected:
        raise CredentialError("root transition proof is bound to different declaration inputs")
    try:
        public_key.verify(signature, canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError) as error:
        raise CredentialError("root transition proof signature is invalid") from error
