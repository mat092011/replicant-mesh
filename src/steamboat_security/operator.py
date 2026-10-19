"""Offline invited enrollment, CSR renewal and fixture authority operations."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import asdict
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .certificates import (ROLE_EKUS, _csr, _key, _pem_certificate, _validate_sans, certificate_sha256,
                           generate_private_key_pem, identity_uri, issue_leaf, make_csr,
                           public_key_sha256, serial_hex, verify_leaf)
from .clock import Clock
from .codec import canonical_json
from .errors import CredentialError, SnapshotError
from .ids import validate_id
from .snapshot import (MAX_SNAPSHOT_LIFETIME_SECONDS, SnapshotStore,
                       snapshot_public_key_pem, sign_snapshot)


MAX_INVITATION_LIFETIME_SECONDS = 600
MAX_INVITATIONS_RETAINED = 4096


def generate_authorization_signing_key_pem() -> bytes:
    """Create the authority/snapshot key; keep it separate from the cohort CA."""
    return generate_private_key_pem()


def _sign(private_key_pem: bytes, payload: dict) -> bytes:
    key = _key(private_key_pem)
    signature = key.sign(canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    return canonical_json({"payload": payload,
                           "signature": base64.b64encode(signature).decode("ascii")})


def _verify_signed(encoded: bytes, public_key_pem: bytes, *, max_bytes: int) -> dict:
    if type(encoded) is not bytes or not 1 <= len(encoded) <= max_bytes:
        raise CredentialError("signed operator document exceeds its bound")
    try:
        envelope = json.loads(encoded.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                              parse_constant=_reject_constant)
    except (ValueError, UnicodeError, TypeError, RecursionError) as error:
        raise CredentialError("signed operator document is malformed") from error
    if type(envelope) is not dict or set(envelope) != {"payload", "signature"}:
        raise CredentialError("signed operator document has unknown fields")
    if canonical_json(envelope) != encoded:
        raise CredentialError("signed operator document is not canonical")
    signature_text = envelope["signature"]
    if type(signature_text) is not str or len(signature_text) > 128:
        raise CredentialError("operator signature is malformed")
    try:
        signature = base64.b64decode(signature_text, validate=True)
        key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise CredentialError("operator verification key must be ECDSA P-256")
        key.verify(signature, canonical_json(envelope["payload"]), ec.ECDSA(hashes.SHA256()))
    except (ValueError, TypeError, InvalidSignature) as error:
        raise CredentialError("operator signature is invalid") from error
    if type(envelope["payload"]) is not dict:
        raise CredentialError("operator payload must be an object")
    return envelope["payload"]


def _pairs(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            raise CredentialError("operator document contains duplicate keys")
        values[key] = value
    return values


def _reject_constant(_):
    raise CredentialError("operator document contains a non-finite value")


def create_invitation(signing_key_pem: bytes, *, account_id: str, device_id: str,
                      roles: tuple[str, ...] | list[str], now: int,
                      lifetime_seconds: int = 600) -> bytes:
    validate_id(account_id, "acct")
    validate_id(device_id, "dev")
    if type(now) is not int or now < 0:
        raise ValueError("invitation issue time must be an integer epoch")
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= MAX_INVITATION_LIFETIME_SECONDS:
        raise ValueError("invitation lifetime must be at most ten minutes")
    if type(roles) not in (tuple, list) or not roles or len(roles) > len(ROLE_EKUS):
        raise ValueError("invitation role list is empty or too large")
    role_values = tuple(sorted(set(roles)))
    if len(role_values) != len(roles) or any(role not in ROLE_EKUS for role in role_values):
        raise ValueError("invitation roles are invalid or duplicated")
    payload = {"version": 1, "account_id": account_id, "device_id": device_id,
               "roles": list(role_values), "nonce": secrets.token_hex(16),
               "issued_at": now, "expires_at": now + lifetime_seconds}
    return _sign(signing_key_pem, payload)


class InvitationRegistry:
    """One-use offline invite verifier with bounded replay retention."""

    def __init__(self, *, verification_key_pem: bytes, clock: Clock,
                 max_retained: int = MAX_INVITATIONS_RETAINED):
        if type(max_retained) is not int or not 1 <= max_retained <= MAX_INVITATIONS_RETAINED:
            raise ValueError("invitation replay bound is invalid")
        self.verification_key_pem = verification_key_pem
        self.clock = clock
        self.max_retained = max_retained
        self._used: set[str] = set()

    def consume(self, encoded: bytes) -> dict:
        payload = _verify_signed(encoded, self.verification_key_pem, max_bytes=4096)
        expected = {"version", "account_id", "device_id", "roles", "nonce", "issued_at", "expires_at"}
        if set(payload) != expected or type(payload["version"]) is not int or payload["version"] != 1:
            raise CredentialError("invitation schema is invalid")
        account = validate_id(payload["account_id"], "acct")
        device = validate_id(payload["device_id"], "dev")
        roles = payload["roles"]
        if type(roles) is not list or not roles or roles != sorted(set(roles)) or any(role not in ROLE_EKUS for role in roles):
            raise CredentialError("invitation roles are invalid")
        nonce = payload["nonce"]
        if type(nonce) is not str or len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
            raise CredentialError("invitation nonce is invalid")
        issued, expires = payload["issued_at"], payload["expires_at"]
        if type(issued) is not int or type(expires) is not int or expires <= issued or expires - issued > 600:
            raise CredentialError("invitation validity is invalid")
        sample = self.clock.sample()
        if issued > sample.earliest_wall or expires <= sample.latest_wall:
            raise CredentialError("invitation is outside its validity interval")
        if nonce in self._used:
            raise CredentialError("invitation was already consumed")
        if len(self._used) >= self.max_retained:
            raise CredentialError("invitation replay table is full")
        self._used.add(nonce)
        return {"account_id": account, "device_id": device, "roles": tuple(roles),
                "nonce": nonce, "issued_at": issued, "expires_at": expires}


def _record_from_leaf(leaf_pem: bytes, *, account_id: str, device_id: str,
                      role: str, credential_epoch: int) -> dict:
    cert = _pem_certificate(leaf_pem)
    from cryptography.x509.oid import ExtendedKeyUsageOID
    eku_extension = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    eku_names = sorted("client" if value == ExtendedKeyUsageOID.CLIENT_AUTH else "server"
                       for value in eku_extension.value)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = sorted(value.lower() for value in san.get_values_for_type(x509.DNSName))
    ips = sorted(str(value) for value in san.get_values_for_type(x509.IPAddress))
    return {"account_id": account_id, "device_id": device_id, "role": role,
            "serial": serial_hex(cert.serial_number),
            "public_key_sha256": public_key_sha256(cert.public_key()),
            "certificate_sha256": certificate_sha256(cert),
            "credential_epoch": credential_epoch,
            "not_before": int(cert.not_valid_before_utc.timestamp()),
            "not_after": int(cert.not_valid_after_utc.timestamp()),
            "ekus": eku_names, "dns_sans": dns, "ip_sans": ips}


def enroll_invited(*, invitation_registry: InvitationRegistry, invitation: bytes,
                   csr_by_role: dict[str, bytes], ca_certificate_pem: bytes,
                   ca_private_key_pem: bytes, now: int,
                   leaf_lifetime_seconds: int = 900,
                   ekus_by_role: dict[str, tuple[str, ...]] | None = None) -> tuple[dict[str, bytes], list[dict]]:
    """Issue role-specific leaves from local CSRs after one-use operator invite."""
    invite = invitation_registry.consume(invitation)
    if type(csr_by_role) is not dict or set(csr_by_role) != set(invite["roles"]):
        raise CredentialError("CSRs do not exactly cover invited roles")
    default_ekus = {"consumer": ("client",), "host": ("server",),
                    "personal_coordinator": ("client", "server")}
    if ekus_by_role is None:
        ekus_by_role = {role: default_ekus[role] for role in invite["roles"]}
    if type(ekus_by_role) is not dict or set(ekus_by_role) != set(invite["roles"]):
        raise CredentialError("operator EKU approvals must exactly cover invited roles")
    if type(now) is not int or not 1 <= leaf_lifetime_seconds <= 900:
        raise ValueError("leaf issue time or lifetime is invalid")
    try:
        ca = _pem_certificate(ca_certificate_pem)
        authorization_key = serialization.load_pem_public_key(
            invitation_registry.verification_key_pem)
    except (ValueError, TypeError) as error:
        raise CredentialError("enrollment authority keys are malformed") from error
    forbidden_hashes = {public_key_sha256(ca.public_key()),
                        public_key_sha256(authorization_key)}
    role_key_hashes = set()
    for role in invite["roles"]:
        csr = _csr(csr_by_role[role])
        uri, _dns, _ips = _validate_sans(csr)
        if uri != identity_uri(invite["account_id"], invite["device_id"], role):
            raise CredentialError("CSR identity differs from the invitation role")
        key_hash = public_key_sha256(csr.public_key())
        if key_hash in forbidden_hashes or key_hash in role_key_hashes:
            raise CredentialError("role CSRs must use distinct non-authority keys")
        role_key_hashes.add(key_hash)
    before, after = now, now + leaf_lifetime_seconds
    issued = {}
    records = []
    for role in invite["roles"]:
        pem = issue_leaf(ca_certificate_pem, ca_private_key_pem, csr_by_role[role],
                         account_id=invite["account_id"], device_id=invite["device_id"],
                         role=role, not_before=before, not_after=after,
                         ekus=ekus_by_role[role])
        issued[role] = pem
        records.append(_record_from_leaf(pem, account_id=invite["account_id"],
                                         device_id=invite["device_id"], role=role,
                                         credential_epoch=1))
    return issued, records


def make_renewal_proof(old_private_key_pem: bytes, old_certificate_pem: bytes,
                       new_csr_pem: bytes) -> bytes:
    """Old role key signs exact new CSR and old serial for offline renewal."""
    old_key = _key(old_private_key_pem)
    old_cert = _pem_certificate(old_certificate_pem)
    if old_key.public_key().public_numbers() != old_cert.public_key().public_numbers():
        raise CredentialError("renewal key does not match current role certificate")
    payload = {"version": 1, "old_serial": serial_hex(old_cert.serial_number),
               "new_csr_sha256": hashlib.sha256(new_csr_pem).hexdigest()}
    signature = old_key.sign(canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    return canonical_json({"payload": payload,
                           "signature": base64.b64encode(signature).decode("ascii")})


def renew_leaf(*, ca_certificate_pem: bytes, ca_private_key_pem: bytes,
               snapshot_store: SnapshotStore, old_certificate_pem: bytes,
               new_csr_pem: bytes, renewal_proof: bytes,
               leaf_lifetime_seconds: int = 900) -> tuple[bytes, dict]:
    """Verify a device-signed renewal against current signed authority and issue.

    The operator needs only the public old certificate and device-generated CSR
    proof; the old device private key never enters the issuer process.
    """
    if not 1 <= leaf_lifetime_seconds <= 900:
        raise ValueError("renewed leaf must be at most 900 seconds")
    sample = snapshot_store.clock.sample()
    view = snapshot_store.current(sample=sample)
    old_cert = _pem_certificate(old_certificate_pem)
    old_serial = serial_hex(old_cert.serial_number)
    enrolled_record = view.credentials_by_serial.get(old_serial)
    if enrolled_record is None:
        raise CredentialError("renewal credential is not in the current snapshot")
    current_record = asdict(enrolled_record)
    if (certificate_sha256(_pem_certificate(ca_certificate_pem))
            != certificate_sha256(_pem_certificate(snapshot_store.ca_certificate_pem))):
        raise CredentialError("renewal CA differs from the current snapshot authority")
    snapshot_store.assert_credential_live(view, enrolled_record, sample)
    if not any(grant.actor_serial == old_serial or grant.target_serial == old_serial
               for grant in view.active_grants(sample)):
        raise CredentialError("renewal requires a current scoped grant")
    old = verify_leaf(ca_certificate_pem, old_certificate_pem, now=sample.wall,
                      uncertainty_seconds=sample.uncertainty,
                      account_id=current_record["account_id"], device_id=current_record["device_id"],
                      role=current_record["role"], serial=current_record["serial"],
                      public_key_hash=current_record["public_key_sha256"],
                      certificate_hash=current_record["certificate_sha256"],
                      ekus=current_record["ekus"], dns_sans=current_record["dns_sans"],
                      ip_sans=current_record["ip_sans"])
    if (int(old.not_valid_before_utc.timestamp()) != current_record["not_before"]
            or int(old.not_valid_after_utc.timestamp()) != current_record["not_after"]):
        raise CredentialError("snapshot credential validity differs from the pinned leaf")
    if old.not_valid_after_utc.timestamp() - sample.latest_wall > 300:
        raise CredentialError("renewal may begin only within 300 seconds of expiry")
    _uri, dns_sans, ip_sans = _validate_sans(_csr(new_csr_pem))
    if _uri != identity_uri(current_record["account_id"], current_record["device_id"],
                            current_record["role"]):
        raise CredentialError("renewal CSR changes the enrolled identity or role")
    if (dns_sans != tuple(current_record["dns_sans"])
            or ip_sans != tuple(current_record["ip_sans"])):
        raise CredentialError("renewal cannot change the enrolled host SAN scope")
    proof = _verify_signed(renewal_proof, old.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), max_bytes=4096)
    if (set(proof) != {"version", "old_serial", "new_csr_sha256"}
            or type(proof["version"]) is not int or proof["version"] != 1):
        raise CredentialError("renewal proof schema is invalid")
    if (proof["old_serial"] != current_record["serial"]
            or proof["new_csr_sha256"] != hashlib.sha256(new_csr_pem).hexdigest()):
        raise CredentialError("renewal proof does not bind the current certificate and CSR")
    csr_key_hash = public_key_sha256(_csr(new_csr_pem).public_key())
    snapshot_store.assert_role_key_allowed(csr_key_hash)
    if any(record.serial != old_serial and record.public_key_sha256 == csr_key_hash
           for record in view.credentials_by_serial.values()):
        raise CredentialError("renewal key is already assigned to another role credential")
    eku_values = tuple(current_record["ekus"])
    issue_time = int(sample.earliest_wall)
    renewed = issue_leaf(ca_certificate_pem, ca_private_key_pem, new_csr_pem,
                         account_id=current_record["account_id"], device_id=current_record["device_id"],
                         role=current_record["role"], not_before=issue_time,
                         not_after=issue_time + leaf_lifetime_seconds,
                         ekus=eku_values)
    record = _record_from_leaf(renewed, account_id=current_record["account_id"],
                               device_id=current_record["device_id"], role=current_record["role"],
                               credential_epoch=current_record["credential_epoch"] + 1)
    return renewed, record


def publish_snapshot(payload: dict, signing_key_pem: bytes) -> bytes:
    return sign_snapshot(payload, signing_key_pem)
