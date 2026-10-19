"""ECDSA P-256/SHA-256 CA, CSR, leaf issue and strict offline validation."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .errors import CredentialError
from .ids import validate_id


MAX_LEAF_LIFETIME_SECONDS = 900
MAX_CERTIFICATE_BYTES = 64 * 1024
ROLE_EKUS = {
    "consumer": frozenset({"client"}),
    "host": frozenset({"server"}),
    "personal_coordinator": frozenset({"client", "server"}),
}
_EKU_OIDS = {"client": ExtendedKeyUsageOID.CLIENT_AUTH,
             "server": ExtendedKeyUsageOID.SERVER_AUTH}
_DNS = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$", re.ASCII)


def _utc(value: datetime | float | int) -> datetime:
    if type(value) in (int, float):
        return datetime.fromtimestamp(float(value), timezone.utc)
    if not isinstance(value, datetime):
        raise ValueError("certificate time must be a UTC datetime or epoch")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _epoch(value: datetime) -> int:
    return int(value.timestamp())


def _key(pem: bytes):
    if type(pem) is not bytes or len(pem) > MAX_CERTIFICATE_BYTES:
        raise CredentialError("private key input is malformed")
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as error:
        raise CredentialError("private key input is malformed") from error
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise CredentialError("only ECDSA P-256 private keys are accepted")
    return key


def _pem_certificate(pem: bytes) -> x509.Certificate:
    if type(pem) is not bytes or not 1 <= len(pem) <= MAX_CERTIFICATE_BYTES:
        raise CredentialError("certificate input exceeds its bound")
    try:
        cert = x509.load_pem_x509_certificate(pem)
    except (ValueError, TypeError) as error:
        raise CredentialError("certificate input is malformed") from error
    canonical = cert.public_bytes(serialization.Encoding.PEM)
    if pem.strip() != canonical.strip():
        raise CredentialError("certificate input must contain exactly one PEM certificate")
    return cert


def _csr(pem: bytes) -> x509.CertificateSigningRequest:
    if type(pem) is not bytes or not 1 <= len(pem) <= MAX_CERTIFICATE_BYTES:
        raise CredentialError("CSR input exceeds its bound")
    try:
        csr = x509.load_pem_x509_csr(pem)
    except (ValueError, TypeError) as error:
        raise CredentialError("CSR input is malformed") from error
    if not csr.is_signature_valid:
        raise CredentialError("CSR proof of possession is invalid")
    if not isinstance(csr.public_key(), ec.EllipticCurvePublicKey) or not isinstance(csr.public_key().curve, ec.SECP256R1):
        raise CredentialError("CSR key must be ECDSA P-256")
    return csr


def _serial() -> int:
    return secrets.randbits(159) or 1


def public_key_sha256(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def certificate_sha256(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def serial_hex(serial: int) -> str:
    if type(serial) is not int or serial <= 0:
        raise ValueError("serial must be a positive integer")
    return format(serial, "x")


def identity_uri(account_id: str, device_id: str, role: str) -> str:
    validate_id(account_id, "acct")
    validate_id(device_id, "dev")
    if role not in ROLE_EKUS:
        raise ValueError("unknown credential role")
    return f"urn:steamboat:participant:v1:{account_id}:{device_id}:{role}"


def generate_private_key_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def generate_ca(*, common_name: str = "steamboat nonproduction cohort CA",
                now: datetime | float | int | None = None,
                lifetime_days: int = 3650) -> tuple[bytes, bytes]:
    """Create an operator-only test CA; never copy its private key to a participant."""
    if type(lifetime_days) is not int or not 1 <= lifetime_days <= 36500:
        raise ValueError("CA lifetime is outside the operator bound")
    current = _utc(now if now is not None else datetime.now(timezone.utc))
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name[:64])])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(_serial())
            .not_valid_before(current.replace(tzinfo=None))
            .not_valid_after((current + timedelta(days=lifetime_days)).replace(tzinfo=None))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=None, decipher_only=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


def verify_ca(ca_pem: bytes, *, now: datetime | float | int,
              uncertainty_seconds: float = 0.0) -> x509.Certificate:
    cert = _pem_certificate(ca_pem)
    if cert.subject != cert.issuer:
        raise CredentialError("configured cohort root must be self-issued")
    public_key = cert.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise CredentialError("cohort root must use ECDSA P-256")
    if cert.signature_hash_algorithm.name != "sha256":
        raise CredentialError("cohort root signature must use SHA-256")
    try:
        public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    except (InvalidSignature, x509.ExtensionNotFound) as error:
        raise CredentialError("cohort root constraints or self-signature are invalid") from error
    if not constraints.critical or not constraints.value.ca or constraints.value.path_length != 0:
        raise CredentialError("cohort root CA constraints are invalid")
    if not usage.critical or not usage.value.key_cert_sign or not usage.value.crl_sign:
        raise CredentialError("cohort root key usage is invalid")
    if (usage.value.digital_signature or usage.value.content_commitment
            or usage.value.key_encipherment or usage.value.data_encipherment
            or usage.value.key_agreement):
        raise CredentialError("cohort root must not use leaf signing usages")
    if x509.oid.ExtensionOID.EXTENDED_KEY_USAGE in cert.extensions:
        raise CredentialError("cohort root must not carry leaf EKU")
    if (type(uncertainty_seconds) not in (int, float)
            or not 0 <= uncertainty_seconds <= 30):
        raise CredentialError("clock uncertainty is outside the accepted bound")
    current = _utc(now)
    earliest = current - timedelta(seconds=uncertainty_seconds)
    latest = current + timedelta(seconds=uncertainty_seconds)
    if earliest < cert.not_valid_before_utc or latest >= cert.not_valid_after_utc:
        raise CredentialError("cohort root is outside its validity interval")
    return cert


def _validate_sans(sans):
    try:
        # CertificateSigningRequest exposes its extensions as a collection,
        # while Certificate exposes get_extension_for_class on extensions.
        # Accept only the collection itself here so caller cannot bypass CSR
        # signature verification in _csr().
        extensions = getattr(sans, "extensions", sans)
        san = extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as error:
        raise CredentialError("CSR must contain the exact identity URI SAN") from error
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    dns_names = san.get_values_for_type(x509.DNSName)
    ips = san.get_values_for_type(x509.IPAddress)
    if len(uris) != 1 or len(san) != 1 + len(dns_names) + len(ips):
        raise CredentialError("certificate SAN must contain exactly one identity URI and approved host SANs")
    if len(dns_names) > 8 or len(ips) > 8:
        raise CredentialError("certificate host SAN count exceeds its bound")
    canonical_dns = tuple(value.lower() for value in dns_names)
    if len(set(canonical_dns)) != len(canonical_dns) or len(set(ips)) != len(ips):
        raise CredentialError("duplicate SAN values are forbidden")
    if any(not _DNS.fullmatch(value) or "*" in value for value in canonical_dns):
        raise CredentialError("DNS SAN must be a fixed non-wildcard name")
    return uris[0], tuple(sorted(canonical_dns)), tuple(sorted(str(ip) for ip in ips))


def make_csr(private_key_pem: bytes, *, account_id: str, device_id: str, role: str,
             dns_sans: tuple[str, ...] = (), ip_sans: tuple[str, ...] = ()) -> bytes:
    key = _key(private_key_pem)
    uri = identity_uri(account_id, device_id, role)
    if type(dns_sans) not in (tuple, list) or type(ip_sans) not in (tuple, list):
        raise ValueError("CSR SANs must be finite sequences")
    if len(dns_sans) > 8 or len(ip_sans) > 8:
        raise ValueError("CSR SAN count exceeds bound")
    names = [x509.UniformResourceIdentifier(uri)]
    for value in dns_sans:
        if type(value) is not str or not _DNS.fullmatch(value) or "*" in value:
            raise ValueError("invalid fixed DNS SAN")
        names.append(x509.DNSName(value.lower()))
    for value in ip_sans:
        names.append(x509.IPAddress(ipaddress.ip_address(value)))
    request = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)]))
               .add_extension(x509.SubjectAlternativeName(names), critical=False)
               .sign(key, hashes.SHA256()))
    return request.public_bytes(serialization.Encoding.PEM)


def issue_leaf(ca_pem: bytes, ca_key_pem: bytes, csr_pem: bytes, *,
               account_id: str, device_id: str, role: str,
               not_before: datetime | float | int, not_after: datetime | float | int,
               serial: int | None = None, ekus: frozenset[str] | set[str] | tuple[str, ...] = ("client",)) -> bytes:
    ca = verify_ca(ca_pem, now=not_before)
    signer = _key(ca_key_pem)
    if signer.public_key().public_numbers() != ca.public_key().public_numbers():
        raise CredentialError("cohort CA signing key does not match pinned root")
    csr = _csr(csr_pem)
    uri, dns_sans, ip_sans = _validate_sans(csr)
    if uri != identity_uri(account_id, device_id, role):
        raise CredentialError("CSR identity differs from operator-approved enrollment")
    expected_ekus = frozenset(ekus)
    if expected_ekus != ROLE_EKUS[role]:
        raise CredentialError("role requires its exact client/server EKU set")
    before, after = _utc(not_before), _utc(not_after)
    if after <= before or (after - before).total_seconds() > MAX_LEAF_LIFETIME_SECONDS:
        raise CredentialError("role leaf lifetime must be positive and at most 900 seconds")
    if before < ca.not_valid_before_utc or after > ca.not_valid_after_utc:
        raise CredentialError("role leaf validity must fit inside cohort CA validity")
    if serial is None:
        serial = _serial()
    if type(serial) is not int or not 1 <= serial < (1 << 159):
        raise CredentialError("leaf serial is outside the X.509 bound")
    eku = [_EKU_OIDS[name] for name in sorted(expected_ekus)]
    cert = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca.subject)
            .public_key(csr.public_key()).serial_number(serial)
            .not_valid_before(before.replace(tzinfo=None)).not_valid_after(after.replace(tzinfo=None))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=None, decipher_only=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage(eku), critical=True)
            .add_extension(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value,
                           critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
            .sign(signer, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def verify_leaf(ca_pem: bytes, leaf_pem: bytes, *, now: datetime | float | int,
                uncertainty_seconds: float = 0.0,
                account_id: str, device_id: str, role: str,
                serial: str | None = None, public_key_hash: str | None = None,
                certificate_hash: str | None = None,
                ekus: tuple[str, ...] | frozenset[str] | set[str] | None = None,
                dns_sans: tuple[str, ...] | None = None,
                ip_sans: tuple[str, ...] | None = None,
                expected_dns: str | None = None, expected_ip: str | None = None) -> x509.Certificate:
    """Validate an exact one-level leaf against a pinned cohort CA and enrollment."""
    ca = verify_ca(ca_pem, now=now, uncertainty_seconds=uncertainty_seconds)
    leaf = _pem_certificate(leaf_pem)
    if leaf.issuer != ca.subject:
        raise CredentialError("leaf is not issued directly by the pinned cohort CA")
    try:
        ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                               ec.ECDSA(hashes.SHA256()))
        if not leaf.extensions.get_extension_for_class(x509.BasicConstraints).critical:
            raise CredentialError("leaf CA constraint must be critical")
        constraints = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage_extension = leaf.extensions.get_extension_for_class(x509.KeyUsage)
        usage = usage_extension.value
        eku_extension = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        eku_values = eku_extension.value
    except (InvalidSignature, x509.ExtensionNotFound) as error:
        raise CredentialError("leaf signature or required constraints are invalid") from error
    if leaf.signature_hash_algorithm.name != "sha256":
        raise CredentialError("leaf signature must use SHA-256")
    if constraints.ca or constraints.path_length is not None:
        raise CredentialError("a role leaf cannot issue certificates")
    if (not usage_extension.critical or not usage.digital_signature
            or usage.content_commitment or usage.key_encipherment or usage.data_encipherment
            or usage.key_agreement or usage.key_cert_sign or usage.crl_sign):
        raise CredentialError("leaf key usage is not a non-CA signing key")
    if not eku_extension.critical:
        raise CredentialError("leaf EKU must be critical")
    public_key = leaf.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise CredentialError("role leaf key must be ECDSA P-256")
    if (type(uncertainty_seconds) not in (int, float)
            or not 0 <= uncertainty_seconds <= 30):
        raise CredentialError("clock uncertainty is outside the accepted bound")
    current = _utc(now)
    earliest = current - timedelta(seconds=uncertainty_seconds)
    latest = current + timedelta(seconds=uncertainty_seconds)
    if earliest < leaf.not_valid_before_utc or latest >= leaf.not_valid_after_utc:
        raise CredentialError("role leaf is outside its validity interval")
    if (leaf.not_valid_before_utc < ca.not_valid_before_utc
            or leaf.not_valid_after_utc > ca.not_valid_after_utc):
        raise CredentialError("role leaf validity extends beyond the pinned cohort CA")
    lifetime = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).total_seconds()
    if lifetime <= 0 or lifetime > MAX_LEAF_LIFETIME_SECONDS:
        raise CredentialError("role leaf lifetime exceeds 900 seconds")
    uri, actual_dns, actual_ips = _validate_sans(leaf.extensions)
    if uri != identity_uri(account_id, device_id, role):
        raise CredentialError("role leaf URI SAN does not match enrolled identity")
    eku_names = frozenset("client" if value == ExtendedKeyUsageOID.CLIENT_AUTH else
                          "server" if value == ExtendedKeyUsageOID.SERVER_AUTH else "unknown"
                          for value in eku_values)
    if eku_names != ROLE_EKUS[role]:
        raise CredentialError("role leaf EKU does not match its required client/server use")
    if ekus is not None and eku_names != frozenset(ekus):
        raise CredentialError("role leaf EKU differs from the enrolled EKU set")
    if dns_sans is not None and actual_dns != tuple(sorted(dns_sans)):
        raise CredentialError("DNS SAN differs from enrolled certificate")
    if ip_sans is not None and actual_ips != tuple(sorted(str(ipaddress.ip_address(value)) for value in ip_sans)):
        raise CredentialError("IP SAN differs from enrolled certificate")
    if expected_dns is not None and (expected_dns.lower() not in actual_dns):
        raise CredentialError("leaf DNS SAN does not match the fixed target")
    if expected_ip is not None and str(ipaddress.ip_address(expected_ip)) not in actual_ips:
        raise CredentialError("leaf IP SAN does not match the fixed target")
    actual_serial = serial_hex(leaf.serial_number)
    if serial is not None and actual_serial != serial:
        raise CredentialError("leaf serial differs from the enrolled serial")
    actual_key_hash = public_key_sha256(public_key)
    if public_key_hash is not None and actual_key_hash != public_key_hash:
        raise CredentialError("leaf public key hash differs from the enrolled key")
    actual_cert_hash = certificate_sha256(leaf)
    if certificate_hash is not None and actual_cert_hash != certificate_hash:
        raise CredentialError("leaf certificate hash differs from the pinned leaf")
    return leaf


def verify_expected_server_leaf(ca_pem: bytes, leaf_pem: bytes, *, now,
                                uncertainty_seconds: float = 0.0,
                                account_id: str, device_id: str, role: str,
                                serial: str, public_key_hash: str,
                                certificate_hash: str, expected_dns: str | None = None,
                                expected_ip: str | None = None,
                                ekus=("server",)) -> bytes:
    """Offline pre-channel check; caller still retains TLS hostname validation."""
    leaf = verify_leaf(ca_pem, leaf_pem, now=now,
                       uncertainty_seconds=uncertainty_seconds, account_id=account_id,
                       device_id=device_id, role=role, serial=serial,
                       public_key_hash=public_key_hash,
                       certificate_hash=certificate_hash, expected_dns=expected_dns,
                       expected_ip=expected_ip, ekus=ekus)
    return leaf.public_bytes(serialization.Encoding.PEM)
