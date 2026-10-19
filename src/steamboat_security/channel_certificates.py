"""Strict C2 channel certificate profile, separate from participant roles.

This module validates certificate shape and endpoint identity only. A valid
certificate is not enrollment, readiness, operator policy, or a gateway
delegation. Callers must separately authorize its fingerprint and identity.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .certificates import (_DNS, _csr, _key,
                           _pem_certificate, _serial, _utc, certificate_sha256,
                           public_key_sha256, serial_hex, verify_ca)
from .errors import CredentialError
from .ids import validate_id


_CHANNEL_URI = "urn:steamboat:channel:v1:"
_GATEWAY_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$", re.ASCII)
_SERIAL = re.compile(r"^(?:[1-9a-f][0-9a-f]{0,39})$", re.ASCII)
_EKUS = {
    "worker_stream": frozenset({"client"}),
    "gateway": frozenset({"client", "server"}),
}
_EKU_OIDS = {"client": ExtendedKeyUsageOID.CLIENT_AUTH,
             "server": ExtendedKeyUsageOID.SERVER_AUTH}
_PROFILE_EXTENSIONS = frozenset({
    x509.ExtensionOID.BASIC_CONSTRAINTS,
    x509.ExtensionOID.KEY_USAGE,
    x509.ExtensionOID.EXTENDED_KEY_USAGE,
    x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
})


@dataclass(frozen=True)
class ChannelCertificate:
    kind: str
    identity: str
    certificate_sha256: str
    serial: str
    public_key_sha256: str
    not_before: datetime
    not_after: datetime
    dns_names: tuple[str, ...]
    ip_addresses: tuple[str, ...]
    ekus: frozenset[str]


def _identity_uri(kind: str, identity: object) -> str:
    if kind == "worker_stream":
        if type(identity) is not dict or set(identity) != {
                "account_id", "device_id", "host_serial", "credential_epoch"}:
            raise CredentialError("worker stream identity fields are invalid")
        account = validate_id(identity["account_id"], "acct")
        device = validate_id(identity["device_id"], "dev")
        serial = identity["host_serial"]
        epoch = identity["credential_epoch"]
        if type(serial) is not str or not _SERIAL.fullmatch(serial):
            raise CredentialError("worker stream host serial is invalid")
        if type(epoch) is not int or not 1 <= epoch <= 2**31 - 1:
            raise CredentialError("worker stream credential epoch is invalid")
        return f"{_CHANNEL_URI}worker_stream:{account}:{device}:{serial}:{epoch}"
    if kind == "gateway":
        if type(identity) is not str or not _GATEWAY_ID.fullmatch(identity):
            raise CredentialError("gateway identity is invalid")
        return f"{_CHANNEL_URI}gateway:{identity}"
    raise CredentialError("unknown channel certificate kind")


def _common_name(kind: str) -> str:
    # X.509 CN has a short encoding limit; all authoritative identity is in URI SAN.
    return "channel-worker-stream" if kind == "worker_stream" else "channel-gateway"


def _san_values(extensions):
    try:
        ext = extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound as error:
        raise CredentialError("channel certificate requires a URI SAN") from error
    san = ext.value
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    dns = san.get_values_for_type(x509.DNSName)
    ips = san.get_values_for_type(x509.IPAddress)
    if len(uris) != 1 or len(san) != len(uris) + len(dns) + len(ips):
        raise CredentialError("channel SAN must contain one URI and unique endpoint SANs")
    canon_dns = tuple(value.lower() for value in dns)
    canon_ips = tuple(sorted(str(value) for value in ips))
    if (len(set(canon_dns)) != len(canon_dns) or len(set(canon_ips)) != len(canon_ips)
            or len(dns) > 8 or len(ips) > 8
            or any(not _DNS.fullmatch(value) or "*" in value for value in canon_dns)):
        raise CredentialError("channel endpoint SANs are invalid or duplicated")
    if tuple(dns) != canon_dns:
        raise CredentialError("channel DNS SANs must be canonical lowercase names")
    return uris[0], tuple(sorted(canon_dns)), canon_ips


def _endpoint_sans(dns_names, ip_addresses):
    if type(dns_names) not in (tuple, list) or type(ip_addresses) not in (tuple, list):
        raise CredentialError("endpoint SANs must be finite sequences")
    if len(dns_names) > 8 or len(ip_addresses) > 8:
        raise CredentialError("endpoint SAN count exceeds its bound")
    dns = []
    for name in dns_names:
        if type(name) is not str or not _DNS.fullmatch(name) or "*" in name:
            raise CredentialError("endpoint DNS name must be fixed and non-wildcard")
        dns.append(name.lower())
    ips = []
    try:
        for address in ip_addresses:
            if type(address) is not str:
                raise ValueError
            ips.append(str(ipaddress.ip_address(address)))
    except ValueError as error:
        raise CredentialError("endpoint IP address is invalid") from error
    if len(set(dns)) != len(dns) or len(set(ips)) != len(ips):
        raise CredentialError("duplicate endpoint SANs are forbidden")
    return tuple(sorted(dns)), tuple(sorted(ips))


def make_channel_csr(private_key_pem, *, kind, identity, dns_names=(),
                     ip_addresses=()):
    """Create a P-256 CSR with exactly this channel profile's subject and SAN.

    The URI SAN is the authoritative channel identity. The short subject CN
    identifies only the profile. A CSR does not establish enrollment or policy.
    """
    key = _key(private_key_pem)
    uri = _identity_uri(kind, identity)
    dns_names, ip_addresses = _endpoint_sans(dns_names, ip_addresses)
    names = [x509.UniformResourceIdentifier(uri)]
    names.extend(x509.DNSName(name) for name in dns_names)
    names.extend(x509.IPAddress(ipaddress.ip_address(address))
                 for address in ip_addresses)
    csr = (x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                    _common_name(kind))]))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM)


def _check_clock(uncertainty_seconds):
    if (type(uncertainty_seconds) not in (int, float)
            or not 0 <= uncertainty_seconds <= 30):
        raise CredentialError("clock uncertainty is outside the accepted bound")
    if type(uncertainty_seconds) is float and not math.isfinite(uncertainty_seconds):
        raise CredentialError("clock uncertainty is outside the accepted bound")


def issue_channel_certificate(ca_certificate_pem, ca_private_key_pem, csr_pem, *,
                              kind, identity, now, lifetime_seconds=900,
                              dns_names=(), ip_addresses=()):
    """Issue the strict C2 channel profile; authorization remains external."""
    uri = _identity_uri(kind, identity)
    dns_names, ip_addresses = _endpoint_sans(dns_names, ip_addresses)
    if type(lifetime_seconds) is not int or not 0 < lifetime_seconds <= 900:
        raise CredentialError("channel certificate lifetime must be at most 900 seconds")
    current = _utc(now)
    ca = verify_ca(ca_certificate_pem, now=current)
    signer = _key(ca_private_key_pem)
    if signer.public_key().public_numbers() != ca.public_key().public_numbers():
        raise CredentialError("channel CA key does not match the pinned cohort root")
    csr = _csr(csr_pem)
    if frozenset(extension.oid for extension in csr.extensions) != frozenset({
            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME}):
        raise CredentialError("channel CSR must contain only the identity and endpoint SAN")
    try:
        csr_uri, csr_dns, csr_ips = _san_values(csr.extensions)
    except CredentialError:
        raise
    if (csr_uri != uri or csr_dns != dns_names or csr_ips != ip_addresses):
        raise CredentialError("channel CSR SANs differ from requested identity or endpoint")
    if csr.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                    _common_name(kind))]):
        raise CredentialError("channel CSR subject does not match its profile")
    before = current.replace(microsecond=0)
    after = before + timedelta(seconds=lifetime_seconds)
    if after > ca.not_valid_after_utc or before < ca.not_valid_before_utc:
        raise CredentialError("channel certificate validity must fit inside cohort CA")
    eku = [_EKU_OIDS[name] for name in sorted(_EKUS[kind])]
    cert = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _common_name(kind))]))
        .issuer_name(ca.subject).public_key(csr.public_key()).serial_number(_serial())
        .not_valid_before(before.replace(tzinfo=None)).not_valid_after(after.replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=None, decipher_only=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage(eku), critical=True)
        .add_extension(x509.SubjectAlternativeName(
            [x509.UniformResourceIdentifier(uri),
             *(x509.DNSName(name) for name in dns_names),
             *(x509.IPAddress(ipaddress.ip_address(address)) for address in ip_addresses)]),
            critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .sign(signer, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def verify_channel_certificate(cert_pem, ca_pem, *, kind, expected_identity, now,
                               uncertainty_seconds=0.0, required_eku=None,
                               expected_dns=None, expected_ip=None):
    """Verify profile, identity and endpoint, without revocation or admission checks.

    A caller must separately check operator authorization, enrollment, revocation,
    readiness, and any signed delegation before accepting this channel.
    """
    expected_uri = _identity_uri(kind, expected_identity)
    if kind == "gateway" and expected_dns is None and expected_ip is None:
        raise CredentialError("gateway verification requires its expected DNS or IP endpoint")
    if required_eku is not None and frozenset(required_eku) != _EKUS[kind]:
        raise CredentialError("requested channel EKU differs from its profile")
    _check_clock(uncertainty_seconds)
    ca = verify_ca(ca_pem, now=now, uncertainty_seconds=uncertainty_seconds)
    cert = _pem_certificate(cert_pem)
    if cert.issuer != ca.subject:
        raise CredentialError("channel leaf is not issued directly by the pinned CA")
    try:
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                               ec.ECDSA(hashes.SHA256()))
        extensions = cert.extensions
        if frozenset(ext.oid for ext in extensions) != _PROFILE_EXTENSIONS:
            raise CredentialError("channel certificate extensions are not the exact profile")
        bc_ext = extensions.get_extension_for_class(x509.BasicConstraints)
        ku_ext = extensions.get_extension_for_class(x509.KeyUsage)
        eku_ext = extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        ski_ext = extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        san_ext = extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except (InvalidSignature, x509.ExtensionNotFound) as error:
        raise CredentialError("channel signature or required extensions are invalid") from error
    if cert.signature_hash_algorithm.name != "sha256":
        raise CredentialError("channel certificate signature must use SHA-256")
    if (not bc_ext.critical or bc_ext.value.ca or bc_ext.value.path_length is not None
            or not ku_ext.critical or not ku_ext.value.digital_signature
            or ku_ext.value.content_commitment or ku_ext.value.key_encipherment
            or ku_ext.value.data_encipherment or ku_ext.value.key_agreement
            or ku_ext.value.key_cert_sign or ku_ext.value.crl_sign
            or not eku_ext.critical or san_ext.critical or ski_ext.critical):
        raise CredentialError("channel key usage or constraints do not match profile")
    eku_names = frozenset("client" if oid == ExtendedKeyUsageOID.CLIENT_AUTH else
                          "server" if oid == ExtendedKeyUsageOID.SERVER_AUTH else "unknown"
                          for oid in eku_ext.value)
    if len(eku_ext.value) != len(eku_names) or eku_names != _EKUS[kind]:
        raise CredentialError("channel EKU does not match profile")
    if not isinstance(cert.public_key(), ec.EllipticCurvePublicKey) or not isinstance(
            cert.public_key().curve, ec.SECP256R1):
        raise CredentialError("channel key must be ECDSA P-256")
    current = _utc(now)
    earliest = current - timedelta(seconds=uncertainty_seconds)
    latest = current + timedelta(seconds=uncertainty_seconds)
    if earliest < cert.not_valid_before_utc or latest >= cert.not_valid_after_utc:
        raise CredentialError("channel leaf is outside its validity interval")
    if (cert.not_valid_before_utc < ca.not_valid_before_utc
            or cert.not_valid_after_utc > ca.not_valid_after_utc
            or not 0 < (cert.not_valid_after_utc-cert.not_valid_before_utc).total_seconds() <= 900):
        raise CredentialError("channel leaf validity exceeds profile or CA bounds")
    uri, dns, ips = _san_values(extensions)
    if uri != expected_uri:
        raise CredentialError("channel identity differs from expected identity")
    if cert.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                     _common_name(kind))]):
        raise CredentialError("channel subject does not match its profile")
    if ski_ext.value.digest != x509.SubjectKeyIdentifier.from_public_key(
            cert.public_key()).digest:
        raise CredentialError("channel subject key identifier does not match its key")
    if expected_dns is not None and (type(expected_dns) is not str
            or not _DNS.fullmatch(expected_dns) or expected_dns.lower() not in dns):
        raise CredentialError("channel DNS SAN does not match expected endpoint")
    if expected_ip is not None:
        try:
            normalized_ip = str(ipaddress.ip_address(expected_ip))
        except ValueError as error:
            raise CredentialError("expected endpoint IP is invalid") from error
        if normalized_ip not in ips:
            raise CredentialError("channel IP SAN does not match expected endpoint")
    return ChannelCertificate(kind, uri, certificate_sha256(cert),
                              serial_hex(cert.serial_number),
                              public_key_sha256(cert.public_key()),
                              cert.not_valid_before_utc, cert.not_valid_after_utc,
                              dns, ips, eku_names)
