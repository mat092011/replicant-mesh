"""Exercise the transport adapter against the actual C0 identity verifier.

The identity core lives in the parent integration worktree. This suite is
required in the composed pinned Docker environment; it intentionally imports
the production verifier and has no permissive test double or skip path.
"""

import hashlib
import ipaddress
import sys
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_runtime.protocol.secure_transport import (
    C0ExpectedServerLeafAdapter,
    ExpectedServerIdentity,
)
from steamboat_security.certificates import verify_expected_server_leaf


ACCOUNT_ID = "acct_" + "1" * 32
DEVICE_ID = "dev_" + "2" * 32
EXPECTED_IP = "127.0.0.1"


def _pem(value):
    from cryptography.hazmat.primitives import serialization

    return value.public_bytes(serialization.Encoding.PEM)


def _issue_fixture():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.utcnow()
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "C1a adapter test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(0xCA01)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None),
            critical=True)
        .sign(ca_key, hashes.SHA256()))

    def issue(serial, *, role="host", ekus=(ExtendedKeyUsageOID.SERVER_AUTH,)):
        key = ec.generate_private_key(ec.SECP256R1())
        uri = f"urn:steamboat:participant:v1:{ACCOUNT_ID}:{DEVICE_ID}:{role}"
        cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "host")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(serial)
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(minutes=10))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName((
                x509.IPAddress(ipaddress.IPv4Address(EXPECTED_IP)),
                x509.UniformResourceIdentifier(uri))), critical=False)
            .add_extension(x509.ExtendedKeyUsage(ekus), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None),
                critical=True)
            .sign(ca_key, hashes.SHA256()))
        public_key_der = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        expected = ExpectedServerIdentity(
            account_id=ACCOUNT_ID, device_id=DEVICE_ID, role=role,
            serial=serial,
            public_key_hash=hashlib.sha256(public_key_der).digest(),
            certificate_hash=hashlib.sha256(cert_der).digest(),
            expected_ip=EXPECTED_IP)
        return _pem(cert), expected, cert

    return _pem(ca), issue(0x1A2B), issue(0x1A2C), issue(
        0x1A2D, ekus=(ExtendedKeyUsageOID.CLIENT_AUTH,)), issue(
        0x1A2E, role="personal_coordinator", ekus=(
            ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH))


class ActualC0ExpectedLeafAdapterTests(unittest.TestCase):
    def test_actual_verifier_accepts_pinned_leaf_and_adapter_normalizes_core_fields(self):
        ca_pem, (leaf_pem, expected, certificate), _wrong, _bad_eku, _coordinator = \
            _issue_fixture()
        adapter = C0ExpectedServerLeafAdapter(verify_expected_server_leaf)
        approved = adapter(leaf_pem, ca_pem, expected, now=time.time())

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        approved_certificate = x509.load_pem_x509_certificate(approved)
        self.assertEqual(approved_certificate.public_bytes(serialization.Encoding.DER),
                         certificate.public_bytes(serialization.Encoding.DER))
        self.assertEqual(expected.serial_hex, "1a2b")
        self.assertEqual(expected.public_key_hash_hex, expected.public_key_hash.hex())
        self.assertEqual(expected.certificate_hash_hex, expected.certificate_hash.hex())

    def test_actual_verifier_accepts_personal_coordinator_client_and_server_ekus(self):
        ca_pem, _host, _wrong, _bad_eku, (leaf_pem, expected, certificate) = _issue_fixture()
        self.assertEqual(expected.ekus, ("client", "server"))
        approved = C0ExpectedServerLeafAdapter(verify_expected_server_leaf)(
            leaf_pem, ca_pem, expected, now=time.time())
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        self.assertEqual(
            x509.load_pem_x509_certificate(approved).public_bytes(serialization.Encoding.DER),
            certificate.public_bytes(serialization.Encoding.DER))

    def test_actual_verifier_rejects_wrong_leaf_serial_hash_and_eku(self):
        ca_pem, (leaf_pem, expected, _certificate), (wrong_leaf, _wrong_expected, _), \
            (bad_eku_leaf, bad_eku_expected, _), _coordinator = _issue_fixture()
        adapter = C0ExpectedServerLeafAdapter(verify_expected_server_leaf)
        now = time.time()
        with self.assertRaises(Exception):
            adapter(wrong_leaf, ca_pem, expected, now=now)
        for field, value in (("serial", expected.serial + 1),
                             ("public_key_hash", "0" * 64),
                             ("certificate_hash", "f" * 64)):
            altered = ExpectedServerIdentity(
                account_id=expected.account_id, device_id=expected.device_id,
                role=expected.role, serial=value if field == "serial" else expected.serial,
                public_key_hash=(value if field == "public_key_hash"
                                 else expected.public_key_hash_hex),
                certificate_hash=(value if field == "certificate_hash"
                                  else expected.certificate_hash_hex),
                expected_ip=expected.expected_ip)
            with self.subTest(field=field), self.assertRaises(Exception):
                adapter(leaf_pem, ca_pem, altered, now=now)
        with self.assertRaises(Exception):
            adapter(bad_eku_leaf, ca_pem, bad_eku_expected, now=now)


if __name__ == "__main__":
    unittest.main()
