from datetime import datetime, timedelta, timezone
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import (ExtendedKeyUsageOID, ExtensionOID, NameOID,
                                   ObjectIdentifier)

from steamboat_security.certificates import (generate_ca, generate_private_key_pem,
    issue_leaf, make_csr, verify_leaf)
from steamboat_security.channel_certificates import (
    issue_channel_certificate, make_channel_csr, verify_channel_certificate)
from steamboat_security.errors import CredentialError


NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
WORKER = {
    "account_id": "acct_" + "1" * 32,
    "device_id": "dev_" + "2" * 32,
    "host_serial": "ab12cd34",
    "credential_epoch": 7,
}
GATEWAY = "gw-eu-1"


def _channel_csr(kind, identity, *, dns=(), ips=()):
    key_pem = generate_private_key_pem()
    return key_pem, make_channel_csr(key_pem, kind=kind, identity=identity,
                                     dns_names=dns, ip_addresses=ips)


def _resign(certificate_pem, ca_key_pem, *, replacements=None,
            extra_extensions=(), not_before=None, not_after=None, subject=None):
    cert = x509.load_pem_x509_certificate(certificate_pem)
    signer = serialization.load_pem_private_key(ca_key_pem, password=None)
    replacements = replacements or {}
    builder = (x509.CertificateBuilder()
        .subject_name(subject if subject is not None else cert.subject)
        .issuer_name(cert.issuer).public_key(cert.public_key())
        .serial_number(cert.serial_number)
        .not_valid_before((not_before or cert.not_valid_before_utc).replace(tzinfo=None))
        .not_valid_after((not_after or cert.not_valid_after_utc).replace(tzinfo=None)))
    for extension in cert.extensions:
        value, critical = replacements.get(extension.oid,
            (extension.value, extension.critical))
        builder = builder.add_extension(value, critical)
    for oid, value, critical in extra_extensions:
        builder = builder.add_extension(x509.UnrecognizedExtension(oid, value), critical)
    return builder.sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


class ChannelCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_pem, cls.ca_key = generate_ca(now=NOW)

    def issue(self, kind="worker_stream", identity=WORKER, *, dns=(), ips=(),
              lifetime=900):
        _key_pem, csr = _channel_csr(kind, identity, dns=dns, ips=ips)
        return issue_channel_certificate(self.ca_pem, self.ca_key, csr,
            kind=kind, identity=identity, now=NOW, lifetime_seconds=lifetime,
            dns_names=dns, ip_addresses=ips)

    def verify(self, cert, kind="worker_stream", identity=WORKER, **kwargs):
        return verify_channel_certificate(cert, self.ca_pem, kind=kind,
            expected_identity=identity, now=NOW, **kwargs)

    def test_worker_profile_and_gateway_mtls_profile(self):
        worker = self.verify(self.issue(dns=("worker.example",), ips=("192.0.2.4",)),
            expected_dns="worker.example", expected_ip="192.0.2.4",
            required_eku={"client"})
        self.assertEqual(worker.kind, "worker_stream")
        self.assertEqual(worker.identity,
            "urn:steamboat:channel:v1:worker_stream:"
            f"{WORKER['account_id']}:{WORKER['device_id']}:ab12cd34:7")
        self.assertEqual(worker.dns_names, ("worker.example",))
        gateway = self.verify(self.issue("gateway", GATEWAY,
            dns=("gateway.example",)), "gateway", GATEWAY,
            expected_dns="gateway.example", required_eku={"client", "server"})
        self.assertEqual(gateway.kind, "gateway")
        self.assertEqual(gateway.ekus, frozenset({"client", "server"}))

    def test_wrong_kind_identity_and_eku_rejected(self):
        cert = self.issue()
        for args in (("gateway", GATEWAY, {}),
                     ("worker_stream", {**WORKER, "credential_epoch": 8}, {}),
                     ("worker_stream", WORKER, {"server"})):
            kind, identity, eku = args
            with self.subTest(kind=kind, identity=identity, eku=eku):
                with self.assertRaises(CredentialError):
                    self.verify(cert, kind, identity, required_eku=eku or None)

    def test_c1_role_certificate_is_not_a_channel_certificate(self):
        key_pem = generate_private_key_pem()
        csr = make_csr(key_pem, account_id=WORKER["account_id"],
                       device_id=WORKER["device_id"], role="host")
        c1 = issue_leaf(self.ca_pem, self.ca_key, csr,
            account_id=WORKER["account_id"], device_id=WORKER["device_id"],
            role="host", not_before=NOW, not_after=NOW.replace(second=0)+
            __import__("datetime").timedelta(minutes=10), ekus={"server"})
        with self.assertRaises(CredentialError):
            self.verify(c1)

    def test_channel_certificates_are_not_c1_participant_credentials(self):
        for cert, role in ((self.issue(), "host"),
                           (self.issue("gateway", GATEWAY,
                                       dns=("gateway.example",)),
                            "personal_coordinator")):
            with self.subTest(role=role):
                with self.assertRaises(CredentialError):
                    verify_leaf(self.ca_pem, cert, account_id=WORKER["account_id"],
                                device_id=WORKER["device_id"], role=role, now=NOW)

    def test_tampering_and_multiple_pem_certificates_rejected(self):
        cert = self.issue()
        with self.assertRaises(CredentialError):
            self.verify(cert[:-20] + b"A" * 20)
        with self.assertRaises(CredentialError):
            self.verify(cert + cert)
        with self.assertRaises(CredentialError):
            self.verify(cert + b"unrecognized trailing content")

    def test_wrong_ca_rejected(self):
        cert = self.issue()
        other_ca, _other_key = generate_ca(now=NOW)
        with self.assertRaises(CredentialError):
            verify_channel_certificate(cert, other_ca, kind="worker_stream",
                expected_identity=WORKER, now=NOW)

    def test_signed_leaves_with_wrong_profile_fields_rejected(self):
        cert = self.issue()
        parsed = x509.load_pem_x509_certificate(cert)
        eku = parsed.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        ski = parsed.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        san = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        wrong_uri = x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier("urn:steamboat:channel:v1:gateway:other")])
        invalid = [
            ("unknown extension", _resign(cert, self.ca_key,
                extra_extensions=((ObjectIdentifier("1.3.6.1.4.1.55555.1"), b"\\x05\\x00", False),))),
            ("repeated EKU", _resign(cert, self.ca_key, replacements={
                ExtensionOID.EXTENDED_KEY_USAGE: (x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), True)})),
            ("wrong KU", _resign(cert, self.ca_key, replacements={
                ExtensionOID.KEY_USAGE: (x509.KeyUsage(digital_signature=True,
                    content_commitment=False, key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=None, decipher_only=None), True)})),
            ("wrong SKI", _resign(cert, self.ca_key, replacements={
                ExtensionOID.SUBJECT_KEY_IDENTIFIER: (x509.SubjectKeyIdentifier(
                    b"x" * len(ski.digest)), False)})),
            ("too-long validity", _resign(cert, self.ca_key, not_after=
                parsed.not_valid_after_utc + timedelta(seconds=1))),
            ("wrong SAN URI", _resign(cert, self.ca_key, replacements={
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME: (wrong_uri, False)})),
            ("wrong subject", _resign(cert, self.ca_key, subject=x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "wrong-profile")]))),
        ]
        for label, candidate in invalid:
            with self.subTest(label=label), self.assertRaises(CredentialError):
                self.verify(candidate)

    def test_make_channel_csr_rejects_non_p256_key_and_noncanonical_identity(self):
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pem = rsa_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with self.assertRaises(CredentialError):
            make_channel_csr(rsa_pem, kind="worker_stream", identity=WORKER)
        with self.assertRaises(CredentialError):
            make_channel_csr(generate_private_key_pem(), kind="worker_stream",
                identity={**WORKER, "host_serial": "0ab12"})

    def test_endpoint_mismatch_and_wildcard_rejected(self):
        cert = self.issue(dns=("worker.example",))
        with self.assertRaises(CredentialError):
            self.verify(cert, expected_dns="other.example")
        with self.assertRaises(CredentialError):
            self.issue(dns=("*.example",))

    def test_time_uncertainty_and_lifetime_are_conservative(self):
        cert = self.issue(lifetime=10)
        with self.assertRaises(CredentialError):
            self.verify(cert, uncertainty_seconds=10)
        with self.assertRaises(CredentialError):
            self.issue(lifetime=901)

    def test_duplicate_san_is_rejected_even_when_csr_is_signed(self):
        key = ec.generate_private_key(ec.SECP256R1())
        uri = ("urn:steamboat:channel:v1:worker_stream:"
               f"{WORKER['account_id']}:{WORKER['device_id']}:ab12cd34:7")
        csr = (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                "channel-worker-stream")]))
            .add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(uri), x509.DNSName("node.example"),
                x509.DNSName("node.example")]), critical=False)
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
        with self.assertRaises(CredentialError):
            issue_channel_certificate(self.ca_pem, self.ca_key, csr,
                kind="worker_stream", identity=WORKER, now=NOW,
                dns_names=("node.example", "node.example"))
        valid = self.issue(dns=("node.example",))
        parsed = x509.load_pem_x509_certificate(valid)
        san = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        duplicated = x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(
                "urn:steamboat:channel:v1:worker_stream:"
                f"{WORKER['account_id']}:{WORKER['device_id']}:ab12cd34:7"),
            x509.DNSName("node.example"), x509.DNSName("node.example")])
        self.assertNotEqual(san, duplicated)
        signed_duplicate = _resign(valid, self.ca_key, replacements={
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME: (duplicated, False)})
        with self.assertRaises(CredentialError):
            self.verify(signed_duplicate)


if __name__ == "__main__":
    unittest.main()
