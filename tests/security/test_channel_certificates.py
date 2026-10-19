from datetime import datetime, timezone
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from steamboat_security.certificates import (generate_ca, generate_private_key_pem,
    issue_leaf, make_csr)
from steamboat_security.channel_certificates import (
    issue_channel_certificate, verify_channel_certificate)
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
    key = serialization.load_pem_private_key(key_pem, password=None)
    if kind == "worker_stream":
        uri = ("urn:steamboat:channel:v1:worker_stream:"
               f"{identity['account_id']}:{identity['device_id']}:"
               f"{identity['host_serial']}:{identity['credential_epoch']}")
    else:
        uri = f"urn:steamboat:channel:v1:gateway:{identity}"
    names = [x509.UniformResourceIdentifier(uri)]
    names.extend(x509.DNSName(name.lower()) for name in dns)
    import ipaddress
    names.extend(x509.IPAddress(ipaddress.ip_address(value)) for value in ips)
    csr = (x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
            "channel-worker-stream" if kind == "worker_stream" else "channel-gateway")]))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .sign(key, hashes.SHA256()))
    return key_pem, csr.public_bytes(serialization.Encoding.PEM)


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

    def test_tampering_and_multiple_pem_certificates_rejected(self):
        cert = self.issue()
        with self.assertRaises(CredentialError):
            self.verify(cert[:-20] + b"A" * 20)
        with self.assertRaises(CredentialError):
            self.verify(cert + cert)

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


if __name__ == "__main__":
    unittest.main()
