from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography import x509

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
SECURITY_TESTS = Path(__file__).resolve().parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(SECURITY_TESTS) not in sys.path:
    sys.path.insert(0, str(SECURITY_TESTS))

import secure_pipeline_fixture as fixture_module
from steamboat_security import verify_leaf


MODEL_FINGERPRINT = "a" * 64


class SecurePipelineFixtureIdentityTests(unittest.TestCase):
    def make_fixture(self, **kwargs):
        fixture = fixture_module.SecurePipelineIdentityFixture(
            MODEL_FINGERPRINT, **kwargs)
        self.addCleanup(fixture.close)
        return fixture

    @staticmethod
    def certificate_ip_sans(principal):
        certificate = x509.load_pem_x509_certificate(principal.certificate_pem)
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName)
        return tuple(str(value) for value in extension.value.get_values_for_type(
            x509.IPAddress))

    def test_default_keeps_loopback_zero_uncertainty_and_exact_issue_times(self):
        fixed_now = int(time.time())
        fixture_time = SimpleNamespace(time=lambda: fixed_now)
        with patch.object(fixture_module, "time", fixture_time):
            fixture = self.make_fixture()

        self.assertEqual(fixture.clock_uncertainty_seconds, 0.0)
        for principal in fixture.principals.values():
            self.assertEqual(self.certificate_ip_sans(principal), ("127.0.0.1",))
            self.assertEqual(principal.record["ip_sans"], ["127.0.0.1"])
            self.assertEqual(principal.record["not_before"], fixed_now)

        store, clock = fixture.new_store()
        view = store.current()
        self.assertEqual(clock.sample().uncertainty, 0.0)
        self.assertEqual(view.issued_at, fixed_now)
        self.assertEqual(view.expires_at - view.issued_at, 300)

    def test_external_ip_and_two_second_uncertainty_use_real_c0_apis(self):
        overrides = {"worker-1": ["192.168.42.17"]}
        fixture = self.make_fixture(
            ip_sans_by_principal=overrides,
            clock_uncertainty_seconds=2.0)

        overrides["worker-1"][0] = "192.168.42.18"
        overrides["worker-2"] = ["192.168.42.19"]
        self.assertEqual(fixture.ip_sans_by_principal["worker-1"],
                         ("192.168.42.17",))
        with self.assertRaises(TypeError):
            fixture.ip_sans_by_principal["worker-1"] = ("192.168.42.18",)

        for name, principal in fixture.principals.items():
            expected_ips = (("192.168.42.17",) if name == "worker-1"
                            else ("127.0.0.1",))
            self.assertEqual(self.certificate_ip_sans(principal), expected_ips)
            self.assertEqual(principal.record["ip_sans"], list(expected_ips))
            verify_leaf(
                fixture.cohort_ca_pem,
                principal.certificate_pem,
                now=datetime.now(timezone.utc),
                uncertainty_seconds=2.0,
                account_id=principal.account_id,
                device_id=principal.device_id,
                role=principal.role,
                ip_sans=expected_ips,
                expected_ip=expected_ips[0],
            )
            self.assertEqual(
                principal.record["not_after"] - principal.record["not_before"],
                900)

        first_store, first_clock = fixture.new_store()
        second_store, second_clock = fixture.new_store()
        self.assertIsNot(first_store, second_store)
        first_view = first_store.current()
        second_view = second_store.current()
        self.assertEqual(first_view.revision, 1)
        self.assertEqual(second_view.revision, 1)
        self.assertEqual(first_view.expires_at - first_view.issued_at, 300)
        self.assertEqual(second_view.expires_at - second_view.issued_at, 300)
        self.assertEqual(first_clock.sample().uncertainty, 2.0)
        self.assertEqual(second_clock.sample().uncertainty, 2.0)
        with self.assertRaises(AttributeError):
            fixture.clock_uncertainty_seconds = 3.0

    def test_invalid_ip_overrides_and_clock_values_fail_before_temp_allocation(self):
        invalid_options = [
            {"ip_sans_by_principal": []},
            {"ip_sans_by_principal": {1: ["192.168.42.17"]}},
            {"ip_sans_by_principal": {"unknown": ["192.168.42.17"]}},
            {"ip_sans_by_principal": {"worker-1": "192.168.42.17"}},
            {"ip_sans_by_principal": {"worker-1": []}},
            {"ip_sans_by_principal": {"worker-1": [
                "192.168.42.1", "192.168.42.2", "192.168.42.3",
                "192.168.42.4", "192.168.42.5"]}},
            {"ip_sans_by_principal": {"worker-1": ["localhost"]}},
            {"ip_sans_by_principal": {"worker-1": ["192.168.042.17"]}},
            {"ip_sans_by_principal": {"worker-1": ["2001:db8::1"]}},
            {"ip_sans_by_principal": {"worker-1": ["0.0.0.0"]}},
            {"ip_sans_by_principal": {"worker-1": ["224.0.0.1"]}},
            {"ip_sans_by_principal": {"worker-1": [
                "192.168.42.17", "192.168.42.17"]}},
            {"clock_uncertainty_seconds": True},
            {"clock_uncertainty_seconds": float("nan")},
            {"clock_uncertainty_seconds": float("inf")},
            {"clock_uncertainty_seconds": -0.01},
            {"clock_uncertainty_seconds": 30.01},
            {"clock_uncertainty_seconds": 10 ** 400},
            {"clock_uncertainty_seconds": "2"},
        ]
        for options in invalid_options:
            with self.subTest(options=options):
                with patch.object(
                        fixture_module.tempfile, "TemporaryDirectory",
                        side_effect=AssertionError("temporary storage allocated")):
                    with self.assertRaises((TypeError, ValueError)):
                        fixture_module.SecurePipelineIdentityFixture(
                            MODEL_FINGERPRINT, **options)


if __name__ == "__main__":
    unittest.main()
