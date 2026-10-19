"""Canonical, closed parsing of inert C2 coordinator runtime settings."""
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from steamboat_connector.c2_coordinator_settings import (
    C2CoordinatorSettingsError, PROFILE, parse_c2_coordinator_settings,
)
from steamboat_security.certificates import generate_private_key_pem
from steamboat_security.codec import canonical_json


def _public_material():
    private = serialization.load_pem_private_key(
        generate_private_key_pem(), password=None
    )
    public = private.public_key()
    return (
        public.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        ),
        public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii"),
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii"),
    )


class C2CoordinatorSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog_key, cls.public_pem, cls.private_pem = _public_material()

    def document(self):
        catalog_digest = hashlib.sha256(self.catalog_key).hexdigest()
        return {
            "schema_version": 1,
            "profile": PROFILE,
            "artifact_root": "/operator/offline/artifacts",
            "catalog_public_key_hex": self.catalog_key.hex(),
            "assignment": {
                "assignment_id": "asg_" + "a" * 32,
                "catalog_sha256": "1" * 64,
                "catalog_public_key_sha256": catalog_digest,
                "assignment_sha256": "2" * 64,
            },
            "gateway": {
                "gateway_id": "gateway-1",
                "policy_root": "/var/lib/steamboat/channel-policy",
                "initial_policy": {
                    "path": "/etc/steamboat/initial-policy.json",
                    "sha256": "3" * 64,
                },
                "verification_key_pem": self.public_pem,
                "minimum_revision": 1,
                "minimum_policy_digest": "4" * 64,
                "gateway_ca": {
                    "path": "/etc/steamboat/gateway-ca.pem",
                    "sha256": "5" * 64,
                },
            },
            "traffic": {
                "state_path": "/var/lib/steamboat/traffic/state.json",
                "allocation_id": "6" * 64,
                "clock_domain": "coordinator-clock-domain",
            },
            "workers": {
                f"worker-{index}": {
                    "device_id": f"dev_{index:032x}",
                    "worker_boot_id": f"{index:032x}",
                    "assignment_id": f"asg_{index:032x}",
                    "host_certificate": {
                        "path": f"/etc/steamboat/worker-{index}.pem",
                        "sha256": f"{index:x}" * 64,
                    },
                }
                for index in range(1, 4)
            },
            "listener": {
                "endpoint": "127.0.0.1:7443",
                "allowed_addresses": ["127.0.0.1"],
                "listener_id": "coordinator-consumer",
                "connection_slots": 1,
                "acceptor_directory": "/var/lib/steamboat/acceptors",
            },
        }

    def encode(self, document=None):
        return canonical_json(self.document() if document is None else document)

    def assert_invalid(self, document=None, encoded=None):
        with self.assertRaises(C2CoordinatorSettingsError):
            parse_c2_coordinator_settings(
                self.encode(document) if encoded is None else encoded
            )

    def test_valid_result_is_frozen_and_key_digest_is_anchored(self):
        source = self.document()
        settings = parse_c2_coordinator_settings(self.encode(source))
        self.assertEqual(settings.assignment.assignment_id, "asg_" + "a" * 32)
        self.assertEqual(settings.assignment.catalog_public_key_sha256,
                         hashlib.sha256(self.catalog_key).hexdigest())
        self.assertEqual(settings.gateway.gateway_id, "gateway-1")
        self.assertEqual(settings.traffic.clock_domain, "coordinator-clock-domain")
        self.assertEqual(tuple(worker.component for worker in settings.workers),
                         ("worker-1", "worker-2", "worker-3"))
        self.assertEqual(settings.workers[0].worker_boot_id, f"{1:032x}")
        self.assertEqual(settings.listener.endpoint, "127.0.0.1:7443")
        self.assertEqual(settings.listener.allowed_addresses, ("127.0.0.1",))
        source["assignment"]["catalog_sha256"] = "f" * 64
        self.assertEqual(settings.assignment.catalog_sha256, "1" * 64)
        with self.assertRaises(FrozenInstanceError):
            settings.assignment.assignment_id = "asg_" + "b" * 32
        # Nonexistent locators remain strings; this parser performs no file I/O.
        self.assertEqual(settings.gateway.gateway_ca.path,
                         "/etc/steamboat/gateway-ca.pem")

    def test_schema_and_nested_objects_are_closed(self):
        doc = self.document()
        doc["extra"] = "command"
        self.assert_invalid(doc)
        doc = self.document()
        doc["assignment"]["model_module"] = "arbitrary.module"
        self.assert_invalid(doc)
        doc = self.document()
        doc["gateway"]["endpoint"] = "127.0.0.1:443"
        self.assert_invalid(doc)
        doc = self.document()
        del doc["traffic"]["clock_domain"]
        self.assert_invalid(doc)

    def test_json_is_canonical_duplicate_free_integer_only_and_bounded(self):
        encoded = self.encode()
        self.assert_invalid(encoded=encoded + b" ")
        self.assert_invalid(encoded=b'{"schema_version":1,"schema_version":1}')
        doc = self.document()
        doc["schema_version"] = True
        self.assert_invalid(doc)
        doc = self.document()
        doc["gateway"]["minimum_revision"] = 1.0
        self.assert_invalid(doc)
        self.assert_invalid(encoded=encoded + b" " * (16 * 1024))

    def test_paths_reject_traversal_and_noncanonical_forms(self):
        for path in ("relative", "/a/../b", "/a//b", "/a\\b", "/a\x00b", "/"):
            with self.subTest(path=path):
                doc = self.document()
                doc["artifact_root"] = path
                self.assert_invalid(doc)
        doc = self.document()
        doc["traffic"]["state_path"] = "/var/lib/../state"
        self.assert_invalid(doc)

    def test_assignment_id_and_hash_anchors_use_actual_formats(self):
        for assignment_id in ("asg_abc", "dev_" + "a" * 32, "asg_" + "A" * 32):
            with self.subTest(assignment_id=assignment_id):
                doc = self.document()
                doc["assignment"]["assignment_id"] = assignment_id
                self.assert_invalid(doc)
        for field in ("catalog_sha256", "catalog_public_key_sha256", "assignment_sha256"):
            doc = self.document()
            doc["assignment"][field] = "A" * 64
            with self.subTest(field=field):
                self.assert_invalid(doc)
        doc = self.document()
        doc["assignment"]["catalog_public_key_sha256"] = "0" * 64
        self.assert_invalid(doc)

    def test_catalog_point_must_be_valid_uncompressed_p256_lowercase(self):
        for key_hex in ("0" * 130, self.catalog_key.hex().upper(), "02" + "1" * 128):
            with self.subTest(key_prefix=key_hex[:8]):
                doc = self.document()
                doc["catalog_public_key_hex"] = key_hex
                self.assert_invalid(doc)

    def test_gateway_key_is_canonical_public_p256_only(self):
        doc = self.document()
        doc["gateway"]["verification_key_pem"] = self.private_pem
        self.assert_invalid(doc)
        doc = self.document()
        doc["gateway"]["verification_key_pem"] += "trailing"
        self.assert_invalid(doc)
        doc = self.document()
        other = ec.generate_private_key(ec.SECP384R1()).public_key()
        doc["gateway"]["verification_key_pem"] = other.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.assert_invalid(doc)

    def test_gateway_and_traffic_match_host_schema_bounds(self):
        doc = self.document()
        doc["gateway"]["gateway_id"] = "BAD_ID"
        self.assert_invalid(doc)
        doc = self.document()
        doc["gateway"]["minimum_revision"] = 0
        self.assert_invalid(doc)
        doc = self.document()
        doc["traffic"]["allocation_id"] = "g" * 64
        self.assert_invalid(doc)
        doc = self.document()
        doc["traffic"]["clock_domain"] = "x" * 257
        self.assert_invalid(doc)

    def test_worker_map_is_exact_unique_and_uses_pinned_certificate_locators(self):
        doc = self.document()
        doc["workers"]["worker-2"]["device_id"] = doc["workers"]["worker-1"]["device_id"]
        parsed = parse_c2_coordinator_settings(self.encode(doc))
        self.assertEqual(parsed.workers[0].device_id, parsed.workers[1].device_id)
        self.assertNotEqual(parsed.workers[0].worker_boot_id,
                            parsed.workers[1].worker_boot_id)

        doc = self.document()
        del doc["workers"]["worker-3"]
        self.assert_invalid(doc)
        doc = self.document()
        doc["workers"]["worker-1"]["device_id"] = doc["workers"]["worker-2"]["device_id"]
        doc["workers"]["worker-1"]["worker_boot_id"] = doc["workers"]["worker-2"]["worker_boot_id"]
        self.assert_invalid(doc)
        doc = self.document()
        doc["workers"]["worker-1"]["assignment_id"] = doc["workers"]["worker-2"]["assignment_id"]
        self.assert_invalid(doc)
        for field, value in (("device_id", "acct_" + "a" * 32),
                             ("worker_boot_id", "A" * 32),
                             ("assignment_id", "asg_short")):
            doc = self.document()
            doc["workers"]["worker-2"][field] = value
            with self.subTest(field=field):
                self.assert_invalid(doc)
        doc = self.document()
        doc["workers"]["worker-1"]["host_certificate"] = {
            "path": "/etc/steamboat/worker.pem", "sha256": "A" * 64,
        }
        self.assert_invalid(doc)
        doc = self.document()
        doc["workers"]["worker-1"]["host_certificate"]["extra"] = "endpoint"
        self.assert_invalid(doc)

    def test_fixed_listener_reuses_strict_numeric_listener_semantics(self):
        for endpoint, allowlist in (
                ("0.0.0.0:7443", ["0.0.0.0"]),
                ("localhost:7443", ["127.0.0.1"]),
                ("127.0.0.1:0", ["127.0.0.1"]),
                ("127.0.0.1:07443", ["127.0.0.1"]),
                ("127.0.0.1:7443", ["127.0.0.1", "127.0.0.1"]),
                ("127.0.0.1:7443", ["127.0.0.1", "10.0.0.2"])):
            with self.subTest(endpoint=endpoint, allowlist=allowlist):
                doc = self.document()
                doc["listener"]["endpoint"] = endpoint
                doc["listener"]["allowed_addresses"] = allowlist
                self.assert_invalid(doc)
        for field, value in (("listener_id", ""), ("listener_id", "x" * 129),
                             ("connection_slots", True), ("connection_slots", 3),
                             ("acceptor_directory", "relative")):
            doc = self.document()
            doc["listener"][field] = value
            with self.subTest(field=field, value=value):
                self.assert_invalid(doc)


if __name__ == "__main__":
    unittest.main()
