"""Closed, data-only parsing for selected C2 host runtime configuration."""
import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from steamboat_connector.c2_host_settings import (
    C2HostSettingsError, PROFILE, parse_c2_host_settings,
)
from steamboat_security.certificates import generate_private_key_pem
from steamboat_security.codec import canonical_json


def _public_key_material():
    private = serialization.load_pem_private_key(
        generate_private_key_pem(), password=None
    )
    public = private.public_key()
    return (
        public.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        ).hex(),
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


class C2HostSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog_hex, cls.public_pem, cls.private_pem = _public_key_material()

    def document(self):
        return {
            "schema_version": 1,
            "profile": PROFILE,
            "artifact_root": "/operator/offline/artifacts",
            "catalog_public_key_hex": self.catalog_hex,
            "component_allocations": {
                "worker-1": {
                    "sessions": 2, "kv_bytes": 1048576,
                    "cache_positions": 1024, "queued_calls": 4,
                },
                "worker-2": {
                    "sessions": 1, "kv_bytes": 2097152,
                    "cache_positions": 512, "queued_calls": 0,
                },
            },
            "gateway": {
                "gateway_id": "gateway-1",
                "policy_root": "/var/lib/steamboat/channel-policy",
                "initial_policy": {
                    "path": "/etc/steamboat/initial-policy.json",
                    "sha256": "1" * 64,
                },
                "verification_key_pem": self.public_pem,
                "minimum_revision": 1,
                "minimum_policy_digest": "2" * 64,
                "gateway_ca": {
                    "path": "/etc/steamboat/gateway-ca.pem",
                    "sha256": "3" * 64,
                },
            },
            "traffic": {
                "state_path": "/var/lib/steamboat/traffic/state.json",
                "allocation_id": "4" * 64,
                "clock_domain": "machine-clock-domain-1",
            },
        }

    def encode(self, document=None):
        return canonical_json(self.document() if document is None else document)

    def assert_invalid(self, document=None, encoded=None):
        with self.assertRaises(C2HostSettingsError):
            parse_c2_host_settings(
                self.encode(document) if encoded is None else encoded
            )

    def test_valid_settings_are_frozen_copied_and_open_no_declared_paths(self):
        source = self.document()
        settings = parse_c2_host_settings(self.encode(source))
        self.assertEqual(settings.artifact_root, "/operator/offline/artifacts")
        self.assertEqual(tuple(settings.component_allocations), ("worker-1", "worker-2"))
        self.assertEqual(settings.component_allocations["worker-1"].sessions, 2)
        self.assertEqual(settings.gateway.initial_policy.sha256, "1" * 64)
        self.assertEqual(settings.traffic.allocation_id, "4" * 64)
        source["component_allocations"]["worker-1"]["sessions"] = 99
        self.assertEqual(settings.component_allocations["worker-1"].sessions, 2)
        with self.assertRaises(TypeError):
            settings.component_allocations["worker-3"] = settings.component_allocations["worker-1"]
        with self.assertRaises(FrozenInstanceError):
            settings.gateway.gateway_id = "other"
        # These nonexistent locators are deliberately only parsed, never opened.
        self.assertEqual(settings.gateway.initial_policy.path,
                         "/etc/steamboat/initial-policy.json")

    def test_schema_is_closed_and_worker_map_is_sorted_bounded(self):
        doc = self.document()
        doc["unexpected"] = "raw endpoint or command"
        self.assert_invalid(doc)
        doc = self.document()
        doc["gateway"]["endpoint"] = "127.0.0.1:443"
        self.assert_invalid(doc)
        doc = self.document()
        doc["component_allocations"]["worker-4"] = doc["component_allocations"]["worker-1"]
        self.assert_invalid(doc)
        doc = self.document()
        doc["component_allocations"] = {}
        self.assert_invalid(doc)

    def test_json_is_canonical_integer_only_duplicate_free_and_bounded(self):
        encoded = self.encode()
        self.assert_invalid(encoded=encoded + b" ")
        self.assert_invalid(encoded=b'{"schema_version":1,"schema_version":1}')
        doc = self.document()
        doc["component_allocations"]["worker-1"]["queued_calls"] = 1.0
        self.assert_invalid(doc)
        doc = self.document()
        doc["component_allocations"]["worker-1"]["sessions"] = True
        self.assert_invalid(doc)
        self.assert_invalid(encoded=encoded + b" " * (16 * 1024))
        self.assert_invalid(encoded=b"\xff")

    def test_paths_reject_noncanonical_and_traversal_forms(self):
        for path in ("relative/path", "/a/../b", "/a//b", "/a\\b", "/a\x00b", "/"):
            with self.subTest(path=path):
                doc = self.document()
                doc["artifact_root"] = path
                self.assert_invalid(doc)
        doc = self.document()
        doc["gateway"]["initial_policy"]["path"] = "/etc/../policy"
        self.assert_invalid(doc)
        doc = self.document()
        doc["traffic"]["state_path"] = "/var/lib/traffic//state"
        self.assert_invalid(doc)

    def test_catalog_point_must_be_canonical_valid_p256_and_lowercase(self):
        for point in ("0" * 130, self.catalog_hex.upper(), "02" + "1" * 128,
                      self.catalog_hex[:-2]):
            with self.subTest(point=point[:8]):
                doc = self.document()
                doc["catalog_public_key_hex"] = point
                self.assert_invalid(doc)

    def test_policy_key_is_canonical_public_p256_pem_only(self):
        doc = self.document()
        doc["gateway"]["verification_key_pem"] = self.private_pem
        self.assert_invalid(doc)
        doc = self.document()
        doc["gateway"]["verification_key_pem"] = self.public_pem + "trailing"
        self.assert_invalid(doc)
        doc = self.document()
        doc["gateway"]["verification_key_pem"] = "x" * 4097
        self.assert_invalid(doc)
        other_curve = ec.generate_private_key(ec.SECP384R1()).public_key()
        doc = self.document()
        doc["gateway"]["verification_key_pem"] = other_curve.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.assert_invalid(doc)

    def test_gateway_and_traffic_use_existing_identity_grammars(self):
        for gateway_id in ("UPPER", "bad host", "-edge", "edge_"):
            with self.subTest(gateway_id=gateway_id):
                doc = self.document()
                doc["gateway"]["gateway_id"] = gateway_id
                self.assert_invalid(doc)
        doc = self.document()
        doc["traffic"]["allocation_id"] = "A" * 64
        self.assert_invalid(doc)
        doc = self.document()
        doc["traffic"]["clock_domain"] = ""
        self.assert_invalid(doc)
        doc = self.document()
        doc["traffic"]["clock_domain"] = "x" * 257
        self.assert_invalid(doc)

    def test_every_allocation_has_closed_types_and_documented_bounds(self):
        for field, value in (("sessions", 0), ("kv_bytes", -1),
                             ("cache_positions", 1.5), ("queued_calls", 9)):
            with self.subTest(field=field, value=value):
                doc = self.document()
                doc["component_allocations"]["worker-1"][field] = value
                self.assert_invalid(doc)


if __name__ == "__main__":
    unittest.main()
