import hashlib
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

from steamboat_connector.c2_pool_config import (
    C2PoolConfigError,
    MAX_CONFIG_BYTES,
    PROFILE,
    canonical_c2_pool_config_bytes,
    c2_pool_config_sha256,
    c2_pool_config_to_document,
    parse_c2_pool_config,
)
from steamboat_connector.validation import json_bytes


def valid_document():
    return {
        "schema_version": 2,
        "profile": PROFILE,
        "physical_host_id": "a" * 64,
        "allocation_id": "b" * 64,
        "pool_kind": "system_ram",
        "pool_id": "primary-system-memory",
        "owner_uid": 1000,
        "operator_root": "/var/lib/steamboat/operator",
        "cgroup_parent": "/sys/fs/cgroup/steamboat",
        "memory_ceiling_bytes": 8192,
        "memory_headroom_bytes": 1024,
        "cpu_quota_millis": 4000,
        "pids_max": 100,
        "swap_max_bytes": 0,
        "disk_ceiling_bytes": 16384,
        "control": {
            "memory_bytes": 2048,
            "cpu_quota_millis": 500,
            "pids_max": 10,
            "disk_bytes": 4096,
        },
    }


def encode(document):
    return json_bytes(document, maximum_bytes=MAX_CONFIG_BYTES)


class C2PoolConfigTests(unittest.TestCase):
    def test_canonical_parse_roundtrip_digest_and_frozen_nested_values(self):
        raw = encode(valid_document())
        config = parse_c2_pool_config(raw)

        self.assertEqual(canonical_c2_pool_config_bytes(config), raw)
        self.assertEqual(c2_pool_config_sha256(config), hashlib.sha256(raw).hexdigest())
        self.assertEqual(c2_pool_config_to_document(config), valid_document())
        with self.assertRaises(AttributeError):
            config.pool_id = "changed"
        with self.assertRaises(AttributeError):
            config.control.memory_bytes = 1
        copied = c2_pool_config_to_document(config)
        copied["control"]["memory_bytes"] = 1
        self.assertEqual(config.control.memory_bytes, 2048)

    def test_exact_numeric_upper_bounds_and_allowed_disk_equality(self):
        document = valid_document()
        maximum = (1 << 63) - 1
        document.update(
            owner_uid=(1 << 31) - 1,
            memory_ceiling_bytes=maximum,
            memory_headroom_bytes=0,
            cpu_quota_millis=100_000,
            pids_max=1_000_000,
            swap_max_bytes=maximum,
            disk_ceiling_bytes=maximum,
        )
        document["control"].update(
            memory_bytes=maximum - 1,
            cpu_quota_millis=99_999,
            pids_max=999_999,
            disk_bytes=maximum,
        )
        config = parse_c2_pool_config(encode(document))
        self.assertEqual(config.control.disk_bytes, config.disk_ceiling_bytes)

    def test_integer_ranges_reject_below_minimum_and_above_maximum(self):
        maximum = (1 << 63) - 1
        cases = (
            ("owner_uid", -1), ("owner_uid", 1 << 31),
            ("memory_ceiling_bytes", 0), ("memory_ceiling_bytes", maximum + 1),
            ("memory_headroom_bytes", -1), ("memory_headroom_bytes", maximum + 1),
            ("cpu_quota_millis", 0), ("cpu_quota_millis", 100_001),
            ("pids_max", 0), ("pids_max", 1_000_001),
            ("swap_max_bytes", -1), ("swap_max_bytes", maximum + 1),
            ("disk_ceiling_bytes", 0), ("disk_ceiling_bytes", maximum + 1),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                document = valid_document()
                document[field] = value
                with self.assertRaises(C2PoolConfigError):
                    parse_c2_pool_config(encode(document))
        for field, value in (
            ("memory_bytes", 0), ("memory_bytes", maximum + 1),
            ("cpu_quota_millis", 0), ("pids_max", 0),
            ("disk_bytes", -1), ("disk_bytes", maximum + 1),
        ):
            with self.subTest(control_field=field, value=value):
                document = valid_document()
                document["control"][field] = value
                with self.assertRaises(C2PoolConfigError):
                    parse_c2_pool_config(encode(document))

    def test_rejects_boolean_for_every_integer_field(self):
        fields = (
            "schema_version", "owner_uid", "memory_ceiling_bytes",
            "memory_headroom_bytes", "cpu_quota_millis", "pids_max",
            "swap_max_bytes", "disk_ceiling_bytes",
        )
        for field in fields:
            with self.subTest(field=field):
                document = valid_document()
                document[field] = True
                with self.assertRaises(C2PoolConfigError):
                    parse_c2_pool_config(encode(document))
        for field in ("memory_bytes", "cpu_quota_millis", "pids_max", "disk_bytes"):
            with self.subTest(control_field=field):
                document = valid_document()
                document["control"][field] = True
                with self.assertRaises(C2PoolConfigError):
                    parse_c2_pool_config(encode(document))

    def test_cross_allocation_bounds_are_enforced(self):
        cases = (
            ("memory_bytes", 7168),  # equals ceiling after headroom
            ("memory_bytes", 7169),
        )
        for field, value in cases:
            with self.subTest(control_memory=value):
                document = valid_document()
                document["control"][field] = value
                with self.assertRaisesRegex(C2PoolConfigError, "memory and headroom"):
                    parse_c2_pool_config(encode(document))

        for field, value, message in (
            ("cpu_quota_millis", 4000, "CPU"),
            ("pids_max", 100, "PID"),
            ("disk_bytes", 16385, "disk ceiling"),
        ):
            with self.subTest(control_field=field):
                document = valid_document()
                document["control"][field] = value
                with self.assertRaisesRegex(C2PoolConfigError, message):
                    parse_c2_pool_config(encode(document))

    def test_closed_schema_profile_identity_and_pool_label(self):
        for mutate in (
            lambda d: d.update(extra="not-allowed"),
            lambda d: d.pop("allocation_id"),
            lambda d: d.update(schema_version=True),
            lambda d: d.update(schema_version=1),
            lambda d: d.update(profile="native_posix_c2_physical_pool_v2"),
            lambda d: d.update(physical_host_id="A" * 64),
            lambda d: d.update(allocation_id="a" * 63),
            lambda d: d.update(pool_kind="gpu_memory"),
            lambda d: d.update(pool_id="x" * 129),
            lambda d: d.update(pool_id="é" * 65),
            lambda d: d.update(pool_id="pool\nname"),
            lambda d: d["control"].update(unrecognized=1),
        ):
            with self.subTest(mutate=mutate):
                document = valid_document()
                mutate(document)
                with self.assertRaises(C2PoolConfigError):
                    parse_c2_pool_config(encode(document))

    def test_paths_must_be_canonical_absolute_nonroot_posix_paths(self):
        for field in ("operator_root", "cgroup_parent"):
            for path in ("relative/path", "/", "//srv/operator", "/srv//operator",
                         "/srv/./operator", "/srv/../operator", "/srv/operator/",
                         "/srv/\x00operator", "/srv\noperator", "/srv\\operator"):
                with self.subTest(field=field, path=path):
                    document = valid_document()
                    document[field] = path
                    with self.assertRaises(C2PoolConfigError):
                        parse_c2_pool_config(encode(document))

    def test_rejects_noncanonical_duplicate_nonfinite_float_and_oversize_json(self):
        document = valid_document()
        canonical = encode(document)
        alternatives = (
            b" " + canonical,
            b'{"schema_version":2,"schema_version":2}',
            canonical.replace(b'"owner_uid":1000', b'"owner_uid":1000.0'),
            canonical.replace(b'"owner_uid":1000', b'"owner_uid":NaN'),
            b"\xff",
            b" " * (MAX_CONFIG_BYTES + 1),
        )
        for raw in alternatives:
            with self.subTest(prefix=raw[:40]):
                with self.assertRaises(C2PoolConfigError):
                    parse_c2_pool_config(raw)
        # JSON text inputs are intentionally not accepted as an alternate API.
        with self.assertRaises(C2PoolConfigError):
            parse_c2_pool_config(canonical.decode("utf-8"))

    def test_parser_and_module_import_need_no_torch_or_filesystem_access(self):
        raw = encode(valid_document())
        with mock.patch("builtins.open", side_effect=AssertionError("file access")), \
                mock.patch.object(os, "open", side_effect=AssertionError("file access")), \
                mock.patch.object(Path, "read_bytes", side_effect=AssertionError("file access")), \
                mock.patch.object(Path, "read_text", side_effect=AssertionError("file access")):
            self.assertEqual(parse_c2_pool_config(raw).pool_kind, "system_ram")

        source_root = str(Path(__file__).resolve().parents[2] / "src")
        script = (
            "import sys; "
            f"sys.path.insert(0, {source_root!r}); "
            "import steamboat_connector.c2_pool_config; "
            "assert 'torch' not in sys.modules"
        )
        result = subprocess.run([sys.executable, "-S", "-c", script],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
