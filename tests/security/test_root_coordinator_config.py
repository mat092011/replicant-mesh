"""Dependency-light tests for the closed root coordinator config contract."""
from __future__ import annotations

import os
import tempfile
import unittest

from steamboat_security.codec import canonical_json
from steamboat_security.errors import BindingError
from lab.root_coordinator_config import parse_config_bytes


class RootCoordinatorConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rcfg-")
        self.root = os.path.abspath(self.temp.name)
        self.config_path = os.path.join(self.root, "coordinator.json")
        self.raw = {
            "schema_version": 1,
            "profile": "native_posix_root_coordinator_v1",
            "artifact_directory": os.path.join(self.root, "artifacts"),
            "reference_directory": os.path.join(self.root, "reference"),
            "listen_ip": "127.0.0.1",
            "listen_port": 43121,
            "clock_uncertainty_seconds": 2.5,
            "acceptor_directory": os.path.join(self.root, "sock"),
            "status_report_path": os.path.join(self.root, "status.json"),
            "workers": [
                {
                    "worker_name": f"worker-{index}",
                    "account_id": f"acct_{index:032x}",
                    "device_id": f"dev_{(index + 10):032x}",
                    "boot_id": f"{index:032x}",
                    "assignment_id": f"asg_{(index + 20):032x}",
                    "certificate_path": os.path.join(self.root, f"worker-{index}.pem"),
                    "ip": "127.0.0.1",
                    "port": 44000 + index,
                }
                for index in (1, 2, 3)
            ],
        }

    def tearDown(self):
        self.temp.cleanup()

    def parse(self, raw=None):
        return parse_config_bytes(
            canonical_json(self.raw if raw is None else raw),
            config_path=self.config_path, protected_root=self.root)

    def test_valid_config_is_canonical_closed_and_immutable(self):
        config = self.parse()
        self.assertEqual(tuple(worker.worker_name for worker in config.workers),
                         ("worker-1", "worker-2", "worker-3"))
        self.assertEqual(config.protected_root, self.root)
        self.assertIsInstance(config.workers, tuple)
        with self.assertRaises((AttributeError, TypeError)):
            config.listen_port = 80
        with self.assertRaises((AttributeError, TypeError)):
            config.workers[0].port = 80

    def test_closed_schema_duplicate_json_nonfinite_and_canonical_bytes(self):
        with self.assertRaises(BindingError):
            self.parse({**self.raw, "unexpected": 1})
        duplicate = canonical_json(self.raw).decode("utf-8")
        duplicate = duplicate.replace('"listen_port":43121,',
                                      '"listen_port":43121,"listen_port":43122,')
        with self.assertRaises(BindingError):
            parse_config_bytes(duplicate.encode(), config_path=self.config_path,
                               protected_root=self.root)
        nonfinite = canonical_json({**self.raw, "clock_uncertainty_seconds": 1.0})
        nonfinite = nonfinite.replace(b'"clock_uncertainty_seconds":1.0',
                                      b'"clock_uncertainty_seconds":NaN')
        with self.assertRaises(BindingError):
            parse_config_bytes(nonfinite, config_path=self.config_path,
                               protected_root=self.root)
        with self.assertRaises(BindingError):
            parse_config_bytes(b" " + canonical_json(self.raw), config_path=self.config_path,
                               protected_root=self.root)
        with self.assertRaises(BindingError):
            parse_config_bytes(b"x" * (16 * 1024 + 1), config_path=self.config_path,
                               protected_root=self.root)

    def test_paths_are_normalized_absolute_and_private_paths_stay_under_root(self):
        bad_root = os.path.join(self.root, "..", "escape")
        with self.assertRaises(BindingError):
            parse_config_bytes(canonical_json(self.raw), config_path=self.config_path,
                               protected_root=bad_root)
        with self.assertRaises(BindingError):
            parse_config_bytes(canonical_json(self.raw),
                               config_path=os.path.join(self.root, "..", "config.json"),
                               protected_root=self.root)
        with self.assertRaises(BindingError):
            self.parse({**self.raw, "status_report_path": os.path.join(self.root, "..", "status")})
        outside = dict(self.raw)
        outside["workers"] = [dict(item) for item in self.raw["workers"]]
        outside["workers"][1]["certificate_path"] = os.path.join(
            self.root, "..", "outside.pem")
        with self.assertRaises(BindingError):
            self.parse(outside)
        for key in ("status_report_path", "acceptor_directory"):
            with self.subTest(root_path=key), self.assertRaises(BindingError):
                self.parse({**self.raw, key: self.root})
        cert_at_root = {**self.raw, "workers": [dict(item) for item in self.raw["workers"]]}
        cert_at_root["workers"][0]["certificate_path"] = self.root
        with self.assertRaises(BindingError):
            self.parse(cert_at_root)
        for control in ("\x01", "\x7f"):
            with self.subTest(control=ord(control)), self.assertRaises(BindingError):
                self.parse({**self.raw,
                            "status_report_path": os.path.join(self.root, f"bad{control}.json")})

    def test_paths_cannot_collide_and_acceptor_path_is_bounded(self):
        collision = dict(self.raw, status_report_path=self.config_path)
        with self.assertRaises(BindingError):
            self.parse(collision)
        collision = dict(self.raw, status_report_path=self.raw["acceptor_directory"])
        with self.assertRaises(BindingError):
            self.parse(collision)
        too_long = dict(self.raw, acceptor_directory=os.path.join(self.root, "s" * 80))
        with self.assertRaises(BindingError):
            self.parse(too_long)

    def test_worker_order_identity_endpoint_ip_and_port_are_strict(self):
        changed = dict(self.raw, workers=list(reversed(self.raw["workers"])))
        with self.assertRaises(BindingError):
            self.parse(changed)
        for field, value in (("account_id", "acct_" + "A" * 32),
                             ("device_id", "dev_bad"),
                             ("boot_id", "z" * 32),
                             ("assignment_id", "asg_" + "0" * 31 + "g")):
            altered = {**self.raw, "workers": [dict(item) for item in self.raw["workers"]]}
            altered["workers"][0][field] = value
            with self.subTest(field=field), self.assertRaises(BindingError):
                self.parse(altered)
        for bad_ip in ("worker.example", "0.0.0.0", "224.0.0.1", "127.0.0.1%eth0",
                       "::1", "8.8.8.8", "169.254.1.1", "240.0.0.1"):
            altered = {**self.raw, "workers": [dict(item) for item in self.raw["workers"]]}
            altered["workers"][0]["ip"] = bad_ip
            with self.subTest(ip=bad_ip), self.assertRaises(BindingError):
                self.parse(altered)
        for bad_port in (True, 0, 65536, 80.0):
            altered = {**self.raw, "workers": [dict(item) for item in self.raw["workers"]]}
            altered["workers"][0]["port"] = bad_port
            with self.subTest(port=bad_port), self.assertRaises(BindingError):
                self.parse(altered)
        duplicate_identity = {**self.raw, "workers": [dict(item) for item in self.raw["workers"]]}
        duplicate_identity["workers"][1]["account_id"] = duplicate_identity["workers"][0]["account_id"]
        duplicate_identity["workers"][1]["device_id"] = duplicate_identity["workers"][0]["device_id"]
        with self.assertRaises(BindingError):
            self.parse(duplicate_identity)
        duplicate_endpoint = {**self.raw, "workers": [dict(item) for item in self.raw["workers"]]}
        duplicate_endpoint["workers"][1]["ip"] = duplicate_endpoint["workers"][0]["ip"]
        duplicate_endpoint["workers"][1]["port"] = duplicate_endpoint["workers"][0]["port"]
        with self.assertRaises(BindingError):
            self.parse(duplicate_endpoint)

    def test_uncertainty_and_workers_container_use_exact_types_and_bounds(self):
        for bad in (True, 0, -1, 30.0001, float("inf"), 10 ** 1000):
            with self.subTest(uncertainty=bad), self.assertRaises(BindingError):
                self.parse({**self.raw, "clock_uncertainty_seconds": bad})
        for workers in (self.raw["workers"][:2],
                        self.raw["workers"] + [self.raw["workers"][-1]], "three"):
            with self.subTest(workers=len(workers)), self.assertRaises(BindingError):
                self.parse({**self.raw, "workers": workers})


if __name__ == "__main__":
    unittest.main()
