"""Focused supervisor ownership and child handoff tests."""

import os
import base64
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from steamboat_connector.aggregate_artifact_pin import RuntimeArtifactGroupPin
from steamboat_connector.catalog import CatalogVerifier
from steamboat_connector.process_supervisor import ProcessRoleBackend, ROLE_CONFIG_MAX_BYTES
from steamboat_connector.runtime_pin_handoff import (
    RuntimePinHandoffError, validate_child_pin)
from steamboat_security.clock import Clock

from tests.connector.test_process_supervisor import (
    FakeCgroup, FakeProcess, sample_policy)


def _public_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    return key.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint)


class RuntimePinHandoffTests(unittest.TestCase):
    def setUp(self):
        platform_patch = mock.patch("steamboat_connector.process_supervisor.sys.platform",
                                    "linux")
        platform_patch.start()
        self.addCleanup(platform_patch.stop)
        self.temp = tempfile.TemporaryDirectory()
        os.chmod(self.temp.name, 0o700)
        self.cgroup = FakeCgroup(self.temp.name)
        self.backend = ProcessRoleBackend(self.temp.name, self.cgroup)
        self.pin_fds = (os.open(os.devnull, os.O_RDONLY),
                        os.open(os.devnull, os.O_RDONLY))
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(lambda: [os.close(fd) for fd in self.pin_fds
                                 if fd >= 0])

    def _configured_group_pin(self):
        pin = object.__new__(RuntimeArtifactGroupPin)
        pin.signed_catalog = b"signed-catalog"
        import hashlib
        catalog_digest = hashlib.sha256(pin.signed_catalog).hexdigest()
        pin.record = {
            "version": 2, "pin_id": "c" * 64,
            "account_id": "acct_" + "1" * 32,
            "device_id": "dev_" + "2" * 32, "role": "host",
            "model_id": "test-model", "catalog_sha256": catalog_digest,
            "runtime_boot_id": "d" * 32,
            "assignments": [{"component": "worker-1",
                             "assignment_id": "asg_" + "3" * 32,
                             "assignment_sha256": "a" * 64,
                             "worker_boot_id": "b" * 32}],
        }
        pin.root = Path(self.temp.name)
        pin.uid = os.getuid() if hasattr(os, "getuid") else 1
        pin.record_path = Path(self.temp.name) / ".runtime-pin-host.json"
        pin.global_fd, pin.role_fd = self.pin_fds
        pin.clock_domain = "linux:test"
        pin.captured_mono = 1.0
        pin.catalog_deadline = 1000.0
        pin.clock = Clock(uncertainty_seconds=lambda: 0.0)
        pin.release = mock.Mock()
        metadata = {
            "component": "worker-1", "worker_boot_id": "b" * 32,
            "assignment_deadline": 900.0, "signed_assignment": b"signed-assignment",
        }
        verifier = CatalogVerifier(_public_key(), clock=pin.clock)
        catalog = SimpleNamespace(document_bytes=pin.signed_catalog)
        assignment = SimpleNamespace(
            payload={"assignment_id": pin.record["assignments"][0]["assignment_id"],
                     "component": "worker-1"},
            document_sha256="a" * 64)
        return pin, verifier, metadata, catalog, assignment

    def test_supervisor_holds_pin_until_empty_group_is_removed(self):
        pin, verifier, metadata, catalog, assignment = self._configured_group_pin()
        holder = {}

        def spawn(args, **kwargs):
            process = FakeProcess(args, kwargs, self.cgroup)
            holder["process"] = process
            return process

        with (mock.patch.object(RuntimeArtifactGroupPin, "assert_open_descriptors",
                                return_value=True),
              mock.patch.object(RuntimeArtifactGroupPin, "child_launch_metadata",
                                return_value=metadata),
              mock.patch.object(CatalogVerifier, "verify_catalog", return_value=catalog),
              mock.patch.object(CatalogVerifier, "verify_assignment",
                                return_value=assignment),
              mock.patch("steamboat_connector.process_supervisor.atomic_write_private",
                         side_effect=lambda path, data: Path(path).write_bytes(data)),
              mock.patch("steamboat_connector.process_supervisor.read_private_json",
                         side_effect=lambda path, **kwargs: __import__("json").loads(
                             Path(path).read_text(encoding="utf-8"))),
              mock.patch.object(ProcessRoleBackend, "_read_ready", return_value=True),
              mock.patch("steamboat_connector.process_supervisor.signal",
                         SimpleNamespace(SIGTERM=15, SIGKILL=9)),
              mock.patch("steamboat_connector.process_supervisor.os.write",
                         side_effect=lambda fd, data: len(data) if data == b"R" else 0),
              mock.patch("steamboat_connector.process_supervisor.subprocess.Popen",
                         side_effect=spawn),
              mock.patch("steamboat_connector.process_supervisor.os.killpg",
                         side_effect=lambda pid, sig: holder["process"].on_signal(
                             sig, kill_descendants=False), create=True)):
            self.assertTrue(self.backend.configure_pinned_role(
                "host", {"test_mode": True}, pin, catalog_verifier=verifier))
            self.assertTrue(self.backend.start("host", sample_policy()))
            self.assertEqual(set(holder["process"].kwargs["pass_fds"]),
                             {holder["process"].kwargs["pass_fds"][0], *self.pin_fds})
            self.assertIs(self.backend._owned["host"].artifact_pin, pin)
            self.assertFalse(self.backend.stop(["host"], 0.2)["host"])
            pin.release.assert_not_called()
            self.assertIn("host", self.backend._pinned_roles)
            self.cgroup.set_empty()
            self.assertTrue(self.backend.stop(["host"], 0.2)["host"])
            pin.release.assert_called_once_with()
            self.assertNotIn("host", self.backend._pinned_roles)

    def test_pinned_metadata_keeps_original_config_limit(self):
        too_large = {"kind": "single", "payload": "x" * ROLE_CONFIG_MAX_BYTES}
        with self.assertRaises(ValueError):
            ProcessRoleBackend._encode_config("host", {}, pin_metadata=too_large)

    def test_child_helper_requires_exact_trusted_clock_and_verifier(self):
        with self.assertRaises(RuntimePinHandoffError):
            validate_child_pin({}, clock=object(), verifier=object())

    def test_group_handoff_duplicates_one_pair_per_assignment(self):
        clock = Clock(uncertainty_seconds=lambda: 0.0)
        public_key = _public_key()
        verifier = CatalogVerifier(public_key, clock=clock)
        original = (os.open(os.devnull, os.O_RDONLY),
                    os.open(os.devnull, os.O_RDONLY))
        metadata = {
            "version": 1, "kind": "group", "role": "host",
            "root": self.temp.name, "uid": os.getuid() if hasattr(os, "getuid") else 1,
            "record_path": str(Path(self.temp.name) / ".runtime-pin-host.json"),
            "record": {"role": "host"}, "global_fd": original[0],
            "role_fd": original[1], "clock_domain": "linux:test",
            "captured_mono": 1.0, "catalog_deadline": 1000.0,
            "signed_catalog": base64.b64encode(b"catalog").decode("ascii"),
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "assignments": [{
                "component": f"worker-{index}",
                "worker_boot_id": f"{index:032x}",
                "assignment_deadline": 900.0,
                "signed_assignment": base64.b64encode(
                    f"assignment-{index}".encode()).decode("ascii"),
            } for index in range(1, 4)],
        }
        created = []

        class Owner:
            def __init__(self, fds):
                self.fds = fds

            def close(self):
                for fd in self.fds:
                    os.close(fd)

        def validate(global_fd, role_fd, **kwargs):
            created.append((global_fd, role_fd))
            return Owner((global_fd, role_fd)), object()

        with mock.patch("steamboat_connector.aggregate_artifact_pin.validate_inherited_group_pin",
                        side_effect=validate):
            handoff = validate_child_pin(metadata, clock=clock, verifier=verifier)
        self.assertEqual(len(created), 3)
        self.assertEqual(len({fd for pair in created for fd in pair}), 6)
        for fd in original:
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertEqual(len(handoff.guards), 3)
        handoff.close()


if __name__ == "__main__":
    unittest.main()
