"""Linux advisory-lock and clock-fence tests for runtime artifact pins."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

try:
    import fcntl
except ImportError:
    fcntl = None

from steamboat_connector import artifact_pin
from steamboat_connector.artifacts import (ArtifactInstallBusy, ArtifactInstallError,
                                           ArtifactInstaller)
from steamboat_security.clock import Clock
from steamboat_runtime.protocol.clock import clock_identity


@unittest.skipUnless(sys.platform.startswith("linux"), "runtime pins require Linux flock")
class ArtifactPinLockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.uid = os.getuid()

    def tearDown(self):
        self.temporary.cleanup()

    def test_global_shared_cross_role_pins_block_every_mutation(self):
        global_host = artifact_pin._lock(self.root, artifact_pin.GLOBAL_LOCK,
                                         self.uid, fcntl.LOCK_SH)
        host_role = artifact_pin._lock(self.root, artifact_pin.ROLE_LOCKS["host"],
                                       self.uid, fcntl.LOCK_EX)
        global_coordinator = artifact_pin._lock(
            self.root, artifact_pin.GLOBAL_LOCK, self.uid, fcntl.LOCK_SH)
        coordinator_role = artifact_pin._lock(
            self.root, artifact_pin.ROLE_LOCKS["coordinator"], self.uid,
            fcntl.LOCK_EX)
        before = os.stat(self.root / artifact_pin.GLOBAL_LOCK).st_ino
        with self.assertRaises(artifact_pin.ArtifactPinBusy):
            with artifact_pin.artifact_store_mutation(self.root, uid=self.uid):
                self.fail("mutation crossed active runtime pins")
        with self.assertRaises(artifact_pin.ArtifactPinBusy):
            artifact_pin._lock(self.root, artifact_pin.ROLE_LOCKS["host"],
                               self.uid, fcntl.LOCK_EX)
        self.assertEqual(os.stat(self.root / artifact_pin.GLOBAL_LOCK).st_ino, before)
        for descriptor in (coordinator_role, global_coordinator, host_role, global_host):
            os.close(descriptor)
        with artifact_pin.artifact_store_mutation(self.root, uid=self.uid):
            self.assertEqual(os.stat(self.root / artifact_pin.GLOBAL_LOCK).st_ino, before)

    def test_child_closing_inherited_descriptors_does_not_release_parent_pin(self):
        from tests.connector.test_artifacts import (
            _PUBLIC, _assignment_payload, _catalog_payload, _sign_document)
        from steamboat_connector.catalog import CatalogVerifier

        global_fd = artifact_pin._lock(self.root, artifact_pin.GLOBAL_LOCK,
                                       self.uid, fcntl.LOCK_SH)
        role_fd = artifact_pin._lock(self.root, artifact_pin.ROLE_LOCKS["host"],
                                     self.uid, fcntl.LOCK_EX)
        pin_id = "a" * 64
        now = int(__import__("time").time())
        clock = Clock(wall=lambda: now + 1, monotonic=lambda: 10.0,
                      uncertainty_seconds=lambda: 0.0)
        verifier = CatalogVerifier(_PUBLIC, clock=clock)
        catalog_bytes = _sign_document(_catalog_payload(now=now), "catalog")
        catalog = verifier.verify_catalog(catalog_bytes)
        assignment_payload = _assignment_payload(
            catalog, now=now, account_id="acct_" + "1" * 32,
            device_id="dev_" + "2" * 32, assignment_id="asg_" + "3" * 32)
        assignment_bytes = _sign_document(assignment_payload, "assignment")
        verifier.verify_assignment(assignment_bytes, catalog,
            account_id=assignment_payload["account_id"],
            device_id=assignment_payload["device_id"], role="host")
        record = {"version": 1, "pin_id": pin_id,
                  "account_id": assignment_payload["account_id"],
                  "device_id": assignment_payload["device_id"], "role": "host",
                  "assignment_id": assignment_payload["assignment_id"],
                  "catalog_sha256": catalog.document_sha256,
                  "assignment_sha256": __import__("hashlib").sha256(
                      assignment_bytes).hexdigest(), "boot_id": "5" * 32}
        name = artifact_pin._pin_record("host")
        artifact_pin._write_pin_record(self.root, name, record, self.uid)
        captured = 9.0
        validated = artifact_pin.validate_inherited_pin(
            os.dup(global_fd), os.dup(role_fd), root=self.root, uid=self.uid,
            role="host", record_path=self.root / name, expected_record=record,
            clock_domain=clock_identity(),
            captured_mono=captured, catalog_deadline=captured + 60,
            assignment_deadline=captured + 60, clock=clock,
            signed_catalog=catalog_bytes, signed_assignment=assignment_bytes,
            verifier=verifier)
        self.assertEqual(dict(validated.pin.record), record)
        forged_record = dict(record, boot_id="6" * 32)
        duplicate_global, duplicate_role = os.dup(global_fd), os.dup(role_fd)
        with self.assertRaises(artifact_pin.ArtifactPinError):
            artifact_pin.validate_inherited_pin(
                duplicate_global, duplicate_role, root=self.root, uid=self.uid,
                role="host", record_path=self.root / name, expected_record=forged_record,
                clock_domain=clock_identity(), captured_mono=captured,
                catalog_deadline=captured + 60, assignment_deadline=captured + 60,
                clock=clock, signed_catalog=catalog_bytes,
                signed_assignment=assignment_bytes, verifier=verifier)
        with self.assertRaises(OSError):
            os.fstat(duplicate_global)
        same_id_replacement = dict(assignment_payload)
        same_id_replacement["issued_at"] -= 1
        replacement_bytes = _sign_document(same_id_replacement, "assignment")
        replacement_global, replacement_role = os.dup(global_fd), os.dup(role_fd)
        with self.assertRaises(artifact_pin.ArtifactPinError):
            artifact_pin.validate_inherited_pin(
                replacement_global, replacement_role, root=self.root, uid=self.uid,
                role="host", record_path=self.root / name, expected_record=record,
                clock_domain=clock_identity(), captured_mono=captured,
                catalog_deadline=captured + 60, assignment_deadline=captured + 60,
                clock=clock, signed_catalog=catalog_bytes,
                signed_assignment=replacement_bytes, verifier=verifier)
        # Parent teardown must not drop the child's descriptor copies.
        os.close(role_fd)
        os.close(global_fd)
        with self.assertRaises(artifact_pin.ArtifactPinBusy):
            with artifact_pin.artifact_store_mutation(self.root, uid=self.uid):
                pass
        self.assertTrue(validated.pin.assert_open_descriptors())
        validated.close()
        with artifact_pin.artifact_store_mutation(self.root, uid=self.uid):
            pass

    def test_stopped_boolean_does_not_bypass_store_pin(self):
        global_fd = artifact_pin._lock(self.root, artifact_pin.GLOBAL_LOCK,
                                       self.uid, fcntl.LOCK_SH)
        installer = object.__new__(ArtifactInstaller)
        installer.root = self.root
        installer.uid = self.uid
        installer.read_only = False
        installer._locked = mock.Mock(side_effect=AssertionError("installer lock must follow global EX"))
        with self.assertRaises(ArtifactInstallBusy):
            installer.deactivate("host", compute_stopped=True)
        installer._locked.assert_not_called()
        os.close(global_fd)

    def test_read_only_installer_opens_under_pin_but_normal_recovery_is_busy(self):
        from tests.connector.test_artifacts import _PUBLIC
        from steamboat_connector.catalog import CatalogVerifier

        verifier = CatalogVerifier(_PUBLIC)
        options = dict(disk_ceiling_bytes=1 << 30,
                       disk_headroom_bytes=16 * 1024 * 1024)
        ArtifactInstaller(self.root, verifier, **options)
        before = (self.root / "artifact-install-state.json").read_bytes()
        global_fd = artifact_pin._lock(self.root, artifact_pin.GLOBAL_LOCK,
                                       self.uid, fcntl.LOCK_SH)
        readonly = ArtifactInstaller(self.root, verifier, read_only=True, **options)
        self.assertTrue(readonly.read_only)
        self.assertEqual((self.root / "artifact-install-state.json").read_bytes(), before)
        with self.assertRaises(ArtifactInstallBusy):
            ArtifactInstaller(self.root, verifier, **options)
        with self.assertRaises(ArtifactInstallError):
            readonly.deactivate("host", compute_stopped=True)
        os.close(global_fd)


@unittest.skipUnless(sys.platform.startswith("linux"), "clock domain is Linux-specific")
class ArtifactPinClockTests(unittest.TestCase):
    def test_guard_clips_expiry_under_uncertainty_and_cannot_revive(self):
        current = {"mono": 50.0, "wall": 1000.0, "uncertainty": 0.0}
        clock = Clock(wall=lambda: current["wall"], monotonic=lambda: current["mono"],
                      uncertainty_seconds=lambda: current["uncertainty"])
        record = {"assignment_id": "asg_" + "a" * 32,
                  "account_id": "acct_" + "b" * 32,
                  "device_id": "dev_" + "c" * 32, "role": "host",
                  "assignment_sha256": "e" * 64, "catalog_sha256": "d" * 64}
        pin = SimpleNamespace(record=record,
                              assert_open_descriptors=mock.Mock(return_value=True))
        guard = artifact_pin.RuntimeAssignmentGuard(
            pin=pin, child_clock=clock, child_verifier=object(),
            clock_domain="test-domain", captured_mono=50.0,
            parent_catalog_deadline=150.0, parent_assignment_deadline=150.0,
            child_catalog_deadline=150.0, child_assignment_deadline=150.0,
            catalog_issued_at=900, catalog_expires_at=1100,
            assignment_issued_at=900, assignment_expires_at=1100,
            component="worker-1", manifest_fingerprint="d" * 64,
            assignment_id=record["assignment_id"], account_id=record["account_id"],
            device_id=record["device_id"], role="host",
            assignment_sha256="e" * 64, catalog_sha256="d" * 64,
            record_snapshot=dict(record))
        with mock.patch("steamboat_runtime.protocol.clock.clock_identity",
                        return_value="test-domain"):
            guard.check()
            current.update(mono=130.0, wall=1080.0, uncertainty=30.0)
            with self.assertRaisesRegex(artifact_pin.ArtifactPinError, "expired"):
                guard.check()
            # Reducing uncertainty cannot widen the previously clipped cap.
            current.update(uncertainty=0.0)
            with self.assertRaisesRegex(artifact_pin.ArtifactPinError, "expired"):
                guard.check()
        self.assertEqual(pin.assert_open_descriptors.call_count, 1)


class ArtifactPinCleanupTests(unittest.TestCase):
    def test_close_error_latches_cleanup_without_retrying_descriptor_numbers(self):
        pin = object.__new__(artifact_pin.RuntimeArtifactPin)
        pin._released = False
        pin._release_faulted = False
        pin._close_state = {"role": "open", "global": "open"}
        pin.role_fd, pin.global_fd = 41, 42
        pin.root = Path("unused")
        pin.record_path = Path(".runtime-pin-host.json")
        pin.uid = 1
        pin.record = {"pin_id": "x"}
        close = mock.Mock(side_effect=[OSError("ambiguous role close"),
                                      OSError("ambiguous global close")])
        with mock.patch.object(artifact_pin, "_remove_old_pin_record"), \
                mock.patch.object(artifact_pin.os, "close", close):
            with self.assertRaisesRegex(artifact_pin.ArtifactPinError, "cleanup failed"):
                pin.release()
            with self.assertRaisesRegex(artifact_pin.ArtifactPinError, "faulted"):
                pin.release()
        self.assertEqual(close.call_count, 2)
        self.assertFalse(pin._released)
        self.assertTrue(pin._release_faulted)


if __name__ == "__main__":
    unittest.main()
