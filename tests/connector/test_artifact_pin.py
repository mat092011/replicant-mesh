"""Linux advisory-lock and clock-fence tests for runtime artifact pins."""

import os
from pathlib import Path
import subprocess
from concurrent.futures import ThreadPoolExecutor
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
        self._fds = set()
        self._pin_owners = []
        self.addCleanup(self._cleanup_fds)

    def _register_fd(self, descriptor):
        self._fds.add(descriptor)
        return descriptor

    def _transfer_fd(self, descriptor):
        self._fds.discard(descriptor)

    def _close_fd(self, descriptor):
        if descriptor in self._fds:
            self._fds.remove(descriptor)
            os.close(descriptor)

    def _cleanup_fds(self):
        for descriptor in tuple(self._fds):
            self._close_fd(descriptor)

    def test_invalid_inherited_pin_retains_ambiguous_close_owner(self):
        descriptors = (os.open(os.devnull, os.O_RDONLY),
                       os.open(os.devnull, os.O_RDONLY))
        real_close = os.close

        def close_then_raise(descriptor):
            real_close(descriptor)
            if descriptor == descriptors[1]:
                raise OSError("injected close result ambiguity")

        with mock.patch.object(artifact_pin.os, "close", side_effect=close_then_raise):
            with self.assertRaises(artifact_pin.ArtifactPinError) as caught:
                artifact_pin.validate_inherited_pin(
                    descriptors[0], descriptors[1], root=self.root, uid=self.uid,
                    role="invalid", record_path=self.root / "unused",
                    expected_record={}, clock_domain="", captured_mono=0,
                    catalog_deadline=2, assignment_deadline=1, clock=object(),
                    signed_catalog=b"", signed_assignment=b"", verifier=object())
        owner = caught.exception.pin_owner
        self.assertEqual(owner._state, "faulted")
        self.assertEqual(owner._uncertain_descriptors["role_fd"], descriptors[1])
        with self.assertRaises(OSError):
            os.fstat(descriptors[1])
        replacement = os.open(os.devnull, os.O_RDONLY)
        if replacement != descriptors[1]:
            os.dup2(replacement, descriptors[1])
            os.close(replacement)
            replacement = descriptors[1]
        with self.assertRaises(artifact_pin.ArtifactPinError):
            owner.close_after_failed_acquire()
        os.fstat(replacement)
        os.close(replacement)

    def test_aliased_invalid_inherited_fd_is_closed_once(self):
        descriptor = os.open(os.devnull, os.O_RDONLY)
        with self.assertRaises(artifact_pin.ArtifactPinError) as caught:
            artifact_pin.validate_inherited_pin(
                descriptor, descriptor, root=self.root, uid=self.uid,
                role="host", record_path=self.root / ".runtime-pin-host.json",
                expected_record={}, clock_domain="", captured_mono=0,
                catalog_deadline=2, assignment_deadline=1, clock=object(),
                signed_catalog=b"", signed_assignment=b"", verifier=object())
        owner = caught.exception.pin_owner if hasattr(caught.exception, "pin_owner") else None
        # A successful one-time close needs no uncertain owner; an error path
        # must never close this numeric descriptor a second time.
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        replacement = os.open(os.devnull, os.O_RDONLY)
        if replacement != descriptor:
            os.dup2(replacement, descriptor)
            os.close(replacement)
            replacement = descriptor
        if owner is not None:
            with self.assertRaises(artifact_pin.ArtifactPinError):
                owner.close_after_failed_acquire()
        os.fstat(replacement)
        os.close(replacement)

    def tearDown(self):
        error = None
        try:
            for owner in reversed(self._pin_owners):
                try:
                    owner.close()
                except BaseException as failure:
                    error = error or failure
        finally:
            try:
                self._cleanup_fds()
            finally:
                self.temporary.cleanup()
        if error is not None:
            raise error

    def test_global_shared_cross_role_pins_block_every_mutation(self):
        global_host = artifact_pin._lock(self.root, artifact_pin.GLOBAL_LOCK,
                                         self.uid, fcntl.LOCK_SH)
        self._register_fd(global_host)
        host_role = artifact_pin._lock(self.root, artifact_pin.ROLE_LOCKS["host"],
                                       self.uid, fcntl.LOCK_EX)
        self._register_fd(host_role)
        global_coordinator = artifact_pin._lock(
            self.root, artifact_pin.GLOBAL_LOCK, self.uid, fcntl.LOCK_SH)
        self._register_fd(global_coordinator)
        coordinator_role = artifact_pin._lock(
            self.root, artifact_pin.ROLE_LOCKS["coordinator"], self.uid,
            fcntl.LOCK_EX)
        self._register_fd(coordinator_role)
        before = os.stat(self.root / artifact_pin.GLOBAL_LOCK).st_ino
        with self.assertRaises(artifact_pin.ArtifactPinBusy):
            with artifact_pin.artifact_store_mutation(self.root, uid=self.uid):
                self.fail("mutation crossed active runtime pins")
        with self.assertRaises(artifact_pin.ArtifactPinBusy):
            artifact_pin._lock(self.root, artifact_pin.ROLE_LOCKS["host"],
                               self.uid, fcntl.LOCK_EX)
        self.assertEqual(os.stat(self.root / artifact_pin.GLOBAL_LOCK).st_ino, before)
        for descriptor in (coordinator_role, global_coordinator, host_role, global_host):
            self._close_fd(descriptor)
        with artifact_pin.artifact_store_mutation(self.root, uid=self.uid):
            self.assertEqual(os.stat(self.root / artifact_pin.GLOBAL_LOCK).st_ino, before)

    def test_child_closing_inherited_descriptors_does_not_release_parent_pin(self):
        from tests.connector.test_artifacts import (
            _PUBLIC, _assignment_payload, _catalog_payload, _sign_document)
        from steamboat_connector.catalog import CatalogVerifier

        owned = {}

        def register(fd):
            owned[fd] = True
            self.addCleanup(lambda descriptor=fd:
                            os.close(descriptor) if owned.pop(descriptor, False) else None)
            return fd

        def close_owned(fd):
            if owned.pop(fd, False):
                os.close(fd)

        global_fd = register(artifact_pin._lock(
            self.root, artifact_pin.GLOBAL_LOCK, self.uid, fcntl.LOCK_SH))
        role_fd = register(artifact_pin._lock(
            self.root, artifact_pin.ROLE_LOCKS["host"], self.uid, fcntl.LOCK_EX))
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
        child_global = register(fcntl.fcntl(global_fd, fcntl.F_DUPFD, 200))
        child_role = register(fcntl.fcntl(role_fd, fcntl.F_DUPFD, 201))
        os.set_inheritable(child_global, True)
        os.set_inheritable(child_role, True)
        # Ownership transfers to the validator, which either closes on failure
        # or returns an owner retaining both descriptors on success.
        owned.pop(child_global)
        owned.pop(child_role)
        validated = artifact_pin.validate_inherited_pin(
            child_global, child_role, root=self.root, uid=self.uid,
            role="host", record_path=self.root / name, expected_record=record,
            clock_domain=clock_identity(),
            captured_mono=captured, catalog_deadline=captured + 60,
            assignment_deadline=captured + 60, clock=clock,
            signed_catalog=catalog_bytes, signed_assignment=assignment_bytes,
            verifier=verifier)
        self._pin_owners.append(validated)
        self.addCleanup(validated.close)
        self.assertEqual(dict(validated.pin.record), record)
        self.assertFalse(os.get_inheritable(validated.pin.global_fd))
        self.assertFalse(os.get_inheritable(validated.pin.role_fd))
        probe = subprocess.Popen(
            [sys.executable, "-c",
             "import os,sys; fd=" + str(validated.pin.global_fd) + "\n"
             "try: os.fstat(fd)\nexcept OSError: sys.exit(0)\nsys.exit(2)"],
            close_fds=False)
        try:
            returncode = probe.wait(timeout=5)
        finally:
            if probe.poll() is None:
                probe.kill()
            probe.wait(timeout=5)
        self.assertEqual(returncode, 0, "CLOEXEC descriptor leaked across exec")
        forged_record = dict(record, boot_id="6" * 32)
        duplicate_global, duplicate_role = register(os.dup(global_fd)), register(os.dup(role_fd))
        owned.pop(duplicate_global)
        owned.pop(duplicate_role)
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
        replacement_global, replacement_role = register(os.dup(global_fd)), register(os.dup(role_fd))
        owned.pop(replacement_global)
        owned.pop(replacement_role)
        real_close = os.close

        def close_then_raise(descriptor):
            real_close(descriptor)
            if descriptor == replacement_role:
                raise OSError("injected late cleanup ambiguity")

        with mock.patch.object(artifact_pin.os, "close", side_effect=close_then_raise):
            with self.assertRaises(artifact_pin.ArtifactPinError) as caught:
                artifact_pin.validate_inherited_pin(
                    replacement_global, replacement_role, root=self.root, uid=self.uid,
                    role="host", record_path=self.root / name, expected_record=record,
                    clock_domain=clock_identity(), captured_mono=captured,
                    catalog_deadline=captured + 60, assignment_deadline=captured + 60,
                    clock=clock, signed_catalog=catalog_bytes,
                    signed_assignment=replacement_bytes, verifier=verifier)
        self.assertEqual(caught.exception.pin_owner._state, "faulted")
        self.assertEqual(caught.exception.pin_owner._uncertain_descriptors["role_fd"],
                         replacement_role)
        # Parent teardown must not drop the child's descriptor copies.
        close_owned(role_fd)
        close_owned(global_fd)
        with self.assertRaises(artifact_pin.ArtifactPinBusy):
            with artifact_pin.artifact_store_mutation(self.root, uid=self.uid):
                pass
        self.assertTrue(validated.pin.assert_open_descriptors())
        validated.close()
        with artifact_pin.artifact_store_mutation(self.root, uid=self.uid):
            pass

    def test_stopped_boolean_does_not_bypass_store_pin(self):
        from tests.connector.test_artifacts import _PUBLIC
        from steamboat_connector.catalog import CatalogVerifier
        installer = ArtifactInstaller(
            self.root, CatalogVerifier(_PUBLIC),
            disk_ceiling_bytes=1 << 30, disk_headroom_bytes=16 * 1024 * 1024)
        state_path = self.root / "artifact-install-state.json"
        before = state_path.read_bytes()
        global_fd = artifact_pin._lock(self.root, artifact_pin.GLOBAL_LOCK,
                                       self.uid, fcntl.LOCK_SH)
        self._register_fd(global_fd)
        with self.assertRaises(ArtifactInstallBusy):
            installer.deactivate("host", compute_stopped=True)
        self.assertEqual(state_path.read_bytes(), before)
        self._close_fd(global_fd)

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
        self._register_fd(global_fd)
        readonly = ArtifactInstaller(self.root, verifier, read_only=True, **options)
        self.assertTrue(readonly.read_only)
        self.assertEqual((self.root / "artifact-install-state.json").read_bytes(), before)
        with self.assertRaises(ArtifactInstallBusy):
            ArtifactInstaller(self.root, verifier, **options)
        with self.assertRaises(ArtifactInstallError):
            readonly.deactivate("host", compute_stopped=True)
        self._close_fd(global_fd)


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
    @staticmethod
    def _release_pin():
        pin = object.__new__(artifact_pin.RuntimeArtifactPin)
        pin._released = False
        pin._release_faulted = False
        pin._close_state = {"role": "open", "global": "open"}
        pin._release_lock = __import__("threading").Lock()
        pin.role_fd, pin.global_fd = 85, 86
        pin.root = Path("unused")
        pin.record_path = Path(".runtime-pin-host.json")
        pin.uid = 1
        pin.record = {"pin_id": "x"}
        return pin

    def test_parent_release_serializes_concurrent_close_once(self):
        import threading
        entered = threading.Event()
        proceed = threading.Event()
        closed = []
        pin = self._release_pin()
        remove = mock.Mock()

        def delayed_close(fd):
            closed.append(fd)
            if len(closed) == 1:
                entered.set()
                self.assertTrue(proceed.wait(2))

        with mock.patch.object(artifact_pin, "_remove_old_pin_record", remove), \
                mock.patch.object(artifact_pin.os, "close", side_effect=delayed_close):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(pin.release)
                self.assertTrue(entered.wait(2))
                second = pool.submit(pin.release)
                proceed.set()
                first.result(timeout=2)
                second.result(timeout=2)
        self.assertEqual(sorted(closed), [85, 86])
        self.assertEqual(remove.call_count, 1)
        self.assertTrue(pin._released)
        self.assertIsNone(pin.role_fd)
        self.assertIsNone(pin.global_fd)

    def test_parent_release_close_error_latches_without_retry(self):
        pin = self._release_pin()
        remove = mock.Mock()
        close = mock.Mock(side_effect=[OSError("unknown role fd state"), None])
        with mock.patch.object(artifact_pin, "_remove_old_pin_record", remove), \
                mock.patch.object(artifact_pin.os, "close", close):
            with self.assertRaisesRegex(artifact_pin.ArtifactPinError, "cleanup failed"):
                pin.release()
            with self.assertRaisesRegex(artifact_pin.ArtifactPinError, "faulted"):
                pin.release()
        self.assertEqual(close.call_count, 2)
        self.assertEqual(remove.call_count, 1)
        self.assertFalse(pin._released)
        self.assertTrue(pin._release_faulted)
        self.assertEqual(pin._close_state, {"role": "unknown", "global": "closed"})
        self.assertIsNone(pin.role_fd)
        self.assertIsNone(pin.global_fd)

    def test_lock_contention_close_error_is_not_retried(self):
        close = mock.Mock(side_effect=OSError("ambiguous close"))
        with mock.patch.object(artifact_pin, "_require_linux"), \
                mock.patch.object(artifact_pin, "_open_stable_lock", return_value=71), \
                mock.patch.object(artifact_pin, "fcntl",
                                  SimpleNamespace(LOCK_NB=4, flock=mock.Mock(
                                      side_effect=BlockingIOError()))), \
                mock.patch.object(artifact_pin.os, "close", close):
            with self.assertRaisesRegex(artifact_pin.ArtifactPinError, "cleanup failed") as raised:
                artifact_pin._lock("unused", "unused", 1, 1)
        self.assertEqual(close.call_count, 1)
        self.assertEqual(raised.exception.pin_owner._state, "faulted")
        self.assertEqual(raised.exception.pin_owner._close_outcomes["global_fd"], "unknown")

    def test_child_pin_close_serializes_concurrent_cleanup(self):
        import threading
        entered = threading.Event()
        proceed = threading.Event()
        calls = []

        def delayed_close(fd):
            calls.append(fd)
            if len(calls) == 1:
                entered.set()
                self.assertTrue(proceed.wait(2))

        pin = artifact_pin.InheritedArtifactPin(
            global_fd=81, role_fd=82, root="unused", uid=1, role="host",
            record={}, global_identity=(), role_identity=())
        with mock.patch.object(artifact_pin.os, "close", side_effect=delayed_close):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(pin.close)
                self.assertTrue(entered.wait(2))
                second = pool.submit(pin.close)
                proceed.set()
                first.result(timeout=2)
                second.result(timeout=2)
        self.assertEqual(sorted(calls), [81, 82])
        self.assertEqual(pin._close_state, "closed")

    def test_child_pin_close_error_is_faulted_and_never_retried(self):
        pin = artifact_pin.InheritedArtifactPin(
            global_fd=83, role_fd=84, root="unused", uid=1, role="host",
            record={}, global_identity=(), role_identity=())
        close = mock.Mock(side_effect=[OSError("unknown role fd state"), None])
        with mock.patch.object(artifact_pin.os, "close", close):
            with self.assertRaisesRegex(artifact_pin.ArtifactPinError, "cleanup failed"):
                pin.close()
            with self.assertRaisesRegex(artifact_pin.ArtifactPinError, "faulted"):
                pin.close()
        self.assertEqual(close.call_count, 2)
        self.assertEqual(pin._uncertain_descriptors, {"role_fd": 84})

    def test_close_error_latches_cleanup_without_retrying_descriptor_numbers(self):
        pin = object.__new__(artifact_pin.RuntimeArtifactPin)
        pin._released = False
        pin._release_faulted = False
        pin._close_state = {"role": "open", "global": "open"}
        pin._release_lock = __import__("threading").Lock()
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

    def test_failed_acquire_retains_faulted_partial_owner_on_close_error(self):
        from tests.connector.test_artifacts import _PUBLIC
        from steamboat_connector.catalog import CatalogVerifier
        from steamboat_runtime.assigned_artifacts import AssignedArtifactView

        view = object.__new__(AssignedArtifactView)
        clock = Clock(wall=lambda: 1000.0, monotonic=lambda: 10.0,
                      uncertainty_seconds=lambda: 0.0)
        view.installer = SimpleNamespace(
            verifier=CatalogVerifier(_PUBLIC, clock=clock), root="unused", uid=1)
        view.role = "host"
        view.assignment_id = "asg_" + "a" * 32
        view.account_id = "acct_" + "b" * 32
        view.device_id = "dev_" + "c" * 32
        view._locked_manifest = mock.Mock(side_effect=RuntimeError("inactive"))
        fake_fcntl = SimpleNamespace(LOCK_SH=1, LOCK_EX=2)
        close = mock.Mock(side_effect=[OSError("uncertain role close"), None])
        with mock.patch.object(artifact_pin, "fcntl", fake_fcntl), \
                mock.patch.object(artifact_pin, "_lock", side_effect=[91, 92]), \
                mock.patch.object(artifact_pin, "_remove_old_pin_record"), \
                mock.patch("steamboat_runtime.protocol.clock.clock_identity",
                           return_value="test-domain"), \
                mock.patch.object(artifact_pin.os, "close", close):
            with self.assertRaisesRegex(artifact_pin.ArtifactPinError, "partial runtime pin cleanup failed") as raised:
                artifact_pin.RuntimeArtifactPin.acquire(
                    view, clock=clock, boot_id="d" * 32)
            owner = raised.exception.pin_owner
            view._locked_manifest.assert_called_once_with()
            self.assertEqual(str(raised.exception.__cause__), "inactive")
            self.assertEqual(owner._state, "faulted")
            self.assertEqual(owner._close_outcomes["role_fd"], "unknown")
            self.assertEqual(owner._close_outcomes["global_fd"], "closed")
            with self.assertRaisesRegex(artifact_pin.ArtifactPinError, "faulted"):
                owner.close_after_failed_acquire()
        self.assertEqual(close.call_count, 2)


if __name__ == "__main__":
    unittest.main()
