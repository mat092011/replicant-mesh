"""Device-pinned owner consent persistence and startup serialization tests."""
from __future__ import annotations

import multiprocessing
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from steamboat_security.errors import StorageError
import steamboat_connector.owner_consent as consent_module
from steamboat_connector.owner_consent import (OwnerConsentStore,
    provision_owner_consent)


ACCOUNT = "acct_" + "1" * 32
DEVICE = "dev_" + "2" * 32


def _cross_process_disable(root, contended, acquired, release, finished):
    import fcntl
    original = fcntl.flock

    def observed(fd, operation):
        if operation == fcntl.LOCK_EX:
            try:
                original(fd, operation | fcntl.LOCK_NB)
            except BlockingIOError:
                contended.set()
            else:
                return None
        return original(fd, operation)

    fcntl.flock = observed
    try:
        store = OwnerConsentStore(root, expected_uid=os.geteuid(),
                                  account_id=ACCOUNT, device_id=DEVICE,
                                  _fault_hook=lambda step: (
                                      acquired.set(), release.wait(10))
                                  if step == "state.write" else None)
        store.set_role_enabled("host", False)
        finished.set()
        store.close()
    except BaseException:
        finished.set()
        raise
    finally:
        fcntl.flock = original


def _open_store_fifo_race(root, result):
    original_stat = os.stat
    injected = False

    def racing_stat(path, *args, **kwargs):
        nonlocal injected
        if (not injected and path == consent_module.STATE_NAME
                and kwargs.get("dir_fd") is not None):
            info = original_stat(path, *args, **kwargs)
            dir_fd = kwargs["dir_fd"]
            os.replace(consent_module.STATE_NAME, "owner-consent.saved",
                       src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            os.mkfifo(consent_module.STATE_NAME, 0o600, dir_fd=dir_fd)
            injected = True
            return info
        return original_stat(path, *args, **kwargs)

    try:
        with mock.patch.object(consent_module.os, "stat", side_effect=racing_stat):
            store = OwnerConsentStore(root, expected_uid=os.geteuid(),
                                      account_id=ACCOUNT, device_id=DEVICE)
            store.close()
        result.put("opened" if not injected else "race-not-rejected")
    except BaseException as error:
        result.put(f"{type(error).__name__}:{error}")


class OwnerConsentParserTests(unittest.TestCase):
    def test_canonical_snapshot_round_trip_and_principal_binding(self):
        encoded = consent_module._canonical(consent_module._document(
            ACCOUNT, DEVICE, 9, ("coordinator", "host")))
        snapshot = consent_module._parse(encoded, ACCOUNT, DEVICE)
        self.assertEqual(snapshot.enabled_roles, ("coordinator", "host"))
        self.assertEqual(snapshot.epoch, 9)
        with self.assertRaises(StorageError):
            consent_module._parse(encoded, ACCOUNT, "dev_" + "3" * 32)
        with self.assertRaises(StorageError):
            consent_module._parse(encoded + b"\n", ACCOUNT, DEVICE)

    def test_parser_rejects_noncanonical_disabled_and_duplicate_role_state(self):
        bad = consent_module._canonical(consent_module._document(
            ACCOUNT, DEVICE, 0, ("host",)))
        self.assertEqual(consent_module._parse(bad, ACCOUNT, DEVICE).enabled_roles,
                         ("host",))
        altered = bad.replace(b'"enabled_roles":["host"]',
                              b'"enabled_roles":["host","host"]')
        with self.assertRaises(StorageError):
            consent_module._parse(altered, ACCOUNT, DEVICE)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid")
                     and hasattr(os, "O_NOFOLLOW"), "native POSIX owner store")
class OwnerConsentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="owner-consent-")
        self.root = Path(self.temp.name) / "owner"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        provision_owner_consent(self.root, expected_uid=os.geteuid(),
                                account_id=ACCOUNT, device_id=DEVICE)

    def tearDown(self):
        self.temp.cleanup()

    def store(self, **kwargs):
        return OwnerConsentStore(self.root, expected_uid=os.geteuid(),
                                 account_id=ACCOUNT, device_id=DEVICE, **kwargs)

    def test_serialized_snapshot_holds_read_only_owner_lock_without_epoch_bump(self):
        import fcntl
        store = self.store()
        self.addCleanup(store.close)
        store.set_role_enabled("host", True)
        second = self.store()
        self.addCleanup(second.close)
        blocked = threading.Event()
        changed = threading.Event()
        original_flock = fcntl.flock

        def observed_flock(fd, operation):
            if operation == fcntl.LOCK_EX:
                try:
                    original_flock(fd, operation | fcntl.LOCK_NB)
                except BlockingIOError:
                    blocked.set()
                else:
                    return None
            return original_flock(fd, operation)

        with store.serialized_snapshot() as snapshot:
            self.assertEqual(snapshot.epoch, 1)
            with mock.patch.object(fcntl, "flock", side_effect=observed_flock):
                thread = threading.Thread(target=lambda: (
                    second.set_role_enabled("host", False), changed.set()))
                thread.start()
                self.assertTrue(blocked.wait(2))
                self.assertFalse(changed.is_set())
                self.assertEqual(snapshot.enabled_roles, ("host",))
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(changed.is_set())
        self.assertEqual(store.snapshot().epoch, 2)

    def test_explicit_provisioning_starts_disabled_and_principal_is_pinned(self):
        with self.store() as store:
            snapshot = store.snapshot()
            self.assertEqual((snapshot.account_id, snapshot.device_id), (ACCOUNT, DEVICE))
            self.assertEqual(snapshot.epoch, 0)
            self.assertEqual(snapshot.enabled_roles, ())
            with self.assertRaises(StorageError):
                OwnerConsentStore(self.root, expected_uid=os.geteuid(),
                                  account_id=ACCOUNT, device_id="dev_" + "3" * 32)
            with self.assertRaises(StorageError):
                provision_owner_consent(self.root, expected_uid=os.geteuid(),
                                        account_id=ACCOUNT, device_id=DEVICE)

    def test_exact_opt_in_projection_and_start_intent_epoch(self):
        with self.store() as store:
            enabled = store.set_role_enabled("host", True)
            self.assertEqual((enabled.epoch, enabled.enabled_roles), (1, ("host",)))
            with self.assertRaises(StorageError):
                with store.begin_start(("coordinator",), cancel_event=threading.Event()):
                    pass
            with self.assertRaises(ValueError):
                with store.begin_start((), cancel_event=threading.Event()):
                    pass
            with store.begin_start(("host",), cancel_event=threading.Event()) as start:
                self.assertEqual((start.epoch, start.enabled_roles), (2, ("host",)))
            self.assertEqual(store.snapshot().epoch, 2)

    def test_close_waits_for_held_start_and_rejects_after_close_before_open(self):
        store = self.store()
        store.set_role_enabled("host", True)
        entered, release, close_started, close_done = (
            threading.Event(), threading.Event(), threading.Event(), threading.Event())
        original_condition = store._lifetime

        class ObservedCondition:
            def __init__(self, wrapped): self.wrapped = wrapped
            def __enter__(self): self.wrapped.__enter__(); return self
            def __exit__(self, *args): return self.wrapped.__exit__(*args)
            def wait(self, timeout=None):
                entered.set()
                return self.wrapped.wait(timeout)
            def notify_all(self): return self.wrapped.notify_all()

        store._lifetime = ObservedCondition(original_condition)

        def close_store():
            close_started.set()
            store.close()
            close_done.set()

        with store.begin_start(("host",), cancel_event=threading.Event()):
            closer = threading.Thread(target=close_store)
            closer.start()
            self.assertTrue(close_started.wait(5))
            self.assertTrue(entered.wait(5), "close did not wait on the active operation")
            self.assertFalse(close_done.is_set())
            self.assertTrue(os.path.isdir(f"/proc/self/fd/{store._fd}")
                            if Path("/proc/self/fd").exists()
                            else os.path.isdir(self.root))
        closer.join(5)
        self.assertFalse(closer.is_alive())
        self.assertTrue(close_done.is_set())
        with mock.patch.object(consent_module.os, "open", side_effect=AssertionError("I/O after close")) as opened:
            with self.assertRaises(StorageError):
                store.snapshot()
            opened.assert_not_called()
        store.close()

    def test_reentrant_snapshot_inside_start_context_is_refused(self):
        with self.store() as store:
            store.set_role_enabled("host", True)
            with store.begin_start(("host",), cancel_event=threading.Event()):
                with self.assertRaises(StorageError):
                    store.snapshot()

    def test_ambiguous_root_close_is_consumed_once_and_does_not_close_reused_fd(self):
        store = self.store()
        root_fd = store._fd
        real_close = os.close

        def close_then_report(fd):
            real_close(fd)
            if fd == root_fd:
                raise OSError("injected ambiguous close")

        with mock.patch.object(consent_module.os, "close", side_effect=close_then_report) as close_mock:
            with self.assertRaises(OSError):
                store.close()
            self.assertEqual(store._fd, -1)
            replacement = os.open(os.devnull, os.O_RDONLY)
            store.close()
            os.fstat(replacement)
            close_mock.assert_called_once_with(root_fd)
            real_close(replacement)

    def test_cancel_event_is_independent_while_role_change_waits_for_start_context(self):
        with self.store() as store:
            store.set_role_enabled("host", True)
            cancel = threading.Event()
            entered, waiting, done = threading.Event(), threading.Event(), threading.Event()

            class ObservedCondition:
                def __init__(self, wrapped): self.wrapped = wrapped
                def __enter__(self): self.wrapped.__enter__(); return self
                def __exit__(self, *args): return self.wrapped.__exit__(*args)
                def wait(self, timeout=None):
                    waiting.set()
                    return self.wrapped.wait(timeout)
                def notify_all(self): return self.wrapped.notify_all()

            store._lifetime = ObservedCondition(store._lifetime)

            def disable():
                entered.set()
                store.set_role_enabled("host", False)
                done.set()

            with store.begin_start(("host",), cancel_event=cancel):
                worker = threading.Thread(target=disable)
                worker.start()
                self.assertTrue(entered.wait(5))
                self.assertTrue(waiting.wait(5), "disable did not block on owner serialization")
                cancel.set()
                self.assertTrue(cancel.is_set())
                self.assertFalse(done.is_set())
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertTrue(done.is_set())
            self.assertEqual(store.snapshot().enabled_roles, ())
            self.assertEqual(store.snapshot().epoch, 3)

    def test_cross_process_lock_serializes_role_change_with_start_context(self):
        with self.store() as store:
            store.set_role_enabled("host", True)
            ctx = multiprocessing.get_context("fork")
            contended, acquired, release, finished = (ctx.Event(), ctx.Event(),
                                                       ctx.Event(), ctx.Event())
            with store.begin_start(("host",), cancel_event=threading.Event()):
                child = ctx.Process(target=_cross_process_disable,
                    args=(str(self.root), contended, acquired, release, finished))
                child.start()
                self.assertTrue(contended.wait(5), "child nonblocking flock did not prove contention")
                self.assertFalse(acquired.is_set(), "child crossed held owner serialization")
                self.assertFalse(finished.is_set())
                release.set()
            self.assertTrue(acquired.wait(5))
            self.assertTrue(finished.wait(5))
            child.join(5)
            self.assertEqual(child.exitcode, 0)
            self.assertEqual(store.snapshot().enabled_roles, ())

    def test_partial_state_write_latches_instance_and_reopen_rejects_debris(self):
        def fail(step):
            if step == "state.file.fsync":
                raise OSError("injected fsync failure")

        store = self.store(_fault_hook=fail)
        with self.assertRaises(StorageError):
            store.set_role_enabled("host", True)
        with self.assertRaises(StorageError):
            store.snapshot()
        store.close()
        with self.assertRaises(StorageError):
            self.store()

    def test_post_replace_root_fsync_failure_fences_reopen_and_already_open_store(self):
        second = self.store()

        def fail(step):
            if step == "state.replace.root.fsync":
                raise OSError("injected post-replace root fsync failure")

        first = self.store(_fault_hook=fail)
        with self.assertRaises(StorageError):
            first.set_role_enabled("host", True)
        with self.assertRaises(StorageError):
            first.snapshot()
        with self.assertRaises(StorageError):
            second.snapshot()
        first.close()
        second.close()
        with self.assertRaises(StorageError):
            self.store()

    def test_final_marker_fsync_failure_never_yields_and_reopen_sees_durable_inert_snapshot(self):
        armed = False

        def fail(step):
            if armed and step == "state.commit.root.fsync":
                raise OSError("injected final marker cleanup fsync failure")

        store = self.store(_fault_hook=fail)
        store.set_role_enabled("host", True)
        armed = True
        yielded = []
        with self.assertRaises(StorageError):
            with store.begin_start(("host",), cancel_event=threading.Event()) as snapshot:
                yielded.append(snapshot)
        self.assertEqual(yielded, [])
        with self.assertRaises(StorageError):
            store.snapshot()
        store.close()
        with self.store() as reopened:
            snapshot = reopened.snapshot()
            self.assertEqual(snapshot.epoch, 2)
            self.assertEqual(snapshot.enabled_roles, ("host",))

    def test_already_open_store_rejects_unexpected_temporary_namespace_entry(self):
        first, second = self.store(), self.store()
        debris = self.root / ".owner-consent-tmp-unexpected"
        debris.write_bytes(b"partial")
        os.chmod(debris, 0o600)
        try:
            for store in (first, second):
                with self.assertRaises(StorageError):
                    store.snapshot()
        finally:
            debris.unlink()
            first.close()
            second.close()

    def test_fifo_replacement_after_stat_is_rejected_without_blocking(self):
        fifo = self.root / consent_module.STATE_NAME
        ctx = multiprocessing.get_context("fork")
        result = ctx.Queue()
        child = ctx.Process(target=_open_store_fifo_race, args=(str(self.root), result))
        try:
            child.start()
            child.join(5)
            if child.is_alive():
                child.terminate()
                child.join(5)
                self.fail("constructor blocked opening substituted FIFO")
            self.assertEqual(child.exitcode, 0)
            self.assertTrue(result.get(timeout=2).startswith("StorageError:"))
        finally:
            if child.is_alive():
                child.terminate()
                child.join(5)
            if os.path.lexists(fifo):
                fifo.unlink()
            saved = self.root / "owner-consent.saved"
            if saved.exists():
                os.replace(saved, fifo)


if __name__ == "__main__":
    unittest.main()
