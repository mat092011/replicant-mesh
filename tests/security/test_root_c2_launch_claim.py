"""C2 append-only whole-cohort claim parser and native store tests."""
from __future__ import annotations

import hashlib
import json
import os
import multiprocessing
import threading
import tempfile
import stat
import unittest
from dataclasses import replace
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0, str(ROOT / "src"))

import tests.security.test_root_c2_selected as selected_fixture
from steamboat_security.codec import canonical_json
from steamboat_security.errors import BindingError, StorageError
from steamboat_security.root_c2_launch_claim import (
    C2LaunchClaimRecord, C2LaunchClaimStore,
    c2_launch_claim_document, parse_c2_launch_claim,
)
import steamboat_security.root_c2_launch_claim as c2_claim_module
from steamboat_security.root_transition_launch import role_launch_document


def _sha(data): return hashlib.sha256(data).hexdigest()


def _claim_process(root, uid, record_args, expected_doc, gate, output):
    try:
        if not gate.wait(10):
            output.put("timeout"); return
        with C2LaunchClaimStore(root, expected_uid=uid) as store:
            def trusted(record):
                return None if c2_launch_claim_document(record) == expected_doc else False
            store.claim(**record_args, fresh_selected_validator=trusted)
        output.put("claimed")
    except BindingError:
        output.put("rejected")
    except BaseException as error:
        output.put("error:" + type(error).__name__)


def _ready_then_claim_process(root, uid, record_args, expected_doc, ready, gate, output):
    try:
        with C2LaunchClaimStore(root, expected_uid=uid) as store:
            ready.put("ready")
            if not gate.wait(10):
                output.put("timeout"); return
            def trusted(record):
                return None if c2_launch_claim_document(record) == expected_doc else False
            store.claim(**record_args, fresh_selected_validator=trusted)
        output.put("claimed")
    except BindingError:
        output.put("rejected")
    except BaseException as error:
        output.put("error:" + type(error).__name__)


class C2ClaimFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected_fixture.C2SelectedCohortTests.setUpClass()

    def setUp(self):
        self.fx_case = object.__new__(selected_fixture.C2SelectedCohortTests)
        self.fx_case.setUp()
        selector, bundle, active, _ = self.fx_case._inputs(grant_fault="none")
        from steamboat_security.root_c2_selected import validate_c2_selected_cohort
        self.cohort = validate_c2_selected_cohort(selector, bundle, active,
            clock=self.fx_case.fx.clock_source.clock)
        self.selector, self.bundle, self.active = selector, bundle, active

    def tearDown(self): self.fx_case.tearDown()

    def _trusted_validator(self, record):
        # Test owner compares the whole canonical cohort and every selected pin.
        self.assertEqual(record.selector_sha256, self.cohort.selector_sha256)
        self.assertEqual(record.activation_manifest_sha256, self.cohort.activation_manifest_sha256)
        self.assertEqual(record.generation_sha256, self.cohort.generation_sha256)
        self.assertEqual(tuple(map(role_launch_document, record.new_role_launch_specs)),
                         tuple(map(role_launch_document, self.cohort.new_specs)))
        self.assertEqual(tuple(x.to_document() for x in record.new_host_group_scopes),
                         tuple(x.to_document() for x in self.cohort.new_groups))
        return None

    def test_parser_round_trips_real_selected_parent_and_child_cohort(self):
        body = {"generation_sha256": self.cohort.generation_sha256,
            "new_role_launch_specs": [role_launch_document(x) for x in self.cohort.new_specs],
            "new_host_group_scopes": [x.to_document() for x in self.cohort.new_groups]}
        record = C2LaunchClaimRecord(self.cohort.selector_sha256,
            self.cohort.activation_manifest_sha256, self.cohort.generation_sha256,
            _sha(canonical_json(body)), self.cohort.new_specs, self.cohort.new_groups)
        encoded = canonical_json(c2_launch_claim_document(record))
        self.assertEqual(parse_c2_launch_claim(encoded), record)
        raw = json.loads(encoded)
        raw["new_host_group_scopes"] = []
        with self.assertRaises(StorageError): parse_c2_launch_claim(canonical_json(raw))
        with self.assertRaises(StorageError): parse_c2_launch_claim(encoded + b" ")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "native POSIX store")
    def test_native_store_consumes_all_parent_and_child_boots_once(self):
        root = Path(self.fx_case.temp.name) / "claims"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        with C2LaunchClaimStore(root, expected_uid=os.geteuid()) as store:
            receipt = store.claim(selector_sha256=self.cohort.selector_sha256,
                activation_manifest_sha256=self.cohort.activation_manifest_sha256,
                generation_sha256=self.cohort.generation_sha256,
                new_role_launch_specs=self.cohort.new_specs,
                new_host_group_scopes=self.cohort.new_groups,
                fresh_selected_validator=self._trusted_validator)
            self.assertEqual(parse_c2_launch_claim((root / receipt.filename).read_bytes()), receipt.record)
            with self.assertRaises(BindingError):
                store.claim(selector_sha256=self.cohort.selector_sha256,
                    activation_manifest_sha256=self.cohort.activation_manifest_sha256,
                    generation_sha256=self.cohort.generation_sha256,
                    new_role_launch_specs=self.cohort.new_specs,
                    new_host_group_scopes=self.cohort.new_groups,
                    fresh_selected_validator=self._trusted_validator)
        with C2LaunchClaimStore(root, expected_uid=os.geteuid()) as reopened:
            with self.assertRaises(BindingError):
                reopened.claim(selector_sha256="a" * 64,
                    activation_manifest_sha256="b" * 64,
                    generation_sha256=self.cohort.generation_sha256,
                    new_role_launch_specs=self.cohort.new_specs,
                    new_host_group_scopes=self.cohort.new_groups,
                    fresh_selected_validator=self._trusted_validator)

    @unittest.skipUnless(os.name == "posix", "native POSIX store")
    def test_callback_failure_and_partial_created_file_are_sticky(self):
        root = Path(self.fx_case.temp.name) / "claims-fault"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        args = dict(selector_sha256=self.cohort.selector_sha256,
            activation_manifest_sha256=self.cohort.activation_manifest_sha256,
            generation_sha256=self.cohort.generation_sha256,
            new_role_launch_specs=self.cohort.new_specs,
            new_host_group_scopes=self.cohort.new_groups)
        with C2LaunchClaimStore(root, expected_uid=os.geteuid()) as store:
            with self.assertRaises(RuntimeError):
                store.claim(**args, fresh_selected_validator=lambda _r: (_ for _ in ()).throw(RuntimeError()))
            self.assertEqual(set(os.listdir(root)), {"claim.lock"})
        def fail(label):
            if label == "claim.write": raise OSError("injected partial write")
        with C2LaunchClaimStore(root, expected_uid=os.geteuid(), _fault_hook=fail) as store:
            with self.assertRaises(StorageError): store.claim(**args, fresh_selected_validator=self._trusted_validator)
            with self.assertRaises(StorageError): store.claim(**args, fresh_selected_validator=self._trusted_validator)
        with self.assertRaises(StorageError): C2LaunchClaimStore(root, expected_uid=os.geteuid())

    @unittest.skipUnless(os.name == "posix", "native POSIX store")
    def test_callback_async_and_non_none_do_not_create_a_claim(self):
        root = Path(self.fx_case.temp.name) / "claims-callback-contract"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        args = dict(selector_sha256=self.cohort.selector_sha256,
            activation_manifest_sha256=self.cohort.activation_manifest_sha256,
            generation_sha256=self.cohort.generation_sha256,
            new_role_launch_specs=self.cohort.new_specs,
            new_host_group_scopes=self.cohort.new_groups)
        with C2LaunchClaimStore(root, expected_uid=os.geteuid()) as store:
            with self.assertRaises(TypeError):
                store.claim(**args, fresh_selected_validator=lambda _record: True)
            async def async_validator(_record): return None
            with self.assertRaises(TypeError):
                store.claim(**args, fresh_selected_validator=async_validator)
            self.assertEqual(set(os.listdir(root)), {"claim.lock"})

    @unittest.skipUnless(os.name == "posix", "native POSIX store")
    def test_callback_cannot_reenter_close_or_claim(self):
        root = Path(self.fx_case.temp.name) / "claims-reentrant"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        args = dict(selector_sha256=self.cohort.selector_sha256,
            activation_manifest_sha256=self.cohort.activation_manifest_sha256,
            generation_sha256=self.cohort.generation_sha256,
            new_role_launch_specs=self.cohort.new_specs,
            new_host_group_scopes=self.cohort.new_groups)
        with C2LaunchClaimStore(root, expected_uid=os.geteuid()) as store:
            rejected = []
            def callback(_record):
                for operation in (store.close,
                    lambda: store.claim(**args, fresh_selected_validator=lambda _r: None)):
                    with self.assertRaises(StorageError): operation()
                    rejected.append(True)
                return None
            store.claim(**args, fresh_selected_validator=callback)
            self.assertEqual(len(rejected), 2)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                         "native POSIX descriptor lifetime")
    def test_external_close_waits_through_root_fsync_and_fd_reuse(self):
        root = Path(self.fx_case.temp.name) / "claims-lifetime"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        args = dict(selector_sha256=self.cohort.selector_sha256,
            activation_manifest_sha256=self.cohort.activation_manifest_sha256,
            generation_sha256=self.cohort.generation_sha256,
            new_role_launch_specs=self.cohort.new_specs,
            new_host_group_scopes=self.cohort.new_groups)
        store = C2LaunchClaimStore(root, expected_uid=os.geteuid())
        root_fd = store._fd
        fsync_entered, fsync_release = threading.Event(), threading.Event()
        close_started, close_waiting, close_done = threading.Event(), threading.Event(), threading.Event()
        results, failures, reused = [], [], []
        original_fsync, original_close = os.fsync, os.close

        def blocked_fsync(fd):
            if fd == root_fd and not fsync_entered.is_set():
                fsync_entered.set()
                if not fsync_release.wait(10): raise OSError("root fsync barrier timed out")
            return original_fsync(fd)

        def claim_thread():
            try: results.append(store.claim(**args, fresh_selected_validator=lambda _r: None))
            except BaseException as error: failures.append(error)

        def close_thread():
            close_started.set()
            try:
                store.close()
                reused.append(os.open(os.devnull, os.O_RDONLY))
            except BaseException as error: failures.append(error)
            finally: close_done.set()

        condition = store._lifetime
        class ObservedCondition:
            def __enter__(self): condition.__enter__(); return self
            def __exit__(self, *args): return condition.__exit__(*args)
            def wait(self, timeout=None):
                if threading.current_thread() is closer:
                    close_waiting.set()
                return condition.wait(timeout)
            def notify_all(self): return condition.notify_all()
        store._lifetime = ObservedCondition()

        claimant, closer = threading.Thread(target=claim_thread), threading.Thread(target=close_thread)
        try:
            with mock.patch.object(c2_claim_module.os, "fsync", blocked_fsync):
                claimant.start()
                self.assertTrue(fsync_entered.wait(5))
                closer.start()
                self.assertTrue(close_started.wait(5))
                self.assertTrue(close_waiting.wait(5), "close did not wait for claim ownership")
                self.assertFalse(close_done.wait(0.1), "close invalidated an active root fsync")
                self.assertTrue(stat.S_ISDIR(os.fstat(root_fd).st_mode))
                fsync_release.set()
                claimant.join(5); closer.join(5)
            self.assertFalse(claimant.is_alive())
            self.assertFalse(closer.is_alive())
            self.assertFalse(failures)
            self.assertEqual(len(results), 1)
            self.assertTrue(close_done.is_set())
            self.assertEqual(reused, [root_fd])
            os.fstat(reused[0])
            with self.assertRaises(StorageError): store.claim(**args,
                fresh_selected_validator=lambda _r: None)
        finally:
            fsync_release.set()
            if claimant.is_alive(): claimant.join(5)
            if closer.is_alive(): closer.join(5)
            store.close()
            if reused: original_close(reused[0])

    @unittest.skipUnless(os.name == "posix", "native POSIX store")
    def test_malformed_public_specs_and_duplicate_principal_reject(self):
        root = Path(self.fx_case.temp.name) / "claims-malformed"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        args = dict(selector_sha256=self.cohort.selector_sha256,
            activation_manifest_sha256=self.cohort.activation_manifest_sha256,
            generation_sha256=self.cohort.generation_sha256,
            new_host_group_scopes=self.cohort.new_groups)
        with C2LaunchClaimStore(root, expected_uid=os.geteuid()) as store:
            invalid = replace(self.cohort.new_specs[0], credential_epoch=True)
            bad_specs = tuple(sorted((invalid,) + self.cohort.new_specs[1:], key=lambda x: x.identity))
            with self.assertRaises(BindingError):
                store.claim(**args, new_role_launch_specs=bad_specs,
                    fresh_selected_validator=self._trusted_validator)
            dup = replace(self.cohort.new_specs[0], boot_id="f" * 32)
            duplicate = tuple(sorted((self.cohort.new_specs[0], dup) + self.cohort.new_specs[1:],
                                     key=lambda x: x.identity))
            with self.assertRaises(BindingError):
                store.claim(**args, new_role_launch_specs=duplicate,
                    fresh_selected_validator=self._trusted_validator)
            self.assertEqual(set(os.listdir(root)), {"claim.lock"})

    @unittest.skipUnless(os.name == "posix", "native POSIX store")
    def test_unknown_entries_and_symlinks_fail_closed(self):
        root = Path(self.fx_case.temp.name) / "claims-unsafe"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        with C2LaunchClaimStore(root, expected_uid=os.geteuid()): pass
        (root / "unknown").write_text("x", encoding="ascii"); os.chmod(root / "unknown", 0o600)
        with self.assertRaises(StorageError): C2LaunchClaimStore(root, expected_uid=os.geteuid())

    @unittest.skipUnless(os.name == "posix" and "fork" in multiprocessing.get_all_start_methods(),
                         "requires POSIX fork and no-follow store")
    def test_cross_process_same_cohort_has_one_winner(self):
        root = Path(self.fx_case.temp.name) / "claims-race"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        args = dict(selector_sha256=self.cohort.selector_sha256,
            activation_manifest_sha256=self.cohort.activation_manifest_sha256,
            generation_sha256=self.cohort.generation_sha256,
            new_role_launch_specs=self.cohort.new_specs,
            new_host_group_scopes=self.cohort.new_groups)
        cohort_body = {"generation_sha256": self.cohort.generation_sha256,
            "new_role_launch_specs": [role_launch_document(x) for x in self.cohort.new_specs],
            "new_host_group_scopes": [x.to_document() for x in self.cohort.new_groups]}
        expected_doc = c2_launch_claim_document(C2LaunchClaimRecord(
            self.cohort.selector_sha256, self.cohort.activation_manifest_sha256,
            self.cohort.generation_sha256, _sha(canonical_json(cohort_body)),
            self.cohort.new_specs, self.cohort.new_groups))
        context = multiprocessing.get_context("fork")
        gate, ready, output = context.Event(), context.Queue(), context.Queue()
        children = [context.Process(target=_ready_then_claim_process,
            args=(str(root), os.geteuid(), args, expected_doc, ready, gate, output)) for _ in range(2)]
        results = []
        try:
            for child in children: child.start()
            # Both constructors must have completed before either claim proceeds.
            self.assertEqual([ready.get(timeout=20) for _ in children], ["ready", "ready"])
            gate.set()
            results = [output.get(timeout=20) for _ in children]
            for child in children: child.join(timeout=10)
        finally:
            gate.set()
            for child in children:
                if child.is_alive(): child.terminate()
                child.join(timeout=3)
            output.close(); ready.close()
        self.assertCountEqual(results, ["claimed", "rejected"])
        self.assertTrue(all(child.exitcode == 0 for child in children))

    @unittest.skipUnless(os.name == "posix", "native POSIX store")
    def test_root_mode_symlink_and_hardlink_reject(self):
        root = Path(self.fx_case.temp.name) / "claims-inodes"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        os.chmod(root, 0o755)
        with self.assertRaises(StorageError): C2LaunchClaimStore(root, expected_uid=os.geteuid())
        os.chmod(root, 0o700)
        with C2LaunchClaimStore(root, expected_uid=os.geteuid()) as store:
            receipt = store.claim(selector_sha256=self.cohort.selector_sha256,
                activation_manifest_sha256=self.cohort.activation_manifest_sha256,
                generation_sha256=self.cohort.generation_sha256,
                new_role_launch_specs=self.cohort.new_specs,
                new_host_group_scopes=self.cohort.new_groups,
                fresh_selected_validator=self._trusted_validator)
        claim = root / receipt.filename
        outside = Path(self.fx_case.temp.name) / "claim-link"
        os.link(claim, outside)
        with self.assertRaises(StorageError): C2LaunchClaimStore(root, expected_uid=os.geteuid())
        outside.unlink()
        claim.unlink()
        outside_target = Path(self.fx_case.temp.name) / "target"
        outside_target.write_bytes(b"{}"); os.chmod(outside_target, 0o600)
        (root / receipt.filename).symlink_to(outside_target)
        with self.assertRaises(StorageError): C2LaunchClaimStore(root, expected_uid=os.geteuid())

    @unittest.skipUnless(os.name == "posix", "native POSIX descriptor semantics")
    def test_claim_close_failure_consumes_fd_number_and_latches_before_cleanup(self):
        root = Path(self.fx_case.temp.name) / "claims-close-fault"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        args = dict(selector_sha256=self.cohort.selector_sha256,
            activation_manifest_sha256=self.cohort.activation_manifest_sha256,
            generation_sha256=self.cohort.generation_sha256,
            new_role_launch_specs=self.cohort.new_specs,
            new_host_group_scopes=self.cohort.new_groups)
        store = C2LaunchClaimStore(root, expected_uid=os.geteuid())
        original_close = os.close
        replacement = os.open(os.devnull, os.O_RDONLY)
        armed = {"value": False, "fd": None}

        def hook(label):
            if label == "claim.file.fsync": armed["value"] = True

        store._fault_hook = hook
        def close_then_reuse(fd):
            if armed["value"]:
                armed["value"] = False
                original_close(fd)
                os.dup2(replacement, fd)
                armed["fd"] = fd
                raise OSError("close completed, reporting failure")
            return original_close(fd)

        try:
            with mock.patch.object(c2_claim_module.os, "close", close_then_reuse):
                with self.assertRaises(StorageError):
                    store.claim(**args, fresh_selected_validator=self._trusted_validator)
                self.assertTrue(store._unknown)
                with self.assertRaises(StorageError):
                    store.claim(**args, fresh_selected_validator=self._trusted_validator)
            self.assertIsNotNone(armed["fd"])
            os.fstat(armed["fd"])
        finally:
            store.close()
            if armed["fd"] is not None: original_close(armed["fd"])
            original_close(replacement)

    @unittest.skipUnless(os.name == "posix", "native POSIX descriptor semantics")
    def test_store_close_failure_cannot_close_reused_descriptor_on_retry(self):
        root = Path(self.fx_case.temp.name) / "claims-root-close-fault"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        store = C2LaunchClaimStore(root, expected_uid=os.geteuid())
        original_close = os.close
        replacement = os.open(os.devnull, os.O_RDONLY)
        target = store._fd
        reused = {"value": False}

        def close_then_reuse(fd):
            if fd == target and not reused["value"]:
                reused["value"] = True
                original_close(fd)
                os.dup2(replacement, fd)
                raise OSError("root close completed, reporting failure")
            return original_close(fd)

        try:
            with mock.patch.object(c2_claim_module.os, "close", close_then_reuse):
                with self.assertRaises(OSError): store.close()
                self.assertEqual(store._fd, -1)
                self.assertTrue(store._unknown)
                store.close()
                with self.assertRaises(StorageError):
                    store.claim(selector_sha256="a" * 64,
                        activation_manifest_sha256="b" * 64,
                        generation_sha256=self.cohort.generation_sha256,
                        new_role_launch_specs=self.cohort.new_specs,
                        new_host_group_scopes=self.cohort.new_groups,
                        fresh_selected_validator=self._trusted_validator)
            os.fstat(target)
        finally:
            if store._fd >= 0: store.close()
            original_close(target)
            original_close(replacement)

    @unittest.skipUnless(os.name == "posix", "native POSIX descriptor semantics")
    def test_lock_close_failure_latches_after_claim_without_reclosing_reused_fd(self):
        root = Path(self.fx_case.temp.name) / "claims-lock-close-fault"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        args = dict(selector_sha256=self.cohort.selector_sha256,
            activation_manifest_sha256=self.cohort.activation_manifest_sha256,
            generation_sha256=self.cohort.generation_sha256,
            new_role_launch_specs=self.cohort.new_specs,
            new_host_group_scopes=self.cohort.new_groups)
        store = C2LaunchClaimStore(root, expected_uid=os.geteuid())
        original_close = os.close
        replacement = os.open(os.devnull, os.O_RDONLY)
        armed = {"value": False, "fd": None}

        def hook(label):
            if label == "claim.root.fsync": armed["value"] = True

        store._fault_hook = hook
        def close_then_reuse(fd):
            if armed["value"]:
                armed["value"] = False
                original_close(fd)
                os.dup2(replacement, fd)
                armed["fd"] = fd
                raise OSError("lock close completed, reporting failure")
            return original_close(fd)

        try:
            with mock.patch.object(c2_claim_module.os, "close", close_then_reuse):
                with self.assertRaises(OSError):
                    store.claim(**args, fresh_selected_validator=self._trusted_validator)
                self.assertTrue(store._unknown)
                with self.assertRaises(StorageError):
                    store.claim(**args, fresh_selected_validator=self._trusted_validator)
            self.assertIsNotNone(armed["fd"])
            os.fstat(armed["fd"])
        finally:
            store.close()
            if armed["fd"] is not None: original_close(armed["fd"])
            original_close(replacement)

    @unittest.skipUnless(os.name == "posix", "native POSIX store")
    def test_file_fsync_fault_is_sticky_and_preserves_consumed_boots(self):
        root = Path(self.fx_case.temp.name) / "claims-file-fsync-fault"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        args = dict(selector_sha256=self.cohort.selector_sha256,
            activation_manifest_sha256=self.cohort.activation_manifest_sha256,
            generation_sha256=self.cohort.generation_sha256,
            new_role_launch_specs=self.cohort.new_specs,
            new_host_group_scopes=self.cohort.new_groups)
        def fail(label):
            if label == "claim.file.fsync": raise OSError("injected file fsync failure")
        with C2LaunchClaimStore(root, expected_uid=os.geteuid(), _fault_hook=fail) as store:
            with self.assertRaises(StorageError): store.claim(**args,
                fresh_selected_validator=self._trusted_validator)
            with self.assertRaises(StorageError): store.claim(**args,
                fresh_selected_validator=self._trusted_validator)
        with C2LaunchClaimStore(root, expected_uid=os.geteuid()) as reopened:
            with self.assertRaises(BindingError): reopened.claim(**args,
                fresh_selected_validator=self._trusted_validator)

    @unittest.skipUnless(os.name == "posix", "native POSIX store")
    def test_historical_child_boot_cannot_move_to_a_new_generation_or_parent(self):
        root = Path(self.fx_case.temp.name) / "claims-child-history"
        root.mkdir(mode=0o700); os.chmod(root, 0o700)
        with C2LaunchClaimStore(root, expected_uid=os.geteuid()) as store:
            store.claim(selector_sha256=self.cohort.selector_sha256,
                activation_manifest_sha256=self.cohort.activation_manifest_sha256,
                generation_sha256=self.cohort.generation_sha256,
                new_role_launch_specs=self.cohort.new_specs,
                new_host_group_scopes=self.cohort.new_groups,
                fresh_selected_validator=self._trusted_validator)
        new_generation = _sha(b"later generation")
        new_specs = tuple(replace(spec, generation_sha256=new_generation,
            credential_epoch=spec.credential_epoch + 1,
            admission_epoch=spec.admission_epoch + 1,
            boot_id=f"{int(spec.boot_id, 16) + 0x1000:032x}",
            launch_nonce=f"{int(spec.launch_nonce, 16) + 1:032x}")
            for spec in self.cohort.new_specs)
        new_specs = tuple(sorted(new_specs, key=lambda x: x.identity))
        host_spec = next(x for x in new_specs if x.role == "host")
        old_group = self.cohort.new_groups[0]
        components = tuple(replace(component,
            worker_boot_id=(old_group.components[0].worker_boot_id if index == 0
                else f"{0xD0000000000000000000000000000000 + index:032x}"))
            for index, component in enumerate(old_group.components))
        credential = replace(old_group.credential,
            credential_epoch=host_spec.credential_epoch,
            serial=host_spec.serial, certificate_sha256=host_spec.certificate_sha256,
            public_key_sha256=host_spec.public_key_sha256)
        new_group = replace(old_group, credential=credential,
            generation_sha256=new_generation, admission_epoch=host_spec.admission_epoch,
            parent_boot_id=host_spec.boot_id, components=components)
        with C2LaunchClaimStore(root, expected_uid=os.geteuid()) as store:
            with self.assertRaises(BindingError):
                store.claim(selector_sha256="a" * 64,
                    activation_manifest_sha256="b" * 64,
                    generation_sha256=new_generation,
                    new_role_launch_specs=new_specs,
                    new_host_group_scopes=(new_group,),
                    fresh_selected_validator=lambda _record: None)


if __name__ == "__main__": unittest.main()
