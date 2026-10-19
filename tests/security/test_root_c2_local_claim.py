"""Portable parser and native POSIX durability tests for device-local C2 claims."""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import sys
import stat
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import tests.security.test_root_c2_selected as selected_fixture
import steamboat_security.root_c2_local_claim as claim_module
import steamboat_security.root_c2_local_plan as plan_module
from steamboat_security.codec import canonical_json
from steamboat_security.errors import BindingError, StorageError
from steamboat_security.root_c2_local_claim import (C2LocalClaimStore,
    c2_local_claim_document, parse_c2_local_claim)
from steamboat_security.root_c2_local_plan import (c2_local_plan_document,
    derive_c2_local_plan)


def _claim_process(root, plan_bytes, account, device, ready, gate, output):
    try:
        store = C2LocalClaimStore(root, expected_uid=os.geteuid(),
            account_id=account, device_id=device)
        ready.put("ready")
        gate.wait(20)
        store.claim(plan_bytes, fresh_selected_validator=lambda _record: None)
        output.put("claimed")
        store.close()
    except BindingError:
        output.put("rejected")
    except BaseException as error:
        output.put(f"error:{type(error).__name__}:{error}")


class C2LocalClaimTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected_fixture.policy_fixture.RootTransitionPolicyTests.setUpClass()

    def setUp(self):
        self.fx = object.__new__(selected_fixture.C2SelectedCohortTests)
        self.fx.setUp()
        self.selector, self.bundle, self.active, _ = self.fx._inputs(grant_fault="none")
        cohort = selected_fixture.validate_c2_selected_cohort(
            self.selector, self.bundle, self.active, clock=self.fx.fx.clock_source.clock)
        self.host = next(x for x in cohort.new_specs if x.role == "host")
        self.account, self.device = self.host.account_id, self.host.device_id
        self.clock = self.fx.fx.clock_source.clock
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()
        self.fx.tearDown()

    def plan(self, epoch=1, *, enabled=("host",)):
        return derive_c2_local_plan(self.selector, self.bundle, self.active,
            clock=self.clock, account_id=self.account, device_id=self.device,
            enable_epoch=epoch, enabled_roles=enabled)

    def root(self, name="claims"):
        path = Path(self.temp.name) / name
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
        return path

    def claim(self, store, plan):
        return store.claim(plan, fresh_selected_validator=lambda _record: None)

    def changed_plan(self, plan, *, epoch, offset, reuse_child=False, admission_increment=1):
        old = plan.enabled_specs[0]
        spec = replace(old, boot_id=f"{int(old.boot_id, 16) + offset:032x}",
                       admission_epoch=old.admission_epoch + admission_increment)
        old_group = plan.enabled_host_groups[0]
        components = tuple(replace(c, worker_boot_id=(
            old_group.components[0].worker_boot_id if reuse_child and i == 0 else
            f"{int(c.worker_boot_id, 16) + offset:032x}"))
            for i, c in enumerate(old_group.components))
        group = replace(old_group, parent_boot_id=spec.boot_id,
                        admission_epoch=spec.admission_epoch, components=components)
        changed = replace(plan, enable_epoch=epoch, complete_local_specs=(spec,),
            enabled_specs=(spec,), enabled_host_groups=(group,), localplan_sha256="0" * 64)
        digest = hashlib.sha256(canonical_json(plan_module._plan_doc(
            changed, include_digest=False))).hexdigest()
        return replace(changed, localplan_sha256=digest)

    def test_local_projection_excludes_remote_and_disabled_roles_and_binds_plan(self):
        plan = self.plan()
        self.assertEqual(tuple(s.role for s in plan.enabled_specs), ("host",))
        self.assertFalse(any(s.identity != self.host.identity for s in plan.enabled_specs))
        self.assertEqual(tuple(s.role for s in plan.disabled_specs), ())
        doc = c2_local_claim_document(claim_module._make_record(plan))
        rec = parse_c2_local_claim(canonical_json(doc))
        expected = tuple(sorted((self.host.boot_id,) + tuple(
            c.worker_boot_id for g in plan.enabled_host_groups for c in g.components)))
        self.assertEqual(rec.enabled_boot_ids, expected)

    def test_empty_projection_reject(self):
        paused = self.plan(enabled=())
        with self.assertRaises(BindingError): claim_module._make_record(paused)
        moved = self.changed_plan(self.plan(), epoch=2, offset=100)
        self.assertEqual(claim_module._plan(moved).enable_epoch, 2)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid"), "native POSIX store")
    def test_remote_store_principal_reject(self):
        with self.assertRaises(BindingError):
            C2LocalClaimStore(self.root(), expected_uid=os.geteuid(),
                account_id=self.account, device_id="dev_" + "9" * 32).claim(
                    self.plan(), fresh_selected_validator=lambda _r: None)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid"), "native POSIX store")
    def test_invalid_pinned_identity_is_rejected_before_filesystem_access(self):
        with mock.patch.object(claim_module, "_open_directory_chain") as open_root:
            with self.assertRaises(BindingError):
                C2LocalClaimStore(self.root(), expected_uid=os.geteuid(),
                    account_id="not-an-account", device_id=self.device)
            open_root.assert_not_called()

    def test_parser_rechecks_recomputed_digest_and_closed_schema(self):
        doc = c2_local_claim_document(claim_module._make_record(self.plan()))
        raw = json.loads(canonical_json(doc))
        raw["plan"]["disabled_specs"] = list(raw["plan"]["enabled_specs"])
        raw["plan"].pop("localplan_sha256")
        raw["plan"]["localplan_sha256"] = hashlib.sha256(canonical_json(raw["plan"])).hexdigest()
        raw.pop("claim_sha256")
        raw["claim_sha256"] = hashlib.sha256(canonical_json(raw)).hexdigest()
        with self.assertRaises(StorageError): parse_c2_local_claim(canonical_json(raw))
        raw = json.loads(canonical_json(doc)); raw["unexpected"] = 1
        with self.assertRaises(StorageError): parse_c2_local_claim(canonical_json(raw))

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "native POSIX store")
    def test_single_use_enable_and_admission_epochs_and_historical_boots(self):
        root = self.root()
        with C2LocalClaimStore(root, expected_uid=os.geteuid(), account_id=self.account,
                               device_id=self.device) as store:
            initial = self.plan(1)
            self.claim(store, initial)
            with self.assertRaises(BindingError): self.claim(store, initial)
            with self.assertRaises(BindingError):
                self.claim(store, self.changed_plan(initial, epoch=2, offset=10, reuse_child=True))
            with self.assertRaises(BindingError):
                self.claim(store, self.changed_plan(initial, epoch=1, offset=20))
            with self.assertRaises(BindingError):
                self.claim(store, self.changed_plan(initial, epoch=2, offset=25,
                                                     admission_increment=0))
            self.claim(store, self.changed_plan(initial, epoch=2, offset=30))
            with self.assertRaises(BindingError):
                self.claim(store, self.changed_plan(initial, epoch=2, offset=40))

    @unittest.skipUnless(os.name == "posix" and "fork" in multiprocessing.get_all_start_methods(),
                         "requires POSIX fork and no-follow store")
    def test_two_processes_ready_barrier_has_one_winner(self):
        root = self.root("race")
        plan = self.plan()
        ctx = multiprocessing.get_context("fork")
        ready, gate, output = ctx.Queue(), ctx.Event(), ctx.Queue()
        children = [ctx.Process(target=_claim_process, args=(str(root),
            canonical_json(c2_local_plan_document(plan)), self.account, self.device,
            ready, gate, output)) for _ in range(2)]
        try:
            for child in children: child.start()
            self.assertEqual([ready.get(timeout=20) for _ in children], ["ready", "ready"])
            gate.set()
            result = [output.get(timeout=20) for _ in children]
            for child in children: child.join(timeout=10)
        finally:
            gate.set()
            for child in children:
                if child.is_alive(): child.terminate()
                child.join(timeout=3)
            ready.close(); output.close()
        self.assertCountEqual(result, ["claimed", "rejected"])
        self.assertTrue(all(child.exitcode == 0 for child in children))

    @unittest.skipUnless(os.name == "posix", "native POSIX store")
    def test_async_validator_and_write_fault_create_no_retry_capability(self):
        root = self.root("callback")
        with C2LocalClaimStore(root, expected_uid=os.geteuid(), account_id=self.account,
                               device_id=self.device) as store:
            async def async_check(_record): return None
            with self.assertRaises(TypeError): store.claim(self.plan(), fresh_selected_validator=async_check)
            self.assertEqual(set(os.listdir(root)), {"claim.lock"})
        def fail(label):
            if label == "claim.write": raise OSError("injected write fault")
        with C2LocalClaimStore(root, expected_uid=os.geteuid(), account_id=self.account,
                               device_id=self.device, _fault_hook=fail) as store:
            with self.assertRaises(StorageError): self.claim(store, self.plan())
            with self.assertRaises(StorageError): self.claim(store, self.plan())
            self.assertTrue(store._unknown)
        with self.assertRaises(StorageError):
            C2LocalClaimStore(root, expected_uid=os.geteuid(), account_id=self.account,
                              device_id=self.device)

    @unittest.skipUnless(os.name == "posix", "native POSIX store")
    def test_fsync_and_ambiguous_close_latch_the_store(self):
        root = self.root("fsync")
        def fail(label):
            if label == "claim.file.fsync": raise OSError("injected fsync fault")
        with C2LocalClaimStore(root, expected_uid=os.geteuid(), account_id=self.account,
                               device_id=self.device, _fault_hook=fail) as store:
            with self.assertRaises(StorageError): self.claim(store, self.plan())
            self.assertTrue(store._unknown)
        with C2LocalClaimStore(root, expected_uid=os.geteuid(), account_id=self.account,
                               device_id=self.device) as reopened:
            with self.assertRaises(BindingError): self.claim(reopened, self.plan())

        root = self.root("close")
        store = C2LocalClaimStore(root, expected_uid=os.geteuid(),
            account_id=self.account, device_id=self.device)
        original_close = os.close
        replacement_fd = os.open(os.devnull, os.O_RDONLY)
        armed = {"value": False, "fd": None}
        def hook(label):
            if label == "claim.file.fsync": armed["value"] = True
        store._fault_hook = hook
        def close_then_reuse(fd):
            if armed["value"]:
                armed["value"] = False
                original_close(fd)
                os.dup2(replacement_fd, fd)
                armed["fd"] = fd
                raise OSError("close completed but reported failure")
            return original_close(fd)
        try:
            with mock.patch.object(claim_module.os, "close", close_then_reuse):
                with self.assertRaises(StorageError): self.claim(store, self.plan())
                with self.assertRaises(StorageError): self.claim(store, self.plan())
            os.fstat(armed["fd"])
        finally:
            store.close()
            if armed["fd"] is not None: original_close(armed["fd"])
            original_close(replacement_fd)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "native POSIX store")
    def test_close_waits_for_root_fsync_and_prevents_fd_reuse_during_claim(self):
        root = self.root("lifetime")
        store = C2LocalClaimStore(root, expected_uid=os.geteuid(),
            account_id=self.account, device_id=self.device)
        root_fd = store._fd
        fsync_entered, fsync_release = threading.Event(), threading.Event()
        close_started, close_done = threading.Event(), threading.Event()
        result, failure, reused_fd = [], [], []
        original_fsync = os.fsync
        original_close = os.close

        def blocked_fsync(fd):
            if fd == root_fd and not fsync_entered.is_set():
                fsync_entered.set()
                if not fsync_release.wait(10): raise OSError("test fsync barrier timed out")
            return original_fsync(fd)

        def do_claim():
            try: result.append(self.claim(store, self.plan()))
            except BaseException as error: failure.append(error)

        def do_close_and_reuse():
            close_started.set()
            store.close()
            reused_fd.append(os.open(os.devnull, os.O_RDONLY))
            close_done.set()

        claimant = threading.Thread(target=do_claim)
        closer = threading.Thread(target=do_close_and_reuse)
        try:
            with mock.patch.object(claim_module.os, "fsync", blocked_fsync):
                claimant.start()
                self.assertTrue(fsync_entered.wait(5))
                closer.start()
                self.assertTrue(close_started.wait(5))
                self.assertFalse(close_done.wait(0.1), "close raced an active root fsync")
                self.assertTrue(stat.S_ISDIR(os.fstat(root_fd).st_mode))
                fsync_release.set()
                claimant.join(5); closer.join(5)
            self.assertFalse(claimant.is_alive())
            self.assertFalse(closer.is_alive())
            self.assertFalse(failure)
            self.assertEqual(len(result), 1)
            self.assertTrue(close_done.is_set())
            self.assertEqual(reused_fd, [root_fd])
            os.fstat(reused_fd[0])
            with self.assertRaises(StorageError): self.claim(store, self.plan())
        finally:
            fsync_release.set()
            if claimant.is_alive(): claimant.join(5)
            if closer.is_alive(): closer.join(5)
            store.close()
            if reused_fd: original_close(reused_fd[0])

    @unittest.skipUnless(os.name == "posix", "native POSIX store")
    def test_callback_cannot_reenter_close_or_claim(self):
        root = self.root("reentrant")
        with C2LocalClaimStore(root, expected_uid=os.geteuid(), account_id=self.account,
                               device_id=self.device) as store:
            rejections = []
            def callback(_record):
                for operation in (store.close,
                    lambda: store.claim(self.plan(), fresh_selected_validator=lambda _r: None)):
                    with self.assertRaises(StorageError): operation()
                    rejections.append(True)
                return None
            store.claim(self.plan(), fresh_selected_validator=callback)
            self.assertEqual(len(rejections), 2)

    @unittest.skipUnless(os.name == "posix", "native POSIX store")
    def test_entry_count_is_bounded_during_scandir(self):
        root = self.root("entries")
        with C2LocalClaimStore(root, expected_uid=os.geteuid(), account_id=self.account,
                               device_id=self.device): pass
        for i in range(18):
            (root / f"noise-{i}").write_text("x", encoding="ascii")
        with self.assertRaises(StorageError):
            C2LocalClaimStore(root, expected_uid=os.geteuid(), account_id=self.account,
                              device_id=self.device)


if __name__ == "__main__": unittest.main()
