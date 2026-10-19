"""Portable fail-closed contract tests for the C2 local startup adapter."""
from __future__ import annotations

import sys
import threading
import unittest
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_connector.c2_local_startup import C2LocalStartup, C2LocalStartupError
from steamboat_connector.owner_consent import OwnerConsentSnapshot
from steamboat_connector.owner_consent import OwnerConsentStore, provision_owner_consent
from steamboat_security.root_c2_local_claim import C2LocalClaimStore
from steamboat_security.errors import BindingError
from steamboat_connector.process_supervisor import ProcessRoleBackend
from steamboat_connector.c2_local_startup import C2LocalLaunchReference, closed_role_config


class _NeverOwner:
    def __init__(self):
        self.calls = 0

    def snapshot(self):
        self.calls += 1
        raise AssertionError("owner state must not be consulted for an invalid request")


class C2LocalStartupContractTests(unittest.TestCase):
    def adapter(self):
        value = object.__new__(C2LocalStartup)
        value._active = threading.Lock()
        value._owner = _NeverOwner()
        value._references = {}
        value._policies = {}
        return value

    def test_consumer_refused_before_owner_epoch_or_claim(self):
        adapter = self.adapter()
        with self.assertRaises(ValueError):
            adapter.start(("consumer",), cancel_event=threading.Event())
        self.assertEqual(adapter._owner.calls, 0)

    def test_remote_or_global_roles_refused_before_owner_snapshot(self):
        adapter = self.adapter()
        for roles in (("remote",), ("host", "remote"), ("global",)):
            with self.subTest(roles=roles), self.assertRaises(ValueError):
                adapter.start(roles, cancel_event=threading.Event())
        self.assertEqual(adapter._owner.calls, 0)

    def test_roles_must_be_exact_sorted_unique_tuple(self):
        adapter = self.adapter()
        for roles in ([], ("host", "host"), ("host", "coordinator"), ()):
            with self.subTest(roles=roles), self.assertRaises(ValueError):
                adapter.start(roles, cancel_event=threading.Event())
        self.assertEqual(adapter._owner.calls, 0)

    def test_only_one_start_operation_can_be_active(self):
        adapter = self.adapter()
        adapter._active.acquire()
        with self.assertRaises(C2LocalStartupError):
            adapter.start(("host",), cancel_event=threading.Event())
        adapter._active.release()
        self.assertEqual(adapter._owner.calls, 0)

    def test_owner_role_names_are_mapped_to_selected_c2_roles(self):
        snapshot = OwnerConsentSnapshot("acct_" + "1" * 32,
            "dev_" + "2" * 32, 4, ("coordinator", "host"))
        self.assertEqual(C2LocalStartup._selected_owner_roles(snapshot),
                         ("host", "personal_coordinator"))
        consumer = OwnerConsentSnapshot(snapshot.account_id, snapshot.device_id,
            5, ("consumer", "host"))
        with self.assertRaises(C2LocalStartupError):
            C2LocalStartup._selected_owner_roles(consumer)


_ARTIFACTS = Path(os.environ.get("STEAMBOAT_C2_STARTUP_ARTIFACTS", "/artifacts"))
_NATIVE_FIXTURE = os.name == "posix" and hasattr(os, "geteuid") and _ARTIFACTS.is_dir()


@unittest.skipUnless(_NATIVE_FIXTURE,
    "requires Linux POSIX and the approved offline /artifacts model fixture")
class C2LocalStartupNativeTests(unittest.TestCase):
    """Real stores/pin with FakePopen/FakeCG; software lifecycle evidence only."""

    @contextmanager
    def resources(self, scratch, *, claim_fault=None):
        from tests.connector.c2_startup_fixture import c2_startup_fixture
        from tests.connector.test_process_supervisor import FakeCgroup, sample_policy
        from steamboat_connector.c2_local_startup import C2LocalStartup

        with c2_startup_fixture(_ARTIFACTS, scratch) as fx:
            spec = fx.selected_host
            owner_root = Path(scratch) / "owner"
            claim_root = Path(scratch) / "claims"
            state_root = Path(scratch) / "backend"
            cgroup_root = Path(scratch) / "cgroups"
            for path in (owner_root, claim_root, state_root, cgroup_root):
                path.mkdir(mode=0o700)
                os.chmod(path, 0o700)
            provision_owner_consent(owner_root, expected_uid=os.geteuid(),
                account_id=spec.account_id, device_id=spec.device_id)
            owner = OwnerConsentStore(owner_root, expected_uid=os.geteuid(),
                account_id=spec.account_id, device_id=spec.device_id)
            owner.set_role_enabled("host", True)
            claims = C2LocalClaimStore(claim_root, expected_uid=os.geteuid(),
                account_id=spec.account_id, device_id=spec.device_id,
                _fault_hook=claim_fault)
            cgroup = FakeCgroup(cgroup_root)
            backend = ProcessRoleBackend(state_root, cgroup)
            reference = C2LocalLaunchReference(spec, str(fx.selected_header_path),
                str(fx.protected_root), fx.operator_verification_key_pem)
            selected_root = os.path.realpath(f"/proc/self/fd/{fx.root_store._root_fd}")
            config = closed_role_config(reference, selected_root=selected_root, role="host")
            if not backend.configure_pinned_role("host", config, fx.pin,
                    catalog_verifier=fx.verifier):
                raise AssertionError("fixture's real host artifact pin did not configure")
            startup = C2LocalStartup(root_store=fx.root_store, owner_store=owner,
                claim_store=claims, backend=backend, clock=fx.clock,
                expected_uid=os.geteuid(), account_id=spec.account_id,
                device_id=spec.device_id, references={"host": reference},
                policies={"host": sample_policy()})
            try:
                yield fx, owner, claims, backend, cgroup, startup
            finally:
                owner.close()
                claims.close()

    @staticmethod
    def _locked(path):
        import fcntl
        fd = os.open(path, os.O_RDWR)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            fcntl.flock(fd, fcntl.LOCK_UN)
            return True
        finally:
            os.close(fd)

    def _start_with_fakes(self, fx, owner, claims, backend, cgroup, startup, *, retry=False):
        from tests.connector.test_process_supervisor import FakeProcess
        import steamboat_connector.process_supervisor as supervisor

        selected_root = Path(fx.fixture.root)
        # Obtain names through the already-open directory FDs, not the private path.
        owner_dir = Path(os.readlink(f"/proc/self/fd/{owner._fd}"))
        owner_lock = owner_dir / "owner-consent.lock"
        root_lock = selected_root / "transition.lock"
        real_write = os.write
        processes = {}
        publication_checks = []
        ready_checks = []

        def popen(args, **kwargs):
            publication_checks.append((len(list(claims._path.glob("claim-*.json")))
                if hasattr(claims, "_path") else len(list(Path(os.readlink(f"/proc/self/fd/{claims._fd}")).glob("claim-*.json"))),
                self._locked(root_lock), self._locked(owner_lock)))
            process = FakeProcess(args, kwargs, cgroup)
            processes[args[4]] = process
            return process

        def ready(process, timeout, cancelled=None):
            ready_checks.append((self._locked(root_lock), self._locked(owner_lock)))
            return True

        def killpg(pid, sig):
            process = next(p for p in processes.values() if p.pid == pid)
            process.on_signal(sig)

        write = lambda fd, data: len(data) if data == b"R" else real_write(fd, data)
        with mock.patch.object(supervisor.sys, "platform", "linux"), \
                mock.patch.object(supervisor.subprocess, "Popen", side_effect=popen), \
                mock.patch.object(supervisor.ProcessRoleBackend, "_read_ready", side_effect=ready), \
                mock.patch.object(supervisor.os, "write", side_effect=write), \
                mock.patch.object(supervisor.os, "killpg", side_effect=killpg, create=True):
            result = startup.start(("host",), cancel_event=threading.Event())
            retry_error = None
            if retry:
                owner.set_role_enabled("host", False)
                owner.set_role_enabled("host", True)
                try:
                    startup.start(("host",), cancel_event=threading.Event())
                except BindingError as error:
                    retry_error = error
            self.assertEqual(backend.stop(["host"], 2.0), {"host": True})
        return result, publication_checks, ready_checks, retry_error

    def test_real_stores_claim_precedes_popen_both_locks_held_then_released_for_ready(self):
        with tempfile.TemporaryDirectory(prefix="c2-local-startup-") as scratch:
            os.chmod(scratch, 0o700)
            with self.resources(scratch) as resources:
                fx, owner, claims, backend, cgroup, startup = resources
                result, published, ready, retry_error = self._start_with_fakes(*resources, retry=True)
                self.assertEqual(len(published), 1)
                claim_count, root_lock_free, owner_lock_free = published[0]
                self.assertEqual(claim_count, 1)
                self.assertFalse(root_lock_free)
                self.assertFalse(owner_lock_free)
                self.assertEqual(ready, [(True, True)])
                self.assertEqual(result.ready_roles, ("host",))
                self.assertIsInstance(retry_error, BindingError)
                self.assertEqual(len(published), 1)
                self.assertEqual(len(list(Path(os.readlink(
                    f"/proc/self/fd/{claims._fd}")).glob("claim-*.json"))), 1)

    def test_cancel_during_claim_fsync_prevents_any_popen(self):
        entered, release = threading.Event(), threading.Event()
        def fault(step):
            if step == "claim.file.fsync":
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("test claim fsync release timed out")
        with tempfile.TemporaryDirectory(prefix="c2-local-startup-cancel-") as scratch:
            os.chmod(scratch, 0o700)
            with self.resources(scratch, claim_fault=fault) as (fx, owner, claims,
                    backend, cgroup, startup):
                import steamboat_connector.process_supervisor as supervisor
                result = {}
                cancel = threading.Event()
                with mock.patch.object(supervisor.sys, "platform", "linux"), \
                        mock.patch.object(supervisor.subprocess, "Popen") as popen:
                    def run():
                        try:
                            startup.start(("host",), cancel_event=cancel)
                        except BaseException as error:
                            result["error"] = error
                    worker = threading.Thread(target=run)
                    worker.start()
                    self.assertTrue(entered.wait(10))
                    cancel.set()
                    release.set()
                    worker.join(10)
                    self.assertFalse(worker.is_alive())
                    self.assertIsInstance(result.get("error"), C2LocalStartupError)
                    popen.assert_not_called()
                self.assertEqual(len(list(Path(os.readlink(
                    f"/proc/self/fd/{claims._fd}")).glob("claim-*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
