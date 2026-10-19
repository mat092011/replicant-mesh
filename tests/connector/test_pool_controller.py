import json
import multiprocessing
import os
from pathlib import Path
import sys
import tempfile
import unittest

from steamboat_connector.pool_controller import (
    PoolAllocationError, PoolControllerLock, _validate_allocation,
)


HOST_ID = "a" * 64


def _policy(pool_id="pool-main", memory=1024, cpu=1000):
    from steamboat_connector.policy import LIMIT_FIELDS

    limits = {name: 1 for name in LIMIT_FIELDS}
    limits.update(memory_ceiling_bytes=memory, memory_headroom_bytes=1,
                  cpu_quota_millis=cpu, max_sessions=1, max_queued_calls=0)
    return {"version": 1, "pool_id": pool_id, "limits": limits,
            "reservations": {}, "required_telemetry": []}


def _allocation(uid=None):
    uid = (os.getuid() if hasattr(os, "getuid") else 0) if uid is None else uid
    return {"version": 1, "physical_host_id": HOST_ID,
            "pool_kind": "system_ram", "pool_id": "pool-main",
            "memory_ceiling_bytes": 2048, "cpu_quota_millis": 2000,
            "controller_cgroup": "/sys/fs/cgroup/steamboat", "owner_uid": uid}


def _try_lock(directory, uid, result):
    try:
        PoolControllerLock(directory, HOST_ID, uid=uid).acquire(_policy())
    except PoolAllocationError:
        result.put(True)
    else:
        result.put(False)


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux private files/flock")
class PoolControllerLinuxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name) / "operator"
        self.directory.mkdir(mode=0o700)
        os.chmod(self.directory, 0o700)
        self.uid = os.getuid()
        self.path = self.directory / "allocation.json"
        self.write_allocation()

    def tearDown(self):
        self.temp.cleanup()

    def write_allocation(self, value=None, mode=0o600):
        self.path.write_text(json.dumps(_allocation(self.uid) if value is None else value),
                             encoding="utf-8")
        os.chmod(self.path, mode)

    def test_acquire_checks_policy_and_refuses_same_host_second_controller(self):
        first = PoolControllerLock(self.directory, HOST_ID).acquire(_policy())
        try:
            self.assertEqual(first.allocation["pool_id"], "pool-main")
            relabeled = PoolControllerLock(self.directory, HOST_ID)
            with self.assertRaises(PoolAllocationError):
                relabeled.acquire(_policy(pool_id="pool-other"))
        finally:
            first.release()
        with PoolControllerLock(self.directory, HOST_ID).acquire(_policy()):
            pass

    def test_policy_cannot_exceed_explicit_memory_or_cpu_allocation(self):
        for policy in (_policy(memory=2049), _policy(cpu=2001)):
            with self.assertRaises(PoolAllocationError):
                PoolControllerLock(self.directory, HOST_ID).acquire(policy)

    def test_allocation_mutation_fails_closed_without_releasing_lock(self):
        controller = PoolControllerLock(self.directory, HOST_ID).acquire(_policy())
        try:
            self.write_allocation(_allocation(self.uid) | {"memory_ceiling_bytes": 4096})
            with self.assertRaises(PoolAllocationError):
                controller.assert_current(_policy())
            with self.assertRaises(PoolAllocationError):
                PoolControllerLock(self.directory, HOST_ID).acquire(_policy())
        finally:
            controller.release()

    def test_private_file_and_directory_modes_are_required(self):
        self.path.chmod(0o640)
        with self.assertRaises(PoolAllocationError):
            PoolControllerLock(self.directory, HOST_ID).acquire(_policy())
        self.write_allocation()
        self.directory.chmod(0o750)
        with self.assertRaises(PoolAllocationError):
            PoolControllerLock(self.directory, HOST_ID).acquire(_policy())

    def test_symlink_and_hardlink_allocations_are_refused(self):
        original = self.path.with_name("original.json")
        self.path.rename(original)
        self.path.symlink_to(original.name)
        with self.assertRaises(PoolAllocationError):
            PoolControllerLock(self.directory, HOST_ID).acquire(_policy())
        self.path.unlink()
        original.rename(self.path)
        alias = self.directory / "alias.json"
        os.link(self.path, alias)
        with self.assertRaises(PoolAllocationError):
            PoolControllerLock(self.directory, HOST_ID).acquire(_policy())

    def test_bad_json_schema_host_kind_uid_path_and_oversize_fail_closed(self):
        cases = [
            {**_allocation(self.uid), "unexpected": True},
            {**_allocation(self.uid), "physical_host_id": "b" * 64},
            {**_allocation(self.uid), "pool_kind": "accelerator"},
            {**_allocation(self.uid), "owner_uid": self.uid + 1},
            {**_allocation(self.uid), "controller_cgroup": "/sys/fs/cgroup/../escape"},
        ]
        for value in cases:
            with self.subTest(value=value):
                self.write_allocation(value)
                with self.assertRaises(PoolAllocationError):
                    PoolControllerLock(self.directory, HOST_ID).acquire(_policy())
        self.path.write_text(" " * 4097, encoding="ascii")
        os.chmod(self.path, 0o600)
        with self.assertRaises(PoolAllocationError):
            PoolControllerLock(self.directory, HOST_ID).acquire(_policy())

    def test_duplicate_json_keys_and_malformed_limits_are_rejected(self):
        self.path.write_text('{"version":1,"version":1}', encoding="ascii")
        os.chmod(self.path, 0o600)
        with self.assertRaises(PoolAllocationError):
            PoolControllerLock(self.directory, HOST_ID).acquire(_policy())
        with self.assertRaises(PoolAllocationError):
            PoolControllerLock(self.directory, HOST_ID).acquire(_policy(memory=True))

    def test_multiprocess_lock_is_shared_across_runtime_instances(self):
        controller = PoolControllerLock(self.directory, HOST_ID).acquire(_policy())
        context = multiprocessing.get_context("fork")
        results = context.Queue()
        child = context.Process(target=_try_lock, args=(self.directory, self.uid, results))
        try:
            child.start()
            child.join(3)
            self.assertFalse(child.is_alive())
            self.assertEqual(child.exitcode, 0)
            self.assertTrue(results.get(timeout=1))
        finally:
            if child.is_alive():
                child.terminate()
                child.join()
            controller.release()


class PoolControllerValidationTests(unittest.TestCase):
    def test_physical_host_identity_and_cgroup_path_are_strict(self):
        for values in ({"physical_host_id": "not-a-hash"},
                       {"controller_cgroup": "relative/path"},
                       {"controller_cgroup": "/sys/fs/cgroup//bad"}):
            with self.subTest(values=values), self.assertRaises(PoolAllocationError):
                uid = os.getuid() if hasattr(os, "getuid") else 0
                _validate_allocation(_allocation(uid) | values, HOST_ID, uid)


if __name__ == "__main__":
    unittest.main()
