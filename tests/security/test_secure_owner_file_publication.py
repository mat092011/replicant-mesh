"""Unit and POSIX execution checks for fixed owner-file publication."""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import ast

from lab.secure_owner_file_publication import (
    MAX_CONTROL_BYTES,
    MAX_POLICY_BYTES,
    REMOTE_PUBLISH_SCRIPT,
    build_publication_plan,
    canonical_receipt_bytes,
    remote_publish_command,
    validate_publication_receipt,
)


class OwnerPublicationPlanTests(unittest.TestCase):
    def plan(self, selected_kind="policy1", **overrides):
        args = {
            "kind": selected_kind,
            "intent_root": "/srv/job-owner-intents",
            "job_root": "/srv/job",
            "uid": 1000,
            "gid": 1000,
            "sha256": "a" * 64,
            "size": 20,
            "expected_prior_sha256": "b" * 64 if selected_kind in (
                "policy1", "policy2", "command2") else "",
        }
        args.update(overrides)
        return build_publication_plan(**args)

    def test_fixed_kind_mapping_and_prior_digest_rules(self):
        self.assertEqual(self.plan("install_intent").target_name, "install-intent.json")
        self.assertEqual(self.plan("removal_intent").target_name, "removal-intent.json")
        self.assertEqual(self.plan("policy2").target_name, "snapshot.json")
        self.assertEqual(self.plan("command1").target_name, "owner-command.json")
        with self.assertRaises(ValueError):
            self.plan("intent", kind="arbitrary", expected_prior_sha256="")
        with self.assertRaises(ValueError):
            self.plan("install_intent", expected_prior_sha256="c" * 64)
        with self.assertRaises(ValueError):
            self.plan("command1", expected_prior_sha256="c" * 64)
        with self.assertRaises(ValueError):
            self.plan("policy2", expected_prior_sha256="")
        with self.assertRaises(ValueError):
            self.plan("install_intent", intent_root="/srv/job/intents")
        with self.assertRaises(ValueError):
            self.plan("install_intent", intent_root="/srv")

    def test_paths_types_hashes_and_bounds_are_exact(self):
        for root in ("relative", "/srv/../job", "/srv//job", "/srv/job/", "/srv/job\x00x"):
            with self.subTest(root=root), self.assertRaises(ValueError):
                self.plan("command1", job_root=root)
        for size in (True, 1.0, 0, MAX_POLICY_BYTES + 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.plan("policy1", size=size)
        for uid in (True, 1.0, -1):
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                self.plan("policy1", uid=uid)

    def test_command_uses_fixed_script_and_plan_arguments(self):
        plan = self.plan("command2")
        command = remote_publish_command(plan)
        self.assertTrue(command.startswith("python3 -c "))
        self.assertIn("owner-command.json", REMOTE_PUBLISH_SCRIPT)
        self.assertEqual(plan.argv, (
            "/srv/job", "command2", "1000", "1000", "a" * 64,
            "20", "b" * 64))
        with self.assertRaises(ValueError):
            remote_publish_command(object())

    def test_receipt_is_closed_exact_typed_and_plan_bound(self):
        plan = self.plan("policy1")
        receipt = {
            "schema_version": 1, "event": "owner_file_publication",
            "kind": "policy1", "sha256": "a" * 64, "size": 20,
            "uid": 1000, "gid": 1000, "mode": 0o600,
            "file_fsync_confirmed": True,
            "directory_fsync_confirmed": True,
            "readback_confirmed": True,
        }
        self.assertEqual(validate_publication_receipt(receipt, plan=plan), receipt)
        self.assertEqual(json.loads(canonical_receipt_bytes(receipt)), receipt)
        for field, bad in (("schema_version", True), ("size", 20.0),
                           ("uid", True), ("mode", float(0o600)),
                           ("readback_confirmed", 1)):
            mutated = dict(receipt, **{field: bad})
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_publication_receipt(mutated)
        with self.assertRaises(ValueError):
            validate_publication_receipt(dict(receipt, extra="x"))
        with self.assertRaises(ValueError):
            validate_publication_receipt(dict(receipt, sha256="c" * 64), plan=plan)

    def test_remote_source_parses_as_standalone_python(self):
        ast.parse(REMOTE_PUBLISH_SCRIPT)


@unittest.skipUnless(os.name == "posix", "remote publication script requires POSIX dirfd semantics")
class OwnerPublicationScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.target = self.base / "private"
        self.target.mkdir(mode=0o700)
        os.chmod(self.target, 0o700)
        self.uid = os.geteuid()
        self.gid = os.getegid()

    def tearDown(self):
        self.temp.cleanup()

    def stage(self, data):
        path = self.target / "owner-upload.bin"
        path.write_bytes(data)
        os.chmod(path, 0o600)
        return path

    def run_publish(self, kind, data, prior="", *, size=None, digest=None,
                    stage_mode=0o600):
        stage = self.stage(data)
        os.chmod(stage, stage_mode)
        size = len(data) if size is None else size
        digest = hashlib.sha256(data).hexdigest() if digest is None else digest
        argv = [sys.executable, "-c", REMOTE_PUBLISH_SCRIPT,
                str(self.target), kind, str(self.uid), str(self.gid), digest,
                str(size), prior]
        return subprocess.run(argv, text=True, capture_output=True, timeout=5)

    def test_exclusive_intent_publishes_fsynced_readback_receipt(self):
        data = b'{"signed":"intent"}'
        result = self.run_publish("install_intent", data)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        plan = build_publication_plan(
            "install_intent", intent_root=str(self.target), job_root="/unused",
            uid=self.uid, gid=self.gid,
            sha256=hashlib.sha256(data).hexdigest(), size=len(data))
        validate_publication_receipt(receipt, plan=plan)
        self.assertEqual((self.target / "install-intent.json").read_bytes(), data)
        self.assertFalse((self.target / "owner-upload.bin").exists())

    def test_replace_requires_exact_prior_digest_and_keeps_old_target_on_failure(self):
        target = self.target / "snapshot.json"
        old = b"old signed policy"
        target.write_bytes(old)
        os.chmod(target, 0o600)
        new = b"new signed policy"
        wrong = self.run_publish("policy2", new, "0" * 64)
        self.assertNotEqual(wrong.returncode, 0)
        self.assertEqual(target.read_bytes(), old)
        self.assertTrue((self.target / "owner-upload.bin").exists())
        (self.target / "owner-upload.bin").unlink()
        success = self.run_publish("policy2", new, hashlib.sha256(old).hexdigest())
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(target.read_bytes(), new)
        self.assertFalse((self.target / "owner-upload.bin").exists())

    def test_exclusive_target_is_never_overwritten(self):
        target = self.target / "removal-intent.json"
        prior = b"original"
        target.write_bytes(prior)
        os.chmod(target, 0o600)
        result = self.run_publish("removal_intent", b"replacement")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_bytes(), prior)
        self.assertTrue((self.target / "owner-upload.bin").exists())

    def test_symlink_and_hardlink_stages_are_rejected(self):
        payload = self.base / "payload"
        payload.write_bytes(b"data")
        os.chmod(payload, 0o600)
        (self.target / "owner-upload.bin").symlink_to(payload)
        symlink_result = subprocess.run(
            [sys.executable, "-c", REMOTE_PUBLISH_SCRIPT, str(self.target),
             "command1", str(self.uid), str(self.gid), hashlib.sha256(b"data").hexdigest(),
             "4", ""], text=True, capture_output=True, timeout=5)
        self.assertNotEqual(symlink_result.returncode, 0)
        (self.target / "owner-upload.bin").unlink()
        self.stage(b"data")
        os.link(self.target / "owner-upload.bin", self.base / "second-link")
        hardlink_result = subprocess.run(
            [sys.executable, "-c", REMOTE_PUBLISH_SCRIPT, str(self.target),
             "command1", str(self.uid), str(self.gid), hashlib.sha256(b"data").hexdigest(),
             "4", ""], text=True, capture_output=True, timeout=5)
        self.assertNotEqual(hardlink_result.returncode, 0)

    def test_symlinked_root_component_is_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.target, target_is_directory=True)
        self.stage(b"data")
        result = subprocess.run(
            [sys.executable, "-c", REMOTE_PUBLISH_SCRIPT, str(alias),
             "command1", str(self.uid), str(self.gid), hashlib.sha256(b"data").hexdigest(),
             "4", ""], text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.target / "owner-command.json").exists())

    def test_fifo_stage_is_rejected_without_blocking(self):
        os.mkfifo(self.target / "owner-upload.bin", 0o600)
        result = subprocess.run(
            [sys.executable, "-c", REMOTE_PUBLISH_SCRIPT, str(self.target),
             "command1", str(self.uid), str(self.gid), hashlib.sha256(b"data").hexdigest(),
             "4", ""], text=True, capture_output=True, timeout=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertTrue(stat.S_ISFIFO((self.target / "owner-upload.bin").lstat().st_mode))

    def test_fifo_target_is_rejected_without_blocking(self):
        os.mkfifo(self.target / "snapshot.json", 0o600)
        data = b"new policy"
        self.stage(data)
        result = subprocess.run(
            [sys.executable, "-c", REMOTE_PUBLISH_SCRIPT, str(self.target),
             "policy2", str(self.uid), str(self.gid), hashlib.sha256(data).hexdigest(),
             str(len(data)), "b" * 64], text=True, capture_output=True, timeout=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertTrue(stat.S_ISFIFO((self.target / "snapshot.json").lstat().st_mode))

    def test_fsync_failure_cannot_return_a_receipt_or_publish(self):
        data = b"signed command"
        self.stage(data)
        failing_script = (
            "import os; os.fsync=lambda fd: (_ for _ in ()).throw(OSError()); exec(" +
            repr(REMOTE_PUBLISH_SCRIPT) + ")")
        result = subprocess.run(
            [sys.executable, "-c", failing_script, str(self.target), "command1",
             str(self.uid), str(self.gid), hashlib.sha256(data).hexdigest(),
             str(len(data)), ""], text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertFalse((self.target / "owner-command.json").exists())

    def test_post_publication_directory_fsync_failure_returns_no_receipt(self):
        data = b"signed command"
        self.stage(data)
        failing_script = (
            "import os; _real_fsync=os.fsync; _count=0\n"
            "def _fail_after_publication(fd):\n"
            " global _count\n"
            " _count += 1\n"
            " if _count == 2: raise OSError('injected post-publication fsync failure')\n"
            " return _real_fsync(fd)\n"
            "os.fsync=_fail_after_publication\nexec(" + repr(REMOTE_PUBLISH_SCRIPT) + ")")
        result = subprocess.run(
            [sys.executable, "-c", failing_script, str(self.target), "command1",
             str(self.uid), str(self.gid), hashlib.sha256(data).hexdigest(),
             str(len(data)), ""], text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual((self.target / "owner-command.json").read_bytes(), data)

    def test_oversize_stage_and_unsafe_private_directory_are_rejected(self):
        data = b"x" * (MAX_CONTROL_BYTES + 1)
        result = self.run_publish("command1", data, size=len(data))
        self.assertNotEqual(result.returncode, 0)
        os.chmod(self.target, 0o750)
        (self.target / "owner-upload.bin").unlink()
        result = self.run_publish("command1", b"small")
        self.assertNotEqual(result.returncode, 0)

    def test_unsafe_stage_mode_is_rejected(self):
        result = self.run_publish("command1", b"small", stage_mode=0o640)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.target / "owner-command.json").exists())


if __name__ == "__main__":
    unittest.main()
