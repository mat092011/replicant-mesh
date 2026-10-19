"""Closed-schema and protected-file tests for the owner command inbox."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

import lab.secure_worker_owner_control as owner_module
from lab.secure_worker_owner_control import (
    ACK_FILENAME, COMMAND_FILENAME, MAX_CONTROL_BYTES, OwnerControlError,
    OwnerControlInbox, OwnerCommand, parse_owner_command,
)


RUN_ID = "1" * 32
BOOT_ID = "2" * 32
_POSIX_FILES = (os.name == "posix" and hasattr(os, "O_NOFOLLOW")
                and hasattr(os, "geteuid") and hasattr(os, "O_DIRECTORY"))


def command_document(sequence=1, *, command_id=None, action="drain",
                     drain_seconds=30, snapshot_sha256="", snapshot_revision=0):
    return {
        "schema_version": 1, "event": "owner_command", "run_id": RUN_ID,
        "worker_boot_id": BOOT_ID, "sequence": sequence,
        "command_id": command_id or f"{sequence:032x}", "action": action,
        "drain_seconds": drain_seconds, "snapshot_sha256": snapshot_sha256,
        "snapshot_revision": snapshot_revision,
    }


def command_bytes(document):
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


class OwnerControlSchemaTests(unittest.TestCase):
    def parse(self, document):
        return parse_owner_command(
            command_bytes(document), expected_run_id=RUN_ID,
            expected_worker_boot_id=BOOT_ID)

    def test_command_digest_uses_sorted_canonical_json_and_owner_command_is_frozen(self):
        document = command_document()
        encoded = json.dumps(document, indent=2).encode("utf-8")
        command = parse_owner_command(
            encoded, expected_run_id=RUN_ID, expected_worker_boot_id=BOOT_ID)
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False).encode("ascii")
        self.assertEqual(command.command_sha256, hashlib.sha256(canonical).hexdigest())
        self.assertEqual(command.action, "drain")
        with self.assertRaises(FrozenInstanceError):
            command.action = "remove"

    def test_closed_schema_rejects_duplicates_wrong_targets_and_bad_exact_types(self):
        good = command_document()
        invalid = []
        for key, value in (("unknown", 1), ("schema_version", True),
                           ("sequence", True), ("command_id", "A" * 32),
                           ("run_id", "3" * 32), ("worker_boot_id", "4" * 32),
                           ("action", "exec"), ("drain_seconds", True),
                           ("drain_seconds", 301), ("snapshot_sha256", "a" * 64)):
            changed = dict(good)
            changed[key] = value
            invalid.append(changed)
        for document in invalid:
            with self.subTest(document=document):
                with self.assertRaises(OwnerControlError):
                    self.parse(document)
        duplicate = command_bytes(good).decode().replace(
            '"sequence":1', '"sequence":1,"sequence":1')
        with self.assertRaises(OwnerControlError):
            parse_owner_command(duplicate.encode(), expected_run_id=RUN_ID,
                                expected_worker_boot_id=BOOT_ID)
        for raw in (b'{"schema_version":NaN}', b"\xff", b" " * (MAX_CONTROL_BYTES + 1)):
            with self.assertRaises(OwnerControlError):
                parse_owner_command(raw, expected_run_id=RUN_ID,
                                    expected_worker_boot_id=BOOT_ID)
        nested = dict(good)
        nested["extra"] = [[[[[[[[[0]]]]]]]]]
        with self.assertRaises(OwnerControlError):
            self.parse(nested)

    def test_snapshot_actions_require_exact_digest_revision_and_zero_drain(self):
        digest = "a" * 64
        for action in ("install_snapshot", "remove"):
            good = command_document(action=action, drain_seconds=0,
                                    snapshot_sha256=digest, snapshot_revision=7)
            self.assertEqual(self.parse(good).snapshot_revision, 7)
            for key, value in (("drain_seconds", 1), ("snapshot_sha256", ""),
                               ("snapshot_revision", 0), ("snapshot_revision", True)):
                changed = dict(good)
                changed[key] = value
                with self.subTest(action=action, key=key, value=value):
                    with self.assertRaises(OwnerControlError):
                        self.parse(changed)


@unittest.skipUnless(_POSIX_FILES, "protected inbox file operations require Linux/POSIX dirfd APIs")
class OwnerControlFileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="owner-control-")
        self.root = Path(self.temporary.name) / "protected"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.inbox = OwnerControlInbox(
            self.root, run_id=RUN_ID, worker_boot_id=BOOT_ID,
            expected_uid=os.geteuid())

    def tearDown(self):
        self.temporary.cleanup()

    def put_command(self, document):
        path = self.root / COMMAND_FILENAME
        path.write_bytes(command_bytes(document))
        os.chmod(path, 0o600)
        return path

    def ack(self, command, *, accepted=True, failure_code=None, digest="a" * 64,
            revision=3, receive=100, complete=200):
        return self.inbox.write_ack(
            command, accepted=accepted, failure_code=failure_code,
            received_monotonic_ns=receive, completed_monotonic_ns=complete,
            phase="paused", applied_snapshot_sha256=digest,
            applied_revision=revision)

    def test_claim_sequence_idempotent_ack_and_atomic_replacement(self):
        self.assertIsNone(self.inbox.claim_next())
        self.put_command(command_document(1))
        first = self.inbox.claim_next()
        self.assertIsInstance(first, OwnerCommand)
        self.assertIsNone(self.inbox.claim_next())
        self.assertIsNone(self.inbox.claim_next())
        clone = replace(first)
        with self.assertRaises(OwnerControlError):
            self.ack(clone)
        ack1 = self.ack(first)
        ack_path = self.root / ACK_FILENAME
        raw1 = ack_path.read_bytes()
        self.assertEqual(ack1["command_sha256"], first.command_sha256)
        self.assertEqual(stat.S_IMODE(ack_path.stat().st_mode), 0o600)
        self.assertEqual(ack_path.stat().st_nlink, 1)
        self.assertEqual(self.ack(first), ack1)
        with self.assertRaises(OwnerControlError):
            self.ack(first, complete=201)

        self.put_command(command_document(2))
        second = self.inbox.claim_next()
        self.assertEqual(second.sequence, 2)
        real_fsync = os.fsync
        failed = False

        def fail_first_directory_sync(fd):
            nonlocal failed
            if stat.S_ISDIR(os.fstat(fd).st_mode) and not failed:
                failed = True
                raise OSError("injected directory durability uncertainty")
            return real_fsync(fd)

        with mock.patch.object(owner_module.os, "fsync", side_effect=fail_first_directory_sync):
            with self.assertRaises(OwnerControlError):
                self.ack(second, receive=300, complete=400, digest="b" * 64,
                         revision=4)
        changed = command_document(3)
        self.put_command(changed)
        with self.assertRaises(OwnerControlError):
            self.inbox.claim_next()
        self.put_command(command_document(2))
        with self.assertRaises(OwnerControlError):
            self.ack(second, receive=300, complete=401, digest="b" * 64,
                     revision=4)
        ack2 = self.ack(second, receive=300, complete=400, digest="b" * 64,
                        revision=4)
        self.assertEqual(json.loads(ack_path.read_bytes()), ack2)
        self.assertNotEqual(ack_path.read_bytes(), raw1)
        self.assertEqual(ack_path.stat().st_nlink, 1)
        self.assertEqual({p.name for p in self.root.iterdir()},
                         {COMMAND_FILENAME, ACK_FILENAME})

    def test_unacknowledged_gap_reused_id_lower_and_changed_same_sequence_fail(self):
        self.put_command(command_document(2))
        with self.assertRaises(OwnerControlError):
            self.inbox.claim_next()
        self.put_command(command_document(1))
        first = self.inbox.claim_next()
        self.put_command(command_document(2))
        with self.assertRaises(OwnerControlError):
            self.inbox.claim_next()
        self.put_command(command_document(1, command_id="f" * 32))
        with self.assertRaises(OwnerControlError):
            self.inbox.claim_next()
        self.ack(first)
        self.put_command(command_document(2, command_id=first.command_id))
        with self.assertRaises(OwnerControlError):
            self.inbox.claim_next()
        self.put_command(command_document(2, command_id="9" * 32))
        second = self.inbox.claim_next()
        self.ack(second, receive=300, complete=400)
        self.put_command(command_document(3, command_id="8" * 32))
        third = self.inbox.claim_next()
        self.ack(third, receive=500, complete=600)
        self.put_command(command_document(2, command_id="9" * 32))
        with self.assertRaises(OwnerControlError):
            self.inbox.claim_next()

    def test_failure_ack_fences_new_commands_and_snapshot_ack_must_match(self):
        self.put_command(command_document())
        drain = self.inbox.claim_next()
        failed = self.ack(drain, accepted=False, failure_code="owner_unavailable",
                          digest="", revision=0)
        self.assertEqual(self.ack(drain, accepted=False,
                                  failure_code="owner_unavailable",
                                  digest="", revision=0), failed)
        self.put_command(command_document(2))
        with self.assertRaises(OwnerControlError):
            self.inbox.claim_next()

        # Use a second isolated root for the positive install-snapshot claim.
        install_root = Path(self.temporary.name) / "install"
        install_root.mkdir(mode=0o700)
        os.chmod(install_root, 0o700)
        other = OwnerControlInbox(install_root, run_id=RUN_ID,
                                  worker_boot_id=BOOT_ID, expected_uid=os.geteuid())
        install = command_document(action="install_snapshot", drain_seconds=0,
                                   snapshot_sha256="c" * 64, snapshot_revision=9)
        path = install_root / COMMAND_FILENAME
        path.write_bytes(command_bytes(install))
        os.chmod(path, 0o600)
        claimed = other.claim_next()
        with self.assertRaises(OwnerControlError):
            other.write_ack(claimed, accepted=True, failure_code=None,
                            received_monotonic_ns=1, completed_monotonic_ns=2,
                            phase="ready", applied_snapshot_sha256="d" * 64,
                            applied_revision=9)
        installed = other.write_ack(
            claimed, accepted=True, failure_code=None,
            received_monotonic_ns=1, completed_monotonic_ns=2,
            phase="ready", applied_snapshot_sha256="c" * 64,
            applied_revision=9)
        self.assertEqual(json.loads((install_root / ACK_FILENAME).read_bytes()), installed)

    def test_existing_ack_target_is_never_overwritten(self):
        self.put_command(command_document())
        command = self.inbox.claim_next()
        ack_path = self.root / ACK_FILENAME
        original = b'{"event":"unrecognized"}'
        ack_path.write_bytes(original)
        os.chmod(ack_path, 0o600)
        with self.assertRaises(OwnerControlError):
            self.ack(command)
        self.assertEqual(ack_path.read_bytes(), original)

    def test_unsafe_root_ancestor_command_types_permissions_and_links_fail_closed(self):
        self.put_command(command_document())
        broad_root = OwnerControlInbox(
            self.root, run_id=RUN_ID, worker_boot_id=BOOT_ID, expected_uid=os.geteuid())
        os.chmod(self.root, 0o750)
        with self.assertRaises(OwnerControlError):
            broad_root.claim_next()
        os.chmod(self.root, 0o700)

        command_path = self.root / COMMAND_FILENAME
        os.chmod(command_path, 0o640)
        with self.assertRaises(OwnerControlError):
            self.inbox.claim_next()
        os.chmod(command_path, 0o600)
        alias = self.root / "command-alias"
        os.link(command_path, alias)
        with self.assertRaises(OwnerControlError):
            self.inbox.claim_next()
        alias.unlink()

        command_path.unlink()
        external = Path(self.temporary.name) / "outside.json"
        external.write_bytes(command_bytes(command_document()))
        os.chmod(external, 0o600)
        command_path.symlink_to(external)
        with self.assertRaises(OwnerControlError):
            self.inbox.claim_next()
        command_path.unlink()
        os.mkfifo(command_path, 0o600)
        with self.assertRaises(OwnerControlError):
            self.inbox.claim_next()
        command_path.unlink()
        command_path.write_bytes(command_bytes(command_document()))
        os.chmod(command_path, 0o600)

        alias_root = Path(self.temporary.name) / "root-alias"
        alias_root.symlink_to(self.root, target_is_directory=True)
        aliased = OwnerControlInbox(
            alias_root, run_id=RUN_ID, worker_boot_id=BOOT_ID, expected_uid=os.geteuid())
        with self.assertRaises(OwnerControlError):
            aliased.claim_next()

    @unittest.skipUnless(sys.platform.startswith("linux"),
                         "pinned foreign-owner fixture is Linux-only")
    def test_foreign_owner_fixture_is_rejected_without_modification(self):
        configured = os.environ.get("STEAMBOAT_IDENTITY_FOREIGN_FIXTURE")
        if not configured:
            self.fail("Docker-provisioned foreign-owner fixture is required")
        fixture = Path(configured)
        before = fixture.stat(follow_symlinks=False)
        self.assertTrue(stat.S_ISREG(before.st_mode))
        self.assertNotEqual(before.st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(before.st_mode), 0o600)
        self.assertEqual(before.st_nlink, 1)
        from steamboat_security.files import _open_directory_chain
        parent_fd = _open_directory_chain(fixture.parent, expected_uid=os.geteuid())
        try:
            with self.assertRaises(OwnerControlError):
                owner_module._read_fixed_at(
                    parent_fd, fixture.name, expected_uid=os.geteuid(),
                    missing_ok=False)
        finally:
            os.close(parent_fd)
        after = fixture.stat(follow_symlinks=False)
        self.assertEqual((after.st_uid, stat.S_IMODE(after.st_mode), after.st_nlink,
                          after.st_size, after.st_mtime_ns),
                         (before.st_uid, stat.S_IMODE(before.st_mode), before.st_nlink,
                          before.st_size, before.st_mtime_ns))


if __name__ == "__main__":
    unittest.main()
