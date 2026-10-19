"""Focused cold root-transition declaration and snapshot-floor foundation tests."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0, str(ROOT / "src"))

from steamboat_security import (
    Clock, ClockError, SnapshotError, SnapshotStore, StorageError,
    canonical_policy_digest, generate_authorization_signing_key_pem,
    generate_ca, load_protected_root_transition, parse_root_transition_declaration,
    sign_snapshot, snapshot_public_key_pem,
)
from steamboat_security.root_transition import (
    MAX_TRANSITION_APPROVAL_BYTES, _check_overlap_clock,
)


NOW = 1_800_000_000


class MutableClock:
    def __init__(self, wall=NOW, monotonic=100.0, uncertainty=0.0):
        self.wall = float(wall)
        self.monotonic = float(monotonic)
        self.uncertainty = float(uncertainty)
        self.samples = 0
        self.clock = Clock(
            wall=self._wall, monotonic=self._mono,
            uncertainty_seconds=self._uncertainty)

    def _wall(self):
        self.samples += 1
        return self.wall

    def _mono(self):
        return self.monotonic

    def _uncertainty(self):
        return self.uncertainty


def _approval_document(*, start=NOW - 10, end=NOW + 200):
    return {
        "schema_version": 1,
        "transition_id": "1" * 32,
        "old_ca_sha256": "a" * 64,
        "new_ca_sha256": "b" * 64,
        "old_snapshot_key_sha256": "c" * 64,
        "new_snapshot_key_sha256": "c" * 64,
        "overlap_not_before": start,
        "overlap_not_after": end,
        "old_policy_revision": 4,
        "old_policy_digest": "d" * 64,
        "next_minimum_revision": 5,
        "new_policy_digest": "e" * 64,
        "affected_principals": [{
            "account_id": "acct_" + "1" * 32,
            "device_id": "dev_" + "1" * 32,
            "role": "host",
            "old_boot_id": "2" * 32,
            "old_serial": "a1",
            "old_certificate_sha256": "f" * 64,
            "old_public_key_sha256": "9" * 64,
            "old_credential_epoch": 2,
            "old_admission_epoch": 3,
            "new_csr_sha256": "8" * 64,
            "dns_sans": ["worker.example"],
            "ip_sans": ["127.0.0.1"],
        }],
    }


def _approval_bytes(document=None):
    return json.dumps(document or _approval_document(), separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


class SnapshotFloorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_pem, _ca_key = generate_ca(now=NOW - 3600)
        cls.signing_key = generate_authorization_signing_key_pem()
        cls.signing_public = snapshot_public_key_pem(cls.signing_key)

    def payload(self, *, revision, revoked_devices=()):
        return {
            "version": 1,
            "revision": revision,
            "issued_at": NOW,
            "expires_at": NOW + 240,
            "revoked_serials": [],
            "revoked_devices": sorted(revoked_devices),
            "credentials": [],
            "grants": [],
        }

    def store(self, time_source, **kwargs):
        return SnapshotStore(
            verification_key_pem=self.signing_public,
            ca_certificate_pem=self.ca_pem,
            clock=time_source.clock,
            **kwargs,
        )

    def test_floor_rejects_old_or_conflicting_policy_before_store_change(self):
        time_source = MutableClock()
        payload = self.payload(revision=5)
        floor = canonical_policy_digest(payload)
        store = self.store(time_source, minimum_revision=5,
                           minimum_policy_digest=floor)
        callbacks = []
        store.subscribe(callbacks.append)
        constructor_samples = time_source.samples

        with self.assertRaises(SnapshotError):
            store.install(sign_snapshot(self.payload(revision=4), self.signing_key))
        self.assertIsNone(store._view)
        self.assertIsNone(store._encoded)
        self.assertEqual(callbacks, [])
        self.assertEqual(time_source.samples, constructor_samples)

        conflicting = self.payload(revision=5, revoked_devices=("dev_" + "7" * 32,))
        with self.assertRaises(SnapshotError):
            store.install(sign_snapshot(conflicting, self.signing_key))
        self.assertIsNone(store._view)
        self.assertIsNone(store._encoded)
        self.assertEqual(callbacks, [])
        self.assertEqual(time_source.samples, constructor_samples)

        encoded_a = sign_snapshot(payload, self.signing_key)
        encoded_b = sign_snapshot(payload, self.signing_key)
        self.assertNotEqual(encoded_a, encoded_b)  # ECDSA signature bytes are not the floor identity.
        view = store.install(encoded_b)
        self.assertEqual(view.policy_digest, floor)
        self.assertEqual(len(callbacks), 1)

        installed_samples = time_source.samples
        installed_view = store._view
        with self.assertRaises(SnapshotError):
            store.install(sign_snapshot(conflicting, self.signing_key))
        with self.assertRaises(SnapshotError):
            store.install(sign_snapshot(self.payload(revision=4), self.signing_key))
        self.assertIs(store._view, installed_view)
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(time_source.samples, installed_samples)

        later = self.payload(revision=6, revoked_devices=("dev_" + "7" * 32,))
        later_view = store.install(sign_snapshot(later, self.signing_key))
        self.assertEqual(later_view.revision, 6)
        self.assertEqual(len(callbacks), 2)

    def test_default_floor_behavior_and_constructor_pair_validation(self):
        time_source = MutableClock()
        store = self.store(time_source)
        self.assertEqual(store.install(sign_snapshot(self.payload(revision=1), self.signing_key)).revision, 1)
        self.assertEqual(store.install(sign_snapshot(self.payload(revision=2), self.signing_key)).revision, 2)

        invalid = (
            {"minimum_revision": 1},
            {"minimum_policy_digest": "a" * 64},
            {"minimum_revision": True, "minimum_policy_digest": "a" * 64},
            {"minimum_revision": 1, "minimum_policy_digest": "A" * 64},
            {"minimum_revision": 0, "minimum_policy_digest": "a" * 64},
        )
        for kwargs in invalid:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.store(MutableClock(), **kwargs)


class DeclarationTests(unittest.TestCase):
    def test_parser_builds_immutable_closed_declaration(self):
        declaration = parse_root_transition_declaration(_approval_bytes())
        self.assertEqual(declaration.schema_version, 1)
        self.assertEqual(declaration.next_minimum_revision, declaration.old_policy_revision + 1)
        self.assertEqual(declaration.affected_principals[0].role, "host")
        self.assertEqual(declaration.affected_principals[0].dns_sans, ("worker.example",))
        self.assertEqual(declaration.affected_principals[0].required_ekus, frozenset({"server"}))
        with self.assertRaises(FrozenInstanceError):
            declaration.transition_id = "0" * 32
        with self.assertRaises(FrozenInstanceError):
            declaration.affected_principals[0].role = "consumer"

    def test_parser_rejects_duplicate_unknown_oversize_nonfinite_and_bool_numbers(self):
        valid = _approval_document()
        duplicate = b'{"schema_version":1,"schema_version":1}'
        with self.assertRaises(SnapshotError):
            parse_root_transition_declaration(duplicate)

        unknown = deepcopy(valid)
        unknown["automatic_fallback"] = True
        with self.assertRaises(SnapshotError):
            parse_root_transition_declaration(_approval_bytes(unknown))

        with self.assertRaises(SnapshotError):
            parse_root_transition_declaration(b" " * (MAX_TRANSITION_APPROVAL_BYTES + 1))

        nonfinite = _approval_bytes(valid).replace(b'"schema_version":1', b'"schema_version":NaN')
        with self.assertRaises(SnapshotError):
            parse_root_transition_declaration(nonfinite)
        exponent_overflow = _approval_bytes(valid).replace(
            b'"overlap_not_before":1799999990', b'"overlap_not_before":1e999')
        with self.assertRaises(SnapshotError):
            parse_root_transition_declaration(exponent_overflow)

        bool_version = deepcopy(valid)
        bool_version["schema_version"] = True
        with self.assertRaises(SnapshotError):
            parse_root_transition_declaration(_approval_bytes(bool_version))

    def test_parser_rejects_invalid_floors_authorities_identity_and_sans(self):
        invalid_documents = []
        bad = deepcopy(_approval_document())
        bad["next_minimum_revision"] = 6
        invalid_documents.append(bad)
        bad = deepcopy(_approval_document())
        bad["new_ca_sha256"] = bad["old_ca_sha256"]
        bad["new_snapshot_key_sha256"] = bad["old_snapshot_key_sha256"]
        invalid_documents.append(bad)
        bad = deepcopy(_approval_document())
        bad["affected_principals"][0]["account_id"] = "dev_" + "1" * 32
        invalid_documents.append(bad)
        bad = deepcopy(_approval_document())
        bad["affected_principals"][0]["role"] = "unknown"
        invalid_documents.append(bad)
        bad = deepcopy(_approval_document())
        bad["affected_principals"][0]["dns_sans"] = ["z.example", "a.example"]
        invalid_documents.append(bad)
        bad = deepcopy(_approval_document())
        bad["affected_principals"][0]["ip_sans"] = ["127.0.0.1", "127.0.0.1"]
        invalid_documents.append(bad)
        bad = deepcopy(_approval_document())
        bad["affected_principals"][0]["old_credential_epoch"] = True
        invalid_documents.append(bad)
        bad = deepcopy(_approval_document())
        bad["affected_principals"][0]["old_boot_id"] = "g" * 32
        invalid_documents.append(bad)
        bad = deepcopy(_approval_document())
        bad["affected_principals"][0]["dns_sans"] = [f"h{i}.example" for i in range(9)]
        invalid_documents.append(bad)
        bad = deepcopy(_approval_document(start=NOW, end=NOW + 301))
        invalid_documents.append(bad)
        bad = deepcopy(_approval_document())
        bad["overlap_not_after"] = bad["overlap_not_before"]
        invalid_documents.append(bad)
        bad = deepcopy(_approval_document())
        bad["affected_principals"].append(deepcopy(bad["affected_principals"][0]))
        invalid_documents.append(bad)
        for duplicate_field in ("old_serial", "old_certificate_sha256", "new_csr_sha256"):
            bad = deepcopy(_approval_document())
            first = bad["affected_principals"][0]
            second = deepcopy(first)
            second.update({
                "account_id": "acct_" + "2" * 32,
                "device_id": "dev_" + "2" * 32,
                "old_serial": "b2",
                "old_certificate_sha256": "0" * 64,
                "old_public_key_sha256": "7" * 64,
                "new_csr_sha256": "6" * 64,
            })
            second[duplicate_field] = first[duplicate_field]
            bad["affected_principals"].append(second)
            invalid_documents.append(bad)

        sixteen = deepcopy(_approval_document())
        principals = []
        for index in range(1, 17):
            principal = deepcopy(sixteen["affected_principals"][0])
            principal.update({
                "account_id": f"acct_{index:032x}",
                "device_id": f"dev_{index:032x}",
                "old_boot_id": f"{index:032x}",
                "old_serial": format(index, "x"),
                "old_certificate_sha256": f"{index + 100:064x}",
                "old_public_key_sha256": f"{index + 200:064x}",
                "new_csr_sha256": f"{index + 300:064x}",
            })
            principals.append(principal)
        sixteen["affected_principals"] = principals
        self.assertEqual(len(parse_root_transition_declaration(_approval_bytes(sixteen)).affected_principals), 16)
        seventeen = deepcopy(sixteen)
        extra = deepcopy(principals[-1])
        extra.update({
            "account_id": "acct_" + "f" * 32,
            "device_id": "dev_" + "f" * 32,
            "old_boot_id": "f" * 32,
            "old_serial": "f1",
            "old_certificate_sha256": "f" * 64,
            "old_public_key_sha256": "e" * 64,
            "new_csr_sha256": "d" * 64,
        })
        seventeen["affected_principals"].append(extra)
        invalid_documents.append(seventeen)
        unsorted = deepcopy(sixteen)
        unsorted["affected_principals"].reverse()
        invalid_documents.append(unsorted)

        for document in invalid_documents:
            with self.subTest(document=document), self.assertRaises(SnapshotError):
                parse_root_transition_declaration(_approval_bytes(document))

    def test_overlap_uses_conservative_interval_and_unhealthy_clock_rejects(self):
        declaration = parse_root_transition_declaration(
            _approval_bytes(_approval_document(start=100, end=200)))

        _check_overlap_clock(declaration, MutableClock(wall=100, uncertainty=0).clock)
        _check_overlap_clock(declaration, MutableClock(wall=199, uncertainty=0).clock)
        for wall, uncertainty in ((99, 0), (105, 6), (199, 1), (200, 0)):
            with self.subTest(wall=wall, uncertainty=uncertainty), self.assertRaises(SnapshotError):
                _check_overlap_clock(
                    declaration, MutableClock(wall=wall, uncertainty=uncertainty).clock)
        with self.assertRaises(ClockError):
            _check_overlap_clock(declaration, Clock())


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW")
                     and hasattr(os, "geteuid"),
                     "protected approval loader requires POSIX no-follow primitives")
class ProtectedLoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "approvals"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.approval = self.root / "transition.json"
        self.approval.write_bytes(_approval_bytes())
        os.chmod(self.approval, 0o600)

    def tearDown(self):
        self.temp.cleanup()

    def load(self, path=None, *, clock=None):
        return load_protected_root_transition(
            path or self.approval, root=self.root, expected_uid=os.geteuid(),
            clock=clock or MutableClock().clock)

    def test_owner_protected_file_loads_and_wrong_modes_reject(self):
        loaded = self.load()
        self.assertEqual(loaded.declaration.transition_id, "1" * 32)

        os.chmod(self.approval, 0o640)
        with self.assertRaises(StorageError):
            self.load()
        os.chmod(self.approval, 0o600)
        os.chmod(self.root, 0o750)
        with self.assertRaises(StorageError):
            self.load()
        os.chmod(self.root, 0o700)
        self.approval.write_bytes(b" " * (MAX_TRANSITION_APPROVAL_BYTES + 1))
        with self.assertRaises(StorageError):
            self.load()

    def test_symlinked_approval_and_intermediate_path_reject(self):
        linked = self.root / "linked.json"
        os.symlink(self.approval, linked)
        with self.assertRaises(StorageError):
            self.load(linked)

        nested = self.root / "nested"
        nested.mkdir(mode=0o700)
        os.chmod(nested, 0o700)
        nested_file = nested / "other.json"
        nested_file.write_bytes(_approval_bytes())
        os.chmod(nested_file, 0o600)
        directory_link = self.root / "directory-link"
        os.symlink(nested, directory_link)
        with self.assertRaises(StorageError):
            self.load(directory_link / nested_file.name)

    def test_wrong_configured_uid_rejects(self):
        with self.assertRaises(StorageError):
            load_protected_root_transition(
                self.approval, root=self.root, expected_uid=os.geteuid() + 1,
                clock=MutableClock().clock)

    def test_wrong_owner_rejects_prebaked_foreign_uid_fixture(self):
        fixture = os.environ.get("STEAMBOAT_IDENTITY_FOREIGN_FIXTURE")
        if not fixture:
            self.skipTest("foreign-UID fixture is provided by the Linux security-test container")
        path = Path(fixture)
        self.assertNotEqual(path.stat().st_uid, os.geteuid())
        self.assertEqual(path.parent.stat().st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(StorageError):
            load_protected_root_transition(
                path, root=path.parent, expected_uid=os.geteuid(),
                clock=MutableClock().clock)

    def test_special_file_rejects_without_blocking(self):
        self.approval.unlink()
        fifo = self.root / "approval.fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(StorageError):
            self.load(fifo)


if __name__ == "__main__":
    unittest.main()
