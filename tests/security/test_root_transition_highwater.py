"""Pinned-authority policy high-water tests with real signed snapshots."""
from __future__ import annotations

import hashlib
import multiprocessing
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_security.codec import canonical_json
from steamboat_security.errors import SnapshotError, StorageError
from steamboat_security.operator import generate_authorization_signing_key_pem
from steamboat_security.root_transition_storage import (
    RootGenerationSelector, RootGenerationStore, root_generation_selector_document,
)
from steamboat_security.snapshot import SnapshotStore, canonical_policy_digest, sign_snapshot

import tests.security.test_root_transition_issuance as issuance_fixture


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_root(root: Path, fixture, payload: dict) -> tuple[RootGenerationSelector, bytes, str]:
    encoded = sign_snapshot(payload, fixture.old_snapshot_key)
    bundle = {
        "activation_manifest.json": canonical_json({"manifest": "baseline"}),
        "policy_snapshot.json": encoded,
        "ca_certificate.pem": fixture.old_ca,
        "snapshot_signer_public.pem": fixture.old_snapshot_public,
    }
    artifact_hashes = {name: _sha(data) for name, data in bundle.items()}
    generation_id = _sha(b"highwater-test-generation")
    selector = RootGenerationSelector(
        generation_sha256=generation_id,
        activation_manifest_sha256=artifact_hashes["activation_manifest.json"],
        policy_revision=payload["revision"],
        policy_digest=canonical_policy_digest(payload),
        active_policy_snapshot_sha256=_sha(encoded),
        artifact_sha256=artifact_hashes,
    )
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    generations = root / "generations"
    generations.mkdir(mode=0o700)
    policies = root / "policies"
    policies.mkdir(mode=0o700)
    (root / "transition.lock").touch(mode=0o600)
    os.chmod(root / "transition.lock", 0o600)
    generation = generations / generation_id
    generation.mkdir(mode=0o700)
    descriptor = {
        "schema_version": 1, "purpose": "root_generation_descriptor",
        "generation_sha256": generation_id,
        "activation_manifest_sha256": selector.activation_manifest_sha256,
        "artifact_sha256": artifact_hashes,
    }
    files = {"descriptor.json": canonical_json(descriptor), **bundle}
    for name, contents in files.items():
        path = generation / name
        path.write_bytes(contents)
        os.chmod(path, 0o600)
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
    policy_path = policies / f"{_sha(encoded)}.json"
    policy_path.write_bytes(encoded)
    os.chmod(policy_path, 0o600)
    with policy_path.open("rb") as stream:
        os.fsync(stream.fileno())
    selector_bytes = canonical_json(root_generation_selector_document(selector))
    selector_path = root / "selector.json"
    selector_path.write_bytes(selector_bytes)
    os.chmod(selector_path, 0o600)
    with selector_path.open("rb") as stream:
        os.fsync(stream.fileno())
    for directory in (generation, generations, policies, root):
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return selector, encoded, _sha(selector_bytes)


def _race_refresh(root, uid, old_head, incoming, clock, start, output):
    try:
        if not start.wait(5):
            output.put("error")
            return
        with RootGenerationStore(root, expected_uid=uid) as store:
            store.advance_policy(incoming, expected_old_selector_sha256=old_head,
                                 clock=clock, validate=lambda *_: None)
        output.put("refresh")
    except StorageError:
        output.put("rejected")
    except BaseException:
        output.put("error")


def _race_cold(root, uid, old_head, bundle, selector, start, output):
    try:
        if not start.wait(5):
            output.put("error")
            return
        with RootGenerationStore(root, expected_uid=uid) as store:
            store.commit(selector, bundle,
                         active_policy_snapshot=bundle["policy_snapshot.json"],
                         expected_old_selector_sha256=old_head,
                         validate=lambda *_: None)
        output.put("cold")
    except StorageError:
        output.put("rejected")
    except BaseException:
        output.put("error")


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "protected root storage requires POSIX no-follow support")
class RootTransitionPolicyHighwaterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        issuance_fixture.RootTransitionIssuanceTests.setUpClass()
        cls.fx = issuance_fixture.RootTransitionIssuanceTests

    def setUp(self):
        self.clock_source = issuance_fixture.MutableClock()
        self.payload = self.fx.snapshot_payload(revision=4)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "root"
        self.selector, self.baseline_policy, self.old_head = _make_root(
            self.root, self.fx, self.payload)
        self.uid = os.geteuid()

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def _validate(_selector, _bundle, _active):
        return None

    def _advance(self, payload, *, signer=None, expected=None):
        encoded = sign_snapshot(payload, signer or self.fx.old_snapshot_key)
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            result = store.advance_policy(
                encoded,
                expected_old_selector_sha256=expected or self.old_head,
                clock=self.clock_source.clock,
                validate=self._validate,
            )
        return encoded, result

    def test_higher_policy_is_pinned_and_independently_verifiable(self):
        payload = self.fx.snapshot_payload(revision=5)
        encoded, new_head = self._advance(payload)
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            selected = store.read_selected(self._validate)
        self.assertEqual(selected.active_policy_snapshot, encoded)
        self.assertEqual(selected.selector.policy_revision, 5)
        self.assertEqual(selected.selector.policy_digest, canonical_policy_digest(payload))
        self.assertEqual(dict(selected.artifacts)["policy_snapshot.json"], self.baseline_policy)
        self.assertEqual(selected.selector.generation_sha256, self.selector.generation_sha256)
        self.assertEqual(selected.selector.artifact_sha256, self.selector.artifact_sha256)
        self.assertNotEqual(new_head, self.old_head)
        verifier = SnapshotStore(
            verification_key_pem=self.fx.old_snapshot_public,
            ca_certificate_pem=self.fx.old_ca, clock=self.clock_source.clock,
            minimum_revision=5, minimum_policy_digest=canonical_policy_digest(payload))
        self.assertEqual(verifier.install(encoded).revision, 5)
        with self.assertRaises(SnapshotError):
            verifier.install(self.baseline_policy)

    def test_rejects_wrong_signer_rollback_equivocation_and_issued_at_rollback(self):
        invalid = []
        wrong = self.fx.snapshot_payload(revision=5)
        invalid.append((wrong, generate_authorization_signing_key_pem()))
        invalid.append((self.fx.snapshot_payload(revision=3), self.fx.old_snapshot_key))
        equivocation = self.fx.snapshot_payload(revision=4)
        equivocation["grants"][0]["not_after"] -= 1
        invalid.append((equivocation, self.fx.old_snapshot_key))
        time_rollback = self.fx.snapshot_payload(revision=5)
        time_rollback["issued_at"] -= 1
        invalid.append((time_rollback, self.fx.old_snapshot_key))
        for payload, signer in invalid:
            encoded = sign_snapshot(payload, signer)
            with self.subTest(revision=payload["revision"]):
                with RootGenerationStore(self.root, expected_uid=self.uid) as store:
                    with self.assertRaises(StorageError):
                        store.advance_policy(encoded,
                            expected_old_selector_sha256=self.old_head,
                            clock=self.clock_source.clock, validate=self._validate)
                    self.assertEqual(store.read_selected(self._validate).selector, self.selector)
        tampered = bytearray(sign_snapshot(self.fx.snapshot_payload(revision=5),
                                           self.fx.old_snapshot_key))
        tampered[-2] = ord("A") if tampered[-2] != ord("A") else ord("B")
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            with self.assertRaises(StorageError):
                store.advance_policy(bytes(tampered),
                    expected_old_selector_sha256=self.old_head,
                    clock=self.clock_source.clock, validate=self._validate)

    def test_equal_canonical_resign_keeps_existing_blob_and_head(self):
        resign = sign_snapshot(self.payload, self.fx.old_snapshot_key)
        self.assertNotEqual(resign, self.baseline_policy)
        before = set(os.listdir(self.root / "policies"))
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            returned = store.advance_policy(resign,
                expected_old_selector_sha256=self.old_head,
                clock=self.clock_source.clock, validate=self._validate)
            selected = store.read_selected(self._validate)
        self.assertEqual(returned, self.old_head)
        self.assertEqual(selected.active_policy_snapshot, self.baseline_policy)
        self.assertEqual(set(os.listdir(self.root / "policies")), before)

    def test_equal_revision_postcallback_checks_initial_monotonic_deadline(self):
        payload = self.fx.snapshot_payload(revision=4)
        payload["issued_at"] = int(self.clock_source.wall) - 2
        payload["expires_at"] = int(self.clock_source.wall) + 10
        root = Path(self.temp.name) / "equal-expiry-root"
        selector, active, head = _make_root(root, self.fx, payload)
        clock_source = issuance_fixture.MutableClock()

        def validate(_selector, _bundle, _policy):
            clock_source.mono += 15
            return None

        with RootGenerationStore(root, expected_uid=self.uid) as store:
            with self.assertRaises(StorageError):
                store.advance_policy(sign_snapshot(payload, self.fx.old_snapshot_key),
                    expected_old_selector_sha256=head, clock=clock_source.clock,
                    validate=validate)
            self.assertEqual(store.read_selected(self._validate).selector, selector)
            self.assertEqual(store.read_selected(self._validate).active_policy_snapshot, active)
        self.assertFalse((root / "pending.json").exists())

    def test_refresh_fault_after_selector_replace_recovers_exact_active_blob(self):
        payload = self.fx.snapshot_payload(revision=5)
        encoded = sign_snapshot(payload, self.fx.old_snapshot_key)

        def fail_on_unlink(label):
            if label == "pending.unlink":
                raise RuntimeError("leave refresh marker after selector replacement")

        with RootGenerationStore(self.root, expected_uid=self.uid,
                                 _fault_hook=fail_on_unlink) as store:
            with self.assertRaises(RuntimeError):
                store.advance_policy(encoded,
                    expected_old_selector_sha256=self.old_head,
                    clock=self.clock_source.clock, validate=self._validate)
        self.assertTrue((self.root / "pending.json").exists())
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            selected = store.recover_committed(validate=self._validate)
            self.assertEqual(selected.active_policy_snapshot, encoded)
            self.assertEqual(selected.selector.active_policy_snapshot_sha256, _sha(encoded))
            self.assertEqual(selected.selector.policy_revision, 5)
            self.assertEqual(selected.selector.policy_digest, canonical_policy_digest(payload))
            self.assertEqual(dict(selected.artifacts)["policy_snapshot.json"],
                             self.baseline_policy)
            self.assertFalse((self.root / "pending.json").exists())

    def test_expired_current_policy_can_be_replaced_while_authority_is_live(self):
        self.clock_source.advance(245)
        payload = self.fx.snapshot_payload(revision=5)
        payload["issued_at"] = int(self.clock_source.wall) - 2
        payload["expires_at"] = int(self.clock_source.wall) + 100
        encoded, _ = self._advance(payload)
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            self.assertEqual(store.read_selected(self._validate).active_policy_snapshot, encoded)

    def test_equal_revision_expired_resign_is_not_persisted(self):
        self.clock_source.advance(245)
        resign = sign_snapshot(self.payload, self.fx.old_snapshot_key)
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            with self.assertRaises(StorageError):
                store.advance_policy(resign,
                    expected_old_selector_sha256=self.old_head,
                    clock=self.clock_source.clock, validate=self._validate)
            self.assertEqual(store.read_selected(self._validate).selector, self.selector)
        self.assertFalse((self.root / "pending.json").exists())

    def test_monotonic_expiry_during_commit_remains_pending_and_blocked(self):
        payload = self.fx.snapshot_payload(revision=5)
        payload["issued_at"] = int(self.clock_source.wall) - 2
        payload["expires_at"] = int(self.clock_source.wall) + 10
        encoded = sign_snapshot(payload, self.fx.old_snapshot_key)
        calls = 0

        def validate(_selector, _bundle, _active):
            nonlocal calls
            calls += 1
            if calls == 2:
                # Ten seconds remain by wall time; monotonic time advances 15.
                self.clock_source.mono += 15
            return None

        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            with self.assertRaises(StorageError):
                store.advance_policy(encoded,
                    expected_old_selector_sha256=self.old_head,
                    clock=self.clock_source.clock, validate=validate)
            self.assertTrue((self.root / "pending.json").exists())
            with self.assertRaises(StorageError):
                store.read_selected(self._validate)

    def test_selector_pre_replace_clock_recheck_keeps_old_bytes(self):
        payload = self.fx.snapshot_payload(revision=5)
        payload["issued_at"] = int(self.clock_source.wall) - 2
        payload["expires_at"] = int(self.clock_source.wall) + 10
        encoded = sign_snapshot(payload, self.fx.old_snapshot_key)
        selector_path = self.root / "selector.json"
        old_selector_bytes = selector_path.read_bytes()

        def advance_at_temp_fsync(label):
            if label == "selector.temp.fsync":
                self.clock_source.advance(15)

        with RootGenerationStore(self.root, expected_uid=self.uid,
                                 _fault_hook=advance_at_temp_fsync) as store:
            with self.assertRaises(StorageError):
                store.advance_policy(encoded,
                    expected_old_selector_sha256=self.old_head,
                    clock=self.clock_source.clock, validate=self._validate)
        self.assertEqual(selector_path.read_bytes(), old_selector_bytes)
        self.assertTrue((self.root / "pending.json").exists())
        self.assertTrue(any(name.startswith("selector.tmp.") for name in os.listdir(self.root)))
        with self.assertRaises(StorageError):
            RootGenerationStore(self.root, expected_uid=self.uid)

    def test_policy_directory_capacity_rejects_before_pending_marker(self):
        policies = self.root / "policies"
        for index in range(63):
            path = policies / f"{index + 1:064x}.json"
            path.write_bytes(b"x" * (64 * 1024))
            os.chmod(path, 0o600)
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            self.assertEqual(store.read_selected(self._validate).selector, self.selector)
        payload = self.fx.snapshot_payload(revision=5)
        encoded = sign_snapshot(payload, self.fx.old_snapshot_key)
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            with self.assertRaises(StorageError):
                store.advance_policy(encoded,
                    expected_old_selector_sha256=self.old_head,
                    clock=self.clock_source.clock, validate=self._validate)
        self.assertFalse((self.root / "pending.json").exists())

    def test_policy_directory_rejects_bad_names_modes_and_links(self):
        policies = self.root / "policies"
        selected_path = policies / f"{self.selector.active_policy_snapshot_sha256}.json"
        malformed = policies / "unrecognized"
        malformed.write_bytes(b"x")
        os.chmod(malformed, 0o600)
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            with self.assertRaises(StorageError):
                store.read_selected(self._validate)
        malformed.unlink()

        os.chmod(selected_path, 0o644)
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            with self.assertRaises(StorageError):
                store.read_selected(self._validate)
        os.chmod(selected_path, 0o600)

        alias = Path(self.temp.name) / "policy-alias"
        os.link(selected_path, alias)
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            with self.assertRaises(StorageError):
                store.read_selected(self._validate)
        alias.unlink()

    def test_policy_directory_aggregate_capacity_is_bounded(self):
        payload = self.fx.snapshot_payload(revision=5)
        encoded = sign_snapshot(payload, self.fx.old_snapshot_key)
        current_bytes = self.baseline_policy
        total = len(current_bytes)
        limit = total + len(encoded) - 1
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            with patch("steamboat_security.root_transition_storage.MAX_POLICY_TOTAL_BYTES", limit):
                with self.assertRaises(StorageError):
                    store.advance_policy(encoded,
                        expected_old_selector_sha256=self.old_head,
                        clock=self.clock_source.clock, validate=self._validate)
        self.assertFalse((self.root / "pending.json").exists())

    def test_cold_commit_cannot_rewrite_same_generation_or_rollback_head(self):
        baseline_bundle = {
            "activation_manifest.json": canonical_json({"manifest": "baseline"}),
            "policy_snapshot.json": self.baseline_policy,
            "ca_certificate.pem": self.fx.old_ca,
            "snapshot_signer_public.pem": self.fx.old_snapshot_public,
        }
        before_files = set(os.listdir(self.root / "policies"))
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            self.assertEqual(store.commit(self.selector, baseline_bundle,
                active_policy_snapshot=self.baseline_policy,
                expected_old_selector_sha256=self.old_head,
                validate=self._validate), self.old_head)
        self.assertEqual(set(os.listdir(self.root / "policies")), before_files)
        self.assertFalse((self.root / "pending.json").exists())
        higher = self.fx.snapshot_payload(revision=5)
        encoded, head5 = self._advance(higher)
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            current = store.read_selected(self._validate)
            before_files = set(os.listdir(self.root / "policies"))
            self.assertEqual(store.commit(current.selector, dict(current.artifacts),
                active_policy_snapshot=current.active_policy_snapshot,
                expected_old_selector_sha256=current.selector_sha256,
                validate=self._validate), head5)
            self.assertEqual(set(os.listdir(self.root / "policies")), before_files)
            current_after = store.read_selected(self._validate)
            self.assertEqual(current_after.selector_sha256, head5)
            self.assertEqual(current_after.active_policy_snapshot, encoded)
            # An old preparation selector cannot reset an advanced generation.
            with self.assertRaises(StorageError):
                store.commit(self.selector, baseline_bundle,
                    active_policy_snapshot=self.baseline_policy,
                    expected_old_selector_sha256=head5, validate=self._validate)
            self.assertEqual(store.read_selected(self._validate).selector.policy_revision, 5)

            lower_bundle = {
                "activation_manifest.json": canonical_json({"manifest": "rollback"}),
                "policy_snapshot.json": self.baseline_policy,
                "ca_certificate.pem": self.fx.old_ca,
                "snapshot_signer_public.pem": self.fx.old_snapshot_public,
            }
            hashes = {name: _sha(data) for name, data in lower_bundle.items()}
            lower_selector = RootGenerationSelector(
                generation_sha256=_sha(b"lower-cold-generation"),
                activation_manifest_sha256=hashes["activation_manifest.json"],
                policy_revision=4, policy_digest=self.selector.policy_digest,
                active_policy_snapshot_sha256=self.selector.active_policy_snapshot_sha256,
                artifact_sha256=hashes)
            with self.assertRaises(StorageError):
                store.commit(lower_selector, lower_bundle,
                    active_policy_snapshot=self.baseline_policy,
                    expected_old_selector_sha256=head5, validate=self._validate)
            self.assertEqual(store.read_selected(self._validate).selector.policy_revision, 5)
        self.assertFalse((self.root / "pending.json").exists())

    def test_competing_cold_transition_and_policy_refresh_have_one_winner(self):
        payload = self.fx.snapshot_payload(revision=5)
        incoming = sign_snapshot(payload, self.fx.old_snapshot_key)
        cold_bundle = {
            "activation_manifest.json": canonical_json({"manifest": "new-cold"}),
            "policy_snapshot.json": incoming,
            "ca_certificate.pem": self.fx.old_ca,
            "snapshot_signer_public.pem": self.fx.old_snapshot_public,
        }
        artifact_hashes = {name: _sha(data) for name, data in cold_bundle.items()}
        cold_selector = RootGenerationSelector(
            generation_sha256=_sha(b"competing-cold-generation"),
            activation_manifest_sha256=artifact_hashes["activation_manifest.json"],
            policy_revision=payload["revision"],
            policy_digest=canonical_policy_digest(payload),
            active_policy_snapshot_sha256=_sha(incoming),
            artifact_sha256=artifact_hashes,
        )
        ctx = multiprocessing.get_context("fork")
        start = ctx.Event()
        output = ctx.Queue()
        processes = [
            ctx.Process(target=_race_cold, args=(str(self.root), self.uid,
                self.old_head, cold_bundle, cold_selector, start, output)),
            ctx.Process(target=_race_refresh, args=(str(self.root), self.uid,
                self.old_head, incoming, self.clock_source.clock, start, output)),
        ]
        started = []
        try:
            for process in processes:
                process.start()
                started.append(process)
            start.set()
            outcomes = [output.get(timeout=15) for _ in processes]
            for process in started:
                process.join(timeout=15)
        finally:
            start.set()
            for process in started:
                if process.is_alive():
                    process.terminate()
            for process in started:
                process.join(timeout=3)
                if process.is_alive() and hasattr(process, "kill"):
                    process.kill()
                    process.join(timeout=3)
            output.cancel_join_thread()
            output.close()
            for process in started:
                self.assertIsNotNone(process.exitcode)
        self.assertEqual(len(outcomes), 2)
        self.assertEqual(outcomes.count("rejected"), 1)
        self.assertEqual(len([item for item in outcomes if item in {"cold", "refresh"}]), 1)
        self.assertNotIn("error", outcomes)
        with RootGenerationStore(self.root, expected_uid=self.uid) as store:
            selected = store.read_selected(self._validate)
        if "cold" in outcomes:
            self.assertEqual(selected.selector.generation_sha256,
                             cold_selector.generation_sha256)
            self.assertEqual(selected.active_policy_snapshot, incoming)
        else:
            self.assertEqual(selected.active_policy_snapshot, incoming)


if __name__ == "__main__":
    unittest.main()
