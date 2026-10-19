from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from steamboat_connector.channel_policy_store import (
    HEAD_NAME,
    LOCK_NAME,
    PersistentChannelPolicyStore,
    _QUARANTINE,
    _QUARANTINE_LOCK,
    _QUARANTINE_MARKER,
)
from steamboat_security.channel_policy import canonical_json, sign_channel_policy
from steamboat_security.clock import Clock
from steamboat_security.errors import SnapshotError, StorageError


def _private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _public_pem(key):
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@unittest.skipUnless(os.name == "posix" and __import__("sys").platform.startswith("linux"),
                     "persistent channel policy owner is Linux-only")
class PersistentChannelPolicyStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "policy"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.wall, self.mono = 1000.0, 50.0
        self.clock = Clock(wall=lambda: self.wall, monotonic=lambda: self.mono,
                           uncertainty_seconds=lambda: 0.0)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.private_pem = _private_pem(self.key)
        self.public_pem = _public_pem(self.key)
        self.payload = {
            "version": 2, "revision": 1, "issued_at": 1000, "expires_at": 1100,
            "gateways": [{
                "gateway_id": "gw-east", "serial": "ab12",
                "certificate_sha256": "1" * 64, "public_key_sha256": "2" * 64,
                "not_before": 900, "not_after": 1500,
                "endpoint_host": "gateway.example.net", "endpoint_port": 443,
                "coordinator_endpoint_host": "coordinator.example.net",
                "coordinator_endpoint_port": 444,
            }],
            "workers": [{
                "account_id": "acct_" + "1" * 32,
                "device_id": "dev_" + "2" * 32, "host_serial": "ab13",
                "host_credential_epoch": 2, "host_certificate_sha256": "3" * 64,
                "worker_boot_id": "4" * 32, "assignment_id": "asg_" + "5" * 32,
                "model_id": "6" * 64, "channel_serial": "ab14",
                "channel_certificate_sha256": "7" * 64,
                "channel_public_key_sha256": "8" * 64,
                "not_before": 900, "not_after": 1500, "gateway_id": "gw-east",
            }],
            "routes": [{
                "gateway_id": "gw-east", "account_id": "acct_" + "1" * 32,
                "device_id": "dev_" + "9" * 32, "actor_serial": "ab15",
                "actor_credential_epoch": 3, "actor_certificate_sha256": "a" * 64,
                "coordinator_boot_id": "b" * 32,
                "tenant_account_id": "acct_" + "1" * 32,
                "target_device_id": "dev_" + "2" * 32,
                "worker_boot_id": "4" * 32, "assignment_id": "asg_" + "5" * 32,
                "model_id": "6" * 64, "methods": ["Describe", "Step"],
            }],
        }
        self.digest = hashlib.sha256(canonical_json(self.payload)).hexdigest()
        self.config = dict(expected_uid=os.geteuid(), verification_key_pem=self.public_pem,
                           clock=self.clock, minimum_revision=1,
                           minimum_policy_digest=self.digest)

    def tearDown(self):
        self.temp.cleanup()

    def sign(self, payload=None, key=None):
        return sign_channel_policy(self.payload if payload is None else payload,
                                   _private_pem(self.key if key is None else key))

    def provision(self, *, root=None, fault_hook=None):
        owner = PersistentChannelPolicyStore.provision(
            self.root if root is None else root, **self.config, _fault_hook=fault_hook)
        owner.install(self.sign())
        return owner

    def open_existing(self, root=None, **kwargs):
        options = dict(self.config)
        options.update(kwargs)
        return PersistentChannelPolicyStore.open_existing(
            self.root if root is None else root, **options)

    def test_provision_reopen_and_exact_payload_replay_are_durable(self):
        owner = self.provision()
        view = owner.current()
        self.assertEqual(view.revision, 1)
        with self.assertRaises(StorageError):
            self.open_existing()
        owner.close()

        # ECDSA may encode a different signature for the same canonical payload.
        replay = self.sign()
        self.assertEqual(owner.faulted, False)
        reopened = self.open_existing()
        self.assertEqual(reopened.current().policy_digest, view.policy_digest)
        self.assertEqual(reopened.install(replay), reopened.current())
        reopened.close()
        head = json.loads((self.root / HEAD_NAME).read_bytes())
        self.assertEqual(head["revision"], 1)
        self.assertEqual((self.root / LOCK_NAME).stat().st_mode & 0o777, 0o600)

    def test_revision_advance_and_reopen_obey_explicit_minimum_anchor(self):
        owner = self.provision()
        second_payload = {**self.payload, "revision": 2, "issued_at": 1000,
                          "expires_at": 1101}
        second = self.sign(second_payload)
        view = owner.install(second)
        self.assertEqual(view.revision, 2)
        owner.close()
        reopened = self.open_existing()
        self.assertEqual(reopened.current().revision, 2)
        reopened.close()

        with self.assertRaises(StorageError):
            self.open_existing(minimum_revision=2)
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(StorageError):
            self.open_existing(verification_key_pem=_public_pem(wrong_key))

    def test_expired_head_cannot_reopen_and_live_owner_can_write_fresh_revision(self):
        owner = self.provision()
        original_bytes = (self.root / HEAD_NAME).read_bytes()
        owner.close()
        self.wall, self.mono = 1100.0, 150.0
        with self.assertRaises(SnapshotError):
            self.open_existing()
        self.assertEqual((self.root / HEAD_NAME).read_bytes(), original_bytes)

        # A separately provisioned cold generation uses its own monotonic clock.
        # No clock rollback is used to simulate cold re-enrollment.
        live_root = self.root.parent / "live-policy"
        live_root.mkdir(mode=0o700)
        os.chmod(live_root, 0o700)
        fresh_time = {"wall": 1000.0, "mono": 50.0}
        fresh_clock = Clock(wall=lambda: fresh_time["wall"],
                            monotonic=lambda: fresh_time["mono"],
                            uncertainty_seconds=lambda: 0.0)
        owner = PersistentChannelPolicyStore.provision(
            live_root, **{**self.config, "clock": fresh_clock})
        owner.install(self.sign())
        fresh_time.update(wall=1100.0, mono=150.0)
        renewed = {**self.payload, "revision": 2, "issued_at": 1100,
                   "expires_at": 1200}
        self.assertEqual(owner.install(self.sign(renewed)).revision, 2)
        owner.close()

    def test_rollback_is_rejected_without_changing_current_head(self):
        owner = self.provision()
        changed = {**self.payload, "revision": 2, "issued_at": 1000,
                   "expires_at": 1101,
                   "routes": [{**self.payload["routes"][0], "methods": ["Describe"]}]}
        owner.install(self.sign(changed))
        with self.assertRaises(SnapshotError):
            owner.install(self.sign())
        self.assertEqual(owner.current().revision, 2)
        self.assertFalse(owner.faulted)
        owner.close()

    def test_same_revision_equivocation_is_rejected_without_changing_head(self):
        owner = self.provision()
        first = {**self.payload, "revision": 2, "issued_at": 1000,
                 "expires_at": 1101,
                 "routes": [{**self.payload["routes"][0], "methods": ["Describe"]}]}
        owner.install(self.sign(first))
        second = {**first, "routes": [{**first["routes"][0], "methods": ["Step"]}]}
        with self.assertRaises(SnapshotError):
            owner.install(self.sign(second))
        self.assertEqual(owner.current().policy_digest,
                         hashlib.sha256(canonical_json(first)).hexdigest())
        self.assertFalse(owner.faulted)
        owner.close()

    def test_durable_write_fault_does_not_publish_initial_policy(self):
        def fail(point):
            if point == "head.file.fsync":
                raise OSError("injected durable write failure")

        owner = PersistentChannelPolicyStore.provision(
            self.root, **self.config, _fault_hook=fail)
        with self.assertRaises(SnapshotError) as caught:
            owner.install(self.sign())
        self.assertIsInstance(caught.exception.__cause__, StorageError)
        self.assertIsInstance(caught.exception.__cause__.__cause__, OSError)
        self.assertTrue(owner.faulted)
        self.assertIsNone(owner._store._view)
        self.assertTrue((self.root / LOCK_NAME).exists())

    def test_open_rejects_corrupt_truncated_symlink_and_fifo_heads(self):
        owner = self.provision()
        owner.close()
        head_path = self.root / HEAD_NAME
        original = head_path.read_bytes()
        for corrupt in (b"{", original[:-1]):
            head_path.write_bytes(corrupt)
            with self.assertRaises(StorageError):
                self.open_existing()
        head_path.unlink()
        head_path.symlink_to(self.root / LOCK_NAME)
        with self.assertRaises(StorageError):
            self.open_existing()
        head_path.unlink()
        if hasattr(os, "mkfifo"):
            os.mkfifo(head_path, 0o600)
            with self.assertRaises(StorageError):
                self.open_existing()

    def test_out_of_band_head_change_fences_cas_and_prevents_publication(self):
        owner = self.provision()
        before = owner.current()
        data = (self.root / HEAD_NAME).read_bytes()
        (self.root / HEAD_NAME).write_bytes(data + b" ")
        advanced = {**self.payload, "revision": 2, "issued_at": 1000,
                    "expires_at": 1101}
        with self.assertRaises(StorageError):
            owner.install(self.sign(advanced))
        self.assertTrue(owner.faulted)
        self.assertEqual(owner._store._view, before)

    def test_storage_preflight_failure_latches_even_without_a_commit(self):
        owner = self.provision()
        (self.root / HEAD_NAME).write_bytes(b"foreign head")
        with self.assertRaises(StorageError):
            owner.current()
        self.assertTrue(owner.faulted)

    def test_ancestor_close_uncertainty_does_not_double_close_reused_fd(self):
        actual_close = os.close
        result = {}
        close_count = {"value": 0}

        def close_then_reuse(fd):
            close_count["value"] += 1
            if close_count["value"] == 1:
                actual_close(fd)
                reused = os.open(os.devnull, os.O_RDONLY)
                result["reused"] = reused
                raise OSError("close reported failure after releasing descriptor")
            if close_count["value"] == 2:
                actual_close(fd)
                raise KeyboardInterrupt("cleanup close reported failure after release")
            return actual_close(fd)

        before = sum(value is not None for value in _QUARANTINE)
        try:
            with patch("steamboat_connector.channel_policy_store.os.close",
                       side_effect=close_then_reuse):
                with self.assertRaises(StorageError) as caught:
                    PersistentChannelPolicyStore.provision(
                        self.root, **self.config)
            after = sum(value is not None for value in _QUARANTINE)
            self.assertEqual(after, before + 1)
            self.assertTrue(hasattr(caught.exception, "channel_policy_owner"))
            self.assertIn(caught.exception.channel_policy_owner, _QUARANTINE)
            os.fstat(result["reused"])
        finally:
            if "reused" in result:
                actual_close(result["reused"])

    def test_inflight_initializations_reserve_all_quarantine_capacity(self):
        first_root = self.root.parent / "capacity-first"
        second_root = self.root.parent / "capacity-second"
        first_root.mkdir(mode=0o700)
        second_root.mkdir(mode=0o700)
        os.chmod(first_root, 0o700)
        os.chmod(second_root, 0o700)
        with _QUARANTINE_LOCK:
            prior = list(_QUARANTINE)
            _QUARANTINE[:] = [_QUARANTINE_MARKER] * (len(_QUARANTINE) - 1) + [None]

        actual_open = os.open
        entered = threading.Event()
        resume = threading.Event()
        results = {}

        def blocked_open(*args, **kwargs):
            if not entered.is_set():
                entered.set()
                if not resume.wait(2.0):
                    raise TimeoutError("test failed to release first initializer")
            return actual_open(*args, **kwargs)

        def first_initializer():
            try:
                results["owner"] = PersistentChannelPolicyStore.provision(
                    first_root, **self.config)
            except BaseException as error:
                results["error"] = error

        worker = threading.Thread(
            target=first_initializer)
        try:
            with patch("steamboat_connector.channel_policy_store.os.open",
                       side_effect=blocked_open):
                worker.start()
                self.assertTrue(entered.wait(1.0))
                with self.assertRaises(StorageError):
                    PersistentChannelPolicyStore.provision(
                        second_root, **self.config)
                resume.set()
                worker.join(2.0)
            self.assertFalse(worker.is_alive())
            self.assertNotIn("error", results)
            results["owner"].close()
        finally:
            resume.set()
            if worker.is_alive():
                worker.join(2.0)
            with _QUARANTINE_LOCK:
                current = list(_QUARANTINE)
                _QUARANTINE[:] = [
                    previous if previous is not None else
                    (current[index] if current[index] is not _QUARANTINE_MARKER else None)
                    for index, previous in enumerate(prior)
                ]


if __name__ == "__main__":
    unittest.main()
