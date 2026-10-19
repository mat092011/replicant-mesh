"""Tests for test-only C0 boot generations and genuine trusted probe contexts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "security"))
sys.path.insert(0, str(ROOT / "lab"))

from secure_pipeline_fixture import SecurePipelineIdentityFixture
import secure_cohort_boot as boot_module
from secure_cohort_boot import (
    BootGenerationError,
    build_trusted_probe_context,
    prepare_boot_generation,
)
from steamboat_security import (
    Authorizer,
    BindingError,
    LocalIdentity,
    ScopeError,
    SessionBindings,
    SnapshotError,
    new_id,
    new_boot_id,
    sign_snapshot,
)
from steamboat_security.codec import (
    COORDINATOR_SERVICE,
    WORKER_SERVICE,
    encode_binding,
)
from steamboat_runtime.secure_context import ConsumerContextAdmissionError


MODEL_FINGERPRINT = "a" * 64
def new_boot_map():
    return {name: new_boot_id() for name in
            ("coordinator", "worker-1", "worker-2", "worker-3")}


class SecureCohortBootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = SecurePipelineIdentityFixture(MODEL_FINGERPRINT)

    @classmethod
    def tearDownClass(cls):
        cls.authority.close()

    def make_generation(self):
        return prepare_boot_generation(self.authority, new_boot_map())

    def test_generation_advances_signed_policy_and_preserves_every_leaf(self):
        original_snapshot = self.authority.signed_snapshot
        original_principals = dict(self.authority.principals)
        generation = self.make_generation()

        self.assertEqual(generation.revision, 2)
        self.assertEqual(set(generation.boot_ids), {
            "coordinator", "worker-1", "worker-2", "worker-3"})
        self.assertEqual(generation.principals["consumer"].boot_id,
                         original_principals["consumer"].boot_id)
        self.assertEqual(self.authority.signed_snapshot, original_snapshot)
        self.assertEqual(self.authority.principals, original_principals)
        self.assertEqual(generation.snapshot_sha256,
                         hashlib.sha256(generation.signed_snapshot).hexdigest())
        self.assertEqual(generation.verification_key_pem,
                         self.authority.snapshot_verification_key_pem)
        self.assertEqual(generation.ca_certificate_pem, self.authority.cohort_ca_pem)
        with self.assertRaises(TypeError):
            generation.principals["worker-3"].record["credential_epoch"] = 2

        old_store, _old_clock = self.authority.new_store()
        new_store, _new_clock = generation.new_store()
        old_view, new_view = old_store.current(), new_store.current()
        self.assertEqual(old_view.revision, 1)
        self.assertEqual(new_view.revision, old_view.revision + 1)
        self.assertNotEqual(new_view.policy_digest, old_view.policy_digest)
        self.assertEqual(new_view.credentials_by_serial,
                         old_view.credentials_by_serial)
        self.assertEqual(new_view.revoked_serials, old_view.revoked_serials)
        self.assertEqual(new_view.revoked_devices, old_view.revoked_devices)

        old_grants = [grant.__dict__ for grant in old_view.grants]
        new_grants = [grant.__dict__ for grant in new_view.grants]
        allowed = {"target_boot_id", "actor_boot_id", "not_before", "not_after"}
        worker_boot_by_device = {
            generation.principals[f"worker-{index}"].device_id:
            generation.boot_ids[f"worker-{index}"]
            for index in (1, 2, 3)
        }
        self.assertEqual(len(old_grants), len(new_grants))
        for before, after in zip(old_grants, new_grants):
            self.assertEqual(set(before), set(after))
            self.assertTrue(all(before[key] == after[key]
                                for key in before if key not in allowed))
            self.assertEqual(after["not_before"], new_view.issued_at)
            self.assertEqual(after["not_after"], new_view.expires_at)
            if before["method"].startswith(f"{WORKER_SERVICE}/"):
                self.assertEqual(after["target_boot_id"],
                                 worker_boot_by_device[before["target_device_id"]])
                self.assertEqual(after["actor_boot_id"],
                                 generation.boot_ids["coordinator"])
            else:
                self.assertTrue(before["method"].startswith(
                    f"{COORDINATOR_SERVICE}/"))
                self.assertEqual(after["target_boot_id"],
                                 generation.boot_ids["coordinator"])
                self.assertIsNone(after["actor_boot_id"])

        for name, old in original_principals.items():
            fresh = generation.principals[name]
            self.assertEqual(fresh.certificate_pem, old.certificate_pem)
            self.assertEqual(fresh.private_key_pem, old.private_key_pem)
            self.assertEqual(fresh.record, old.record)
            self.assertEqual(fresh.boot_id,
                             generation.boot_ids.get(name, old.boot_id))

    def test_new_boot_grant_is_authorized_and_old_boot_rejects_before_claim(self):
        from steamboat_runtime.protocol.worker_pb2 import Request

        generation = self.make_generation()
        store, clock = generation.new_store()
        coordinator = generation.principals["coordinator"]
        worker = generation.principals["worker-3"]
        sessions = SessionBindings(clock=clock)
        authorizer = Authorizer(
            local_identity=LocalIdentity(
                worker.certificate_pem, worker.boot_id,
                generation.model_fingerprint, worker.assignment_id),
            snapshot_store=store, clock=clock, session_bindings=sessions,
            worker_request_type=Request)

        def common_binding(worker_boot):
            return {
                "binding_version": 1,
                "operation_id": new_id("op"),
                "account_id": coordinator.account_id,
                "device_id": coordinator.device_id,
                "role": coordinator.role,
                "credential_epoch": coordinator.record["credential_epoch"],
                "target_device_id": worker.device_id,
                "worker_boot_id": worker_boot,
            }

        binding = common_binding(generation.boot_ids["worker-3"])
        binding.update({
            "assignment_id": worker.assignment_id,
            "coordinator_boot_id": generation.boot_ids["coordinator"],
            "tenant_account_id": coordinator.account_id,
            "request_id": new_id("req"),
            "session_id": new_id("ses"),
            "route_id": new_id("route"),
            "route_epoch": 1,
            "attempt": 1,
        })
        payload = Request(
            protocol_version=1,
            manifest_fingerprint=generation.model_fingerprint,
            worker_boot_id=generation.boot_ids["worker-3"],
            session_id=binding["session_id"],
            timeout_ms=30_000,
            max_positions=8,
            lifetime_ms=30_000,
            idle_lease_ms=5_000,
        )
        metadata = (("steamboat-binding-bin",
                     encode_binding(WORKER_SERVICE, "OpenSession", binding)),)
        authorization = authorizer.authorize(
            WORKER_SERVICE, "OpenSession", payload, metadata,
            coordinator.certificate_pem)
        self.assertEqual(authorization.grant.target_boot_id, worker.boot_id)
        self.assertEqual(sessions.record_count(), 1)
        authorization.close()

        stale = common_binding(self.authority.principals["worker-3"].boot_id)
        stale.update({
            "coordinator_boot_id": self.authority.principals["coordinator"].boot_id,
            "tenant_account_id": coordinator.account_id,
            "request_id": new_id("req"),
            "session_id": new_id("ses"),
            "route_id": new_id("route"),
            "route_epoch": 1,
            "attempt": 1,
            "assignment_id": worker.assignment_id,
        })
        stale_payload = Request(
            protocol_version=1,
            manifest_fingerprint=generation.model_fingerprint,
            worker_boot_id=stale["worker_boot_id"],
            session_id=stale["session_id"],
            timeout_ms=30_000,
            max_positions=8,
            lifetime_ms=30_000,
            idle_lease_ms=5_000)
        stale_metadata = (("steamboat-binding-bin",
                           encode_binding(WORKER_SERVICE, "OpenSession", stale)),)
        with self.assertRaises((BindingError, ScopeError)):
            authorizer.authorize(
                WORKER_SERVICE, "OpenSession", stale_payload, stale_metadata,
                coordinator.certificate_pem)
        self.assertEqual(sessions.record_count(), 1)
        # This test created only a core admission claim, no worker allocation.
        # Reclaim that exact owner after exercising the stale-boot refusal.
        self.assertTrue(sessions.mark_reclaimed(
            target_device_id=worker.device_id,
            worker_boot_id=generation.boot_ids["worker-3"],
            session_id=binding["session_id"]))

    def test_generate_probe_payload_matches_actual_remote_validator(self):
        from steamboat_runtime.remote_client import RemoteError, validate_generate

        self.assertEqual(validate_generate({
            "input_ids": [1, 2],
            "new_tokens": 1,
            "forced_tokens": [],
            "timeout_seconds": 30.0,
            "capture_logits": False,
        })["new_tokens"], 1)
        with self.assertRaises(RemoteError):
            validate_generate({
                "input_ids": [1, 2],
                "new_tokens": 1,
                "forced_tokens": [3],
                "timeout_seconds": 30.0,
                "capture_logits": False,
            })

    def test_probe_timeout_rejects_invalid_values_before_authority_access(self):
        for invalid in (True, False, 0, -1, 301, 30.0, "120", None):
            with self.subTest(timeout_seconds=invalid):
                with self.assertRaises(BootGenerationError):
                    build_trusted_probe_context(object(),
                                               timeout_seconds=invalid)

    @unittest.skipUnless(os.name == "posix", "POSIX protected-file checks")
    def test_operator_signer_reader_rejects_root_and_key_path_attacks(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            base.chmod(0o700)

            root_link = base / "root-link"
            root_link.symlink_to(Path(self.authority.root), target_is_directory=True)
            with self.assertRaises(BootGenerationError):
                boot_module._read_private_signer(root_link)

            broad_root = base / "broad-root"
            broad_root.mkdir(mode=0o755)
            broad_root.chmod(0o755)
            (broad_root / boot_module._SIGNER_FILENAME).write_bytes(b"x")
            (broad_root / boot_module._SIGNER_FILENAME).chmod(0o600)
            with self.assertRaises(BootGenerationError):
                boot_module._read_private_signer(broad_root)

            key_link_root = base / "key-link-root"
            key_link_root.mkdir(mode=0o700)
            target = base / "target"
            target.write_bytes(b"not a signer")
            (key_link_root / boot_module._SIGNER_FILENAME).symlink_to(target)
            with self.assertRaises(BootGenerationError):
                boot_module._read_private_signer(key_link_root)

            mode_root = base / "mode-root"
            mode_root.mkdir(mode=0o700)
            mode_key = mode_root / boot_module._SIGNER_FILENAME
            mode_key.write_bytes(b"test")
            mode_key.chmod(0o644)
            with self.assertRaises(BootGenerationError):
                boot_module._read_private_signer(mode_root)

            hardlink_root = base / "hardlink-root"
            hardlink_root.mkdir(mode=0o700)
            hardlink_key = hardlink_root / boot_module._SIGNER_FILENAME
            hardlink_key.write_bytes(b"test")
            hardlink_key.chmod(0o600)
            os.link(hardlink_key, base / "extra-link")
            with self.assertRaises(BootGenerationError):
                boot_module._read_private_signer(hardlink_root)

    @unittest.skipUnless(os.name == "posix", "POSIX ownership semantics")
    def test_baked_foreign_owner_file_is_rejected_without_modification(self):
        fixture = Path(os.environ.get(
            "STEAMBOAT_IDENTITY_FOREIGN_FIXTURE",
            "/opt/steamboat-test/identity-root/foreign.pem"))
        if not fixture.is_file():
            self.skipTest("pinned Linux foreign-owner fixture is unavailable")
        before = fixture.stat()
        self.assertNotEqual(before.st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(before.st_mode), 0o600)
        with self.assertRaises(BootGenerationError):
            boot_module._read_protected_file(fixture.parent, fixture.name)
        after = fixture.stat()
        self.assertEqual((after.st_uid, after.st_gid, after.st_mode,
                          after.st_nlink, after.st_size, after.st_mtime_ns),
                         (before.st_uid, before.st_gid, before.st_mode,
                          before.st_nlink, before.st_size, before.st_mtime_ns))

    def test_higher_revision_rejects_rollback_and_same_revision_equivocation(self):
        generation = self.make_generation()
        store, _clock = generation.new_store()
        with self.assertRaises(SnapshotError):
            store.install(self.authority.signed_snapshot)

        altered = json.loads(store.current().canonical_payload)
        altered["revoked_devices"] = [new_id("dev")]
        signer = boot_module._read_private_signer(Path(self.authority.root))
        equivocation = sign_snapshot(altered, signer)
        with self.assertRaises(SnapshotError):
            store.install(equivocation)

    def test_malformed_boot_map_fails_before_operator_signer_read(self):
        invalid = new_boot_map()
        invalid["worker-3"] = "not-a-boot"
        with patch("secure_cohort_boot._read_private_signer",
                   side_effect=AssertionError("signer must not be read")) as read_signer:
            with self.assertRaises(BootGenerationError):
                prepare_boot_generation(self.authority, invalid)
        read_signer.assert_not_called()

    def test_probe_context_comes_from_actual_consumer_authorization_and_factory(self):
        generation = self.make_generation()
        probes = []
        try:
            old_probe = build_trusted_probe_context(self.authority)
            probes.append(old_probe)
            probe = build_trusted_probe_context(self.authority, generation=generation)
            probes.append(probe)
            long_probe = build_trusted_probe_context(
                self.authority, generation=generation, timeout_seconds=120)
            probes.append(long_probe)
            from steamboat_runtime.remote_client import validate_generate

            self.assertEqual(old_probe.payload["timeout_seconds"], 30.0)
            self.assertEqual(probe.payload["timeout_seconds"], 30.0)
            self.assertEqual(long_probe.payload["timeout_seconds"], 120.0)
            self.assertIs(validate_generate(long_probe.payload), long_probe.payload)
            self.assertIs(long_probe.context.authorization,
                          long_probe.authorization)
            self.assertGreater(long_probe.context.remaining_seconds(), 100.0)
            self.assertLessEqual(long_probe.context.remaining_seconds(), 120.0)
            self.assertLessEqual(long_probe.context.remaining_seconds(),
                                 long_probe.authorization.remaining_seconds())
            self.assertEqual(type(probe.authorization).__name__, "Authorization")
            self.assertIs(probe.context.authorization, probe.authorization)
            self.assertEqual(probe.context.request_id,
                             probe.authorization.binding["request_id"])
            self.assertEqual(probe.context.route_epoch, 1)
            self.assertEqual(probe.context.attempt, 1)
            self.assertEqual(probe.context.coordinator_boot_id,
                             generation.boot_ids["coordinator"])
            self.assertEqual(probe.outbound_authorizer.target.boot_id,
                             generation.boot_ids["worker-3"])
            self.assertEqual(probe.snapshot_store.current().revision,
                             generation.revision)
            probe.context.assert_data_live()
            self.assertEqual(old_probe.snapshot_store.current().revision, 1)
            self.assertEqual(old_probe.outbound_authorizer.target.boot_id,
                             self.authority.principals["worker-3"].boot_id)
            self.assertNotEqual(probe.context.request_id, old_probe.context.request_id)
            self.assertNotEqual(probe.context.session_id, old_probe.context.session_id)
            self.assertNotEqual(probe.context.route_id, old_probe.context.route_id)

            fake = SimpleNamespace(assert_live=lambda: True,
                                   remaining_seconds=lambda: 5.0)
            with self.assertRaises(ConsumerContextAdmissionError):
                probe.context_factory(fake, probe.payload)
        finally:
            for probe in reversed(probes):
                probe.close()


if __name__ == "__main__":
    unittest.main()
