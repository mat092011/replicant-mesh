"""Contract tests for bounded C1b remote restart control records."""

from __future__ import annotations

import copy
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "security"))
sys.path.insert(0, str(ROOT / "lab"))

from secure_pipeline_fixture import SecurePipelineIdentityFixture
from lab.secure_cohort_boot import prepare_boot_generation
from lab import secure_cohort, secure_cohort_supervisor
from lab.secure_cohort_supervisor import HANDOFF_ROOT
from lab.secure_cohort_restart import (
    BASELINE_CASES,
    LOCAL_COORDINATOR_CLEANUP_SECONDS,
    PROFILE_C1B_RESTART,
    RESTART_BUNDLE_FIELDS,
    RESTART_CASES,
    RESTART_GENERATION_ROOT_NAME,
    REMOTE_NEW_STARTUP_SECONDS,
    RESTART_OLD_SESSION_CASE,
    RESTART_OVERALL_SECONDS,
    RESTART_READY_FIELDS,
    RESTART_STALE_BINDING_CASE,
    REMOTE_OLD_RETIREMENT_SECONDS,
    RestartContractError,
    STOP_ACK_FIELDS,
    STOP_OWNER_FIELDS,
    borrow_restart_generation,
    validate_restart_bundle_ready,
    validate_restart_ready_ack,
    validate_restart_stop_ack,
)


MODEL_FINGERPRINT = "a" * 64
RUN_ID = "1" * 32
OLD_NONCE = "2" * 32
NEW_NONCE = "3" * 32
OLD_BOOT = "4" * 32
NEW_BOOT = "5" * 32
OLD_SNAPSHOT = "6" * 64
NEW_SNAPSHOT = "7" * 64
MANIFEST = "8" * 64
HOST_KEY = "9" * 64
ENDPOINT = "127.0.0.1:39123"


def stop_ack():
    return {
        "schema_version": 1,
        "event": "restart_stopped",
        "run_id": RUN_ID,
        "old_nonce": OLD_NONCE,
        "old_boot_id": OLD_BOOT,
        "manifest_fingerprint": MANIFEST,
        "endpoint": ENDPOINT,
        "ssh_host_key_sha256": HOST_KEY,
        "old_owner": {
            "container_id": "a" * 64,
            "image_sha256": "b" * 64,
            "exit_code": 0,
            "ownership_verified": True,
            "process_state": "exited",
            "container_removed": True,
            "shutdown_confirmed": True,
            "private_files_removed": True,
            "job_root_removed": True,
            "stop_arm_monotonic_ns": 1000,
            "exit_monotonic_ns": 2000,
            "elapsed_ns": 1000,
        },
    }


def bundle_ready(receipt_digest):
    return {
        "schema_version": 1,
        "event": "restart_bundle_ready",
        "run_id": RUN_ID,
        "old_nonce": OLD_NONCE,
        "new_nonce": NEW_NONCE,
        "old_boot_id": OLD_BOOT,
        "new_boot_id": NEW_BOOT,
        "old_snapshot_sha256": OLD_SNAPSHOT,
        "new_snapshot_sha256": NEW_SNAPSHOT,
        "old_owner_receipt_sha256": receipt_digest,
        "bundle": {
            "schema_version": 1,
            "event": "bundle_ready",
            "run_id": RUN_ID,
            "nonce": NEW_NONCE,
            "bundle_path": f"{HANDOFF_ROOT}/c1b/{RESTART_GENERATION_ROOT_NAME}/bundle",
            "expected_boot_id": NEW_BOOT,
            "manifest_fingerprint": MANIFEST,
            "snapshot_sha256": NEW_SNAPSHOT,
            "endpoint": ENDPOINT,
            "worker_name": "worker-3",
        },
    }


def ready_envelope(receipt_digest, bundle):
    return {
        "schema_version": 1,
        "event": "restart_ready_ack",
        "run_id": RUN_ID,
        "old_nonce": OLD_NONCE,
        "new_nonce": NEW_NONCE,
        "old_boot_id": OLD_BOOT,
        "new_boot_id": NEW_BOOT,
        "old_owner_receipt_sha256": receipt_digest,
        "ready_ack": {
            "schema_version": 1,
            "event": "ready_ack",
            "run_id": RUN_ID,
            "nonce": NEW_NONCE,
            "boot_id": NEW_BOOT,
            "manifest_fingerprint": bundle["manifest_fingerprint"],
            "snapshot_sha256": bundle["snapshot_sha256"],
            "endpoint": bundle["endpoint"],
            "ssh_host_key_sha256": HOST_KEY,
            "remote_status_uid": 1000,
            "remote_status_mode": 0o600,
            "remote_status_mtime_ns": 2000,
            "measurement_label": "c0_ready_status_v1",
            "remote_status": {"event": "ready"},
        },
    }


class RestartContractTests(unittest.TestCase):
    def test_package_import_is_stdlib_only_without_path_injection(self):
        code = (
            "import sys; "
            f"sys.path.insert(0, {str(ROOT)!r}); "
            "import lab.secure_cohort_restart; "
            "bad = [name for name in sys.modules if "
            "name in ('secure_cohort_boot', 'lab.secure_cohort_boot') "
            "or name.startswith("
            "('steamboat_runtime', 'steamboat_security'))]; "
            "assert not bad, bad"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", code],
            capture_output=True, text=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def stop_digest(self, value=None):
        return validate_restart_stop_ack(
            stop_ack() if value is None else value,
            run_id=RUN_ID,
            old_nonce=OLD_NONCE,
            old_boot_id=OLD_BOOT,
            manifest_fingerprint=MANIFEST,
            endpoint=ENDPOINT,
            ssh_host_key_sha256=HOST_KEY,
            stop_arm_monotonic_ns=1000,
        )

    def test_profile_observations_deadlines_and_fixed_file_names(self):
        self.assertEqual(PROFILE_C1B_RESTART, "c1b-restart-v1")
        self.assertEqual(BASELINE_CASES, (
            (1, "greedy-one-token"),
            (2, "forced-length-1"),
            (3, "forced-length-128"),
            (4, "forced-length-1024"),
        ))
        self.assertEqual(RESTART_OLD_SESSION_CASE,
                         (5, "restart-old-session-held"))
        self.assertEqual(RESTART_STALE_BINDING_CASE,
                         (6, "restart-new-boot-stale-binding-rejected"))
        self.assertEqual(RESTART_CASES[6:], (
            (7, "restart-new-greedy-one-token"),
            (8, "restart-new-forced-length-1"),
            (9, "restart-new-forced-length-128"),
            (10, "restart-new-forced-length-1024"),
        ))
        self.assertEqual((REMOTE_OLD_RETIREMENT_SECONDS,
                          REMOTE_NEW_STARTUP_SECONDS,
                          LOCAL_COORDINATOR_CLEANUP_SECONDS,
                          RESTART_OVERALL_SECONDS), (15, 60, 40, 300))

    def test_stop_ack_is_closed_and_returns_canonical_full_record_digest(self):
        payload = stop_ack()
        digest = self.stop_digest(payload)
        self.assertEqual(len(digest), 64)
        self.assertEqual(self.stop_digest(copy.deepcopy(payload)), digest)
        self.assertEqual(STOP_ACK_FIELDS, frozenset(payload))
        self.assertEqual(STOP_OWNER_FIELDS, frozenset(payload["old_owner"]))
        for change in (
                lambda p: p.update(extra=True),
                lambda p: p["old_owner"].update(extra=True),
                lambda p: p["old_owner"].update(ownership_verified=1),
                lambda p: p["old_owner"].update(exit_code=1),
                lambda p: p["old_owner"].update(process_state="running"),
                lambda p: p["old_owner"].update(elapsed_ns=True),
                lambda p: p["old_owner"].update(elapsed_ns=15_000_000_001),
                lambda p: p["old_owner"].update(exit_monotonic_ns=1999),
                lambda p: p.update(old_nonce=NEW_NONCE),
                lambda p: p.update(ssh_host_key_sha256="x"),
        ):
            broken = copy.deepcopy(payload)
            change(broken)
            with self.subTest(broken=broken):
                with self.assertRaises(RestartContractError):
                    self.stop_digest(broken)
        with self.assertRaises(RestartContractError):
            validate_restart_stop_ack(
                payload, run_id=RUN_ID, old_nonce=OLD_NONCE,
                old_boot_id=OLD_BOOT, manifest_fingerprint=MANIFEST,
                endpoint=ENDPOINT, ssh_host_key_sha256=HOST_KEY,
                stop_arm_monotonic_ns=999)

    def test_bundle_envelope_binds_disjoint_nonce_boot_snapshots_and_stop_receipt(self):
        digest = self.stop_digest()
        payload = bundle_ready(digest)
        calls = []

        def existing_bundle_validator(value, endpoint):
            calls.append((value, endpoint))
            return secure_cohort_supervisor._validate_bundle_ready(value, endpoint)

        validated = validate_restart_bundle_ready(
            payload, run_id=RUN_ID, old_nonce=OLD_NONCE, new_nonce=NEW_NONCE,
            old_boot_id=OLD_BOOT, new_boot_id=NEW_BOOT,
            old_snapshot_sha256=OLD_SNAPSHOT, new_snapshot_sha256=NEW_SNAPSHOT,
            old_owner_receipt_sha256=digest, manifest_fingerprint=MANIFEST,
            endpoint=ENDPOINT, bundle_validator=existing_bundle_validator)
        self.assertIs(validated, payload["bundle"])
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0][0], payload["bundle"])
        self.assertEqual(calls[0][1], ENDPOINT)
        self.assertEqual(RESTART_BUNDLE_FIELDS, frozenset(payload))
        broken_edits = (
            lambda p: p.update(extra=True),
            lambda p: p.update(new_nonce=OLD_NONCE),
            lambda p: p.update(new_nonce=OLD_BOOT),
            lambda p: p.update(new_boot_id=OLD_BOOT),
            lambda p: p.update(old_snapshot_sha256=NEW_SNAPSHOT),
            lambda p: p.update(new_snapshot_sha256=OLD_SNAPSHOT),
            lambda p: p.update(old_owner_receipt_sha256="f" * 64),
            lambda p: p["bundle"].update(expected_boot_id=OLD_BOOT),
            lambda p: p["bundle"].update(nonce=OLD_NONCE),
            lambda p: p["bundle"].update(extra_owner_data={"key": "value"}),
        )
        for edit in broken_edits:
            broken = copy.deepcopy(payload)
            edit(broken)
            with self.subTest(broken=broken):
                with self.assertRaises(RestartContractError):
                    validate_restart_bundle_ready(
                        broken, run_id=RUN_ID, old_nonce=OLD_NONCE,
                        new_nonce=NEW_NONCE, old_boot_id=OLD_BOOT,
                        new_boot_id=NEW_BOOT, old_snapshot_sha256=OLD_SNAPSHOT,
                        new_snapshot_sha256=NEW_SNAPSHOT,
                        old_owner_receipt_sha256=digest,
                        manifest_fingerprint=MANIFEST, endpoint=ENDPOINT,
                        bundle_validator=existing_bundle_validator)
        with self.assertRaises(RestartContractError):
            validate_restart_bundle_ready(
                payload, run_id=RUN_ID, old_nonce=OLD_NONCE, new_nonce=NEW_NONCE,
                old_boot_id=OLD_BOOT, new_boot_id=NEW_BOOT,
                old_snapshot_sha256=OLD_SNAPSHOT, new_snapshot_sha256=NEW_SNAPSHOT,
                old_owner_receipt_sha256=digest, manifest_fingerprint=MANIFEST,
                endpoint=ENDPOINT, bundle_validator=None)
        malformed_path = copy.deepcopy(payload)
        malformed_path["bundle"]["bundle_path"] = "/tmp/not-handoff/restart"
        with self.assertRaises(secure_cohort_supervisor.SupervisorError):
            validate_restart_bundle_ready(
                malformed_path, run_id=RUN_ID, old_nonce=OLD_NONCE,
                new_nonce=NEW_NONCE, old_boot_id=OLD_BOOT, new_boot_id=NEW_BOOT,
                old_snapshot_sha256=OLD_SNAPSHOT, new_snapshot_sha256=NEW_SNAPSHOT,
                old_owner_receipt_sha256=digest, manifest_fingerprint=MANIFEST,
                endpoint=ENDPOINT, bundle_validator=existing_bundle_validator)

    def test_ready_envelope_requires_matching_expectation_and_existing_validator(self):
        from tests.security.test_secure_cohort_lab import SecureCohortControlUnitTests

        digest = self.stop_digest()
        bundle = bundle_ready(digest)["bundle"]
        payload = ready_envelope(digest, bundle)
        fixture = SecureCohortControlUnitTests()
        fixture.setUp()
        expected = replace(fixture.expected, nonce=NEW_NONCE, boot_id=NEW_BOOT,
                           manifest_fingerprint=MANIFEST,
                           snapshot_sha256=NEW_SNAPSHOT, endpoint=ENDPOINT)
        fixture.expected = expected
        payload["ready_ack"] = fixture._ready_ack()
        calls = []

        def existing_ready_validator(value, actual_expected):
            calls.append((value, actual_expected))
            self.assertIs(actual_expected, expected)
            return secure_cohort.validate_ready_ack(value, actual_expected)

        self.assertEqual(validate_restart_ready_ack(
            payload, run_id=RUN_ID, old_nonce=OLD_NONCE, new_nonce=NEW_NONCE,
            old_boot_id=OLD_BOOT, new_boot_id=NEW_BOOT,
            old_owner_receipt_sha256=digest,
            expected_ssh_host_key_sha256=HOST_KEY, bundle=bundle, expected=expected,
            ready_validator=existing_ready_validator), HOST_KEY)
        self.assertEqual(len(calls), 1)
        self.assertEqual(RESTART_READY_FIELDS, frozenset(payload))
        for field, value in (("new_nonce", OLD_NONCE),
                             ("new_boot_id", OLD_BOOT),
                             ("old_owner_receipt_sha256", "f" * 64)):
            broken = copy.deepcopy(payload)
            broken[field] = value
            with self.subTest(field=field):
                with self.assertRaises(RestartContractError):
                    validate_restart_ready_ack(
                        broken, run_id=RUN_ID, old_nonce=OLD_NONCE,
                        new_nonce=NEW_NONCE, old_boot_id=OLD_BOOT,
                        new_boot_id=NEW_BOOT, old_owner_receipt_sha256=digest,
                        expected_ssh_host_key_sha256=HOST_KEY,
                        bundle=bundle, expected=expected,
                        ready_validator=existing_ready_validator)
        wrong_expected = SimpleNamespace(**vars(expected))
        wrong_expected.snapshot_sha256 = OLD_SNAPSHOT
        with self.assertRaises(RestartContractError):
            validate_restart_ready_ack(
                payload, run_id=RUN_ID, old_nonce=OLD_NONCE,
                new_nonce=NEW_NONCE, old_boot_id=OLD_BOOT,
                new_boot_id=NEW_BOOT, old_owner_receipt_sha256=digest,
                expected_ssh_host_key_sha256=HOST_KEY,
                bundle=bundle, expected=wrong_expected,
                ready_validator=existing_ready_validator)
        changed_host = copy.deepcopy(payload)
        changed_host["ready_ack"]["ssh_host_key_sha256"] = "f" * 64
        with self.assertRaises(RestartContractError):
            validate_restart_ready_ack(
                changed_host, run_id=RUN_ID, old_nonce=OLD_NONCE,
                new_nonce=NEW_NONCE, old_boot_id=OLD_BOOT,
                new_boot_id=NEW_BOOT, old_owner_receipt_sha256=digest,
                expected_ssh_host_key_sha256=HOST_KEY, bundle=bundle,
                expected=expected, ready_validator=existing_ready_validator)
        invalid_status = copy.deepcopy(payload)
        invalid_status["ready_ack"]["remote_status"]["phase"] = "unavailable"
        with self.assertRaises(secure_cohort.CohortError):
            validate_restart_ready_ack(
                invalid_status, run_id=RUN_ID, old_nonce=OLD_NONCE,
                new_nonce=NEW_NONCE, old_boot_id=OLD_BOOT,
                new_boot_id=NEW_BOOT, old_owner_receipt_sha256=digest,
                expected_ssh_host_key_sha256=HOST_KEY, bundle=bundle,
                expected=expected, ready_validator=existing_ready_validator)

    def test_borrowed_generation_is_immutable_and_does_not_own_fixture(self):
        authority = SecurePipelineIdentityFixture(MODEL_FINGERPRINT)
        phase_root = Path(authority.root) / RESTART_GENERATION_ROOT_NAME
        try:
            phase_root.mkdir(mode=0o700)
            if os.name == "posix":
                phase_root.chmod(0o700)
            generation = prepare_boot_generation(authority, {
                "coordinator": "a" * 32,
                "worker-1": "b" * 32,
                "worker-2": "c" * 32,
                "worker-3": "d" * 32,
            })
            original_snapshot = authority.signed_snapshot
            original_principals = dict(authority.principals)
            original_sans = dict(authority.ip_sans_by_principal)
            view = borrow_restart_generation(authority, generation, phase_root)
            self.assertEqual(view.root, phase_root)
            self.assertEqual(view.model_id, MODEL_FINGERPRINT)
            self.assertEqual(view.cohort_ca_pem, authority.cohort_ca_pem)
            self.assertEqual(view.snapshot_verification_key_pem,
                             authority.snapshot_verification_key_pem)
            self.assertIs(view.principals, generation.principals)
            self.assertEqual(dict(view.ip_sans_by_principal), original_sans)
            with self.assertRaises(TypeError):
                view.ip_sans_by_principal["worker-3"] = ("192.0.2.1",)
            with self.assertRaises(TypeError):
                view.principals["worker-3"] = original_principals["worker-3"]
            with self.assertRaises(TypeError):
                view.principals["worker-3"].record["credential_epoch"] = 9
            store, _clock = view.new_store()
            self.assertEqual(store.current().revision, generation.revision)
            self.assertEqual(authority.signed_snapshot, original_snapshot)
            self.assertEqual(authority.principals, original_principals)
            self.assertEqual(dict(authority.ip_sans_by_principal), original_sans)
            with self.assertRaises(RestartContractError):
                borrow_restart_generation(authority, generation,
                                          phase_root.parent / "wrong-generation")
        finally:
            if phase_root.exists():
                phase_root.rmdir()
            authority.close()

    @unittest.skipUnless(os.name == "posix", "requires POSIX private UDS path checks")
    def test_actual_generation_fixture_fits_bounded_backend_and_client_socket_paths(self):
        with tempfile.TemporaryDirectory(prefix="tmp", dir="/tmp") as short_parent:
            os.chmod(short_parent, 0o700)
            self._assert_actual_generation_socket_paths(Path(short_parent))

    def _assert_actual_generation_socket_paths(self, short_parent):
        from steamboat_runtime.protocol.secure_acceptor import (
            _GateConnection,
            new_private_socket_path,
            validate_private_unix_directory,
        )

        previous_tempdir = tempfile.tempdir
        tempfile.tempdir = str(short_parent)
        authority = None
        phase_root = None
        acceptor_directory = None
        try:
            authority = SecurePipelineIdentityFixture(MODEL_FINGERPRINT)
            self.assertEqual(Path(authority.root).parent, short_parent)
            self.assertTrue(Path(authority.root).name.startswith(
                "steamboat-secure-pipeline-"))
            self.assertEqual(len(os.fsencode(authority.root)), 51)
            phase_root = Path(authority.root) / RESTART_GENERATION_ROOT_NAME
            phase_root.mkdir(mode=0o700)
            phase_root.chmod(0o700)
            generation = prepare_boot_generation(authority, {
                "coordinator": "a" * 32,
                "worker-1": "b" * 32,
                "worker-2": "c" * 32,
                "worker-3": "d" * 32,
            })
            view = borrow_restart_generation(authority, generation, phase_root)
            self.assertEqual(view.root, phase_root)

            acceptor_directory = (
                phase_root / secure_cohort.LOCAL_COHORT_ACCEPTOR_DIRECTORY_NAME)
            acceptor_directory.mkdir(mode=0o700)
            acceptor_directory.chmod(0o700)
            private_directory = validate_private_unix_directory(acceptor_directory)
            directory_bytes = len(os.fsencode(private_directory))
            self.assertEqual(directory_bytes, 56)
            self.assertLessEqual(directory_bytes, 70)

            backend = new_private_socket_path(
                private_directory, name="backend-0123456789ab.sock")
            connection = _GateConnection(
                SimpleNamespace(private_directory=private_directory), None, None, None)
            self.assertEqual(connection.client_directory.parent, private_directory)
            self.assertEqual(connection.client_path.name, "gate-client.sock")
            self.assertEqual(len(os.fsencode(connection.client_path)), 92)
            self.assertLessEqual(len(os.fsencode(backend)), 100)
        finally:
            tempfile.tempdir = previous_tempdir
            if acceptor_directory is not None:
                acceptor_directory.rmdir()
            if phase_root is not None:
                phase_root.rmdir()
            if authority is not None:
                authority.close()


if __name__ == "__main__":
    unittest.main()
