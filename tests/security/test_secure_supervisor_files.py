"""Synthetic file-protocol tests for the bounded secure cohort supervisor."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

from lab import secure_cohort_supervisor as supervisor


TEST_EXTERNAL_IP = "10.23.45.67"
TEST_OTHER_EXTERNAL_IP = "10.23.45.68"
TEST_ENDPOINT = f"{TEST_EXTERNAL_IP}:50061"


_POSIX_FILE_HELPERS = (
    os.name == "posix"
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "geteuid")
    and hasattr(os, "getegid")
    and hasattr(os, "fchown")
    and os.open in getattr(os, "supports_dir_fd", set())
    and os.link in getattr(os, "supports_dir_fd", set())
)


class SecureSupervisorFileProtocolTests(unittest.TestCase):
    def setUp(self):
        self.expected_endpoint = TEST_ENDPOINT
        self.snapshot = b'{"synthetic":"signed-snapshot-fixture"}'
        self.manifest = "a" * 64
        self.ready = {
            "schema_version": 1,
            "event": "bundle_ready",
            "run_id": "1" * 32,
            "nonce": "2" * 32,
            "bundle_path": "/tmp/handoff/synthetic/worker-3-bundle",
            "expected_boot_id": "3" * 32,
            "manifest_fingerprint": self.manifest,
            "snapshot_sha256": hashlib.sha256(self.snapshot).hexdigest(),
            "endpoint": self.expected_endpoint,
            "worker_name": "worker-3",
        }
        self.config = {
            "schema_version": 1,
            "protected_root": supervisor.REMOTE_ROOT,
            "account_id": "acct_" + "4" * 32,
            "device_id": "dev_" + "5" * 32,
            "boot_id": self.ready["expected_boot_id"],
            "assignment_id": "asg_" + "6" * 32,
            "worker_name": "worker-3",
            "model_id": supervisor.MODEL_ID,
            "model_revision": supervisor.MODEL_REVISION,
            "manifest_fingerprint": self.manifest,
            "listen_ip": TEST_EXTERNAL_IP,
            "listen_port": supervisor.REMOTE_PORT,
            "clock_uncertainty_seconds": 2.0,
            "certificate_path": f"{supervisor.REMOTE_ROOT}/host.crt",
            "private_key_path": f"{supervisor.REMOTE_ROOT}/host.key",
            "cohort_ca_path": f"{supervisor.REMOTE_ROOT}/cohort-ca.crt",
            "snapshot_verification_key_path": f"{supervisor.REMOTE_ROOT}/snapshot.pub",
            "signed_snapshot_path": f"{supervisor.REMOTE_ROOT}/snapshot.json",
            "artifact_directory": "/artifacts",
            "acceptor_directory": f"{supervisor.REMOTE_ROOT}/sockets",
            "status_report_path": f"{supervisor.REMOTE_ROOT}/status.json",
        }

    def _bundle_files(self):
        return {
            "worker.json": json.dumps(self.config, sort_keys=True,
                                       separators=(",", ":")).encode("utf-8"),
            "host.crt": b"synthetic host certificate",
            "host.key": b"synthetic host private key; not a credential",
            "cohort-ca.crt": b"synthetic CA certificate",
            "snapshot.pub": b"synthetic snapshot verification key",
            "snapshot.json": self.snapshot,
        }

    @staticmethod
    def _happy_result():
        baseline_requests = ["req_" + str(index) * 32 for index in range(1, 5)]
        baseline_sessions = ["ses_" + str(index) * 32 for index in range(1, 5)]
        extension_requests = ["req_" + str(index) * 32 for index in range(5, 8)]
        extension_sessions = ["ses_" + str(index) * 32 for index in range(5, 8)]
        preflight = {
            "case_id": "context-over-boundary-1152-plus-1-local-preflight",
            "request_id": "req_" + "8" * 32,
            "session_id": None,
            "accepted": False,
            "error_code": "INVALID_INPUT",
            "tensor_allocations": 0,
            "coordinator_submits": 0,
            "remote_worker_contacted": False,
            "local_owner_check": {
                "confirmed": True,
                "active_requests": 0,
                "active_streams": 0,
                "active_generate_streams": 0,
                "active_captures": 0,
                "capture_reserved_bytes": 0,
                "worker_sessions": 0,
                "worker_active_compute": False,
                "transport_reserved_connections": 15,
                "transport_reserved_pending": 0,
            },
            "evidence_scope": "public client preflight only; no worker RPC or remote compute claim",
        }
        extension_cases = []
        for index, (prompt_length, vector_count, case_id) in enumerate((
                (5, 4, "unequal-concurrent-prompt-5"),
                (11, 4, "unequal-concurrent-prompt-11"),
                (1151, 1, "context-boundary-1151-plus-1"))):
            errors = [0.0002] * vector_count
            case = {
                "case_id": case_id,
                "request_id": extension_requests[index],
                "session_id": extension_sessions[index],
                "prompt_length": prompt_length,
                "new_tokens": 1 if prompt_length == 1151 else 4,
                "captured_vectors": vector_count,
                "max_absolute_error": max(errors),
                "comparison_errors": errors,
            }
            if prompt_length != 1151:
                case["forced_feedback_count"] = 3
            else:
                case["positions_total"] = 1152
                case["positions"] = [1151]
            extension_cases.append(case)
        extensions = {
            "profile": supervisor.PROFILE_C1B_HAPPY,
            "status": "passed",
            "completed_requests": 3,
            "numerical_errors": [0.0002] * 9,
            "request_ids": extension_requests,
            "session_ids": extension_sessions,
            "remote_overlap_observed": False,
            "preflight_rejection": preflight,
        }
        return {
            "schema_version": 1,
            "event": "result",
            "run_id": "9" * 32,
            "baseline": {
                "status": "passed",
                "completed_requests": 4,
                "captured_vectors": 27,
                "lifecycle_extensions": extensions,
            },
            "request_ids": baseline_requests,
            "session_ids": baseline_sessions,
            "numerical_errors": {
                "captured_vectors": 27,
                "max_absolute_error": 0.0001,
                "values": [0.0001] * 27,
                "atol": 1e-3,
                "rtol": 0.0,
            },
            "cases": [
                *({"case_id": case_id, "request_id": baseline_requests[index],
                   "session_id": baseline_sessions[index]}
                  for index, case_id in enumerate((
                      "greedy-one-token", "forced-length-1",
                      "forced-length-128", "forced-length-1024"))),
                preflight,
                *extension_cases,
            ],
        }

    def test_profile_parser_and_observation_sequences_are_closed(self):
        parser = supervisor.build_parser()
        required = [
            "--local-image", "local:test", "--remote-image", "remote:test",
            "--ssh-host", "lab-host", "--ssh-user", "operator",
            "--known-hosts", "/tmp/known-hosts",
            "--ssh-password-file", "/tmp/operator-password",
            "--artifacts-volume", "artifacts", "--reference-volume", "reference",
            "--remote-artifacts", "/srv/artifacts", "--remote-job-root", "/srv/job",
            "--result-directory", "/tmp/results", "--uncertainty-seconds", "2",
            "--external-ip", TEST_EXTERNAL_IP,
        ]
        self.assertEqual(parser.parse_args(required).profile, supervisor.PROFILE_BASELINE)
        self.assertEqual(parser.parse_args(
            required + ["--profile", supervisor.PROFILE_C1B_HAPPY]).profile,
            supervisor.PROFILE_C1B_HAPPY)
        with self.assertRaises(SystemExit):
            parser.parse_args(required + ["--profile", "arbitrary"])

        ready = self.ready
        cases = dict(supervisor._PROFILE_OBSERVATIONS)
        self.assertEqual(tuple(sequence for sequence, _ in cases[supervisor.PROFILE_BASELINE]),
                         (1, 2, 3, 4))
        self.assertEqual(tuple(sequence for sequence, _ in cases[supervisor.PROFILE_C1B_HAPPY]),
                         (1, 2, 3, 4, 5, 6, 7))
        for profile, sequence, case_id in (
                (supervisor.PROFILE_BASELINE, 1, "greedy-one-token"),
                (supervisor.PROFILE_C1B_HAPPY, 5, "unequal-concurrent-prompt-5"),
                (supervisor.PROFILE_C1B_HAPPY, 7, "context-boundary-1151-plus-1")):
            observation = {
                "schema_version": 1, "event": "observe",
                "run_id": ready["run_id"], "nonce": ready["nonce"],
                "expected_boot_id": ready["expected_boot_id"],
                "sequence": sequence, "case_id": case_id,
                "request_id": "req_" + "a" * 32,
                "session_id": "ses_" + "b" * 32,
            }
            self.assertIs(supervisor._validate_observation(
                observation, ready, sequence, profile), observation)

        invalid = {
            "schema_version": 1, "event": "observe",
            "run_id": ready["run_id"], "nonce": ready["nonce"],
            "expected_boot_id": ready["expected_boot_id"],
            "sequence": 5, "case_id": "unequal-concurrent-prompt-5",
            "request_id": "req_" + "a" * 32,
            "session_id": "ses_" + "b" * 32,
        }
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._validate_observation(
                invalid, ready, 5, supervisor.PROFILE_BASELINE)
        invalid["sequence"] = 8
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._validate_observation(
                invalid, ready, 8, supervisor.PROFILE_C1B_HAPPY)
        invalid["sequence"] = 7
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._validate_observation(
                invalid, ready, 7, supervisor.PROFILE_C1B_HAPPY)
        self.assertNotIn(
            supervisor._PROFILE_LOCAL_CASES[supervisor.PROFILE_C1B_HAPPY][0],
            [case_id for _sequence, case_id in
             supervisor._PROFILE_OBSERVATIONS[supervisor.PROFILE_C1B_HAPPY]])

    def test_handoff_filename_union_is_bounded_to_sequence_seven(self):
        # Preserve this historical ID; restart adds a bounded tenth observation.
        self.assertIn("observation-request-10.json", supervisor._CONTROL_REQUESTS)
        self.assertIn("observation-response-10.json", supervisor._CONTROL_RESPONSES)
        self.assertNotIn("observation-request-11.json", supervisor._CONTROL_REQUESTS)
        self.assertNotIn("observation-response-11.json", supervisor._CONTROL_RESPONSES)
        with mock.patch.object(supervisor, "_local_command", return_value=(3, b"")) as read:
            self.assertIsNone(supervisor._read_local_handoff(
                "container", "observation-request-10.json",
                time.monotonic() + 5, missing_ok=True))
            self.assertEqual(read.call_count, 1)
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._read_local_handoff(
                    "container", "observation-request-11.json",
                    time.monotonic() + 5, missing_ok=True)
            self.assertEqual(read.call_count, 1)
        with mock.patch.object(supervisor, "_local_docker") as write:
            supervisor._write_local_handoff(
                "container", "observation-response-10.json", {"event": "ack"},
                time.monotonic() + 5)
            self.assertEqual(write.call_count, 1)
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._write_local_handoff(
                    "container", "observation-response-11.json", {"event": "ack"},
                    time.monotonic() + 5)
            self.assertEqual(write.call_count, 1)

    def test_failure_location_is_read_only_and_hard_capped(self):
        raw = b'{"schema_version":1}'
        with mock.patch.object(supervisor, "_local_command",
                                return_value=(0, raw)) as read:
            self.assertEqual(supervisor._read_local_handoff(
                "container", "failure-location.json", time.monotonic() + 5,
                maximum=supervisor.CONTROL_LIMIT), raw)
            self.assertEqual(read.call_args.kwargs["stdout_limit"], 4096)
        with mock.patch.object(supervisor, "_local_command", return_value=(22, b"")):
            with self.assertRaisesRegex(supervisor.SupervisorError, "untrusted_file"):
                supervisor._read_local_handoff(
                    "container", "failure-location.json", time.monotonic() + 5,
                    missing_ok=True)
        with mock.patch.object(supervisor, "_local_docker") as write:
            with self.assertRaisesRegex(supervisor.SupervisorError, "response_filename"):
                supervisor._write_local_handoff(
                    "container", "failure-location.json", {"event": "failure"},
                    time.monotonic() + 5)
            write.assert_not_called()

    def test_failure_location_validator_rejects_untrusted_schema_and_frames(self):
        value = {
            "schema_version": 1,
            "event": "cohort_failure_location",
            "run_id": self.ready["run_id"],
            "nonce": self.ready["nonce"],
            "failure_type": "TimeoutError",
            "frames": [{"file": "cohort.py", "function": "run_case", "line": 17}],
        }
        self.assertEqual(
            supervisor._validate_cohort_failure_location(value, self.ready), value)
        mutations = (
            lambda item: item.pop("event"),
            lambda item: item.update(extra="untrusted"),
            lambda item: item.update(schema_version=True),
            lambda item: item.update(event="other"),
            lambda item: item.update(run_id="f" * 32),
            lambda item: item.update(nonce="f" * 32),
            lambda item: item.update(failure_type="érror"),
            lambda item: item.update(failure_type="x" * 81),
            lambda item: item.update(frames="not-a-list"),
            lambda item: item.update(frames=[dict(item["frames"][0]) for _ in range(13)]),
            lambda item: item["frames"][0].update(file="../cohort.py"),
            lambda item: item["frames"][0].update(file="nested\\cohort.py"),
            lambda item: item["frames"][0].update(file="é.py"),
            lambda item: item["frames"][0].update(function="not-valid"),
            lambda item: item["frames"][0].update(function="class"),
            lambda item: item["frames"][0].update(function="функция"),
            lambda item: item["frames"][0].update(line=True),
            lambda item: item["frames"][0].update(line=0),
            lambda item: item["frames"][0].update(line=1_000_001),
            lambda item: item["frames"][0].update(extra="source"),
        )
        for mutate in mutations:
            invalid = json.loads(json.dumps(value))
            mutate(invalid)
            with self.subTest(invalid=invalid), self.assertRaises(
                    supervisor.SupervisorError):
                supervisor._validate_cohort_failure_location(invalid, self.ready)

    def test_failure_location_parser_rejects_duplicate_and_oversized_json(self):
        with self.assertRaisesRegex(supervisor.SupervisorError, "size"):
            supervisor._json_load(b" " * 4097, 4096,
                                  label="cohort_failure_location")
        with self.assertRaisesRegex(supervisor.SupervisorError, "invalid_json"):
            supervisor._json_load(b'{"schema_version":1,"schema_version":1}', 4096,
                                  label="cohort_failure_location")

    def test_happy_result_summary_accepts_only_fixed_flat_extension_schema(self):
        summary = supervisor._sanitize_cohort_result(
            self._happy_result(), supervisor.PROFILE_C1B_HAPPY)
        self.assertEqual(summary["captured_vectors"], 27)
        self.assertEqual(len(summary["request_ids"]), 4)
        self.assertEqual(len(summary["session_ids"]), 4)
        self.assertEqual(len(summary["cases"]), 8)
        self.assertEqual(summary["cases"][4]["session_id"], None)
        self.assertEqual(summary["lifecycle_extensions"]["captured_vectors"], 9)
        self.assertFalse(summary["lifecycle_extensions"]["remote_overlap_observed"])
        self.assertFalse(summary["lifecycle_extensions"]["preflight_rejection"]["remote_worker_contacted"])

        unknown_profile = self._happy_result()
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(unknown_profile, "unlisted")

        for mutate in (
                lambda result: result["baseline"]["lifecycle_extensions"].update(extra=True),
                lambda result: result["baseline"]["lifecycle_extensions"].update(remote_overlap_observed=True),
                lambda result: result["baseline"]["lifecycle_extensions"].update(numerical_errors={"values": []}),
                lambda result: result["baseline"]["lifecycle_extensions"].update(numerical_errors=[float("nan")] * 9),
                lambda result: result["cases"][4].update(session_id="ses_" + "a" * 32),
                lambda result: result["cases"][4].update(remote_worker_contacted=True),
                lambda result: result["cases"].append(dict(result["cases"][-1])),
                lambda result: result["cases"][7].update(case_id="unknown-case")):
            invalid = self._happy_result()
            mutate(invalid)
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._sanitize_cohort_result(invalid, supervisor.PROFILE_C1B_HAPPY)

    def test_baseline_result_summary_keeps_string_extension_and_four_cases(self):
        result = self._happy_result()
        result["baseline"]["lifecycle_extensions"] = "pending_separate_C1b_gate"
        result["cases"] = result["cases"][:4]
        result["request_ids"] = result["request_ids"][:4]
        result["session_ids"] = result["session_ids"][:4]
        summary = supervisor._sanitize_cohort_result(result)
        self.assertEqual(len(summary["cases"]), 4)
        self.assertNotIn("lifecycle_extensions", summary)

    def test_configured_endpoint_is_required_canonical_private_and_pinned_to_bundle(self):
        parser = supervisor.build_parser()
        required = [
            "--local-image", "local:test", "--remote-image", "remote:test",
            "--ssh-host", "lab-host", "--ssh-user", "operator",
            "--known-hosts", "/tmp/known-hosts",
            "--ssh-password-file", "/tmp/operator-password",
            "--artifacts-volume", "artifacts", "--reference-volume", "reference",
            "--remote-artifacts", "/srv/artifacts", "--remote-job-root", "/srv/job",
            "--result-directory", "/tmp/results", "--uncertainty-seconds", "2",
        ]
        with self.assertRaises(SystemExit):
            parser.parse_args(required)
        parsed = parser.parse_args(required + ["--external-ip", TEST_EXTERNAL_IP])
        self.assertEqual(parsed.external_port, 50061)
        self.assertEqual(supervisor._configured_endpoint(
            parsed.external_ip, parsed.external_port), self.expected_endpoint)
        self.assertEqual(supervisor._configured_endpoint(
            TEST_OTHER_EXTERNAL_IP, supervisor.REMOTE_PORT),
            f"{TEST_OTHER_EXTERNAL_IP}:50061")
        for invalid_ip in ("192.0.2.2", "127.0.0.1", "8.8.8.8", "peer.example"):
            with self.subTest(invalid_ip=invalid_ip), self.assertRaises(supervisor.SupervisorError):
                supervisor._configured_endpoint(invalid_ip, supervisor.REMOTE_PORT)
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._configured_endpoint(TEST_EXTERNAL_IP, 50062)

        self.assertIs(supervisor._validate_bundle_ready(
            self.ready, self.expected_endpoint), self.ready)
        mismatched_ready = dict(self.ready, endpoint=f"{TEST_OTHER_EXTERNAL_IP}:50061")
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._validate_bundle_ready(mismatched_ready, self.expected_endpoint)

        raw_config = json.dumps(self.config, sort_keys=True, separators=(",", ":")).encode()
        checked = supervisor._validate_worker_config(
            raw_config, self.ready, self.expected_endpoint)
        self.assertEqual(checked["listen_ip"], TEST_EXTERNAL_IP)
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._validate_worker_config(raw_config, self.ready,
                                               f"{TEST_OTHER_EXTERNAL_IP}:50061")
        changed_config = dict(self.config, listen_ip=TEST_OTHER_EXTERNAL_IP)
        changed_raw = json.dumps(changed_config, sort_keys=True,
                                 separators=(",", ":")).encode()
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._validate_worker_config(
                changed_raw, self.ready, self.expected_endpoint)

    @staticmethod
    def _write_file(path: Path, contents: bytes, mode: int) -> None:
        path.write_bytes(contents)
        os.chmod(path, mode)

    def _make_bundle_tree(self, root: Path) -> Path:
        os.chmod(root, 0o700)
        job = root / "synthetic-job"
        bundle = job / "worker-3-bundle"
        bundle.mkdir(parents=True, mode=0o700)
        os.chmod(job, 0o700)
        os.chmod(bundle, 0o700)
        for name, contents in self._bundle_files().items():
            self._write_file(bundle / name, contents, 0o600)
        (bundle / "sockets").mkdir(mode=0o700)
        os.chmod(bundle / "sockets", 0o700)
        return bundle

    @staticmethod
    def _tar_with_variant(files, *, variant="valid") -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, contents in files.items():
                archive_name = "../" + name if variant == "traversal" and name == "host.crt" else name
                info = tarfile.TarInfo(archive_name)
                info.type = tarfile.REGTYPE
                info.mode = 0o600
                info.size = len(contents)
                archive.addfile(info, io.BytesIO(contents))
            if variant == "link":
                directory = tarfile.TarInfo("sockets")
                directory.type = tarfile.SYMTYPE
                directory.linkname = "host.crt"
                directory.mode = 0o700
                archive.addfile(directory)
            elif variant == "wrong_directory_type":
                directory = tarfile.TarInfo("sockets")
                directory.type = tarfile.REGTYPE
                directory.mode = 0o700
                directory.size = 1
                archive.addfile(directory, io.BytesIO(b"x"))
            else:
                directory = tarfile.TarInfo("sockets/")
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o700
                archive.addfile(directory)
            if variant == "extra":
                extra = tarfile.TarInfo("unapproved.txt")
                extra.type = tarfile.REGTYPE
                extra.mode = 0o600
                extra.size = 1
                archive.addfile(extra, io.BytesIO(b"x"))
        return output.getvalue()

    @unittest.skipUnless(_POSIX_FILE_HELPERS,
                         "embedded bundle scripts require POSIX descriptor-relative file APIs")
    def test_actual_writer_validator_extractor_round_trip(self):
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory(prefix="secure-supervisor-bundle-") as directory:
            base = Path(directory)
            source_root = base / "source-root"
            source_root.mkdir(mode=0o700)
            bundle = self._make_bundle_tree(source_root)
            writer = supervisor._LOCAL_TAR_SCRIPT.replace(
                'root="/tmp/handoff"', f"root={str(source_root)!r}")
            made = subprocess.run(
                [sys.executable, "-c", writer, str(bundle)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(made.returncode, 0, made.stderr.decode("utf-8", "replace"))
            raw_tar = made.stdout
            extracted_files = supervisor.validate_worker_tar(
                raw_tar, self.ready, self.expected_endpoint)
            self.assertEqual(extracted_files, self._bundle_files())
            with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:") as archive:
                socket_members = [member for member in archive.getmembers()
                                  if member.name in {"sockets", "sockets/"}]
            self.assertEqual(len(socket_members), 1)
            self.assertTrue(socket_members[0].isdir())

            extract_root = base / "extract-root"
            extract_root.mkdir(mode=0o700)
            os.chmod(extract_root, 0o700)
            self._write_file(extract_root / "worker.tar", raw_tar, 0o600)
            extracted = subprocess.run(
                [sys.executable, "-c", supervisor._REMOTE_EXTRACT_SCRIPT,
                 str(extract_root), str(uid), str(gid)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(extracted.returncode, 0,
                             extracted.stderr.decode("utf-8", "replace"))
            self.assertEqual(extracted.stdout.strip(), b"extracted")
            self.assertFalse((extract_root / "worker.tar").exists())
            for name, contents in self._bundle_files().items():
                self.assertEqual((extract_root / name).read_bytes(), contents)
                self.assertEqual(stat.S_IMODE((extract_root / name).stat().st_mode), 0o600)
            sockets = extract_root / "sockets"
            self.assertTrue(sockets.is_dir())
            self.assertEqual(stat.S_IMODE(sockets.stat().st_mode), 0o700)
            self.assertEqual(list(sockets.iterdir()), [])

    def test_validator_accepts_tarfile_normalized_sockets_directory(self):
        raw_tar = self._tar_with_variant(self._bundle_files())
        extracted = supervisor.validate_worker_tar(
            raw_tar, self.ready, self.expected_endpoint)
        self.assertEqual(extracted, self._bundle_files())

    def test_validator_rejects_links_traversal_wrong_directory_and_extras(self):
        variants = ("link", "traversal", "wrong_directory_type", "extra")
        for variant in variants:
            with self.subTest(variant=variant):
                raw_tar = self._tar_with_variant(self._bundle_files(), variant=variant)
                with self.assertRaises(supervisor.SupervisorError):
                    supervisor.validate_worker_tar(
                        raw_tar, self.ready, self.expected_endpoint)

    @unittest.skipUnless(_POSIX_FILE_HELPERS,
                         "embedded extractor requires POSIX descriptor-relative file APIs")
    def test_embedded_extractor_rejects_links_traversal_wrong_directory_and_extras(self):
        uid, gid = os.geteuid(), os.getegid()
        variants = ("link", "traversal", "wrong_directory_type", "extra")
        with tempfile.TemporaryDirectory(prefix="secure-supervisor-bad-tar-") as directory:
            base = Path(directory)
            for variant in variants:
                with self.subTest(variant=variant):
                    raw_tar = self._tar_with_variant(self._bundle_files(), variant=variant)
                    extract_root = base / variant
                    extract_root.mkdir(mode=0o700)
                    os.chmod(extract_root, 0o700)
                    self._write_file(extract_root / "worker.tar", raw_tar, 0o600)
                    result = subprocess.run(
                        [sys.executable, "-c", supervisor._REMOTE_EXTRACT_SCRIPT,
                         str(extract_root), str(uid), str(gid)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual({path.name for path in extract_root.iterdir()},
                                     {"worker.tar"})

    def _final_status(self):
        return {
            "schema_version": 1,
            "event": "final",
            "phase": "stopped",
            "worker_name": "worker-3",
            "account_id": self.config["account_id"],
            "device_id": self.config["device_id"],
            "boot_id": self.config["boot_id"],
            "assignment_id": self.config["assignment_id"],
            "model_id": supervisor.MODEL_ID,
            "model_revision": supervisor.MODEL_REVISION,
            "manifest_fingerprint": self.manifest,
            "listen_endpoint": self.expected_endpoint,
            "layer_range": [6, 8],
            "clock_uncertainty_seconds": 2.0,
            "torch_threads": 2,
            "handler": {
                "state": "observed",
                "active_sessions": 0,
                "active_session_ids": [],
                "tombstones": 3,
                "retained_entries": 3,
                "queued_operations": 0,
                "active_compute": False,
                "cache_bytes_exact": True,
                "requires_restart": True,
                "stopping": False,
                "limits": {
                    "max_sessions": 8,
                    "max_tombstones": 8,
                    "max_stage_queue": 8,
                    "max_positions": 1152,
                    "max_cache_positions": 12288,
                    "max_cache_bytes": 16777216,
                    "max_message_bytes": 1048576,
                },
                "committed_cache_bytes": 0,
                "committed_cache_bytes_lower_bound": None,
                "allocated_cache_bytes": 0,
            },
            "bridge": {
                "state": "observed",
                "ready": False,
                "unavailable": True,
                "requires_restart": True,
                "cleanup_confirmed": True,
                "active_authorizations": 0,
                "owned_sessions": 0,
                "pending_notices": 0,
                "fault_present": False,
            },
            "transport": {
                "listener_slots": 1,
                "max_connections": 16,
                "max_pending": 4,
                "reserved_connections": 0,
                "reserved_pending": 0,
                "reserved_listener_pending_capacity": 0,
                "reserved_outbound_pending": 0,
                "server_state": "stopped",
            },
            "external_supervision": {
                "startup_watchdog_seconds": 60,
                "termination_watchdog_seconds": 15,
                "resource_caps": "configured_by_external_supervisor",
                "verified_by_worker": False,
            },
            "shutdown": {
                "server": "confirmed", "bridge": "confirmed",
                "handler": "confirmed", "overall": "confirmed",
            },
            "report_state": "confirmed",
            "resource_state": "observed",
        }

    @staticmethod
    def _successful_remote_removal_evidence(job_root):
        removed = sorted(supervisor._WORKER_FILES) + [
            "status.json", "worker.tar", "sockets/backend-0123456789ab.sock",
            "sockets/", ".",
        ]
        return {
            "schema_version": 1,
            "event": "remote_job_removal",
            "job_root": job_root,
            "uid": 1000,
            "gid": 1000,
            "confirmed": True,
            "removed": removed,
            "residuals": [],
            "residuals_known": True,
            "residuals_truncated": False,
            "reason": None,
        }

    def test_final_status_accepts_bounded_terminal_tombstones_without_clearing_fence(self):
        status = self._final_status()
        self.assertTrue(supervisor._final_status_is_confirmed(status, self.config))
        self.assertEqual(status["handler"]["tombstones"], 3)
        self.assertTrue(status["handler"]["requires_restart"])

    def test_final_status_accepts_actual_v1_tombstone_limit(self):
        status = self._final_status()
        status["handler"]["limits"]["max_tombstones"] = 4096
        status["handler"]["tombstones"] = 4096
        status["handler"]["retained_entries"] = 4096
        self.assertTrue(supervisor._final_status_is_confirmed(status, self.config))
        self.assertEqual(status["handler"]["tombstones"], 4096)
        self.assertEqual(status["handler"]["retained_entries"], 4096)
        self.assertTrue(status["handler"]["requires_restart"])

    def test_live_status_is_bound_to_the_validated_configured_endpoint(self):
        def ready_status(endpoint):
            status = self._final_status()
            status["event"] = "heartbeat"
            status["phase"] = "ready"
            status["listen_endpoint"] = endpoint
            status["handler"]["requires_restart"] = False
            status["bridge"].update(ready=True, unavailable=False,
                                    requires_restart=False)
            status["transport"].update(
                reserved_connections=1, reserved_pending=0,
                reserved_listener_pending_capacity=1,
                reserved_outbound_pending=0, server_state="running")
            status["shutdown"] = {"state": "not_started"}
            return status

        supervisor._validate_status(ready_status(self.expected_endpoint), self.config,
                                    event="heartbeat")
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._validate_status(
                ready_status(f"{TEST_OTHER_EXTERNAL_IP}:50061"), self.config,
                event="heartbeat")

    def test_final_status_rejects_unbounded_or_live_ownership(self):
        bad_cases = (
            ("over_limit_tombstones", ("handler", "tombstones"), 9),
            ("mismatched_retained", ("handler", "retained_entries"), 2),
            ("live_session", ("handler", "active_sessions"), 1),
            ("queued_operation", ("handler", "queued_operations"), 1),
            ("committed_cache_bytes", ("handler", "committed_cache_bytes"), 1),
            ("cache_bytes", ("handler", "allocated_cache_bytes"), 1),
            ("active_compute", ("handler", "active_compute"), True),
            ("bad_restart_type", ("handler", "requires_restart"), 1),
            ("authorization", ("bridge", "active_authorizations"), 1),
            ("owned_session", ("bridge", "owned_sessions"), 1),
            ("pending_notice", ("bridge", "pending_notices"), 1),
            ("transport_reservation", ("transport", "reserved_connections"), 1),
            ("pending_transport", ("transport", "reserved_pending"), 1),
            ("listener_pending_capacity",
             ("transport", "reserved_listener_pending_capacity"), 1),
            ("outbound_pending", ("transport", "reserved_outbound_pending"), 1),
        )
        for label, (section, key), value in bad_cases:
            with self.subTest(case=label):
                status = self._final_status()
                status[section][key] = value
                self.assertFalse(supervisor._final_status_is_confirmed(status, self.config))
        status = self._final_status()
        status["handler"]["limits"]["max_tombstones"] = 4097
        self.assertFalse(supervisor._final_status_is_confirmed(status, self.config))
        status = self._final_status()
        status["handler"]["limits"]["max_tombstones"] = 4096
        status["handler"]["tombstones"] = 4097
        status["handler"]["retained_entries"] = 4097
        self.assertFalse(supervisor._final_status_is_confirmed(status, self.config))

    def test_status_helpers_use_a_custom_host_job_root(self):
        host_path = "/var/tmp/steamboat-host-job-91/status.json"
        frame = {
            "uid": supervisor.REMOTE_STATUS_UID,
            "mode": 0o600,
            "mtime_ns": 200,
            "mark_ns": 100,
            "status": {"event": "heartbeat"},
        }
        with mock.patch.object(supervisor, "_remote_script",
                               return_value=json.dumps(frame).encode("utf-8")) as remote:
            result = supervisor._read_remote_status(
                object(), password=None, status_path=host_path, mark_ns=100,
                deadline=time.monotonic() + 10)
        self.assertEqual(result, frame)
        self.assertEqual(remote.call_args.args[1], supervisor._REMOTE_STATUS_SCRIPT)
        self.assertEqual(remote.call_args.args[2][0], host_path)
        self.assertNotEqual(host_path, f"{supervisor.REMOTE_ROOT}/status.json")

        final_frame = {**frame, "mark_ns": 0}
        with mock.patch.object(supervisor, "_remote_script",
                               return_value=json.dumps(final_frame).encode("utf-8")) as remote:
            value, status = supervisor._final_remote_status(
                object(), password=None, status_path=host_path,
                deadline=time.monotonic() + 10)
        self.assertEqual(value, final_frame)
        self.assertEqual(status, final_frame["status"])
        self.assertEqual(remote.call_args.args[2][0], host_path)

    def test_remote_stop_derives_final_status_from_host_job_root(self):
        job_root = "/var/tmp/steamboat-host-job-92"
        status = self._final_status()
        removal = self._successful_remote_removal_evidence(job_root)
        frame = {"uid": 1000, "mode": 0o600, "mtime_ns": 123, "mark_ns": 0,
                 "status": status}
        with (mock.patch.object(supervisor, "_remote_inspect",
                                return_value={"running": False, "exit_code": 0}),
              mock.patch.object(supervisor, "_final_remote_status",
                                return_value=(frame, status)) as final_reader,
              mock.patch.object(supervisor, "_ssh_checked", return_value=b""),
              mock.patch.object(supervisor, "_ssh_exec",
                                return_value=(0, json.dumps(removal).encode("utf-8")))
              as removal_command):
            evidence = supervisor._stop_remote(
                object(), "8" * 64, name="synthetic-worker", owner="9" * 32,
                image="synthetic:image", password=None, config=self.config,
                job_root=job_root, uid=1000, gid=1000,
                deadline=time.monotonic() + 20)
        self.assertEqual(final_reader.call_args.kwargs["status_path"],
                         f"{job_root}/status.json")
        self.assertEqual(evidence["status"], status)
        self.assertEqual(evidence["status"]["event"], "final")
        self.assertEqual(evidence["status"]["phase"], "stopped")
        self.assertTrue(evidence["shutdown_confirmed"])
        self.assertTrue(evidence["graceful_compute_shutdown"])
        self.assertTrue(evidence["container_removed"])
        self.assertTrue(evidence["private_files_removed"])
        self.assertTrue(evidence["job_root_removed"])
        self.assertTrue(evidence["cleanup_confirmed"])
        self.assertEqual(evidence["removal_evidence"], removal)
        self.assertEqual(evidence["removal_evidence"]["residuals"], [])
        self.assertEqual(removal_command.call_count, 1)
        command = removal_command.call_args.args[1]
        self.assertEqual(command[:3], ["python3", "-c",
                                       supervisor._remote_remove_job_script()])
        self.assertEqual(command[3:], [job_root, "1000", "1000"])

    def test_remote_removal_adapter_requires_confirmed_root_and_preserves_residuals(self):
        job_root = "/var/tmp/steamboat-host-job-93"
        base = self._successful_remote_removal_evidence(job_root)
        unconfirmed = {
            **base,
            "confirmed": False,
            "removed": [],
            "residuals": ["leftover"],
            "reason": "unexpected_entries",
        }
        with mock.patch.object(
                supervisor, "_ssh_exec",
                return_value=(1, json.dumps(unconfirmed).encode("utf-8"))):
            result = supervisor._remove_remote_job(
                object(), job_root=job_root, uid=1000, gid=1000,
                password=None, deadline=time.monotonic() + 10)
        self.assertFalse(result["private_files_removed"])
        self.assertFalse(result["job_root_removed"])
        self.assertEqual(result["raw_evidence"], unconfirmed)
        self.assertEqual(result["raw_evidence"]["residuals"], ["leftover"])

        root_marker_without_confirmation = {
            **base,
            "confirmed": False,
            "removed": ["."],
            "residuals": [],
            "reason": "removal_failed",
        }
        with mock.patch.object(
                supervisor, "_ssh_exec",
                return_value=(1, json.dumps(root_marker_without_confirmation).encode("utf-8"))):
            result = supervisor._remove_remote_job(
                object(), job_root=job_root, uid=1000, gid=1000,
                password=None, deadline=time.monotonic() + 10)
        self.assertFalse(result["private_files_removed"])
        self.assertFalse(result["job_root_removed"])
        self.assertEqual(result["raw_evidence"]["removed"], ["."])
        self.assertEqual(result["raw_evidence"]["residuals"], [])

        false_success = {**base, "confirmed": False, "removed": [], "reason": None}
        with mock.patch.object(
                supervisor, "_ssh_exec",
                return_value=(0, json.dumps(false_success).encode("utf-8"))):
            with self.assertRaises(supervisor.SupervisorError) as caught:
                supervisor._remove_remote_job(
                    object(), job_root=job_root, uid=1000, gid=1000,
                    password=None, deadline=time.monotonic() + 10)
        self.assertEqual(caught.exception.code, "missing_failure_reason")

        confirmed_without_root = {
            **base,
            "removed": [item for item in base["removed"] if item != "."],
        }
        with mock.patch.object(
                supervisor, "_ssh_exec",
                return_value=(0, json.dumps(confirmed_without_root).encode("utf-8"))):
            with self.assertRaises(supervisor.SupervisorError) as caught:
                supervisor._remove_remote_job(
                    object(), job_root=job_root, uid=1000, gid=1000,
                    password=None, deadline=time.monotonic() + 10)
        self.assertEqual(caught.exception.code, "incomplete_confirmation")

    @unittest.skipUnless(_POSIX_FILE_HELPERS,
                         "protected status reader requires POSIX descriptor-relative file APIs")
    def test_embedded_status_reader_uses_nofollow_stable_host_descriptors(self):
        uid = os.geteuid()
        with tempfile.TemporaryDirectory(prefix="secure-supervisor-status-") as directory:
            root = Path(directory) / "host-job-root-91"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            status_path = root / "status.json"
            status_path.write_text('{"event":"heartbeat"}', encoding="utf-8")
            os.chmod(status_path, 0o600)
            result = subprocess.run(
                [sys.executable, "-c", supervisor._REMOTE_STATUS_SCRIPT,
                 str(status_path), str(uid), "0", "0"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(result.returncode, 0,
                             result.stderr.decode("utf-8", "replace"))
            frame = json.loads(result.stdout)
            self.assertEqual(frame["uid"], uid)
            self.assertEqual(frame["mode"], 0o600)
            self.assertEqual(frame["status"], {"event": "heartbeat"})

            alias = Path(directory) / "job-root-symlink"
            alias.symlink_to(root, target_is_directory=True)
            link_result = subprocess.run(
                [sys.executable, "-c", supervisor._REMOTE_STATUS_SCRIPT,
                 str(alias / "status.json"), str(uid), "0", "0"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(link_result.returncode, 0)

    @unittest.skipUnless(_POSIX_FILE_HELPERS,
                         "atomic handoff publication requires POSIX link and directory fsync")
    def test_embedded_handoff_writer_publishes_complete_file_without_overwrite(self):
        payload = b'{"schema_version":1,"event":"ready_ack","complete":true}\n'
        with tempfile.TemporaryDirectory(prefix="secure-supervisor-ack-") as directory:
            root = Path(directory) / "private-handoff"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            script = supervisor._LOCAL_WRITE_SCRIPT.replace(
                'root="/tmp/handoff"', f"root={str(root)!r}")
            result = subprocess.run(
                [sys.executable, "-c", script, "ready.json"], input=payload,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(result.returncode, 0,
                             result.stderr.decode("utf-8", "replace"))
            target = root / "ready.json"
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(target.stat().st_nlink, 1)
            self.assertEqual({path.name for path in root.iterdir()}, {"ready.json"})

            retry = subprocess.run(
                [sys.executable, "-c", script, "ready.json"], input=b'{"different":true}',
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(retry.returncode, 0)
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual({path.name for path in root.iterdir()}, {"ready.json"})

    @unittest.skipUnless(_POSIX_FILE_HELPERS,
                         "post-link publication uncertainty requires POSIX descriptor APIs")
    def test_post_link_failure_leaves_complete_final_acknowledgement(self):
        payload = b'{"event":"ready_ack","synthetic":true}\n'
        fsync_injector = """\
import os as _os
import stat as _stat
_real_fsync = _os.fsync
def _fail_directory_fsync(fd):
    if _stat.S_ISDIR(_os.fstat(fd).st_mode):
        raise OSError('synthetic directory fsync failure')
    return _real_fsync(fd)
_os.fsync = _fail_directory_fsync
"""
        with tempfile.TemporaryDirectory(prefix="secure-supervisor-uncertain-ack-") as directory:
            root = Path(directory) / "private-handoff"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            writer = supervisor._LOCAL_WRITE_SCRIPT.replace(
                'root="/tmp/handoff"', f"root={str(root)!r}")
            script = fsync_injector + writer
            result = subprocess.run(
                [sys.executable, "-c", script, "ready.json"], input=payload,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"synthetic directory fsync failure", result.stderr)
            target = root / "ready.json"
            self.assertTrue(target.exists())
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(json.loads(target.read_bytes()),
                             {"event": "ready_ack", "synthetic": True})
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual({path.name for path in root.iterdir()}, {"ready.json"})

            existing_root = Path(directory) / "existing-handoff"
            existing_root.mkdir(mode=0o700)
            os.chmod(existing_root, 0o700)
            existing = existing_root / "ready.json"
            existing_payload = b'{"event":"earlier_ack"}\n'
            existing.write_bytes(existing_payload)
            os.chmod(existing, 0o600)
            existing_writer = supervisor._LOCAL_WRITE_SCRIPT.replace(
                'root="/tmp/handoff"', f"root={str(existing_root)!r}")
            existing_result = subprocess.run(
                [sys.executable, "-c", fsync_injector + existing_writer,
                 "ready.json"], input=b'{"event":"replacement"}\n',
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(existing_result.returncode, 0)
            self.assertEqual(existing.read_bytes(), existing_payload)
            self.assertEqual(json.loads(existing.read_bytes()),
                             {"event": "earlier_ack"})
            self.assertEqual({path.name for path in existing_root.iterdir()},
                             {"ready.json"})


class SecureSupervisorInspectPreflightTests(unittest.TestCase):
    IMAGE_ID = "sha256:" + "a" * 64
    DEADLINE = 12345.25

    @staticmethod
    def _args(*, local_image=None, artifacts_volume="artifact-volume",
              reference_volume="reference-volume"):
        return type("Args", (), {
            "local_image": local_image or SecureSupervisorInspectPreflightTests.IMAGE_ID,
            "artifacts_volume": artifacts_volume,
            "reference_volume": reference_volume,
        })()

    def test_local_inspects_use_fixed_bounded_identity_formats_and_deadline(self):
        args = self._args()
        outputs = [b"artifact-volume\n", b"reference-volume\n",
                   (self.IMAGE_ID + "\n").encode("ascii")]
        with mock.patch.object(supervisor, "_local_docker",
                               side_effect=outputs) as inspect:
            supervisor._prepare_local_volumes(args, self.DEADLINE)

        self.assertEqual(
            [call.args[0] for call in inspect.call_args_list],
            [
                ["docker", "volume", "inspect", "--format", "{{.Name}}",
                 "artifact-volume"],
                ["docker", "volume", "inspect", "--format", "{{.Name}}",
                 "reference-volume"],
                ["docker", "image", "inspect", "--format", "{{.Id}}",
                 self.IMAGE_ID],
            ],
        )
        self.assertEqual(
            [(call.kwargs["deadline"], call.kwargs["output"])
             for call in inspect.call_args_list],
            [(self.DEADLINE, 256)] * 3,
        )

    def test_remote_image_inspect_uses_fixed_bounded_identity_format(self):
        client = object()
        password = "synthetic-password"
        with mock.patch.object(supervisor, "_ssh_checked",
                               return_value=(self.IMAGE_ID + "\n").encode("ascii")) as inspect:
            supervisor._prepare_remote_image(
                client, self.IMAGE_ID, password, self.DEADLINE)

        inspect.assert_called_once_with(
            client,
            ["docker", "image", "inspect", "--format", "{{.Id}}", self.IMAGE_ID],
            password=password, deadline=self.DEADLINE, output_limit=256,
        )

    def test_local_volume_identity_rejects_mismatch_malformed_and_extra_lines(self):
        for raw in (b"different-volume\n", b"artifact-volume\nextra\n",
                    b" artifact-volume\n", b"artifact-volume\r\n", b"\xff\n"):
            with self.subTest(raw=raw):
                with mock.patch.object(supervisor, "_local_docker",
                                       return_value=raw) as inspect:
                    with self.assertRaises(supervisor.SupervisorError) as raised:
                        supervisor._prepare_local_volumes(self._args(), self.DEADLINE)
                self.assertEqual(raised.exception.stage, "local_volume")
                self.assertIn(raised.exception.code, {"inspect_output", "identity_mismatch"})
                inspect.assert_called_once()

    def test_local_image_identity_rejects_mismatch_malformed_and_nonimmutable_input(self):
        for raw in (("sha256:" + "b" * 64 + "\n").encode("ascii"),
                    b"sha256:short\n", (self.IMAGE_ID + "\nextra\n").encode("ascii"),
                    self.IMAGE_ID.encode("ascii") + b" extra\n", b"\xff"):
            with self.subTest(raw=raw):
                with mock.patch.object(
                        supervisor, "_local_docker",
                        side_effect=[b"artifact-volume\n", b"reference-volume\n", raw]) as inspect:
                    with self.assertRaises(supervisor.SupervisorError) as raised:
                        supervisor._prepare_local_volumes(self._args(), self.DEADLINE)
                self.assertEqual(raised.exception.stage, "local_image")
                self.assertIn(raised.exception.code, {"inspect_output", "identity_mismatch"})
                self.assertEqual(inspect.call_count, 3)

        with mock.patch.object(
                supervisor, "_local_docker",
                side_effect=[b"artifact-volume\n", b"reference-volume\n"]) as inspect:
            with self.assertRaises(supervisor.SupervisorError) as raised:
                supervisor._prepare_local_volumes(
                    self._args(local_image="example:mutable"), self.DEADLINE)
        self.assertEqual(raised.exception.code, "expected_immutable_id")
        self.assertEqual(inspect.call_count, 2)

    def test_remote_image_identity_rejects_mismatch_malformed_and_nonimmutable_input(self):
        for raw in (("sha256:" + "b" * 64 + "\n").encode("ascii"),
                    b"sha256:short\n", (self.IMAGE_ID + "\nextra\n").encode("ascii"),
                    self.IMAGE_ID.encode("ascii") + b" extra\n", b"\xff"):
            with self.subTest(raw=raw):
                with mock.patch.object(supervisor, "_ssh_checked", return_value=raw) as inspect:
                    with self.assertRaises(supervisor.SupervisorError) as raised:
                        supervisor._prepare_remote_image(
                            object(), self.IMAGE_ID, None, self.DEADLINE)
                self.assertEqual(raised.exception.stage, "remote_image")
                self.assertIn(raised.exception.code, {"inspect_output", "identity_mismatch"})
                inspect.assert_called_once()

        with mock.patch.object(supervisor, "_ssh_checked") as inspect:
            with self.assertRaises(supervisor.SupervisorError) as raised:
                supervisor._prepare_remote_image(
                    object(), "example:mutable", None, self.DEADLINE)
        self.assertEqual(raised.exception.code, "expected_immutable_id")
        inspect.assert_not_called()

    def test_inspect_command_failures_propagate_unchanged(self):
        local_failure = supervisor.SupervisorError("local_docker", "command_failed")
        with mock.patch.object(supervisor, "_local_docker", side_effect=local_failure):
            with self.assertRaises(supervisor.SupervisorError) as raised:
                supervisor._prepare_local_volumes(self._args(), self.DEADLINE)
        self.assertIs(raised.exception, local_failure)

        remote_failure = supervisor.SupervisorError("ssh_command", "transport_error")
        with mock.patch.object(supervisor, "_ssh_checked", side_effect=remote_failure):
            with self.assertRaises(supervisor.SupervisorError) as raised:
                supervisor._prepare_remote_image(
                    object(), self.IMAGE_ID, None, self.DEADLINE)
        self.assertIs(raised.exception, remote_failure)


class SecureSupervisorRemoteRunBuilderTests(unittest.TestCase):
    def test_remote_job_bind_uses_docker_default_rw_and_artifacts_stay_readonly(self):
        image = "sha256:" + "a" * 64
        argv = supervisor.build_remote_run_argv(
            image=image,
            name="steamboat-c1b-worker3-" + "b" * 32,
            owner="c" * 32,
            job_root="/run/steamboat/jobs/" + "d" * 32,
            artifacts="/srv/steamboat/artifacts",
        )

        mount_values = [argv[index + 1] for index, value in enumerate(argv[:-1])
                        if value == "--mount"]
        self.assertEqual(mount_values, [
            "type=bind,src=/run/steamboat/jobs/" + "d" * 32
            + ",dst=" + supervisor.REMOTE_ROOT,
            "type=bind,src=/srv/steamboat/artifacts,dst=/artifacts,readonly",
        ])
        self.assertEqual(argv[argv.index("--user") + 1], "1000:1000")
        self.assertIn("--read-only", argv)
        self.assertIn("--cap-drop=ALL", argv)
        self.assertIn("--security-opt=no-new-privileges", argv)
        self.assertIn("--cpus=2", argv)
        self.assertIn("--memory=3g", argv)
        self.assertIn("--pids-limit=128", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "host")
        self.assertEqual(argv[-5:-1], ["python", "-m", "lab.secure_worker", "--config"])
        self.assertEqual(argv[-1], supervisor.REMOTE_ROOT + "/worker.json")


if __name__ == "__main__":
    unittest.main()
