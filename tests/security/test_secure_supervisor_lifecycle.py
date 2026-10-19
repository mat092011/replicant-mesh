"""Synthetic lifecycle regressions for the bounded C1b supervisor."""

from __future__ import annotations

from contextlib import ExitStack
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lab import secure_cohort_supervisor as supervisor


_CID = "a" * 64


class SecureSupervisorLifecycleTests(unittest.TestCase):
    def test_early_stop_is_checked_before_readiness_payload(self):
        seen = []

        def read(_cid, name, _deadline, **_kwargs):
            seen.append(name)
            if name == "stop-request.json":
                return b"{}"
            return None

        with patch.object(supervisor, "_read_local_handoff", side_effect=read):
            with self.assertRaises(supervisor.SupervisorError) as raised:
                supervisor._wait_local_json(
                    _CID, "bundle-ready.json", supervisor.time.monotonic() + 1,
                    label="bundle_ready")

        self.assertEqual((raised.exception.stage, raised.exception.code),
                         ("cohort_control", "stop_requested"))
        self.assertIsNone(raised.exception.stop_request)
        self.assertEqual(seen, ["stop-request.json"])

    def test_early_stop_is_checked_before_remote_readiness_status(self):
        terminal = []

        def stop_now():
            terminal.append(True)
            raise supervisor.SupervisorError("cohort_control", "stop_requested")

        with patch.object(supervisor, "_read_remote_status") as read_status:
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._wait_remote_status(
                    object(), config={}, password=None, status_path="/job/status.json",
                    mark_ns=1, deadline=supervisor.time.monotonic() + 2,
                    expected_events={"ready"}, terminal_check=stop_now)
        self.assertEqual(terminal, [True])
        read_status.assert_not_called()

    def test_local_cid_survives_post_create_inspection_failure(self):
        args = SimpleNamespace(local_image="local-image",
                               artifacts_volume="artifacts",
                               reference_volume="reference")
        captured = []
        with patch.object(supervisor, "build_local_run_argv", return_value=["docker", "run"]), \
                patch.object(supervisor, "_local_docker", return_value=(_CID.encode("ascii"))), \
                patch.object(supervisor, "_docker_inspect_local",
                             side_effect=supervisor.SupervisorError("container", "inspect_failed")):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._create_local_container(
                    args=args, name="owned-local", owner="run-owner",
                    cohort_args=[], deadline=supervisor.time.monotonic() + 5,
                    on_cid=captured.append)
        self.assertEqual(captured, [_CID])

    def test_remote_cid_survives_post_create_inspection_failure(self):
        captured = []
        with patch.object(supervisor, "build_remote_run_argv", return_value=["docker", "run"]), \
                patch.object(supervisor, "_ssh_checked", return_value=_CID.encode("ascii")), \
                patch.object(supervisor, "_remote_inspect",
                             side_effect=supervisor.SupervisorError("container", "inspect_failed")):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._create_remote_container(
                    object(), image="remote-image", name="owned-remote",
                    owner="run-owner", job_root="/srv/job", artifacts="/srv/artifacts",
                    password=None, deadline=supervisor.time.monotonic() + 5,
                    on_cid=captured.append)
        self.assertEqual(captured, [_CID])

    def test_reconciliation_requests_full_local_and_remote_container_ids(self):
        local_commands = []
        remote_commands = []
        state = {"running": False, "exit_code": 0}

        def local_docker(argv, **_kwargs):
            local_commands.append(argv)
            return (_CID + "\n").encode("ascii")

        def remote_checked(_client, argv, **_kwargs):
            remote_commands.append(argv)
            return (_CID + "\n").encode("ascii")

        with patch.object(supervisor, "_local_docker", side_effect=local_docker), \
                patch.object(supervisor, "_docker_inspect_local", return_value=state):
            self.assertEqual(supervisor._find_local_owned(
                name="owned-local", owner="run-owner", image="local-image",
                deadline=supervisor.time.monotonic() + 5), _CID)

        with patch.object(supervisor, "_ssh_checked", side_effect=remote_checked), \
                patch.object(supervisor, "_remote_inspect", return_value=state):
            self.assertEqual(supervisor._remote_find_owned(
                object(), name="owned-remote", owner="run-owner",
                image="remote-image", password=None,
                deadline=supervisor.time.monotonic() + 5), _CID)

        self.assertIn("--no-trunc", local_commands[0])
        self.assertIn("--no-trunc", remote_commands[0])
        self.assertEqual(len(_CID), 64)

    def test_local_and_remote_inspect_use_the_same_seven_field_template(self):
        local_commands = []
        remote_commands = []

        def output(name, image, role):
            return (f"{_CID}\n/{name}\n{image}\nrun-owner\n{role}\nfalse\n0\n"
                    ).encode("ascii")

        def local_docker(argv, **_kwargs):
            local_commands.append(argv)
            return output("local-probe", "local@sha256:" + "1" * 64, "operator")

        def remote_checked(_client, argv, **_kwargs):
            remote_commands.append(argv)
            return output("remote-probe", "remote@sha256:" + "2" * 64, "worker-3")

        with patch.object(supervisor, "_local_docker", side_effect=local_docker):
            local = supervisor._docker_inspect_local(
                _CID, name="local-probe", owner="run-owner", role="operator",
                image="local@sha256:" + "1" * 64,
                deadline=supervisor.time.monotonic() + 5)
        with patch.object(supervisor, "_ssh_checked", side_effect=remote_checked):
            remote = supervisor._remote_inspect(
                object(), _CID, name="remote-probe", owner="run-owner",
                image="remote@sha256:" + "2" * 64, password=None,
                deadline=supervisor.time.monotonic() + 5)

        expected_argv = supervisor._container_inspect_argv(_CID)
        self.assertEqual(local_commands, [expected_argv])
        self.assertEqual(remote_commands, [expected_argv])
        template = expected_argv[expected_argv.index("--format") + 1]
        self.assertEqual(template.count("{{println "), 7)
        self.assertNotIn(r"\n", template)
        self.assertEqual(local, {"running": False, "exit_code": 0})
        self.assertEqual(remote, {"running": False, "exit_code": 0})

    def test_lost_local_create_output_retains_unverified_cid_before_failed_inspect(self):
        args = SimpleNamespace(local_image="local-image",
                               artifacts_volume="artifacts",
                               reference_volume="reference")
        tracked = []
        commands = []

        def docker(argv, **_kwargs):
            commands.append(argv)
            if argv[1] == "run":
                raise supervisor.SupervisorError("local_docker", "create_reply_lost")
            if argv[1] == "ps":
                return (_CID + "\n").encode("ascii")
            self.fail("unverified local candidate reached a destructive Docker command")

        def inspect(_cid, **_kwargs):
            self.assertEqual(tracked, [_CID])
            raise supervisor.SupervisorError("container", "inspect_unavailable")

        with patch.object(supervisor, "build_local_run_argv", return_value=["docker", "run"]), \
                patch.object(supervisor, "_local_docker", side_effect=docker), \
                patch.object(supervisor, "_docker_inspect_local", side_effect=inspect):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._create_local_container(
                    args=args, name="owned-local", owner="run-owner",
                    cohort_args=[], deadline=supervisor.time.monotonic() + 5,
                    on_cid=tracked.append)
            evidence = supervisor._terminate_local_owned(
                _CID, name="owned-local", owner="run-owner", image="local-image",
                termination_deadline=supervisor.time.monotonic() + 5,
                observation_deadline=supervisor.time.monotonic() + 5)

        self.assertEqual(tracked, [_CID])
        self.assertEqual([argv[1] for argv in commands], ["run", "ps"])
        self.assertFalse(evidence["ownership_verified"])
        self.assertFalse(evidence["cleanup_confirmed"])

    def test_lost_remote_create_output_retains_unverified_cid_before_failed_inspect(self):
        tracked = []
        commands = []

        def remote(_client, argv, **_kwargs):
            commands.append(argv)
            if argv[0:2] == ["docker", "run"]:
                raise supervisor.SupervisorError("ssh_command", "create_reply_lost")
            if argv[0:3] == ["docker", "ps", "--all"]:
                return (_CID + "\n").encode("ascii")
            self.fail("unverified remote candidate reached a destructive Docker command")

        def inspect(_client, cid, **_kwargs):
            self.assertEqual(cid, _CID)
            self.assertEqual(tracked, [_CID])
            raise supervisor.SupervisorError("container", "inspect_unavailable")

        with patch.object(supervisor, "build_remote_run_argv",
                          return_value=["docker", "run"]), \
                patch.object(supervisor, "_ssh_checked", side_effect=remote), \
                patch.object(supervisor, "_remote_inspect", side_effect=inspect):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._create_remote_container(
                    object(), image="remote-image", name="owned-remote",
                    owner="run-owner", job_root="/srv/job", artifacts="/srv/artifacts",
                    password=None, deadline=supervisor.time.monotonic() + 5,
                    on_cid=tracked.append)
            evidence = supervisor._stop_remote(
                object(), _CID, name="owned-remote", owner="run-owner",
                image="remote-image", password=None, config={},
                job_root="/srv/job", uid=1000, gid=1000,
                deadline=supervisor.time.monotonic() + 5)

        self.assertEqual(tracked, [_CID])
        self.assertEqual([argv[1] for argv in commands], ["run", "ps"])
        self.assertTrue(all("--no-trunc" in argv for argv in commands if argv[1] == "ps"))
        self.assertFalse(evidence["container_removed"])
        self.assertFalse(evidence.get("cleanup_confirmed", False))

    @staticmethod
    def _supervisor_args():
        return SimpleNamespace(
            result_directory=Path("unused-results"),
            local_image="local-image", remote_image="remote-image",
            artifacts_volume="artifacts", reference_volume="reference",
            ssh_host="lab-host", ssh_user="operator", known_hosts=Path("unused-known-hosts"),
            ssh_password_file=Path("unused-password"), ssh_key_file=None,
            remote_artifacts="/srv/artifacts", remote_job_root="/srv/job",
            uncertainty_seconds=1.0, external_ip="10.23.45.67",
            external_port=50061, profile=supervisor.PROFILE_BASELINE)

    def _run_supervisor_with_local_records(self, *, clock, ready, records,
                                           local_create_error=False,
                                           termination_ownership_verified=True,
                                           profile=supervisor.PROFILE_BASELINE,
                                           actual_handoff_reader=False,
                                           persisted_report_directory=None):
        args = self._supervisor_args()
        args.profile = profile
        if persisted_report_directory is not None:
            args.result_directory = Path(persisted_report_directory)
        reads = []
        releases = []
        termination_calls = []
        reports = []

        def create_local(**kwargs):
            cohort_args = kwargs["cohort_args"]
            self.last_cohort_args = tuple(cohort_args)
            self.assertIn("--external-ip", cohort_args)
            self.assertEqual(cohort_args[cohort_args.index("--external-ip") + 1],
                             args.external_ip)
            self.assertIn("--external-port", cohort_args)
            self.assertEqual(cohort_args[cohort_args.index("--external-port") + 1],
                             str(args.external_port))
            self.assertIn("--profile", cohort_args)
            self.assertEqual(cohort_args[cohort_args.index("--profile") + 1],
                             args.profile)
            kwargs["on_cid"](_CID)
            if local_create_error:
                raise supervisor.SupervisorError("local_start", "synthetic_create_unknown")
            return _CID

        def wait_local(*_args, **_kwargs):
            if ready is None:
                raise supervisor.SupervisorError("bundle_ready", "synthetic_stop")
            return ready

        def read_handoff(_cid, name, deadline, **_kwargs):
            reads.append((name, deadline, clock[0]))
            return records.get(name)

        def local_command(argv, **_kwargs):
            name = argv[-1]
            reads.append((name, _kwargs.get("timeout"), clock[0]))
            raw = records.get(name)
            return (3, b"") if raw is None else (0, raw)

        def write_handoff(_cid, name, _value, deadline):
            if name == "supervisor-release.json":
                releases.append((deadline, clock[0], tuple(item[0] for item in reads)))

        def terminate(_cid, **kwargs):
            termination_calls.append((clock[0], kwargs))
            if not termination_ownership_verified:
                return {
                    "container_id": _CID, "exit_code": None,
                    "process_state": "unknown", "graceful_stop": False,
                    "forced_kill": False, "container_removed": False,
                    "cleanup_confirmed": False, "failure_type": "inspect_failed",
                    "ownership_verified": False,
                }
            return {
                "container_id": _CID, "exit_code": 0, "process_state": "exited",
                "graceful_stop": True, "forced_kill": False,
                "container_removed": True, "cleanup_confirmed": True,
                "failure_type": None, "ownership_verified": True,
            }

        def sleep(seconds):
            clock[0] += seconds

        with ExitStack() as stack:
            stack.enter_context(patch.object(supervisor, "validate_cli"))
            stack.enter_context(patch.object(supervisor, "_create_results_dir",
                                              return_value=args.result_directory))
            stack.enter_context(patch.object(supervisor, "_prepare_local_volumes"))
            stack.enter_context(patch.object(supervisor, "_create_local_container",
                                              side_effect=create_local))
            stack.enter_context(patch.object(supervisor, "_wait_local_json",
                                              side_effect=wait_local))
            stack.enter_context(patch.object(supervisor, "_validate_bundle_ready",
                                              return_value=ready))
            stack.enter_context(patch.object(supervisor, "_local_docker",
                                              return_value=b"synthetic-tar"))
            stack.enter_context(patch.object(supervisor, "validate_worker_tar",
                                              return_value={"worker.json": b"config"}))
            stack.enter_context(patch.object(supervisor, "_validate_worker_config",
                                              return_value={}))
            stack.enter_context(patch.object(
                supervisor, "_connect_ssh",
                side_effect=supervisor.SupervisorError("ssh", "synthetic_failure")))
            if actual_handoff_reader:
                stack.enter_context(patch.object(supervisor, "_local_command",
                                                  side_effect=local_command))
            else:
                stack.enter_context(patch.object(supervisor, "_read_local_handoff",
                                                  side_effect=read_handoff))
            stack.enter_context(patch.object(supervisor, "_write_local_handoff",
                                              side_effect=write_handoff))
            stack.enter_context(patch.object(supervisor, "_terminate_local_owned",
                                              side_effect=terminate))
            if persisted_report_directory is None:
                stack.enter_context(patch.object(supervisor, "_write_final_report",
                                                  side_effect=lambda _a, _d, report:
                                                  reports.append(report)))
            else:
                write_final_report = supervisor._write_final_report

                def persist_report(a, directory, report):
                    reports.append(report)
                    return write_final_report(a, directory, report)

                stack.enter_context(patch.object(supervisor, "_write_final_report",
                                                  side_effect=persist_report))
            stack.enter_context(patch.object(supervisor.time, "monotonic",
                                              side_effect=lambda: clock[0]))
            stack.enter_context(patch.object(supervisor.time, "sleep", side_effect=sleep))
            exit_code = supervisor.run_supervisor(args)
        return exit_code, reads, releases, termination_calls, reports

    def test_selected_profile_is_forwarded_and_uses_only_its_fixed_sequences(self):
        clock = [100.0]
        exit_code, *_ = self._run_supervisor_with_local_records(
            clock=clock, ready=None, records={}, profile=supervisor.PROFILE_C1B_HAPPY)
        self.assertEqual(exit_code, 1)
        self.assertEqual(
            self.last_cohort_args[self.last_cohort_args.index("--profile") + 1],
            supervisor.PROFILE_C1B_HAPPY)
        self.assertEqual(
            supervisor._PROFILE_OBSERVATIONS[supervisor.PROFILE_C1B_HAPPY],
            ((1, "greedy-one-token"), (2, "forced-length-1"),
             (3, "forced-length-128"), (4, "forced-length-1024"),
             (5, "unequal-concurrent-prompt-5"),
             (6, "unequal-concurrent-prompt-11"),
             (7, "context-boundary-1151-plus-1")))

    def test_run_missing_records_stops_waiting_at_early_cutoff_and_keeps_local_budget(self):
        clock = [100.0]
        exit_code, reads, releases, termination_calls, reports = (
            self._run_supervisor_with_local_records(
                clock=clock, ready=None, records={}))

        self.assertEqual(exit_code, 1)
        self.assertEqual(releases, [])
        self.assertTrue(reads)
        self.assertEqual({name for name, _deadline, _now in reads},
                         {"result.json", "operator-exit.json"})
        self.assertEqual(len(termination_calls), 1)
        stopped_at, kwargs = termination_calls[0]
        self.assertEqual(kwargs["termination_deadline"], 115.0)
        self.assertEqual(kwargs["observation_deadline"], 115.0)
        self.assertEqual(stopped_at, 110.0)
        self.assertEqual(kwargs["termination_deadline"] - stopped_at, 5.0)
        self.assertEqual(reports[0]["failure_type"], "synthetic_stop")
        self.assertIn({"stage": "operator", "type": "result_or_exit_record_missing"},
                      reports[0]["failures"])

    def test_run_captures_result_and_exit_before_publishing_release(self):
        clock = [100.0]
        run_id = "b" * 32
        ready = {"run_id": run_id, "nonce": "a" * 32,
                 "bundle_path": "/tmp/handoff/bundle.tar"}
        records = {
            "result.json": json.dumps({
                "schema_version": 1, "event": "result", "run_id": run_id,
                "baseline": {"status": "passed", "completed_requests": 1},
                "request_ids": [], "session_ids": [],
            }).encode("ascii"),
            "operator-exit.json": json.dumps({
                "schema_version": 1, "event": "operator_exit", "exit_code": 0,
                "failure_type": None,
            }).encode("ascii"),
        }
        exit_code, reads, releases, termination_calls, reports = (
            self._run_supervisor_with_local_records(
                clock=clock, ready=ready, records=records))

        self.assertEqual(exit_code, 1)  # The synthetic SSH startup failure remains visible.
        self.assertEqual([name for name, _deadline, _now in reads],
                         ["failure-location.json", "result.json", "operator-exit.json"])
        self.assertEqual(len(releases), 1)
        release_deadline, _release_time, prior_reads = releases[0]
        self.assertEqual(release_deadline, 110.0)
        self.assertEqual(prior_reads, (
            "failure-location.json", "result.json", "operator-exit.json"))
        self.assertEqual(len(termination_calls), 1)
        self.assertEqual(termination_calls[0][1]["termination_deadline"], 115.0)
        self.assertEqual(reports[0]["cohort"]["baseline_status"], "passed")
        self.assertEqual(reports[0]["operator_exit_code"], 0)

    @unittest.skipUnless(
        os.name == "posix", "private report writer uses POSIX no-follow flags")
    def test_run_reads_identity_bound_failure_location_into_private_report(self):
        run_id = "d" * 32
        nonce = "e" * 32
        ready = {"run_id": run_id, "nonce": nonce,
                 "bundle_path": "/tmp/handoff/bundle.tar"}
        diagnostic = {
            "schema_version": 1,
            "event": "cohort_failure_location",
            "run_id": run_id,
            "nonce": nonce,
            "failure_type": "TimeoutError",
            "frames": [{"file": "secure_cohort.py", "function": "run_case", "line": 42}],
        }
        with tempfile.TemporaryDirectory() as result_directory:
            exit_code, reads, _releases, termination_calls, reports = (
                self._run_supervisor_with_local_records(
                    clock=[100.0], ready=ready,
                    records={"failure-location.json": json.dumps(
                        diagnostic, separators=(",", ":")).encode("ascii")},
                    actual_handoff_reader=True,
                    persisted_report_directory=result_directory))

            self.assertEqual(exit_code, 1)
            names = [name for name, _deadline, _now in reads]
            self.assertEqual(names[0], "failure-location.json")
            self.assertLess(names.index("failure-location.json"),
                            names.index("result.json"))
            self.assertEqual(len(termination_calls), 1)
            self.assertLessEqual(reads[0][2], termination_calls[0][0])
            self.assertEqual(reports[0]["cohort_failure_location"], diagnostic)
            self.assertIn({"stage": "cohort_failure_location",
                           "type": "cohort_reported_failure"}, reports[0]["failures"])
            report_files = list(Path(result_directory).glob("secure-cohort-*.json"))
            self.assertEqual(len(report_files), 1)
            self.assertEqual(stat.S_IMODE(report_files[0].stat().st_mode), 0o600)
            persisted = json.loads(report_files[0].read_text(encoding="utf-8"))
            self.assertEqual(persisted["cohort_failure_location"], diagnostic)

    @unittest.skipUnless(
        os.name == "posix", "private report writer uses POSIX no-follow flags")
    def test_run_redacts_malformed_failure_location_from_persisted_report(self):
        run_id = "f" * 32
        ready = {"run_id": run_id, "nonce": "1" * 32,
                 "bundle_path": "/tmp/handoff/bundle.tar"}
        untrusted = b"not-json-private-prompt-and-token"
        with tempfile.TemporaryDirectory() as result_directory:
            exit_code, _reads, _releases, _termination_calls, reports = (
                self._run_supervisor_with_local_records(
                    clock=[100.0], ready=ready,
                    records={"failure-location.json": untrusted},
                    actual_handoff_reader=True,
                    persisted_report_directory=result_directory))

            self.assertEqual(exit_code, 1)
            self.assertEqual(reports[0]["cohort_failure_location"], {
                "observed": True, "validated": False, "failure_type": "invalid_json",
            })
            report_files = list(Path(result_directory).glob("secure-cohort-*.json"))
            self.assertEqual(len(report_files), 1)
            persisted_bytes = report_files[0].read_bytes()
            self.assertNotIn(untrusted, persisted_bytes)
            self.assertIn(b'"type":"invalid_json"', persisted_bytes)

    def test_run_reports_validated_partial_prelaunch_remote_removal_evidence(self):
        args = self._supervisor_args()
        run_id = "c" * 32
        ready = {"run_id": run_id, "nonce": "b" * 32,
                 "bundle_path": "/tmp/handoff/bundle.tar"}
        raw_removal = {
            "schema_version": 1,
            "event": "remote_job_removal",
            "job_root": args.remote_job_root,
            "uid": 1000,
            "gid": 1000,
            "confirmed": False,
            "removed": ["worker.json"],
            "residuals": ["worker.key"],
            "residuals_known": True,
            "residuals_truncated": False,
            "reason": "permission_denied",
        }
        records = {
            "result.json": json.dumps({
                "schema_version": 1, "event": "result", "run_id": run_id,
                "baseline": {"status": "failed", "completed_requests": 0},
                "request_ids": [], "session_ids": [],
                "failure_type": "synthetic_setup_failure",
            }).encode("ascii"),
            "operator-exit.json": json.dumps({
                "schema_version": 1, "event": "operator_exit", "exit_code": 1,
                "failure_type": "synthetic_setup_failure",
            }).encode("ascii"),
        }
        ssh = SimpleNamespace(close=lambda: None)
        sftp = SimpleNamespace(close=lambda: None)
        reports = []
        remote_script_calls = []
        removal_commands = []

        def create_local(**kwargs):
            kwargs["on_cid"](_CID)
            return _CID

        def remote_script(_client, script, _argv, **_kwargs):
            remote_script_calls.append(script)
            if script == supervisor._REMOTE_CREATE_JOB_SCRIPT:
                return b"created"
            if script == supervisor._REMOTE_CHECK_DIRECTORY_SCRIPT:
                raise supervisor.SupervisorError(
                    "remote_artifacts", "directory_unverified")
            self.fail("unexpected remote setup script")

        def ssh_exec(client, argv, **kwargs):
            self.assertIs(client, ssh)
            self.assertEqual(argv[:3], [
                "python3", "-c", supervisor._remote_remove_job_script()])
            self.assertEqual(argv[3:], [args.remote_job_root, "1000", "1000"])
            self.assertEqual(kwargs["output_limit"], supervisor.CONTROL_LIMIT)
            self.assertTrue(kwargs["sudo"])
            removal_commands.append(argv)
            return 1, json.dumps(raw_removal).encode("ascii")

        with ExitStack() as stack:
            stack.enter_context(patch.object(supervisor, "validate_cli"))
            stack.enter_context(patch.object(supervisor, "_create_results_dir",
                                              return_value=args.result_directory))
            stack.enter_context(patch.object(supervisor, "_prepare_local_volumes"))
            stack.enter_context(patch.object(supervisor, "_create_local_container",
                                              side_effect=create_local))
            stack.enter_context(patch.object(supervisor, "_wait_local_json",
                                              return_value=ready))
            stack.enter_context(patch.object(supervisor, "_validate_bundle_ready",
                                              return_value=ready))
            stack.enter_context(patch.object(supervisor, "_local_docker",
                                              return_value=b"synthetic-tar"))
            stack.enter_context(patch.object(supervisor, "validate_worker_tar",
                                              return_value={"worker.json": b"config"}))
            stack.enter_context(patch.object(supervisor, "_validate_worker_config",
                                              return_value={}))
            stack.enter_context(patch.object(
                supervisor, "_connect_ssh",
                return_value=(ssh, "d" * 64, None)))
            stack.enter_context(patch.object(supervisor, "_open_sftp",
                                              return_value=sftp))
            stack.enter_context(patch.object(supervisor, "_remote_user_ids",
                                              return_value=(1000, 1000)))
            stack.enter_context(patch.object(
                supervisor, "_sftp_call",
                side_effect=lambda _sftp, _deadline, _stage, call: call()))
            stack.enter_context(patch.object(supervisor, "_abort_sftp"))
            stack.enter_context(patch.object(supervisor, "_remote_script",
                                              side_effect=remote_script))
            # Keep the production _remove_remote_job parser/validator active;
            # only its SSH command boundary is synthetic.
            stack.enter_context(patch.object(supervisor, "_ssh_exec",
                                              side_effect=ssh_exec))
            stack.enter_context(patch.object(
                supervisor, "_read_local_handoff",
                side_effect=lambda _cid, name, *_a, **_k: records.get(name)))
            stack.enter_context(patch.object(supervisor, "_write_local_handoff"))
            stack.enter_context(patch.object(
                supervisor, "_terminate_local_owned", return_value={
                    "container_id": _CID, "exit_code": 0,
                    "process_state": "exited", "graceful_stop": True,
                    "forced_kill": False, "container_removed": True,
                    "cleanup_confirmed": True, "failure_type": None,
                    "ownership_verified": True,
                }))
            stack.enter_context(patch.object(
                supervisor, "_write_final_report",
                side_effect=lambda _args, _directory, report: reports.append(report)))
            exit_code = supervisor.run_supervisor(args)

        self.assertEqual(remote_script_calls, [
            supervisor._REMOTE_CREATE_JOB_SCRIPT,
            supervisor._REMOTE_CHECK_DIRECTORY_SCRIPT,
        ])
        self.assertEqual(len(removal_commands), 1)
        self.assertEqual(exit_code, 1)
        self.assertEqual(len(reports), 1)
        report = reports[0]
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["cohort"]["baseline_status"], "failed")
        self.assertFalse(report["remote_worker"]["cleanup_confirmed"])
        self.assertFalse(report["remote_worker"]["private_files_removed"])
        self.assertFalse(report["remote_worker"]["job_root_removed"])
        self.assertEqual(report["remote_worker"]["removal_evidence"], raw_removal)
        for field in ("removed", "residuals", "reason",
                      "residuals_known", "residuals_truncated"):
            self.assertEqual(report["remote_worker"]["removal_evidence"][field],
                             raw_removal[field])

    @unittest.skipUnless(
        os.name == "posix", "private report writer uses POSIX no-follow flags")
    def test_run_upload_owner_fences_prelaunch_removal_and_ssh_close(self):
        self.assertEqual(supervisor._pending_channel_operation_count(), 0)
        args = self._supervisor_args()
        run_id = f"{time.time_ns():032x}"
        ready = {"run_id": run_id, "nonce": "c" * 32,
                 "bundle_path": "/tmp/handoff/bundle.tar"}
        records = {
            "result.json": json.dumps({
                "schema_version": 1, "event": "result", "run_id": run_id,
                "baseline": {"status": "failed", "completed_requests": 0},
                "request_ids": [], "session_ids": [],
                "failure_type": "ack_timeout_unknown",
            }).encode("ascii"),
            "operator-exit.json": json.dumps({
                "schema_version": 1, "event": "operator_exit", "exit_code": 1,
                "failure_type": "ack_timeout_unknown",
            }).encode("ascii"),
        }
        operation_started = threading.Event()
        operation_release = threading.Event()
        channel_close_started = threading.Event()
        ssh_close_started = threading.Event()
        ssh_close_release = threading.Event()
        channel_errors = []
        remote_script_calls = []
        remote_removal = []

        class BlockingOperationChannel:
            def close(self):
                channel_close_started.set()
                operation_release.wait(3)

        def blocking_operation():
            operation_started.set()
            operation_release.wait(3)

        def upload_fails_with_owned_request(*_args, **_kwargs):
            try:
                supervisor._channel_operation(
                    BlockingOperationChannel(), blocking_operation,
                    deadline=time.monotonic() + 0.15,
                    stage="bundle_upload", failure_code="transfer_failed")
            except supervisor.SupervisorError as error:
                channel_errors.append(error.code)
                if not channel_close_started.wait(1):
                    raise AssertionError("timed-out channel close did not start")
                self.assertEqual(supervisor._pending_channel_operation_count(), 1)
                raise
            raise AssertionError("blocked upload operation unexpectedly completed")

        class BlockingSSHClient:
            def close(self):
                ssh_close_started.set()
                ssh_close_release.wait(3)

        ssh = BlockingSSHClient()
        sftp = SimpleNamespace(close=lambda: None)
        bounded_termination_deadline = time.monotonic() + 0.4

        def remote_script(_client, script, _argv, **_kwargs):
            remote_script_calls.append(script)
            if script == supervisor._REMOTE_CREATE_JOB_SCRIPT:
                return b"created"
            if script == supervisor._REMOTE_CHECK_DIRECTORY_SCRIPT:
                return b"ok"
            self.fail("unexpected remote setup script")

        with ExitStack() as report_cleanup:
            args.result_directory = Path(report_cleanup.enter_context(
                tempfile.TemporaryDirectory(
                    prefix="supervisor-race-",
                    dir=Path(__file__).resolve().parent if os.name == "nt" else None)))
            report_path = args.result_directory / f"secure-cohort-{run_id}.json"
            report_cleanup.callback(lambda: report_path.unlink(missing_ok=True))
            try:
                with ExitStack() as stack:
                    stack.enter_context(patch.object(supervisor, "validate_cli"))
                    stack.enter_context(patch.object(supervisor, "_prepare_local_volumes"))
                    stack.enter_context(patch.object(
                        supervisor, "_create_local_container",
                        side_effect=lambda **kwargs: (kwargs["on_cid"](_CID), _CID)[1]))
                    stack.enter_context(patch.object(
                        supervisor, "_wait_local_json", return_value=ready))
                    stack.enter_context(patch.object(
                        supervisor, "_validate_bundle_ready", return_value=ready))
                    stack.enter_context(patch.object(
                        supervisor, "_local_docker", return_value=b"synthetic-tar"))
                    stack.enter_context(patch.object(
                        supervisor, "validate_worker_tar",
                        return_value={"worker.json": b"config"}))
                    stack.enter_context(patch.object(
                        supervisor, "_validate_worker_config", return_value={}))
                    stack.enter_context(patch.object(
                        supervisor, "_connect_ssh", return_value=(ssh, "f" * 64, None)))
                    stack.enter_context(patch.object(
                        supervisor, "_open_sftp", return_value=sftp))
                    stack.enter_context(patch.object(
                        supervisor, "_remote_user_ids", return_value=(1000, 1000)))
                    stack.enter_context(patch.object(
                        supervisor, "_sftp_call",
                        side_effect=lambda _sftp, _deadline, _stage, call: call()))
                    stack.enter_context(patch.object(supervisor, "_abort_sftp"))
                    stack.enter_context(patch.object(
                        supervisor, "_remote_script", side_effect=remote_script))
                    stack.enter_context(patch.object(
                        supervisor, "_sftp_upload_bundle",
                        side_effect=upload_fails_with_owned_request))
                    stack.enter_context(patch.object(
                        supervisor, "_remove_remote_job",
                        side_effect=lambda *a, **k: remote_removal.append((a, k))))
                    stack.enter_context(patch.object(
                        supervisor, "_read_local_handoff",
                        side_effect=lambda _cid, name, *_a, **_k: records.get(name)))
                    stack.enter_context(patch.object(supervisor, "_write_local_handoff"))
                    stack.enter_context(patch.object(
                        supervisor, "_terminate_local_owned", return_value={
                            "container_id": _CID, "exit_code": 0,
                            "process_state": "exited", "graceful_stop": True,
                            "forced_kill": False, "container_removed": True,
                            "cleanup_confirmed": True, "failure_type": None,
                            "ownership_verified": True,
                        }))
                    stack.enter_context(patch.object(
                        supervisor, "_termination_deadline_once",
                        side_effect=lambda _deadline: (
                            lambda: bounded_termination_deadline)))
                    exit_code = supervisor.run_supervisor(args)

                self.assertTrue(operation_started.is_set())
                self.assertEqual(channel_errors, ["ack_timeout_unknown"])
                self.assertEqual(exit_code, 1)
                self.assertEqual(remote_script_calls, [
                    supervisor._REMOTE_CREATE_JOB_SCRIPT,
                    supervisor._REMOTE_CHECK_DIRECTORY_SCRIPT,
                ])
                self.assertEqual(remote_removal, [])
                self.assertFalse(ssh_close_started.is_set())

                self.assertTrue(report_path.is_file())
                report = json.loads(report_path.read_text(encoding="utf-8"))
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["failure_stage"], "bundle_upload")
                self.assertEqual(report["failure_type"], "ack_timeout_unknown")
                self.assertEqual(report["job_root_state"], "created")
                self.assertFalse(report["remote_worker"]["private_files_removed"])
                self.assertFalse(report["remote_worker"]["job_root_removed"])
                self.assertFalse(report["remote_worker"]["cleanup_confirmed"])
                self.assertIsNone(report["remote_worker"]["removal_evidence"])
                self.assertIn({
                    "stage": "remote_bundle_cleanup",
                    "type": "operation_ownership_pending",
                }, report["failures"])
                self.assertIn({
                    "stage": "ssh_close", "type": "operation_ownership_pending",
                }, report["failures"])
                self.assertEqual(len(report["pending_transport_operations"]), 1)
                pending = report["pending_transport_operations"][0]
                self.assertEqual(pending["stage"], "bundle_upload")
                self.assertEqual(pending["state"], "unknown_pending_retirement")
                self.assertEqual(pending["failure_code"], "ack_timeout_unknown")
                self.assertTrue(pending["close_started"])
            finally:
                operation_release.set()
                ssh_close_release.set()
                cleanup_deadline = time.monotonic() + 2
                while (supervisor._pending_channel_operation_count()
                       and time.monotonic() < cleanup_deadline):
                    time.sleep(0.01)
            self.assertEqual(supervisor._pending_channel_operation_count(), 0)

    def test_run_keeps_discovered_cid_candidate_fenced_when_ownership_stays_unknown(self):
        clock = [100.0]
        exit_code, reads, releases, termination_calls, reports = (
            self._run_supervisor_with_local_records(
                clock=clock, ready=None, records={}, local_create_error=True,
                termination_ownership_verified=False))

        self.assertEqual(exit_code, 1)
        self.assertEqual(reads, [])
        self.assertEqual(releases, [])
        self.assertEqual(len(termination_calls), 1)
        self.assertEqual(reports[0]["local_operator"]["container_id"], _CID)
        self.assertEqual(reports[0]["local_operator"]["ownership_status"], "candidate")
        self.assertFalse(reports[0]["local_operator"]["ownership_verified"])
        self.assertIn({"stage": "local_start", "type": "container_ownership_unverified"},
                      reports[0]["failures"])

    def test_stop_response_publication_is_never_retried(self):
        state = {"stop_response": "not_attempted"}
        deadline = supervisor.time.monotonic() + 5
        with patch.object(supervisor, "_write_local_handoff") as writer:
            supervisor._publish_stop_response_once(
                _CID, {"event": "stop_ack"}, deadline, state)
            self.assertEqual(state["stop_response"], "published")
            with self.assertRaisesRegex(supervisor.SupervisorError,
                                       "duplicate_publication_fenced"):
                supervisor._publish_stop_response_once(
                    _CID, {"event": "stop_ack"}, deadline, state)
            self.assertEqual(writer.call_count, 1)

        uncertain = {"stop_response": "not_attempted"}
        with patch.object(supervisor, "_write_local_handoff",
                          side_effect=supervisor.SupervisorError(
                              "local_handoff", "write_uncertain")) as writer:
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._publish_stop_response_once(
                    _CID, {"event": "stop_ack"}, deadline, uncertain)
            self.assertEqual(uncertain["stop_response"], "attempted_unknown")
            with self.assertRaisesRegex(supervisor.SupervisorError,
                                       "duplicate_publication_fenced"):
                supervisor._publish_stop_response_once(
                    _CID, {"event": "stop_ack"}, deadline, uncertain)
            self.assertEqual(writer.call_count, 1)

    def test_still_running_local_container_is_not_removed_or_marked_graceful(self):
        deadline = supervisor.time.monotonic() + 9
        states = iter((
            {"running": True, "exit_code": None},
            {"running": True, "exit_code": None},
            {"running": True, "exit_code": None},
        ))
        docker_calls = []
        inspect_deadlines = []

        def inspect(_cid, **kwargs):
            inspect_deadlines.append(kwargs["deadline"])
            return next(states)

        def docker(argv, **kwargs):
            docker_calls.append((argv, kwargs["deadline"]))
            return b""

        with patch.object(supervisor, "_docker_inspect_local", side_effect=inspect), \
                patch.object(supervisor, "_local_docker", side_effect=docker):
            evidence = supervisor._terminate_local_owned(
                _CID, name="owned-local", owner="run-owner", image="local-image",
                termination_deadline=deadline, observation_deadline=deadline)

        self.assertEqual([entry[0][1] for entry in docker_calls], ["stop", "kill"])
        self.assertTrue(all(call_deadline == deadline for _, call_deadline in docker_calls))
        self.assertEqual(inspect_deadlines, [deadline, deadline, deadline])
        self.assertEqual(evidence["process_state"], "running")
        self.assertFalse(evidence["container_removed"])
        self.assertFalse(evidence["cleanup_confirmed"])
        self.assertFalse(evidence["graceful_stop"])

    def test_forced_kill_is_removed_only_after_exit_and_never_graceful(self):
        deadline = supervisor.time.monotonic() + 9
        states = iter((
            {"running": True, "exit_code": None},
            {"running": True, "exit_code": None},
            {"running": False, "exit_code": 137},
        ))
        commands = []

        def docker(argv, **kwargs):
            commands.append((argv, kwargs["deadline"]))
            return b""

        with patch.object(supervisor, "_docker_inspect_local",
                          side_effect=lambda *_a, **_k: next(states)), \
                patch.object(supervisor, "_local_docker", side_effect=docker):
            evidence = supervisor._terminate_local_owned(
                _CID, name="owned-local", owner="run-owner", image="local-image",
                termination_deadline=deadline, observation_deadline=deadline)

        self.assertEqual([entry[0][1] for entry in commands], ["stop", "kill", "rm"])
        self.assertTrue(all(command_deadline == deadline
                            for _, command_deadline in commands))
        self.assertTrue(evidence["container_removed"])
        self.assertTrue(evidence["cleanup_confirmed"])
        self.assertTrue(evidence["forced_kill"])
        self.assertFalse(evidence["graceful_stop"])
        self.assertEqual(evidence["failure_type"], "forced_kill")

    def test_termination_deadline_is_absolute_and_nonrenewing(self):
        clock = [100.0]
        with patch.object(supervisor.time, "monotonic", side_effect=lambda: clock[0]):
            deadline = supervisor._termination_deadline_once(500.0)
            first = deadline()
            clock[0] = 140.0
            second = deadline()
        self.assertEqual(first, 100.0 + supervisor.TERMINATION_SECONDS)
        self.assertEqual(second, first)


if __name__ == "__main__":
    unittest.main()
