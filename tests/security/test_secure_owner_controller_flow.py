"""Controlled executions of the C1b owner controller's action boundary."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(_REPOSITORY_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT / "src"))
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from lab import secure_cohort, secure_cohort_supervisor as supervisor
from lab.secure_cohort_owner import (
    PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE,
    OwnerExpectation, build_owner_action_request,
    validate_owner_action_request,
)


class OwnerControllerActionFlowTests(unittest.TestCase):
    """Execute the actual controller action code against bounded fake I/O."""

    @classmethod
    def setUpClass(cls):
        try:
            from tests.security import test_secure_cohort_owner as fixture_module
            from tests.security.secure_pipeline_fixture import SecurePipelineIdentityFixture
        except ModuleNotFoundError as error:
            if error.name not in {"google", "grpc", "grpc_tools", "numpy"}:
                raise
            raise unittest.SkipTest(
                f"owner flow optional dependency unavailable: {error.name}")
        cls.fixture_module = fixture_module
        cls.identity_fixture_type = SecurePipelineIdentityFixture

    def _run_action(self, profile, *, sequence=1):
        fixture = self.fixture_module.OwnerResponseSchemaTests(
            "test_action_response_drain_and_remove_round_trip")
        if profile == PROFILE_C1B_OWNER_DRAIN:
            expected = self.fixture_module.expected(profile)
            config = fixture._config(expected)
            source_response = None
            parsed = validate_owner_action_request(
                self.fixture_module.owner.build_owner_action_request(
                    expected, sequence,
                    self.fixture_module.command(profile, sequence)), expected)
            request = build_owner_action_request(
                expected, sequence,
                self.fixture_module.command(profile, sequence))
            initial_view = initial_store = None
            bundle_files = {}
            initial_serials = ["a1", "b2"]
            intent_root = None
            owner_state = {
                "handled_requests": [], "action_responses": [],
                "command_sha256s": [], "prepared_commands": [],
                "intent_receipts": {}, "action_frames": {}, "attempts": [],
                "observation_acks": [], "delivered_handoffs": [],
            }
            material_setup = mock.patch.object(
                supervisor, "_wait_owner_materials",
                side_effect=AssertionError("drain must not stage removal materials"))
            publication_receipts = {}
        else:
            if os.name != "posix" or not hasattr(os, "geteuid"):
                self.skipTest("signed owner material execution requires POSIX protected files")
            authority = self.identity_fixture_type(
                "9" * 64, clock_uncertainty_seconds=0.25)
            self.addCleanup(authority.close)
            worker = authority.principals["worker-3"]
            store, _clock = authority.new_store()
            initial_view = store.current()
            expected = OwnerExpectation(
                profile=profile, run_id="a" * 32, nonce="b" * 32,
                worker_boot_id=worker.boot_id, manifest_fingerprint="9" * 64,
                endpoint="127.0.0.1:50061",
                initial_snapshot_sha256=hashlib.sha256(authority.signed_snapshot).hexdigest(),
                initial_revision=initial_view.revision)
            config = {
                "account_id": worker.account_id, "device_id": worker.device_id,
                "boot_id": worker.boot_id, "assignment_id": worker.assignment_id,
                "model_id": "9" * 64, "model_revision": "rev-owner",
                "manifest_fingerprint": expected.manifest_fingerprint,
                "listen_ip": "127.0.0.1", "listen_port": 50061,
                "clock_uncertainty_seconds": 0.25,
            }
            prepared = secure_cohort._prepare_owner_materials(
                authority, expected, command_ids=("3" * 32, "4" * 32))
            files = prepared["files"]
            wrapper = prepared["ready"]
            archive = self.fixture_module.make_archive(files)
            command_doc = prepared["commands"][sequence - 1]
            request = build_owner_action_request(expected, sequence, command_doc)
            parsed = validate_owner_action_request(request, expected)
            initial_serials = prepared["initial_local_serials"]
            bundle_files = {
                "snapshot.pub": authority.snapshot_verification_key_pem,
                "cohort-ca.crt": authority.cohort_ca_pem,
            }
            source_response = None
            intent_root = "/srv/job-owner-intents"
            owner_state = {
                "handled_requests": [], "action_responses": [],
                "command_sha256s": [], "prepared_commands": [],
                "intent_receipts": {}, "action_frames": {}, "attempts": [],
                "observation_acks": [], "delivered_handoffs": [],
            }
            publication_receipts = {}
            material_setup = mock.patch.object(
                supervisor, "_wait_owner_materials",
                side_effect=lambda *_args, **_kwargs:
                    supervisor._verify_owner_material_bundle(
                        expected, wrapper, archive, initial_view=initial_view,
                        snapshot_store=store,
                        verifier_pem=authority.snapshot_verification_key_pem,
                        initial_local_serials=initial_serials,
                        initial_device_id=config["device_id"]))

        if profile == PROFILE_C1B_OWNER_REMOVE:
            endpoint_patcher = mock.patch.object(
                self.fixture_module, "ENDPOINT", expected.endpoint)
            endpoint_patcher.start()
            self.addCleanup(endpoint_patcher.stop)

        ack = (source_response["worker_ack"] if source_response is not None else
               self.fixture_module.ack_for(
                   expected, parsed, received=100, completed=200,
                   phase="draining",
                   digest=(None if profile == PROFILE_C1B_OWNER_DRAIN
                           else parsed.snapshot_sha256),
                   revision=(None if profile == PROFILE_C1B_OWNER_DRAIN
                             else parsed.snapshot_revision)))
        status_config = config
        if source_response is not None:
            status = source_response["protected_status"]["remote_status"]
            status_frame = source_response["protected_status"]
            publication_receipts = source_response["publication"]
        else:
            status = fixture._status(
                expected, status_config, ack, event="heartbeat",
                lifecycle_phase="draining")
            status_frame = {
                "measurement_label": "ssh_protected_owner_status_v1",
                "ssh_host_key_sha256": "6" * 64, "remote_mark_ns": 10,
                "heartbeat_mtime_ns": 11, "remote_status_uid": 1000,
                "remote_status_mode": 0o600, "remote_status": status,
            }
            if profile == PROFILE_C1B_OWNER_REMOVE:
                for kind, raw in (
                        ("install_intent", files["install-intent.json"]),
                        ("removal_intent", files["removal-intent.json"]),
                        ("policy1", files["install-snapshot.json"])):
                    publication_receipts[kind] = fixture._receipt(
                        kind, hashlib.sha256(raw).hexdigest(), len(raw))
                publication_receipts["policy"] = publication_receipts.pop("policy1")
        provenance = {
            "uid": 1000, "gid": 1000, "mode": 0o600,
            "size": len(json.dumps(ack)), "mtime_ns": 11,
            "sha256": "7" * 64, "metadata_stable": True,
        }
        observed = []

        def publish(_ssh, data, *, kind, on_attempt=None, **_kwargs):
            observed.append(("publish", kind))
            if on_attempt is not None:
                on_attempt()
            receipt = publication_receipts.get(kind)
            if receipt is None:
                if kind.startswith("command"):
                    receipt_size = len(self.fixture_module.owner._canonical_bytes(
                        self.fixture_module.owner._command_document(parsed)))
                    receipt_digest = parsed.command_sha256
                else:
                    receipt_size = len(data)
                    receipt_digest = hashlib.sha256(data).hexdigest()
                receipt = fixture._receipt(
                    kind, receipt_digest, receipt_size)
                publication_receipts[kind] = receipt
            return receipt

        with material_setup, \
                mock.patch.object(supervisor, "_terminal_controls"), \
                mock.patch.object(supervisor, "_read_local_handoff",
                                  return_value=supervisor._json_bytes(request)), \
                mock.patch.object(supervisor, "_remote_mark", return_value=10), \
                mock.patch.object(supervisor, "_publish_owner_file", side_effect=publish), \
                mock.patch.object(supervisor, "_read_owner_ack",
                                  return_value=(ack, provenance)), \
                mock.patch.object(supervisor, "_read_remote_status",
                                  return_value={
                                      "uid": 1000, "mode": 0o600,
                                      "mtime_ns": 11, "mark_ns": 10,
                                      "status": status}), \
                mock.patch.object(supervisor, "_write_local_handoff",
                                  side_effect=lambda _cid, name, _value, _deadline:
                                  observed.append(("handoff", name))), \
                mock.patch.object(supervisor, "_wait_owner_container_exit",
                                  return_value={"process_state": "exited", "exit_code": 0}) as exit_wait:
            response, command, _frame = supervisor._handle_owner_action(
                local_cid="c" * 64, number=sequence, expected=expected,
                ready={"run_id": expected.run_id}, config=config,
                bundle_files=bundle_files, initial_view=initial_view,
                initial_store=initial_view and store, initial_serials=initial_serials,
                host_key="6" * 64, ssh=object(), password=None,
                job_root="/srv/job", intent_root=intent_root,
                uid=1000, gid=1000, container_id="d" * 64,
                container_name="worker", owner_label="owner", image="image",
                deadline=time.monotonic() + 20, owner_state=owner_state)
        self.assertEqual(response["command_sha256"], command.command_sha256)
        self.assertEqual(owner_state["handled_requests"], [request])
        self.assertEqual(owner_state["action_responses"], [response])
        self.assertEqual(observed[-1], ("handoff", f"owner-action-response-{sequence}.json"))
        if profile == PROFILE_C1B_OWNER_DRAIN:
            self.assertEqual([item[1] for item in observed if item[0] == "publish"], ["command1"])
            exit_wait.assert_not_called()
        else:
            self.assertEqual([item[1] for item in observed if item[0] == "publish"], [
                "install_intent", "removal_intent", "policy1", "command1"])
            self.assertTrue(owner_state["intent_publication_complete"])
            self.assertEqual(owner_state["attempts"] and
                             [item["kind"] for item in owner_state["attempts"]], [
                                 "install_intent", "removal_intent", "policy1", "command1"])

    def test_drain_action_handler_executes_actual_protocol_path(self):
        self._run_action(PROFILE_C1B_OWNER_DRAIN)

    def test_remove_action_handler_executes_actual_protocol_path(self):
        self._run_action(PROFILE_C1B_OWNER_REMOVE)

    def test_remove_observation_six_rejects_a_still_held_session_before_ack(self):
        fixture = self.fixture_module.OwnerResponseSchemaTests(
            "test_owner_result_drain_and_remove_schema_fixtures")
        expected, _result = fixture._result_fixture(PROFILE_C1B_OWNER_REMOVE)
        config = fixture._config(expected)
        request, response = fixture._response(expected, 1)
        command = self.fixture_module.owner.validate_owner_command_ack(
            response["worker_ack"],
            self.fixture_module.owner._command_dict(
                self.fixture_module.command(PROFILE_C1B_OWNER_REMOVE, 1), expected),
            expected)
        held_status = fixture._status(
            expected, config, command, event="heartbeat",
            lifecycle_phase="draining", session_id="ses_" + "a" * 32, held=True)
        frame = {"uid": 1000, "mode": 0o600, "mtime_ns": 301,
                 "mark_ns": 300, "status": held_status}
        published = []
        with mock.patch.object(supervisor, "_read_remote_status", return_value=frame), \
                mock.patch.object(supervisor, "_remote_observation_ack",
                                  side_effect=lambda *args, **kwargs:
                                  published.append((args, kwargs))):
            with self.assertRaises(supervisor.SupervisorError) as caught:
                supervisor._wait_remote_status(
                    object(), config=config, password=None, status_path="/job/status.json",
                    mark_ns=300, deadline=time.monotonic() + 1,
                    expected_events={"heartbeat"}, owner_expected=expected,
                    owner_command=response["worker_ack"], owner_observation=True)
        self.assertEqual((caught.exception.stage, caught.exception.code),
                         ("remote_status", "owner_not_globally_idle"))
        self.assertEqual(published, [])

    def test_wait_completion_correlates_ack_provenance_and_worker_status(self):
        fixture = self.fixture_module.OwnerResponseSchemaTests(
            "test_action_response_drain_and_remove_round_trip")
        expected = self.fixture_module.expected(PROFILE_C1B_OWNER_DRAIN)
        config = fixture._config(expected)
        request, response = fixture._response(expected, 1)
        command = self.fixture_module.owner.validate_owner_action_request(
            request, expected)
        ack = response["worker_ack"]
        protected = response["protected_status"]
        frame = {
            "uid": protected["remote_status_uid"],
            "mode": protected["remote_status_mode"],
            "mtime_ns": protected["heartbeat_mtime_ns"],
            "mark_ns": protected["remote_mark_ns"],
            "status": protected["remote_status"],
        }
        provenance = {"mtime_ns": protected["heartbeat_mtime_ns"]}
        with mock.patch.object(supervisor, "_read_owner_ack",
                               return_value=(ack, provenance)), \
                mock.patch.object(supervisor, "_read_remote_status", return_value=frame):
            checked, actual_provenance, actual_frame = (
                supervisor._wait_owner_command_completion(
                    object(), config=config, expected=expected,
                    expected_command=command, password=None, job_root="/job",
                    uid=1000, gid=1000, mark_ns=protected["remote_mark_ns"],
                    deadline=time.monotonic() + 1))
        self.assertEqual(checked, ack)
        self.assertIs(actual_provenance, provenance)
        self.assertIs(actual_frame, frame)

    def test_drain_run_supervisor_executes_owned_transcript_and_captures_result(self):
        self._run_supervisor_transcript(PROFILE_C1B_OWNER_DRAIN)

    def test_remove_run_supervisor_executes_owned_transcript_and_captures_result(self):
        self._run_supervisor_transcript(PROFILE_C1B_OWNER_REMOVE)
        if os.name == "posix" and hasattr(os, "geteuid"):
            for outcome in ("unconfirmed", "nonzero"):
                with self.subTest(cleanup_outcome=outcome):
                    self._run_supervisor_transcript(
                        PROFILE_C1B_OWNER_REMOVE, cleanup_outcome=outcome)

    def _run_supervisor_transcript(self, profile, *, cleanup_outcome=None):
        fixture = self.fixture_module.OwnerResponseSchemaTests(
            "test_owner_result_drain_and_remove_schema_fixtures")
        authority = None
        prepared = None
        if profile == PROFILE_C1B_OWNER_REMOVE:
            if os.name != "posix" or not hasattr(os, "geteuid"):
                self.skipTest("signed owner materials require POSIX protected files")
            authority = self.identity_fixture_type(
                "9" * 64, clock_uncertainty_seconds=0.25)
            self.addCleanup(authority.close)
            worker = authority.principals["worker-3"]
            initial_store, _clock = authority.new_store()
            initial_view = initial_store.current()
            expected = OwnerExpectation(
                profile=profile, run_id="a" * 32, nonce="b" * 32,
                worker_boot_id=worker.boot_id, manifest_fingerprint="9" * 64,
                endpoint="10.1.2.3:50061",
                initial_snapshot_sha256=hashlib.sha256(authority.signed_snapshot).hexdigest(),
                initial_revision=initial_view.revision)
            config = {
                "account_id": worker.account_id, "device_id": worker.device_id,
                "boot_id": worker.boot_id, "assignment_id": worker.assignment_id,
                "model_id": "9" * 64, "model_revision": "rev-owner",
                "manifest_fingerprint": expected.manifest_fingerprint,
                "listen_ip": "10.1.2.3", "listen_port": 50061,
                "clock_uncertainty_seconds": 0.25,
            }
            prepared = secure_cohort._prepare_owner_materials(
                authority, expected, command_ids=("3" * 32, "4" * 32))
            endpoint_patcher = mock.patch.object(
                self.fixture_module, "ENDPOINT", expected.endpoint)
            endpoint_patcher.start()
            self.addCleanup(endpoint_patcher.stop)
            command_patcher = mock.patch.object(
                self.fixture_module, "command",
                side_effect=lambda _profile, sequence: prepared["commands"][sequence - 1])
            command_patcher.start()
            self.addCleanup(command_patcher.stop)
            with mock.patch.object(self.fixture_module, "expected", return_value=expected), \
                    mock.patch.object(fixture, "_config", return_value=config):
                _fixture_expected, template = fixture._result_fixture(profile)
        else:
            expected = self.fixture_module.expected(profile)
            endpoint_patcher = mock.patch.object(
                self.fixture_module, "ENDPOINT", expected.endpoint)
            endpoint_patcher.start()
            self.addCleanup(endpoint_patcher.stop)
            _fixture_expected, template = fixture._result_fixture(profile)
            config = fixture._config(expected)
        host_key = "6" * 64
        ready = {
            "run_id": expected.run_id, "nonce": expected.nonce,
            "expected_boot_id": expected.worker_boot_id,
            "manifest_fingerprint": expected.manifest_fingerprint,
            "snapshot_sha256": expected.initial_snapshot_sha256,
            "endpoint": expected.endpoint, "bundle_path": "/handoff/bundle.tar",
        }
        if profile == PROFILE_C1B_OWNER_REMOVE:
            bundle_files = {
                "worker.json": json.dumps(config, sort_keys=True).encode("ascii"),
                "snapshot.json": authority.signed_snapshot,
                "snapshot.pub": authority.snapshot_verification_key_pem,
                "cohort-ca.crt": authority.cohort_ca_pem,
            }
            initial_context = supervisor._owner_initial_context(
                profile, ready, config, bundle_files)
            initial_view = initial_context[3]
            initial_store = initial_context[2]
            initial_serials = initial_context[4]
            self.assertEqual(initial_serials, prepared["initial_local_serials"])
        else:
            bundle_files = {
                "worker.json": b"worker", "snapshot.pub": b"pub",
                "cohort-ca.crt": b"ca", "snapshot.json": b"snapshot",
            }
            initial_context = None
        probe_observation = template["owner_actions"]["observations"][0]
        request_id, session_id = probe_observation["request_id"], probe_observation["session_id"]
        requests = {}
        for sequence, case_id in supervisor._PROFILE_OBSERVATIONS[profile]:
            requests[f"observation-request-{sequence}.json"] = secure_cohort.build_observation_request(
                secure_cohort.RemoteExpectation(
                    expected.run_id, expected.nonce, "worker-3", config["account_id"],
                    config["device_id"], expected.worker_boot_id, config["assignment_id"],
                    config["model_id"], config["model_revision"],
                    config["manifest_fingerprint"], expected.initial_snapshot_sha256,
                    expected.endpoint, config["clock_uncertainty_seconds"], (6, 8)),
                sequence=sequence, case_id=case_id, request_id=request_id,
                session_id=session_id, profile=profile)
        if profile == PROFILE_C1B_OWNER_REMOVE:
            for number, command_doc in enumerate(prepared["commands"], 1):
                requests[f"owner-action-request-{number}.json"] = build_owner_action_request(
                    expected, number, command_doc)
        else:
            for number in (1, 2):
                command_doc = self.fixture_module.command(profile, number)
                requests[f"owner-action-request-{number}.json"] = build_owner_action_request(
                    expected, number, command_doc)
        stop_request = {
            "schema_version": 1, "event": "stop", "run_id": expected.run_id,
            "nonce": expected.nonce, "expected_boot_id": expected.worker_boot_id,
            "may_have_started": True, "maximum_wait_seconds": 15,
        }
        owner_state = {"action_responses": [], "observation_acks": []}
        observations_seen = []
        actions_seen = []
        handoffs = []
        report_rows = []
        capture_ns = []
        marks = {"value": 10, "sequence": 0}
        real_monotonic = time.monotonic
        coherent_clock = {"seconds": real_monotonic()}
        stop_deadlines = []
        local_stop_deadlines = []
        statuses = {}
        ready_status = fixture._status(expected, config, None, event="ready",
                                       lifecycle_phase="ready")
        statuses[0] = ready_status
        for sequence in (1, 2, 3, 4):
            statuses[sequence] = fixture._status(
                expected, config, None, event="heartbeat", lifecycle_phase="ready")
        for sequence in (5, 6, 7):
            command_number = (2 if sequence >= 6 else 0)
            if profile == PROFILE_C1B_OWNER_REMOVE and sequence == 6:
                command_number = 1
            parsed = (self.fixture_module.owner.validate_owner_action_request(
                requests[f"owner-action-request-{command_number}.json"], expected)
                if command_number else None)
            event = ("final" if profile == PROFILE_C1B_OWNER_REMOVE and sequence == 7
                     else "heartbeat")
            statuses[sequence] = fixture._status(
                expected, config, parsed, event=event,
                lifecycle_phase=("ready" if sequence == 5 else
                                 "paused" if sequence == 7 else "draining"),
                session_id=(session_id if sequence == 5 or
                            (profile == PROFILE_C1B_OWNER_DRAIN and sequence == 6)
                            else None),
                held=(sequence == 5 or
                      (profile == PROFILE_C1B_OWNER_DRAIN and sequence == 6)),
                stopped=(profile == PROFILE_C1B_OWNER_REMOVE and sequence == 7))

        def read_handoff(_cid, name, _deadline=None, **_kwargs):
            if name.startswith("observation-request-"):
                marks["sequence"] = int(name.split("-")[-1].split(".")[0])
            elif name.startswith("owner-action-request-"):
                actions_seen.append(name)
                marks["command"] = int(name.split("-")[-1].split(".")[0])
            value = requests.get(name)
            if value is None and name == "stop-request.json":
                value = stop_request
            return None if value is None else supervisor._json_bytes(value)

        def read_remote_status(*_args, **_kwargs):
            sequence = marks["sequence"]
            current_command = marks.get("command", 0)
            if current_command:
                parsed = self.fixture_module.owner.validate_owner_action_request(
                    requests[f"owner-action-request-{current_command}.json"], expected)
                event = ("final" if profile == PROFILE_C1B_OWNER_REMOVE
                         and current_command == 2 else "heartbeat")
                status = fixture._status(
                    expected, config, parsed, event=event,
                    lifecycle_phase=("paused" if event == "final" or
                                     (profile == PROFILE_C1B_OWNER_DRAIN
                                      and sequence == 7) else "draining"),
                    session_id=(session_id if profile == PROFILE_C1B_OWNER_DRAIN
                                and sequence in (5, 6) else None),
                    held=(profile == PROFILE_C1B_OWNER_DRAIN and sequence in (5, 6)),
                    stopped=event == "final")
            else:
                status = statuses.get(sequence, ready_status)
            return {"uid": 1000, "mode": 0o600,
                    "mtime_ns": marks["value"] + 1, "mark_ns": marks["value"],
                    "status": status}

        def mark_remote(*_args, **_kwargs):
            marks["value"] += 10
            return marks["value"]

        def advance_clock():
            coherent_clock["seconds"] += 0.001
            return coherent_clock["seconds"]

        def monotonic():
            return advance_clock()

        def monotonic_ns():
            return int(advance_clock() * 1_000_000_000)

        def publish(_ssh, data, *, kind, on_attempt=None, **_kwargs):
            if on_attempt is not None:
                on_attempt()
            if kind.startswith("command"):
                request_number = int(kind[-1])
                marks["command"] = request_number
                parsed = self.fixture_module.owner.validate_owner_action_request(
                    requests[f"owner-action-request-{request_number}.json"], expected)
                digest = parsed.command_sha256
                size = len(self.fixture_module.owner._canonical_bytes(
                    self.fixture_module.owner._command_document(parsed)))
            else:
                digest, size = hashlib.sha256(data).hexdigest(), len(data)
            return fixture._receipt(kind, digest, size)

        def capture(_cid, *, deadline):
            capture_ns.append(monotonic_ns())
            # The existing 4/27 fixture supplies protocol-compatible baseline
            # shape only; no model or numerical execution occurs in this test.
            built = secure_cohort._build_owner_actions_result(
                expected, worker_config=config, ssh_host_key_sha256=host_key,
                initial_local_serials=(initial_serials if initial_context is not None
                                       else template["owner_actions"]["initial_local_serials"]),
                old_local_shutdown=template["owner_actions"]["old_local_shutdown"],
                direct_probe=template["owner_actions"]["direct_probe"],
                commands=owner_state["action_responses"],
                controls=template["owner_actions"]["controls"],
                observations=[row for row in owner_state["observation_acks"]
                              if row.get("sequence") >= 5],
                probe_cleanup=template["owner_actions"]["probe_cleanup"])
            shutdown_confirmed = cleanup_outcome is None
            remote_exit_code = (0 if cleanup_outcome in (None, "unconfirmed") else 17)
            raw_result = dict(template, owner_actions=built,
                local_shutdown={"confirmed": True, "failure_types": []},
                remote_shutdown={"confirmed": shutdown_confirmed, "process_state": "exited",
                    "exit_code": remote_exit_code,
                    "shutdown_overall": "confirmed" if shutdown_confirmed else "unconfirmed",
                    "worker_boot_id": expected.worker_boot_id},
                identities={"run_id": expected.run_id,
                    "manifest_fingerprint": expected.manifest_fingerprint,
                    "coordinator_boot_id": "5" * 32,
                    "consumer_boot_id": "6" * 32,
                    "worker_boot_ids": {"worker-1": "7" * 32,
                        "worker-2": "8" * 32,
                        "worker-3": expected.worker_boot_id}})
            return raw_result, {"schema_version": 1, "event": "operator_exit",
                                "exit_code": 0, "failure_type": None}

        args = SimpleNamespace(
            result_directory=Path("unused-results"), local_image="local-image",
            remote_image="remote-image", artifacts_volume="artifacts",
            reference_volume="reference", ssh_host="host", ssh_user="user",
            known_hosts=Path("unused-known-hosts"),
            ssh_password_file=Path("unused-password"), ssh_key_file=None,
            remote_artifacts="/srv/artifacts", remote_job_root="/srv/job",
            uncertainty_seconds=0.25, external_ip=config["listen_ip"],
            external_port=config["listen_port"], profile=profile)

        def local_create(**kwargs):
            kwargs["on_cid"]("c" * 64)
            return "c" * 64

        def remote_create(_ssh, *, on_cid, **_kwargs):
            on_cid("d" * 64)
            return "d" * 64

        def write_handoff(_cid, name, value, _deadline):
            handoffs.append((name, value))
            if name.startswith("observation-response-"):
                observations_seen.append(value)
                owner_state["observation_acks"].append(value)
            if name.startswith("owner-action-response-"):
                owner_state["action_responses"].append(value)

        def stop_remote(*_args, **kwargs):
            self.assertTrue(kwargs["owner_cleanup_ready"])
            stop_deadlines.append(kwargs["deadline"])
            if cleanup_outcome is not None:
                return {"container_id": "d" * 64, "process_state": "exited",
                    "ownership_status": "verified",
                    "exit_code": 0 if cleanup_outcome == "unconfirmed" else 17,
                    "graceful_compute_shutdown": False, "shutdown_confirmed": False,
                    "container_removed": False, "private_files_removed": False,
                    "job_root_removed": False, "cleanup_confirmed": False,
                    "failure_type": ("shutdown_unconfirmed" if cleanup_outcome == "unconfirmed"
                                     else "nonzero_exit"),
                    "status": statuses[7]}
            return {"container_id": "d" * 64, "process_state": "exited",
                    "ownership_status": "verified", "exit_code": 0,
                    "graceful_compute_shutdown": True, "shutdown_confirmed": True,
                    "container_removed": True, "private_files_removed": True,
                    "job_root_removed": True, "cleanup_confirmed": True,
                    "failure_type": None,
                    "status": statuses[7] if profile == PROFILE_C1B_OWNER_REMOVE
                    else ready_status}

        expected_material_records = [
            {"name": name, "size": len(raw),
             "sha256": hashlib.sha256(raw).hexdigest()}
            for name, raw in sorted(prepared["files"].items())
        ] if profile == PROFILE_C1B_OWNER_REMOVE else []
        if profile == PROFILE_C1B_OWNER_REMOVE:
            self.assertEqual(len(expected_material_records), 4)

        def verify_materials(*_args, **_kwargs):
            return supervisor._verify_owner_material_bundle(
                expected, prepared["ready"], self.fixture_module.make_archive(prepared["files"]),
                initial_view=initial_view, snapshot_store=initial_store,
                verifier_pem=authority.snapshot_verification_key_pem,
                initial_local_serials=initial_serials,
                initial_device_id=config["device_id"])

        def ensure_intent_root(*_args, on_attempt=None, **_kwargs):
            if on_attempt is not None:
                on_attempt()
            return "/srv/job-owner-intents"

        def install_verifier(*_args, on_attempt=None, **_kwargs):
            if on_attempt is not None:
                on_attempt()
            return fixture._receipt(
                "snapshot_verifier", hashlib.sha256(
                    authority.snapshot_verification_key_pem).hexdigest(),
                len(authority.snapshot_verification_key_pem))

        def read_ack(*_args, **_kwargs):
            number = marks.get("command", 0)
            parsed = self.fixture_module.owner.validate_owner_action_request(
                requests[f"owner-action-request-{number}.json"], expected)
            ack = self.fixture_module.ack_for(
                expected, parsed, received=(100 if number == 1 else 300),
                completed=(200 if number == 1 else 400),
                phase=(None if profile == PROFILE_C1B_OWNER_REMOVE
                       else "draining"))
            return ack, {"mtime_ns": marks["value"] + 1}

        patches = {
            "validate_cli": mock.patch.object(supervisor, "validate_cli"),
            "_create_results_dir": mock.patch.object(supervisor, "_create_results_dir",
                                                       return_value=Path("unused-results")),
            "_prepare_local_volumes": mock.patch.object(supervisor, "_prepare_local_volumes"),
            "_create_local_container": mock.patch.object(supervisor, "_create_local_container",
                                                          side_effect=local_create),
            "_wait_local_json": mock.patch.object(supervisor, "_wait_local_json",
                side_effect=lambda *_a, label, **_k: ready if label == "bundle_ready" else stop_request),
            "_validate_bundle_ready": mock.patch.object(supervisor, "_validate_bundle_ready",
                                                          return_value=ready),
            "_local_docker": mock.patch.object(supervisor, "_local_docker", return_value=b"bundle"),
            "validate_worker_tar": mock.patch.object(supervisor, "validate_worker_tar",
                return_value=bundle_files),
            "_validate_worker_config": mock.patch.object(supervisor, "_validate_worker_config",
                                                           return_value=config),
            "_owner_initial_context": mock.patch.object(supervisor, "_owner_initial_context",
                return_value=(initial_context if initial_context is not None else
                    (expected, object(), object(), None,
                     template["owner_actions"]["initial_local_serials"]))),
            "_connect_ssh": mock.patch.object(supervisor, "_connect_ssh",
                                               return_value=(object(), host_key, None)),
            "_open_sftp": mock.patch.object(supervisor, "_open_sftp", return_value=mock.Mock()),
            "_remote_user_ids": mock.patch.object(supervisor, "_remote_user_ids",
                                                   return_value=(1000, 1000)),
            "_remote_script": mock.patch.object(supervisor, "_remote_script", return_value=b"ok"),
            "_sftp_upload_bundle": mock.patch.object(supervisor, "_sftp_upload_bundle"),
            "_prepare_remote_image": mock.patch.object(supervisor, "_prepare_remote_image"),
            "_create_remote_container": mock.patch.object(supervisor, "_create_remote_container",
                                                           side_effect=remote_create),
            "_ensure_owner_intent_root": mock.patch.object(
                supervisor, "_ensure_owner_intent_root", side_effect=ensure_intent_root),
            "_install_owner_verifier_copy": mock.patch.object(
                supervisor, "_install_owner_verifier_copy", side_effect=install_verifier),
            "_wait_owner_materials": mock.patch.object(
                supervisor, "_wait_owner_materials",
                side_effect=verify_materials if profile == PROFILE_C1B_OWNER_REMOVE
                else AssertionError("drain requested removal materials")),
            "_verify_owner_intent_sidecar": mock.patch.object(
                supervisor, "_verify_owner_intent_sidecar", return_value={}),
            "_remote_inspect": mock.patch.object(supervisor, "_remote_inspect",
                return_value={"running": False, "exit_code": 0}),
            "_terminal_controls": mock.patch.object(supervisor, "_terminal_controls"),
            "_read_local_handoff": mock.patch.object(supervisor, "_read_local_handoff",
                                                       side_effect=read_handoff),
            "_write_local_handoff": mock.patch.object(supervisor, "_write_local_handoff",
                                                        side_effect=write_handoff),
            "_remote_mark": mock.patch.object(supervisor, "_remote_mark", side_effect=mark_remote),
            "monotonic_ns": mock.patch.object(supervisor.time, "monotonic_ns",
                                               side_effect=monotonic_ns),
            "monotonic": mock.patch.object(supervisor.time, "monotonic",
                                            side_effect=monotonic),
            "_read_remote_status": mock.patch.object(supervisor, "_read_remote_status",
                                                       side_effect=read_remote_status),
            "_publish_owner_file": mock.patch.object(supervisor, "_publish_owner_file",
                                                       side_effect=publish),
            "_read_owner_ack": mock.patch.object(supervisor, "_read_owner_ack",
                                                  side_effect=read_ack),
            "_wait_owner_command_completion": mock.patch.object(
                supervisor, "_wait_owner_command_completion",
                side_effect=supervisor._wait_owner_command_completion),
            "_wait_observation_request": mock.patch.object(
                supervisor, "_wait_observation_request",
                side_effect=supervisor._wait_observation_request),
            "_stop_remote": mock.patch.object(supervisor, "_stop_remote",
                                               side_effect=stop_remote),
            "_capture_operator_result": mock.patch.object(supervisor, "_capture_operator_result",
                                                           side_effect=capture),
            "_terminate_local_owned": mock.patch.object(supervisor, "_terminate_local_owned",
                side_effect=lambda *_a, **kwargs: (local_stop_deadlines.append(
                    kwargs["termination_deadline"]) or {"process_state": "exited",
                    "exit_code": 0, "graceful_stop": True, "forced_kill": False,
                    "container_removed": True, "cleanup_confirmed": True,
                    "failure_type": None, "ownership_verified": True})),
            "_abort_channel": mock.patch.object(supervisor, "_abort_channel"),
            "_pending_channel_operation_count": mock.patch.object(
                supervisor, "_pending_channel_operation_count", return_value=0),
            "_pending_channel_operation_evidence": mock.patch.object(
                supervisor, "_pending_channel_operation_evidence", return_value=[]),
            "_channel_operation_owned": mock.patch.object(
                supervisor, "_channel_operation_owned", return_value=False),
            "_write_final_report": mock.patch.object(supervisor, "_write_final_report",
                                                       side_effect=lambda _a, _d, report:
                                                       report_rows.append(report)),
        }
        with ExitStack() as stack:
            for patcher in patches.values():
                stack.enter_context(patcher)
            code = supervisor.run_supervisor(args)
        if cleanup_outcome is not None:
            report = report_rows[0]
            self.assertNotEqual(code, 0, report)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["remote_worker"]["ownership_status"], "verified")
            self.assertFalse(report["remote_worker"]["shutdown_confirmed"])
            self.assertFalse(report["remote_worker"]["container_removed"])
            self.assertFalse(report["remote_worker"]["private_files_removed"])
            self.assertFalse(report["remote_worker"]["job_root_removed"])
            self.assertFalse(report["remote_worker"]["cleanup_confirmed"])
            negative_controller = report["owner_controller_evidence"]
            self.assertFalse(negative_controller["sidecar_deletion_attempted"])
            self.assertEqual(negative_controller["material_files"],
                             expected_material_records)
            self.assertIsNotNone(negative_controller["sidecar_retention_receipt"])
            self.assertEqual(len(stop_deadlines), 1)
            self.assertEqual(len(local_stop_deadlines), 1)
            self.assertAlmostEqual(local_stop_deadlines[0],
                report["owner_controller_evidence"]["local_disposal"][
                    "arm_monotonic_ns"] / 1_000_000_000 + 40.0, places=6)
            return
        self.assertEqual(code, 0, report_rows[0])
        self.assertEqual(report_rows[0]["status"], "passed")
        self.assertEqual(report_rows[0]["cohort"]["baseline_status"], "passed")
        self.assertEqual(report_rows[0]["cohort"]["completed_requests"], 4)
        self.assertEqual(report_rows[0]["cohort"]["captured_vectors"], 27)
        self.assertEqual([name for name, _ in handoffs if name.startswith("owner-action-response-")],
                         ["owner-action-response-1.json", "owner-action-response-2.json"])
        self.assertEqual(len(observations_seen), 7)
        self.assertEqual([row["sequence"] for row in observations_seen if row["sequence"] >= 5],
                         [5, 6, 7])
        owner_handoffs = [name for name, _ in handoffs
                          if name in {"observation-response-5.json",
                                      "owner-action-response-1.json",
                                      "owner-action-response-2.json",
                                      "observation-response-6.json",
                                      "observation-response-7.json"}]
        expected_handoffs = (
            ["observation-response-5.json", "owner-action-response-1.json",
             "owner-action-response-2.json", "observation-response-6.json",
             "observation-response-7.json"]
            if profile == PROFILE_C1B_OWNER_DRAIN else
            ["observation-response-5.json", "owner-action-response-1.json",
             "observation-response-6.json", "owner-action-response-2.json",
             "observation-response-7.json"])
        self.assertEqual(owner_handoffs, expected_handoffs)
        attempts = report_rows[0]["owner_controller_evidence"]["publication_attempts"]
        expected_attempts = (["command1", "command2"]
            if profile == PROFILE_C1B_OWNER_DRAIN else
            ["intent_root", "snapshot_verifier", "install_intent", "removal_intent",
             "policy1", "command1", "policy2", "command2"])
        self.assertEqual([row["kind"] for row in attempts], expected_attempts)
        disposal = report_rows[0]["owner_controller_evidence"]["local_disposal"]
        self.assertGreater(disposal["arm_monotonic_ns"],
                           max(row["monotonic_ns"] for row in attempts))
        self.assertGreater(capture_ns[0], disposal["arm_monotonic_ns"])
        self.assertEqual(len(stop_deadlines), 1)
        self.assertEqual(len(local_stop_deadlines), 1)
        self.assertAlmostEqual(local_stop_deadlines[0],
            disposal["arm_monotonic_ns"] / 1_000_000_000 + 40.0, places=6)
        if profile == PROFILE_C1B_OWNER_REMOVE:
            remote_report = report_rows[0]["remote_worker"]
            self.assertTrue(remote_report["container_removed"])
            self.assertTrue(remote_report["private_files_removed"])
            self.assertTrue(remote_report["job_root_removed"])
            self.assertTrue(remote_report["cleanup_confirmed"])
            command2_response = next(value for name, value in handoffs
                                     if name == "owner-action-response-2.json")
            self.assertEqual(observations_seen[-1]["remote_status"],
                             command2_response["protected_status"]["remote_status"])
            self.assertEqual(observations_seen[-1]["request_id"],
                             observations_seen[0]["request_id"])
            controller = report_rows[0]["owner_controller_evidence"]
            self.assertEqual(controller["actual_remove_exit"],
                             {"process_state": "exited", "exit_code": 0})
            self.assertIsNotNone(controller["sidecar_retention_receipt"])
            self.assertEqual(controller["material_files"], expected_material_records)
