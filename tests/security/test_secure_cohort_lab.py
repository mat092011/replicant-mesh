"""Unit-only control protocol checks; synthetic status is not remote evidence."""

from __future__ import annotations

import ast
import copy
import importlib.util
import json
import math
import os
from pathlib import Path
import re
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from lab import secure_cohort as cohort


TEST_EXTERNAL_IP = "10.23.45.67"
TEST_OTHER_EXTERNAL_IP = "10.23.45.68"
TEST_ENDPOINT = f"{TEST_EXTERNAL_IP}:50061"


class SecureCohortControlUnitTests(unittest.TestCase):
    """Synthetic objects exercise validators only, never readiness or acceptance."""

    def _partial_retained_graph(self):
        try:
            from steamboat_runtime.coordinator import RequestHandle
        except ImportError as error:
            self.skipTest(f"coordinator test dependencies are unavailable: {type(error).__name__}")

        session = "ses_" + "a" * 32
        context = object()
        state = SimpleNamespace(
            session_id=session, unknown_opens={2}, leases={}, restart_required=True,
            completion=SimpleNamespace(done=lambda: True),
            trusted_request_context=context,
        )

        class Coordinator:
            def __init__(self):
                self._requests = {session: state}

            def stats(self):
                return {"ready": False, "active_requests": 1}

        coordinator = Coordinator()
        handle = RequestHandle(coordinator, state)
        slot = {
            "handle": handle, "trusted_context": context, "retained": True,
            "resource_cleanup_required": True, "resource_cleanup_confirmed": False,
            "service": True, "generate": True, "cleanup_task": None,
            "context_release_task": None, "capture_cleanup_task": None,
            "pending_cleanup_monitor_task": None, "authorization_owner_task": None,
            "admission_cleanup_tasks": set(), "admission_pending_tasks": set(),
            "pending_cleanup_tasks": set(), "producer_wrapper_tasks": set(),
        }

        class Capture:
            def status(self):
                return SimpleNamespace(active_captures=0,
                                       cleanup_pending_captures=0, reserved_bytes=0)

        class Transport:
            reserved_connections = 0
            reserved_pending = 0
            reserved_outbound_pending = 0
            reserved_listener_pending_capacity = 0

        class Handler:
            sessions = {}
            tombstones = {}
            _queue = ()
            _active_operation = None

        class Bridge:
            def status(self):
                return {"cleanup_confirmed": True, "owned_sessions": 0,
                        "active_authorizations": 0, "pending_notices": 0}

        capture_budget = Capture()
        service = SimpleNamespace(coordinator=coordinator, active_streams=1, cleanups=set())
        secure_service = SimpleNamespace(
            service=service, capture_budget=capture_budget, active_generate_streams=1,
            _unreclaimed_generate_slots=[slot], pending_tasks=set(),
            runtime_owner=SimpleNamespace(pending_tasks=set()),
            _unconfirmed_capacity_rejection_authorizations={},
        )
        pipeline_state = {
            "coordinator": coordinator,
            "service": service,
            "secure_service": secure_service,
            "capture_budget": capture_budget, "transport_budget": Transport(),
            "worker_nodes": [{"handler": Handler(), "bridge": Bridge()},
                             {"handler": Handler(), "bridge": Bridge()}],
            "partial_admission_owner_binding": {
                "coordinator": coordinator, "request_state": state,
                "trusted_context": context, "session_id": session,
                "secure_slot": slot, "secure_cleanup_task": None,
            },
        }
        result = {"partial_admission": {
            "profile": cohort.PROFILE_C1B_PARTIAL, "status": "passed",
            "session_id": session,
        }}
        errors = [
            cohort.CohortError("close", cleanup_component="coordinator_close"),
            cohort.CohortError("service", cleanup_component="coordinator_service_streams"),
            cohort.CohortError("generate", cleanup_component="secure_generate_streams"),
        ]
        return pipeline_state, result, errors, state, slot

    def test_partial_retained_graph_requires_exact_original_owner_correlations(self):
        pipeline, result, errors, state, slot = self._partial_retained_graph()
        record = cohort._partial_retained_shutdown_record(pipeline, result, errors)
        self.assertIsNotNone(record)
        self.assertEqual(record["retained_components"], [
            "coordinator_close", "coordinator_service_streams", "secure_generate_streams"])
        self.assertEqual(record["owner_counts"]["active_requests"], 1)
        self.assertEqual(record["owner_counts"]["active_streams"], 1)
        self.assertFalse(record["confirmed"])
        slot["pending_cleanup_roots"] = set()
        slot["pending_cleanup_discovery_tasks"] = set()
        self.assertIsNotNone(cohort._partial_retained_shutdown_record(
            pipeline, result, errors))

        cases = []
        broken, bad_result, bad_errors, _, _ = self._partial_retained_graph()
        broken["partial_admission_owner_binding"]["request_state"] = object()
        cases.append((broken, bad_result, bad_errors))
        broken, bad_result, bad_errors, _, slot2 = self._partial_retained_graph()
        slot2["trusted_context"] = object()
        cases.append((broken, bad_result, bad_errors))
        broken, bad_result, bad_errors, _, _ = self._partial_retained_graph()
        broken["secure_service"]._unreclaimed_generate_slots.append({})
        cases.append((broken, bad_result, bad_errors))
        broken, bad_result, bad_errors, _, _ = self._partial_retained_graph()
        stray_task = object()
        broken["service"].cleanups.add(stray_task)
        cases.append((broken, bad_result, bad_errors))
        broken, bad_result, bad_errors, _, _ = self._partial_retained_graph()
        broken["secure_service"].service = SimpleNamespace(
            coordinator=broken["coordinator"], active_streams=1, cleanups=set())
        cases.append((broken, bad_result, bad_errors))
        broken, bad_result, bad_errors, _, _ = self._partial_retained_graph()
        broken["secure_service"].capture_budget = object()
        cases.append((broken, bad_result, bad_errors))
        broken, bad_result, bad_errors, _, _ = self._partial_retained_graph()
        broken["secure_service"].pending_tasks.add(object())
        cases.append((broken, bad_result, bad_errors))
        broken, bad_result, bad_errors, _, _ = self._partial_retained_graph()
        broken["secure_service"].runtime_owner.pending_tasks.add(object())
        cases.append((broken, bad_result, bad_errors))
        broken, bad_result, bad_errors, _, _ = self._partial_retained_graph()
        broken["secure_service"]._unconfirmed_capacity_rejection_authorizations[1] = object()
        cases.append((broken, bad_result, bad_errors))
        broken, bad_result, bad_errors, _, slot3 = self._partial_retained_graph()
        slot3["pending_cleanup_roots"] = []
        cases.append((broken, bad_result, bad_errors))
        broken, bad_result, bad_errors, _, _ = self._partial_retained_graph()
        bad_errors.append(cohort.CohortError("unclassified cleanup"))
        cases.append((broken, bad_result, bad_errors))
        broken, bad_result, bad_errors, _, _ = self._partial_retained_graph()
        bad_errors[0].cleanup_component = "coordinator_service_streams"
        cases.append((broken, bad_result, bad_errors))
        broken, bad_result, bad_errors, _, _ = self._partial_retained_graph()
        broken["worker_nodes"][0]["handler"].sessions = {"unexpected": object()}
        cases.append((broken, bad_result, bad_errors))
        for index, (broken, bad_result, bad_errors) in enumerate(cases):
            with self.subTest(case=index):
                self.assertIsNone(cohort._partial_retained_shutdown_record(
                    broken, bad_result, bad_errors))

    def test_cancel_dispatch_prefix_pins_prompt_and_first_decode_positions(self):
        session = "ses_" + "a" * 32
        events = [
            {"event": "stage_dispatch", "session_id": session,
             "worker": 1, "sequence": 0, "position": 0, "token_count": 3},
            {"event": "stage_dispatch", "session_id": session,
             "worker": 2, "sequence": 0, "position": 0, "token_count": 3},
            {"event": "stage_dispatch", "session_id": session,
             "worker": 3, "sequence": 0, "position": 0, "token_count": 3},
            {"event": "stage_dispatch", "session_id": session,
             "worker": 1, "sequence": 1, "position": 3, "token_count": 1},
        ]
        self.assertTrue(cohort._cancellation_dispatch_prefix(events, session))
        malformed = copy.deepcopy(events)
        malformed[-1]["position"] = True
        self.assertFalse(cohort._cancellation_dispatch_prefix(malformed, session))
        self.assertFalse(cohort._cancellation_dispatch_prefix(events[:-1], session))

    def test_local_owner_snapshot_preserves_active_fence_and_checks_notices(self):
        class Handler:
            sessions = {}
            tombstones = {}
            _queue = ()
            _active_operation = None

        class Bridge:
            def __init__(self, pending_notices=0):
                self.pending_notices = pending_notices

            def status(self):
                return {"owned_sessions": 0, "active_authorizations": 0,
                        "pending_notices": self.pending_notices,
                        "cleanup_confirmed": True, "unavailable": False,
                        "requires_restart": False}

        class Capture:
            def __init__(self, pending=0):
                self.value = SimpleNamespace(active_captures=0,
                                             cleanup_pending_captures=pending,
                                             reserved_bytes=0)

            def status(self):
                return self.value

        class Transport:
            reserved_connections = 15
            reserved_pending = 0
            reserved_outbound_pending = 0

        class Coordinator:
            def stats(self):
                return {"active_requests": 1}

        service = SimpleNamespace(active_streams=0, cleanups=())
        secure_service = SimpleNamespace(active_generate_streams=0)
        worker_nodes = [{"handler": Handler(), "bridge": Bridge()}]
        snapshot = cohort._local_owner_snapshot(
            coordinator=Coordinator(), service=service,
            secure_service=secure_service, worker_nodes=worker_nodes,
            capture_budget=Capture(), transport_budget=Transport(),
            expected_connections=15, expected_active_requests=1)
        self.assertEqual(snapshot["active_requests"], 1)
        with self.assertRaises(cohort.CohortError):
            cohort._local_owner_snapshot(
                coordinator=Coordinator(), service=service,
                secure_service=secure_service,
                worker_nodes=[{"handler": Handler(), "bridge": Bridge(1)}],
                capture_budget=Capture(), transport_budget=Transport(),
                expected_connections=15, expected_active_requests=1)
        with self.assertRaises(cohort.CohortError):
            cohort._local_owner_snapshot(
                coordinator=Coordinator(), service=service,
                secure_service=secure_service, worker_nodes=worker_nodes,
                capture_budget=Capture(1), transport_budget=Transport(),
                expected_connections=15, expected_active_requests=1)

    def test_retained_cancellation_owner_registry_fails_closed_at_capacity(self):
        with mock.patch.object(cohort, "_RETAINED_CANCELLATION_OWNERS", [object()]):
            with self.assertRaisesRegex(cohort.CohortError, "capacity exceeded"):
                cohort._retain_cancellation_owners(
                    object(), {}, None, None, {})

    def setUp(self):
        self.expected = cohort.RemoteExpectation(
            run_id="1" * 32,
            nonce="2" * 32,
            worker_name="worker-3",
            account_id="acct_" + "a" * 32,
            device_id="dev_" + "b" * 32,
            boot_id="c" * 32,
            assignment_id="asg_" + "d" * 32,
            model_id="Maykeye/TinyLLama-v0",
            model_revision="298338802ab94432b917bcce11382aa151aee50f",
            manifest_fingerprint="e" * 64,
            snapshot_sha256="f" * 64,
            endpoint=TEST_ENDPOINT,
            clock_uncertainty_seconds=2.0,
            layer_range=(6, 8),
        )

    def _status(self, *, event="ready"):
        return {
            "schema_version": 1,
            "event": event,
            "phase": "ready",
            "worker_name": "worker-3",
            "account_id": self.expected.account_id,
            "device_id": self.expected.device_id,
            "boot_id": self.expected.boot_id,
            "assignment_id": self.expected.assignment_id,
            "model_id": self.expected.model_id,
            "model_revision": self.expected.model_revision,
            "manifest_fingerprint": self.expected.manifest_fingerprint,
            "listen_endpoint": self.expected.endpoint,
            "layer_range": [6, 8],
            "clock_uncertainty_seconds": 2.0,
            "torch_threads": 2,
            "handler": {
                "state": "observed",
                "active_sessions": 0,
                "active_session_ids": [],
                "tombstones": 0,
                "retained_entries": 0,
                "queued_operations": 0,
                "active_compute": False,
                "cache_bytes_exact": True,
                "requires_restart": False,
                "stopping": False,
                "limits": {
                    "max_sessions": 8,
                    "max_tombstones": 16,
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
                "ready": True,
                "unavailable": False,
                "requires_restart": False,
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
                "reserved_connections": 1,
                "reserved_pending": 0,
                "reserved_listener_pending_capacity": 1,
                "reserved_outbound_pending": 0,
                "server_state": "running",
            },
            "external_supervision": {
                "startup_watchdog_seconds": 60,
                "termination_watchdog_seconds": 15,
                "resource_caps": "configured_by_external_supervisor",
                "verified_by_worker": False,
            },
            "shutdown": {"state": "not_started"},
            "report_state": "confirmed",
            "resource_state": "observed",
        }

    def _ready_ack(self):
        return {
            "schema_version": 1,
            "event": "ready_ack",
            "run_id": self.expected.run_id,
            "nonce": self.expected.nonce,
            "boot_id": self.expected.boot_id,
            "manifest_fingerprint": self.expected.manifest_fingerprint,
            "snapshot_sha256": self.expected.snapshot_sha256,
            "endpoint": self.expected.endpoint,
            "ssh_host_key_sha256": "9" * 64,
            "remote_status_uid": cohort.REMOTE_STATUS_UID,
            "remote_status_mode": cohort.REMOTE_STATUS_MODE,
            "remote_status_mtime_ns": 100,
            "measurement_label": cohort.READY_LABEL,
            "remote_status": self._status(),
        }

    def _observation_ack(self, *, sequence=1, status_event="heartbeat",
                         case_id="greedy-one-token", request_id=None,
                         session_id=None):
        if request_id is None:
            request_id = "req_" + "1" * 32
        if session_id is None:
            session_id = "ses_" + "2" * 32
        return {
            "schema_version": 1,
            "event": "observation_ack",
            "run_id": self.expected.run_id,
            "nonce": self.expected.nonce,
            "sequence": sequence,
            "case_id": case_id,
            "request_id": request_id,
            "session_id": session_id,
            "boot_id": self.expected.boot_id,
            "manifest_fingerprint": self.expected.manifest_fingerprint,
            "endpoint": self.expected.endpoint,
            "ssh_host_key_sha256": "9" * 64,
            "remote_status_uid": cohort.REMOTE_STATUS_UID,
            "remote_status_mode": cohort.REMOTE_STATUS_MODE,
            "supervisor_monotonic_ns": 123456789,
            "remote_mark_ns": 1000,
            "heartbeat_mtime_ns": 1001,
            "measurement_label": cohort.OBSERVATION_LABEL,
            "remote_status": self._status(event=status_event),
        }

    def test_parser_requires_every_operator_input_and_uncertainty(self):
        with self.assertRaises(SystemExit):
            cohort.build_parser().parse_args([])
        with self.assertRaises(SystemExit):
            cohort.build_parser().parse_args([
                "--artifacts", str(Path.cwd() / "artifacts"),
                "--reference", str(Path.cwd() / "reference"),
                "--external-port", "50061",
                "--clock-uncertainty-seconds", "2",
                "--handoff-directory", str(Path.cwd() / "handoff"),
            ])
        args = SimpleNamespace(
            artifacts=str(Path.cwd() / "artifacts"),
            reference=str(Path.cwd() / "reference"),
            handoff_directory=str(Path.cwd() / "handoff"),
            external_ip=TEST_EXTERNAL_IP,
            external_port=cohort.REMOTE_PORT,
            clock_uncertainty_seconds=2.0,
        )
        cohort.validate_cli_values(args)
        self.assertEqual(cohort.MAX_SNAPSHOT_BYTES, 65_536)

    def test_fixed_profile_cli_defaults_to_unchanged_baseline(self):
        common = [
            "--artifacts", str(Path.cwd() / "artifacts"),
            "--reference", str(Path.cwd() / "reference"),
            "--external-ip", TEST_EXTERNAL_IP,
            "--external-port", "50061",
            "--clock-uncertainty-seconds", "2",
            "--handoff-directory", str(Path.cwd() / "handoff"),
        ]
        baseline = cohort.build_parser().parse_args(common)
        self.assertEqual(baseline.profile, cohort.PROFILE_BASELINE)
        cohort.validate_cli_values(baseline)
        happy = cohort.build_parser().parse_args(
            common + ["--profile", cohort.PROFILE_C1B_HAPPY])
        self.assertEqual(happy.profile, cohort.PROFILE_C1B_HAPPY)
        cohort.validate_cli_values(happy)
        interleave = cohort.build_parser().parse_args(
            common + ["--profile", cohort.PROFILE_C1B_INTERLEAVE])
        self.assertEqual(interleave.profile, cohort.PROFILE_C1B_INTERLEAVE)
        cohort.validate_cli_values(interleave)
        cancel = cohort.build_parser().parse_args(
            common + ["--profile", cohort.PROFILE_C1B_CANCEL])
        self.assertEqual(cancel.profile, cohort.PROFILE_C1B_CANCEL)
        cohort.validate_cli_values(cancel)
        partial = cohort.build_parser().parse_args(
            common + ["--profile", cohort.PROFILE_C1B_PARTIAL])
        self.assertEqual(partial.profile, cohort.PROFILE_C1B_PARTIAL)
        cohort.validate_cli_values(partial)
        step_loss = cohort.build_parser().parse_args(
            common + ["--profile", cohort.PROFILE_C1B_STEP_LOSS])
        self.assertEqual(step_loss.profile, cohort.PROFILE_C1B_STEP_LOSS)
        cohort.validate_cli_values(step_loss)
        capacity = cohort.build_parser().parse_args(
            common + ["--profile", cohort.PROFILE_C1B_CAPACITY])
        self.assertEqual(capacity.profile, cohort.PROFILE_C1B_CAPACITY)
        cohort.validate_cli_values(capacity)
        restart = cohort.build_parser().parse_args(
            common + ["--profile", cohort.PROFILE_C1B_RESTART])
        self.assertEqual(restart.profile, cohort.PROFILE_C1B_RESTART)
        cohort.validate_cli_values(restart)
        with self.assertRaises(SystemExit):
            cohort.build_parser().parse_args(common + ["--profile", "arbitrary"])

    def test_profiles_keep_baseline_sequence_and_close_happy_extension_cases(self):
        self.assertEqual(
            cohort._PROFILE_OBSERVATIONS[cohort.PROFILE_BASELINE],
            ((1, "greedy-one-token", True),
             (2, "forced-length-1", True),
             (3, "forced-length-128", True),
             (4, "forced-length-1024", True)))
        self.assertEqual(
            cohort._PROFILE_OBSERVATIONS[cohort.PROFILE_C1B_HAPPY],
            cohort._BASELINE_OBSERVATIONS + (
                (5, "unequal-concurrent-prompt-5", True),
                (6, "unequal-concurrent-prompt-11", True),
                (7, "context-boundary-1151-plus-1", True),
            ))
        self.assertEqual(
            cohort._PROFILE_LOCAL_CASES[cohort.PROFILE_C1B_HAPPY],
            ("context-over-boundary-1152-plus-1-local-preflight",))
        self.assertNotIn(cohort._PROFILE_LOCAL_CASES[cohort.PROFILE_C1B_HAPPY][0],
                         {case for _sequence, case, _needs_session
                          in cohort._PROFILE_OBSERVATIONS[cohort.PROFILE_C1B_HAPPY]})
        self.assertEqual(cohort.MAX_OBSERVATION_SEQUENCE, 10)

    def test_restart_profile_has_exact_old_probe_and_new_baseline_order(self):
        expected = (
            cohort._BASELINE_OBSERVATIONS
            + ((5, "restart-old-session-held", True),
               (6, "restart-new-boot-stale-binding-rejected", True))
            + ((7, "restart-new-greedy-one-token", True),
               (8, "restart-new-forced-length-1", True),
               (9, "restart-new-forced-length-128", True),
               (10, "restart-new-forced-length-1024", True)))
        self.assertEqual(cohort._PROFILE_OBSERVATIONS[cohort.PROFILE_C1B_RESTART], expected)
        for sequence, case_id, required in expected:
            self.assertEqual(cohort._profile_observation(
                cohort.PROFILE_C1B_RESTART, sequence), (case_id, required))
        with self.assertRaises(cohort.CohortError):
            cohort.build_observation_request(
                self.expected, sequence=6,
                case_id="restart-old-session-held",
                request_id="req_" + "a" * 32,
                session_id="ses_" + "b" * 32,
                profile=cohort.PROFILE_C1B_RESTART)

    @staticmethod
    def _valid_restart_projection():
        old_requests = [f"req_{index:032x}" for index in range(1, 5)]
        old_sessions = [f"ses_{index:032x}" for index in range(1, 5)]
        new_requests = [f"req_{index:032x}" for index in range(11, 15)]
        new_sessions = [f"ses_{index:032x}" for index in range(11, 15)]
        probe_request, probe_session = "req_" + "a" * 32, "ses_" + "a" * 32
        route_id = "route_" + "a" * 32
        old_boots = {"coordinator": "1" * 32, "worker-1": "2" * 32,
                     "worker-2": "3" * 32, "worker-3": "4" * 32}
        new_boots = {"coordinator": "5" * 32, "worker-1": "6" * 32,
                     "worker-2": "7" * 32, "worker-3": "8" * 32}
        old_identity = {
            "run_id": "0" * 32, "coordinator_boot_id": old_boots["coordinator"],
            "consumer_boot_id": "9" * 32, "worker_boot_ids": old_boots,
            "manifest_fingerprint": "a" * 64,
        }
        new_identity = {
            "run_id": "0" * 32, "coordinator_boot_id": new_boots["coordinator"],
            "consumer_boot_id": "9" * 32, "worker_boot_ids": new_boots,
            "manifest_fingerprint": "a" * 64,
        }
        new_cases = [{"case_id": case_id, "request_id": request_id,
                      "session_id": session_id, "local_owner_check": {},
                      "remote_owner_check": {}}
                     for case_id, request_id, session_id in zip(
                         ("restart-new-greedy-one-token", "restart-new-forced-length-1",
                          "restart-new-forced-length-128", "restart-new-forced-length-1024"),
                         new_requests, new_sessions)]
        direct = {
            "request_id": probe_request, "session_id": probe_session,
            "route_id": route_id, "route_epoch": 1, "attempt": 1,
            "open_response": {"session_id": probe_session,
                              "worker_boot_id": old_boots["worker-3"], "code": "OK"},
            "step_response": {"sequence": 0, "start_position": 0, "token_count": 3,
                              "end_position": 3, "next_sequence": 1,
                              "tensor_shape": [1, 3, 64], "dtype": "float32_le",
                              "byte_count": 768, "finite": True},
            "held_status": {
                "worker_boot_id": old_boots["worker-3"], "active_sessions": 1,
                "active_session_ids": [probe_session], "queued_operations": 0,
                "active_compute": False, "cache_bytes_exact": True,
                "committed_cache_bytes": 1024, "allocated_cache_bytes": 1024,
                "active_authorizations": 0, "owned_sessions": 1,
                "transport_reserved_connections": 1,
            },
            "new_target_before": {
                "worker_boot_id": new_boots["worker-3"], "ready": True,
                "active_sessions": 0, "reserved_positions": 0,
                "allocated_cache_bytes": 0, "active_operations": 0,
                "queued_operations": 0, "tombstones": 0,
                "cache_bytes_exact": True, "requires_restart": False,
            },
            "client_replacement": {
                "connection_mode": "serial_new_describe_then_stale_control",
                "original_close": {
                    "attempted": True, "confirmed": True, "close_calls": 1,
                    "reserved_connections_before": 6,
                    "reserved_connections_after": 3, "client_closed": True,
                },
                "initial_new_close": {
                    "attempted": True, "confirmed": True, "close_calls": 1,
                    "reserved_connections_before": 3,
                    "reserved_connections_after": 0, "client_closed": True,
                },
                "stale_clients": [
                    {"method": method, "created_after_close": True,
                     "same_request_context": True, "old_authorizer_preserved": True,
                     "same_target_peer": True, "same_local_tls_identity": True,
                     "reserved_connections_after_create": 3,
                     "native_status": "UNAUTHENTICATED",
                     "new_target_preface": {
                         "worker_boot_id": new_boots["worker-3"], "ready": True,
                         "active_sessions": 0, "reserved_positions": 0,
                         "allocated_cache_bytes": 0, "active_operations": 0,
                         "queued_operations": 0, "tombstones": 0,
                         "cache_bytes_exact": True, "requires_restart": False,
                     },
                     "same_channel_and_connector_at_dispatch": True,
                     "close": {"attempted": True, "confirmed": True, "close_calls": 1,
                               "reserved_connections_before": 3,
                               "reserved_connections_after": 0, "client_closed": True}}
                    for method in ("SessionStatus", "CancelSession")
                ],
                "preface_bindings": [
                    {"for_method": method, "method": "Describe",
                     "operation_id": f"op_{index:032x}",
                     "worker_boot_id": new_boots["worker-3"],
                     "assignment_id": "asg_" + "a" * 32,
                     "target_device_id": "dev_" + "b" * 32}
                    for index, method in enumerate(("SessionStatus", "CancelSession"), 9)
                ],
                "accounted_client_counts": [1, 2, 1, 0, 1, 0, 1, 0],
                "max_accounted_clients": 2,
            },
            "bindings": [
                {"method": method, "operation_id": f"op_{index:032x}",
                 "request_id": probe_request, "session_id": probe_session,
                 "route_id": route_id, "route_epoch": 1, "attempt": 1,
                 "worker_boot_id": old_boots["worker-3"]}
                for index, method in enumerate(
                    ("OpenSession", "Step", "SessionStatus", "CancelSession"), 1)
            ],
        }
        new_baseline = {
            "baseline": {"status": "passed", "completed_requests": 4,
                         "captured_vectors": 27,
                         "lifecycle_extensions": "pending_separate_C1b_gate"},
            "identities": new_identity,
            "request_ids": new_requests, "session_ids": new_sessions,
            "numerical_errors": {"captured_vectors": 27,
                                  "max_absolute_error": 0.0,
                                  "values": [0.0] * 27, "atol": 1e-3, "rtol": 0.0},
            "cases": new_cases,
        }
        return {
            "baseline": {"status": "passed", "completed_requests": 4,
                         "captured_vectors": 27,
                         "lifecycle_extensions": "pending_separate_C1b_gate"},
            "identities": old_identity, "request_ids": old_requests,
            "session_ids": old_sessions,
            "local_shutdown": {"confirmed": True, "failure_types": []},
            "remote_shutdown": {"confirmed": True, "process_state": "exited",
                                "exit_code": 0, "worker_boot_id": new_boots["worker-3"]},
            "restart": {
                "profile": cohort.PROFILE_C1B_RESTART, "status": "passed",
                "scope": "remote_worker_between_rpcs",
                "old_boot_id": old_boots["worker-3"],
                "new_boot_id": new_boots["worker-3"],
                "old_snapshot_sha256": "b" * 64,
                "new_snapshot_sha256": "c" * 64,
                "old_owner_receipt_sha256": "d" * 64,
                "old_local_shutdown": {"confirmed": True, "failure_types": []},
                "direct_probe": direct,
                "stale_binding_rejections": [
                    {"method": "SessionStatus", "code": "UNAUTHENTICATED"},
                    {"method": "CancelSession", "code": "UNAUTHENTICATED"},
                ],
                "new_baseline": new_baseline,
                "probe_cleanup": {
                    "confirmed": True, "transport_reserved_connections": 0,
                    "transport_reserved_pending": 0,
                    "transport_reserved_outbound_pending": 0,
                    "authorization_closed": True, "context_released": True,
                    "client_closed": True,
                },
                "same_leaf_continuity": {
                    "same_ca": True, "same_snapshot_signer_public_key": True,
                    "same_worker_leaf_certificate": True, "same_worker_private_key": True,
                    "same_device_id": True, "same_assignment_id": True,
                    "same_credential_epoch": True,
                },
            },
        }

    def test_restart_result_projection_is_closed_and_rejects_false_cleanup_or_replay(self):
        result = self._valid_restart_projection()
        cohort._validate_restart_result(result)
        for mutate in (
                lambda value: value["restart"]["direct_probe"]["held_status"].update(
                    committed_cache_bytes=0),
                lambda value: value["restart"]["stale_binding_rejections"][1].update(
                    code="PERMISSION_DENIED"),
                lambda value: value["restart"]["direct_probe"]["bindings"][3].update(
                    operation_id=value["restart"]["direct_probe"]["bindings"][2]["operation_id"]),
                lambda value: value["restart"]["direct_probe"]["bindings"][2].update(
                    method="Step"),
                lambda value: value["restart"]["new_baseline"]["request_ids"].__setitem__(
                    0, value["request_ids"][0]),
                lambda value: value["restart"]["probe_cleanup"].update(client_closed=False),
                lambda value: value["restart"]["direct_probe"]["client_replacement"][
                    "original_close"].update(close_calls=2),
                lambda value: value["restart"]["direct_probe"]["client_replacement"][
                    "stale_clients"][1].update(method="SessionStatus"),
                lambda value: value["restart"]["direct_probe"]["client_replacement"][
                    "stale_clients"][0]["close"].update(close_calls=2),
                lambda value: value["restart"]["direct_probe"]["client_replacement"][
                    "initial_new_close"].update(close_calls=True),
                lambda value: value["restart"]["direct_probe"]["client_replacement"][
                    "stale_clients"][0]["new_target_preface"].update(active_sessions=True),
                lambda value: value["restart"]["direct_probe"]["client_replacement"].update(
                    max_accounted_clients=3),
                lambda value: value["restart"]["direct_probe"]["client_replacement"][
                    "accounted_client_counts"].__setitem__(2, 2),
                lambda value: value["restart"]["direct_probe"]["client_replacement"].update(
                    connection_mode="parallel_invalid_first_rpc"),
                lambda value: value["restart"]["direct_probe"]["client_replacement"][
                    "preface_bindings"][1].update(
                        operation_id=value["restart"]["direct_probe"]["bindings"][0][
                            "operation_id"]),
                lambda value: value["restart"]["direct_probe"]["client_replacement"][
                    "preface_bindings"][0].update(assignment_id="assignment_worker3"),
                lambda value: value["restart"]["direct_probe"]["client_replacement"][
                    "stale_clients"][0].update(same_channel_and_connector_at_dispatch=False),
                lambda value: value["restart"]["new_baseline"].update(unexpected=True)):
            broken = copy.deepcopy(result)
            mutate(broken)
            with self.assertRaises(cohort.CohortError):
                cohort._validate_restart_result(broken)

    def test_restart_routed_authorizer_has_only_the_two_identity_routes(self):
        from steamboat_security.codec import WORKER_SERVICE, encode_binding

        old_context, new_context = object(), object()
        calls = []

        class Delegate:
            def __init__(self, label, describe=False):
                self.label = label
                self.describe = describe

            def authorize_outbound(self, **kwargs):
                calls.append((self.label, kwargs.copy()))
                binding = b""
                if self.describe:
                    fields = {
                        "binding_version": 1, "operation_id": "op_" + "1" * 32,
                        "account_id": "acct_" + "2" * 32,
                        "device_id": "dev_" + "3" * 32, "role": "consumer",
                        "credential_epoch": 1, "target_device_id": "dev_" + "4" * 32,
                        "worker_boot_id": "5" * 32, "assignment_id": "asg_" + "6" * 32,
                    }
                    binding = encode_binding(WORKER_SERVICE, "Describe", fields)
                return SimpleNamespace(binding_bytes=binding)

        old = Delegate("old")
        new = Delegate("new", describe=True)
        captured = []
        routed = cohort._serial_preface_authorizer(
            old_context, new_context, old, new, captured,
            old_method="SessionStatus")
        args = {"service": WORKER_SERVICE, "method": "Describe", "payload": object(),
                "trusted_request_context": new_context, "peer_certificate_pem": b"peer"}
        routed.authorize_outbound(**args)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "new")
        self.assertIs(calls[0][1]["trusted_request_context"], new_context)
        self.assertIs(calls[0][1]["payload"], args["payload"])
        self.assertEqual(captured[0]["method"], "Describe")
        self.assertEqual(captured[0]["worker_boot_id"], "5" * 32)
        stale_args = dict(args, method="SessionStatus", trusted_request_context=old_context)
        routed.authorize_outbound(**stale_args)
        self.assertEqual(calls[-1][0], "old")
        self.assertIs(calls[-1][1]["payload"], stale_args["payload"])
        for invalid in (
                dict(args, method="SessionStatus"),
                dict(args, trusted_request_context=old_context),
                dict(stale_args, method="CancelSession", trusted_request_context=old_context),
                dict(stale_args, method="CancelSession", trusted_request_context=new_context),
                dict(stale_args, service="steamboat.v1.Coordinator")):
            before = len(calls)
            with self.assertRaises(cohort.CohortError):
                routed.authorize_outbound(**invalid)
            self.assertEqual(len(calls), before)
        self.assertIs(routed.old_authorizer, old)
        cancel_routed = cohort._serial_preface_authorizer(
            old_context, new_context, old, new, [], old_method="CancelSession")
        cancel_args = dict(stale_args, method="CancelSession")
        cancel_routed.authorize_outbound(**cancel_args)
        self.assertEqual(calls[-1][0], "old")
        before = len(calls)
        with self.assertRaises(cohort.CohortError):
            cancel_routed.authorize_outbound(**stale_args)
        self.assertEqual(len(calls), before)

    def test_restart_routed_authorizer_keeps_genuine_old_and_new_core_bindings(self):
        try:
            from tests.security.secure_pipeline_fixture import SecurePipelineIdentityFixture
            from lab.secure_cohort_boot import build_trusted_probe_context, prepare_boot_generation
            from steamboat_security import new_boot_id
            from steamboat_security.codec import METADATA_KEY, WORKER_SERVICE, parse_metadata
            from steamboat_runtime.protocol.worker_pb2 import Request
        except ImportError as error:
            self.skipTest(f"C0 identity dependencies are unavailable: {type(error).__name__}")

        authority = SecurePipelineIdentityFixture("a" * 64)
        old_probe = new_probe = None
        try:
            old_probe = build_trusted_probe_context(authority, timeout_seconds=120)
            generation = prepare_boot_generation(
                authority, {name: new_boot_id() for name in (
                    "coordinator", "worker-1", "worker-2", "worker-3")})
            new_probe = build_trusted_probe_context(
                authority, generation=generation, timeout_seconds=120)
            prefaces = []
            captured = []
            old_observer = cohort._recording_outbound_authorizer(
                old_probe.outbound_authorizer, captured)
            routed = cohort._serial_preface_authorizer(
                old_probe.context, new_probe.context, old_observer,
                new_probe.outbound_authorizer, prefaces,
                old_method="SessionStatus")
            old_worker = authority.principals["worker-3"]
            peer_pem = old_worker.certificate_pem
            new_auth = routed.authorize_outbound(
                service=WORKER_SERVICE, method="Describe",
                payload=Request(protocol_version=1, timeout_ms=5_000),
                trusted_request_context=new_probe.context,
                peer_certificate_pem=peer_pem)
            old_request = Request(
                protocol_version=1, manifest_fingerprint=authority.model_id,
                worker_boot_id=old_worker.boot_id,
                session_id=old_probe.context.session_id,
                lease_token="lease_" + "1" * 32, timeout_ms=5_000)
            open_request = Request(
                protocol_version=1, manifest_fingerprint=authority.model_id,
                worker_boot_id=old_worker.boot_id,
                session_id=old_probe.context.session_id, timeout_ms=5_000,
                max_positions=12, lifetime_ms=120_000, idle_lease_ms=120_000)
            step_request = Request(
                protocol_version=1, manifest_fingerprint=authority.model_id,
                worker_boot_id=old_worker.boot_id,
                session_id=old_probe.context.session_id,
                lease_token="lease_" + "1" * 32, timeout_ms=5_000,
                sequence=0, start_position=0, token_count=1)
            step_request.tensor.shape.extend((1, 1, 64))
            step_request.tensor.dtype = "float32_le"
            step_request.tensor.layout = "batch_sequence_hidden"
            step_request.tensor.byte_count = 256
            step_request.tensor.data = bytes(256)
            open_auth = old_observer.authorize_outbound(
                service=WORKER_SERVICE, method="OpenSession", payload=open_request,
                trusted_request_context=old_probe.context,
                peer_certificate_pem=peer_pem)
            step_auth = old_observer.authorize_outbound(
                service=WORKER_SERVICE, method="Step", payload=step_request,
                trusted_request_context=old_probe.context,
                peer_certificate_pem=peer_pem)
            old_auth = routed.authorize_outbound(
                service=WORKER_SERVICE, method="SessionStatus", payload=old_request,
                trusted_request_context=old_probe.context,
                peer_certificate_pem=peer_pem)
            cancel_routed = cohort._serial_preface_authorizer(
                old_probe.context, new_probe.context, old_observer,
                new_probe.outbound_authorizer, [], old_method="CancelSession")
            cancel_auth = cancel_routed.authorize_outbound(
                service=WORKER_SERVICE, method="CancelSession", payload=old_request,
                trusted_request_context=old_probe.context,
                peer_certificate_pem=peer_pem)
            new_binding = parse_metadata(
                WORKER_SERVICE, "Describe", ((METADATA_KEY, new_auth.binding_bytes),))
            old_binding = parse_metadata(
                WORKER_SERVICE, "SessionStatus", ((METADATA_KEY, old_auth.binding_bytes),))
            self.assertNotEqual(new_binding["worker_boot_id"], old_binding["worker_boot_id"])
            self.assertEqual(new_binding["worker_boot_id"], generation.boot_ids["worker-3"])
            self.assertEqual(old_binding["worker_boot_id"], old_worker.boot_id)
            self.assertEqual(new_binding["assignment_id"], old_binding["assignment_id"])
            self.assertNotEqual(new_binding["operation_id"], old_binding["operation_id"])
            self.assertEqual(len(prefaces), 1)
            self.assertEqual([row["method"] for row in captured],
                             ["OpenSession", "Step", "SessionStatus", "CancelSession"])
            self.assertEqual(len({row["operation_id"] for row in captured}), 4)
            new_auth.close()
            open_auth.close()
            step_auth.close()
            old_auth.close()
            cancel_auth.close()
        finally:
            if new_probe is not None:
                new_probe.close()
            if old_probe is not None:
                old_probe.close()
            authority.close()

    def test_restart_dispatch_guard_rejects_channel_or_connector_replacement(self):
        class Subchannel:
            channel = object()
            connector = object()

        class Client:
            def __init__(self):
                self._subchannel = Subchannel()

            async def _ensure_channel(self, _timeout, _deadline=None):
                return self._subchannel.channel

        async def check():
            client = Client()
            channel, connector = client._subchannel.channel, client._subchannel.connector
            state = cohort._guard_restart_dispatch(client, channel, connector)
            self.assertIs(await client._ensure_channel(1), channel)
            self.assertTrue(state["same_channel_and_connector_at_dispatch"])
            client = Client()
            channel, connector = client._subchannel.channel, client._subchannel.connector
            cohort._guard_restart_dispatch(client, channel, connector)
            client._subchannel.connector = object()
            with self.assertRaises(cohort.CohortError):
                await client._ensure_channel(1)
            client = Client()
            channel, connector = client._subchannel.channel, client._subchannel.connector
            cohort._guard_restart_dispatch(client, channel, connector)
            client._subchannel.channel = object()
            with self.assertRaises(cohort.CohortError):
                await client._ensure_channel(1)

        import asyncio
        asyncio.run(check())

    def test_interleave_profile_and_causal_observer_fail_closed(self):
        self.assertEqual(
            cohort._PROFILE_OBSERVATIONS[cohort.PROFILE_C1B_INTERLEAVE],
            cohort._BASELINE_OBSERVATIONS + ((5, "ordered-step-interleave", True),))
        self.assertEqual(
            cohort._profile_observation(cohort.PROFILE_C1B_INTERLEAVE, 5),
            ("ordered-step-interleave", True))
        with self.assertRaises(cohort.CohortError):
            cohort.build_observation_request(
                self.expected, sequence=5, case_id="not-the-fixed-case",
                request_id="req_" + "1" * 32, session_id="ses_" + "2" * 32,
                profile=cohort.PROFILE_C1B_INTERLEAVE)

        def job(session_id, position, count):
            return SimpleNamespace(
                request=SimpleNamespace(session_id=session_id),
                sequence=0, position=position, count=count)

        active_a0 = job("ses_" + "a" * 32, 0, 5)
        queued_b0 = job("ses_" + "b" * 32, 0, 11)
        self.assertIsNone(cohort._ordered_interleave_stage1_sessions(
            active_a0, (), set()))
        self.assertEqual(cohort._ordered_interleave_stage1_sessions(
            active_a0, (queued_b0,), set()),
            ("ses_" + "a" * 32, "ses_" + "b" * 32))
        self.assertIsNone(cohort._ordered_interleave_stage1_sessions(
            active_a0, (queued_b0,), {"ses_" + "b" * 32}))

        reply_events = [
            {"event": "stage_response", "worker": 3, "session_id": "ses_" + "a" * 32,
             "position": 0, "token_count": 5},
            {"event": "stage_response", "worker": 3, "session_id": "ses_" + "b" * 32,
             "position": 0, "token_count": 11},
            {"event": "stage_response", "worker": 3, "session_id": "ses_" + "a" * 32,
             "position": 5, "token_count": 1},
            {"event": "stage_response", "worker": 3, "session_id": "ses_" + "b" * 32,
             "position": 11, "token_count": 1},
        ]
        self.assertEqual(cohort._ordered_interleave_reply_trace(
            reply_events, "ses_" + "a" * 32, "ses_" + "b" * 32),
            ["A0", "B0", "A1", "B1"])
        reply_events[1], reply_events[2] = reply_events[2], reply_events[1]
        with self.assertRaises(cohort.CohortError):
            cohort._ordered_interleave_reply_trace(
                reply_events, "ses_" + "a" * 32, "ses_" + "b" * 32)

    def test_cancel_profile_has_two_fixed_session_bound_observations(self):
        self.assertEqual(cohort._PROFILE_OBSERVATIONS[cohort.PROFILE_C1B_CANCEL],
                         cohort._BASELINE_OBSERVATIONS + (
                             (5, "cancel-held-worker3-session", True),
                             (6, "cancel-worker3-reclaimed", True)))
        for sequence, case_id in ((5, "cancel-held-worker3-session"),
                                  (6, "cancel-worker3-reclaimed")):
            self.assertEqual(cohort._profile_observation(
                cohort.PROFILE_C1B_CANCEL, sequence), (case_id, True))

    def test_partial_open_profile_has_only_two_fixed_lease_observations(self):
        self.assertEqual(cohort._PROFILE_OBSERVATIONS[cohort.PROFILE_C1B_PARTIAL],
                         cohort._BASELINE_OBSERVATIONS + (
                             (5, "partial-open-reply-held", True),
                             (6, "partial-open-lease-expired", True)))
        for sequence, case_id in ((5, "partial-open-reply-held"),
                                  (6, "partial-open-lease-expired")):
            self.assertEqual(cohort._profile_observation(
                cohort.PROFILE_C1B_PARTIAL, sequence), (case_id, True))

    def test_step_reply_loss_profile_has_two_session_bound_observations(self):
        expected = cohort._BASELINE_OBSERVATIONS + (
            (5, "step-reply-loss-held", True),
            (6, "step-reply-loss-reclaimed", True))
        self.assertEqual(cohort._PROFILE_OBSERVATIONS[cohort.PROFILE_C1B_STEP_LOSS],
                         expected)
        held = self._observation_ack(
            sequence=5, case_id="step-reply-loss-held",
            request_id="req_" + "6" * 32, session_id="ses_" + "7" * 32)
        held["remote_status"]["handler"].update(
            active_sessions=1, active_session_ids=[held["session_id"]],
            retained_entries=1, committed_cache_bytes=12,
            allocated_cache_bytes=16)
        held["remote_status"]["bridge"]["owned_sessions"] = 1
        checked = cohort.validate_observation_ack(
            held, self.expected, sequence=5, case_id="step-reply-loss-held",
            request_id=held["request_id"], session_id=held["session_id"],
            expected_host_key="9" * 64, profile=cohort.PROFILE_C1B_STEP_LOSS)
        self.assertEqual(checked["committed_cache_bytes"], 12)
        for mutate in (
                lambda item: item["remote_status"].update(boot_id="0" * 32),
                lambda item: item["remote_status"]["handler"].update(
                    active_session_ids=["ses_" + "8" * 32]),
                lambda item: item["remote_status"]["handler"].update(
                    committed_cache_bytes=0),
                lambda item: item["remote_status"]["handler"].update(
                    active_compute=True)):
            broken = copy.deepcopy(held)
            mutate(broken)
            with self.assertRaises(cohort.CohortError):
                cohort.validate_observation_ack(
                    broken, self.expected, sequence=5,
                    case_id="step-reply-loss-held", request_id=held["request_id"],
                    session_id=held["session_id"], expected_host_key="9" * 64,
                    profile=cohort.PROFILE_C1B_STEP_LOSS)
        reclaimed = self._observation_ack(
            sequence=6, case_id="step-reply-loss-reclaimed",
            request_id="req_" + "6" * 32, session_id="ses_" + "7" * 32)
        checked_idle = cohort.validate_observation_ack(
            reclaimed, self.expected, sequence=6,
            case_id="step-reply-loss-reclaimed", request_id=reclaimed["request_id"],
            session_id=reclaimed["session_id"], expected_host_key="9" * 64,
            profile=cohort.PROFILE_C1B_STEP_LOSS)
        self.assertEqual(checked_idle["active_sessions"], 0)

    def test_step_reply_loss_successful_cleanup_removes_captured_request(self):
        captured = object()
        requests = {"ses_example": captured}
        self.assertEqual(cohort._step_reply_loss_request_membership(
            requests, "ses_example", captured), "retained")
        # Coordinator._complete_request_state removes a successfully cleaned
        # request; the observer must inspect the captured object by identity.
        del requests["ses_example"]
        self.assertEqual(cohort._step_reply_loss_request_membership(
            requests, "ses_example", captured), "absent")
        requests["ses_example"] = object()
        self.assertEqual(cohort._step_reply_loss_request_membership(
            requests, "ses_example", captured), "replaced")

    def test_capacity_profile_requires_exact_eight_remote_session_identities(self):
        self.assertEqual(cohort._PROFILE_OBSERVATIONS[cohort.PROFILE_C1B_CAPACITY],
                         cohort._BASELINE_OBSERVATIONS + (
                             (5, "capacity-eight-held", True),
                             (6, "capacity-eight-reclaimed", True)))
        ack = self._observation_ack(
            sequence=5, case_id="capacity-eight-held",
            request_id="req_" + "5" * 32, session_id="ses_" + "1" * 32)
        session_ids = sorted([ack["session_id"]]
                             + [f"ses_{index:032x}" for index in range(1, 8)])
        ack["remote_status"]["handler"].update(
            active_sessions=8, active_session_ids=session_ids,
            committed_cache_bytes=0, allocated_cache_bytes=0)
        ack["remote_status"]["bridge"]["owned_sessions"] = 8
        checked = cohort.validate_observation_ack(
            ack, self.expected, sequence=5, case_id="capacity-eight-held",
            request_id=ack["request_id"], session_id=ack["session_id"],
            expected_host_key="9" * 64, profile=cohort.PROFILE_C1B_CAPACITY,
            expected_session_ids=session_ids)
        self.assertEqual(checked["active_session_ids"], session_ids)
        for mutate in (
                lambda item: item["remote_status"]["handler"].update(
                    active_session_ids=session_ids[:-1]),
                lambda item: item["remote_status"]["handler"].update(active_sessions=7),
                lambda item: item["remote_status"]["bridge"].update(owned_sessions=7)):
            broken = copy.deepcopy(ack)
            mutate(broken)
            with self.assertRaises(cohort.CohortError):
                cohort.validate_observation_ack(
                    broken, self.expected, sequence=5, case_id="capacity-eight-held",
                    request_id=broken["request_id"], session_id=broken["session_id"],
                    expected_host_key="9" * 64, profile=cohort.PROFILE_C1B_CAPACITY,
                    expected_session_ids=session_ids)

    def test_capacity_drain_preserves_both_directions_of_request_session_identity(self):
        pairs = [(f"req_{index:032x}", f"ses_{index:032x}")
                 for index in range(1, 9)]
        outcomes = [{"request_id": request_id, "session_id": session_id}
                    for request_id, session_id in reversed(pairs)]
        session_ids = [session_id for _, session_id in pairs]
        self.assertTrue(cohort._capacity_outcomes_match(pairs, outcomes, session_ids))

        crossed = copy.deepcopy(outcomes)
        crossed[0]["session_id"] = pairs[0][1]
        self.assertFalse(cohort._capacity_outcomes_match(pairs, crossed, session_ids))
        self.assertFalse(cohort._capacity_outcomes_match(
            pairs, outcomes, session_ids[:-1]))

    def test_capacity_held_queue_requires_exact_one_plus_seven_session_topology(self):
        session_ids = [f"ses_{index:032x}" for index in range(1, 9)]
        active = SimpleNamespace(
            request=SimpleNamespace(session_id=session_ids[0]), sequence=0, position=0)
        queued = tuple(SimpleNamespace(request=SimpleNamespace(session_id=session_id))
                       for session_id in session_ids[1:])
        active_jobs = [active, None, None]
        self.assertEqual(cohort._capacity_held_queue_active_session(
            active, queued, session_ids, active_jobs=active_jobs,
            stage_count=3), session_ids[0])

        self.assertIsNone(cohort._capacity_held_queue_active_session(
            active, queued[:-1], session_ids, active_jobs=active_jobs, stage_count=3))
        duplicate_queue = queued[:-1] + (queued[0],)
        self.assertIsNone(cohort._capacity_held_queue_active_session(
            active, duplicate_queue, session_ids, active_jobs=active_jobs, stage_count=3))
        bool_sequence_job = SimpleNamespace(
            request=active.request, sequence=True, position=0)
        self.assertIsNone(cohort._capacity_held_queue_active_session(
            bool_sequence_job, queued, session_ids,
            active_jobs=[bool_sequence_job, None, None], stage_count=3))
        self.assertIsNone(cohort._capacity_held_queue_active_session(
            active, queued, session_ids[:-1] + [session_ids[0]],
            active_jobs=active_jobs, stage_count=3))
        self.assertIsNone(cohort._capacity_held_queue_active_session(
            active, queued, session_ids, active_jobs=[active, object(), None], stage_count=3))
        self.assertIsNone(cohort._capacity_held_queue_active_session(
            active, queued, session_ids, active_jobs=[active, None], stage_count=2))

    def test_interleave_extension_schema_is_closed_and_requires_causal_barrier(self):
        summary = {
            "profile": cohort.PROFILE_C1B_INTERLEAVE, "status": "passed",
            "completed_requests": 2, "prompt_lengths": [5, 11],
            "captured_vectors": 8, "comparison_errors": [0.0] * 8,
            "max_absolute_error": 0.0,
            "request_ids": ["req_" + "1" * 32, "req_" + "2" * 32],
            "session_ids": ["ses_" + "1" * 32, "ses_" + "2" * 32],
            "step_trace": ["A0", "B0", "A1", "B1"],
            "causal_barrier_confirmed": True,
            "local_owner_check": {
                "confirmed": True, "active_requests": 0, "active_streams": 0,
                "active_generate_streams": 0, "active_captures": 0,
                "capture_reserved_bytes": 0, "worker_sessions": 0,
                "worker_active_compute": False,
                "transport_reserved_connections": 15,
                "transport_reserved_pending": 0,
            },
            "remote_owner_check_confirmed": True,
        }
        self.assertIs(cohort._validate_interleave_summary(summary), summary)
        invalid = copy.deepcopy(summary)
        invalid["causal_barrier_confirmed"] = False
        with self.assertRaises(cohort.CohortError):
            cohort._validate_interleave_summary(invalid)
        for lengths in ([5.0, 11], [True, 11], [5, 11.0]):
            invalid = copy.deepcopy(summary)
            invalid["prompt_lengths"] = lengths
            with self.subTest(prompt_lengths=lengths), self.assertRaises(cohort.CohortError):
                cohort._validate_interleave_summary(invalid)

    def test_happy_extension_summary_matches_closed_flat_supervisor_schema(self):
        expected_fields = {
            "profile", "status", "completed_requests", "numerical_errors",
            "request_ids", "session_ids", "remote_overlap_observed",
            "preflight_rejection",
        }
        self.assertEqual(cohort._C1B_EXTENSION_RESULT_FIELDS, expected_fields)
        summary = {
            "profile": cohort.PROFILE_C1B_HAPPY,
            "status": "passed",
            "completed_requests": 3,
            "numerical_errors": [0.0] * 9,
            "request_ids": [f"req_{index:032x}" for index in range(1, 4)],
            "session_ids": [f"ses_{index:032x}" for index in range(1, 4)],
            "remote_overlap_observed": False,
            "preflight_rejection": {
                "case_id": "context-over-boundary-1152-plus-1-local-preflight",
                "request_id": "req_" + "4" * 32,
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
                "evidence_scope": (
                    "public client preflight only; no worker RPC or remote compute claim"),
            },
        }
        self.assertIs(cohort._validate_c1b_extension_summary(summary), summary)

        invalid_summaries = []
        nested_errors = copy.deepcopy(summary)
        nested_errors["numerical_errors"] = {
            "captured_vectors": 9, "values": [0.0] * 9,
        }
        invalid_summaries.append(nested_errors)
        unknown_field = copy.deepcopy(summary)
        unknown_field["max_absolute_error"] = 0.0
        invalid_summaries.append(unknown_field)
        wrong_error_count = copy.deepcopy(summary)
        wrong_error_count["numerical_errors"] = [0.0] * 8
        invalid_summaries.append(wrong_error_count)
        fabricated_remote_preflight = copy.deepcopy(summary)
        fabricated_remote_preflight["preflight_rejection"]["session_id"] = (
            "ses_" + "5" * 32)
        invalid_summaries.append(fabricated_remote_preflight)
        for invalid in invalid_summaries:
            with self.subTest(summary=invalid):
                with self.assertRaises(cohort.CohortError):
                    cohort._validate_c1b_extension_summary(invalid)

    def test_happy_profile_observations_are_fixed_and_keep_session_binding(self):
        request_id = "req_" + "1" * 32
        session_id = "ses_" + "2" * 32
        expected_cases = (
            (5, "unequal-concurrent-prompt-5"),
            (6, "unequal-concurrent-prompt-11"),
            (7, "context-boundary-1151-plus-1"),
        )
        for sequence, case_id in expected_cases:
            with self.subTest(sequence=sequence):
                request = cohort.build_observation_request(
                    self.expected, sequence=sequence, case_id=case_id,
                    request_id=request_id, session_id=session_id,
                    profile=cohort.PROFILE_C1B_HAPPY)
                self.assertEqual(request["sequence"], sequence)
                self.assertEqual(request["case_id"], case_id)
                self.assertEqual(request["session_id"], session_id)
                ack = self._observation_ack(
                    sequence=sequence, case_id=case_id, request_id=request_id,
                    session_id=session_id)
                checked = cohort.validate_observation_ack(
                    ack, self.expected, sequence=sequence, case_id=case_id,
                    request_id=request_id, session_id=session_id,
                    expected_host_key="9" * 64, profile=cohort.PROFILE_C1B_HAPPY)
                self.assertTrue(checked["confirmed"])
        for sequence, case_id, profile, supplied_session in (
            (5, "unequal-concurrent-prompt-5", cohort.PROFILE_BASELINE, session_id),
            (5, "arbitrary", cohort.PROFILE_C1B_HAPPY, session_id),
            (7, "context-boundary-1151-plus-1", cohort.PROFILE_C1B_HAPPY, None),
            (8, "context-boundary-1151-plus-1", cohort.PROFILE_C1B_HAPPY, session_id),
            (True, "greedy-one-token", cohort.PROFILE_BASELINE, session_id),
        ):
            with self.subTest(sequence=sequence, case=case_id, profile=profile):
                with self.assertRaises(cohort.CohortError):
                    cohort.build_observation_request(
                        self.expected, sequence=sequence, case_id=case_id,
                        request_id=request_id, session_id=supplied_session,
                        profile=profile)

    def test_handoff_v1_field_sets_and_launch_state_are_fixed(self):
        observation = cohort.build_observation_request(
            self.expected, sequence=1, case_id="greedy-one-token",
            request_id="req_" + "1" * 32, session_id="ses_" + "2" * 32)
        self.assertEqual(set(observation), cohort.HANDOFF_OBSERVATION_REQUEST_FIELDS)
        stopped = cohort.build_stop_request(
            run_id=self.expected.run_id, nonce=self.expected.nonce,
            boot_id=self.expected.boot_id, may_have_started=True)
        self.assertEqual(set(stopped), cohort.HANDOFF_STOP_REQUEST_FIELDS)
        not_started = cohort.build_stop_request(
            run_id=self.expected.run_id, nonce=self.expected.nonce,
            boot_id=None, may_have_started=False)
        self.assertEqual(not_started["expected_boot_id"], None)
        with self.assertRaises(cohort.CohortError):
            cohort.build_stop_request(
                run_id=self.expected.run_id, nonce=self.expected.nonce,
                boot_id=None, may_have_started=True)

    def test_cli_requires_canonical_private_endpoint_and_fixed_port(self):
        for uncertainty in (0.0, 30.1, math.inf, math.nan, True):
            args = SimpleNamespace(
                artifacts=str(Path.cwd() / "artifacts"),
                reference=str(Path.cwd() / "reference"),
                handoff_directory=str(Path.cwd() / "handoff"),
                external_ip=TEST_EXTERNAL_IP,
                external_port=cohort.REMOTE_PORT,
                clock_uncertainty_seconds=uncertainty,
            )
            with self.subTest(uncertainty=uncertainty), self.assertRaises(cohort.CohortError):
                cohort.validate_cli_values(args)
        alternate = TEST_OTHER_EXTERNAL_IP
        self.assertEqual(cohort._validate_ip_port(alternate, cohort.REMOTE_PORT),
                         (alternate, cohort.REMOTE_PORT))
        for invalid_ip in ("192.0.2.2", "127.0.0.1", "8.8.8.8", "worker.local",
                           "010.0.0.1"):
            with self.subTest(invalid_ip=invalid_ip), self.assertRaises(cohort.CohortError):
                cohort._validate_ip_port(invalid_ip, cohort.REMOTE_PORT)
        with self.assertRaises(cohort.CohortError):
            cohort._validate_ip_port(TEST_EXTERNAL_IP, 50062)

    def test_remote_expectation_uses_the_supplied_private_endpoint(self):
        principal = SimpleNamespace(
            account_id="acct_" + "a" * 32,
            device_id="dev_" + "b" * 32,
            boot_id="c" * 32,
            assignment_id="asg_" + "d" * 32,
        )
        manifest = {
            "fingerprint": "e" * 64,
            "components": {"worker-3": {"layer_range": [6, 8]}},
        }
        alternate = "10.71.22.9"
        expected = cohort._make_remote_expectation(
            run_id="1" * 32, nonce="2" * 32, principal=principal,
            manifest=manifest, snapshot_sha256="f" * 64, uncertainty=2.0,
            external_ip=alternate, external_port=cohort.REMOTE_PORT)
        self.assertEqual(expected.endpoint, f"{alternate}:50061")

    def test_strict_json_rejects_duplicate_keys_nonfinite_and_oversize(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b"[]"):
            with self.subTest(raw=raw), self.assertRaises(cohort.CohortError):
                cohort.decode_control_json(raw)
        with self.assertRaises(cohort.CohortError):
            cohort.decode_control_json(b" " * (cohort.MAX_CONTROL_BYTES + 1))

    def test_worker_config_is_closed_to_worker3_and_fixed_secret_scope(self):
        from steamboat_runtime.manifest import MODEL_ID, MODEL_REVISION

        principal = SimpleNamespace(
            name="worker-3", role="host", account_id=self.expected.account_id,
            device_id=self.expected.device_id, boot_id=self.expected.boot_id,
            assignment_id=self.expected.assignment_id,
            certificate_pem=b"PRIVATE-LEAF-CERT-DO-NOT-SERIALIZE",
            private_key_pem=b"PRIVATE-ROLE-KEY-DO-NOT-SERIALIZE",
        )
        config = cohort.build_worker_config_payload(
            principal=principal,
            manifest={"model_id": MODEL_ID, "revision": MODEL_REVISION,
                      "fingerprint": self.expected.manifest_fingerprint},
            artifact_directory=str(Path.cwd() / "artifacts"),
            clock_uncertainty_seconds=2.0,
            external_ip=TEST_EXTERNAL_IP,
            external_port=cohort.REMOTE_PORT,
        )
        self.assertEqual(set(config), cohort._WORKER_CONFIG_FIELDS)
        self.assertEqual(config["worker_name"], "worker-3")
        self.assertEqual(config["listen_ip"], TEST_EXTERNAL_IP)
        self.assertEqual(config["listen_port"], cohort.REMOTE_PORT)
        self.assertEqual(config["clock_uncertainty_seconds"], 2.0)
        self.assertEqual(config["private_key_path"], "/run/steamboat/host.key")
        encoded = cohort._json_bytes(config, maximum=cohort.MAX_CONFIG_BYTES)
        self.assertNotIn(principal.private_key_pem, encoded)
        self.assertNotIn(principal.certificate_pem, encoded)

        wrong_role = copy.copy(principal)
        object.__setattr__(wrong_role, "name", "worker-2")
        with self.assertRaises(cohort.CohortError):
            cohort.build_worker_config_payload(
                principal=wrong_role,
                manifest={"model_id": MODEL_ID, "revision": MODEL_REVISION,
                          "fingerprint": self.expected.manifest_fingerprint},
                artifact_directory=str(Path.cwd() / "artifacts"),
                clock_uncertainty_seconds=2.0,
                external_ip=TEST_EXTERNAL_IP,
                external_port=cohort.REMOTE_PORT,
            )

    def test_ready_ack_requires_matching_nonce_boot_hash_and_real_owner_shape(self):
        ack = self._ready_ack()
        host_key = cohort.validate_ready_ack(ack, self.expected)
        self.assertEqual(host_key, "9" * 64)
        heartbeat_ack = copy.deepcopy(ack)
        heartbeat_ack["remote_status"]["event"] = "heartbeat"
        self.assertEqual(cohort.validate_ready_ack(heartbeat_ack, self.expected), "9" * 64)
        for phase, event in (("unavailable", "heartbeat"), ("ready", "unknown")):
            unhealthy = copy.deepcopy(ack)
            unhealthy["remote_status"]["phase"] = phase
            unhealthy["remote_status"]["event"] = event
            with self.subTest(phase=phase, event=event), self.assertRaises(cohort.CohortError):
                cohort.validate_ready_ack(unhealthy, self.expected)
        for field, value in (("nonce", "0" * 32), ("boot_id", "0" * 32),
                             ("snapshot_sha256", "0" * 64),
                             ("remote_status_uid", 0)):
            broken = copy.deepcopy(ack)
            broken[field] = value
            with self.subTest(field=field), self.assertRaises(cohort.CohortError):
                cohort.validate_ready_ack(broken, self.expected)
        broken = copy.deepcopy(ack)
        broken["unapproved"] = True
        with self.assertRaises(cohort.CohortError):
            cohort.validate_ready_ack(broken, self.expected)

    def test_remote_owner_status_fails_closed_on_any_live_or_unknown_owner(self):
        status = self._status()
        result = cohort._validate_worker_status(status, self.expected, event="ready")
        self.assertTrue(result["confirmed"])
        for section, key, value in (
            ("handler", "active_sessions", 1),
            ("handler", "allocated_cache_bytes", None),
            ("handler", "cache_bytes_exact", False),
            ("handler", "active_compute", True),
            ("bridge", "active_authorizations", 1),
            ("bridge", "cleanup_confirmed", False),
            ("transport", "reserved_connections", 2),
        ):
            broken = copy.deepcopy(status)
            broken[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(cohort.CohortError):
                cohort._validate_worker_status(broken, self.expected, event="ready")

    def test_observation_requires_current_nonce_sequence_and_new_remote_heartbeat(self):
        request = cohort.build_observation_request(
            self.expected, sequence=1, case_id="greedy-one-token",
            request_id="req_" + "1" * 32, session_id="ses_" + "2" * 32)
        self.assertEqual(request["expected_boot_id"], self.expected.boot_id)
        ack = self._observation_ack()
        checked = cohort.validate_observation_ack(
            ack, self.expected, sequence=1, case_id="greedy-one-token",
            request_id="req_" + "1" * 32, session_id="ses_" + "2" * 32,
            expected_host_key="9" * 64)
        self.assertTrue(checked["confirmed"])
        for field, value in (("nonce", "0" * 32), ("sequence", 2),
                             ("heartbeat_mtime_ns", 1000),
                             ("ssh_host_key_sha256", "8" * 64)):
            broken = copy.deepcopy(ack)
            broken[field] = value
            with self.subTest(field=field), self.assertRaises(cohort.CohortError):
                cohort.validate_observation_ack(
                    broken, self.expected, sequence=1, case_id="greedy-one-token",
                    request_id="req_" + "1" * 32,
                    session_id="ses_" + "2" * 32, expected_host_key="9" * 64)

    def test_observation_request_rejects_unknown_case_and_untyped_ids(self):
        for case_id, request_id, session_id in (
            ("arbitrary-command", "req_" + "1" * 32, "ses_" + "2" * 32),
            ("greedy-one-token", "request-1", "ses_" + "2" * 32),
            ("greedy-one-token", "req_" + "1" * 32, "session-1"),
        ):
            with self.subTest(case=case_id, request=request_id, session=session_id):
                with self.assertRaises(cohort.CohortError):
                    cohort.build_observation_request(
                        self.expected, sequence=1, case_id=case_id,
                        request_id=request_id, session_id=session_id)

    def test_cancel_profile_requires_exact_held_session_and_cache_then_idle(self):
        request_id, session_id = "req_" + "3" * 32, "ses_" + "4" * 32
        held = self._observation_ack(
            sequence=5, case_id="cancel-held-worker3-session",
            request_id=request_id, session_id=session_id)
        handler = held["remote_status"]["handler"]
        handler.update({"active_sessions": 1, "active_session_ids": [session_id],
                        "committed_cache_bytes": 128, "allocated_cache_bytes": 256})
        held["remote_status"]["bridge"]["owned_sessions"] = 1
        checked = cohort.validate_observation_ack(
            held, self.expected, sequence=5,
            case_id="cancel-held-worker3-session", request_id=request_id,
            session_id=session_id, expected_host_key="9" * 64,
            profile=cohort.PROFILE_C1B_CANCEL)
        self.assertTrue(checked["confirmed"])
        self.assertEqual(checked["active_sessions"], 1)
        self.assertEqual(checked["owned_sessions"], 1)
        for mutate in (
                lambda item: item["remote_status"]["handler"].update(
                    active_session_ids=["ses_" + "5" * 32]),
                lambda item: item["remote_status"]["handler"].update(
                    committed_cache_bytes=0),
                lambda item: item["remote_status"]["bridge"].update(owned_sessions=0),
                lambda item: item.update(supervisor_monotonic_ns=True)):
            broken = copy.deepcopy(held)
            mutate(broken)
            with self.assertRaises(cohort.CohortError):
                cohort.validate_observation_ack(
                    broken, self.expected, sequence=5,
                    case_id="cancel-held-worker3-session", request_id=request_id,
                    session_id=session_id, expected_host_key="9" * 64,
                    profile=cohort.PROFILE_C1B_CANCEL)

    def test_partial_profile_requires_exact_open_reservation_with_no_cache(self):
        request_id, session_id = "req_" + "6" * 32, "ses_" + "7" * 32
        held = self._observation_ack(
            sequence=5, case_id="partial-open-reply-held",
            request_id=request_id, session_id=session_id)
        held["remote_status"]["handler"].update(
            active_sessions=1, active_session_ids=[session_id])
        held["remote_status"]["bridge"]["owned_sessions"] = 1
        checked = cohort.validate_observation_ack(
            held, self.expected, sequence=5,
            case_id="partial-open-reply-held", request_id=request_id,
            session_id=session_id, expected_host_key="9" * 64,
            profile=cohort.PROFILE_C1B_PARTIAL)
        self.assertTrue(checked["confirmed"])
        self.assertEqual(checked["active_sessions"], 1)
        self.assertEqual(checked["owned_sessions"], 1)
        for key in ("committed_cache_bytes", "allocated_cache_bytes"):
            held["remote_status"]["handler"][key] = 1
            with self.assertRaises(cohort.CohortError):
                cohort.validate_observation_ack(
                    held, self.expected, sequence=5,
                    case_id="partial-open-reply-held", request_id=request_id,
                    session_id=session_id, expected_host_key="9" * 64,
                    profile=cohort.PROFILE_C1B_PARTIAL)
            held["remote_status"]["handler"][key] = 0

    def test_stop_ack_distinguishes_observed_exit_from_not_started(self):
        ack = {
            "schema_version": 1, "event": "stop_ack",
            "run_id": self.expected.run_id, "nonce": self.expected.nonce,
            "boot_id": self.expected.boot_id, "process_state": "not_started",
            "exit_code": None, "shutdown_confirmed": True,
            "ssh_host_key_sha256": "9" * 64,
            "remote_status_uid": None, "remote_status_mode": None,
            "measurement_label": "ssh_supervisor_not_started", "remote_status": None,
        }
        with self.assertRaises(cohort.CohortError):
            cohort.validate_stop_ack(
                ack, run_id=self.expected.run_id, nonce=self.expected.nonce,
                expected_boot_id=self.expected.boot_id, may_have_started=True,
                readiness_observed=True,
                expected_host_key="9" * 64, expected=self.expected)
        confirmed = cohort.validate_stop_ack(
            ack, run_id=self.expected.run_id, nonce=self.expected.nonce,
            expected_boot_id=self.expected.boot_id, may_have_started=True,
            readiness_observed=False,
            expected_host_key="9" * 64, expected=self.expected)
        self.assertEqual(confirmed["process_state"], "not_started")
        never_published = dict(ack)
        never_published["boot_id"] = None
        confirmed = cohort.validate_stop_ack(
            never_published, run_id=self.expected.run_id, nonce=self.expected.nonce,
            expected_boot_id=None, may_have_started=False,
            readiness_observed=False,
            expected_host_key="9" * 64)
        self.assertEqual(confirmed["process_state"], "not_started")
        ack["shutdown_confirmed"] = False
        with self.assertRaises(cohort.CohortError):
            cohort.validate_stop_ack(
                ack, run_id=self.expected.run_id, nonce=self.expected.nonce,
                expected_boot_id=self.expected.boot_id, may_have_started=True,
                readiness_observed=True,
                expected_host_key="9" * 64, expected=self.expected)

    def _final_status(self):
        status = self._status(event="final")
        status["phase"] = "stopped"
        status["shutdown"] = {
            "server": "confirmed", "bridge": "confirmed",
            "handler": "confirmed", "overall": "confirmed",
        }
        status["transport"].update({
            "reserved_connections": 0,
            "reserved_pending": 0,
            "reserved_listener_pending_capacity": 0,
            "reserved_outbound_pending": 0,
            "server_state": "stopped",
        })
        return status

    def _stop_ack(self, status):
        return {
            "schema_version": 1, "event": "stop_ack",
            "run_id": self.expected.run_id, "nonce": self.expected.nonce,
            "boot_id": self.expected.boot_id, "process_state": "exited",
            "exit_code": 0, "shutdown_confirmed": True,
            "ssh_host_key_sha256": "9" * 64,
            "remote_status_uid": cohort.REMOTE_STATUS_UID,
            "remote_status_mode": cohort.REMOTE_STATUS_MODE,
            "measurement_label": cohort.STOP_LABEL,
            "remote_status": status,
        }

    def test_stop_ack_requires_actual_full_worker_owner_cleanup(self):
        ack = self._stop_ack(self._final_status())
        result = cohort.validate_stop_ack(
            ack, run_id=self.expected.run_id, nonce=self.expected.nonce,
            expected_boot_id=self.expected.boot_id, may_have_started=True,
            readiness_observed=True,
            expected_host_key="9" * 64, expected=self.expected)
        self.assertEqual(result["process_state"], "exited")
        mutations = (
            ("handler", "active_sessions", 1),
            ("handler", "cache_bytes_exact", False),
            ("bridge", "active_authorizations", 1),
            ("transport", "reserved_connections", 1),
        )
        for section, key, value in mutations:
            broken = copy.deepcopy(ack)
            broken["remote_status"][section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(cohort.CohortError):
                cohort.validate_stop_ack(
                    broken, run_id=self.expected.run_id, nonce=self.expected.nonce,
                    expected_boot_id=self.expected.boot_id, may_have_started=True,
                    readiness_observed=True,
                    expected_host_key="9" * 64, expected=self.expected)

        broken = copy.deepcopy(ack)
        broken["remote_status"]["shutdown"]["overall"] = "unknown"
        with self.assertRaises(cohort.CohortError):
            cohort.validate_stop_ack(
                broken, run_id=self.expected.run_id, nonce=self.expected.nonce,
                expected_boot_id=self.expected.boot_id, may_have_started=True,
                readiness_observed=True,
                expected_host_key="9" * 64, expected=self.expected)

    def test_final_status_accepts_only_coherent_bounded_terminal_records(self):
        ack = self._stop_ack(self._final_status())
        ack["remote_status"]["handler"]["tombstones"] = 2
        ack["remote_status"]["handler"]["retained_entries"] = 2
        ack["remote_status"]["handler"]["limits"]["max_tombstones"] = 2
        accepted = cohort.validate_stop_ack(
            ack, run_id=self.expected.run_id, nonce=self.expected.nonce,
            expected_boot_id=self.expected.boot_id, may_have_started=True,
            readiness_observed=True, expected_host_key="9" * 64,
            expected=self.expected)
        self.assertTrue(accepted["confirmed"])

        for change in (("retained_entries", 1), ("tombstones", 3)):
            broken = copy.deepcopy(ack)
            broken["remote_status"]["handler"][change[0]] = change[1]
            with self.subTest(change=change), self.assertRaises(cohort.CohortError):
                cohort.validate_stop_ack(
                    broken, run_id=self.expected.run_id, nonce=self.expected.nonce,
                    expected_boot_id=self.expected.boot_id, may_have_started=True,
                    readiness_observed=True, expected_host_key="9" * 64,
                    expected=self.expected)

    def test_nonzero_worker_exit_keeps_cleanup_evidence_and_fails_baseline(self):
        ack = self._stop_ack(self._final_status())
        ack["exit_code"] = 9
        remote_shutdown = cohort.validate_stop_ack(
            ack, run_id=self.expected.run_id, nonce=self.expected.nonce,
            expected_boot_id=self.expected.boot_id, may_have_started=True,
            readiness_observed=True, expected_host_key="9" * 64,
            expected=self.expected)
        result = {"baseline": {"status": "passed"}}
        cleanup_errors = []
        cohort._record_remote_shutdown(result, remote_shutdown, cleanup_errors)
        self.assertEqual(result["baseline"]["status"], "failed")
        self.assertIs(result["remote_shutdown"], remote_shutdown)
        self.assertTrue(remote_shutdown["confirmed"])
        self.assertEqual(remote_shutdown["exit_code"], 9)
        self.assertEqual(len(cleanup_errors), 1)

    def test_stop_ack_accepts_explicit_pre_runtime_startup_failure_only(self):
        status = self._final_status()
        status.update({
            "phase": "startup_failed", "layer_range": None, "torch_threads": 0,
            "handler": {"state": "not_started"},
            "bridge": {"state": "not_started"},
            "transport": {"state": "not_started"},
            "shutdown": {
                "server": "not_started", "bridge": "not_started",
                "handler": "not_started", "overall": "confirmed",
            },
            "startup_error_type": "WorkerConfigError",
        })
        ack = self._stop_ack(status)
        result = cohort.validate_stop_ack(
            ack, run_id=self.expected.run_id, nonce=self.expected.nonce,
            expected_boot_id=self.expected.boot_id, may_have_started=True,
            readiness_observed=False,
            expected_host_key="9" * 64, expected=self.expected)
        self.assertTrue(result["confirmed"])

        broken = copy.deepcopy(ack)
        broken["remote_status"]["shutdown"]["overall"] = "unknown"
        with self.assertRaises(cohort.CohortError):
            cohort.validate_stop_ack(
                broken, run_id=self.expected.run_id, nonce=self.expected.nonce,
                expected_boot_id=self.expected.boot_id, may_have_started=True,
                readiness_observed=False,
                expected_host_key="9" * 64, expected=self.expected)

        malformed = copy.deepcopy(ack)
        malformed["remote_status"] = {
            "schema_version": 1, "event": "final", "phase": "startup_failed",
            "status": "unknown", "error_type": "WorkerConfigError",
        }
        with self.assertRaises(cohort.CohortError):
            cohort.validate_stop_ack(
                malformed, run_id=self.expected.run_id, nonce=self.expected.nonce,
                expected_boot_id=self.expected.boot_id, may_have_started=True,
                readiness_observed=False,
                expected_host_key="9" * 64, expected=self.expected)

    def test_result_allowlist_prevents_prompt_tensor_or_secret_payloads(self):
        with self.assertRaises(cohort.CohortError):
            cohort._private_result_summary({"prompt": [7, 13, 31]})

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_DIRECTORY"),
                         "requires POSIX dirfd publication semantics")
    def test_postlink_directory_fsync_failure_keeps_launch_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            launch_state = {"boot_id": None, "may_have_started": False}
            boot_id = "c" * 32
            ready = {
                "schema_version": 1, "event": "bundle_ready",
                "run_id": self.expected.run_id, "nonce": self.expected.nonce,
                "bundle_path": "/tmp/private/worker-3-bundle",
                "expected_boot_id": boot_id,
                "manifest_fingerprint": self.expected.manifest_fingerprint,
                "snapshot_sha256": self.expected.snapshot_sha256,
                "endpoint": self.expected.endpoint, "worker_name": "worker-3",
            }
            original_fsync = os.fsync
            calls = 0

            def fail_directory_fsync(fd):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected directory fsync failure after link")
                return original_fsync(fd)

            try:
                with mock.patch.object(cohort.os, "fsync", side_effect=fail_directory_fsync):
                    with self.assertRaisesRegex(OSError, "after link"):
                        cohort._publish_bundle_ready(
                            directory_fd, ready, boot_id=boot_id,
                            launch_state=launch_state)
                self.assertTrue((Path(directory) / cohort.HANDOFF_BUNDLE_READY_FILE).is_file())
                self.assertEqual(launch_state, {"boot_id": boot_id, "may_have_started": True})
                stop_request = cohort.build_stop_request(
                    run_id=self.expected.run_id, nonce=self.expected.nonce,
                    boot_id=launch_state["boot_id"],
                    may_have_started=launch_state["may_have_started"])
                self.assertTrue(stop_request["may_have_started"])
                self.assertEqual(stop_request["expected_boot_id"], boot_id)
            finally:
                os.close(directory_fd)


class SecureCohortRuntimeLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_restart_probe_cleanup_retains_context_when_first_client_close_fails(self):
        class Budget:
            reserved_connections = 3
            reserved_pending = 0
            reserved_outbound_pending = 0
            reserved_listener_pending_capacity = 0

        class Probe:
            def __init__(self, events):
                self.context_factory = SimpleNamespace(_context_index={"owned": self})
                self.context = SimpleNamespace()
                self.authorization_membership = {"owned": self}
                self.close_calls = 0
                self.events = events

            def close(self):
                self.close_calls += 1
                self.events.append("probe-close")
                self.context_factory._context_index.clear()
                self.authorization_membership.clear()

        class Client:
            _closed = False

            def __init__(self):
                self.close_calls = 0

            async def close(self):
                self.close_calls += 1
                raise OSError("first close outcome unknown")

        events, budget, probe, client = [], Budget(), None, Client()
        probe = Probe(events)
        state, owner, outcomes = {}, cohort._CleanupOwner(), {}
        clients, probes = [(client, state)], [probe]
        owner.add("probe release gate", lambda: cohort._close_restart_probe_owners_after_clients(
            probes, clients, budget, outcomes))
        owner.add("client first close", lambda: cohort._close_restart_probe_client_once(
            client, budget, state, expected_connections_before=3,
            expected_connections_after=0))
        errors = await owner.close()
        self.assertEqual(client.close_calls, 1)
        self.assertEqual(probe.close_calls, 0)
        self.assertIn("owned", probe.context_factory._context_index)
        self.assertIn("owned", probe.authorization_membership)
        self.assertEqual(events, [])
        self.assertEqual(len(errors), 2)

    async def test_restart_probe_cleanup_closes_all_created_clients_before_contexts(self):
        class Budget:
            reserved_connections = 6
            reserved_pending = 0
            reserved_outbound_pending = 0
            reserved_listener_pending_capacity = 0

        events = []

        class Probe:
            def __init__(self, name):
                self.name = name
                self.context_factory = SimpleNamespace(_context_index={name: self})
                self.context = SimpleNamespace()

            def close(self):
                self.assert_clients_closed()
                events.append("probe-" + self.name)
                self.context_factory._context_index.clear()

            @staticmethod
            def assert_clients_closed():
                if not all(client._closed for client, _state in clients):
                    raise AssertionError("probe context released before all client closes")

        class Client:
            def __init__(self, name):
                self.name = name
                self._closed = False
                self.close_calls = 0

            async def close(self):
                self.close_calls += 1
                self._closed = True
                budget.reserved_connections -= 3
                events.append("client-" + self.name)

        budget, outcomes = Budget(), {}
        first, second = Client("old"), Client("new")
        first_state, second_state = {}, {}
        clients = [(first, first_state), (second, second_state)]
        probes = [Probe("old"), Probe("new")]
        owner = cohort._CleanupOwner()
        owner.add("probe release gate", lambda: cohort._close_restart_probe_owners_after_clients(
            probes, clients, budget, outcomes))
        owner.add("old client close", lambda: cohort._close_restart_probe_client_for_cleanup(
            first, budget, first_state, connection_slots=3))
        owner.add("new client close", lambda: cohort._close_restart_probe_client_for_cleanup(
            second, budget, second_state, connection_slots=3))
        self.assertEqual(await owner.close(), [])
        self.assertEqual(events, ["client-new", "client-old", "probe-old", "probe-new"])
        self.assertEqual((first.close_calls, second.close_calls), (1, 1))
        self.assertEqual(budget.reserved_connections, 0)
        self.assertEqual(probes[0].context_factory._context_index, {})
        self.assertEqual(probes[1].context_factory._context_index, {})

    async def test_restart_probe_cleanup_tracks_only_clients_created_before_failure(self):
        class Budget:
            reserved_connections = 3
            reserved_pending = 0
            reserved_outbound_pending = 0
            reserved_listener_pending_capacity = 0

        events = []

        class Probe:
            context_factory = SimpleNamespace(_context_index={"old": object()})

            def close(self):
                events.append("probe-close")
                self.context_factory._context_index.clear()

        class Client:
            _closed = False
            close_calls = 0

            async def close(self):
                self.close_calls += 1
                self._closed = True
                budget.reserved_connections = 0
                events.append("client-close")

        budget, probe, client = Budget(), Probe(), Client()
        state, outcomes = {}, {}
        probes, clients = [probe], [(client, state)]
        owner = cohort._CleanupOwner()
        owner.add("probe release gate", lambda: cohort._close_restart_probe_owners_after_clients(
            probes, clients, budget, outcomes))
        owner.add("only client actually created", lambda: cohort._close_restart_probe_client_once(
            client, budget, state, expected_connections_before=3,
            expected_connections_after=0))
        self.assertEqual(await owner.close(), [])
        self.assertEqual(events, ["client-close", "probe-close"])
        self.assertEqual(client.close_calls, 1)
        self.assertEqual(probe.context_factory._context_index, {})

    async def test_restart_early_old_rpc_failure_cleanup_releases_single_client(self):
        class Budget:
            reserved_connections = 3

        class Client:
            def __init__(self, budget):
                self.budget = budget
                self.close_calls = 0
                self._closed = False

            async def close(self):
                self.close_calls += 1
                self.budget.reserved_connections -= 3
                self._closed = True

        budget, state = Budget(), {}
        client = Client(budget)
        owner = cohort._CleanupOwner()
        owner.add("original client", lambda: cohort._close_restart_probe_client_for_cleanup(
            client, budget, state, connection_slots=3))
        # The old RPC failed before a new Describe client could be created.
        errors = await owner.close()
        self.assertEqual(errors, [])
        self.assertEqual(client.close_calls, 1)
        self.assertTrue(state["confirmed"])
        self.assertEqual(state["reserved_connections_before"], 3)
        self.assertEqual(state["reserved_connections_after"], 0)
        self.assertEqual(budget.reserved_connections, 0)

    async def test_restart_new_describe_failure_cleanup_closes_new_then_original(self):
        class Budget:
            reserved_connections = 6

        class Client:
            def __init__(self, budget, name, events):
                self.budget, self.name, self.events = budget, name, events
                self.close_calls = 0
                self._closed = False

            async def close(self):
                self.close_calls += 1
                self.events.append(self.name)
                self.budget.reserved_connections -= 3
                self._closed = True

        budget, events, original_state = Budget(), [], {}
        original = Client(budget, "original", events)
        new_client = Client(budget, "new-describe", events)
        owner = cohort._CleanupOwner()
        owner.add("original client", lambda: cohort._close_restart_probe_client_for_cleanup(
            original, budget, original_state, connection_slots=3))
        # LIFO teardown closes the failed new Describe caller before old client.
        owner.add("new Describe client", lambda: cohort._close_worker_client(
            {"client": new_client}))
        errors = await owner.close()
        self.assertEqual(errors, [])
        self.assertEqual(events, ["new-describe", "original"])
        self.assertEqual(new_client.close_calls, 1)
        self.assertEqual(original.close_calls, 1)
        self.assertEqual(original_state["reserved_connections_before"], 3)
        self.assertEqual(original_state["reserved_connections_after"], 0)
        self.assertEqual(budget.reserved_connections, 0)

    async def test_restart_stale_client_closes_before_replacement_with_same_binding_and_budget(self):
        class Budget:
            reserved_connections = 6

        class Client:
            def __init__(self, budget):
                self.budget = budget
                self.close_calls = 0
                self._closed = False

            async def close(self):
                self.close_calls += 1
                self.budget.reserved_connections -= 3
                self._closed = True

        budget = Budget()
        original = Client(budget)
        context = object()
        authorizer = object()
        peer = object()
        local_identity = object()
        state = {}
        registered = []
        factory_calls = []

        async def create_replacement():
            self.assertTrue(original._closed)
            self.assertEqual(budget.reserved_connections, 3)
            factory_calls.append((context, authorizer, peer, local_identity))
            self.assertIs(factory_calls[-1][0], context)
            self.assertIs(factory_calls[-1][1], authorizer)
            self.assertIs(factory_calls[-1][2], peer)
            self.assertIs(factory_calls[-1][3], local_identity)
            budget.reserved_connections += 3
            return Client(budget)

        replacement, counts = await cohort._replace_restart_probe_client(
            original, budget, state, create_replacement=create_replacement,
            register_replacement=registered.append, connection_slots=3)
        self.assertEqual(original.close_calls, 1)
        self.assertTrue(state["confirmed"])
        self.assertEqual(state["reserved_connections_before"], 6)
        self.assertEqual(state["reserved_connections_after"], 3)
        self.assertEqual(counts, [2, 1, 2])
        self.assertEqual(budget.reserved_connections, 6)
        self.assertEqual(len(factory_calls), 1)
        self.assertEqual(registered, [replacement])

        repeated, repeated_counts = await cohort._replace_restart_probe_client(
            original, budget, state, create_replacement=create_replacement,
            register_replacement=registered.append, connection_slots=3)
        self.assertIs(repeated, replacement)
        self.assertEqual(repeated_counts, counts)
        self.assertEqual(original.close_calls, 1)
        self.assertEqual(len(factory_calls), 1)

    async def test_restart_uses_two_serialized_clients_for_distinct_stale_methods(self):
        class Budget:
            reserved_connections = 6

        class Client:
            def __init__(self, budget, name):
                self.budget, self.name = budget, name
                self.close_calls = 0
                self._closed = False

            async def close(self):
                self.close_calls += 1
                self.budget.reserved_connections -= 3
                self._closed = True

        budget = Budget()
        status_client = Client(budget, "status")
        context, authorizer, peer, local_identity = (object() for _ in range(4))
        status_state, cancel_state = {}, {}
        registered = []

        async def create_cancel_client():
            self.assertTrue(status_client._closed)
            self.assertEqual(budget.reserved_connections, 3)
            budget.reserved_connections += 3
            return Client(budget, "cancel")

        cancel_client, counts = await cohort._replace_restart_probe_client(
            status_client, budget, status_state,
            create_replacement=create_cancel_client,
            register_replacement=registered.append, connection_slots=3)
        self.assertEqual(status_client.close_calls, 1)
        self.assertEqual(cancel_client.name, "cancel")
        self.assertEqual(counts, [2, 1, 2])
        self.assertEqual(budget.reserved_connections, 6)

        await cohort._close_restart_probe_client_once(
            cancel_client, budget, cancel_state,
            expected_connections_before=6, expected_connections_after=3)
        accounted = [1, 2] + counts[1:] + [1]
        self.assertEqual(accounted, [1, 2, 1, 2, 1])
        self.assertEqual(max(accounted), 2)
        self.assertEqual(cancel_client.close_calls, 1)
        self.assertTrue(cancel_state["confirmed"])
        self.assertEqual(registered, [cancel_client])
        # The binding material is caller-owned and survives both client lifetimes.
        self.assertIsNotNone(context)
        self.assertIsNotNone(authorizer)
        self.assertIsNotNone(peer)
        self.assertIsNotNone(local_identity)

    async def test_restart_failed_original_close_is_retained_and_never_retried_or_replaced(self):
        class Budget:
            reserved_connections = 6

        class Client:
            def __init__(self):
                self.close_calls = 0
                self._closed = False
                self.failure = OSError("first close outcome unknown")

            async def close(self):
                self.close_calls += 1
                raise self.failure

        budget = Budget()
        original = Client()
        state = {}
        factory_calls = []

        async def create_replacement():
            factory_calls.append(True)
            return Client()

        for _attempt in range(2):
            with self.assertRaises(OSError) as caught:
                await cohort._replace_restart_probe_client(
                    original, budget, state, create_replacement=create_replacement,
                    register_replacement=lambda _client: None, connection_slots=3)
            self.assertIs(caught.exception, original.failure)
        self.assertEqual(original.close_calls, 1)
        self.assertFalse(original._closed)
        self.assertEqual(budget.reserved_connections, 6)
        self.assertEqual(factory_calls, [])
        self.assertIs(state["failure"], original.failure)
        self.assertIs(state["replacement_failure"], original.failure)
        with self.assertRaises(OSError) as cleanup_error:
            await cohort._close_restart_probe_client_for_cleanup(
                original, budget, state, connection_slots=3)
        self.assertIs(cleanup_error.exception, original.failure)
        self.assertEqual(original.close_calls, 1)

    async def test_restart_close_attempt_keeps_consumed_failure_and_owner(self):
        calls = []
        owner = cohort._CleanupOwner()

        def fail_once():
            calls.append("called")
            raise OSError("bounded test close failure")

        owner.add("injected close", fail_once)
        attempts = {}
        first = await cohort._close_restart_owner_once(owner, attempts)
        second = await cohort._close_restart_owner_once(owner, attempts)
        self.assertEqual(calls, ["called"])
        self.assertEqual(len(first), 1)
        self.assertIs(first, second)
        self.assertIs(attempts[id(owner)][0], owner)
        self.assertEqual(len(owner._retained_actions), 1)

    def test_restart_unknown_remote_exit_retains_full_graph(self):
        graph = object()
        before = len(cohort._RETAINED_RESTART_OWNERS)
        try:
            retained = cohort._retain_restart_graph_if_uncertain(
                {"confirmed": False, "process_state": "unknown", "exit_code": None},
                [], graph)
            self.assertTrue(retained)
            self.assertEqual(len(cohort._RETAINED_RESTART_OWNERS), before + 1)
            self.assertIs(cohort._RETAINED_RESTART_OWNERS[-1][0], graph)
            self.assertFalse(cohort._restart_remote_exit_confirmed(
                {"confirmed": True, "process_state": "unknown", "exit_code": 0}))
            self.assertFalse(cohort._restart_remote_exit_confirmed(
                {"confirmed": False, "process_state": "exited", "exit_code": 0}))
            completed = {"confirmed": True, "process_state": "exited", "exit_code": 0}
            self.assertFalse(cohort._retain_restart_graph_if_uncertain(
                completed, [], object()))
            cleanup_failure = OSError("cleanup unconfirmed")
            self.assertTrue(cohort._retain_restart_graph_if_uncertain(
                completed, [cleanup_failure], graph))
            self.assertIs(cohort._RETAINED_RESTART_OWNERS[-1][0], graph)
        finally:
            del cohort._RETAINED_RESTART_OWNERS[before:]

    def test_restart_probe_close_records_real_terminal_auth_and_factory_release(self):
        from tests.security.secure_pipeline_fixture import SecurePipelineIdentityFixture
        try:
            from lab.secure_cohort_boot import build_trusted_probe_context
            probe_module_error = None
        except ModuleNotFoundError as error:
            if not ((error.name or "").startswith("google")
                    or error.name == "worker_pb2"):
                raise
            probe_module_error = error
        if probe_module_error is not None:
            self.skipTest("worker protocol dependency unavailable for genuine probe close")

        authority = SecurePipelineIdentityFixture("a" * 64)
        try:
            try:
                probe = build_trusted_probe_context(authority, timeout_seconds=120)
            except ModuleNotFoundError as error:
                if not (error.name or "").startswith("google"):
                    raise
                self.skipTest("worker protocol dependency unavailable for genuine probe close")
            probe.close()
            authorization_terminal, context_released = cohort._trusted_probe_cleanup_state(probe)
            self.assertTrue(authorization_terminal)
            self.assertTrue(context_released)
            self.assertTrue(probe.authorization._failed)
            self.assertFalse(probe.authorization._finished)
            self.assertNotIn(id(probe.context), probe.context_factory._context_index)
        finally:
            authority.close()

    async def test_false_local_closers_retain_owner_and_fail_with_zero_counters(self):
        class FalseCloser:
            async def close(self):
                return False

        coordinator = FalseCloser()
        coordinator_holder = {"coordinator": coordinator}
        coordinator_owner = cohort._CleanupOwner()
        coordinator_owner.add(
            "coordinator close",
            lambda: cohort._close_coordinator(coordinator_holder))
        coordinator_errors = await cohort._close_local_pipeline(
            coordinator_owner, {}, expected_connections=15)
        self.assertEqual(len(coordinator_errors), 1)
        self.assertIs(coordinator_holder["coordinator"], coordinator)
        self.assertEqual(len(coordinator_owner._retained_actions), 1)

        model = FalseCloser()
        model_holder = {"model": model}
        model_owner = cohort._CleanupOwner()
        model_owner.add("model close", lambda: cohort._close_model(model_holder))
        model_errors = await cohort._close_local_pipeline(
            model_owner, {}, expected_connections=15)
        self.assertEqual(len(model_errors), 1)
        self.assertIs(model_holder["model"], model)
        self.assertEqual(len(model_owner._retained_actions), 1)

    async def test_overflow_preflight_guards_client_dispatch_and_coordinator_submit(self):
        import time
        from steamboat_runtime.remote_client import RemoteError, validate_generate
        from steamboat_security import ConsumerRequestContext

        class Outbound:
            def create_consumer_request_context(self, *, lifetime_seconds):
                return ConsumerRequestContext(
                    self, "req_" + "a" * 32, time.monotonic() + lifetime_seconds)

        class Coordinator:
            def __init__(self):
                self.events = []
                self.trace_dropped = 0
                self.original_submit_calls = 0

            def stats(self):
                return {"active_requests": 0}

            def submit(self, *_args, **_kwargs):
                self.original_submit_calls += 1
                raise AssertionError("overflow preflight must not submit work")

        class Channel:
            def __init__(self):
                self.dispatch_calls = 0

            def unary_stream(self, *_args, **_kwargs):
                def dispatch(*_call_args, **_call_kwargs):
                    self.dispatch_calls += 1
                    raise AssertionError("guard should intercept before channel dispatch")
                return dispatch

        class Client:
            def __init__(self, coordinator, mode):
                self.coordinator = coordinator
                self.mode = mode
                self.channel = Channel()

            async def _ensure_channel(self, *_args, **_kwargs):
                return self.channel

            def generate(self, input_ids, new_tokens, *, trusted_request_context,
                         capture_logits, timeout_seconds):
                async def events():
                    if self.mode == "local-validation":
                        validate_generate({
                            "input_ids": input_ids, "new_tokens": new_tokens,
                            "forced_tokens": None, "capture_logits": capture_logits,
                            "timeout_seconds": timeout_seconds,
                        })
                    elif self.mode == "client-dispatch":
                        channel = await self._ensure_channel(timeout_seconds)
                        try:
                            channel.unary_stream(
                                "/steamboat.v1.Coordinator/Generate")(
                                    b"bounded-test-payload", timeout=timeout_seconds)
                        except cohort.CohortError:
                            # Model an invalid-input response after a boundary
                            # was crossed; the preflight helper must reject it.
                            raise RemoteError("INVALID_INPUT", "synthetic rejection") from None
                    elif self.mode == "coordinator-submit":
                        try:
                            self.coordinator.submit(input_ids, new_tokens,
                                trusted_request_context=trusted_request_context)
                        except cohort.CohortError:
                            raise RemoteError("INVALID_INPUT", "synthetic rejection") from None
                    if False:
                        yield None
                return events()

        class Budget:
            def status(self):
                return SimpleNamespace(
                    active_captures=0, cleanup_pending_captures=0, reserved_bytes=0)

        async def run_case(mode):
            coordinator = Coordinator()
            client = Client(coordinator, mode)
            service = SimpleNamespace(active_streams=0, cleanups={})
            secure_service = SimpleNamespace(active_generate_streams=0)
            transport = SimpleNamespace(
                reserved_connections=15, reserved_pending=0,
                reserved_outbound_pending=0)
            torch = SimpleNamespace(tensor=lambda *_args, **_kwargs: None)
            original_tensor = torch.tensor
            outbound = Outbound()
            if mode == "local-validation":
                result = await cohort._check_context_overflow_preflight(
                    torch=torch, client=client, outbound=outbound,
                    coordinator=coordinator, service=service,
                    secure_service=secure_service, worker_nodes=[],
                    capture_budget=Budget(), transport_budget=transport)
                self.assertEqual(result["error_code"], "INVALID_INPUT")
                self.assertEqual(result["tensor_allocations"], 0)
                self.assertEqual(result["coordinator_submits"], 0)
                self.assertFalse(result["remote_worker_contacted"])
            else:
                with self.assertRaisesRegex(cohort.CohortError, "crossed"):
                    await cohort._check_context_overflow_preflight(
                        torch=torch, client=client, outbound=outbound,
                        coordinator=coordinator, service=service,
                        secure_service=secure_service, worker_nodes=[],
                        capture_budget=Budget(), transport_budget=transport)
            self.assertIs(torch.tensor, original_tensor)
            self.assertNotIn("_ensure_channel", client.__dict__)
            self.assertNotIn("submit", coordinator.__dict__)
            self.assertEqual(coordinator.original_submit_calls, 0)
            self.assertEqual(client.channel.dispatch_calls, 0)

        await run_case("local-validation")
        await run_case("client-dispatch")
        await run_case("coordinator-submit")

    async def test_real_worker_handler_shutdown_keeps_only_bounded_terminal_record(self):
        try:
            from steamboat_runtime.protocol.worker_pb2 import Request
            from steamboat_runtime.worker_state import WorkerHandler
        except ModuleNotFoundError as error:
            self.skipTest(f"worker protocol dependency unavailable: {error.name}")

        manifest_path = Path(__file__).resolve().parents[1] / "runtime" / "test_manifest.py"
        spec = importlib.util.spec_from_file_location("_secure_cohort_manifest_fixture", manifest_path)
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        manifest = fixture.sample_manifest()

        class EmptyCache:
            def clear(self):
                return None

            def allocated_bytes(self):
                return 0

            def lengths(self):
                return ()

        class CheapExecutor:
            def new_cache(self):
                return EmptyCache()

            def execute(self, hidden, cache, position):
                raise AssertionError("this lifecycle test must not run model computation")

        handler = WorkerHandler(
            manifest, "worker-1", CheapExecutor(), boot_id="a" * 32,
            max_tombstones=4)
        shutdown_called = False
        try:
            opened = await handler.handle("OpenSession", Request(
                protocol_version=1, manifest_fingerprint=manifest["fingerprint"],
                worker_boot_id=handler.boot_id, session_id="terminal-session",
                timeout_ms=1000, max_positions=2, lifetime_ms=30_000,
                idle_lease_ms=10_000))
            self.assertEqual(opened.code, "OK", opened.message)
            closed = await handler.handle("CloseSession", Request(
                protocol_version=1, manifest_fingerprint=manifest["fingerprint"],
                worker_boot_id=handler.boot_id, session_id="terminal-session",
                lease_token=opened.lease_token, timeout_ms=1000))
            self.assertEqual(closed.code, "OK", closed.message)
            self.assertTrue(closed.reclaimed)

            self.assertIs(await handler.shutdown(grace_seconds=1), True)
            shutdown_called = True
            status = handler._response()
            retained = len({id(entry) for entry in
                            tuple(handler.sessions.values()) + tuple(handler.tombstones.values())})
            self.assertEqual(status.active_sessions, 0)
            self.assertEqual(status.active_operations, 0)
            self.assertEqual(status.queued_operations, 0)
            self.assertEqual(status.allocated_cache_bytes, 0)
            self.assertTrue(status.cache_bytes_exact)
            self.assertEqual(status.tombstones, 1)
            self.assertEqual(retained, status.tombstones)
            self.assertLessEqual(status.tombstones, handler.max_tombstones)
            tombstone = handler.tombstones["terminal-session"]
            self.assertEqual(tombstone.terminal_code, "CLOSED_SESSION")
            self.assertEqual(tombstone.committed_bytes, 0)
            self.assertEqual(tombstone.cache.allocated_bytes(), 0)
            self.assertFalse(any(tombstone.cache.lengths()))
        finally:
            if not shutdown_called:
                await handler.shutdown(grace_seconds=1)


class SecureCohortDeferredRuntimeImportTests(unittest.TestCase):
    def test_production_deferred_imports_resolve_without_running_pipeline(self):
        missing_base = [name for name in ("torch", "transformers")
                        if importlib.util.find_spec(name) is None]
        if missing_base:
            self.skipTest("base model dependencies unavailable: " + ", ".join(missing_base))

        source_path = Path(cohort.__file__)
        source_tree = ast.parse(source_path.read_text(encoding="utf-8"))
        pipeline = next(
            node for node in source_tree.body
            if isinstance(node, ast.AsyncFunctionDef)
            and node.name == "_run_real_pipeline")
        imports = []

        def collect_imports(node):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imports.append(node)
                return
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return
            for child in ast.iter_child_nodes(node):
                collect_imports(child)

        for statement in pipeline.body:
            collect_imports(statement)
        imports.sort(key=lambda node: (node.lineno, node.col_offset))
        self.assertTrue(imports, "_run_real_pipeline has no deferred imports to smoke")

        import_module = ast.Module(body=imports, type_ignores=[])
        ast.fix_missing_locations(import_module)
        namespace = {"__name__": "secure_cohort_deferred_import_smoke"}
        exec(compile(import_module, str(source_path), "exec"), namespace)
        self.assertIn("create_secure_coordinator_server", namespace)


class SecureCohortFailureLocationTests(unittest.TestCase):
    def _record_from(self, function):
        try:
            function()
        except BaseException as error:
            return cohort._failure_location_record("a" * 32, "b" * 32, error)
        self.fail("fixture function did not raise")

    def _assert_record_schema(self, record):
        self.assertEqual(set(record), {
            "schema_version", "event", "run_id", "nonce", "failure_type",
            "error_code", "frames",
        })
        self.assertIs(type(record["schema_version"]), int)
        self.assertEqual(record["schema_version"], 2)
        self.assertEqual(record["event"], "cohort_failure_location")
        self.assertRegex(record["run_id"], re.compile(r"[0-9a-f]{32}\Z", re.ASCII))
        self.assertRegex(record["nonce"], re.compile(r"[0-9a-f]{32}\Z", re.ASCII))
        self.assertRegex(record["failure_type"],
                         re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z", re.ASCII))
        self.assertLessEqual(len(record["frames"]), 12)
        self.assertIs(type(record["frames"]), list)
        for frame in record["frames"]:
            self.assertEqual(set(frame), {"file", "function", "line"})
            self.assertRegex(frame["file"],
                             re.compile(r"[A-Za-z0-9_.-]{1,80}\Z", re.ASCII))
            self.assertTrue(frame["file"].isascii())
            self.assertRegex(frame["function"],
                             re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z", re.ASCII))
            self.assertIs(type(frame["line"]), int)
            self.assertGreaterEqual(frame["line"], 1)
            self.assertLessEqual(frame["line"], 1_000_000)

    def test_record_omits_secret_exception_text_and_uses_atomic_fixed_handoff(self):
        secret = "secret-prompt-and-token-must-not-appear"

        def raise_sensitive():
            raise RuntimeError(secret)

        record = self._record_from(raise_sensitive)
        self._assert_record_schema(record)
        raw = cohort._json_bytes(record, maximum=cohort.MAX_FAILURE_LOCATION_BYTES)
        self.assertLessEqual(len(raw), 4096)
        self.assertNotIn(secret.encode("ascii"), raw)
        self.assertNotIn(str(Path.cwd()).encode("utf-8"), raw)
        self.assertEqual(record["failure_type"], "RuntimeError")
        self.assertIsNone(record["error_code"])
        self.assertTrue(any(frame["function"] == "raise_sensitive"
                            for frame in record["frames"]))
        self.assertTrue(all("/" not in frame["file"] and "\\" not in frame["file"]
                            for frame in record["frames"]))

        with mock.patch.object(cohort, "_atomic_create_at") as atomic_create:
            cohort._safe_write_handoff(
                23, cohort.HANDOFF_FAILURE_LOCATION_FILE, record)
        atomic_create.assert_called_once()
        args = atomic_create.call_args.args
        self.assertEqual(args[0], 23)
        self.assertEqual(args[1], "failure-location.json")
        self.assertLessEqual(len(args[2]), 4096)
        self.assertEqual(json.loads(args[2]), record)

    def test_record_keeps_nearest_valid_frames_within_the_bound(self):
        def raise_deep(depth):
            if depth:
                return raise_deep(depth - 1)
            raise ValueError("location only")

        record = self._record_from(lambda: raise_deep(80))
        self._assert_record_schema(record)
        self.assertEqual(len(record["frames"]), 12)
        self.assertTrue(all(frame["function"] == "raise_deep"
                            for frame in record["frames"]))

    def test_record_skips_invalid_frame_names_without_exposing_paths(self):
        source = (
            "def é():\n"
            "    raise ValueError('private detail')\n"
            "é()\n"
        )
        code = compile(source, r"C:\private\secret\<bad>.py", "exec")

        def execute_bad_names():
            exec(code, {})

        record = self._record_from(execute_bad_names)
        self._assert_record_schema(record)
        serialized = cohort._json_bytes(record)
        self.assertNotIn(b"private", serialized)
        self.assertNotIn(b"secret", serialized)
        self.assertNotIn("é".encode("utf-8"), serialized)
        self.assertTrue(record["frames"])
        self.assertTrue(all(frame["file"] == "test_secure_cohort_lab.py"
                            for frame in record["frames"]))

    def _supervisor_parser(self):
        from lab import secure_cohort_supervisor
        return secure_cohort_supervisor

    def test_collector_codes_are_finite_redacted_and_accepted_by_supervisor_parser(self):
        from steamboat_runtime.remote_client import RemoteError
        from steamboat_runtime.protocol.errors import ProtocolError

        parser = self._supervisor_parser()
        ready = {"run_id": "a" * 32, "nonce": "b" * 32}
        recognized = self._record_from(
            lambda: (_ for _ in ()).throw(RemoteError("TIMEOUT", "secret prompt")))
        self.assertEqual(recognized["error_code"], "TIMEOUT")
        normalized = parser._validate_cohort_failure_location(recognized, ready)
        self.assertEqual(normalized["error_code"], "TIMEOUT")
        protocol_record = self._record_from(
            lambda: (_ for _ in ()).throw(
                ProtocolError("EXECUTION_FAILED", "secret protocol details")))
        self.assertEqual(protocol_record["error_code"], "EXECUTION_FAILED")
        self.assertEqual(
            parser._validate_cohort_failure_location(protocol_record, ready)["error_code"],
            "EXECUTION_FAILED")
        self.assertNotIn(b"secret protocol details", cohort._json_bytes(protocol_record))

        cases = []
        cases.append(self._record_from(lambda: (_ for _ in ()).throw(ValueError("secret"))))

        class NonStringCodeError(Exception):
            code = 42

        cases.append(self._record_from(
            lambda: (_ for _ in ()).throw(NonStringCodeError("secret"))))

        class CallableCodeError(Exception):
            called = False

            def code(self):
                self.called = True
                return "TIMEOUT"

        callable_error = CallableCodeError("secret")
        record = self._record_from(lambda: (_ for _ in ()).throw(callable_error))
        cases.append(record)
        self.assertFalse(callable_error.called)

        class ArbitraryCodeError(Exception):
            code = "private-unknown-" + ("é" * 2000)

        cases.append(self._record_from(
            lambda: (_ for _ in ()).throw(ArbitraryCodeError("secret diagnostic"))))
        for index, item in enumerate(cases):
            expected_code = (None if index < len(cases) - 1
                             else "UNRECOGNIZED_ERROR_CODE")
            self.assertEqual(item["error_code"], expected_code)
            encoded = cohort._json_bytes(item, maximum=cohort.MAX_FAILURE_LOCATION_BYTES)
            self.assertNotIn(b"secret", encoded)
            self.assertNotIn("é".encode("utf-8"), encoded)
            self.assertEqual(
                parser._validate_cohort_failure_location(item, ready), item)
        self.assertEqual(cases[-1]["error_code"], "UNRECOGNIZED_ERROR_CODE")

    def test_supervisor_parser_accepts_legacy_v1_and_rejects_malformed_v2(self):
        parser = self._supervisor_parser()
        ready = {"run_id": "a" * 32, "nonce": "b" * 32}
        record = self._record_from(lambda: (_ for _ in ()).throw(ValueError("secret")))
        legacy = dict(record, schema_version=1)
        legacy.pop("error_code")
        normalized = parser._validate_cohort_failure_location(legacy, ready)
        self.assertEqual(normalized, legacy)

        for mutate in (
                lambda value: value.update(schema_version=True),
                lambda value: value.pop("error_code"),
                lambda value: value.update(error_code="UNKNOWN-PRIVATE"),
                lambda value: value.update(error_code=7),
                lambda value: value.update(unexpected=True)):
            malformed = dict(record)
            mutate(malformed)
            with self.assertRaises(parser.SupervisorError):
                parser._validate_cohort_failure_location(malformed, ready)


class OwnerRemovalMaterialPreparationTests(unittest.TestCase):
    """Real C0 policy/signing material checks; no publication or worker action."""

    @classmethod
    def setUpClass(cls):
        try:
            from tests.security.secure_pipeline_fixture import SecurePipelineIdentityFixture
            from lab.secure_cohort_owner import (
                OwnerExpectation, PROFILE_C1B_OWNER_REMOVE,
            )
        except ImportError as error:
            raise unittest.SkipTest(
                f"secure identity dependencies are unavailable: {type(error).__name__}")
        cls.fingerprint = "a" * 64
        cls.authority = SecurePipelineIdentityFixture(cls.fingerprint)
        store, _clock = cls.authority.new_store()
        initial = store.current()
        cls.expected = OwnerExpectation(
            profile=PROFILE_C1B_OWNER_REMOVE,
            run_id="1" * 32, nonce="2" * 32,
            worker_boot_id=cls.authority.principals["worker-3"].boot_id,
            manifest_fingerprint=cls.fingerprint,
            endpoint="127.0.0.1:50061",
            initial_snapshot_sha256=__import__("hashlib").sha256(
                cls.authority.signed_snapshot).hexdigest(),
            initial_revision=initial.revision,
        )

    @classmethod
    def tearDownClass(cls):
        authority = getattr(cls, "authority", None)
        if authority is not None:
            authority.close()

    def _prepare(self, authority=None, expected=None, command_ids=None):
        return cohort._prepare_owner_materials(
            authority or self.authority, expected or self.expected,
            command_ids=command_ids or ("3" * 32, "4" * 32))

    def test_materials_are_two_verified_higher_policies_and_actual_worker_intents(self):
        import hashlib
        import json
        import os
        import stat
        import tempfile
        from types import SimpleNamespace

        result = self._prepare()
        self.assertEqual(set(result), {
            "ready", "files", "commands", "initial_local_serials"})
        self.assertEqual(set(result["files"]), {
            "install-snapshot.json", "remove-snapshot.json",
            "install-intent.json", "removal-intent.json"})
        self.assertEqual(len(result["initial_local_serials"]), 1)
        self.assertEqual(len(result["commands"]), 2)
        self.assertEqual(
            [item["action"] for item in result["commands"]],
            ["install_snapshot", "remove"])
        self.assertEqual(
            [item["snapshot_revision"] for item in result["commands"]],
            [self.expected.initial_revision + 1, self.expected.initial_revision + 2])
        original_store, _clock = self.authority.new_store()
        original = json.loads(original_store.current().canonical_payload)
        old_worker = self.authority.principals["worker-3"]
        original_local = sorted(row["serial"] for row in original["credentials"]
                                if row["device_id"] == old_worker.device_id)
        self.assertEqual(result["initial_local_serials"], original_local)

        preserved_credentials = [row for row in original["credentials"]
                                 if row["device_id"] != old_worker.device_id]
        preserved_grants = [row for row in original["grants"]
                            if row["device_id"] != old_worker.device_id
                            and row["target_device_id"] != old_worker.device_id]
        for offset, name in enumerate(("install-snapshot.json", "remove-snapshot.json"), 1):
            payload = json.loads(result["files"][name])["payload"]
            self.assertEqual(payload["revision"], self.expected.initial_revision + offset)
            self.assertEqual(payload["issued_at"], original["issued_at"])
            self.assertEqual(payload["expires_at"], original["expires_at"])
            self.assertEqual(payload["credentials"], preserved_credentials)
            self.assertEqual(payload["grants"], preserved_grants)
            self.assertEqual(payload["revoked_devices"], sorted(
                set(original["revoked_devices"]) | {old_worker.device_id}))
            self.assertEqual(payload["revoked_serials"], sorted(
                set(original["revoked_serials"]) | set(original_local)))
            self.assertEqual(result["commands"][offset - 1]["snapshot_sha256"],
                             hashlib.sha256(result["files"][name]).hexdigest())

        self.assertEqual(result["ready"]["event"], "owner_materials_ready")
        for name, metadata in result["ready"]["files"].items():
            data = result["files"][name]
            self.assertEqual(metadata, {
                "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    def test_archive_roundtrips_through_the_actual_pinned_material_parser(self):
        from lab.secure_cohort_owner import validate_owner_material_archive

        prepared = self._prepare()
        archive = cohort._owner_material_archive(prepared["files"])
        parsed = validate_owner_material_archive(archive, prepared["ready"], self.expected)
        self.assertEqual(tuple(parsed), tuple(prepared["files"]))
        self.assertEqual(parsed, prepared["files"])
        damaged_bytes = bytearray(archive)
        damaged_bytes[0] ^= 1
        damaged = bytes(damaged_bytes)
        with self.assertRaises(ValueError):
            validate_owner_material_archive(damaged, prepared["ready"], self.expected)

    def test_signed_intents_are_accepted_by_the_actual_worker_verifier(self):
        import json
        import os
        import stat
        import tempfile
        from types import SimpleNamespace

        if os.name != "posix":
            self.skipTest("actual worker intent verifier requires POSIX protected files")
        result = self._prepare()
        from lab.secure_worker import _verify_owner_removal_intent
        from lab.secure_worker_owner_control import parse_owner_command
        with tempfile.TemporaryDirectory(prefix="owner-intent-interop-") as temporary:
            root = Path(temporary)
            role_root, intent_root = root / "role", root / "materials"
            role_root.mkdir(mode=0o700)
            intent_root.mkdir(mode=0o700)
            os.chmod(role_root, 0o700)
            os.chmod(intent_root, 0o700)
            for number, (filename, command) in enumerate(zip(
                    ("install-intent.json", "removal-intent.json"),
                    result["commands"])):
                path = intent_root / filename
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(result["files"][filename])
                os.chmod(path, 0o600)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                parsed = parse_owner_command(
                    json.dumps(command, sort_keys=True, separators=(",", ":")).encode(),
                    expected_run_id=self.expected.run_id,
                    expected_worker_boot_id=self.expected.worker_boot_id)
                verified = _verify_owner_removal_intent(
                    SimpleNamespace(protected_root=str(role_root)), parsed,
                    str(intent_root),
                    verification_key_pem=self.authority.snapshot_verification_key_pem,
                    filename=filename)
                self.assertEqual(verified["command_id"], command["command_id"])
                self.assertEqual(verified["snapshot_sha256"], command["snapshot_sha256"])

    def test_bad_expectation_or_command_ids_fail_before_operator_key_read(self):
        from dataclasses import replace
        from unittest import mock

        bad_identity = replace(self.expected, worker_boot_id="f" * 32)
        bad_fingerprint = replace(self.expected, manifest_fingerprint="b" * 64)
        bad_digest = replace(self.expected, initial_snapshot_sha256="c" * 64)
        with mock.patch("lab.secure_cohort_boot._read_private_signer",
                        side_effect=AssertionError("signer read before identity validation")) as reader:
            with self.assertRaises(cohort.CohortError):
                self._prepare(expected=bad_identity)
            with self.assertRaises(cohort.CohortError):
                self._prepare(expected=bad_fingerprint)
            with self.assertRaises(cohort.CohortError):
                self._prepare(expected=bad_digest)
            with self.assertRaises(cohort.CohortError):
                self._prepare(command_ids=("3" * 32, "3" * 32))
            with self.assertRaises(cohort.CohortError):
                self._prepare(command_ids=("3" * 31 + "G", "4" * 32))
        reader.assert_not_called()

    def test_tampered_initial_snapshot_fails_without_authority_mutation_or_key_read(self):
        from unittest import mock

        signed = self.authority.signed_snapshot
        with mock.patch.object(self.authority, "signed_snapshot", b"tampered"):
            with mock.patch("lab.secure_cohort_boot._read_private_signer",
                            side_effect=AssertionError("signer read before policy validation")) as reader:
                with self.assertRaises(Exception):
                    self._prepare()
                reader.assert_not_called()
        self.assertIs(self.authority.signed_snapshot, signed)

    def test_authority_snapshot_and_principal_material_are_unchanged(self):
        import copy

        signed = self.authority.signed_snapshot
        principal_records = {name: (
            copy.deepcopy(principal.record), principal.private_key_pem,
            principal.certificate_pem)
                             for name, principal in self.authority.principals.items()}
        ca_pem = self.authority.cohort_ca_pem
        self._prepare()
        self.assertIs(self.authority.signed_snapshot, signed)
        self.assertEqual(self.authority.cohort_ca_pem, ca_pem)
        self.assertEqual({name: (principal.record, principal.private_key_pem,
                                 principal.certificate_pem)
                          for name, principal in self.authority.principals.items()},
                         principal_records)


class OwnerDrainCommandPreparationTests(unittest.TestCase):
    """Drain commands are built and checked through the shared protocol parser."""

    @classmethod
    def setUpClass(cls):
        try:
            from lab.secure_cohort_owner import OwnerExpectation, PROFILE_C1B_OWNER_DRAIN
        except ImportError as error:
            raise unittest.SkipTest(f"owner protocol dependencies unavailable: {type(error).__name__}")
        cls.expected = OwnerExpectation(
            profile=PROFILE_C1B_OWNER_DRAIN, run_id="1" * 32, nonce="2" * 32,
            worker_boot_id="3" * 32, manifest_fingerprint="a" * 64,
            endpoint="127.0.0.1:50061", initial_snapshot_sha256="b" * 64,
            initial_revision=7)

    def test_two_distinct_commands_use_actual_drain_profile_and_inbox_validation(self):
        from lab.secure_cohort_owner import build_owner_action_request, validate_owner_action_request

        commands = cohort._prepare_owner_drain_commands(
            self.expected, command_ids=("4" * 32, "5" * 32))
        self.assertEqual([command["action"] for command in commands], ["drain", "drain"])
        self.assertEqual([command["drain_seconds"] for command in commands], [30, 300])
        self.assertEqual([command["sequence"] for command in commands], [1, 2])
        for number, command in enumerate(commands, 1):
            request = build_owner_action_request(self.expected, number, command)
            parsed = validate_owner_action_request(request, self.expected)
            self.assertEqual(parsed.sequence, number)
            self.assertEqual(parsed.command_id, command["command_id"])

    def test_duplicate_or_malformed_command_ids_fail_closed(self):
        for command_ids in (("4" * 32, "4" * 32), ("4" * 31 + "G", "5" * 32),
                            ("4" * 32,), ("4" * 32, 5)):
            with self.subTest(command_ids=command_ids), self.assertRaises(cohort.CohortError):
                cohort._prepare_owner_drain_commands(self.expected, command_ids=command_ids)

    def test_owner_actions_are_required_only_for_the_selected_owner_profile(self):
        with self.assertRaises(cohort.CohortError):
            cohort._private_result_summary(
                {"baseline": {"status": "passed"}},
                profile=cohort.PROFILE_C1B_OWNER_DRAIN)
        with self.assertRaises(cohort.CohortError):
            cohort._private_result_summary(
                {"baseline": {"status": "passed"},
                 "owner_actions": {"profile": cohort.PROFILE_C1B_OWNER_DRAIN}},
                profile=cohort.PROFILE_BASELINE)


class OwnerDrainAuthorityMarginTests(unittest.TestCase):
    """The 30-second drain margin comes from real C0 context and worker grants."""

    def test_genuine_probe_context_and_signed_worker_grants_cover_drain(self):
        try:
            from lab.secure_cohort_boot import build_trusted_probe_context
            from tests.security.secure_pipeline_fixture import SecurePipelineIdentityFixture
        except ImportError as error:
            self.skipTest(f"secure identity dependencies are unavailable: {type(error).__name__}")
        authority = SecurePipelineIdentityFixture("a" * 64)
        probe = None
        try:
            try:
                probe = build_trusted_probe_context(authority, timeout_seconds=120)
            except ModuleNotFoundError as error:
                if error.name in {"google", "grpc"}:
                    self.skipTest(f"runtime probe dependencies are unavailable: {error.name}")
                raise
            self.assertIsNone(cohort._require_owner_drain_authority_margin(probe, authority))
            with self.assertRaises(cohort.CohortError):
                cohort._require_owner_drain_authority_margin(
                    probe, authority, minimum_seconds=10_000)
        finally:
            if probe is not None:
                probe.close()
                self.assertEqual(cohort._trusted_probe_cleanup_state(probe), (True, True))
            authority.close()

    def test_qualified_signed_grants_include_every_actual_drain_method(self):
        from steamboat_security.codec import WORKER_SERVICE

        coordinator = SimpleNamespace(
            account_id="acct_coordinator", role="personal_coordinator",
            device_id="dev_coordinator", boot_id="boot-coordinator",
            record={"serial": "coord"})
        worker = SimpleNamespace(
            account_id="acct_worker", role="host",
            device_id="dev_worker", boot_id="boot-worker",
            assignment_id="asg_worker", record={"serial": "worker"})
        methods = ("Describe", "OpenSession", "Step", "RenewSession")
        grants = [SimpleNamespace(
            account_id="acct_coordinator", role="personal_coordinator",
            device_id="dev_coordinator", actor_boot_id="boot-coordinator",
            actor_serial="coord", tenant_account_id="acct_coordinator",
            target_account_id="acct_worker", target_role="host", target_serial="worker",
            target_device_id="dev_worker", target_boot_id="boot-worker",
            assignment_id="asg_worker", model_id="model",
            method=f"{WORKER_SERVICE}/{method}", identity=method) for method in methods]
        sample = SimpleNamespace(monotonic=10.0)
        view = SimpleNamespace(
            grants=grants, grant_deadlines={method: 200.0 for method in methods},
            deadline_monotonic=200.0,
            credential_deadlines={"coord": 200.0, "worker": 200.0})
        probe = SimpleNamespace(
            context=SimpleNamespace(remaining_seconds=lambda: 120.0),
            outbound_authorizer=SimpleNamespace(
                clock=SimpleNamespace(sample=lambda: sample)),
            snapshot_store=SimpleNamespace(current=lambda *, sample: view))
        authority = SimpleNamespace(
            principals={"coordinator": coordinator, "worker-3": worker},
            model_id="model")

        self.assertIsNone(cohort._require_owner_drain_authority_margin(probe, authority))
        grants[0].method = "Describe"
        with self.assertRaisesRegex(cohort.CohortError, "cover every actual"):
            cohort._require_owner_drain_authority_margin(probe, authority)
        grants[0].method = f"{WORKER_SERVICE}/Describe"
        grants[0].target_device_id = "dev_other"
        with self.assertRaisesRegex(cohort.CohortError, "cover every actual"):
            cohort._require_owner_drain_authority_margin(probe, authority)

    def test_original_open_lease_and_context_must_survive_remaining_drain(self):
        import asyncio

        from steamboat_security.codec import WORKER_SERVICE

        coordinator = SimpleNamespace(
            account_id="acct_coordinator", role="personal_coordinator",
            device_id="dev_coordinator", boot_id="boot-coordinator",
            record={"serial": "coord"})
        worker = SimpleNamespace(
            account_id="acct_worker", role="host",
            device_id="dev_worker", boot_id="boot-worker",
            assignment_id="asg_worker", record={"serial": "worker"})
        methods = ("Describe", "OpenSession", "Step", "RenewSession")
        grants = [SimpleNamespace(
            account_id="acct_coordinator", role="personal_coordinator",
            device_id="dev_coordinator", actor_boot_id="boot-coordinator",
            actor_serial="coord", tenant_account_id="acct_coordinator",
            target_account_id="acct_worker", target_role="host", target_serial="worker",
            target_device_id="dev_worker", target_boot_id="boot-worker",
            assignment_id="asg_worker", model_id="model",
            method=f"{WORKER_SERVICE}/{method}", identity=method) for method in methods]
        sample = SimpleNamespace(monotonic=10.0)
        view = SimpleNamespace(
            grants=grants, grant_deadlines={method: 200.0 for method in methods},
            deadline_monotonic=200.0,
            credential_deadlines={"coord": 200.0, "worker": 200.0})
        probe = SimpleNamespace(
            context=SimpleNamespace(remaining_seconds=lambda: 120.0),
            outbound_authorizer=SimpleNamespace(
                clock=SimpleNamespace(sample=lambda: sample)),
            snapshot_store=SimpleNamespace(current=lambda *, sample: view))
        authority = SimpleNamespace(
            principals={"coordinator": coordinator, "worker-3": worker},
            model_id="model")
        async def check():
            received = asyncio.get_running_loop().time()
            opened = SimpleNamespace(remaining_lifetime_ms=120_000,
                                     remaining_idle_ms=120_000)
            self.assertIsNone(cohort._require_owner_drain_authority_margin(
                probe, authority, minimum_seconds=35.0, opened=opened,
                opened_received_at=received))
            await asyncio.sleep(0.03)
            with self.assertRaisesRegex(cohort.CohortError, "Open lease"):
                cohort._require_owner_drain_authority_margin(
                    probe, authority, minimum_seconds=119.99, opened=opened,
                    opened_received_at=received)
            opened.remaining_idle_ms = 20_000
            with self.assertRaisesRegex(cohort.CohortError, "Open lease"):
                cohort._require_owner_drain_authority_margin(
                    probe, authority, minimum_seconds=35.0, opened=opened,
                    opened_received_at=received)
            opened.remaining_idle_ms = 120_000
            opened.remaining_lifetime_ms = 90_000
            with self.assertRaisesRegex(cohort.CohortError, "Open lease"):
                cohort._require_owner_drain_authority_margin(
                    probe, authority, minimum_seconds=35.0, opened=opened,
                    opened_received_at=received - 60.0)
            opened.remaining_lifetime_ms = 120_000
            probe.context.remaining_seconds = lambda: 20.0
            with self.assertRaisesRegex(cohort.CohortError, "Generate context"):
                cohort._require_owner_drain_authority_margin(
                    probe, authority, minimum_seconds=35.0, opened=opened,
                    opened_received_at=received)
            probe.context.remaining_seconds = lambda: 120.0
            view.grant_deadlines["Describe"] = 15.0
            with self.assertRaisesRegex(cohort.CohortError, "worker grant"):
                cohort._require_owner_drain_authority_margin(
                    probe, authority, minimum_seconds=35.0, opened=opened,
                    opened_received_at=received)
        asyncio.run(check())


class OwnerCleanupGateTests(unittest.TestCase):
    def test_post_close_predicate_failure_marks_unknown_and_retains_authority(self):
        probe = object()
        state = {}
        with mock.patch.object(
                cohort, "_trusted_probe_cleanup_state",
                side_effect=RuntimeError("context index unavailable")):
            with self.assertRaisesRegex(RuntimeError, "context index"):
                cohort._require_owner_probe_cleanup([probe], state)
        self.assertIs(state["direct_cleanup_unconfirmed"], True)
        self.assertTrue(cohort._owner_authority_retention_required(
            active=True, cleanup_errors=[], direct_cleanup_unconfirmed=True,
            may_have_started=True, remote_shutdown={"confirmed": True}))
        self.assertFalse(cohort._owner_authority_retention_required(
            active=True, cleanup_errors=[], direct_cleanup_unconfirmed=False,
            may_have_started=True, remote_shutdown={"confirmed": True}))

    def test_authority_retention_merges_complete_graph_after_probe_retention(self):
        previous = list(cohort._RETAINED_OWNER_OWNERS)
        authority, probe_graph, outer_graph = object(), object(), object()
        try:
            cohort._RETAINED_OWNER_OWNERS.clear()
            cohort._retain_owner_graph(authority, probe_graph)
            cohort._retain_owner_graph(authority, outer_graph, probe_graph)
            retained = cohort._RETAINED_OWNER_OWNERS[0]
            self.assertIs(retained[0], authority)
            self.assertTrue(any(item is probe_graph for item in retained))
            self.assertTrue(any(item is outer_graph for item in retained))
        finally:
            cohort._RETAINED_OWNER_OWNERS[:] = previous

    def test_drain_observation_uses_second_ack_but_remove_uses_first(self):
        commands = [{"worker_ack": {"sequence": 1}},
                    {"worker_ack": {"sequence": 2}}]
        for profile, expected_sequence in (
                (cohort.PROFILE_C1B_OWNER_DRAIN, 2),
                (cohort.PROFILE_C1B_OWNER_REMOVE, 1)):
            expectation = SimpleNamespace(profile=profile)
            observed = []
            with mock.patch.object(
                    cohort, "_validate_owner_status_frame",
                    side_effect=lambda status, owner_expected, worker_config,
                    command=None, observation=False: observed.append(command) or "ok"):
                self.assertEqual(cohort._validate_owner_observation_status(
                    {}, owner_expected=expectation, worker_config={}, sequence=6,
                    commands=commands), "ok")
            self.assertEqual(observed[0]["sequence"], expected_sequence)

    def test_ready_idle_gate_rejects_active_session_and_pending_work(self):
        status = {
            "handler": {"active_sessions": 0, "active_session_ids": [],
                        "queued_operations": 0, "committed_cache_bytes": 0,
                        "allocated_cache_bytes": 0, "active_compute": False},
            "bridge": {"active_authorizations": 0, "owned_sessions": 0,
                       "pending_notices": 0},
            "transport": {"reserved_pending": 0, "reserved_outbound_pending": 0,
                          "reserved_connections": 1,
                          "reserved_listener_pending_capacity": 1, "listener_slots": 1},
        }
        cohort._require_owner_global_idle(status)
        status["handler"]["active_sessions"] = 1
        with self.assertRaisesRegex(cohort.CohortError, "globally idle"):
            cohort._require_owner_global_idle(status)

    def test_baseline_observation_path_enforces_global_idle_after_shared_validation(self):
        status = {
            "handler": {"active_sessions": 0, "active_session_ids": [],
                        "queued_operations": 0, "committed_cache_bytes": 0,
                        "allocated_cache_bytes": 0, "active_compute": False},
            "bridge": {"active_authorizations": 0, "owned_sessions": 0,
                       "pending_notices": 0},
            "transport": {"reserved_pending": 0, "reserved_outbound_pending": 0,
                          "reserved_connections": 1,
                          "reserved_listener_pending_capacity": 1, "listener_slots": 1},
        }
        expectation = SimpleNamespace(profile=cohort.PROFILE_C1B_OWNER_DRAIN)
        with mock.patch.object(cohort, "_validate_owner_status_frame", return_value="valid"):
            self.assertEqual(cohort._validate_owner_observation_status(
                status, owner_expected=expectation, worker_config={}, sequence=1,
                commands=()), "valid")
            status["bridge"]["pending_notices"] = 1
            with self.assertRaisesRegex(cohort.CohortError, "globally idle"):
                cohort._validate_owner_observation_status(
                    status, owner_expected=expectation, worker_config={}, sequence=1,
                    commands=())


class OwnerProfileStopValidationTests(unittest.IsolatedAsyncioTestCase):
    """Not-started uses the frozen legacy envelope; started needs a validated ACK."""

    def setUp(self):
        from lab.secure_cohort_owner import OwnerExpectation, PROFILE_C1B_OWNER_DRAIN

        self.expected = cohort.RemoteExpectation(
            run_id="1" * 32, nonce="2" * 32, worker_name="worker-3",
            account_id="acct_" + "3" * 32, device_id="dev_" + "4" * 32,
            boot_id="5" * 32, assignment_id="asg_" + "6" * 32,
            model_id="model", model_revision="1", manifest_fingerprint="a" * 64,
            snapshot_sha256="b" * 64, endpoint="127.0.0.1:50061",
            clock_uncertainty_seconds=1.0, layer_range=(6, 8))
        self.owner_expected = OwnerExpectation(
            profile=PROFILE_C1B_OWNER_DRAIN, run_id=self.expected.run_id,
            nonce=self.expected.nonce, worker_boot_id=self.expected.boot_id,
            manifest_fingerprint=self.expected.manifest_fingerprint,
            endpoint=self.expected.endpoint,
            initial_snapshot_sha256=self.expected.snapshot_sha256,
            initial_revision=1)
        self.host_key = "c" * 64

    def _stop_ack(self, *, started):
        if not started:
            process_state, exit_code, uid, mode, label, status = (
                "not_started", None, None, None,
                "ssh_supervisor_not_started", None)
        else:
            process_state, exit_code, uid, mode, label, status = (
                "exited", 0, 1000, 0o600,
                cohort.STOP_LABEL, {"event": "final"})
        return {
            "schema_version": 1, "event": "stop_ack",
            "run_id": self.expected.run_id, "nonce": self.expected.nonce,
            "boot_id": self.expected.boot_id, "process_state": process_state,
            "exit_code": exit_code, "shutdown_confirmed": True,
            "ssh_host_key_sha256": self.host_key,
            "remote_status_uid": uid, "remote_status_mode": mode,
            "measurement_label": label, "remote_status": status,
        }

    async def test_exact_not_started_ack_uses_legacy_validator(self):
        from unittest.mock import AsyncMock, patch

        with patch.object(cohort, "_safe_write_handoff"), patch.object(
                cohort, "_wait_for_control", new=AsyncMock(return_value=self._stop_ack(started=False))):
            result = await cohort._stop_remote_owner(
                7, expected=self.expected, owner_expected=self.owner_expected,
                worker_config={}, host_key=self.host_key, last_command=None,
                readiness_observed=False)
        self.assertEqual(result, {"confirmed": True, "process_state": "not_started"})

    async def test_started_final_status_without_a_real_command_ack_fails_closed(self):
        from unittest.mock import AsyncMock, patch

        with patch.object(cohort, "_safe_write_handoff"), patch.object(
                cohort, "_wait_for_control", new=AsyncMock(return_value=self._stop_ack(started=True))):
            with self.assertRaisesRegex(cohort.CohortError, "no validated command ACK"):
                await cohort._stop_remote_owner(
                    7, expected=self.expected, owner_expected=self.owner_expected,
                    worker_config={}, host_key=self.host_key, last_command=None,
                    readiness_observed=True)


if __name__ == "__main__":
    unittest.main()
