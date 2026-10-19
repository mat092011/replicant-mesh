"""Closed result schema checks for opt-in C1b ordered interleave evidence."""
from __future__ import annotations

import copy
import ast
import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lab import secure_cohort_supervisor as supervisor


class OrderedInterleaveSupervisorSchemaTests(unittest.TestCase):
    def _result(self):
        requests = [f"req_{index:032x}" for index in range(1, 5)]
        sessions = [f"ses_{index:032x}" for index in range(1, 5)]
        return {
            "schema_version": 1, "event": "result", "run_id": "a" * 32,
            "baseline": {"status": "passed", "completed_requests": 4,
                         "captured_vectors": 27},
            "request_ids": requests, "session_ids": sessions,
            "numerical_errors": {"captured_vectors": 27,
                                 "max_absolute_error": 0.0,
                                 "values": [0.0] * 27,
                                 "atol": 1e-3, "rtol": 0.0},
            "cases": [
                {"case_id": case_id, "request_id": requests[index],
                 "session_id": sessions[index]}
                for index, case_id in enumerate((
                    "greedy-one-token", "forced-length-1",
                    "forced-length-128", "forced-length-1024"))
            ], "local_shutdown": {"confirmed": True},
            "remote_shutdown": {"confirmed": True},
            "pending_scope": [],
            "interleave": {
                "profile": supervisor.PROFILE_C1B_INTERLEAVE,
                "status": "passed", "completed_requests": 2,
                "prompt_lengths": [5, 11], "captured_vectors": 8,
                "comparison_errors": [0.0] * 8, "max_absolute_error": 0.0,
                "request_ids": [f"req_{index:032x}" for index in range(10, 12)],
                "session_ids": [f"ses_{index:032x}" for index in range(10, 12)],
                "step_trace": ["A0", "B0", "A1", "B1"],
                "causal_barrier_confirmed": True,
                "remote_owner_check_confirmed": True,
                "local_owner_check": {
                    "confirmed": True, "active_requests": 0,
                    "active_streams": 0, "active_generate_streams": 0,
                    "active_captures": 0, "capture_reserved_bytes": 0,
                    "worker_sessions": 0, "worker_active_compute": False,
                    "transport_reserved_connections": 15,
                    "transport_reserved_pending": 0,
                },
            },
        }

    def _cancel_result(self):
        result = self._result()
        result.pop("interleave")
        result["local_shutdown"] = {
            "confirmed": False, "failure_types": ["CohortError"],
            "restart_fenced_retained": True,
        }
        result["cancellation"] = {
            "profile": supervisor.PROFILE_C1B_CANCEL, "status": "passed",
            "request_id": "req_" + "c" * 32, "session_id": "ses_" + "d" * 32,
            "tokens_before_cancel": 1, "tokens_after_cancel": 1,
            "step_counts": [2, 1, 1], "stage_gate_after_cache_mutation": True,
            "remote_held_session_confirmed": True, "cancelled_error_observed": True,
            "compute_joined": True, "remote_reclaimed_confirmed": True,
            "supervisor_arm_monotonic_ns": 123456789,
            "local_state": {
                "state": "restart_fenced_retained", "logical_cleanup_confirmed": False,
                "coordinator_ready": False, "active_requests": 1,
                "model_cleanup_complete": None, "active_streams": 0,
                "active_generate_streams": 0, "active_captures": 0,
                "cleanup_pending_captures": 0, "capture_reserved_bytes": 0,
                "worker_sessions": 0, "worker_active_compute": False,
                "transport_reserved_connections": 15, "transport_reserved_pending": 0,
            },
        }
        return result


    def _partial_result(self):
        result = self._result()
        result.pop("interleave")
        result["local_shutdown"] = {
            "confirmed": False, "failure_types": ["CohortError"] * 3,
            "restart_fenced_retained": True,
            "retained_components": ["coordinator_close",
                                     "coordinator_service_streams",
                                     "secure_generate_streams"],
            "owner_counts": {
                "active_requests": 1, "active_streams": 1,
                "coordinator_cleanup_tasks": 0, "active_generate_streams": 1,
                "worker_sessions": 0, "worker_active_compute": False,
                "bridge_owned_sessions": 0, "bridge_active_authorizations": 0,
                "bridge_pending_notices": 0, "active_captures": 0,
                "cleanup_pending_captures": 0, "capture_reserved_bytes": 0,
                "transport_reserved_connections": 0,
                "transport_reserved_pending": 0,
                "transport_reserved_outbound_pending": 0,
                "transport_reserved_listener_pending": 0,
            },
        }
        result["partial_admission"] = {
            "profile": supervisor.PROFILE_C1B_PARTIAL, "status": "passed",
            "request_id": "req_" + "c" * 32, "session_id": "ses_" + "d" * 32,
            "open_attempts": [1, 1, 1], "open_reply_order": [0, 1, 2],
            "step_attempts": [0, 0, 0],
            "worker3_open_lifetime_ms": 10_000,
            "actual_tls_open_reply_validated": True,
            "caller_boundary_reply_loss": True,
            "remote_held_session_confirmed": True,
            "unknown_cleanup_preserved": True,
            "remote_lease_expiry_reclaimed": True,
            "supervisor_arm_monotonic_ns": 123456789,
            "local_state": {
                "state": "restart_fenced_retained", "logical_cleanup_confirmed": False,
                "coordinator_ready": False, "active_requests": 1,
                "unknown_open_indices": [2], "known_lease_indices": [],
                "active_streams": 0, "active_generate_streams": 0,
                "worker_sessions": 0, "worker_active_compute": False,
                "bridge_owned_sessions": 0, "bridge_active_authorizations": 0,
                "bridge_pending_notices": 0, "active_captures": 0,
                "cleanup_pending_captures": 0, "capture_reserved_bytes": 0,
                "transport_reserved_connections": 15,
                "transport_reserved_pending": 0,
            },
        }
        return result

    def _step_loss_result(self, *, fenced=False):
        result = self._result()
        result.pop("interleave")
        local_state = {
            "state": ("restart_fenced_retained" if fenced
                      else "resources_reclaimed_service_failed"),
            "logical_cleanup_confirmed": not fenced,
            "coordinator_ready": False,
            "active_requests": 1 if fenced else 0,
            "request_state_membership": "retained" if fenced else "absent",
            "known_leases_reclaimed": True,
            "active_streams": 0, "active_generate_streams": 0,
            "active_captures": 0, "capture_reserved_bytes": 0,
            "worker_sessions": 0, "worker_active_compute": False,
            "transport_reserved_connections": 15, "transport_reserved_pending": 0,
        }
        result["local_shutdown"] = ({
            "confirmed": False, "failure_types": ["CohortError"],
            "restart_fenced_retained": True,
        } if fenced else {"confirmed": True, "failure_types": []})
        result["step_reply_loss"] = {
            "profile": supervisor.PROFILE_C1B_STEP_LOSS, "status": "passed",
            "request_id": "req_" + "c" * 32, "session_id": "ses_" + "d" * 32,
            "open_attempts": [1, 1, 1], "step_attempts": [1, 1, 1],
            "cancel_attempts": [1, 1, 1], "step_reply_validated": True,
            "caller_boundary_reply_loss": True,
            "remote_held_session_confirmed": True,
            "remote_reclaimed_confirmed": True, "known_leases_reclaimed": True,
            "token_ids_emitted": [],
            "step_commit": {
                "sequence": 0, "start_position": 0, "token_count": 3,
                "end_position": 3, "next_sequence": 1,
                "hidden_size": 64, "tensor_shape": [1, 3, 64],
                "tensor_dtype": "float32_le", "tensor_layout": "batch_sequence_hidden",
                "response_tensor_bytes": 768, "response_tensor_envelope_bytes": 812,
                "committed_cache_bytes": 64, "allocated_cache_bytes": 64,
            },
            "supervisor_arm_monotonic_ns": 123456789,
            "local_state": local_state,
        }
        return result

    def _capacity_result(self):
        result = self._result()
        result.pop("interleave")
        request_ids = [f"req_{index:032x}" for index in range(20, 28)]
        session_ids = [f"ses_{index:032x}" for index in range(20, 28)]
        result["capacity"] = {
            "profile": supervisor.PROFILE_C1B_CAPACITY, "status": "passed",
            "completed_requests": 8, "captured_vectors": 8,
            "comparison_errors": [0.0] * 8, "max_absolute_error": 0.0,
            "request_ids": request_ids, "session_ids": session_ids,
            "token_ids": [123] * 8,
            "ninth_rejection": {
                "error_code": "CAPACITY_EXHAUSTED", "coordinator_submits": 0,
                "tensor_allocations": 0,
                "worker_open_attempts": [0, 0, 0],
                "worker_step_attempts": [0, 0, 0],
                "used_request_ids_unchanged": True,
            },
            "remote_held_confirmed": True, "remote_reclaimed_confirmed": True,
            "local_owner_check": {
                "confirmed": True, "active_requests": 0, "active_streams": 0,
                "active_generate_streams": 0, "active_captures": 0,
                "capture_reserved_bytes": 0, "worker_sessions": 0,
                "worker_active_compute": False,
                "transport_reserved_connections": 15,
                "transport_reserved_pending": 0,
            },
            "supervisor_arm_monotonic_ns": 123456789,
        }
        return result

    def test_interleave_result_is_projected_to_bounded_evidence(self):
        result = supervisor._sanitize_cohort_result(
            self._result(), supervisor.PROFILE_C1B_INTERLEAVE)
        self.assertEqual(result["interleave"]["step_trace"],
                         ["A0", "B0", "A1", "B1"])
        self.assertEqual(result["interleave"]["captured_vectors"], 8)
        self.assertTrue(result["interleave"]["causal_barrier_confirmed"])
        self.assertTrue(result["interleave"]["remote_owner_check_confirmed"])

    def test_interleave_result_rejects_wrong_trace_and_unbounded_or_unknown_data(self):
        result = self._result()
        result["interleave"]["step_trace"] = ["A0", "A1", "B0", "B1"]
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(
                result, supervisor.PROFILE_C1B_INTERLEAVE)

    def test_interleave_result_rejects_float_prompt_lengths_and_boolean_tolerance(self):
        result = self._result()
        result["interleave"]["prompt_lengths"] = [5.0, 11]
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(
                result, supervisor.PROFILE_C1B_INTERLEAVE)
        result = self._result()
        result["numerical_errors"]["rtol"] = False
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(
                result, supervisor.PROFILE_C1B_INTERLEAVE)
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(self._result(), supervisor.PROFILE_BASELINE)
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(self._result(), supervisor.PROFILE_C1B_HAPPY)

    def test_cancel_result_preserves_explicit_fence_and_rejects_missing_causal_proof(self):
        summary = supervisor._sanitize_cohort_result(
            self._cancel_result(), supervisor.PROFILE_C1B_CANCEL)
        self.assertEqual(summary["cancellation"]["local_state"]["state"],
                         "restart_fenced_retained")
        self.assertFalse(summary["cancellation"]["local_state"]["logical_cleanup_confirmed"])
        broken = self._cancel_result()
        broken["cancellation"]["step_counts"] = [2, 2, 1]
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(broken, supervisor.PROFILE_C1B_CANCEL)

    def test_partial_open_result_requires_real_reply_loss_and_retained_fence(self):
        summary = supervisor._sanitize_cohort_result(
            self._partial_result(), supervisor.PROFILE_C1B_PARTIAL)
        self.assertEqual(summary["partial_admission"]["local_state"]["state"],
                         "restart_fenced_retained")
        self.assertEqual(summary["partial_admission"]["local_state"]["unknown_open_indices"],
                         [2])
        self.assertFalse(summary["local_shutdown"]["confirmed"])
        self.assertEqual(summary["local_shutdown"]["failure_types"],
                         ["CohortError"] * 3)
        self.assertEqual(summary["local_shutdown"]["owner_counts"]["active_requests"], 1)
        for field, value in (("step_attempts", [0, 0, 1]),
                             ("open_attempts", [1, 0, 1]),
                             ("open_reply_order", [0, 2, 1]),
                             ("caller_boundary_reply_loss", False),
                             ("unknown_cleanup_preserved", False),
                             ("worker3_open_lifetime_ms", 10_001)):
            broken = self._partial_result()
            broken["partial_admission"][field] = value
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._sanitize_cohort_result(
                    broken, supervisor.PROFILE_C1B_PARTIAL)
        broken = self._partial_result()
        broken["partial_admission"]["local_state"]["unknown_open_indices"] = []
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(
                broken, supervisor.PROFILE_C1B_PARTIAL)
        broken = self._partial_result()
        broken["partial_admission"]["local_state"]["unknown_open_indices"] = [2.0]
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(
                broken, supervisor.PROFILE_C1B_PARTIAL)
        for mutate in (
                lambda shutdown: shutdown["owner_counts"].__setitem__("worker_sessions", 1),
                lambda shutdown: shutdown["retained_components"].append("other"),
                lambda shutdown: shutdown["owner_counts"].__setitem__("active_requests", True),
                lambda shutdown: shutdown["owner_counts"].__setitem__("active_streams", 0),
                lambda shutdown: shutdown.__setitem__("unapproved", 1),
                lambda shutdown: shutdown["failure_types"].append("ValueError"),
        ):
            broken = self._partial_result()
            mutate(broken["local_shutdown"])
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._sanitize_cohort_result(
                    broken, supervisor.PROFILE_C1B_PARTIAL)

    def test_partial_profile_observations_are_exact_and_session_bound(self):
        self.assertEqual(supervisor._profile_observation_cases(
            supervisor.PROFILE_C1B_PARTIAL), {
                1: "greedy-one-token", 2: "forced-length-1",
                3: "forced-length-128", 4: "forced-length-1024",
                5: "partial-open-reply-held", 6: "partial-open-lease-expired",
            })

    def test_step_reply_loss_result_preserves_real_commit_and_cleanup_evidence(self):
        summary = supervisor._sanitize_cohort_result(
            self._step_loss_result(), supervisor.PROFILE_C1B_STEP_LOSS)
        self.assertEqual(summary["step_reply_loss"]["step_commit"]["token_count"], 3)
        self.assertEqual(summary["step_reply_loss"]["local_state"]["state"],
                         "resources_reclaimed_service_failed")
        fenced = supervisor._sanitize_cohort_result(
            self._step_loss_result(fenced=True), supervisor.PROFILE_C1B_STEP_LOSS)
        self.assertFalse(
            fenced["step_reply_loss"]["local_state"]["logical_cleanup_confirmed"])
        for field, invalid in (("step_attempts", [1, 1, 2]),
                               ("cancel_attempts", [1, 0, 1]),
                               ("token_ids_emitted", [12]),
                               ("caller_boundary_reply_loss", False),
                               ("known_leases_reclaimed", False)):
            broken = self._step_loss_result()
            broken["step_reply_loss"][field] = invalid
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._sanitize_cohort_result(
                    broken, supervisor.PROFILE_C1B_STEP_LOSS)
        for field, invalid in (("coordinator_ready", True),
                               ("request_state_membership", "retained")):
            broken = self._step_loss_result()
            broken["step_reply_loss"]["local_state"][field] = invalid
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._sanitize_cohort_result(
                    broken, supervisor.PROFILE_C1B_STEP_LOSS)
        for field, invalid in (("token_count", 4),
                               ("tensor_shape", [1.0, 3, 64]),
                               ("response_tensor_envelope_bytes", 700),
                               ("committed_cache_bytes", 0)):
            broken = self._step_loss_result()
            broken["step_reply_loss"]["step_commit"][field] = invalid
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._sanitize_cohort_result(
                    broken, supervisor.PROFILE_C1B_STEP_LOSS)

    def test_capacity_profile_has_two_fixed_eight_session_observation_steps(self):
        self.assertEqual(supervisor._profile_observation_cases(
            supervisor.PROFILE_C1B_CAPACITY), {
                1: "greedy-one-token", 2: "forced-length-1",
                3: "forced-length-128", 4: "forced-length-1024",
                5: "capacity-eight-held", 6: "capacity-eight-reclaimed",
            })
    def test_step_reply_loss_has_fixed_held_and_reclaimed_observation_cases(self):
        self.assertEqual(supervisor._profile_observation_cases(
            supervisor.PROFILE_C1B_STEP_LOSS), {
                1: "greedy-one-token", 2: "forced-length-1",
                3: "forced-length-128", 4: "forced-length-1024",
                5: "step-reply-loss-held", 6: "step-reply-loss-reclaimed",
            })

    def test_capacity_result_requires_eight_captures_and_pre_submit_ninth_refusal(self):
        summary = supervisor._sanitize_cohort_result(
            self._capacity_result(), supervisor.PROFILE_C1B_CAPACITY)
        self.assertEqual(summary["capacity"]["completed_requests"], 8)
        self.assertEqual(summary["capacity"]["ninth_rejection"]["error_code"],
                         "CAPACITY_EXHAUSTED")
        for field, value in (("completed_requests", 7),
                             ("captured_vectors", 7),
                             ("request_ids", ["req_" + "a" * 32] * 8),
                             ("session_ids", ["ses_" + "a" * 32] * 8)):
            broken = self._capacity_result()
            broken["capacity"][field] = value
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._sanitize_cohort_result(
                    broken, supervisor.PROFILE_C1B_CAPACITY)

    def test_capacity_extension_is_rejected_by_every_other_profile(self):
        baseline = self._result()
        baseline.pop("interleave")
        cases = [
            (baseline, supervisor.PROFILE_BASELINE),
            (copy.deepcopy(baseline), supervisor.PROFILE_C1B_HAPPY),
            (self._result(), supervisor.PROFILE_C1B_INTERLEAVE),
            (self._cancel_result(), supervisor.PROFILE_C1B_CANCEL),
            (self._partial_result(), supervisor.PROFILE_C1B_PARTIAL),
            (self._step_loss_result(), supervisor.PROFILE_C1B_STEP_LOSS),
        ]
        for result, profile in cases:
            with self.subTest(profile=profile):
                result["capacity"] = {}
                with self.assertRaisesRegex(supervisor.SupervisorError,
                                            "cohort_result:profile_mismatch"):
                    supervisor._sanitize_cohort_result(result, profile)
        for field, value in (("coordinator_submits", 1),
                             ("tensor_allocations", 1),
                             ("worker_open_attempts", [0, 0, 1]),
                             ("used_request_ids_unchanged", False)):
            broken = self._capacity_result()
            broken["capacity"]["ninth_rejection"][field] = value
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._sanitize_cohort_result(
                    broken, supervisor.PROFILE_C1B_CAPACITY)

    def test_restart_extension_is_rejected_by_every_prior_profile(self):
        result = {
            "schema_version": 1, "event": "result", "run_id": "a" * 32,
            "baseline": {"status": "failed"}, "request_ids": [],
            "session_ids": [], "restart": {},
        }
        profiles = (
            supervisor.PROFILE_BASELINE, supervisor.PROFILE_C1B_HAPPY,
            supervisor.PROFILE_C1B_INTERLEAVE, supervisor.PROFILE_C1B_CANCEL,
            supervisor.PROFILE_C1B_PARTIAL, supervisor.PROFILE_C1B_STEP_LOSS,
            supervisor.PROFILE_C1B_CAPACITY,
        )
        for profile in profiles:
            with self.subTest(profile=profile):
                with self.assertRaisesRegex(
                        supervisor.SupervisorError,
                        "cohort_result:profile_mismatch"):
                    supervisor._sanitize_cohort_result(result, profile)

    def test_cancel_result_accepts_request_reclamation_before_model_teardown(self):
        result = self._cancel_result()
        local = result["cancellation"]["local_state"]
        local.update({"state": "fully_reclaimed", "logical_cleanup_confirmed": True,
                      "coordinator_ready": True, "active_requests": 0,
                      "model_cleanup_complete": None})
        result["local_shutdown"] = {"confirmed": True}
        summary = supervisor._sanitize_cohort_result(
            result, supervisor.PROFILE_C1B_CANCEL)
        self.assertIsNone(summary["cancellation"]["local_state"]["model_cleanup_complete"])
        for pending in (None, 1):
            broken = self._cancel_result()
            broken["cancellation"]["local_state"]["cleanup_pending_captures"] = pending
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._sanitize_cohort_result(
                    broken, supervisor.PROFILE_C1B_CANCEL)
        broken = self._cancel_result()
        del broken["cancellation"]["local_state"]["cleanup_pending_captures"]
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(
                broken, supervisor.PROFILE_C1B_CANCEL)
        for invalid in (1, False):
            broken = self._cancel_result()
            broken["cancellation"]["local_state"].update({
                "state": "fully_reclaimed", "logical_cleanup_confirmed": True,
                "coordinator_ready": True, "active_requests": 0,
                "model_cleanup_complete": invalid,
            })
            broken["local_shutdown"] = {"confirmed": True}
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._sanitize_cohort_result(
                    broken, supervisor.PROFILE_C1B_CANCEL)

    def test_cancel_schema_rejects_float_counters_and_interleave_mix(self):
        for field, value in (("completed_requests", 4.0),
                             ("captured_vectors", 27.0)):
            broken = self._cancel_result()
            broken["baseline"][field] = value
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._sanitize_cohort_result(
                    broken, supervisor.PROFILE_C1B_CANCEL)
        broken = self._cancel_result()
        broken["interleave"] = {}
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(
                broken, supervisor.PROFILE_C1B_CANCEL)

    def test_cancel_disposal_requires_zero_exit_within_arm_deadline(self):
        local = {"process_state": "exited", "exit_code": 0,
                 "ownership_verified": True, "cleanup_confirmed": True,
                 "graceful_stop": True}
        arm = 10_000_000_000
        self.assertTrue(supervisor._cancellation_disposal_valid(
            local, arm, arm + 40_000_000_000))
        self.assertFalse(supervisor._cancellation_disposal_valid(
            local, arm, arm + 40_000_000_001))
        self.assertFalse(supervisor._cancellation_disposal_valid(
            {"process_state": "exited", "exit_code": 1}, arm,
            arm + 1_000_000_000))
        self.assertTrue(supervisor._owner_disposal_valid(
            local, arm, arm + 39_999_999_999))
        self.assertFalse(supervisor._owner_disposal_valid(
            {"process_state": "unknown", "exit_code": None}, arm,
            arm + 1_000_000_000))
        self.assertFalse(supervisor._owner_disposal_valid(
            {**local, "cleanup_confirmed": False}, arm, arm + 1_000_000_000))
        self.assertFalse(supervisor._owner_disposal_valid(
            local, arm, arm + 40_000_000_001))

    def test_remote_status_requires_exact_held_session_identity(self):
        config = {
            "account_id": "acct_" + "a" * 32, "device_id": "dev_" + "b" * 32,
            "boot_id": "c" * 32, "assignment_id": "asg_" + "d" * 32,
            "manifest_fingerprint": "e" * 64, "listen_ip": "10.1.2.3",
            "listen_port": 50061, "clock_uncertainty_seconds": 2.0,
        }
        session_id = "ses_" + "f" * 32
        status = {
            "schema_version": 1, "event": "heartbeat", "phase": "ready",
            "worker_name": "worker-3", "account_id": config["account_id"],
            "device_id": config["device_id"], "boot_id": config["boot_id"],
            "assignment_id": config["assignment_id"],
            "manifest_fingerprint": config["manifest_fingerprint"],
            "clock_uncertainty_seconds": config["clock_uncertainty_seconds"],
            "model_id": supervisor.MODEL_ID,
            "model_revision": supervisor.MODEL_REVISION,
            "listen_endpoint": "10.1.2.3:50061", "layer_range": [6, 8],
            "torch_threads": 2, "resource_state": "observed", "report_state": "confirmed",
            "handler": {
                "state": "observed", "active_sessions": 1,
                "active_session_ids": [session_id], "tombstones": 0,
                "retained_entries": 1, "queued_operations": 0,
                "active_compute": False, "cache_bytes_exact": True,
                "requires_restart": False, "stopping": False,
                "limits": {
                    "max_sessions": 8, "max_tombstones": 16, "max_stage_queue": 8,
                    "max_positions": 1152, "max_cache_positions": 12_288,
                    "max_cache_bytes": 16_777_216, "max_message_bytes": 1_048_576,
                }, "committed_cache_bytes": 128,
                "committed_cache_bytes_lower_bound": None, "allocated_cache_bytes": 256,
            },
            "bridge": {"state": "observed", "ready": True, "cleanup_confirmed": True,
                       "unavailable": False, "requires_restart": False,
                       "fault_present": False, "active_authorizations": 0,
                       "owned_sessions": 1, "pending_notices": 0},
            "transport": {"listener_slots": 1, "max_connections": 16, "max_pending": 4,
                          "reserved_connections": 1, "reserved_pending": 0,
                          "reserved_listener_pending_capacity": 1,
                          "reserved_outbound_pending": 0, "server_state": "running"},
            "external_supervision": {"startup_watchdog_seconds": 60,
                                      "termination_watchdog_seconds": 15,
                                      "resource_caps": "configured_by_external_supervisor",
                                      "verified_by_worker": False},
            "shutdown": {"state": "not_started"},
        }
        # The cohort validator independently checks fixed limit values.
        supervisor._validate_status(status, config, event="heartbeat",
                                    expected_session_id=session_id)
        status["handler"]["committed_cache_bytes"] = 0
        status["handler"]["allocated_cache_bytes"] = 0
        supervisor._validate_status(
            status, config, event="heartbeat", expected_session_id=session_id,
            expected_open_only=True)

        held = copy.deepcopy(status)
        capacity = copy.deepcopy(held)
        capacity_ids = sorted([session_id]
                              + [f"ses_{index:032x}" for index in range(1, 8)])
        capacity["handler"].update(active_sessions=8, active_session_ids=capacity_ids)
        capacity["bridge"]["owned_sessions"] = 8
        supervisor._validate_status(
            capacity, config, event="heartbeat", expected_session_id=session_id,
            expected_session_count=8)
        for invalid in (capacity_ids[:-1], list(reversed(capacity_ids))):
            broken_capacity = copy.deepcopy(capacity)
            broken_capacity["handler"]["active_session_ids"] = invalid
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._validate_status(
                    broken_capacity, config, event="heartbeat",
                    expected_session_id=session_id, expected_session_count=8)
        idle = copy.deepcopy(status)
        idle["handler"].update(active_sessions=0, active_session_ids=[], retained_entries=0)
        idle["bridge"]["owned_sessions"] = 0
        frames = iter(({"status": held}, {"status": idle}))
        with patch.object(supervisor, "_read_remote_status",
                          side_effect=lambda *args, **kwargs: next(frames)), \
                patch.object(supervisor.time, "monotonic", return_value=0.0), \
                patch.object(supervisor.time, "sleep"):
            found = supervisor._wait_remote_status(
                None, config=config, password=None, status_path="status",
                mark_ns=1, deadline=10.0, expected_events={"heartbeat"},
                partial_expiry_session_id=session_id)
        self.assertEqual(found["status"]["handler"]["active_session_ids"], [])

        for changed in ("session", "boot"):
            invalid = copy.deepcopy(held)
            if changed == "session":
                invalid["handler"]["active_session_ids"] = ["ses_" + "0" * 32]
            else:
                invalid["boot_id"] = "1" * 32
            with patch.object(supervisor, "_read_remote_status",
                              return_value={"status": invalid}), \
                    patch.object(supervisor.time, "monotonic", return_value=0.0):
                with self.assertRaises(supervisor.SupervisorError):
                    supervisor._wait_remote_status(
                        None, config=config, password=None, status_path="status",
                        mark_ns=1, deadline=10.0, expected_events={"heartbeat"},
                        partial_expiry_session_id=session_id)

        with patch.object(supervisor, "_read_remote_status",
                          return_value={"status": held}), \
                patch.object(supervisor.time, "monotonic",
                             side_effect=(0.0, 0.0, 0.2, 0.4, 0.6)), \
                patch.object(supervisor.time, "sleep"):
            with self.assertRaisesRegex(supervisor.SupervisorError,
                                        "fresh_status_timeout"):
                supervisor._wait_remote_status(
                    None, config=config, password=None, status_path="status",
                    mark_ns=1, deadline=0.5, expected_events={"heartbeat"},
                    partial_expiry_session_id=session_id)

        status["handler"]["committed_cache_bytes"] = 128
        status["handler"]["allocated_cache_bytes"] = 256
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._validate_status(
                status, config, event="heartbeat", expected_session_id=session_id,
                expected_open_only=True)
        status["handler"]["active_session_ids"] = ["ses_" + "0" * 32]
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._validate_status(status, config, event="heartbeat",
                                        expected_session_id=session_id)
        broken = self._cancel_result()
        broken["cancellation"]["local_state"]["logical_cleanup_confirmed"] = True
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(broken, supervisor.PROFILE_C1B_CANCEL)
        result = self._result()
        result["interleave"]["extra"] = "not allowed"
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(
                result, supervisor.PROFILE_C1B_INTERLEAVE)
        result = self._result()
        result["interleave"]["comparison_errors"] = [0.0] * 9
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._sanitize_cohort_result(
                result, supervisor.PROFILE_C1B_INTERLEAVE)


class RestartSupervisorControlTests(unittest.TestCase):
    def setUp(self):
        self.ready = {
            "schema_version": 1, "event": "bundle_ready",
            "run_id": "1" * 32, "nonce": "2" * 32,
            "bundle_path": "/tmp/handoff/c1b/worker-3-bundle",
            "expected_boot_id": "3" * 32,
            "manifest_fingerprint": "4" * 64,
            "snapshot_sha256": "5" * 64,
            "endpoint": "10.1.2.3:50061", "worker_name": "worker-3",
        }

    def _restart_result(self):
        old_ready = self.ready
        new_ready = dict(self.ready, nonce="8" * 32,
                         expected_boot_id="9" * 32, snapshot_sha256="a" * 64)
        old_workers = {f"worker-{i}": f"{i + 3:x}" * 32 for i in range(1, 4)}
        old_workers["worker-3"] = old_ready["expected_boot_id"]
        new_workers = {"worker-1": "e" * 32, "worker-2": "f" * 32,
                       "worker-3": "9" * 32}
        new_workers["worker-3"] = new_ready["expected_boot_id"]
        old_ids = {
            "run_id": old_ready["run_id"], "coordinator_boot_id": "b" * 32,
            "consumer_boot_id": "c" * 32, "worker_boot_ids": old_workers,
            "manifest_fingerprint": old_ready["manifest_fingerprint"],
        }
        new_ids = {
            "run_id": old_ready["run_id"], "coordinator_boot_id": "d" * 32,
            "consumer_boot_id": old_ids["consumer_boot_id"], "worker_boot_ids": new_workers,
            "manifest_fingerprint": old_ready["manifest_fingerprint"],
        }

        def baseline(prefix, offset, identities):
            requests = [f"req_{i:032x}" for i in range(offset, offset + 4)]
            sessions = [f"ses_{i:032x}" for i in range(offset, offset + 4)]
            names = ("greedy-one-token", "forced-length-1",
                     "forced-length-128", "forced-length-1024")
            return {
                "baseline": {"status": "passed", "completed_requests": 4,
                             "captured_vectors": 27},
                "request_ids": requests, "session_ids": sessions,
                "numerical_errors": {"captured_vectors": 27,
                                     "max_absolute_error": 0.0,
                                     "values": [0.0] * 27, "atol": 1e-3,
                                     "rtol": 0.0},
                "cases": [{"case_id": prefix + name, "request_id": requests[i],
                           "session_id": sessions[i]}
                          for i, name in enumerate(names)],
                "identities": identities,
            }

        old = baseline("", 1, old_ids)
        probe_request, probe_session = "req_" + "9" * 32, "ses_" + "9" * 32
        new = baseline("restart-new-", 10, new_ids)
        direct = {
            "request_id": probe_request, "session_id": probe_session,
            "route_id": "route_" + "a" * 32, "route_epoch": 1, "attempt": 1,
            "open_response": {"session_id": probe_session,
                              "worker_boot_id": old_ready["expected_boot_id"], "code": "OK"},
            "step_response": {"sequence": 0, "start_position": 0, "token_count": 3,
                              "end_position": 3, "next_sequence": 1,
                              "tensor_shape": [1, 3, 64], "dtype": "float32_le",
                              "byte_count": 768, "finite": True},
            "held_status": {
                "worker_boot_id": old_ready["expected_boot_id"],
                "active_sessions": 1, "active_session_ids": [probe_session],
                "queued_operations": 0, "active_compute": False,
                "cache_bytes_exact": True, "committed_cache_bytes": 128,
                "allocated_cache_bytes": 256, "active_authorizations": 0,
                "owned_sessions": 1, "transport_reserved_connections": 1,
            },
            "bindings": [{"method": method, "operation_id": f"op_{i:032x}",
                          "request_id": probe_request, "session_id": probe_session,
                          "route_id": "route_" + "a" * 32, "route_epoch": 1,
                          "attempt": 1, "worker_boot_id": old_ready["expected_boot_id"]}
                         for i, method in enumerate(
                             ("OpenSession", "Step", "SessionStatus", "CancelSession"), 1)],
            "new_target_before": {
                "worker_boot_id": new_ready["expected_boot_id"], "ready": True,
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
                         "worker_boot_id": new_ready["expected_boot_id"], "ready": True,
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
                     "worker_boot_id": new_ready["expected_boot_id"],
                     "assignment_id": "asg_" + "a" * 32,
                     "target_device_id": "dev_" + "b" * 32}
                    for index, method in enumerate(("SessionStatus", "CancelSession"), 9)
                ],
                "accounted_client_counts": [1, 2, 1, 0, 1, 0, 1, 0],
                "max_accounted_clients": 2,
            },
        }
        result = dict(old)
        result.update({
            "schema_version": 1, "event": "result", "run_id": old_ready["run_id"],
            "local_shutdown": {"confirmed": True, "failure_types": []},
            "remote_shutdown": {"confirmed": True},
            "pending_scope": [],
            "restart": {
                "profile": supervisor.PROFILE_C1B_RESTART, "status": "passed",
                "scope": "remote_worker_between_rpcs",
                "old_boot_id": old_ready["expected_boot_id"],
                "new_boot_id": new_ready["expected_boot_id"],
                "old_snapshot_sha256": old_ready["snapshot_sha256"],
                "new_snapshot_sha256": new_ready["snapshot_sha256"],
                "old_owner_receipt_sha256": "f" * 64,
                "old_local_shutdown": {"confirmed": True, "failure_types": []},
                "direct_probe": direct,
                "stale_binding_rejections": [
                    {"method": "SessionStatus", "code": "UNAUTHENTICATED"},
                    {"method": "CancelSession", "code": "UNAUTHENTICATED"}],
                "new_baseline": {key: new[key] for key in (
                    "baseline", "request_ids", "session_ids", "numerical_errors",
                    "cases", "identities")},
                "probe_cleanup": {
                    "confirmed": True, "transport_reserved_connections": 0,
                    "transport_reserved_pending": 0,
                    "transport_reserved_outbound_pending": 0,
                    "authorization_closed": True, "context_released": True,
                    "client_closed": True,
                },
                "same_leaf_continuity": {key: True for key in (
                    "same_ca", "same_snapshot_signer_public_key",
                    "same_worker_leaf_certificate", "same_worker_private_key",
                    "same_device_id", "same_assignment_id", "same_credential_epoch")},
            },
        })
        requests = {5: {"request_id": probe_request, "session_id": probe_session},
                    6: {"request_id": probe_request, "session_id": probe_session}}
        for sequence, (request, session) in enumerate(zip(new["request_ids"],
                                                           new["session_ids"]), 7):
            requests[sequence] = {"request_id": request, "session_id": session}
        actual_status = {
            "handler": {"active_sessions": 1, "active_session_ids": [probe_session],
                        "queued_operations": 0, "active_compute": False,
                        "cache_bytes_exact": True, "committed_cache_bytes": 128,
                        "allocated_cache_bytes": 256},
            "bridge": {"active_authorizations": 0, "owned_sessions": 1},
            "transport": {"reserved_connections": 1},
        }
        return result, old_ready, new_ready, actual_status, requests

    def test_restart_has_exact_ten_observation_order_and_bounded_control_names(self):
        self.assertEqual(supervisor._profile_observation_cases(
            supervisor.PROFILE_C1B_RESTART), {
                1: "greedy-one-token", 2: "forced-length-1",
                3: "forced-length-128", 4: "forced-length-1024",
                5: "restart-old-session-held",
                6: "restart-new-boot-stale-binding-rejected",
                7: "restart-new-greedy-one-token",
                8: "restart-new-forced-length-1",
                9: "restart-new-forced-length-128",
                10: "restart-new-forced-length-1024",
            })
        for name in ("restart-stop-request.json", "restart-bundle-ready.json"):
            self.assertIn(name, supervisor._CONTROL_REQUESTS)
        for name in ("restart-stop-response.json", "restart-ready-ack.json"):
            self.assertIn(name, supervisor._CONTROL_RESPONSES)
        self.assertNotIn("arbitrary-command.json", supervisor._CONTROL_REQUESTS)
        self.assertNotIn("arbitrary-command.json", supervisor._CONTROL_RESPONSES)
        for script in (supervisor._LOCAL_READ_SCRIPT, supervisor._LOCAL_WRITE_SCRIPT):
            self.assertIn('range(1,11)', script)
        self.assertIn('"restart-stop-request.json"', supervisor._LOCAL_READ_SCRIPT)
        self.assertIn('"restart-ready-ack.json"', supervisor._LOCAL_WRITE_SCRIPT)

    def test_restart_stop_request_is_closed_and_bound_to_old_ready(self):
        request = {
            "schema_version": 1, "event": "restart_stop_request",
            "run_id": self.ready["run_id"], "old_nonce": self.ready["nonce"],
            "old_boot_id": self.ready["expected_boot_id"],
            "manifest_fingerprint": self.ready["manifest_fingerprint"],
            "endpoint": self.ready["endpoint"],
        }
        self.assertIs(supervisor._validate_restart_stop_request(
            request, self.ready), request)
        for mutate in (
                lambda item: item.update(old_boot_id="6" * 32),
                lambda item: item.update(schema_version=True),
                lambda item: item.update(unexpected="field"),
                lambda item: item.update(endpoint="10.1.2.4:50061")):
            broken = copy.deepcopy(request)
            mutate(broken)
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._validate_restart_stop_request(broken, self.ready)

    def test_restart_owner_receipt_requires_real_complete_exit_evidence(self):
        state = {
            "container_id": "a" * 64, "exit_code": 0,
            "process_state": "exited", "ownership_status": "verified",
            "shutdown_confirmed": True, "container_removed": True,
            "private_files_removed": True, "job_root_removed": True,
            "failure_type": None,
        }
        receipt, digest = supervisor._restart_stop_receipt(
            ready=self.ready, host_key="6" * 64, remote_state=state,
            image="sha256:" + "7" * 64, arm_ns=10_000_000_000,
            exit_ns=10_000_000_001)
        self.assertEqual(len(digest), 64)
        self.assertEqual(receipt["old_owner"]["elapsed_ns"], 1)
        for field, invalid in (("exit_code", 1), ("shutdown_confirmed", False),
                               ("container_removed", False),
                               ("private_files_removed", False),
                               ("job_root_removed", False)):
            broken = dict(state)
            broken[field] = invalid
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._restart_stop_receipt(
                    ready=self.ready, host_key="6" * 64,
                    remote_state=broken, image="sha256:" + "7" * 64,
                    arm_ns=10_000_000_000, exit_ns=10_000_000_001)

    def test_restart_worker_config_may_change_only_boot_id(self):
        config = {
            "schema_version": 1, "protected_root": "/run/steamboat",
            "account_id": "acct_" + "a" * 32, "device_id": "dev_" + "b" * 32,
            "boot_id": "c" * 32, "assignment_id": "asg_" + "d" * 32,
            "worker_name": "worker-3", "model_id": supervisor.MODEL_ID,
            "model_revision": supervisor.MODEL_REVISION,
            "manifest_fingerprint": "e" * 64, "listen_ip": "10.1.2.3",
            "listen_port": 50061, "clock_uncertainty_seconds": 1.0,
            "certificate_path": "/run/steamboat/host.crt",
            "private_key_path": "/run/steamboat/host.key",
            "cohort_ca_path": "/run/steamboat/cohort-ca.crt",
            "snapshot_verification_key_path": "/run/steamboat/snapshot.pub",
            "signed_snapshot_path": "/run/steamboat/snapshot.json",
            "artifact_directory": "/artifacts", "acceptor_directory": "/run/steamboat/sockets",
            "status_report_path": "/run/steamboat/status.json",
        }
        fresh = dict(config, boot_id="f" * 32)
        supervisor._validate_restart_config_continuity(config, fresh)
        for field in ("assignment_id", "listen_ip", "manifest_fingerprint", "model_revision"):
            broken = dict(fresh)
            broken[field] = "changed"
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._validate_restart_config_continuity(config, broken)

    def test_restart_observation_sequence_is_bound_to_generation_nonce_and_boot(self):
        old_request = {
            "schema_version": 1, "event": "observe",
            "run_id": self.ready["run_id"], "nonce": self.ready["nonce"],
            "expected_boot_id": self.ready["expected_boot_id"],
            "sequence": 5, "case_id": "restart-old-session-held",
            "request_id": "req_" + "a" * 32, "session_id": "ses_" + "b" * 32,
        }
        self.assertIs(supervisor._validate_observation(
            old_request, self.ready, 5, supervisor.PROFILE_C1B_RESTART), old_request)
        new_ready = dict(self.ready, nonce="8" * 32,
                         expected_boot_id="9" * 32,
                         snapshot_sha256="c" * 64)
        new_request = dict(old_request, nonce=new_ready["nonce"],
                           expected_boot_id=new_ready["expected_boot_id"],
                           sequence=6,
                           case_id="restart-new-boot-stale-binding-rejected")
        self.assertIs(supervisor._validate_observation(
            new_request, new_ready, 6, supervisor.PROFILE_C1B_RESTART), new_request)
        for field in ("nonce", "expected_boot_id"):
            broken = dict(new_request)
            broken[field] = self.ready[field if field == "nonce" else "expected_boot_id"]
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._validate_observation(
                    broken, new_ready, 6, supervisor.PROFILE_C1B_RESTART)

    def test_restart_result_projection_binds_both_baselines_and_owner_receipt(self):
        result, old_ready, new_ready, status, requests = self._restart_result()
        summary = supervisor._sanitize_restart_cohort_result(
            result, old_ready=old_ready, new_ready=new_ready,
            new_assignment_id="asg_" + "a" * 32,
            new_device_id="dev_" + "b" * 32,
            old_held_status=status, observed_requests=requests,
            old_receipt_digest="f" * 64)
        self.assertEqual(summary["restart"]["status"], "passed")
        self.assertEqual(summary["restart"]["new_baseline"]["baseline"],
                         {"status": "passed", "completed_requests": 4,
                          "captured_vectors": 27, "max_absolute_error": 0.0})
        for edit in (
                lambda x: x["restart"].update(old_owner_receipt_sha256="e" * 64),
                lambda x: x["restart"]["direct_probe"]["step_response"].update(byte_count=0),
                lambda x: x["restart"]["stale_binding_rejections"].reverse(),
                lambda x: x["restart"]["new_baseline"]["identities"]["worker_boot_ids"].update({"worker-3": old_ready["expected_boot_id"]}),
                lambda x: x["restart"]["probe_cleanup"].update(client_closed=False),
                lambda x: x["restart"]["direct_probe"]["client_replacement"][
                    "stale_clients"][1].update(method="SessionStatus"),
                lambda x: x["restart"]["direct_probe"]["client_replacement"][
                    "stale_clients"][0]["close"].update(close_calls=2),
                lambda x: x["restart"]["direct_probe"]["client_replacement"][
                    "initial_new_close"].update(close_calls=True),
                lambda x: x["restart"]["direct_probe"]["client_replacement"][
                    "stale_clients"][0]["new_target_preface"].update(active_sessions=True),
                lambda x: x["restart"]["direct_probe"]["client_replacement"].update(
                    connection_mode="invalid_first_rpc"),
                lambda x: x["restart"]["direct_probe"]["client_replacement"][
                    "preface_bindings"][0].update(
                        operation_id=x["restart"]["direct_probe"]["bindings"][1][
                            "operation_id"]),
                lambda x: x["restart"]["direct_probe"]["client_replacement"][
                    "preface_bindings"][0].update(
                        assignment_id="asg_" + "c" * 32),
                lambda x: x["restart"]["direct_probe"]["client_replacement"][
                    "preface_bindings"][1].update(
                        target_device_id="dev_" + "c" * 32),
                lambda x: x["restart"]["direct_probe"]["client_replacement"][
                    "stale_clients"][1].update(same_channel_and_connector_at_dispatch=False),
                lambda x: x["restart"]["direct_probe"]["client_replacement"].update(
                    accounted_client_counts=[1, 2, 1, 2, 1, 2, 1]),
                lambda x: x["restart"]["same_leaf_continuity"].update(same_worker_private_key=False),
        ):
            broken = copy.deepcopy(result)
            edit(broken)
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._sanitize_restart_cohort_result(
                    broken, old_ready=old_ready, new_ready=new_ready,
                    new_assignment_id="asg_" + "a" * 32,
                    new_device_id="dev_" + "b" * 32,
                    old_held_status=status, observed_requests=requests,
                    old_receipt_digest="f" * 64)
        wrong_request = copy.deepcopy(requests)
        wrong_request[6]["request_id"] = "req_" + "0" * 32
        with self.assertRaisesRegex(supervisor.SupervisorError,
                                    "cohort_result:restart_probe_observation"):
            supervisor._sanitize_restart_cohort_result(
                result, old_ready=old_ready, new_ready=new_ready,
                new_assignment_id="asg_" + "a" * 32,
                new_device_id="dev_" + "b" * 32,
                old_held_status=status, observed_requests=wrong_request,
                old_receipt_digest="f" * 64)


class RestartLaunchBoundaryTests(unittest.TestCase):
    def _launch(self, *, remote_script_side_effect=None,
                upload_side_effect=None, create_side_effect=None):
        events = []
        scripts = []

        def remote_script(_client, script, *_args, **_kwargs):
            scripts.append(script)
            events.append("extract" if script == supervisor._REMOTE_EXTRACT_SCRIPT
                          else "check_artifacts")
            if remote_script_side_effect is not None:
                return remote_script_side_effect(script)
            return b"ok"

        def upload(*_args, **_kwargs):
            events.append("upload")
            if upload_side_effect is not None:
                upload_side_effect()

        def prepare_image(*_args, **_kwargs):
            events.append("image")

        def create(*_args, **kwargs):
            events.append("docker_create")
            if create_side_effect is not None:
                return create_side_effect()
            return "container-id"

        def mark_attempt():
            events.append("launch_attempt")

        args = type("Args", (), {
            "remote_artifacts": "/private/artifacts",
            "remote_image": "sha256:" + "a" * 64,
        })()
        with patch.object(supervisor, "_remote_script", side_effect=remote_script), \
                patch.object(supervisor, "_sftp_upload_bundle", side_effect=upload), \
                patch.object(supervisor, "_prepare_remote_image", side_effect=prepare_image), \
                patch.object(supervisor, "_create_remote_container", side_effect=create):
            result = supervisor._launch_restart_generation(
                object(), raw_tar=b"bundle", ready={}, config={}, args=args,
                owner="owner", password=None, uid=1000, gid=1000, deadline=10.0,
                container_name="worker-g2", job_root="/private/job-g2",
                on_cid=lambda _cid: None, on_launch_attempt=mark_attempt)
        return result, events, scripts

    def test_restart_root_is_prepared_once_and_attempt_marks_exact_docker_boundary(self):
        result, events, scripts = self._launch()
        self.assertEqual(result, "container-id")
        self.assertEqual(events, ["check_artifacts", "upload", "extract", "image",
                                  "launch_attempt", "docker_create"])
        self.assertNotIn(supervisor._REMOTE_CREATE_JOB_SCRIPT, scripts)

    def test_prelaunch_setup_failures_do_not_claim_ambiguous_container_ownership(self):
        for failure_stage in ("upload", "extract"):
            with self.subTest(failure_stage=failure_stage):
                events = []

                def remote_script(_client, script, *_args, **_kwargs):
                    events.append("extract" if script == supervisor._REMOTE_EXTRACT_SCRIPT
                                  else "check_artifacts")
                    if failure_stage == "extract" and script == supervisor._REMOTE_EXTRACT_SCRIPT:
                        raise supervisor.SupervisorError("remote_extract", "test_failure")
                    return b"ok"

                def upload(*_args, **_kwargs):
                    events.append("upload")
                    if failure_stage == "upload":
                        raise supervisor.SupervisorError("bundle_upload", "test_failure")

                args = type("Args", (), {
                    "remote_artifacts": "/private/artifacts",
                    "remote_image": "sha256:" + "a" * 64,
                })()
                attempted = []
                with patch.object(supervisor, "_remote_script", side_effect=remote_script), \
                        patch.object(supervisor, "_sftp_upload_bundle", side_effect=upload), \
                        patch.object(supervisor, "_prepare_remote_image") as prepare_image, \
                        patch.object(supervisor, "_create_remote_container") as create:
                    with self.assertRaises(supervisor.SupervisorError):
                        supervisor._launch_restart_generation(
                            object(), raw_tar=b"bundle", ready={}, config={}, args=args,
                            owner="owner", password=None, uid=1000, gid=1000,
                            deadline=10.0, container_name="worker-g2",
                            job_root="/private/job-g2", on_cid=lambda _cid: None,
                            on_launch_attempt=lambda: attempted.append(True))
                self.assertEqual(attempted, [])
                prepare_image.assert_not_called()
                create.assert_not_called()
                self.assertNotIn(supervisor._REMOTE_CREATE_JOB_SCRIPT, events)

    def test_ambiguous_docker_failure_is_marked_as_a_launch_attempt(self):
        events = []

        def remote_script(_client, script, *_args, **_kwargs):
            events.append("extract" if script == supervisor._REMOTE_EXTRACT_SCRIPT
                          else "check_artifacts")
            return b"ok"

        def ambiguous_create(*_args, **_kwargs):
            events.append("docker_create")
            raise supervisor.SupervisorError("container", "create_unknown")

        # _create_remote_container is the first operation allowed to create an
        # owned container; the callback runs immediately before that boundary.
        args = type("Args", (), {
            "remote_artifacts": "/private/artifacts",
            "remote_image": "sha256:" + "a" * 64,
        })()
        with patch.object(supervisor, "_remote_script", side_effect=remote_script), \
                patch.object(supervisor, "_sftp_upload_bundle",
                             side_effect=lambda *_args, **_kwargs: events.append("upload")), \
                patch.object(supervisor, "_prepare_remote_image",
                             side_effect=lambda *_args, **_kwargs: events.append("image")), \
                patch.object(supervisor, "_create_remote_container",
                             side_effect=ambiguous_create):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._launch_restart_generation(
                    object(), raw_tar=b"bundle", ready={}, config={}, args=args,
                    owner="owner", password=None, uid=1000, gid=1000, deadline=10.0,
                    container_name="worker-g2", job_root="/private/job-g2",
                    on_cid=lambda _cid: None,
                    on_launch_attempt=lambda: events.append("launch_attempt"))
        self.assertEqual(events[-2:], ["launch_attempt", "docker_create"])

    def test_remote_exit_callback_precedes_final_status_and_cleanup_io(self):
        events = []

        def on_exit(value):
            self.assertIs(type(value), int)
            events.append(("exit", value))

        def final_status(*args, **kwargs):
            self.assertEqual(events[0][0], "exit")
            events.append(("status", None))
            return None, None

        with patch.object(supervisor, "_remote_inspect",
                          return_value={"running": False, "exit_code": 0}), \
                patch.object(supervisor, "_final_remote_status",
                             side_effect=final_status), \
                patch.object(supervisor, "_ssh_checked", return_value=b""), \
                patch.object(supervisor, "_remove_remote_job",
                             side_effect=supervisor.SupervisorError("cleanup", "test")):
            supervisor._stop_remote(
                object(), "a" * 64, name="worker", owner="owner",
                image="image", password="password", config={}, job_root="/job",
                uid=1000, gid=1000, deadline=supervisor.time.monotonic() + 2,
                on_exit_confirmed=on_exit)
        self.assertEqual([event[0] for event in events], ["exit", "status"])


class FailureLocationVersionTests(unittest.TestCase):
    def _record(self, version=1, code=None):
        value = {"schema_version": version, "event": "cohort_failure_location",
                 "run_id": "a" * 32, "nonce": "b" * 32,
                 "failure_type": "RemoteError",
                 "frames": [{"file": "secure_worker.py", "function": "serve",
                             "line": 42}]}
        if version == 2:
            value["error_code"] = code
        return value

    def test_failure_location_v1_compatibility_and_v2_code_normalization(self):
        ready = {"run_id": "a" * 32, "nonce": "b" * 32}
        v1 = self._record()
        self.assertEqual(supervisor._validate_cohort_failure_location(v1, ready), v1)
        for code in (None, "UNAUTHENTICATED", "UNRECOGNIZED_ERROR_CODE"):
            record = self._record(2, code)
            normalized = supervisor._validate_cohort_failure_location(record, ready)
            self.assertEqual(normalized, record)

    def test_failure_location_rejects_unknown_types_and_v2_fields(self):
        ready = {"run_id": "a" * 32, "nonce": "b" * 32}
        for version, code, extra in ((True, None, False), (2, True, False),
                                     (2, "UNAUTHENTICATED", True),
                                     (3, None, False)):
            record = self._record(version if type(version) is int else 1,
                                  code if version == 2 else None)
            record["schema_version"] = version
            if extra:
                record["unexpected"] = 1
            with self.subTest(version=version, code=code, extra=extra), \
                    self.assertRaises(supervisor.SupervisorError):
                supervisor._validate_cohort_failure_location(record, ready)
        bad_code = self._record(2, "PEER MESSAGE MUST NOT BE ACCEPTED")
        with self.assertRaisesRegex(supervisor.SupervisorError,
                                    "cohort_failure_location:error_code"):
            supervisor._validate_cohort_failure_location(bad_code, ready)



class OwnerControllerIntegrationShapeTests(unittest.TestCase):
    @staticmethod
    def _baseline4_for_owner(run_id, manifest_fingerprint, worker3_boot):
        """Use the established, separate four-request/27-vector baseline fixture."""
        result = OrderedInterleaveSupervisorSchemaTests()._result()
        result.pop("interleave")
        result["run_id"] = run_id
        result["identities"] = {
            "run_id": run_id, "coordinator_boot_id": "0" * 32,
            "consumer_boot_id": "1" * 32,
            "worker_boot_ids": {"worker-1": "2" * 32,
                                "worker-2": "4" * 32,
                                "worker-3": worker3_boot},
            "manifest_fingerprint": manifest_fingerprint,
        }
        result["local_shutdown"] = {"confirmed": True, "failure_types": []}
        result["remote_shutdown"] = {
            "confirmed": True, "process_state": "exited", "exit_code": 0,
            "shutdown_overall": "confirmed", "worker_boot_id": worker3_boot,
        }
        return result

    def test_owner_action_request_uses_shared_closed_parser(self):
        from lab.secure_cohort_owner import (
            OwnerExpectation, build_owner_action_request, build_owner_command,
        )
        expected = OwnerExpectation(
            profile=supervisor.PROFILE_C1B_OWNER_DRAIN,
            run_id="a" * 32, nonce="b" * 32, worker_boot_id="c" * 32,
            manifest_fingerprint="d" * 64, endpoint="127.0.0.1:50051",
            initial_snapshot_sha256="e" * 64, initial_revision=7)
        command = build_owner_command(expected, 1, "f" * 32)
        request = build_owner_action_request(expected, 1, command)
        raw = supervisor._json_bytes(request)
        with patch.object(supervisor, "_terminal_controls"), patch.object(
                supervisor, "_read_local_handoff", return_value=raw):
            actual_request, actual_command = supervisor._wait_owner_action_request(
                "0" * 64, 1, expected, time.monotonic() + 2.0)
        self.assertEqual(actual_request, request)
        self.assertEqual(actual_command.sequence, 1)
        malformed = dict(request, command_number=2)
        with patch.object(supervisor, "_terminal_controls"), patch.object(
                supervisor, "_read_local_handoff",
                return_value=supervisor._json_bytes(malformed)):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._wait_owner_action_request(
                    "0" * 64, 1, expected, time.monotonic() + 2.0)

    def test_owner_command_publication_uses_exact_parser_canonical_bytes(self):
        from tests.security import test_secure_cohort_owner as owner_fixtures
        from lab import secure_cohort_owner as owner

        fixture = owner_fixtures.OwnerResponseSchemaTests(
            "test_owner_result_drain_and_remove_schema_fixtures")
        expected = owner_fixtures.expected(owner.PROFILE_C1B_OWNER_DRAIN)
        config = fixture._config(expected)
        owner_state = {
            "handled_requests": [], "action_responses": [],
            "command_sha256s": [], "action_frames": {},
            "attempts": [], "delivered_handoffs": [],
        }
        published = []
        response_fixtures = {}
        request_fixtures = {}
        command_fixtures = {}
        for sequence in (1, 2):
            request, response = fixture._response(expected, sequence)
            response_fixtures[sequence] = response
            request_fixtures[sequence] = request
            command_fixtures[sequence] = owner.validate_owner_action_request(
                request, expected)

        def publish(_ssh, raw, *, kind, expected_prior_sha256, **_kwargs):
            self.assertEqual(kind, f"command{len(published) + 1}")
            self.assertEqual(raw[-1:], b"}")
            self.assertFalse(raw.endswith(b"\n"))
            receipt = {
                "schema_version": 1, "event": "owner_file_publication",
                "kind": kind, "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw), "uid": 1000, "gid": 1000, "mode": 0o600,
                "file_fsync_confirmed": True,
                "directory_fsync_confirmed": True,
                "readback_confirmed": True,
            }
            if not published:
                self.assertEqual(expected_prior_sha256, "")
            else:
                self.assertEqual(expected_prior_sha256, published[0]["sha256"])
            published.append({"raw": raw,
                              "expected_prior_sha256": expected_prior_sha256,
                              **receipt})
            return receipt

        def wait_request(_cid, number, _expected, _deadline):
            return request_fixtures[number], command_fixtures[number]

        def wait_completion(_ssh, *, expected_command, **_kwargs):
            response = response_fixtures[expected_command.sequence]
            status_frame = response["protected_status"]
            return (
                response["worker_ack"],
                {"uid": 1000, "gid": 1000, "mode": 0o600,
                 "size": 1, "mtime_ns": 11, "sha256": "a" * 64,
                 "metadata_stable": True},
                {"uid": 1000, "mode": 0o600, "mark_ns": 10,
                 "mtime_ns": 11, "status": status_frame["remote_status"]},
            )

        with patch.object(supervisor, "_wait_owner_action_request",
                          side_effect=wait_request), \
                patch.object(supervisor, "_publish_owner_file", side_effect=publish), \
                patch.object(supervisor, "_remote_mark", return_value=10), \
                patch.object(supervisor, "_wait_owner_command_completion",
                             side_effect=wait_completion), \
                patch.object(supervisor, "_write_local_handoff"):
            for sequence in (1, 2):
                response, command, _frame = supervisor._handle_owner_action(
                    local_cid="local", number=sequence, expected=expected,
                    ready={}, config=config, bundle_files={}, initial_view=None,
                    initial_store=None, initial_serials=[], host_key="6" * 64,
                    ssh=object(), password=None, job_root="/srv/job",
                    intent_root=None, uid=1000, gid=1000,
                    container_id="", container_name="", owner_label="",
                    image="", deadline=time.monotonic() + 5.0,
                    owner_state=owner_state)
                raw = published[sequence - 1]["raw"]
                parsed_command_bytes = owner._canonical_bytes(
                    owner._command_document(command), maximum=owner.MAX_RECORD_BYTES)
                self.assertEqual(raw, parsed_command_bytes)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), command.command_sha256)
                self.assertEqual(response["publication"]["command"]["sha256"],
                                 command.command_sha256)
                self.assertEqual(response["publication"]["command"]["size"], len(raw))
                self.assertIs(owner.validate_owner_action_response(
                    response, request_fixtures[sequence], expected,
                    expected_ssh_host_key_sha256="6" * 64,
                    expected_worker_config=config), response)

        self.assertEqual(len(published), 2)
        self.assertEqual(published[1]["expected_prior_sha256"],
                         published[0]["sha256"])
        self.assertEqual(owner_state["command_sha256s"],
                         [row["sha256"] for row in published])

        # The same canonical-byte rule covers Remove's two signed command records.
        remove_expected = owner_fixtures.expected(owner.PROFILE_C1B_OWNER_REMOVE)
        for sequence in (1, 2):
            request, response = fixture._response(remove_expected, sequence)
            command = owner.validate_owner_action_request(request, remove_expected)
            raw = supervisor._owner_canonical_bytes(
                request["command"], maximum=supervisor.OWNER_CONTROL_LIMIT)
            self.assertFalse(raw.endswith(b"\n"))
            self.assertEqual(hashlib.sha256(raw).hexdigest(), command.command_sha256)
            response["publication"]["command"].update(
                sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
            self.assertIs(owner.validate_owner_action_response(
                response, request, remove_expected,
                expected_ssh_host_key_sha256="6" * 64,
                expected_worker_config=fixture._config(remove_expected)), response)

    def test_owner_profiles_have_exact_seven_observation_positions(self):
        expected = ((1, "greedy-one-token"), (2, "forced-length-1"),
                    (3, "forced-length-128"), (4, "forced-length-1024"))
        self.assertEqual(supervisor._PROFILE_OBSERVATIONS[
            supervisor.PROFILE_C1B_OWNER_DRAIN], expected + (
                (5, "owner-drain-held"), (6, "owner-drain-controls"),
                (7, "owner-drain-paused")))
        self.assertEqual(supervisor._PROFILE_OBSERVATIONS[
            supervisor.PROFILE_C1B_OWNER_REMOVE], expected + (
                (5, "owner-remove-held"), (6, "owner-remove-revoked"),
                (7, "owner-remove-final")))

    def test_owner_actions_are_rejected_by_legacy_profile_parsers(self):
        value = {"owner_actions": {}}
        for profile in (supervisor.PROFILE_BASELINE,
                        supervisor.PROFILE_C1B_HAPPY,
                        supervisor.PROFILE_C1B_INTERLEAVE,
                        supervisor.PROFILE_C1B_CANCEL,
                        supervisor.PROFILE_C1B_PARTIAL,
                        supervisor.PROFILE_C1B_STEP_LOSS,
                        supervisor.PROFILE_C1B_CAPACITY,
                        supervisor.PROFILE_C1B_RESTART):
            with self.subTest(profile=profile), self.assertRaises(
                    supervisor.SupervisorError):
                supervisor._sanitize_cohort_result(value, profile)

    def test_owner_container_arguments_are_fixed_and_remove_mount_is_read_only(self):
        common = dict(image="sha256:" + "a" * 64, name="worker", owner="owner",
                      job_root="/srv/job", artifacts="/srv/artifacts",
                      owner_controls_run_id="b" * 32)
        drain = supervisor.build_remote_run_argv(**common)
        self.assertIn("--owner-controls-run-id", drain)
        self.assertEqual(drain[-2:], ["--owner-controls-run-id", "b" * 32])
        self.assertFalse(any("/owner-intents" in item for item in drain))
        remove = supervisor.build_remote_run_argv(
            **common, owner_intent_root="/srv/job-owner-intents")
        owner_mounts = [remove[index + 1] for index, item in enumerate(remove[:-1])
                        if item == "--mount" and "dst=/owner-intents" in remove[index + 1]]
        self.assertEqual(len(owner_mounts), 1)
        self.assertIn("readonly", owner_mounts[0])
        self.assertEqual(remove[-2:], ["--owner-removal-intent-root", "/owner-intents"])

    def test_owner_cli_argument_cannot_be_used_without_control_mode(self):
        common = dict(
            image="sha256:" + "a" * 64, name="worker", owner="owner",
            job_root="/srv/job", artifacts="/srv/artifacts")
        with self.assertRaises(supervisor.SupervisorError):
            supervisor.build_remote_run_argv(
                **common, owner_intent_root="/srv/job-owner-intents")

    def test_owner_sidecar_verification_is_fixed_and_hash_bound(self):
        files = {"install-snapshot.json": b"snapshot-one",
                 "remove-snapshot.json": b"snapshot-two",
                 "install-intent.json": b"intent-one",
                 "removal-intent.json": b"intent-two",
                 "snapshot.pub": b"public-verifier"}
        hashes = {name: hashlib.sha256(files[name]).hexdigest()
                  for name in ("snapshot.pub", "install-intent.json",
                               "removal-intent.json")}
        receipt = {"schema_version": 1, "event": "owner_intent_sidecar_verified",
                   "files": hashes}
        calls = []

        def remote(_client, script, argv, **kwargs):
            calls.append((script, list(argv), kwargs))
            return supervisor._json_bytes(receipt)

        with patch.object(supervisor, "_remote_script", side_effect=remote):
            actual = supervisor._verify_owner_intent_sidecar(
                object(), intent_root="/srv/job-owner-intents", uid=1000, gid=1000,
                password=None, deadline=time.monotonic() + 2.0,
                material_files=files)
        self.assertEqual(actual, receipt)
        self.assertIs(calls[0][0], supervisor._REMOTE_OWNER_SIDECAR_VERIFY_SCRIPT)
        ast.parse(supervisor._REMOTE_OWNER_SIDECAR_VERIFY_SCRIPT)
        self.assertEqual(calls[0][1][0:3], ["/srv/job-owner-intents", "1000", "1000"])
        changed = dict(receipt, files=dict(hashes, **{"snapshot.pub": "f" * 64}))
        with patch.object(supervisor, "_remote_script",
                          return_value=supervisor._json_bytes(changed)):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._verify_owner_intent_sidecar(
                    object(), intent_root="/srv/job-owner-intents", uid=1000, gid=1000,
                    password=None, deadline=time.monotonic() + 2.0,
                    material_files=files)

    def test_producer_builder_and_controller_bind_real_worker_status_shapes(self):
        # Reuse the shared owner fixture only as an importable module. Its positive
        # worker statuses are produced by lab.secure_worker._status_payload.
        from tests.security import test_secure_cohort_owner as owner_fixtures
        from lab import secure_cohort, secure_cohort_owner as owner

        fixture = owner_fixtures.OwnerResponseSchemaTests(
            "test_owner_result_drain_and_remove_schema_fixtures")
        for profile in owner.OWNER_PROFILES:
            expected, source_result = fixture._result_fixture(profile)
            result = self._baseline4_for_owner(
                expected.run_id, expected.manifest_fingerprint, expected.worker_boot_id)
            result["owner_actions"] = source_result["owner_actions"]
            actions = result["owner_actions"]
            config = fixture._config(expected)
            built = secure_cohort._build_owner_actions_result(
                expected, worker_config=config, ssh_host_key_sha256="6" * 64,
                initial_local_serials=actions["initial_local_serials"],
                old_local_shutdown=actions["old_local_shutdown"],
                direct_probe=actions["direct_probe"], commands=actions["commands"],
                controls=actions["controls"], observations=actions["observations"],
                probe_cleanup=actions["probe_cleanup"])
            self.assertEqual(built, actions)
            ready_status = fixture._status(
                expected, config, None, event="ready", lifecycle_phase="ready")
            supervisor._require_owner_global_idle(ready_status)
            remote_expected = secure_cohort.RemoteExpectation(
                expected.run_id, expected.nonce, "worker-3", config["account_id"],
                config["device_id"], expected.worker_boot_id, config["assignment_id"],
                config["model_id"], config["model_revision"],
                config["manifest_fingerprint"], expected.initial_snapshot_sha256,
                expected.endpoint, config["clock_uncertainty_seconds"], (6, 8))
            baseline_request = secure_cohort.build_observation_request(
                remote_expected, sequence=1, case_id="greedy-one-token",
                request_id="req_" + "a" * 32, session_id="ses_" + "b" * 32,
                profile=supervisor.PROFILE_BASELINE)
            baseline_frame = {"uid": 1000, "mode": 0o600,
                              "mtime_ns": 20, "mark_ns": 10,
                              "status": ready_status}
            owner_baseline_ack = supervisor._remote_observation_ack(
                {"run_id": expected.run_id, "nonce": expected.nonce,
                 "expected_boot_id": expected.worker_boot_id,
                 "manifest_fingerprint": expected.manifest_fingerprint,
                 "endpoint": expected.endpoint}, "6" * 64,
                baseline_request, baseline_frame,
                measurement_label="ssh_protected_owner_status_v1")
            self.assertEqual(owner_baseline_ack["measurement_label"],
                             "ssh_protected_owner_status_v1")
            from lab.secure_cohort_owner import _validate_owner_status
            _validate_owner_status(ready_status, expected, config)
            for branch, value in (("handler", "active_sessions"),
                                  ("bridge", "active_authorizations"),
                                  ("transport", "reserved_pending")):
                damaged = copy.deepcopy(ready_status)
                damaged[branch][value] = 1
                with self.subTest(profile=profile, idle_field=f"{branch}.{value}"), \
                        self.assertRaises(supervisor.SupervisorError):
                    supervisor._require_owner_global_idle(damaged)
            requests = []
            for number, response in enumerate(actions["commands"], 1):
                ack = response["worker_ack"]
                digest = ("" if profile == owner.PROFILE_C1B_OWNER_DRAIN
                          else ack["applied_snapshot_sha256"])
                revision = (0 if profile == owner.PROFILE_C1B_OWNER_DRAIN
                            else ack["applied_revision"])
                command = owner.build_owner_command(
                    expected, number, ack["command_id"], snapshot_sha256=digest,
                    snapshot_revision=revision)
                requests.append(owner.build_owner_action_request(
                    expected, number, command))
            attempt_kinds = (
                ["command1", "command2"]
                if profile == owner.PROFILE_C1B_OWNER_DRAIN else
                ["intent_root", "snapshot_verifier", "install_intent",
                 "removal_intent", "policy1", "command1", "policy2", "command2"])
            attempts = [{"kind": kind, "monotonic_ns": (index + 1) * 10,
                         **({"mark_ns": (index + 1) * 100}
                            if kind in ("command1", "command2") else {})}
                        for index, kind in enumerate(attempt_kinds)]
            owner_state = {
                "attempts": attempts,
                "verifier_copy_receipt": {} if profile == owner.PROFILE_C1B_OWNER_REMOVE else None,
                "intent_publication_complete": profile == owner.PROFILE_C1B_OWNER_REMOVE,
                "sidecar_retention_receipt": {} if profile == owner.PROFILE_C1B_OWNER_REMOVE else None,
                "actual_remove_exit": ({"process_state": "exited", "exit_code": 0}
                                        if profile == owner.PROFILE_C1B_OWNER_REMOVE else None),
            }
            actual_responses = actions["commands"]
            sanitized = supervisor._sanitize_owner_cohort_result(
                result, expected=expected, host_key="6" * 64, config=config,
                expected_serials=actions["initial_local_serials"],
                handled_requests=requests, action_responses=actual_responses,
                observation_acks=actions["observations"], owner_state=owner_state)
            self.assertEqual(sanitized["owner_actions"], built)
            self.assertEqual((sanitized["baseline_status"],
                              sanitized["completed_requests"],
                              sanitized["captured_vectors"]), ("passed", 4, 27))
            for field, bad_value in (
                    ("run_id", "f" * 32),
                    ("local_shutdown", {"confirmed": False, "failure_types": []}),
                    ("remote_shutdown", {"confirmed": True, "process_state": "exited",
                                         "exit_code": True, "shutdown_overall": "confirmed",
                                         "worker_boot_id": expected.worker_boot_id})):
                damaged_result = dict(result, **{field: bad_value})
                with self.subTest(profile=profile, field=field), \
                        self.assertRaises(supervisor.SupervisorError):
                    supervisor._sanitize_owner_cohort_result(
                        damaged_result, expected=expected, host_key="6" * 64,
                        config=config, expected_serials=actions["initial_local_serials"],
                        handled_requests=requests, action_responses=actual_responses,
                        observation_acks=actions["observations"], owner_state=owner_state)

            changed = copy.deepcopy(result)
            changed["owner_actions"] = copy.deepcopy(built)
            changed_response = changed["owner_actions"]["commands"][0]
            changed_response["protected_status"]["remote_mark_ns"] += 1
            changed_response["protected_status"]["heartbeat_mtime_ns"] += 1
            with self.subTest(profile=profile), self.assertRaises(
                    supervisor.SupervisorError):
                supervisor._sanitize_owner_cohort_result(
                    changed, expected=expected, host_key="6" * 64, config=config,
                    expected_serials=actions["initial_local_serials"],
                    handled_requests=requests, action_responses=actual_responses,
                    observation_acks=actions["observations"], owner_state=owner_state)

    def test_producer_drain_command_helper_round_trips_controller_parser(self):
        from tests.security import test_secure_cohort_owner as owner_fixtures
        from lab import secure_cohort, secure_cohort_owner as owner

        fixture = owner_fixtures.OwnerResponseSchemaTests(
            "test_owner_result_drain_and_remove_schema_fixtures")
        expected, _result = fixture._result_fixture(owner.PROFILE_C1B_OWNER_DRAIN)
        commands = secure_cohort._prepare_owner_drain_commands(
            expected, command_ids=("a" * 32, "b" * 32))
        self.assertEqual(len(commands), 2)
        for number, command in enumerate(commands, 1):
            request = owner.build_owner_action_request(expected, number, command)
            raw = supervisor._json_bytes(request)
            with patch.object(supervisor, "_terminal_controls"), patch.object(
                    supervisor, "_read_local_handoff", return_value=raw):
                _request, parsed = supervisor._wait_owner_action_request(
                    "0" * 64, number, expected, time.monotonic() + 2.0)
            self.assertEqual(parsed.command_id, "a" * 32 if number == 1 else "b" * 32)

    def test_owner_cleanup_requires_resolved_real_handoffs_and_mutations(self):
        from lab.secure_cohort_owner import PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE
        drain_handoffs = ["observation-response-5.json", "owner-action-response-1.json",
                          "owner-action-response-2.json", "observation-response-6.json",
                          "observation-response-7.json"]
        remove_handoffs = ["observation-response-5.json", "owner-action-response-1.json",
                           "observation-response-6.json", "owner-action-response-2.json",
                           "observation-response-7.json"]
        drain = {"attempts": [{"kind": "command1"}, {"kind": "command2"}],
                 "action_responses": [{}, {}], "handled_requests": [{}, {}],
                 "observation_acks": [{}, {}, {}], "delivered_handoffs": list(drain_handoffs)}
        self.assertTrue(supervisor._owner_cleanup_is_authorized(
            drain, PROFILE_C1B_OWNER_DRAIN, intent_root=None))
        for field, damaged in (("delivered_handoffs", drain_handoffs[:-1]),
                               ("action_responses", [{}]),
                               ("attempts", [{"kind": "command1"}])):
            changed = dict(drain, **{field: damaged})
            with self.subTest(field=field):
                self.assertFalse(supervisor._owner_cleanup_is_authorized(
                    changed, PROFILE_C1B_OWNER_DRAIN, intent_root=None))
        unresolved = dict(drain, attempts=[{"kind": "command1"}],
                          action_responses=[], delivered_handoffs=[])
        self.assertFalse(supervisor._owner_cleanup_is_authorized(
            unresolved, PROFILE_C1B_OWNER_DRAIN, intent_root=None))
        with patch.object(supervisor, "_pending_channel_operation_count", return_value=1):
            self.assertFalse(supervisor._owner_cleanup_is_authorized(
                drain, PROFILE_C1B_OWNER_DRAIN, intent_root=None))
        remove = dict(drain, delivered_handoffs=list(remove_handoffs), attempts=[{"kind": kind} for kind in (
            "intent_root", "snapshot_verifier", "install_intent", "removal_intent",
            "policy1", "command1", "policy2", "command2")],
            intent_publication_complete=True, verifier_copy_receipt={},
            sidecar_retention_receipt={},
            actual_remove_exit={"process_state": "exited", "exit_code": 0})
        self.assertTrue(supervisor._owner_cleanup_is_authorized(
            remove, PROFILE_C1B_OWNER_REMOVE, intent_root="/owner-intents"))
        for field, bad in (("actual_remove_exit", {"process_state": "exited", "exit_code": 1}),
                           ("sidecar_retention_receipt", None),
                           ("delivered_handoffs", remove_handoffs[:-1]),
                           ("delivered_handoffs", drain_handoffs)):
            changed = dict(remove, **{field: bad})
            self.assertFalse(supervisor._owner_cleanup_is_authorized(
                changed, PROFILE_C1B_OWNER_REMOVE, intent_root="/owner-intents"))

    def test_owner_sequence6_expected_session_is_profile_specific(self):
        from lab.secure_cohort_owner import PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE
        probe = {"request_id": "req_" + "a" * 32,
                 "session_id": "ses_" + "b" * 32}
        self.assertEqual(supervisor._owner_observation_session(
            PROFILE_C1B_OWNER_DRAIN, 6, dict(probe), [probe]), probe["session_id"])
        self.assertIsNone(supervisor._owner_observation_session(
            PROFILE_C1B_OWNER_REMOVE, 6, dict(probe), [probe]))
        with self.assertRaises(supervisor.SupervisorError):
            supervisor._owner_observation_session(
                PROFILE_C1B_OWNER_REMOVE, 6,
                dict(probe, request_id="req_" + "c" * 32), [probe])

    def test_owner_no_session_observation_requires_global_idle_before_ack(self):
        from tests.security import test_secure_cohort_owner as owner_fixtures
        from lab.secure_cohort_owner import PROFILE_C1B_OWNER_REMOVE

        fixture = owner_fixtures.OwnerResponseSchemaTests(
            "test_owner_result_drain_and_remove_schema_fixtures")
        expected, _ = fixture._result_fixture(PROFILE_C1B_OWNER_REMOVE)
        config = fixture._config(expected)
        zero = fixture._status(expected, config, None, event="heartbeat",
                               lifecycle_phase="paused")
        held = fixture._status(
            expected, config, None, event="heartbeat", lifecycle_phase="draining",
            session_id="ses_" + "e" * 32, held=True)

        def read_status(status):
            return {"uid": 1000, "mode": 0o600, "mtime_ns": 20,
                    "mark_ns": 10, "status": status}

        kwargs = dict(
            config=config, password=None, status_path="/srv/job/status.json",
            mark_ns=10, deadline=time.monotonic() + 2,
            expected_events={"heartbeat"}, expected_session_id=None,
            owner_expected=expected, owner_observation=True)
        with patch.object(supervisor, "_read_remote_status",
                          return_value=read_status(zero)):
            frame = supervisor._wait_remote_status(object(), **kwargs)
        self.assertIs(frame["status"], zero)
        with patch.object(supervisor, "_read_remote_status",
                          return_value=read_status(held)):
            with self.assertRaisesRegex(
                    supervisor.SupervisorError,
                    "remote_status:owner_not_globally_idle"):
                supervisor._wait_remote_status(object(), **kwargs)

    def test_owner_cleanup_names_are_profile_scoped_not_wildcarded(self):
        ordinary = supervisor._remote_remove_job_script()
        owner = supervisor._remote_remove_job_script(owner_profile=True)
        self.assertNotIn('"owner-command.json"', ordinary)
        self.assertNotIn('"owner-ack.json"', ordinary)
        self.assertIn('"owner-command.json":16384', owner)
        self.assertIn('"owner-ack.json":16384', owner)
        self.assertNotIn("owner-*.json", owner)
        ast.parse(ordinary)
        ast.parse(owner)

    def test_owner_stop_never_deletes_on_nonzero_exit_bad_status_or_unknown_mutation(self):
        from tests.security import test_secure_cohort_owner as owner_fixtures
        from lab import secure_cohort_owner as owner
        fixture = owner_fixtures.OwnerResponseSchemaTests(
            "test_owner_result_drain_and_remove_schema_fixtures")
        expected, _ = fixture._result_fixture(owner.PROFILE_C1B_OWNER_REMOVE)
        for exit_code, status_valid, cleanup_ready in (
                (1, True, True), (0, False, True), (0, True, False)):
            with self.subTest(exit_code=exit_code, status_valid=status_valid,
                              cleanup_ready=cleanup_ready):
                with patch.object(supervisor, "_remote_inspect",
                                  return_value={"running": False, "exit_code": exit_code}), \
                        patch.object(supervisor, "_final_remote_status",
                                     return_value=({"uid": 1000, "mode": 0o600},
                                                   {"event": "final"})), \
                        patch.object(supervisor, "_validate_owner_status",
                                     side_effect=None if status_valid else ValueError("bad")), \
                        patch.object(supervisor, "_ssh_checked") as remove_container, \
                        patch.object(supervisor, "_remove_remote_job") as remove_files:
                    result = supervisor._stop_remote(
                        object(), "c" * 64, name="worker", owner="owner", image="image",
                        password=None, config={}, job_root="/job", uid=1000, gid=1000,
                        deadline=time.monotonic() + 2, owner_expected=expected,
                        owner_final_ack={}, owner_cleanup_ready=cleanup_ready)
                self.assertFalse(result["cleanup_confirmed"])
                remove_container.assert_not_called()
                remove_files.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "owner handoff uses POSIX directory descriptors")
    def test_owner_baseline_ack_round_trips_through_frozen_owner_observer(self):
        from tests.security import test_secure_cohort_owner as owner_fixtures
        from lab import secure_cohort, secure_cohort_owner as owner
        fixture = owner_fixtures.OwnerResponseSchemaTests(
            "test_owner_result_drain_and_remove_schema_fixtures")
        owner_expected, _ = fixture._result_fixture(owner.PROFILE_C1B_OWNER_DRAIN)
        config = fixture._config(owner_expected)
        expected = secure_cohort.RemoteExpectation(
            owner_expected.run_id, owner_expected.nonce, "worker-3", config["account_id"],
            config["device_id"], owner_expected.worker_boot_id, config["assignment_id"],
            config["model_id"], config["model_revision"], config["manifest_fingerprint"],
            owner_expected.initial_snapshot_sha256, owner_expected.endpoint,
            config["clock_uncertainty_seconds"], (6, 8))
        request_id, session_id = "req_" + "a" * 32, "ses_" + "b" * 32
        ready = {"run_id": expected.run_id, "nonce": expected.nonce,
                 "expected_boot_id": expected.boot_id,
                 "manifest_fingerprint": expected.manifest_fingerprint,
                 "snapshot_sha256": expected.snapshot_sha256,
                 "endpoint": expected.endpoint}
        host_key = "6" * 64
        status = fixture._status(owner_expected, config, None,
                                 event="heartbeat", lifecycle_phase="ready")
        async def run_pair(directory, measurement_label):
            os.chmod(directory, 0o700)
            directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                async def answer():
                    request_path = Path(directory) / "observation-request-1.json"
                    limit = time.monotonic() + 2
                    while not request_path.exists() and time.monotonic() < limit:
                        await asyncio.sleep(0.005)
                    request = json.loads(request_path.read_text(encoding="utf-8"))
                    frame = {"uid": 1000, "mode": 0o600, "mtime_ns": 20,
                             "mark_ns": 10, "status": status}
                    ack = supervisor._remote_observation_ack(
                        ready, host_key, request, frame,
                        measurement_label=measurement_label)
                    response_path = Path(directory) / "observation-response-1.json"
                    response_fd = os.open(
                        response_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600)
                    try:
                        os.write(response_fd, supervisor._json_bytes(ack))
                        os.fsync(response_fd)
                    finally:
                        os.close(response_fd)
                responder = asyncio.create_task(answer())
                response = await secure_cohort._observe_owner_remote(
                    directory_fd, expected=expected, owner_expected=owner_expected,
                    worker_config=config, sequence=1, request_id=request_id,
                    session_id=session_id, host_key=host_key, commands=[])
                await responder
                return response
            finally:
                os.close(directory_fd)
        with tempfile.TemporaryDirectory() as good_directory, \
                tempfile.TemporaryDirectory() as bad_directory:
            response = asyncio.run(run_pair(
                good_directory, "ssh_protected_owner_status_v1"))
            self.assertEqual(response["measurement_label"],
                             "ssh_protected_owner_status_v1")
            with self.assertRaises(secure_cohort.CohortError):
                asyncio.run(run_pair(bad_directory, "ssh_status_after_heartbeat"))



class _OwnerStageStream:
    def __init__(self, events, uid=1000, gid=1000, write_error=None):
        self.events = events
        self.uid = uid
        self.gid = gid
        self.data = b""
        self.write_error = write_error

    def chmod(self, mode):
        self.events.append(("chmod", mode))

    def stat(self):
        self.events.append("stream_stat")
        return SimpleNamespace(st_uid=self.uid, st_gid=self.gid,
                               st_mode=stat.S_IFREG | 0o600,
                               st_size=len(self.data))

    def set_pipelined(self, enabled):
        self.events.append(("pipelined", enabled))

    def write(self, data):
        self.events.append("write")
        if self.write_error is not None:
            raise self.write_error
        self.data += data

    def flush(self):
        self.events.append("flush")

    def close(self):
        self.events.append("stream_close")


class _OwnerSftp:
    def __init__(self, events, stream):
        self.events = events
        self.stream = stream
        self.channel = object()

    def open(self, path, mode):
        self.events.append(("open", path, mode))
        return self.stream

    def stat(self, path):
        self.events.append(("path_stat", path))
        return self.stream.stat()

    def close(self):
        self.events.append("sftp_close")

    def get_channel(self):
        return self.channel


class OwnerPublicationControllerHelperTests(unittest.TestCase):
    def setUp(self):
        self.deadline = time.monotonic() + 10
        self.job_root = "/srv/job"
        self.intent_root = "/srv/job-owner-intents"
        self.data = b'{"schema_version":1,"event":"owner_action"}'
        self.uid, self.gid = 1000, 1000

    def _receipt(self, kind="command1", data=None):
        from lab.secure_owner_file_publication import build_publication_plan
        data = self.data if data is None else data
        plan = build_publication_plan(
            kind, intent_root=self.intent_root, job_root=self.job_root,
            uid=self.uid, gid=self.gid, sha256=hashlib.sha256(data).hexdigest(),
            size=len(data), expected_prior_sha256="")
        receipt = {
            "schema_version": 1, "event": "owner_file_publication", "kind": kind,
            "sha256": plan.sha256, "size": plan.size, "uid": plan.uid,
            "gid": plan.gid, "mode": 0o600, "file_fsync_confirmed": True,
            "directory_fsync_confirmed": True, "readback_confirmed": True,
        }
        return json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()

    def _fake_remote(self, events, receipt=None, failure=None):
        def call(_client, script, args, **kwargs):
            events.append(("remote", script, tuple(args), kwargs.get("sudo"),
                           kwargs.get("deadline")))
            if script is supervisor._REMOTE_OWNER_STAGE_PREFLIGHT_SCRIPT:
                return json.dumps({"event": "owner_stage_preflight", "uid": self.uid,
                                   "gid": self.gid, "mode": 0o600, "nlink": 1,
                                   "size": 0}, separators=(",", ":")).encode()
            if failure is not None:
                raise failure
            return receipt
        return call

    def test_publish_uses_bounded_order_and_receipt_validation(self):
        events = []
        stream = _OwnerStageStream(events, self.uid, self.gid)
        sftp = _OwnerSftp(events, stream)
        self.assertFalse(hasattr(stream.stat(), "st_nlink"))
        deadlines = []

        def sftp_call(_sftp, deadline, stage, call):
            deadlines.append((deadline, stage))
            return call()

        with patch.object(supervisor, "_open_sftp", side_effect=lambda *_: sftp), \
                patch.object(supervisor, "_sftp_call", side_effect=sftp_call), \
                patch.object(supervisor, "_remote_script",
                             side_effect=self._fake_remote(
                                 events, self._receipt())):
            receipt = supervisor._publish_owner_file(
                object(), self.data, kind="command1", job_root=self.job_root,
                intent_root=self.intent_root, uid=self.uid, gid=self.gid,
                password=None, deadline=self.deadline,
                on_attempt=lambda: events.append("attempt"))
        self.assertEqual(receipt["kind"], "command1")
        self.assertEqual(stream.data, self.data)
        labels = [event[0] if type(event) is tuple else event for event in events]
        self.assertLess(labels.index("attempt"), labels.index("open"))
        self.assertLess(labels.index("remote"), labels.index("write"))
        self.assertLess(labels.index("flush"), labels.index("stream_close"))
        publish_index = max(i for i, event in enumerate(events)
                            if type(event) is tuple and event[0] == "remote")
        self.assertLess(labels.index("sftp_close"), publish_index)
        self.assertEqual({deadline for deadline, _ in deadlines}, {self.deadline})
        self.assertEqual([stage for _, stage in deadlines], [
            "owner_publish_stage", "owner_publish_stage", "owner_publish_stage",
            "owner_publish_stage", "owner_publish_stage", "owner_publish_stage",
            "owner_publish_stage", "owner_publish_stage", "owner_publish_stage",
        ])
        remote_calls = [event for event in events
                        if type(event) is tuple and event[0] == "remote"]
        self.assertIs(remote_calls[0][1], supervisor._REMOTE_OWNER_STAGE_PREFLIGHT_SCRIPT)
        self.assertIs(remote_calls[1][1], supervisor.REMOTE_PUBLISH_SCRIPT)
        self.assertEqual([event[3] for event in remote_calls], [False, False])
        self.assertEqual([event[4] for event in remote_calls],
                         [self.deadline, self.deadline])

    def test_attempt_record_failure_prevents_first_stage_creation(self):
        events = []
        stream = _OwnerStageStream(events, self.uid, self.gid)
        sftp = _OwnerSftp(events, stream)
        with patch.object(supervisor, "_open_sftp", return_value=sftp), \
                patch.object(supervisor, "_sftp_call",
                             side_effect=lambda _sftp, _deadline, _stage, call: call()), \
                patch.object(supervisor, "_remote_script"):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._publish_owner_file(
                    object(), self.data, kind="command1", job_root=self.job_root,
                    intent_root=self.intent_root, uid=self.uid, gid=self.gid,
                    password=None, deadline=self.deadline,
                    on_attempt=lambda: "not-recorded")
        self.assertFalse(any(type(event) is tuple and event[0] == "open"
                             for event in events))
        self.assertNotIn("write", events)

    def test_unknown_stage_write_retains_channel_and_never_commits_or_retries(self):
        events = []
        stream = _OwnerStageStream(
            events, self.uid, self.gid,
            supervisor.SupervisorError("owner_publish_stage", "ack_timeout_unknown"))
        sftp = _OwnerSftp(events, stream)

        def sftp_call(_sftp, _deadline, _stage, call):
            return call()

        with patch.object(supervisor, "_open_sftp", return_value=sftp), \
                patch.object(supervisor, "_sftp_call", side_effect=sftp_call), \
                patch.object(supervisor, "_remote_script",
                             side_effect=self._fake_remote(events)), \
                patch.object(supervisor, "_channel_operation_owned", return_value=True):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._publish_owner_file(
                    object(), self.data, kind="command1", job_root=self.job_root,
                    intent_root=self.intent_root, uid=self.uid, gid=self.gid,
                    password=None, deadline=self.deadline)
        self.assertEqual(sum(event == "write" for event in events), 1)
        self.assertFalse(any(type(event) is tuple and event[0] == "remote"
                             and event[1] is supervisor.REMOTE_PUBLISH_SCRIPT
                             for event in events))
        self.assertNotIn("stream_close", events)
        self.assertNotIn("sftp_close", events)

    def test_failed_commit_is_attempted_once_and_returns_no_receipt(self):
        events = []
        stream = _OwnerStageStream(events, self.uid, self.gid)
        sftp = _OwnerSftp(events, stream)

        def sftp_call(_sftp, _deadline, _stage, call):
            return call()

        calls = []
        def remote(client, script, args, **kwargs):
            if script is supervisor._REMOTE_OWNER_STAGE_PREFLIGHT_SCRIPT:
                return self._fake_remote(events)(client, script, args, **kwargs)
            calls.append((script, tuple(args)))
            raise supervisor.SupervisorError("ssh_command", "ack_timeout_unknown")

        with patch.object(supervisor, "_open_sftp", return_value=sftp), \
                patch.object(supervisor, "_sftp_call", side_effect=sftp_call), \
                patch.object(supervisor, "_remote_script", side_effect=remote):
            with self.assertRaises(supervisor.SupervisorError):
                supervisor._publish_owner_file(
                    object(), self.data, kind="command1", job_root=self.job_root,
                    intent_root=self.intent_root, uid=self.uid, gid=self.gid,
                    password=None, deadline=self.deadline)
        self.assertEqual(sum(script is supervisor.REMOTE_PUBLISH_SCRIPT
                             for script, _ in calls), 1)
        self.assertEqual(stream.data, self.data)
        self.assertIn("sftp_close", events)

    def test_verifier_receipt_rejects_bool_integer_type_aliases(self):
        expected = {
            "schema_version": 1, "event": "owner_verifier_copy",
            "uid": self.uid, "gid": self.gid, "mode": 0o600,
            "size": len(b"public verifier"),
            "sha256": hashlib.sha256(b"public verifier").hexdigest(),
            "fsynced": True, "readback": True,
        }
        for field, bad in (("schema_version", True), ("uid", True),
                           ("size", float(len(b"public verifier"))),
                           ("fsynced", 1), ("readback", 1)):
            with self.subTest(field=field):
                events = []
                stream = _OwnerStageStream(events, self.uid, self.gid)
                sftp = _OwnerSftp(events, stream)
                receipt = dict(expected, **{field: bad})
                with patch.object(supervisor, "_open_sftp", return_value=sftp), \
                        patch.object(supervisor, "_sftp_call",
                                     side_effect=lambda _sftp, _deadline, _stage, call: call()), \
                        patch.object(supervisor, "_remote_script",
                                     return_value=supervisor._json_bytes(receipt)), \
                        patch.object(supervisor, "_channel_operation_owned", return_value=False):
                    with self.assertRaises(supervisor.SupervisorError):
                        supervisor._install_owner_verifier_copy(
                            object(), b"public verifier", intent_root=self.intent_root,
                            uid=self.uid, gid=self.gid, password=None,
                            deadline=self.deadline)

    def test_external_intent_sidecar_attempt_is_recorded_before_single_create(self):
        events = []
        def remote(_client, script, args, **kwargs):
            events.append((script, tuple(args), kwargs.get("deadline")))
            return b"created\n"
        with patch.object(supervisor, "_remote_script", side_effect=remote):
            result = supervisor._ensure_owner_intent_root(
                object(), job_root=self.job_root, uid=self.uid, gid=self.gid,
                password=None, deadline=self.deadline,
                on_attempt=lambda: events.append("attempt"))
        self.assertEqual(result, self.intent_root)
        self.assertEqual(events[0], "attempt")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[1][1], (self.intent_root, "1000", "1000"))
        self.assertIs(events[1][0], supervisor._REMOTE_CREATE_JOB_SCRIPT)

    def test_fixed_ack_reader_and_stage_preflight_scripts_parse(self):
        ast.parse(supervisor._REMOTE_OWNER_ACK_READ_SCRIPT)
        ast.parse(supervisor._REMOTE_OWNER_STAGE_PREFLIGHT_SCRIPT)
        ast.parse(supervisor._REMOTE_OWNER_VERIFIER_PUBLISH_SCRIPT)

    def test_ack_reader_is_fixed_path_and_validates_bounded_provenance(self):
        ack = {"schema_version": 1, "sequence": 2, "action": "drain"}
        provenance = {"uid": self.uid, "gid": self.gid, "mode": 0o600,
                      "size": 40, "mtime_ns": 123, "sha256": "a" * 64,
                      "metadata_stable": True}
        frame = {"schema_version": 1, "event": "owner_ack_read", "ack": ack,
                 "provenance": provenance}
        calls = []
        def remote(_client, script, args, **kwargs):
            calls.append((script, tuple(args), kwargs["output_limit"]))
            return json.dumps(frame, separators=(",", ":")).encode()
        with patch.object(supervisor, "_remote_script", side_effect=remote):
            actual_ack, actual_provenance = supervisor._read_owner_ack(
                object(), job_root=self.job_root, uid=self.uid, gid=self.gid,
                password=None, deadline=self.deadline)
        self.assertEqual(actual_ack, ack)
        self.assertEqual(actual_provenance, provenance)
        self.assertIs(calls[0][0], supervisor._REMOTE_OWNER_ACK_READ_SCRIPT)
        self.assertEqual(calls[0][1], (self.job_root + "/owner-ack.json", "1000", "1000", "0"))
        self.assertEqual(calls[0][2], supervisor.CONTROL_LIMIT)
        for field, invalid in (("metadata_stable", 1), ("size", 1.0),
                               ("sha256", "A" * 64)):
            broken = dict(frame)
            broken["provenance"] = dict(provenance, **{field: invalid})
            with patch.object(supervisor, "_remote_script",
                              return_value=json.dumps(broken).encode()):
                with self.assertRaises(supervisor.SupervisorError):
                    supervisor._read_owner_ack(
                        object(), job_root=self.job_root, uid=self.uid, gid=self.gid,
                        password=None, deadline=self.deadline)


@unittest.skipUnless(os.name == "posix", "owner ACK reader requires POSIX dirfd semantics")
class OwnerAckReaderScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.uid, self.gid = os.geteuid(), os.getegid()
        self.path = self.root / "owner-ack.json"
        self.intent_root = self.root / "owner-intents"
        self.intent_root.mkdir(mode=0o700)
        os.chmod(self.intent_root, 0o700)

    def tearDown(self):
        self.temp.cleanup()

    def run_reader(self):
        return subprocess.run(
            [sys.executable, "-c", supervisor._REMOTE_OWNER_ACK_READ_SCRIPT,
             str(self.path), str(self.uid), str(self.gid), "0"],
            text=True, capture_output=True, timeout=3)

    def test_reads_exact_ack_with_stable_provenance(self):
        raw = b'{"action":"drain","sequence":3}'
        self.path.write_bytes(raw)
        os.chmod(self.path, 0o600)
        result = self.run_reader()
        self.assertEqual(result.returncode, 0, result.stderr)
        frame = json.loads(result.stdout)
        self.assertEqual(frame["ack"], {"action": "drain", "sequence": 3})
        self.assertEqual(frame["provenance"]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertIs(frame["provenance"]["metadata_stable"], True)

    def test_rejects_duplicate_nonfinite_and_fifo_ack_without_blocking(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            self.path.write_bytes(raw)
            os.chmod(self.path, 0o600)
            result = self.run_reader()
            self.assertEqual(result.returncode, 96, result.stderr)
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        result = self.run_reader()
        self.assertEqual(result.returncode, 93, result.stderr)
        self.assertEqual(result.stdout, "")

    def run_sidecar_verifier(self, hashes):
        return subprocess.run(
            [sys.executable, "-c", supervisor._REMOTE_OWNER_SIDECAR_VERIFY_SCRIPT,
             str(self.intent_root), str(self.uid), str(self.gid),
             hashes["snapshot.pub"], hashes["install-intent.json"],
             hashes["removal-intent.json"]],
            text=True, capture_output=True, timeout=3)

    def test_sidecar_verifier_reads_exact_retained_public_material(self):
        materials = {
            "snapshot.pub": b"public verifier bytes",
            "install-intent.json": b'{"intent":"install"}',
            "removal-intent.json": b'{"intent":"remove"}',
        }
        for name, raw in materials.items():
            path = self.intent_root / name
            path.write_bytes(raw)
            os.chmod(path, 0o600)
        hashes = {name: hashlib.sha256(raw).hexdigest()
                  for name, raw in materials.items()}
        result = self.run_sidecar_verifier(hashes)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt, {
            "schema_version": 1,
            "event": "owner_intent_sidecar_verified",
            "files": hashes,
        })

        (self.intent_root / "unexpected.json").write_bytes(b"extra")
        os.chmod(self.intent_root / "unexpected.json", 0o600)
        rejected = self.run_sidecar_verifier(hashes)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, "")


if __name__ == "__main__":
    unittest.main()
