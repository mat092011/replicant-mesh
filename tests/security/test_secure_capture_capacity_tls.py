"""Opt-in C0/native-TLS capture capacity regression using the real model fixture."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys


_TESTS_DIRECTORY = Path(__file__).resolve().parent
if str(_TESTS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIRECTORY))

from test_secure_pipeline import (
    SecurePipelinePositiveTests as _SecurePipelinePositiveTests,
)


class SecureCaptureCapacityTlsPositiveTests(_SecurePipelinePositiveTests):
    async def _run_lifecycle_extensions(self, pipeline):
        from steamboat_runtime.capture_budget import CaptureBudget
        from steamboat_runtime.remote_client import RemoteError

        torch = pipeline["torch"]
        coordinator = pipeline["coordinator"]
        coordinator_client = pipeline["coordinator_client"]
        secure_service = pipeline["secure_service"]
        service = pipeline["service"]
        original_budget = pipeline["capture_budget"]
        self.assertIs(secure_service.capture_budget, original_budget)
        await self._assert_request_reclaimed(
            coordinator=coordinator,
            service=service,
            secure_service=secure_service,
            worker_nodes=pipeline["worker_nodes"],
            capture_budget=original_budget,
            transport_budget=pipeline["transport_budget"],
        )

        small_budget = CaptureBudget(replace(
            original_budget.config,
            capacity_bytes=original_budget.per_capture.total_bytes - 1,
        ))
        self.assertEqual(
            small_budget.config.vocabulary_size,
            coordinator.manifest["config"]["vocab_size"],
        )
        self.assertEqual(
            small_budget.config.output_queue_slots,
            coordinator.limits.output_queue_tokens,
        )
        self.assertLess(
            small_budget.config.capacity_bytes,
            small_budget.per_capture.total_bytes,
        )

        submit = coordinator.submit
        had_submit_override = "submit" in vars(coordinator)
        submit_override = vars(coordinator).get("submit")
        tensor = torch.tensor
        denial_phase = {"active": True}
        submit_phases = []
        tensor_phases = []

        def guarded_submit(*args, **kwargs):
            submit_phases.append(denial_phase["active"])
            if denial_phase["active"]:
                raise AssertionError("capture refusal reached Coordinator.submit")
            return submit(*args, **kwargs)

        def guarded_tensor(*args, **kwargs):
            tensor_phases.append(denial_phase["active"])
            if denial_phase["active"]:
                raise AssertionError("capture refusal allocated a tensor")
            return tensor(*args, **kwargs)

        def restore():
            secure_service.capture_budget = original_budget
            if had_submit_override:
                coordinator.submit = submit_override
            elif "submit" in vars(coordinator):
                delattr(coordinator, "submit")
            torch.tensor = tensor

        cleanup_action = pipeline["cleanup_owner"].add(
            "restore secure capture-capacity regression hooks", restore)
        secure_service.capture_budget = small_budget
        coordinator.submit = guarded_submit
        torch.tensor = guarded_tensor
        try:
            rejected_before = service.counters["rejected_requests"]
            with self.assertRaises(RemoteError) as caught:
                await self._secure_generate(
                    coordinator_client,
                    pipeline["consumer_outbound"],
                    [7, 13, 31],
                    new_tokens=1,
                    capture_logits=True,
                )
            self.assertEqual(caught.exception.code, "CAPACITY_EXHAUSTED")
            self.assertIn("rejected before admission", str(caught.exception))
            self.assertEqual(submit_phases, [])
            self.assertEqual(tensor_phases, [])
            self.assertEqual(
                service.counters["rejected_requests"], rejected_before + 1)
            self.assertFalse(coordinator_client._unavailable)
            small_status = small_budget.status()
            self.assertEqual(small_status.active_captures, 0)
            self.assertEqual(small_status.cleanup_pending_captures, 0)
            self.assertEqual(small_status.reserved_bytes, 0)
            self.assertEqual(small_status.used_request_ids, 0)
            await self._assert_request_reclaimed(
                coordinator=coordinator,
                service=service,
                secure_service=secure_service,
                worker_nodes=pipeline["worker_nodes"],
                capture_budget=original_budget,
                transport_budget=pipeline["transport_budget"],
            )
            self.assertEqual(secure_service._unreclaimed_generate_slots, [])
            self.assertFalse(secure_service.pending_tasks)
            self.assertFalse(coordinator_client._active_calls)

            denial_phase["active"] = False
            context, events = await self._secure_generate(
                coordinator_client,
                pipeline["consumer_outbound"],
                [7, 13, 31],
                new_tokens=1,
                capture_logits=False,
            )
            self.assertEqual([event["type"] for event in events], ["token", "result"])
            self.assertEqual(events[-1]["status"], "completed")
            self.assertRegex(context.request_id, r"^req_[0-9a-f]{32}$")
            self.assertEqual(submit_phases, [False])
            self.assertTrue(tensor_phases)
            self.assertTrue(all(phase is False for phase in tensor_phases))
            self.assertFalse(coordinator_client._unavailable)
            await self._assert_request_reclaimed(
                coordinator=coordinator,
                service=service,
                secure_service=secure_service,
                worker_nodes=pipeline["worker_nodes"],
                capture_budget=original_budget,
                transport_budget=pipeline["transport_budget"],
            )
        finally:
            restore()
            pipeline["cleanup_owner"].disarm(cleanup_action)


del _SecurePipelinePositiveTests
