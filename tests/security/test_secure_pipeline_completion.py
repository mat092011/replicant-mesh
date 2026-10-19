"""Opt-in real mTLS completion and interleaving checks for C1a.

The tests inherit the pinned local pipeline fixture. Their gates pause only
after real worker calls or real CPU execution; the scheduled interleaving is a
correctness fixture and is not evidence of compute overlap.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest

if __package__:
    from . import test_secure_pipeline as _pipeline
else:
    import test_secure_pipeline as _pipeline


CPU_GATE_WAIT_SECONDS = 30.0
PIPELINE_GATE_WAIT_SECONDS = 30.0
CLEANUP_WAIT_SECONDS = 12.0
UNKNOWN_EXPIRY_WAIT_SECONDS = 12.5
MAX_RETAINED_FENCED_OWNERS = 2
_RETAINED_FENCED_OWNERS = []
CHILD_MARKER = "STEAMBOAT_C1A_COMPLETION_CHILD"
CHILD_CASE = "secure-cancel-restart-fence-v1"
CHILD_TIMEOUT_SECONDS = 180.0
MAX_CHILD_REPORT_BYTES = 4096


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate child report key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value):
    raise ValueError(f"nonfinite child report number: {value}")


def _parse_child_report(payload):
    if type(payload) is not bytes or len(payload) > MAX_CHILD_REPORT_BYTES:
        raise ValueError("child report must be bounded bytes")
    report = json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_json_keys,
        parse_constant=_reject_nonfinite_json_constant)
    fields = {
        "schema", "case", "session_id", "coordinator_close",
        "cancelled_monotonic_ns", "restart_required", "coordinator_ready",
        "coordinator_active_requests", "model_active_compute",
        "worker_active_compute", "worker_sessions_empty", "worker_queue_sizes",
        "worker_bridge_owned_sessions", "worker_active_authorizations",
        "worker_cached_bytes", "contexts_retained", "step_attempts",
        "token_events", "disposal",
    }
    if type(report) is not dict or set(report) != fields:
        raise ValueError("child report has an invalid field set")
    if type(report["schema"]) is not int or report["schema"] != 1:
        raise ValueError("child report schema must be integer 1")
    if type(report["case"]) is not str or report["case"] != CHILD_CASE:
        raise ValueError("child report case identity is invalid")
    if (type(report["session_id"]) is not str
            or _pipeline.TYPED_SESSION.fullmatch(report["session_id"]) is None):
        raise ValueError("child report session identity is invalid")
    if (type(report["cancelled_monotonic_ns"]) is not int
            or report["cancelled_monotonic_ns"] <= 0):
        raise ValueError("child report cancellation monotonic timestamp is invalid")
    if (type(report["coordinator_close"]) is not str
            or report["coordinator_close"] != "false_restart_fence"):
        raise ValueError("child report did not preserve close(False)")
    for field, expected in (("restart_required", True),
                            ("coordinator_ready", False),
                            ("model_active_compute", False)):
        if type(report[field]) is not bool or report[field] is not expected:
            raise ValueError(f"child report {field} is invalid")
    if (type(report["coordinator_active_requests"]) is not int
            or report["coordinator_active_requests"] != 1):
        raise ValueError("child report must retain its one restart-fenced request")
    for field in ("worker_active_compute", "worker_sessions_empty"):
        values = report[field]
        expected = False if field == "worker_active_compute" else True
        if (type(values) is not list or len(values) != 3
                or any(type(value) is not bool or value is not expected
                       for value in values)):
            raise ValueError(f"child report {field} is invalid")
    for field in ("worker_queue_sizes", "worker_bridge_owned_sessions",
                  "worker_active_authorizations", "worker_cached_bytes"):
        values = report[field]
        if (type(values) is not list or len(values) != 3
                or any(type(value) is not int or value != 0 for value in values)):
            raise ValueError(f"child report {field} is invalid")
    if type(report["contexts_retained"]) is not bool or not report["contexts_retained"]:
        raise ValueError("child report did not retain context owners to child exit")
    if (type(report["step_attempts"]) is not list
            or report["step_attempts"] != [1, 0, 0]
            or any(type(value) is not int for value in report["step_attempts"])):
        raise ValueError("child report shows a replayed or advanced Step")
    if type(report["token_events"]) is not int or report["token_events"] != 0:
        raise ValueError("child report exposes a token after cancellation")
    if (type(report["disposal"]) is not str
            or report["disposal"] != "confirmed_by_child_process_exit_only"):
        raise ValueError("child report disposal claim is invalid")
    return report


def _exception_leaves(error):
    if isinstance(error, BaseExceptionGroup):
        for nested in error.exceptions:
            yield from _exception_leaves(nested)
    else:
        yield error


def _expected_forced_rows(test, reference, torch, prompt, new_tokens):
    vocabulary_size = 32_000
    for forced_token in (vocabulary_size - 1, vocabulary_size - 2):
        reference_input = prompt + [forced_token] * (new_tokens - 1)
        input_tensor = torch.tensor([reference_input], dtype=torch.long)
        with torch.inference_mode():
            output = reference(input_ids=input_tensor, use_cache=False,
                               return_dict=True)
            rows = output.logits[0, len(prompt) - 1:].detach().clone()
            first_greedy_token = int(rows[0].argmax().item())
        del output, input_tensor
        if first_greedy_token != forced_token:
            test.assertEqual(tuple(rows.shape), (new_tokens, vocabulary_size))
            test.assertTrue(bool(torch.isfinite(rows).all().item()))
            return forced_token, rows
        del rows
    raise AssertionError("reference first token matched both fixed forced-feedback candidates")


async def _wait_for_worker_retirement(test, handler, *, timeout_seconds,
                                     description):
    await _pipeline._wait_until(
        lambda: not handler.supervision_status()["active_compute"],
        timeout_seconds=timeout_seconds, description=description)
    compute_task = handler._compute_task
    if compute_task is not None:
        test.assertTrue(compute_task.done(), "supervised worker compute task is still owned")


def _worker_retirement_snapshot(worker_nodes):
    snapshot = {
        "active_compute": [],
        "sessions_empty": [],
        "queue_sizes": [],
        "bridge_owned_sessions": [],
        "active_authorizations": [],
        "cached_bytes": [],
    }
    for node in worker_nodes:
        handler = node["handler"]
        bridge = node["bridge"]
        tombstones = tuple(handler.tombstones.values())
        active_cache_bytes = sum(
            entry.cache.allocated_bytes()
            for entry in (*handler.sessions.values(), *tombstones))
        snapshot["active_compute"].append(
            handler.supervision_status()["active_compute"])
        snapshot["sessions_empty"].append(not handler.sessions)
        snapshot["queue_sizes"].append(len(handler._queue))
        snapshot["bridge_owned_sessions"].append(
            bridge.status()["owned_sessions"])
        snapshot["active_authorizations"].append(
            bridge.status()["active_authorizations"])
        snapshot["cached_bytes"].append(active_cache_bytes)
    return snapshot


def _workers_physically_retired(worker_nodes):
    snapshot = _worker_retirement_snapshot(worker_nodes)
    return (
        snapshot["active_compute"] == [False, False, False]
        and snapshot["sessions_empty"] == [True, True, True]
        and snapshot["queue_sizes"] == [0, 0, 0]
        and snapshot["bridge_owned_sessions"] == [0, 0, 0]
        and snapshot["active_authorizations"] == [0, 0, 0]
        and snapshot["cached_bytes"] == [0, 0, 0]
    )


def _install_restart_fenced_cleanup(test, pipeline, session_id, *,
                                    contexts, cancelled_monotonic_ns,
                                    step_attempts, events):
    """Record the real fence and retain its owner until the child process exits."""
    coordinator = pipeline["coordinator"]
    actions = pipeline["cleanup_owner"]._actions
    action = next((item for item in actions
                   if item["active"] and item["label"] == "coordinator close"), None)
    if action is None:
        raise AssertionError("base pipeline cleanup owner lacks coordinator close action")
    if len(_RETAINED_FENCED_OWNERS) >= MAX_RETAINED_FENCED_OWNERS:
        raise RuntimeError("bounded cancellation cleanup owner registry is full")

    original_close = action["callback"]
    owner = {
        "pipeline": pipeline,
        "session_id": session_id,
        "coordinator": coordinator,
        "model": coordinator.model,
        "workers": tuple({
            "handler": node["handler"],
            "executor": node["executor"],
            "bridge": node["bridge"],
            "server": node["server"],
        } for node in pipeline["worker_nodes"]),
        "worker_clients": tuple(coordinator.clients),
        "coordinator_client": pipeline["coordinator_client"],
        "contexts": tuple(contexts),
        "service": pipeline["service"],
        "secure_service": pipeline["secure_service"],
        "capture_budget": pipeline["capture_budget"],
        "transport_budget": pipeline["transport_budget"],
        "consumer_outbound": pipeline["consumer_outbound"],
        "failure": None,
    }
    _RETAINED_FENCED_OWNERS.append(owner)

    async def close_after_worker_retirement():
        try:
            result = await asyncio.wait_for(original_close(), timeout=5.0)
            test.assertIs(result, False)
            state = coordinator._requests.get(session_id)
            test.assertIsNotNone(state)
            test.assertIs(state.restart_required, True)
            test.assertIs(coordinator.stats()["ready"], False)
            test.assertTrue(coordinator._closed)
            test.assertTrue(all(task.done() for task in coordinator._consumers))
            test.assertTrue(all(job is None for job in coordinator._active_jobs))
            test.assertFalse(any(coordinator.stats()["stage_queue_sizes"]))
            test.assertIs(
                coordinator.model.supervision_status()["active_compute"], False)
            workers = _worker_retirement_snapshot(pipeline["worker_nodes"])
            test.assertEqual(workers["active_compute"], [False, False, False])
            test.assertEqual(workers["sessions_empty"], [True, True, True])
            test.assertEqual(workers["queue_sizes"], [0, 0, 0])
            test.assertEqual(workers["bridge_owned_sessions"], [0, 0, 0])
            test.assertEqual(workers["active_authorizations"], [0, 0, 0])
            test.assertEqual(workers["cached_bytes"], [0, 0, 0])
            test.assertEqual(coordinator.stats()["active_requests"], 1)
            report_path = os.environ.get("STEAMBOAT_C1A_COMPLETION_REPORT")
            if os.environ.get(CHILD_MARKER) != CHILD_CASE or not report_path:
                raise RuntimeError("restart-fenced cancellation requires child supervision")
            report = {
                "schema": 1,
                "case": CHILD_CASE,
                "session_id": session_id,
                "coordinator_close": "false_restart_fence",
                "cancelled_monotonic_ns": cancelled_monotonic_ns,
                "restart_required": state.restart_required,
                "coordinator_ready": coordinator.stats()["ready"],
                "coordinator_active_requests": coordinator.stats()["active_requests"],
                "model_active_compute": coordinator.model.supervision_status()["active_compute"],
                "worker_active_compute": workers["active_compute"],
                "worker_sessions_empty": workers["sessions_empty"],
                "worker_queue_sizes": workers["queue_sizes"],
                "worker_bridge_owned_sessions": workers["bridge_owned_sessions"],
                "worker_active_authorizations": workers["active_authorizations"],
                "worker_cached_bytes": workers["cached_bytes"],
                "contexts_retained": len(contexts) > 0,
                "step_attempts": list(step_attempts),
                "token_events": sum(event.get("type") == "token" for event in events),
                "disposal": "confirmed_by_child_process_exit_only",
            }
            payload = json.dumps(report, sort_keys=True, separators=(",", ":"))
            if len(payload.encode("utf-8")) > MAX_CHILD_REPORT_BYTES:
                raise RuntimeError("cancellation child report exceeds bounded size")
            Path(report_path).write_text(payload, encoding="utf-8")
            # None records the expected fixture fence; only parent-observed
            # process exit confirms disposal of this retained owner.
            return None
        except BaseException as error:
            owner["failure"] = type(error).__name__
            raise

    action["label"] = "cancellation restart fence after worker retirement"
    action["callback"] = close_after_worker_retirement


class _FixedOutbound:
    def __init__(self, context):
        self.context = context

    def create_consumer_request_context(self, *, lifetime_seconds):
        if lifetime_seconds != 120:
            raise AssertionError("pipeline helper requested an unexpected context lifetime")
        return self.context


class SecureGenerateCancellationCompletionTests(
        _pipeline.SecurePipelinePositiveTests):
    async def _run_lifecycle_extensions(self, pipeline):
        coordinator = pipeline["coordinator"]
        worker = pipeline["worker_nodes"][0]
        handler = worker["handler"]
        executor = worker["executor"]
        original_stage_execute = executor.execute
        gate_entered = threading.Event()
        gate_release = threading.Event()
        consumer_tasks = []
        owned_contexts = []
        step_attempts = [0, 0, 0]
        step_replies = []
        session_ids_by_request = {}
        observed_clients = []
        restored = {"value": False}
        fenced_context_retained = {"value": False}
        cancelled_monotonic_ns = None

        def execute_after_real_cache_mutation(hidden, cache, position):
            result = original_stage_execute(hidden, cache, position)
            gate_entered.set()
            if not gate_release.wait(CPU_GATE_WAIT_SECONDS):
                raise TimeoutError("bounded worker CPU completion gate expired")
            return result

        def restore_observers():
            if restored["value"]:
                return
            if handler.supervision_status()["active_compute"]:
                raise RuntimeError(
                    "cannot restore executor while its real CPU future is active")
            executor.execute = original_stage_execute
            for client, original in reversed(observed_clients):
                client.execute = original
            restored["value"] = True

        async def cancel_and_join_consumer():
            for task in consumer_tasks:
                if not task.done():
                    task.cancel()
            if consumer_tasks:
                done, pending = await asyncio.wait(
                    consumer_tasks, timeout=CLEANUP_WAIT_SECONDS)
                if pending:
                    raise RuntimeError("cancelled Generate task did not retire boundedly")
                await asyncio.gather(*done, return_exceptions=True)

        def close_contexts():
            if handler.supervision_status()["active_compute"]:
                raise RuntimeError(
                    "cannot close consumer context while worker CPU is still owned")
            if any(not task.done() for task in consumer_tasks):
                raise RuntimeError(
                    "cannot close consumer context while Generate is still owned")
            if fenced_context_retained["value"]:
                return None
            for context in owned_contexts:
                context.close()

        async def wait_for_cpu_retirement():
            await _wait_for_worker_retirement(
                self, handler, timeout_seconds=CLEANUP_WAIT_SECONDS,
                description="real worker CPU future retirement after gate release")

        owner = pipeline["cleanup_owner"]
        restore_action = owner.add("restore cancellation CPU observer", restore_observers)
        context_action = owner.add("close cancellation consumer context", close_contexts)
        task_action = owner.add("cancel and join cancellation Generate", cancel_and_join_consumer)
        cpu_action = owner.add("wait for cancellation CPU future retirement",
                               wait_for_cpu_retirement)
        gate_action = owner.add("release cancellation CPU gate", gate_release.set)

        executor.execute = execute_after_real_cache_mutation
        try:
            from steamboat_runtime.participant_context import TrustedRequestContext

            for index, client in enumerate(coordinator.clients):
                original = client.execute
                observed_clients.append((client, original))

                async def observed(method, request, *args, _index=index,
                                   _original=original, **kwargs):
                    if method == "Step":
                        trusted_context = kwargs.get("trusted_request_context")
                        self.assertIsInstance(trusted_context, TrustedRequestContext)
                        step_attempts[_index] += 1
                        previous = session_ids_by_request.setdefault(
                            trusted_context.request_id, request.session_id)
                        self.assertEqual(previous, request.session_id)
                    response = await _original(method, request, *args, **kwargs)
                    if method == "Step":
                        step_replies.append((_index, request.session_id,
                                             request.sequence, response.code))
                    return response

                client.execute = observed

            context = pipeline["consumer_outbound"].create_consumer_request_context(
                lifetime_seconds=30)
            owned_contexts.append(context)
            self.assertRegex(context.request_id, _pipeline.TYPED_REQUEST)
            stream = pipeline["coordinator_client"].generate(
                [7, 13, 31], 1, trusted_request_context=context,
                capture_logits=False, timeout_seconds=10)
            events = []

            async def consume_until_terminal():
                async for event in stream:
                    event.pop("logits", None)
                    events.append(dict(event))

            consumer = asyncio.create_task(consume_until_terminal())
            consumer_tasks.append(consumer)

            await _pipeline._wait_until(
                gate_entered.is_set, timeout_seconds=CPU_GATE_WAIT_SECONDS,
                description="real worker CPU operation after cache mutation")
            session_id = session_ids_by_request.get(context.request_id)
            self.assertRegex(session_id or "", _pipeline.TYPED_SESSION,
                             "real worker Step did not expose the admitted session id")
            entry = handler.sessions.get(session_id)
            self.assertIsNotNone(entry, "real worker session disappeared before CPU retirement")
            self.assertIs(entry.in_flight, True)
            self.assertTrue(any(entry.cache.lengths()),
                            "worker cache was not mutated before the gate")
            self.assertGreater(entry.cache.allocated_bytes(), 0)
            self.assertIs(handler.supervision_status()["active_compute"], True)
            self.assertIsNotNone(handler._compute_task)
            self.assertFalse(handler._compute_task.done())
            self.assertEqual(step_attempts, [1, 0, 0])
            self.assertEqual(step_replies, [])

            binding_key = worker["bindings"].key_for({
                "target_device_id": worker["principal"].device_id,
                "worker_boot_id": worker["principal"].boot_id,
                "session_id": session_id,
            })
            binding_record = worker["bindings"]._records.get(binding_key)
            self.assertIsNotNone(binding_record,
                                 "actual worker C0 session owner record is missing")
            original_hard_expiry = binding_record.hard_expiry_monotonic

            cancelled_monotonic_ns = time.monotonic_ns()
            consumer.cancel()
            self.assertGreater(consumer.cancelling(), 0)
            await _pipeline._wait_until(
                lambda: ((state := coordinator._requests.get(session_id)) is not None
                         and state.abort_error is not None),
                timeout_seconds=2.0,
                description="real secure caller cancellation reaching its request")
            cancelled_state = coordinator._requests.get(session_id)
            self.assertEqual(cancelled_state.abort_error.code, "CANCELLED")
            await _pipeline._wait_until(
                lambda: (handler.sessions.get(session_id) is entry
                         and entry.in_flight
                         and handler.supervision_status()["active_compute"]),
                timeout_seconds=2.0,
                description="resource retention while caller cancellation is delivered")
            self.assertEqual(events, [], "cancelled Generate exposed stale output")
            self.assertEqual(step_attempts, [1, 0, 0],
                             "cancelled Generate retried or advanced a worker Step")
            self.assertGreater(entry.cache.allocated_bytes(), 0)
            self.assertIsNot(binding_record.reclaimed, True,
                             "C0 owner was reclaimed before its worker CPU future retired")
            self.assertGreaterEqual(pipeline["service"].active_streams, 1)
            self.assertGreaterEqual(pipeline["secure_service"].active_generate_streams, 1)

            gate_release.set()
            await _wait_for_worker_retirement(
                self, handler, timeout_seconds=CLEANUP_WAIT_SECONDS,
                description="actual worker CPU future after cancellation")
            done, pending = await asyncio.wait((consumer,), timeout=CLEANUP_WAIT_SECONDS)
            self.assertFalse(pending, "cancelled secure consumer did not unwind boundedly")
            if consumer.cancelled():
                consumer_error = asyncio.CancelledError()
            else:
                consumer_error = consumer.exception()
            from steamboat_runtime.protocol.secure_transport import SecureTaskPending

            pending_failure = any(isinstance(error, SecureTaskPending)
                                 for error in _exception_leaves(consumer_error)
                                 if error is not None)
            cancellation_observed = (
                consumer.cancelled()
                or any(isinstance(error, asyncio.CancelledError)
                       for error in _exception_leaves(consumer_error)
                       if error is not None)
                or any(getattr(error, "code", None) == "CANCELLED"
                       for error in _exception_leaves(consumer_error)
                       if error is not None))
            self.assertTrue(cancellation_observed,
                            "Generate did not report the caller's cancellation")
            self.assertEqual(events, [], "cancelled Generate exposed stale output")
            self.assertEqual(step_attempts, [1, 0, 0],
                             "cancelled Generate retried or advanced a worker Step")

            await _pipeline._wait_until(
                lambda: (session_id not in handler.sessions
                         and worker["bridge"].status()["owned_sessions"] == 0
                         and worker["bridge"].status()["active_authorizations"] == 0),
                timeout_seconds=CLEANUP_WAIT_SECONDS,
                description="worker cache, session binding and RPC authorization cleanup")
            tombstone = handler.tombstones.get(session_id)
            self.assertIsNotNone(tombstone)
            self.assertEqual(tombstone.committed_bytes, 0)
            self.assertEqual(tombstone.cache.allocated_bytes(), 0)
            self.assertFalse(any(tombstone.cache.lengths()))

            await _pipeline._wait_until(
                lambda: (session_id not in coordinator._requests
                         or ((state := coordinator._requests.get(session_id)) is not None
                             and state.restart_required
                             and not coordinator.stats()["ready"])),
                timeout_seconds=CLEANUP_WAIT_SECONDS,
                description="bounded cancellation cleanup or explicit coordinator restart fence")
            state = coordinator._requests.get(session_id)
            if state is None:
                self.assertFalse(pending_failure,
                                 "pending transport ownership disappeared without a fence")
                await self._assert_request_reclaimed(
                    coordinator=coordinator, service=pipeline["service"],
                    secure_service=pipeline["secure_service"],
                    worker_nodes=pipeline["worker_nodes"],
                    capture_budget=pipeline["capture_budget"],
                    transport_budget=pipeline["transport_budget"])
            else:
                self.assertTrue(pending_failure or state.restart_required)
                self.assertIs(state.restart_required, True)
                self.assertIs(coordinator.stats()["ready"], False)
                self.assertTrue(state.completion.done())
                self.assertIs(type(cancelled_monotonic_ns), int)
                fenced_context_retained["value"] = True
                _install_restart_fenced_cleanup(
                    self, pipeline, session_id, contexts=owned_contexts,
                    cancelled_monotonic_ns=cancelled_monotonic_ns,
                    step_attempts=step_attempts, events=events)
                if not binding_record.reclaimed:
                    await _pipeline._wait_until(
                        lambda: (time.monotonic() >= original_hard_expiry
                                 and session_id not in handler.sessions
                                 and binding_record.state == "tombstone"
                                 and binding_record.reclaimed is True),
                        timeout_seconds=UNKNOWN_EXPIRY_WAIT_SECONDS,
                        description="unknown worker owner hard expiry and core reclamation")
                    tombstone = handler.tombstones.get(session_id)
                    self.assertIsNotNone(tombstone)
                    self.assertGreaterEqual(
                        tombstone.monotonic_terminated_at, original_hard_expiry)
                    self.assertEqual(binding_record.invalid_reason,
                                     "session-hard-expiry")
                self.assertIs(binding_record.reclaimed, True)
                self.assertEqual(binding_record.state, "tombstone")
                self.assertTrue(state.restart_required,
                                "worker expiry must not clear the coordinator restart fence")
                await _pipeline._wait_until(
                    lambda: _workers_physically_retired(pipeline["worker_nodes"]),
                    timeout_seconds=CLEANUP_WAIT_SECONDS,
                    description="physical worker session, compute, queue, and cache retirement")
                workers = _worker_retirement_snapshot(pipeline["worker_nodes"])
                self.assertEqual(workers["active_compute"], [False, False, False])
                self.assertEqual(workers["sessions_empty"], [True, True, True])
                self.assertEqual(workers["queue_sizes"], [0, 0, 0])
                self.assertEqual(workers["bridge_owned_sessions"], [0, 0, 0])
                self.assertEqual(workers["active_authorizations"], [0, 0, 0])
                self.assertEqual(workers["cached_bytes"], [0, 0, 0])
                self.assertEqual(coordinator.stats()["active_requests"], 1)
        finally:
            gate_release.set()
            for task in consumer_tasks:
                if not task.done():
                    task.cancel()
            await wait_for_cpu_retirement()
            if consumer_tasks:
                done, pending = await asyncio.wait(
                    consumer_tasks, timeout=CLEANUP_WAIT_SECONDS)
                if pending:
                    raise RuntimeError("consumer task remains live after gate release")
                await asyncio.gather(*done, return_exceptions=True)
            close_contexts()
            restore_observers()
            for action in (restore_action, context_action, task_action,
                           cpu_action, gate_action):
                owner.disarm(action)


@unittest.skipUnless(
    _pipeline.ENABLED,
    "Set STEAMBOAT_SECURE_PIPELINE_TESTS=1 for the opt-in offline mTLS model path",
)
class SecureGenerateCancellationProcessTests(unittest.TestCase):
    def test_fenced_cancellation_owner_is_disposed_by_confirmed_child_exit(self):
        if os.environ.get(CHILD_MARKER) == CHILD_CASE:
            self.fail("cancellation child marker prevents recursive supervision")

        child_test = (
            "SecureGenerateCancellationCompletionTests."
            "test_consumer_generate_crosses_real_secure_three_stage_pipeline")
        with tempfile.TemporaryDirectory(prefix="steamboat-c1a-cancel-") as temp_dir:
            report_path = Path(temp_dir) / "child-report.json"
            environment = os.environ.copy()
            environment[CHILD_MARKER] = CHILD_CASE
            environment["STEAMBOAT_C1A_COMPLETION_REPORT"] = str(report_path)
            child_output = bytearray()
            child = subprocess.Popen(
                [sys.executable, "-B", "-m", "unittest",
                 f"tests.security.test_secure_pipeline_completion.{child_test}"],
                cwd=str(Path(__file__).resolve().parents[2]),
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            def drain_child_output():
                while True:
                    chunk = child.stdout.read(2048)
                    if not chunk:
                        return
                    child_output.extend(chunk)
                    if len(child_output) > 8192:
                        del child_output[:-8192]

            output_reader = threading.Thread(target=drain_child_output, daemon=True)
            output_reader.start()
            timed_out = False
            try:
                child.wait(timeout=CHILD_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
                child.kill()
                child.wait(timeout=10.0)
            output_reader.join(timeout=5.0)
            child.stdout.close()
            diagnostic = bytes(child_output).decode("utf-8", "replace")[-8192:]
            self.assertFalse(
                output_reader.is_alive(), "child output reader did not retire boundedly")
            self.assertFalse(
                timed_out,
                "cancellation child exceeded bounded runtime and was killed; "
                f"bounded child tail:\n{diagnostic}")
            self.assertEqual(
                child.returncode, 0,
                "child cancellation assertions or teardown failed; "
                f"bounded child tail:\n{diagnostic}")
            self.assertTrue(report_path.is_file(), "child did not write its bounded result report")
            self.assertLessEqual(report_path.stat().st_size, MAX_CHILD_REPORT_BYTES)
            child_exit_monotonic_ns = time.monotonic_ns()
            report = _parse_child_report(report_path.read_bytes())
            self.assertIsNotNone(child.poll(), "child process exit was not confirmed")
            elapsed_ns = child_exit_monotonic_ns - report["cancelled_monotonic_ns"]
            self.assertGreaterEqual(elapsed_ns, 0)
            self.assertLessEqual(
                elapsed_ns, 40_000_000_000,
                "confirmed child disposal exceeded the 40-second same-host lifecycle bound")


class ChildReportParserTests(unittest.TestCase):
    def test_rejects_duplicate_keys_aliases_extra_fields_and_unbounded_input(self):
        valid = {
            "schema": 1,
            "case": CHILD_CASE,
            "session_id": "ses_" + "a" * 32,
            "coordinator_close": "false_restart_fence",
            "cancelled_monotonic_ns": 1,
            "restart_required": True,
            "coordinator_ready": False,
            "coordinator_active_requests": 1,
            "model_active_compute": False,
            "worker_active_compute": [False, False, False],
            "worker_sessions_empty": [True, True, True],
            "worker_queue_sizes": [0, 0, 0],
            "worker_bridge_owned_sessions": [0, 0, 0],
            "worker_active_authorizations": [0, 0, 0],
            "worker_cached_bytes": [0, 0, 0],
            "contexts_retained": True,
            "step_attempts": [1, 0, 0],
            "token_events": 0,
            "disposal": "confirmed_by_child_process_exit_only",
        }
        encoded = json.dumps(valid, separators=(",", ":")).encode("utf-8")
        self.assertEqual(_parse_child_report(encoded), valid)
        malformed = (
            (b'{"schema":1,"schema":1}', "duplicate"),
            (encoded.replace(b'"schema":1', b'"schema":true'), "schema alias"),
            (encoded.replace(b'"cancelled_monotonic_ns":1',
                             b'"cancelled_monotonic_ns":true'), "timestamp alias"),
            (encoded[:-1] + b',"extra":0}', "extra field"),
            (encoded.replace(b'"coordinator_ready":false',
                             b'"coordinator_ready":NaN'), "nonfinite"),
            (b" " * (MAX_CHILD_REPORT_BYTES + 1), "oversized"),
        )
        for payload, label in malformed:
            with self.subTest(label=label), self.assertRaises(ValueError):
                _parse_child_report(payload)


class SecureForcedInterleavingCompletionTests(
        _pipeline.SecurePipelinePositiveTests):
    async def _run_lifecycle_extensions(self, pipeline):
        torch = pipeline["torch"]
        coordinator = pipeline["coordinator"]
        client = pipeline["coordinator_client"]
        outbound = pipeline["consumer_outbound"]
        prompts = {
            "A": [7, 13, 31],
            "B": [11, 23, 37, 47, 59, 61, 71],
        }
        output_lengths = {"A": 5, "B": 11}
        expected = {}
        for label in ("A", "B"):
            forced_token, rows = _expected_forced_rows(
                self, pipeline["reference"], torch,
                prompts[label], output_lengths[label])
            expected[label] = (forced_token, rows)
        contexts = {}
        labels_by_request = {}
        sessions_by_label = {}

        a_prefill_stage1_reached = asyncio.Event()
        release_a_prefill_stage1 = asyncio.Event()
        phase_order = []
        completed_steps = []
        consumer_tasks = []
        observed_clients = []
        restore_state = {"done": False}
        owner = pipeline["cleanup_owner"]

        def release_all_gates():
            release_a_prefill_stage1.set()

        def restore_observers():
            if restore_state["done"]:
                return
            if any(not task.done() for task in consumer_tasks):
                raise RuntimeError("cannot restore Step observers while Generate tasks remain")
            for wrapped, original in reversed(observed_clients):
                wrapped.execute = original
            restore_state["done"] = True

        async def cancel_and_join_consumers():
            for task in consumer_tasks:
                if not task.done():
                    task.cancel()
            if consumer_tasks:
                done, pending = await asyncio.wait(
                    consumer_tasks, timeout=CLEANUP_WAIT_SECONDS)
                if pending:
                    raise RuntimeError("interleaved Generate task did not retire boundedly")
                await asyncio.gather(*done, return_exceptions=True)

        async def wait_for_worker_compute_retirement():
            for node in pipeline["worker_nodes"]:
                await _wait_for_worker_retirement(
                    self, node["handler"], timeout_seconds=CLEANUP_WAIT_SECONDS,
                    description=("real worker CPU retirement for interleaved request "
                                 f"on worker {node['principal'].device_id}"))

        def close_contexts():
            if any(not task.done() for task in consumer_tasks):
                raise RuntimeError(
                    "cannot close consumer contexts while Generate is still owned")
            if any(node["handler"].supervision_status()["active_compute"]
                   for node in pipeline["worker_nodes"]):
                raise RuntimeError(
                    "cannot close consumer contexts while worker CPU is still owned")
            for context in contexts.values():
                context.close()

        restore_action = owner.add("restore interleaved Step observers", restore_observers)
        context_action = owner.add("close interleaved consumer contexts", close_contexts)
        task_action = owner.add("cancel and join interleaved Generate tasks",
                                cancel_and_join_consumers)
        compute_action = owner.add("wait for interleaved worker CPU retirement",
                                   wait_for_worker_compute_retirement)
        gate_action = owner.add("release interleaved real Step reply gates",
                                release_all_gates)

        try:
            from steamboat_runtime.participant_context import TrustedRequestContext
            from steamboat_runtime.protocol.worker_pb2 import Response

            contexts.update({
                label: outbound.create_consumer_request_context(lifetime_seconds=120)
                for label in ("A", "B")
            })
            self.assertNotEqual(contexts["A"].request_id, contexts["B"].request_id)
            labels_by_request.update({context.request_id: label
                                      for label, context in contexts.items()})

            for index, worker_client in enumerate(coordinator.clients):
                original = worker_client.execute
                observed_clients.append((worker_client, original))

                async def observed(method, request, *args, _index=index,
                                   _original=original, **kwargs):
                    response = await _original(method, request, *args, **kwargs)
                    if method != "Step":
                        return response
                    trusted_context = kwargs.get("trusted_request_context")
                    self.assertIsInstance(trusted_context, TrustedRequestContext)
                    self.assertIs(type(response), Response)
                    self.assertEqual(response.code, "OK")
                    self.assertEqual(response.session_id, request.session_id)
                    label = labels_by_request.get(trusted_context.request_id)
                    self.assertIn(label, ("A", "B"))
                    previous_session = sessions_by_label.setdefault(
                        label, request.session_id)
                    self.assertEqual(previous_session, request.session_id)
                    record = {
                        "label": label,
                        "worker": _index + 1,
                        "sequence": request.sequence,
                        "start_position": request.start_position,
                        "token_count": request.token_count,
                        "response_code": response.code,
                    }
                    completed_steps.append(record)
                    if _index == 2 and request.sequence in (0, 1):
                        phase_order.append((label, request.sequence))
                    if (_index == 0 and label == "A" and request.sequence == 0
                            and not a_prefill_stage1_reached.is_set()):
                        a_prefill_stage1_reached.set()
                        await asyncio.wait_for(
                            release_a_prefill_stage1.wait(),
                            timeout=PIPELINE_GATE_WAIT_SECONDS)
                    return response

                worker_client.execute = observed

            def compare_event(label, event):
                if event["type"] != "token":
                    return
                forced_token, expected_rows = expected[label]
                index = event["index"]
                self.assertGreaterEqual(index, 0)
                self.assertLess(index, output_lengths[label])
                self.assertEqual(event["sequence"], index)
                self.assertEqual(event["position"], len(prompts[label]) + index)
                self.assertEqual(len(event["logits"]), 32_000)
                actual = torch.tensor(event["logits"], dtype=torch.float32)
                row = expected_rows[index]
                maximum_error = float(torch.max(torch.abs(actual - row)).item())
                self.assertTrue(bool(torch.isfinite(actual).all().item()))
                self.assertTrue(bool(torch.allclose(actual, row, atol=1e-3, rtol=0.0)),
                                msg=(f"{label} reference logits differ at {index}: "
                                     f"max_abs_error={maximum_error}"))
                self.assertEqual(event["token_id"], int(row.argmax().item()))
                del actual

            async def run_request(label):
                forced_token, _rows = expected[label]
                return await self._secure_generate(
                    client, _FixedOutbound(contexts[label]), prompts[label],
                    new_tokens=output_lengths[label],
                    forced_tokens=[forced_token] * (output_lengths[label] - 1),
                    capture_logits=True,
                    on_token=lambda event: compare_event(label, event))

            task_a = asyncio.create_task(run_request("A"))
            consumer_tasks.append(task_a)
            await _pipeline._wait_until(
                a_prefill_stage1_reached.is_set,
                timeout_seconds=PIPELINE_GATE_WAIT_SECONDS,
                description="A prefill's real stage-1 Step reply")
            self.assertIn("A", sessions_by_label)

            task_b = asyncio.create_task(run_request("B"))
            consumer_tasks.append(task_b)
            await _pipeline._wait_until(
                lambda: any(
                    job.sequence == 0
                    and job.request.trusted_request_context.request_id
                    == contexts["B"].request_id
                    for job in coordinator._queues[0].items),
                timeout_seconds=PIPELINE_GATE_WAIT_SECONDS,
                description="B prefill queued at real stage 1 while A's reply is held")
            b_queued = next(
                job for job in coordinator._queues[0].items
                if job.sequence == 0
                and job.request.trusted_request_context.request_id
                == contexts["B"].request_id)
            self.assertRegex(b_queued.request.session_id, _pipeline.TYPED_SESSION)
            sessions_by_label["B"] = b_queued.request.session_id
            self.assertEqual(b_queued.request.trusted_request_context.request_id,
                             contexts["B"].request_id)
            release_a_prefill_stage1.set()

            release_all_gates()
            (context_a, events_a), (context_b, events_b) = await asyncio.gather(
                task_a, task_b)
            self.assertIs(context_a, contexts["A"])
            self.assertIs(context_b, contexts["B"])
            for label, context, events in (
                    ("A", context_a, events_a), ("B", context_b, events_b)):
                count = output_lengths[label]
                self.assertRegex(context.request_id, _pipeline.TYPED_REQUEST)
                self.assertEqual([event["type"] for event in events],
                                 ["token"] * count + ["result"])
                tokens = events[:-1]
                terminal = events[-1]
                self.assertEqual(terminal["status"], "completed")
                self.assertIs(terminal["cleanup_complete"], True)
                self.assertRegex(sessions_by_label[label], _pipeline.TYPED_SESSION)
                self.assertEqual(terminal["session_id"], sessions_by_label[label])
                self.assertEqual(terminal["token_ids"],
                                 [event["token_id"] for event in tokens])
                self.assertEqual(len(tokens), count)

            self.assertEqual(phase_order,
                             [("A", 0), ("B", 0), ("A", 1), ("B", 1)])
            expected_sequences = {
                "A": list(range(output_lengths["A"])),
                "B": list(range(output_lengths["B"])),
            }
            for label in ("A", "B"):
                prompt_length = len(prompts[label])
                for worker_index in (1, 2, 3):
                    records = [item for item in completed_steps
                               if item["label"] == label
                               and item["worker"] == worker_index]
                    self.assertEqual([item["sequence"] for item in records],
                                     expected_sequences[label])
                    self.assertTrue(all(item["response_code"] == "OK"
                                        for item in records))
                    self.assertEqual([item["start_position"] for item in records],
                                     [0] + [prompt_length + index - 1
                                            for index in range(1, output_lengths[label])])
                    self.assertEqual([item["token_count"] for item in records],
                                     [prompt_length] + [1] * (output_lengths[label] - 1))
            await self._assert_request_reclaimed(
                coordinator=coordinator, service=pipeline["service"],
                secure_service=pipeline["secure_service"],
                worker_nodes=pipeline["worker_nodes"],
                capture_budget=pipeline["capture_budget"],
                transport_budget=pipeline["transport_budget"])
        finally:
            release_all_gates()
            for task in consumer_tasks:
                if not task.done():
                    task.cancel()
            await wait_for_worker_compute_retirement()
            if consumer_tasks:
                done, pending = await asyncio.wait(
                    consumer_tasks, timeout=CLEANUP_WAIT_SECONDS)
                if pending:
                    raise RuntimeError("interleaved Generate owner remains live after gate release")
                await asyncio.gather(*done, return_exceptions=True)
            close_contexts()
            restore_observers()
            for action in (restore_action, context_action, task_action,
                           compute_action, gate_action):
                owner.disarm(action)


def load_tests(loader, _tests, _pattern):
    """Keep the child-only fixture out of ordinary discovery."""
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(
        SecureGenerateCancellationProcessTests))
    suite.addTests(loader.loadTestsFromTestCase(
        SecureForcedInterleavingCompletionTests))
    suite.addTests(loader.loadTestsFromTestCase(ChildReportParserTests))
    return suite


if __name__ == "__main__":
    import unittest

    unittest.main()
