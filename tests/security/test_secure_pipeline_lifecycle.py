"""Opt-in authenticated lifecycle extensions for the real pipeline harness.

This subclasses the existing mTLS/model test so each invocation owns one real
identity cohort, one coordinator/reference model, and the same three workers.
"""

from __future__ import annotations

import asyncio
import gc
import threading
import unittest
from unittest.mock import patch


if __package__:
    from . import test_secure_pipeline as _pipeline
else:
    import test_secure_pipeline as _pipeline


VOCABULARY_SIZE = 32_000
MAX_POSITIONS = 1_152
CAPTURE_ACTIVE_LIMIT = 8
_REQUEST_ID = _pipeline.TYPED_REQUEST
_SESSION_ID = _pipeline.TYPED_SESSION


def _patterned_prompt(length: int, offset: int) -> list[int]:
    if type(length) is not int or not 1 <= length <= MAX_POSITIONS + 1:
        raise ValueError("prompt length is outside the supported or boundary-probe range")
    if type(offset) is not int or offset < 0:
        raise ValueError("prompt offset must be a nonnegative integer")
    return [3 + ((index * 37 + offset) % (VOCABULARY_SIZE - 3))
            for index in range(length)]


def _reference_last_row(reference, torch, input_ids):
    input_tensor = torch.tensor([input_ids], dtype=torch.long)
    with torch.inference_mode():
        output = reference(input_ids=input_tensor, use_cache=False,
                           return_dict=True)
        last_row = output.logits[0, -1].detach().clone()
    del output, input_tensor
    return last_row


def _reference_greedy(reference, torch, prompt_ids, token_count):
    """Compute unforced autoregressive feedback with the pinned full model."""
    sequence = list(prompt_ids)
    generated = []
    for _ in range(token_count):
        input_tensor = torch.tensor([sequence], dtype=torch.long)
        with torch.inference_mode():
            output = reference(input_ids=input_tensor, use_cache=False,
                               return_dict=True)
            token_id = int(output.logits[0, -1].argmax().item())
        del output, input_tensor
        generated.append(token_id)
        sequence.append(token_id)
    return generated


def _reference_forced_rows(reference, torch, prompt_ids, forced_count):
    """Return only expected last-position rows for repeated forced feedback."""
    for forced_token in (VOCABULARY_SIZE - 1, VOCABULARY_SIZE - 2,
                         VOCABULARY_SIZE - 3):
        reference_input = list(prompt_ids) + [forced_token] * forced_count
        input_tensor = torch.tensor([reference_input], dtype=torch.long)
        with torch.inference_mode():
            output = reference(input_ids=input_tensor, use_cache=False,
                               return_dict=True)
            rows = output.logits[0, len(prompt_ids) - 1:].detach().clone()
            first_greedy_token = int(rows[0].argmax().item())
        del output, input_tensor
        if first_greedy_token != forced_token:
            if tuple(rows.shape) != (forced_count + 1, VOCABULARY_SIZE):
                raise AssertionError("reference forced rows have the wrong shape")
            return forced_token, rows
        del rows
    raise AssertionError("could not choose forced feedback distinct from the first greedy token")


async def _drain_tasks(tasks, *, timeout_seconds: float = 150.0):
    """Boundedly join owned request tasks, cancelling and joining on timeout."""
    tasks = tuple(tasks)
    if not tasks:
        return ()
    _done, pending = await asyncio.wait(tasks, timeout=timeout_seconds)
    if pending:
        for task in pending:
            task.cancel()
        _done, pending = await asyncio.wait(pending, timeout=30.0)
    if pending:
        raise AssertionError("owned secure Generate task did not stop within its bound")
    return tuple(await asyncio.gather(*tasks, return_exceptions=True))


def _raise_task_errors(outcomes, description: str) -> None:
    errors = [outcome for outcome in outcomes if isinstance(outcome, BaseException)]
    if errors:
        raise BaseExceptionGroup(description, errors)


class SecurePipelineLifecycleTests(_pipeline.SecurePipelinePositiveTests):
    """Run lifecycle models as extensions of the authenticated positive case."""

    async def _assert_reclaimed(self, pipeline):
        await self._assert_request_reclaimed(
            coordinator=pipeline["coordinator"],
            service=pipeline["service"],
            secure_service=pipeline["secure_service"],
            worker_nodes=pipeline["worker_nodes"],
            capture_budget=pipeline["capture_budget"],
            transport_budget=pipeline["transport_budget"],
        )

    def _assert_capture_rows(self, torch, expected_rows, prompt_length,
                             records, *, start_index=0):
        def compare(event):
            index = len(records)
            self.assertLess(index, len(expected_rows))
            self.assertEqual(len(event["logits"]), VOCABULARY_SIZE)
            actual = torch.tensor(event["logits"], dtype=torch.float32)
            expected = expected_rows[index]
            self.assertTrue(bool(torch.isfinite(actual).all().item()))
            self.assertTrue(bool(torch.allclose(
                actual, expected, atol=1e-3, rtol=0.0)),
                msg=(f"captured row differs: prompt={prompt_length}, "
                     f"row={index}, max_abs="
                     f"{float(torch.max(torch.abs(actual - expected)).item())}"))
            self.assertEqual(event["index"], start_index + index)
            self.assertEqual(event["sequence"], start_index + index)
            self.assertEqual(event["position"], prompt_length + start_index + index)
            self.assertEqual(event["token_id"], int(expected.argmax().item()))
            records.append((event["index"], event["sequence"],
                            event["position"], event["token_id"]))
            del actual
        return compare

    def _assert_terminal_events(self, context, events, *, prompt_length,
                                new_tokens):
        self.assertRegex(context.request_id, _REQUEST_ID)
        self.assertEqual([event["type"] for event in events],
                         ["token"] * new_tokens + ["result"])
        tokens, terminal = events[:-1], events[-1]
        self.assertEqual(len(tokens), new_tokens)
        self.assertTrue(all("logits" not in event for event in tokens))
        self.assertTrue(all(_SESSION_ID.fullmatch(event["session_id"])
                            for event in tokens))
        session_id = tokens[0]["session_id"]
        self.assertTrue(all(event["session_id"] == session_id for event in tokens))
        self.assertEqual(terminal["session_id"], session_id)
        self.assertEqual(terminal["status"], "completed")
        self.assertIs(terminal["cleanup_complete"], True)
        token_ids = [event["token_id"] for event in tokens]
        self.assertEqual(terminal["token_ids"], token_ids)
        self.assertEqual(len(token_ids), new_tokens)
        self.assertEqual([event["index"] for event in tokens], list(range(new_tokens)))
        self.assertEqual([event["sequence"] for event in tokens], list(range(new_tokens)))
        self.assertEqual([event["position"] for event in tokens],
                         [prompt_length + index for index in range(new_tokens)])
        return context.request_id, session_id, token_ids

    async def _run_lifecycle_extensions(self, pipeline):
        torch = pipeline["torch"]
        reference = pipeline["reference"]
        client = pipeline["coordinator_client"]
        outbound = pipeline["consumer_outbound"]
        coordinator = pipeline["coordinator"]
        cleanup_owner = pipeline["cleanup_owner"]
        request_ids = []
        session_ids = []

        # Observe only the narrow pre-tensor Coordinator admission boundary.
        # This calls the original production method unchanged.
        original_submit = coordinator.submit
        submit_count = [0]

        def restore_submit_observer():
            coordinator.submit = original_submit

        submit_action = cleanup_owner.add(
            "restore lifecycle Coordinator.submit observation",
            restore_submit_observer)

        def observed_submit(*args, **kwargs):
            submit_count[0] += 1
            return original_submit(*args, **kwargs)

        coordinator.submit = observed_submit

        try:
            await self._test_exact_context_boundary(pipeline, submit_count,
                                                    request_ids, session_ids)
            await self._test_over_boundary_is_rejected_before_tensor_work(
                pipeline, submit_count)
            await self._test_unforced_greedy_matches_complete_reference(
                pipeline, request_ids, session_ids)
            await self._test_unequal_concurrent_forced_requests_match_references(
                pipeline, request_ids, session_ids)
            await self._test_eight_active_capture_admission_and_ninth_rejection(
                pipeline, submit_count, request_ids, session_ids)
            self.assertEqual(len(request_ids), len(set(request_ids)))
            self.assertEqual(len(session_ids), len(set(session_ids)))
            self.assertTrue(all(_REQUEST_ID.fullmatch(item) for item in request_ids))
            self.assertTrue(all(_SESSION_ID.fullmatch(item) for item in session_ids))
            cleanup_owner.disarm(submit_action)
        finally:
            if not submit_action["active"]:
                coordinator.submit = original_submit

    async def _test_exact_context_boundary(self, pipeline, submit_count,
                                           request_ids, session_ids):
        torch = pipeline["torch"]
        prompt = _patterned_prompt(1_151, 53)
        self.assertEqual(len(prompt) + 1, MAX_POSITIONS)
        self.assertLessEqual(min(prompt), VOCABULARY_SIZE - 1)
        expected = _reference_last_row(pipeline["reference"], torch, prompt)
        self.assertEqual(tuple(expected.shape), (VOCABULARY_SIZE,))
        records = []
        context, events = await self._secure_generate(
            pipeline["coordinator_client"], pipeline["consumer_outbound"], prompt,
            new_tokens=1, capture_logits=True,
            on_token=self._assert_capture_rows(torch, expected.unsqueeze(0),
                                               len(prompt), records))
        request_id, session_id, _tokens = self._assert_terminal_events(
            context, events, prompt_length=len(prompt), new_tokens=1)
        self.assertEqual(records, [(0, 0, 1_151, events[0]["token_id"])])
        self.assertEqual(events[0]["token_id"], int(expected.argmax().item()))
        request_ids.append(request_id)
        session_ids.append(session_id)
        del expected
        gc.collect()
        await self._assert_reclaimed(pipeline)
        self.assertGreaterEqual(submit_count[0], 1)

    async def _test_over_boundary_is_rejected_before_tensor_work(
            self, pipeline, submit_count):
        from steamboat_runtime.remote_client import RemoteError
        from steamboat_security import ConsumerRequestContext

        torch = pipeline["torch"]
        client = pipeline["coordinator_client"]
        outbound = pipeline["consumer_outbound"]
        cases = (
            (_patterned_prompt(1_153, 61), 1),
            (_patterned_prompt(1_152, 59), 2),
        )
        before_submit = submit_count[0]
        before_requests = pipeline["coordinator"].stats()["active_requests"]
        before_capture = pipeline["capture_budget"].status()
        before_secure_streams = pipeline["secure_service"].active_generate_streams
        before_service_streams = pipeline["service"].active_streams

        for input_ids, new_tokens in cases:
            context = outbound.create_consumer_request_context(lifetime_seconds=30)
            self.assertIs(type(context), ConsumerRequestContext)
            try:
                with patch.object(
                        torch, "tensor",
                        side_effect=AssertionError(
                            "over-bound request reached tensor allocation")) as tensor_call:
                    with self.assertRaises(RemoteError) as rejected:
                        async for _event in client.generate(
                                input_ids, new_tokens,
                                trusted_request_context=context,
                                capture_logits=True, timeout_seconds=30):
                            self.fail("over-bound Generate unexpectedly emitted an event")
                    self.assertEqual(rejected.exception.code, "INVALID_INPUT")
                    tensor_call.assert_not_called()
            finally:
                context.close()

        self.assertEqual(submit_count[0], before_submit)
        self.assertEqual(pipeline["coordinator"].stats()["active_requests"],
                         before_requests)
        self.assertEqual(pipeline["secure_service"].active_generate_streams,
                         before_secure_streams)
        self.assertEqual(pipeline["service"].active_streams, before_service_streams)
        self.assertEqual(pipeline["capture_budget"].status(), before_capture)
        self.assertTrue(all(not node["handler"].sessions
                            for node in pipeline["worker_nodes"]))

    async def _test_unforced_greedy_matches_complete_reference(
            self, pipeline, request_ids, session_ids):
        prompt = _patterned_prompt(17, 23)
        expected = _reference_greedy(
            pipeline["reference"], pipeline["torch"], prompt, 4)
        context, events = await self._secure_generate(
            pipeline["coordinator_client"], pipeline["consumer_outbound"], prompt,
            new_tokens=4, capture_logits=False)
        request_id, session_id, token_ids = self._assert_terminal_events(
            context, events, prompt_length=len(prompt), new_tokens=4)
        self.assertEqual(token_ids, expected)
        request_ids.append(request_id)
        session_ids.append(session_id)
        await self._assert_reclaimed(pipeline)

    async def _test_unequal_concurrent_forced_requests_match_references(
            self, pipeline, request_ids, session_ids):
        cases = ((5, 37), (11, 41))
        prepared = []
        for prompt_length, offset in cases:
            prompt = _patterned_prompt(prompt_length, offset)
            forced_token, expected_rows = _reference_forced_rows(
                pipeline["reference"], pipeline["torch"], prompt, 3)
            prepared.append((prompt, forced_token, expected_rows))

        tasks = []
        cleanup_owner = pipeline["cleanup_owner"]

        async def drain_concurrent_tasks():
            outcomes = await _drain_tasks(tasks)
            _raise_task_errors(outcomes, "concurrent authenticated Generate failures")

        task_action = cleanup_owner.add(
            "join unequal concurrent authenticated Generate tasks",
            drain_concurrent_tasks)

        async def run_one(prompt, forced_token, expected_rows):
            records = []
            context, events = await self._secure_generate(
                pipeline["coordinator_client"], pipeline["consumer_outbound"], prompt,
                new_tokens=4, forced_tokens=[forced_token] * 3,
                capture_logits=True,
                on_token=self._assert_capture_rows(
                    pipeline["torch"], expected_rows, len(prompt), records))
            request_id, session_id, token_ids = self._assert_terminal_events(
                context, events, prompt_length=len(prompt), new_tokens=4)
            self.assertEqual(len(records), 4)
            self.assertNotEqual(forced_token, records[0][3])
            self.assertEqual([record[3] for record in records], token_ids)
            return request_id, session_id

        try:
            for prompt, forced_token, expected_rows in prepared:
                tasks.append(asyncio.create_task(
                    run_one(prompt, forced_token, expected_rows)))
            outcomes = await _drain_tasks(tasks)
            _raise_task_errors(outcomes, "unequal concurrent Generate failures")
            for outcome in outcomes:
                request_id, session_id = outcome
                request_ids.append(request_id)
                session_ids.append(session_id)
            await self._assert_reclaimed(pipeline)
            cleanup_owner.disarm(task_action)
        finally:
            for _prompt, _forced_token, expected_rows in prepared:
                del expected_rows
            gc.collect()

    async def _test_eight_active_capture_admission_and_ninth_rejection(
            self, pipeline, submit_count, request_ids, session_ids):
        from steamboat_runtime.remote_client import RemoteError
        import re

        torch = pipeline["torch"]
        prompt = _patterned_prompt(1, 83)
        expected = _reference_last_row(pipeline["reference"], torch, prompt)
        nodes = pipeline["worker_nodes"]
        first_executor = nodes[0]["executor"]
        original_execute = first_executor.execute
        loop = asyncio.get_running_loop()
        entered = asyncio.Event()
        release = threading.Event()
        request_tasks = []
        cleanup_owner = pipeline["cleanup_owner"]

        def restore_execute():
            first_executor.execute = original_execute

        execute_action = cleanup_owner.add(
            "restore real first-stage execution boundary", restore_execute)

        async def drain_request_tasks():
            outcomes = await _drain_tasks(request_tasks)
            _raise_task_errors(outcomes, "eight active capture Generate failures")

        tasks_action = cleanup_owner.add(
            "join eight active capture Generate tasks", drain_request_tasks)
        release_action = cleanup_owner.add(
            "release held first-stage result", release.set)

        def execute_and_hold_real_result(hidden, cache, position):
            # Run the production stage computation and keep its real result and
            # mutated KV cache owned by the in-flight worker operation.
            result = original_execute(hidden, cache, position)
            loop.call_soon_threadsafe(entered.set)
            if not release.wait(timeout=90):
                raise TimeoutError("test-only first-stage result hold expired")
            return result

        first_executor.execute = execute_and_hold_real_result
        start_submit_count = submit_count[0]
        case_primary = None
        case_cleanup_errors = []
        try:
            for _index in range(CAPTURE_ACTIVE_LIMIT):
                records = []
                request_tasks.append(asyncio.create_task(
                    self._secure_generate(
                        pipeline["coordinator_client"],
                        pipeline["consumer_outbound"], prompt,
                        new_tokens=1, capture_logits=True,
                        on_token=self._assert_capture_rows(
                            torch, expected.unsqueeze(0), len(prompt), records))))

            await _pipeline._wait_until(
                lambda: (entered.is_set()
                         and submit_count[0] == start_submit_count + CAPTURE_ACTIVE_LIMIT
                         and pipeline["coordinator"].stats()["active_requests"]
                         == CAPTURE_ACTIVE_LIMIT
                         and pipeline["capture_budget"].status().active_captures
                         == CAPTURE_ACTIVE_LIMIT
                         and all(len(node["handler"].sessions)
                                 == CAPTURE_ACTIVE_LIMIT for node in nodes)),
                timeout_seconds=90,
                description="eight authenticated capture requests held at first stage",
            )

            status = pipeline["capture_budget"].status()
            self.assertEqual(status.active_captures, CAPTURE_ACTIVE_LIMIT)
            self.assertEqual(status.reserved_bytes,
                             CAPTURE_ACTIVE_LIMIT * status.per_capture.total_bytes)
            self.assertEqual(pipeline["secure_service"].active_generate_streams,
                             CAPTURE_ACTIVE_LIMIT)
            self.assertEqual(pipeline["service"].active_streams,
                             CAPTURE_ACTIVE_LIMIT)
            self.assertEqual(pipeline["coordinator"].stats()["active_requests"],
                             CAPTURE_ACTIVE_LIMIT)
            self.assertEqual(pipeline["coordinator"].stats()["waiting_admissions"], 0)
            for node in nodes:
                handler = node["handler"]
                self.assertEqual(len(handler.sessions), CAPTURE_ACTIVE_LIMIT)
                self.assertEqual(sum(item.max_positions
                                     for item in handler.sessions.values()),
                                 CAPTURE_ACTIVE_LIMIT * 2)
                self.assertTrue(all(
                    re.fullmatch(r"ses_[0-9a-f]{32}", session_id)
                    for session_id in handler.sessions))

            first_handler = nodes[0]["handler"]
            self.assertIs(first_handler.supervision_status()["active_compute"], True)
            in_flight = [entry for entry in first_handler.sessions.values()
                         if entry.in_flight]
            self.assertEqual(len(in_flight), 1)
            self.assertEqual(in_flight[0].cache.lengths(), [1] *
                             (nodes[0]["executor"].end - nodes[0]["executor"].start))
            self.assertGreater(in_flight[0].cache.allocated_bytes(), 0)
            self.assertEqual(in_flight[0].committed_bytes, 0)
            for node in nodes[1:]:
                self.assertTrue(all(not any(entry.cache.lengths())
                                    for entry in node["handler"].sessions.values()))
            transport = pipeline["transport_budget"]
            self.assertEqual(transport.reserved_connections, 16)
            self.assertEqual(transport.reserved_pending, 0)
            self.assertEqual(transport.reserved_outbound_pending, 0)

            before_ninth_submit = submit_count[0]
            before_ninth_ids = status.used_request_ids
            with self.assertRaises(RemoteError) as rejected:
                await self._secure_generate(
                    pipeline["coordinator_client"], pipeline["consumer_outbound"],
                    prompt, new_tokens=1, capture_logits=True)
            self.assertEqual(rejected.exception.code, "CAPACITY_EXHAUSTED")
            self.assertEqual(submit_count[0], before_ninth_submit)
            await _pipeline._wait_until(
                lambda: (pipeline["secure_service"].active_generate_streams
                         == CAPTURE_ACTIVE_LIMIT
                         and pipeline["service"].active_streams
                         == CAPTURE_ACTIVE_LIMIT),
                timeout_seconds=10,
                description="rejected ninth stream releases its trusted admission slot",
            )
            self.assertEqual(pipeline["capture_budget"].status().active_captures,
                             CAPTURE_ACTIVE_LIMIT)
            self.assertEqual(pipeline["capture_budget"].status().used_request_ids,
                             before_ninth_ids)
            self.assertEqual(pipeline["coordinator"].stats()["active_requests"],
                             CAPTURE_ACTIVE_LIMIT)
            self.assertEqual(pipeline["coordinator"].stats()["waiting_admissions"], 0)
            self.assertTrue(all(len(node["handler"].sessions)
                                == CAPTURE_ACTIVE_LIMIT for node in nodes))
            self.assertEqual(transport.reserved_connections, 16)
            self.assertEqual(transport.reserved_pending, 0)

            release.set()
            outcomes = await _drain_tasks(request_tasks, timeout_seconds=150)
            _raise_task_errors(outcomes, "eight active capture Generate failures")
            for context, events in outcomes:
                request_id, session_id, token_ids = self._assert_terminal_events(
                    context, events, prompt_length=1, new_tokens=1)
                self.assertEqual(token_ids, [int(expected.argmax().item())])
                request_ids.append(request_id)
                session_ids.append(session_id)
            self.assertEqual(len({item[0] for item in outcomes}),
                             CAPTURE_ACTIVE_LIMIT)
            returned_sessions = [events[0]["session_id"] for _context, events in outcomes]
            self.assertEqual(len(set(returned_sessions)),
                             CAPTURE_ACTIVE_LIMIT)
            await self._assert_reclaimed(pipeline)
        except BaseException as error:
            case_primary = error
        finally:
            release.set()
            try:
                cleanup_outcomes = await _drain_tasks(
                    request_tasks, timeout_seconds=150)
                task_errors = [item for item in cleanup_outcomes
                               if isinstance(item, BaseException)]
                if task_errors:
                    case_cleanup_errors.append(BaseExceptionGroup(
                        "held first-stage request cleanup errors", task_errors))
            except BaseException as error:
                case_cleanup_errors.append(error)
            try:
                restore_execute()
            except BaseException as error:
                case_cleanup_errors.append(error)
            else:
                cleanup_owner.disarm(execute_action)
            if not case_cleanup_errors:
                cleanup_owner.disarm(tasks_action)
                cleanup_owner.disarm(release_action)
            del expected
            gc.collect()

        if case_primary is not None and case_cleanup_errors:
            raise BaseExceptionGroup(
                "capture admission assertion and teardown failures",
                [case_primary, *case_cleanup_errors])
        if case_primary is not None:
            raise case_primary.with_traceback(case_primary.__traceback__)
        if case_cleanup_errors:
            raise BaseExceptionGroup("capture admission teardown failures",
                                     case_cleanup_errors)
