"""Opt-in real mTLS caller-boundary reply-loss cases for C1a.

These tests inherit the real pipeline fixture and numerical baseline.  The
faults happen only after a successful protobuf response has crossed the real
TLS client call; neither a worker response nor an activation is fabricated.
"""

from __future__ import annotations

import asyncio
import inspect
import re
import time
import unittest


# Keep the imported TestCase behind a module namespace.  unittest discovers
# classes in this module, so importing the class directly would rediscover the
# base integration test here as well.
if __package__:
    from . import test_secure_pipeline as _pipeline
else:
    import test_secure_pipeline as _pipeline


FAULT_REQUEST_TIMEOUT_SECONDS = 10.0
FAULT_CONTEXT_LIFETIME_SECONDS = 30.0
FAULT_PROMPT_LENGTH = 3
FAULT_NEW_TOKENS = 3
OPEN_FAULT_OFFSET = 23
STEP_FAULT_OFFSET = 47
_LEASE = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
FAULT_EXPIRY_PROOF_TIMEOUT_SECONDS = 12.5
FAULT_COORDINATOR_CLOSE_TIMEOUT_SECONDS = 5.0
FAULT_MODEL_CLOSE_TIMEOUT_SECONDS = 5.0
# This module has one partial-Open lifecycle case per unittest run. Keep a
# finite number of failed fixture owners alive until the test process exits;
# dropping an owner after an unconfirmed physical cleanup would be unsafe.
MAX_RETAINED_UNSAFE_FIXTURE_OWNERS = 4
_UNSAFE_FIXTURE_CLEANUP_OWNERS = []


def _patterned_prompt(offset: int) -> list[int]:
    """Small deterministic public token input; never derived from model data."""
    return [3 + ((index * 37 + offset) % (32_000 - 3))
            for index in range(FAULT_PROMPT_LENGTH)]


async def _wait_until(predicate, *, timeout_seconds: float, description: str) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.025)
    raise AssertionError(f"timed out waiting for {description}")


def _assert_hard_expiry_cause(test, *, tombstone, binding_record,
                              original_hard_expiry, now_monotonic):
    """Require worker termination and core reclamation to follow hard expiry."""
    test.assertIn(tombstone.terminal_code, {"CANCELLED", "EXPIRED_SESSION"})
    # These monotonic values are captured by the worker and core in this same
    # process. They are compared only with the original worker/core fixture,
    # never across hosts.
    test.assertGreaterEqual(tombstone.monotonic_terminated_at,
                            original_hard_expiry)
    test.assertEqual(binding_record.state, "tombstone")
    test.assertIs(binding_record.reclaimed, True)
    test.assertEqual(binding_record.invalid_reason, "session-hard-expiry")
    test.assertGreaterEqual(now_monotonic, original_hard_expiry)
    test.assertGreaterEqual(now_monotonic, binding_record.hard_expiry_monotonic)


def _assert_single_open_no_cleanup_retry(test, attempts):
    test.assertEqual([item.get("OpenSession", 0) for item in attempts], [1, 0, 0])
    test.assertEqual([item.get("Step", 0) for item in attempts], [0, 0, 0])
    for method in ("RenewSession", "CancelSession", "CloseSession", "SessionStatus"):
        test.assertEqual([item.get(method, 0) for item in attempts], [0, 0, 0],
                         f"unexpected Open cleanup/retry RPC: {method}")


async def _generate_with_fault_budget(client, outbound, input_ids):
    """Use the supported authenticated Generate API with its own short budget."""
    from steamboat_security import ConsumerRequestContext

    context = outbound.create_consumer_request_context(
        lifetime_seconds=FAULT_CONTEXT_LIFETIME_SECONDS)
    if type(context) is not ConsumerRequestContext:
        raise TypeError("fault Generate requires the actual consumer request context")
    stream = None
    events = []
    primary_error = None
    cleanup_errors = []
    try:
        stream = client.generate(
            input_ids,
            FAULT_NEW_TOKENS,
            trusted_request_context=context,
            capture_logits=False,
            timeout_seconds=FAULT_REQUEST_TIMEOUT_SECONDS,
        )
        async for event in stream:
            if event.get("type") == "token":
                # Fault cases must not retain a generated prefix or logits.
                event.pop("logits", None)
            events.append(dict(event))
    except BaseException as error:
        primary_error = error
    finally:
        if stream is not None:
            try:
                await stream.aclose()
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            context.close()
        except BaseException as error:
            cleanup_errors.append(error)

    if primary_error is not None and cleanup_errors:
        raise BaseExceptionGroup(
            "secure fault Generate and local cleanup both failed",
            [primary_error, *cleanup_errors],
        )
    if cleanup_errors:
        raise BaseExceptionGroup(
            "secure fault Generate local cleanup failed", cleanup_errors)
    if isinstance(primary_error, asyncio.CancelledError):
        raise primary_error.with_traceback(primary_error.__traceback__)
    if primary_error is not None and not isinstance(primary_error, Exception):
        raise primary_error.with_traceback(primary_error.__traceback__)
    return context, events, primary_error


def _install_execute_observers(test, pipeline, *, fault_method: str):
    """Count actual coordinator-to-worker calls and inject one lost reply."""
    from steamboat_runtime.protocol.errors import ERROR_CODES, ProtocolError
    from steamboat_runtime.protocol.worker_pb2 import Response
    from steamboat_runtime.participant_context import TrustedRequestContext

    attempts = [dict() for _ in pipeline["coordinator"].clients]
    observation = {"injected": False, "session_id": None,
                   "open_lifetimes_ms": [[], [], []],
                   "step_commit": None, "coordinator_close_action": None,
                   "first_observer_failure": None}
    originals = []

    try:
        for index, client in enumerate(pipeline["coordinator"].clients):
            original = client.execute
            originals.append((client, original))

            async def observed(method, request, *, trusted_request_context=None,
                               _index=index, _original=original):
                attempts[_index][method] = attempts[_index].get(method, 0) + 1
                if (trusted_request_context is None
                        or type(trusted_request_context) is not TrustedRequestContext):
                    raise AssertionError(
                        "real worker RPC omitted its trusted request context")
                if method == "OpenSession":
                    observation["open_lifetimes_ms"][_index].append(
                        (request.lifetime_ms, request.idle_lease_ms,
                         request.max_positions))

                response = await _original(
                    method, request,
                    trusted_request_context=trusted_request_context)

                if (_index == 0 and method == fault_method
                        and not observation["injected"]):
                    test.assertIs(type(response), Response)
                    test.assertEqual(response.code, "OK")
                    test.assertEqual(response.session_id, request.session_id)
                    test.assertEqual(
                        response.worker_boot_id,
                        pipeline["worker_nodes"][0]["principal"].boot_id)
                    observation["session_id"] = request.session_id

                    if fault_method == "OpenSession":
                        test.assertRegex(request.session_id,
                                         _pipeline.TYPED_SESSION)
                        test.assertRegex(response.lease_token, _LEASE)
                        handler = pipeline["worker_nodes"][0]["handler"]
                        entry = handler.sessions.get(request.session_id)
                        test.assertIsNotNone(
                            entry,
                            "real OpenSession reply preceded physical reservation")
                        test.assertEqual(entry.lease, response.lease_token)
                        test.assertEqual(entry.position, 0)
                        test.assertEqual(tuple(entry.cache.lengths()),
                                         (0,) * len(entry.cache.lengths()))
                        observation["open_reservation"] = {
                            "max_positions": entry.max_positions,
                            "position": entry.position,
                            "allocated_bytes": entry.cache.allocated_bytes(),
                        }
                        binding_key = pipeline["worker_nodes"][0]["bindings"].key_for({
                            "target_device_id": pipeline["worker_nodes"][0]["principal"].device_id,
                            "worker_boot_id": pipeline["worker_nodes"][0]["principal"].boot_id,
                            "session_id": request.session_id,
                        })
                        binding_record = pipeline["worker_nodes"][0]["bindings"]._records.get(
                            binding_key)
                        test.assertIsNotNone(
                            binding_record,
                            "accepted OpenSession lacks its actual core expiry record")
                        open_reply_monotonic = time.monotonic()
                        observation["open_reservation"].update({
                            "open_reply_monotonic": open_reply_monotonic,
                            "core_hard_expiry_monotonic":
                                binding_record.hard_expiry_monotonic,
                            "core_requested_expiry_monotonic":
                                binding_record.requested_expiry_monotonic,
                            "worker_deadline_monotonic": entry.deadline,
                        })
                        observation["injected"] = True
                        _install_fenced_restart_cleanup(
                            test, pipeline, observation, request.session_id)
                    elif fault_method == "Step":
                        handler = pipeline["worker_nodes"][0]["handler"]
                        entry = handler.sessions.get(request.session_id)
                        test.assertIsNotNone(
                            entry, "real Step reply preceded its live worker session")
                        test.assertEqual(response.sequence, request.sequence)
                        test.assertEqual(response.start_position,
                                         request.start_position)
                        test.assertEqual(response.token_count, request.token_count)
                        test.assertEqual(
                            response.end_position,
                            request.start_position + request.token_count)
                        test.assertEqual(response.next_sequence,
                                         request.sequence + 1)
                        test.assertGreater(response.tensor.ByteSize(), 0)
                        lengths = tuple(entry.cache.lengths())
                        allocated_bytes = entry.cache.allocated_bytes()
                        test.assertEqual(
                            entry.position,
                            request.start_position + request.token_count)
                        test.assertEqual(entry.sequence, request.sequence + 1)
                        test.assertEqual(lengths,
                                         (entry.position,) * len(lengths))
                        test.assertGreater(entry.committed_bytes, 0)
                        test.assertEqual(entry.committed_bytes, allocated_bytes)
                        observation["step_commit"] = {
                            "position": entry.position,
                            "sequence": entry.sequence,
                            "cache_lengths": lengths,
                            "committed_bytes": entry.committed_bytes,
                            "allocated_bytes": allocated_bytes,
                            "response_tensor_bytes": response.tensor.ByteSize(),
                        }
                        test.assertEqual(
                            [attempts[worker].get("Step", 0)
                             for worker in (1, 2)], [0, 0])
                        observation["injected"] = True

                    # The TLS client has already validated the actual server
                    # response and completed its authorization.  Raising here
                    # is exactly the caller-boundary reply-loss injection.
                    raise ProtocolError(
                        "EXECUTION_FAILED",
                        f"test fault: successful {fault_method} reply lost at caller boundary",
                    )
                return response

            async def observed_with_provenance(method, request, *,
                                               trusted_request_context=None,
                                               _observed=observed, _index=index):
                try:
                    return await _observed(
                        method, request,
                        trusted_request_context=trusted_request_context)
                except BaseException as error:
                    if (not observation["injected"]
                            and observation["first_observer_failure"] is None):
                        code = None
                        if type(error) is ProtocolError:
                            value = error.code
                            if type(value) is str and value in ERROR_CODES:
                                code = value
                        line = None
                        trace = error.__traceback__
                        for _ in range(64):
                            if trace is None:
                                break
                            filename = trace.tb_frame.f_code.co_filename.rsplit("/", 1)[-1]
                            if filename == "test_secure_pipeline_faults.py":
                                line = trace.tb_lineno
                            trace = trace.tb_next
                        name = type(error).__name__
                        if (type(name) is not str
                                or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name,
                                                re.ASCII) is None):
                            name = "UnknownException"
                        methods = {"Describe", "OpenSession", "RenewSession", "Step",
                                   "CloseSession", "CancelSession", "SessionStatus"}
                        safe_method = (method if type(method) is str and method in methods
                                       else "unknown")
                        observation["first_observer_failure"] = {
                            "worker_index": _index, "method": safe_method,
                            "exception_class": name, "exception_code": code,
                            "test_line": line,
                        }
                    raise

            client.execute = observed_with_provenance
    except BaseException:
        for client, original in reversed(originals):
            client.execute = original
        raise

    def restore():
        for client, original in reversed(originals):
            client.execute = original

    return attempts, observation, restore


def _install_fenced_restart_cleanup(test, pipeline, observation, session_id):
    """Replace only the test fixture's close action for an observed unknown Open.

    Runtime correctly retains the request and refuses to claim cleanup while its
    lease is unknown.  The isolated test fixture may dispose of the coordinator
    only after the worker's original hard lease expires and the bridge confirms
    worker-side reclamation.  This is a fixture teardown fence, not a runtime
    recovery path.
    """
    if observation["coordinator_close_action"] is not None:
        return
    coordinator = pipeline["coordinator"]
    worker = pipeline["worker_nodes"][0]
    actions = pipeline["cleanup_owner"]._actions
    action = next((item for item in actions
                   if item["active"] and item["label"] == "coordinator close"), None)
    if action is None:
        raise AssertionError("base pipeline cleanup owner lacks coordinator close action")
    original_close = action["callback"]
    if len(_UNSAFE_FIXTURE_CLEANUP_OWNERS) >= MAX_RETAINED_UNSAFE_FIXTURE_OWNERS:
        raise RuntimeError("bounded unsafe fixture cleanup registry is full")
    action["label"] = "coordinator fenced restart teardown after worker expiry"
    retained_resources = [coordinator, coordinator.model]
    for node in pipeline.get("worker_nodes", ()):
        retained_resources.extend(
            node.get(name) for name in ("executor", "handler", "bridge", "server")
            if node.get(name) is not None)
    retained_resources.extend(
        pipeline.get(name) for name in (
            "coordinator_client", "consumer_outbound", "service", "secure_service",
            "coordinator_server", "capture_budget", "transport_budget")
        if pipeline.get(name) is not None)
    retained_owner = {
        "pipeline": pipeline,
        "coordinator": coordinator,
        "model": coordinator.model,
        "worker": worker,
        "resources": tuple(retained_resources),
        "session_id": session_id,
        "failure": None,
    }
    _UNSAFE_FIXTURE_CLEANUP_OWNERS.append(retained_owner)

    def release_retained_owner():
        try:
            _UNSAFE_FIXTURE_CLEANUP_OWNERS.remove(retained_owner)
        except ValueError:
            pass

    async def bounded_call(callback, timeout_seconds):
        result = callback()
        if inspect.isawaitable(result):
            result = await asyncio.wait_for(result, timeout=timeout_seconds)
        return result

    def raise_failures(message, failures):
        if len(failures) == 1:
            raise failures[0]
        raise BaseExceptionGroup(message, failures)

    async def close_after_expiry_and_restart_fence():
        proof_error = None
        try:
            await _wait_until(
                lambda: (session_id not in worker["handler"].sessions
                         and worker["bridge"].status()["owned_sessions"] == 0
                         and not worker["bridge"].status()["active_authorizations"]),
                timeout_seconds=FAULT_EXPIRY_PROOF_TIMEOUT_SECONDS,
                description="unknown Open hard-expiry and worker-side reclamation",
            )
            tombstone = worker["handler"].tombstones.get(session_id)
            test.assertIsNotNone(tombstone)
            test.assertEqual(tombstone.committed_bytes, 0)
            test.assertEqual(tombstone.cache.allocated_bytes(), 0)
            test.assertFalse(any(tombstone.cache.lengths()))
            binding_key = worker["bindings"].key_for({
                "target_device_id": worker["principal"].device_id,
                "worker_boot_id": worker["principal"].boot_id,
                "session_id": session_id,
            })
            binding_record = worker["bindings"]._records.get(binding_key)
            test.assertIsNotNone(
                binding_record, "fault-session core binding record is missing")
            open_lifetime_ms, idle_lease_ms, _max_positions = observation[
                "open_lifetimes_ms"][0][0]
            reservation = observation["open_reservation"]
            test.assertLessEqual(idle_lease_ms, open_lifetime_ms)
            expiry_upper_bound = (reservation["open_reply_monotonic"]
                                  + open_lifetime_ms / 1000)
            test.assertLessEqual(reservation["core_hard_expiry_monotonic"],
                                 expiry_upper_bound)
            test.assertLessEqual(reservation["worker_deadline_monotonic"],
                                 expiry_upper_bound)
            _assert_hard_expiry_cause(
                test, tombstone=tombstone, binding_record=binding_record,
                original_hard_expiry=reservation["core_hard_expiry_monotonic"],
                now_monotonic=time.monotonic())
            _assert_single_open_no_cleanup_retry(test, observation["attempts"])
        except BaseException as error:
            proof_error = error

        # Always ask the actual coordinator to close, even if expiry proof or
        # its tombstone assertions failed. Coordinator.close has its own
        # bounded shutdown; this outer timeout also bounds a stuck callback.
        close_error = None
        close_result = None
        try:
            close_result = await bounded_call(
                original_close, FAULT_COORDINATOR_CLOSE_TIMEOUT_SECONDS)
            if close_result is not True and close_result is not False:
                raise AssertionError(
                    "original coordinator close did not return an exact bool")
        except BaseException as error:
            close_error = error

        if proof_error is not None:
            close_summary = (f"raised {close_error!r}" if close_error is not None
                             else f"returned {close_result!r}")
            retained_owner["failure"] = (
                f"expiry/reclamation proof failed: {proof_error!r}; "
                f"coordinator close {close_summary}")
            failures = [proof_error]
            if close_error is not None:
                failures.append(close_error)
            elif close_result is False:
                failures.append(RuntimeError(
                    "original coordinator close did not confirm shutdown"))
            raise_failures(
                "expiry proof and coordinator cleanup both failed", failures)

        if close_error is not None:
            retained_owner["failure"] = f"coordinator close failed: {close_error!r}"
            raise close_error
        if close_result is True:
            release_retained_owner()
            return True

        # The expected restart fence keeps Coordinator.close from closing the
        # local model while the unknown-open request remains retained. Proceed
        # only after checking that the fenced request and all compute work have
        # actually stopped.
        try:
            retained = coordinator._requests.get(session_id)
            test.assertIsNotNone(retained)
            test.assertEqual(retained.unknown_opens, {0})
            test.assertEqual(retained.leases, {})
            test.assertTrue(retained.completion.done())
            test.assertTrue(coordinator._closed)
            test.assertTrue(all(task.done() for task in coordinator._consumers))
            test.assertTrue(all(job is None for job in coordinator._active_jobs))
            test.assertFalse(any(coordinator.stats()["stage_queue_sizes"]))
            test.assertFalse(coordinator.model.supervision_status()["active_compute"])
        except BaseException as error:
            retained_owner["failure"] = f"coordinator retirement proof failed: {error!r}"
            raise

        # Expiry and coordinator shutdown are confirmed, so this harness may
        # close the resident local model. Any non-exact result keeps the strong
        # owner above until the process supervisor terminates the test process.
        try:
            model_close = await bounded_call(
                coordinator.model.close, FAULT_MODEL_CLOSE_TIMEOUT_SECONDS)
            test.assertIs(model_close, True)
        except BaseException as error:
            retained_owner["failure"] = f"model close was not confirmed: {error!r}"
            raise
        release_retained_owner()
        return True

    action["callback"] = close_after_expiry_and_restart_fence
    observation["coordinator_close_action"] = action


class _SecurePipelineFaultMixin:
    async def _run_lifecycle_extensions(self, pipeline):
        raise NotImplementedError

    async def _run_fault(self, pipeline, *, fault_method: str, offset: int,
                         retain_observers_until_cleanup: bool = False):
        if (fault_method == "OpenSession"
                and len(_UNSAFE_FIXTURE_CLEANUP_OWNERS)
                >= MAX_RETAINED_UNSAFE_FIXTURE_OWNERS):
            raise RuntimeError(
                "bounded unsafe fixture cleanup registry is full before Open fault")
        coordinator = pipeline["coordinator"]
        attempts, observation, restore = _install_execute_observers(
            self, pipeline, fault_method=fault_method)
        observation["attempts"] = attempts
        context = None
        events = None
        failure = None
        deferred_restore = False
        try:
            prompt = _patterned_prompt(offset)
            self.assertEqual(prompt, [
                3 + ((index * 37 + offset) % (32_000 - 3))
                for index in range(FAULT_PROMPT_LENGTH)])
            context, events, failure = await _generate_with_fault_budget(
                pipeline["coordinator_client"],
                pipeline["consumer_outbound"], prompt)
            self.assertRegex(context.request_id, _pipeline.TYPED_REQUEST)
            from steamboat_runtime.protocol.errors import ERROR_CODES, ProtocolError
            consumer_class = type(failure).__name__ if failure is not None else None
            if (type(consumer_class) is not str
                    or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", consumer_class,
                                    re.ASCII) is None):
                consumer_class = "UnknownException" if failure is not None else None
            consumer_code = None
            if type(failure) is ProtocolError:
                value = failure.code
                if type(value) is str and value in ERROR_CODES:
                    consumer_code = value
            self.assertTrue(
                observation["injected"],
                "fault did not follow an accepted real TLS response; "
                f"first_observer_failure={observation['first_observer_failure']!r}; "
                f"consumer_exception_class={consumer_class!r}; "
                f"consumer_exception_code={consumer_code!r}")
            self.assertIsNotNone(failure,
                                 "faulted consumer Generate unexpectedly succeeded")
            self.assertEqual(getattr(failure, "code", None), "EXECUTION_FAILED")
            self.assertEqual(
                [event["type"] for event in events if event["type"] == "token"], [])
            self.assertFalse(any(event.get("status") == "completed"
                                 for event in events))
            self.assertLessEqual(
                sum(1 for event in events if event["type"] == "result"), 1)
            self.assertEqual(pipeline["capture_budget"].status().active_captures, 0)
            self.assertEqual(pipeline["capture_budget"].status().reserved_bytes, 0)
            self.assertTrue(all(
                1 <= lifetime <= int(FAULT_REQUEST_TIMEOUT_SECONDS * 1000)
                and 1 <= idle <= lifetime
                and max_positions == FAULT_PROMPT_LENGTH + FAULT_NEW_TOKENS
                for per_worker in observation["open_lifetimes_ms"]
                for lifetime, idle, max_positions in per_worker))
            if retain_observers_until_cleanup:
                pipeline["cleanup_owner"].add(
                    "restore secure fault execution observers", restore)
                deferred_restore = True
            return attempts, observation, context, events, failure
        finally:
            if not deferred_restore:
                restore()


class PartialOpenReplyLossTests(
        _SecurePipelineFaultMixin, _pipeline.SecurePipelinePositiveTests):
    async def _run_lifecycle_extensions(self, pipeline):
        attempts, observation, context, events, failure = await self._run_fault(
            pipeline, fault_method="OpenSession", offset=OPEN_FAULT_OFFSET,
            retain_observers_until_cleanup=True)
        self.assertIsNotNone(failure)
        self.assertEqual(getattr(failure, "code", None), "EXECUTION_FAILED")
        wire_results = [event for event in events if event["type"] == "result"]
        if wire_results:
            self.assertEqual(len(wire_results), 1)
            self.assertEqual(wire_results[0]["status"], "failed")
            self.assertIs(wire_results[0]["cleanup_complete"], False)
            self.assertEqual(wire_results[0]["token_ids"], [])
        session_id = observation["session_id"]
        self.assertRegex(session_id, _pipeline.TYPED_SESSION)
        self.assertEqual([item.get("OpenSession", 0) for item in attempts],
                         [1, 0, 0])
        self.assertEqual([item.get("Step", 0) for item in attempts], [0, 0, 0])
        self.assertEqual(len(observation["open_lifetimes_ms"][0]), 1)
        self.assertEqual(observation["open_lifetimes_ms"][1:], [[], []])
        self.assertEqual(observation["open_reservation"]["max_positions"],
                         FAULT_PROMPT_LENGTH + FAULT_NEW_TOKENS)

        coordinator = pipeline["coordinator"]
        state = coordinator._requests.get(session_id)
        self.assertIsNotNone(state)
        self.assertEqual(state.unknown_opens, {0})
        self.assertEqual(state.leases, {})
        self.assertTrue(state.completion.done())
        result = state.completion.result()
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.error_code, "EXECUTION_FAILED")
        self.assertIs(result.cleanup_complete, False)
        self.assertEqual(result.token_ids, ())
        self.assertTrue(state.restart_required)
        self.assertIs(coordinator.stats()["ready"], False)
        self.assertEqual(coordinator.stats()["active_requests"], 1)

        first = pipeline["worker_nodes"][0]
        entry = first["handler"].sessions.get(session_id)
        self.assertIsNotNone(entry,
                            "unknown Open must remain charged while its lease is live")
        self.assertGreater(entry.deadline, time.monotonic())
        self.assertEqual(entry.position, 0)
        self.assertEqual(entry.cache.allocated_bytes(), 0)
        self.assertFalse(any(entry.cache.lengths()))
        self.assertFalse(pipeline["worker_nodes"][1]["handler"].sessions)
        self.assertFalse(pipeline["worker_nodes"][2]["handler"].sessions)

        secure_service = pipeline["secure_service"]
        await _wait_until(
            lambda: (bool(secure_service._unreclaimed_generate_slots)
                     and secure_service.active_generate_streams >= 1
                     and pipeline["service"].active_streams >= 1),
            timeout_seconds=3,
            description="explicit service ownership for unknown Open cleanup",
        )
        self.assertGreaterEqual(secure_service.active_generate_streams, 1)
        self.assertTrue(secure_service._unreclaimed_generate_slots)
        retained_slot = secure_service._unreclaimed_generate_slots[0]
        self.assertIs(retained_slot["retained"], True)
        self.assertIs(retained_slot["resource_cleanup_confirmed"], False)
        self.assertGreaterEqual(pipeline["service"].active_streams, 1)

        # The sole accepted Open had a bounded 10 second hard lifetime.  Wait
        # for actual worker maintenance and bridge reconciliation; do not clear
        # the coordinator's unknown-open marker or report in-process recovery.
        await _wait_until(
            lambda: (session_id not in first["handler"].sessions
                     and first["bridge"].status()["owned_sessions"] == 0
                     and first["bridge"].status()["active_authorizations"] == 0),
            timeout_seconds=12.5,
            description="partial Open hard expiry and physical reclamation",
        )
        tombstone = first["handler"].tombstones.get(session_id)
        self.assertIsNotNone(tombstone)
        self.assertEqual(tombstone.committed_bytes, 0)
        self.assertEqual(tombstone.cache.allocated_bytes(), 0)
        self.assertFalse(any(tombstone.cache.lengths()))
        binding_key = first["bindings"].key_for({
            "target_device_id": first["principal"].device_id,
            "worker_boot_id": first["principal"].boot_id,
            "session_id": session_id,
        })
        binding_record = first["bindings"]._records.get(binding_key)
        self.assertIsNotNone(
            binding_record, "fault-session core binding record is missing")
        lifetime_ms, idle_lease_ms, _max_positions = observation[
            "open_lifetimes_ms"][0][0]
        reservation = observation["open_reservation"]
        self.assertLessEqual(idle_lease_ms, lifetime_ms)
        expiry_upper_bound = reservation["open_reply_monotonic"] + lifetime_ms / 1000
        self.assertLessEqual(reservation["core_hard_expiry_monotonic"],
                             expiry_upper_bound)
        self.assertLessEqual(reservation["worker_deadline_monotonic"],
                             expiry_upper_bound)
        _assert_hard_expiry_cause(
            self, tombstone=tombstone, binding_record=binding_record,
            original_hard_expiry=reservation["core_hard_expiry_monotonic"],
            now_monotonic=time.monotonic())
        self.assertIs(coordinator._requests.get(session_id), state)
        self.assertEqual(state.unknown_opens, {0})
        self.assertEqual(coordinator.stats()["active_requests"], 1)
        self.assertTrue(secure_service._unreclaimed_generate_slots)
        self.assertEqual(pipeline["capture_budget"].status().reserved_bytes, 0)
        self.assertRegex(context.request_id, _pipeline.TYPED_REQUEST)
        # These counters remain observed through expiry/quarantine, so an Open
        # retry after the initial Generate failure cannot hide in that interval.
        _assert_single_open_no_cleanup_retry(self, attempts)


class MutatingStepReplyLossTests(
        _SecurePipelineFaultMixin, _pipeline.SecurePipelinePositiveTests):
    async def _run_lifecycle_extensions(self, pipeline):
        attempts, observation, context, events, failure = await self._run_fault(
            pipeline, fault_method="Step", offset=STEP_FAULT_OFFSET,
            retain_observers_until_cleanup=True)
        self.assertEqual([item.get("OpenSession", 0) for item in attempts],
                         [1, 1, 1])
        self.assertEqual([item.get("Step", 0) for item in attempts], [1, 0, 0])
        self.assertEqual(len(observation["open_lifetimes_ms"][0]), 1)
        self.assertEqual(len(observation["open_lifetimes_ms"][1]), 1)
        self.assertEqual(len(observation["open_lifetimes_ms"][2]), 1)
        self.assertEqual(len(observation["step_commit"]["cache_lengths"]),
                         len(pipeline["worker_nodes"][0]["handler"].executor.stage.layers))
        self.assertEqual(observation["step_commit"]["position"],
                         FAULT_PROMPT_LENGTH)
        self.assertEqual(observation["step_commit"]["sequence"], 1)
        self.assertEqual(observation["step_commit"]["cache_lengths"],
                         (FAULT_PROMPT_LENGTH,) * len(
                             observation["step_commit"]["cache_lengths"]))
        self.assertGreater(observation["step_commit"]["committed_bytes"], 0)
        self.assertGreater(observation["step_commit"]["allocated_bytes"], 0)
        self.assertGreater(observation["step_commit"]["response_tensor_bytes"], 0)
        self.assertIsNotNone(failure,
                             "mutating Step reply loss must fail Generate")
        self.assertEqual(getattr(failure, "code", None), "EXECUTION_FAILED")
        self.assertEqual([event["type"] for event in events], ["result"])
        terminal = events[0]
        self.assertEqual(terminal["status"], "failed")
        self.assertEqual(terminal["error_code"], "EXECUTION_FAILED")
        self.assertEqual(terminal["token_ids"], [])
        self.assertIs(terminal["cleanup_complete"], True)
        self.assertRegex(terminal["session_id"], _pipeline.TYPED_SESSION)
        self.assertEqual(terminal["session_id"], observation["session_id"])
        self.assertRegex(context.request_id, _pipeline.TYPED_REQUEST)

        await self._assert_request_reclaimed(
            coordinator=pipeline["coordinator"],
            service=pipeline["service"],
            secure_service=pipeline["secure_service"],
            worker_nodes=pipeline["worker_nodes"],
            capture_budget=pipeline["capture_budget"],
            transport_budget=pipeline["transport_budget"],
        )
        self.assertEqual([item.get("OpenSession", 0) for item in attempts],
                         [1, 1, 1])
        self.assertEqual([item.get("Step", 0) for item in attempts], [1, 0, 0])
        session_id = observation["session_id"]
        for node in pipeline["worker_nodes"]:
            binding_key = node["bindings"].key_for({
                "target_device_id": node["principal"].device_id,
                "worker_boot_id": node["principal"].boot_id,
                "session_id": session_id,
            })
            binding_record = node["bindings"]._records.get(binding_key)
            self.assertIsNotNone(
                binding_record, "fault-session core binding record is missing")
            self.assertEqual(binding_record.state, "tombstone")
            self.assertIs(binding_record.reclaimed, True)
            bridge_status = node["bridge"].status()
            self.assertEqual(bridge_status["active_authorizations"], 0)
            self.assertEqual(bridge_status["owned_sessions"], 0)


if __name__ == "__main__":
    unittest.main()
