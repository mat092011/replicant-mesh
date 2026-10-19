"""Supervised real TLS disconnect during worker-3 CPU ownership."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
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


CASE = "secure-worker3-tls-disconnect-v1"
CHILD_MARKER = "STEAMBOAT_C1A_DISCONNECT_CHILD"
REPORT_ENV = "STEAMBOAT_C1A_DISCONNECT_REPORT"
CHILD_TIMEOUT_SECONDS = 180.0
MAX_REPORT_BYTES = 4096
MAX_CHILD_TAIL_BYTES = 8192
CPU_GATE_WAIT_SECONDS = 30.0
RPC_RETIRE_SECONDS = 8.0
WORKER_RETIRE_SECONDS = 12.0
LEASE_EXPIRY_EXTRA_SECONDS = 1.0
PROCESS_RETIRE_SECONDS = 40.0
_RETAINED_DISCONNECT_OWNERS = []
_MAX_RETAINED_DISCONNECT_OWNERS = 1
_TYPED_SESSION = re.compile(r"^ses_[0-9a-f]{32}$", re.ASCII)


def _reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate disconnect report field: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value):
    raise ValueError(f"nonfinite disconnect report value: {value}")


def _parse_report(payload):
    if type(payload) is not bytes or len(payload) > MAX_REPORT_BYTES:
        raise ValueError("disconnect report must be bounded bytes")
    report = json.loads(payload.decode("utf-8"),
                        object_pairs_hook=_reject_duplicate_pairs,
                        parse_constant=_reject_nonfinite)
    fields = {
        "schema", "case", "session_id", "disconnect_monotonic_ns",
        "channel_close", "channel_state", "connector_closed",
        "connector_evidence", "compute_owned_before_release",
        "cache_mutated_before_release", "reclaimed_before_release",
        "step_attempts", "step_outcomes", "token_events", "terminal_status",
        "coordinator_close", "coordinator_restart_required",
        "coordinator_ready", "coordinator_active_requests",
        "worker_active_compute", "worker_sessions_empty", "worker_queue_sizes",
        "worker_bridge_owned_sessions", "worker_active_authorizations",
        "worker_cached_bytes", "contexts_retained",
        "disposal",
    }
    if type(report) is not dict or set(report) != fields:
        raise ValueError("disconnect report field set is invalid")
    if type(report["schema"]) is not int or report["schema"] != 1:
        raise ValueError("disconnect report schema must be integer 1")
    if type(report["case"]) is not str or report["case"] != CASE:
        raise ValueError("disconnect report case identity is invalid")
    if (type(report["session_id"]) is not str
            or _TYPED_SESSION.fullmatch(report["session_id"]) is None):
        raise ValueError("disconnect report session identity is invalid")
    if (type(report["disconnect_monotonic_ns"]) is not int
            or report["disconnect_monotonic_ns"] <= 0):
        raise ValueError("disconnect timestamp must be a positive exact integer")
    if type(report["channel_close"]) is not str or report["channel_close"] != "confirmed":
        raise ValueError("disconnect report lacks confirmed native channel closure")
    if type(report["channel_state"]) is not str or report["channel_state"] != "SHUTDOWN":
        raise ValueError("disconnect report lacks the native gRPC shutdown state")
    if type(report["connector_closed"]) is not bool or not report["connector_closed"]:
        raise ValueError("disconnect report lacks confirmed owned connector closure")
    if type(report["connector_evidence"]) is not str or not report["connector_evidence"]:
        raise ValueError("disconnect report lacks connector closure evidence")
    for field, expected in (("compute_owned_before_release", True),
                            ("cache_mutated_before_release", True),
                            ("reclaimed_before_release", False),
                            ("coordinator_ready", False)):
        if type(report[field]) is not bool or report[field] is not expected:
            raise ValueError(f"disconnect report {field} is invalid")
    if type(report["coordinator_restart_required"]) is not bool:
        raise ValueError("disconnect report restart fence state is invalid")
    if (type(report["step_attempts"]) is not list
            or any(type(value) is not int for value in report["step_attempts"])
            or report["step_attempts"] != [1, 1, 1]):
        raise ValueError("disconnect report shows a missing or replayed Step")
    outcomes = report["step_outcomes"]
    if (type(outcomes) is not list or len(outcomes) != 3
            or outcomes[:2] != ["OK", "OK"]
            or type(outcomes[0]) is not str or type(outcomes[1]) is not str
            or type(outcomes[2]) is not str or outcomes[2] == "OK"):
        raise ValueError("disconnect report does not show the expected actual Step outcomes")
    if type(report["token_events"]) is not int or report["token_events"] != 0:
        raise ValueError("disconnect report shows a successful output token")
    if type(report["terminal_status"]) is not str or report["terminal_status"] not in {
            "failed", "cancelled", "raised-failure"}:
        raise ValueError("disconnect report lacks explicit terminal failure")
    if type(report["coordinator_close"]) is not str or report["coordinator_close"] not in {
            "true", "false_restart_fence"}:
        raise ValueError("disconnect report coordinator close result is invalid")
    fenced = report["coordinator_close"] == "false_restart_fence"
    if type(report["coordinator_active_requests"]) is not int:
        raise ValueError("disconnect report coordinator request count is invalid")
    if fenced:
        if report["coordinator_active_requests"] != 1:
            raise ValueError("fenced coordinator request was erased or miscounted")
        if not report["coordinator_restart_required"]:
            raise ValueError("fenced coordinator lost its restart requirement")
        if type(report["contexts_retained"]) is not bool or not report["contexts_retained"]:
            raise ValueError("fenced disconnect did not retain context ownership")
    else:
        if report["coordinator_active_requests"] != 0:
            raise ValueError("confirmed coordinator close retained an unreported request")
        if report["coordinator_restart_required"]:
            raise ValueError("closed coordinator unexpectedly retained its restart fence")
        if type(report["contexts_retained"]) is not bool or report["contexts_retained"]:
            raise ValueError("confirmed coordinator cleanup retained context ownership")
    for field, expected in (("worker_active_compute", False),
                            ("worker_sessions_empty", True)):
        values = report[field]
        if (type(values) is not list or len(values) != 3
                or any(type(value) is not bool or value is not expected
                       for value in values)):
            raise ValueError(f"disconnect report {field} is invalid")
    for field in ("worker_queue_sizes", "worker_bridge_owned_sessions",
                  "worker_active_authorizations", "worker_cached_bytes"):
        values = report[field]
        if (type(values) is not list or len(values) != 3
                or any(type(value) is not int or value != 0 for value in values)):
            raise ValueError(f"disconnect report {field} is invalid")
    if (type(report["disposal"]) is not str
            or report["disposal"] != "confirmed_by_child_process_exit_only"):
        raise ValueError("disconnect report overstates in-process disposal")
    return report


def _worker_snapshot(nodes):
    result = {
        "active_compute": [],
        "sessions_empty": [],
        "queue_sizes": [],
        "bridge_owned_sessions": [],
        "active_authorizations": [],
        "cached_bytes": [],
    }
    for node in nodes:
        handler = node["handler"]
        bridge = node["bridge"]
        caches = (*handler.sessions.values(), *handler.tombstones.values())
        result["active_compute"].append(
            handler.supervision_status()["active_compute"])
        result["sessions_empty"].append(not handler.sessions)
        result["queue_sizes"].append(len(handler._queue))
        result["bridge_owned_sessions"].append(bridge.status()["owned_sessions"])
        result["active_authorizations"].append(
            bridge.status()["active_authorizations"])
        result["cached_bytes"].append(sum(
            entry.cache.allocated_bytes() for entry in caches))
    return result


def _physically_retired(nodes):
    result = _worker_snapshot(nodes)
    return (
        result["active_compute"] == [False, False, False]
        and result["sessions_empty"] == [True, True, True]
        and result["queue_sizes"] == [0, 0, 0]
        and result["bridge_owned_sessions"] == [0, 0, 0]
        and result["active_authorizations"] == [0, 0, 0]
        and result["cached_bytes"] == [0, 0, 0]
    )


def _install_disconnect_cleanup(test, pipeline, context, session_id,
                                disconnect_monotonic_ns, step_attempts,
                                step_outcomes, token_events, terminal_status,
                                channel_state, connector):
    if len(_RETAINED_DISCONNECT_OWNERS) >= _MAX_RETAINED_DISCONNECT_OWNERS:
        raise RuntimeError("bounded TLS disconnect owner registry is full")
    actions = pipeline["cleanup_owner"]._actions
    action = next((item for item in actions
                   if item["active"] and item["label"] == "coordinator close"), None)
    if action is None:
        raise AssertionError("pipeline cleanup owner lacks coordinator close action")
    coordinator = pipeline["coordinator"]
    original_close = action["callback"]
    owner = {
        "pipeline": pipeline,
        "context": context,
        "coordinator": coordinator,
        "model": coordinator.model,
        "worker_clients": tuple(coordinator.clients),
        "workers": tuple({
            "handler": node["handler"], "executor": node["executor"],
            "bridge": node["bridge"], "server": node["server"],
        } for node in pipeline["worker_nodes"]),
        "service": pipeline["service"],
        "secure_service": pipeline["secure_service"],
        "connector": connector,
        "failure": None,
    }
    _RETAINED_DISCONNECT_OWNERS.append(owner)

    async def close_and_report():
        try:
            result = await asyncio.wait_for(original_close(), timeout=5.0)
            if result is True:
                context.close()
                coordinator_close = "true"
            elif result is False:
                state = coordinator._requests.get(session_id)
                test.assertIsNotNone(state)
                test.assertIs(state.restart_required, True)
                test.assertIs(coordinator.stats()["ready"], False)
                test.assertEqual(coordinator.stats()["active_requests"], 1)
                coordinator_close = "false_restart_fence"
            else:
                raise AssertionError("real coordinator close did not return exact bool")
            test.assertTrue(_physically_retired(pipeline["worker_nodes"]))
            test.assertEqual(coordinator.stats()["stage_queue_sizes"], [0, 0, 0])
            if not connector.closed_confirmed:
                raise AssertionError("native SecureConnector closure lacks confirmation")
            report_path = os.environ.get(REPORT_ENV)
            if os.environ.get(CHILD_MARKER) != CASE or not report_path:
                raise RuntimeError("TLS disconnect requires its supervised child boundary")
            state = coordinator._requests.get(session_id)
            workers = _worker_snapshot(pipeline["worker_nodes"])
            report = {
                "schema": 1,
                "case": CASE,
                "session_id": session_id,
                "disconnect_monotonic_ns": disconnect_monotonic_ns,
                "channel_close": "confirmed",
                "channel_state": channel_state,
                "connector_closed": connector.closed_confirmed,
                "connector_evidence": connector.closure_evidence,
                "compute_owned_before_release": True,
                "cache_mutated_before_release": True,
                "reclaimed_before_release": False,
                "step_attempts": list(step_attempts),
                "step_outcomes": list(step_outcomes),
                "token_events": token_events,
                "terminal_status": terminal_status,
                "coordinator_close": coordinator_close,
                "coordinator_restart_required": coordinator_close == "false_restart_fence",
                "coordinator_ready": coordinator.stats()["ready"],
                "coordinator_active_requests": coordinator.stats()["active_requests"],
                "worker_active_compute": workers["active_compute"],
                "worker_sessions_empty": workers["sessions_empty"],
                "worker_queue_sizes": workers["queue_sizes"],
                "worker_bridge_owned_sessions": workers["bridge_owned_sessions"],
                "worker_active_authorizations": workers["active_authorizations"],
                "worker_cached_bytes": workers["cached_bytes"],
                "contexts_retained": coordinator_close == "false_restart_fence",
                "disposal": "confirmed_by_child_process_exit_only",
            }
            payload = json.dumps(report, sort_keys=True, separators=(",", ":"))
            if len(payload.encode("utf-8")) > MAX_REPORT_BYTES:
                raise RuntimeError("TLS disconnect child report exceeds size bound")
            Path(report_path).write_text(payload, encoding="utf-8")
            return None
        except BaseException as error:
            owner["failure"] = type(error).__name__
            raise

    action["label"] = "native TLS disconnect owner disposal report"
    action["callback"] = close_and_report


class SecurePipelineDisconnectChildTests(_pipeline.SecurePipelinePositiveTests):
    async def _run_lifecycle_extensions(self, pipeline):
        coordinator = pipeline["coordinator"]
        worker_nodes = pipeline["worker_nodes"]
        worker = worker_nodes[2]
        handler = worker["handler"]
        executor = worker["executor"]
        coordinator_client = pipeline["coordinator_client"]
        native_wrapper = coordinator.clients[2]
        native_client = getattr(native_wrapper, "_client", None)
        self.assertIsNotNone(native_client, "worker-3 native secure-client ownership hook missing")
        from steamboat_runtime.protocol.secure_transport import SecureWorkerClient
        self.assertIs(type(native_client), SecureWorkerClient)
        channel = native_client.channel
        connector = native_client._subchannel.connector
        self.assertIsNotNone(channel, "worker-3 owned TLS channel is not active")
        self.assertIsNotNone(connector, "worker-3 SecureConnector is not active")
        self.assertEqual(
            getattr(channel.get_state(try_to_connect=False), "name", ""), "READY")
        original_stage_execute = executor.execute
        gate_entered = threading.Event()
        gate_release = threading.Event()
        gate_evidence = {"active": False, "cache_bytes": 0}
        consumer_tasks = []
        observed_clients = []
        contexts = []
        step_attempts = [0, 0, 0]
        step_outcomes = [None, None, None]
        sessions_by_request = {}
        restored = False
        fenced = False
        context = pipeline["consumer_outbound"].create_consumer_request_context(
            lifetime_seconds=25)
        contexts.append(context)

        def gated_stage_execute(hidden, cache, position):
            result = original_stage_execute(hidden, cache, position)
            gate_evidence["cache_bytes"] = cache.allocated_bytes()
            gate_entered.set()
            if not gate_release.wait(CPU_GATE_WAIT_SECONDS):
                raise TimeoutError("bounded real worker-3 CPU gate expired")
            return result

        async def restore_observers():
            nonlocal restored
            if restored:
                return
            if handler.supervision_status()["active_compute"]:
                raise RuntimeError("cannot restore StageExecutor during owned worker compute")
            executor.execute = original_stage_execute
            for client, original in reversed(observed_clients):
                client.execute = original
            restored = True

        async def close_contexts():
            if fenced:
                return None
            if handler.supervision_status()["active_compute"]:
                raise RuntimeError("cannot close disconnect context during worker compute")
            if any(not task.done() for task in consumer_tasks):
                raise RuntimeError("cannot close disconnect context while Generate is live")
            for owned in contexts:
                owned.close()

        async def cancel_and_join():
            for task in consumer_tasks:
                if not task.done():
                    task.cancel()
            if consumer_tasks:
                done, pending = await asyncio.wait(
                    consumer_tasks, timeout=RPC_RETIRE_SECONDS)
                if pending:
                    raise RuntimeError("disconnect Generate task did not retire boundedly")
                await asyncio.gather(*done, return_exceptions=True)

        async def wait_compute_retirement():
            await _pipeline._wait_until(
                lambda: all(not node["handler"].supervision_status()["active_compute"]
                            for node in worker_nodes),
                timeout_seconds=WORKER_RETIRE_SECONDS,
                description="all actual worker CPU futures retire after gate release")
            for node in worker_nodes:
                task = node["handler"]._compute_task
                if task is not None:
                    self.assertTrue(task.done())

        owner = pipeline["cleanup_owner"]
        restore_action = owner.add("restore disconnect observers", restore_observers)
        context_action = owner.add("close disconnect consumer context", close_contexts)
        task_action = owner.add("join disconnect Generate", cancel_and_join)
        compute_action = owner.add("wait disconnect worker compute retirement",
                                   wait_compute_retirement)
        gate_action = owner.add("release disconnect real worker-3 CPU gate",
                                gate_release.set)
        executor.execute = gated_stage_execute
        try:
            from steamboat_runtime.participant_context import TrustedRequestContext

            for index, client in enumerate(coordinator.clients):
                original = client.execute
                observed_clients.append((client, original))

                async def observed(method, request, *args, _index=index,
                                   _original=original, **kwargs):
                    if method == "Step":
                        trusted = kwargs.get("trusted_request_context")
                        self.assertIsInstance(trusted, TrustedRequestContext)
                        step_attempts[_index] += 1
                        previous = sessions_by_request.setdefault(
                            trusted.request_id, request.session_id)
                        self.assertEqual(previous, request.session_id)
                    try:
                        response = await _original(method, request, *args, **kwargs)
                    except BaseException as error:
                        if method == "Step":
                            step_outcomes[_index] = type(error).__name__
                        raise
                    if method == "Step":
                        step_outcomes[_index] = response.code
                    return response

                client.execute = observed

            events = []
            stream = coordinator_client.generate(
                [17, 29, 43], 1, trusted_request_context=context,
                capture_logits=False, timeout_seconds=60)

            async def consume():
                try:
                    async for event in stream:
                        events.append(dict(event))
                except BaseException as error:
                    return error
                return None

            consumer = asyncio.create_task(consume())
            consumer_tasks.append(consumer)
            await _pipeline._wait_until(
                gate_entered.is_set, timeout_seconds=CPU_GATE_WAIT_SECONDS,
                description="real worker-3 StageExecutor after cache mutation")
            session_id = sessions_by_request.get(context.request_id)
            self.assertRegex(session_id or "", _TYPED_SESSION)
            entry = handler.sessions.get(session_id)
            self.assertIsNotNone(entry)
            self.assertTrue(entry.in_flight)
            self.assertTrue(any(entry.cache.lengths()))
            self.assertGreater(entry.cache.allocated_bytes(), 0)
            self.assertEqual(gate_evidence["cache_bytes"], entry.cache.allocated_bytes())
            self.assertTrue(handler.supervision_status()["active_compute"])
            self.assertIsNotNone(handler._compute_task)
            self.assertFalse(handler._compute_task.done())
            gate_evidence["active"] = True
            binding_key = worker["bindings"].key_for({
                "target_device_id": worker["principal"].device_id,
                "worker_boot_id": worker["principal"].boot_id,
                "session_id": session_id,
            })
            binding_record = worker["bindings"]._records.get(binding_key)
            self.assertIsNotNone(binding_record)
            hard_expiry = binding_record.hard_expiry_monotonic
            self.assertEqual(step_attempts, [1, 1, 1])
            self.assertEqual(step_outcomes[:2], ["OK", "OK"])
            self.assertIsNone(step_outcomes[2])
            self.assertEqual(events, [])
            self.assertIsNot(binding_record.reclaimed, True)

            disconnect_monotonic_ns = time.monotonic_ns()
            close_result = await asyncio.wait_for(channel.close(grace=0), timeout=5.0)
            self.assertIsNone(close_result)
            await _pipeline._wait_until(
                lambda: getattr(channel.get_state(try_to_connect=False), "name", "")
                == "SHUTDOWN",
                timeout_seconds=5.0,
                description="actual owned gRPC TLS channel shutdown")
            await _pipeline._wait_until(
                lambda: connector.closed_confirmed,
                timeout_seconds=5.0,
                description="owned SecureConnector physical tunnel closure")
            self.assertTrue(handler.supervision_status()["active_compute"])
            self.assertIs(handler.sessions.get(session_id), entry)
            self.assertTrue(entry.in_flight)
            self.assertGreater(entry.cache.allocated_bytes(), 0)
            self.assertIsNot(binding_record.reclaimed, True)
            await _pipeline._wait_until(
                consumer.done, timeout_seconds=RPC_RETIRE_SECONDS,
                description="real Generate failure following TLS disconnect")
            consumer_error = consumer.result()
            terminal_status = (
                next((event.get("status") for event in reversed(events)
                      if event.get("type") == "result"), None))
            token_count = sum(event.get("type") == "token" for event in events)
            self.assertEqual(token_count, 0)
            self.assertNotEqual(terminal_status, "completed")
            self.assertTrue(
                consumer_error is not None or terminal_status in {"failed", "cancelled"},
                "native TLS disconnect did not produce an explicit terminal failure")
            self.assertEqual(step_attempts, [1, 1, 1], "disconnect replayed a Step")
            self.assertNotEqual(step_outcomes[2], "OK",
                                "worker-3 Step returned success after native TLS close")
            self.assertTrue(handler.supervision_status()["active_compute"],
                            "worker CPU ownership was reclaimed before gate release")
            self.assertIs(handler.sessions.get(session_id), entry)
            self.assertGreater(entry.cache.allocated_bytes(), 0)
            self.assertIsNot(binding_record.reclaimed, True)
            self.assertIs(coordinator.stats()["ready"], False,
                          "coordinator must fence work after a real worker transport failure")

            gate_release.set()
            await _pipeline._wait_until(
                lambda: not handler.supervision_status()["active_compute"],
                timeout_seconds=WORKER_RETIRE_SECONDS,
                description="worker-3 CPU retires after explicit gate release")
            compute_task = handler._compute_task
            if compute_task is not None:
                self.assertTrue(compute_task.done())
            if binding_record.reclaimed is not True:
                await _pipeline._wait_until(
                    lambda: (time.monotonic() >= hard_expiry
                             and session_id not in handler.sessions
                             and binding_record.state == "tombstone"
                             and binding_record.reclaimed is True),
                    timeout_seconds=30.0,
                    description="unknown worker-3 lease hard expiry and core reclamation")
            tombstone = handler.tombstones.get(session_id)
            self.assertIsNotNone(tombstone)
            self.assertEqual(tombstone.cache.allocated_bytes(), 0)
            self.assertFalse(any(tombstone.cache.lengths()))
            await _pipeline._wait_until(
                lambda: _physically_retired(worker_nodes),
                timeout_seconds=WORKER_RETIRE_SECONDS,
                description="all worker cache, queue, session and authorization retirement")
            state = coordinator._requests.get(session_id)
            if state is not None and state.restart_required:
                fenced = True
            self.assertEqual(step_attempts, [1, 1, 1])
            self.assertEqual(token_count, 0)
            _install_disconnect_cleanup(
                self, pipeline, context, session_id, disconnect_monotonic_ns,
                step_attempts, step_outcomes, token_count,
                terminal_status or "raised-failure",
                getattr(channel.get_state(try_to_connect=False), "name", ""),
                connector)
        finally:
            gate_release.set()
            for task in consumer_tasks:
                if not task.done():
                    task.cancel()
            if consumer_tasks:
                done, pending = await asyncio.wait(
                    consumer_tasks, timeout=RPC_RETIRE_SECONDS)
                if pending:
                    raise RuntimeError("disconnect consumer remains live after gate release")
                await asyncio.gather(*done, return_exceptions=True)
            await wait_compute_retirement()
            await close_contexts()
            if executor.execute is not original_stage_execute:
                executor.execute = original_stage_execute
            for client, original in reversed(observed_clients):
                client.execute = original
            for action in (restore_action, context_action, task_action,
                           compute_action, gate_action):
                owner.disarm(action)


@unittest.skipUnless(
    _pipeline.ENABLED,
    "Set STEAMBOAT_SECURE_PIPELINE_TESTS=1 for the opt-in offline mTLS model path",
)
class SecurePipelineDisconnectProcessTests(unittest.TestCase):
    def test_worker3_native_tls_disconnect_is_supervised_until_physical_retirement(self):
        if os.environ.get(CHILD_MARKER) == CASE:
            self.fail("disconnect child marker prevents recursive supervision")
        child_test = (
            "SecurePipelineDisconnectChildTests."
            "test_consumer_generate_crosses_real_secure_three_stage_pipeline")
        with tempfile.TemporaryDirectory(prefix="steamboat-c1a-disconnect-") as root:
            report_path = Path(root) / "disconnect-report.json"
            environment = os.environ.copy()
            environment[CHILD_MARKER] = CASE
            environment[REPORT_ENV] = str(report_path)
            child_output = bytearray()
            child = subprocess.Popen(
                [sys.executable, "-B", "-m", "unittest",
                 f"tests.security.test_secure_pipeline_disconnect.{child_test}"],
                cwd=str(Path(__file__).resolve().parents[2]), env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            def drain():
                while True:
                    chunk = child.stdout.read(2048)
                    if not chunk:
                        return
                    child_output.extend(chunk)
                    if len(child_output) > MAX_CHILD_TAIL_BYTES:
                        del child_output[:-MAX_CHILD_TAIL_BYTES]

            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            timed_out = False
            try:
                child.wait(timeout=CHILD_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
                child.kill()
                child.wait(timeout=10.0)
            reader.join(timeout=5.0)
            child.stdout.close()
            diagnostic = bytes(child_output).decode("utf-8", "replace")[-MAX_CHILD_TAIL_BYTES:]
            self.assertFalse(reader.is_alive(), "disconnect child output reader did not stop")
            self.assertFalse(timed_out,
                             f"disconnect child exceeded bound; tail:\n{diagnostic}")
            self.assertEqual(child.returncode, 0,
                             f"disconnect child assertions/teardown failed; tail:\n{diagnostic}")
            self.assertTrue(report_path.is_file(), "disconnect child omitted report")
            self.assertLessEqual(report_path.stat().st_size, MAX_REPORT_BYTES)
            child_exit_monotonic_ns = time.monotonic_ns()
            report = _parse_report(report_path.read_bytes())
            self.assertIsNotNone(child.poll(), "disconnect child exit was not confirmed")
            elapsed_ns = child_exit_monotonic_ns - report["disconnect_monotonic_ns"]
            self.assertGreaterEqual(elapsed_ns, 0)
            self.assertLessEqual(elapsed_ns, int(PROCESS_RETIRE_SECONDS * 1e9),
                                 "disconnect-to-child-exit exceeded 40 seconds")


class DisconnectReportParserTests(unittest.TestCase):
    def test_rejects_duplicate_keys_aliases_and_invalid_worker_proof(self):
        report = {
            "schema": 1, "case": CASE, "session_id": "ses_" + "b" * 32,
            "disconnect_monotonic_ns": 1, "channel_close": "confirmed",
            "channel_state": "SHUTDOWN", "connector_closed": True,
            "connector_evidence": "owned tunnel closed", "compute_owned_before_release": True,
            "cache_mutated_before_release": True, "reclaimed_before_release": False,
            "step_attempts": [1, 1, 1], "step_outcomes": ["OK", "OK", "ProtocolError"],
            "token_events": 0, "terminal_status": "failed",
            "coordinator_close": "false_restart_fence",
            "coordinator_restart_required": True, "coordinator_ready": False,
            "coordinator_active_requests": 1,
            "worker_active_compute": [False, False, False],
            "worker_sessions_empty": [True, True, True],
            "worker_queue_sizes": [0, 0, 0], "worker_bridge_owned_sessions": [0, 0, 0],
            "worker_active_authorizations": [0, 0, 0], "worker_cached_bytes": [0, 0, 0],
            "contexts_retained": True,
            "disposal": "confirmed_by_child_process_exit_only",
        }
        encoded = json.dumps(report, separators=(",", ":")).encode("utf-8")
        self.assertEqual(_parse_report(encoded), report)
        malformed = (
            (b'{"schema":1,"schema":1}', "duplicate"),
            (encoded.replace(b'"disconnect_monotonic_ns":1',
                             b'"disconnect_monotonic_ns":true'), "timestamp alias"),
            (encoded.replace(b'"worker_cached_bytes":[0,0,0]',
                             b'"worker_cached_bytes":[false,0,0]'), "bool as integer"),
            (encoded[:-1] + b',"unexpected":0}', "extra field"),
            (b" " * (MAX_REPORT_BYTES + 1), "oversized"),
        )
        for payload, label in malformed:
            with self.subTest(label=label), self.assertRaises(ValueError):
                _parse_report(payload)


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(SecurePipelineDisconnectProcessTests))
    suite.addTests(loader.loadTestsFromTestCase(DisconnectReportParserTests))
    return suite


if __name__ == "__main__":
    unittest.main()
