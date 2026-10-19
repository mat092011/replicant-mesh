"""Opt-in real mTLS consumer-to-three-worker correctness matrix.

Set STEAMBOAT_SECURE_PIPELINE_TESTS=1 to require this test. When enabled,
missing offline artifacts, reference files, or runtime dependencies are errors.
The test uses the real generated Request type and real C0/C1 runtime adapters;
it does not substitute an in-memory transport or test authorizer.
"""

from __future__ import annotations

import asyncio
import gc
import inspect
import os
from pathlib import Path
import re
import shutil
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
SECURITY_TESTS = Path(__file__).resolve().parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(SECURITY_TESTS) not in sys.path:
    sys.path.insert(0, str(SECURITY_TESTS))

ENABLED = os.environ.get("STEAMBOAT_SECURE_PIPELINE_TESTS") == "1"
PINNED_MODEL = "Maykeye/TinyLLama-v0"
PINNED_REVISION = "298338802ab94432b917bcce11382aa151aee50f"
TYPED_REQUEST = re.compile(r"^req_[0-9a-f]{32}$", re.ASCII)
TYPED_SESSION = re.compile(r"^ses_[0-9a-f]{32}$", re.ASCII)


class _CleanupFailure:
    def __init__(self, label: str, error: BaseException):
        self.label = label
        self.error = error


class _AsyncCleanupOwner:
    """Own test resources as soon as they exist and drain every cleanup."""

    def __init__(self):
        self._actions = []
        self._closed = False

    def add(self, label, callback):
        if self._closed:
            raise RuntimeError("cleanup owner is already closed")
        if type(label) is not str or not label or not callable(callback):
            raise TypeError("cleanup registration needs a label and callable")
        action = {"label": label, "callback": callback, "active": True}
        self._actions.append(action)
        return action

    def disarm(self, action):
        if not isinstance(action, dict) or action not in self._actions:
            raise ValueError("cleanup action does not belong to this owner")
        action["active"] = False

    async def aclose(self):
        if self._closed:
            return ()
        self._closed = True
        failures = []
        for action in reversed(self._actions):
            if not action["active"]:
                continue
            try:
                result = action["callback"]()
                if inspect.isawaitable(result):
                    result = await result
                if result is False:
                    raise RuntimeError("cleanup did not confirm successful closure")
            except BaseException as error:
                try:
                    error.add_note(f"pipeline teardown action: {action['label']}")
                except (AttributeError, TypeError):
                    pass
                failures.append(_CleanupFailure(action["label"], error))
        self._actions.clear()
        return tuple(failures)


def _combined_pipeline_failure(primary, teardown_failures):
    if not teardown_failures:
        return primary
    exceptions = []
    if primary is not None:
        exceptions.append(primary)
    exceptions.extend(failure.error for failure in teardown_failures)
    return BaseExceptionGroup(
        "secure pipeline primary failure and teardown failures", exceptions)


async def _wait_until(predicate, *, timeout_seconds: float, description: str) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.025)
    raise AssertionError(f"timed out waiting for {description}")


class PipelineCleanupOwnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_partial_setup_failure_closes_already_owned_resource(self):
        owner = _AsyncCleanupOwner()
        closed = []
        primary = None

        class PartialResource:
            async def close(self):
                closed.append("first")

        try:
            resource = PartialResource()
            owner.add("first acquired resource", resource.close)
            raise OSError("second setup step failed")
        except BaseException as error:
            primary = error

        failures = await owner.aclose()
        self.assertEqual(closed, ["first"])
        self.assertEqual(failures, ())
        self.assertIs(primary.__class__, OSError)
        self.assertIn("second setup step failed", str(primary))

    async def test_cleanup_false_is_reported_and_other_actions_still_run(self):
        owner = _AsyncCleanupOwner()
        closed = []

        async def unsuccessful_close():
            return False

        owner.add("successful cleanup", lambda: closed.append(True))
        owner.add("unconfirmed cleanup", unsuccessful_close)
        failures = await owner.aclose()
        self.assertEqual(closed, [True])
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0].error, RuntimeError)

    async def test_cleanup_failure_keeps_primary_and_runs_remaining_cleanup(self):
        owner = _AsyncCleanupOwner()
        cleanup_order = []
        primary = AssertionError("numerical assertion failed")
        cleanup_error = OSError("listener close failed")

        def failing_cleanup():
            cleanup_order.append("failing")
            raise cleanup_error

        async def later_cleanup():
            cleanup_order.append("later")

        owner.add("later cleanup", later_cleanup)
        owner.add("failing cleanup", failing_cleanup)
        failures = await owner.aclose()
        combined = _combined_pipeline_failure(primary, failures)

        self.assertEqual(cleanup_order, ["failing", "later"])
        self.assertEqual(len(failures), 1)
        self.assertIs(failures[0].error, cleanup_error)
        self.assertIsInstance(combined, BaseExceptionGroup)
        self.assertIs(combined.exceptions[0], primary)
        self.assertIs(combined.exceptions[1], cleanup_error)


def _reference_forced_last_positions(reference, torch, prompt_ids):
    """Keep full-prefill logits local and return only the nine expected rows."""
    vocabulary_size = 32_000
    continuation_count = 8
    for forced_token in (vocabulary_size - 1, vocabulary_size - 2):
        reference_input = prompt_ids + [forced_token] * continuation_count
        input_tensor = torch.tensor([reference_input], dtype=torch.long)
        with torch.inference_mode():
            output = reference(input_ids=input_tensor, use_cache=False,
                               return_dict=True)
            full_prefill_logits = output.logits[0]
            last_positions = full_prefill_logits[
                len(prompt_ids) - 1:].detach().clone()
            first_greedy_token = int(last_positions[0].argmax().item())
        del full_prefill_logits, output, input_tensor
        if first_greedy_token != forced_token:
            if tuple(last_positions.shape) != (continuation_count + 1,
                                                vocabulary_size):
                raise AssertionError("reference last-position matrix has the wrong shape")
            return forced_token, last_positions
        del last_positions
    raise AssertionError("could not select forced feedback distinct from the first greedy token")


@unittest.skipUnless(
    ENABLED,
    "Set STEAMBOAT_SECURE_PIPELINE_TESTS=1 for the opt-in offline mTLS model path",
)
class SecurePipelinePositiveTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        artifact_value = os.environ.get("STEAMBOAT_ARTIFACT_DIR")
        reference_value = os.environ.get("STEAMBOAT_REFERENCE_DIR")
        if not artifact_value or not Path(artifact_value).is_dir():
            raise RuntimeError(
                "opt-in secure pipeline test requires STEAMBOAT_ARTIFACT_DIR")
        if not reference_value or not Path(reference_value).is_dir():
            raise RuntimeError(
                "opt-in secure pipeline test requires STEAMBOAT_REFERENCE_DIR")

        # Import failures are intentionally test errors after opt-in, never skips.
        import grpc  # noqa: F401
        import google.protobuf  # noqa: F401
        import safetensors  # noqa: F401
        import torch
        import transformers  # noqa: F401

        torch.set_num_threads(2)
        try:
            torch.set_num_interop_threads(2)
        except RuntimeError:
            # Some complete-suite runners initialize Torch before collection.
            if torch.get_num_interop_threads() > 2:
                raise
        if torch.get_num_threads() > 2 or torch.get_num_interop_threads() > 2:
            raise RuntimeError("secure pipeline test requires at most two Torch threads")

        from steamboat_runtime.manifest import load_manifest
        from steamboat_runtime.prepare import verify_snapshot

        cls.artifact_dir = Path(artifact_value)
        cls.reference_dir = Path(reference_value)
        cls.manifest = load_manifest(cls.artifact_dir)
        if (cls.manifest.get("model_id") != PINNED_MODEL
                or cls.manifest.get("revision") != PINNED_REVISION):
            raise RuntimeError("offline artifacts differ from the pinned C0 model revision")
        verify_snapshot(cls.reference_dir)
        cls.torch = torch

    async def _secure_generate(self, client, outbound, input_ids, *, new_tokens,
                               forced_tokens=None, capture_logits=False,
                               on_token=None):
        """Run one authenticated Generate with a fresh consumer context.

        Captured vectors are inspected synchronously and removed before events
        are retained, so the test does not accumulate capture payloads.
        """
        from steamboat_security import ConsumerRequestContext

        context = outbound.create_consumer_request_context(lifetime_seconds=120)
        self.assertIs(type(context), ConsumerRequestContext)
        events = []
        stream = client.generate(
            input_ids, new_tokens, forced_tokens=forced_tokens,
            trusted_request_context=context,
            capture_logits=capture_logits, timeout_seconds=120)
        primary_error = None
        cleanup_errors = []
        try:
            async for event in stream:
                if event.get("type") == "token" and on_token is not None:
                    on_token(event)
                event.pop("logits", None)
                events.append(event)
        except BaseException as error:
            primary_error = error
        finally:
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
                "secure Generate failure and local cleanup failures",
                [primary_error, *cleanup_errors])
        if primary_error is not None:
            raise primary_error.with_traceback(primary_error.__traceback__)
        if cleanup_errors:
            raise BaseExceptionGroup("secure Generate local cleanup failures",
                                     cleanup_errors)
        return context, events

    async def _run_lifecycle_extensions(self, _pipeline):
        """Hook for test-only subclasses sharing this real pipeline harness."""
        return None

    async def _assert_request_reclaimed(self, *, coordinator, service,
                                        secure_service, worker_nodes,
                                        capture_budget, transport_budget):
        await _wait_until(
            lambda: (secure_service.active_generate_streams == 0
                     and service.active_streams == 0
                     and not service.cleanups
                     and coordinator.stats()["active_requests"] == 0
                     and all(not node["handler"].sessions
                             and node["bridge"].status()["owned_sessions"] == 0
                             for node in worker_nodes)
                     and capture_budget.status().reserved_bytes == 0
                     and capture_budget.status().active_captures == 0
                     and capture_budget.status().cleanup_pending_captures == 0
                     and transport_budget.reserved_connections == 16
                     and transport_budget.reserved_pending == 0
                     and transport_budget.reserved_listener_pending_capacity == 4
                     and transport_budget.reserved_outbound_pending == 0),
            timeout_seconds=10,
            description="trusted coordinator, worker and capture cleanup",
        )
        for node in worker_nodes:
            handler = node["handler"]
            self.assertEqual(handler.sessions, {})
            self.assertEqual(handler.supervision_status()["active_compute"], False)
            self.assertTrue(all(
                entry.committed_bytes == 0 and entry.cache.allocated_bytes() == 0
                and not any(entry.cache.lengths())
                for entry in handler.tombstones.values()))
            self.assertEqual(node["bridge"].status()["owned_sessions"], 0)
        status = capture_budget.status()
        self.assertEqual(status.active_captures, 0)
        self.assertEqual(status.cleanup_pending_captures, 0)
        self.assertEqual(status.reserved_bytes, 0)

    async def test_consumer_generate_crosses_real_secure_three_stage_pipeline(self):
        from transformers import AutoModelForCausalLM

        from secure_pipeline_fixture import SecurePipelineIdentityFixture
        from steamboat_runtime.coordinator import Coordinator
        from steamboat_runtime.coordinator_service import (
            CoordinatorService,
            supervised_model_class,
        )
        from steamboat_runtime.protocol.secure_connector import SecureConnector
        from steamboat_runtime.protocol.secure_transport import (
            C0ExpectedServerLeafAdapter,
            ExpectedServerIdentity,
            FixedPeer,
            LocalTlsIdentity,
            NodeConnectionBudget,
            create_secure_coordinator_client,
            create_secure_worker_client,
        )
        from steamboat_runtime.protocol.secure_transport import (
            create_secure_worker_server,
        )
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_runtime.participant_context import TrustedRequestContext
        from steamboat_runtime.secure_context import (
            BootstrapWorkerClient,
            ConsumerContextFactory,
        )
        from steamboat_runtime.capture_budget import (
            CaptureBudget,
            CaptureBudgetConfig,
        )
        from steamboat_runtime.secure_coordinator_service import (
            create_secure_coordinator_server,
        )
        from steamboat_runtime.secure_worker_runtime import SecureWorkerRuntimeBridge
        from steamboat_runtime.worker_state import StageExecutor, WorkerHandler
        from steamboat_security import (
            AuthorizationWatcher,
            Authorizer,
            LocalIdentity,
            OutboundAuthorizer,
            OutboundTarget,
            SessionBindings,
            verify_expected_server_leaf,
        )
        from steamboat_security.codec import WORKER_SERVICE
        from steamboat_runtime.remote_client import SERVICE as COORDINATOR_SERVICE

        torch = self.torch
        fingerprint = self.manifest["fingerprint"]
        cleanup_owner = _AsyncCleanupOwner()
        authority = None
        budget = None
        acceptor_directory = None
        worker_nodes = []
        worker_clients = []
        coordinator = None
        coordinator_client = None
        coordinator_server = None
        coordinator_secure_service = None
        capture_budget = None
        model = None
        reference = None
        primary_error = None

        def release_reference():
            nonlocal reference
            reference = None
            gc.collect()

        async def stop_worker_listener(node):
            server = node.get("server")
            if server is not None:
                await server.stop(0)
                node["server"] = None

        async def stop_worker_bridge(node):
            bridge = node.get("bridge")
            if bridge is not None:
                if bridge._started and not bridge._closed:
                    result = await bridge.stop(grace_seconds=5)
                    if result is not True:
                        raise RuntimeError("worker bridge did not confirm shutdown")
                node["bridge"] = None

        async def stop_worker_handler(node):
            handler = node.get("handler")
            if handler is not None:
                result = await handler.shutdown(grace_seconds=5)
                if result is not True:
                    raise RuntimeError("worker handler did not confirm shutdown")
                node["handler"] = None

        def release_worker_executor(node):
            node["executor"] = None

        async def close_owned_worker_client(holder):
            client = holder.get("client")
            if client is None or getattr(client, "_closed", False):
                return
            result = client.close()
            if inspect.isawaitable(result):
                await result

        def verify_after_cleanup(label, callback, failures):
            try:
                callback()
            except BaseException as error:
                try:
                    error.add_note(f"pipeline teardown verification: {label}")
                except (AttributeError, TypeError):
                    pass
                failures.append(_CleanupFailure(label, error))

        try:
            authority = SecurePipelineIdentityFixture(fingerprint)
            cleanup_owner.add("identity fixture directory", authority.close)
            budget = NodeConnectionBudget(max_connections=16, max_pending=4)
            acceptor_directory = authority.root / "acceptors"
            acceptor_directory.mkdir(mode=0o700)
            cleanup_owner.add(
                "acceptor directory",
                lambda path=acceptor_directory: (
                    shutil.rmtree(path) if path.exists() else None))
            if os.name == "posix":
                os.chmod(acceptor_directory, 0o700)

            for index in (1, 2, 3):
                principal = authority.principals[f"worker-{index}"]
                store, clock = authority.new_store()
                bindings = SessionBindings(clock=clock)
                authorizer = Authorizer(
                    local_identity=LocalIdentity(
                        principal.certificate_pem, principal.boot_id, fingerprint,
                        principal.assignment_id),
                    snapshot_store=store,
                    clock=clock,
                    session_bindings=bindings,
                    worker_request_type=Request)
                name = f"worker-{index}"
                node = {
                    "principal": principal,
                    "store": store,
                    "clock": clock,
                    "bindings": bindings,
                    "authorizer": authorizer,
                    "executor": None,
                    "handler": None,
                    "bridge": None,
                    "server": None,
                }
                worker_nodes.append(node)
                executor = StageExecutor(self.artifact_dir, name)
                node["executor"] = executor
                cleanup_owner.add(
                    f"{name} stage executor references",
                    lambda node=node: release_worker_executor(node))
                handler = WorkerHandler(
                    self.manifest, name, executor,
                    boot_id=principal.boot_id, enable_queue=True)
                node["handler"] = handler
                cleanup_owner.add(
                    f"{name} handler shutdown",
                    lambda node=node: stop_worker_handler(node))
                bridge = SecureWorkerRuntimeBridge(
                    authorizer, handler, sweep_interval_seconds=0.5)
                node["bridge"] = bridge
                cleanup_owner.add(
                    f"{name} runtime bridge stop",
                    lambda node=node: stop_worker_bridge(node))
                await bridge.start()
                node["server"] = await create_secure_worker_server(
                    bridge.handler,
                    listen_endpoint="127.0.0.1:0",
                    allowed_listen_addresses=("127.0.0.1",),
                    server_identity=LocalTlsIdentity(
                        principal.certificate_pem, principal.private_key_pem),
                    client_ca_pem=authority.cohort_ca_pem,
                    authorizer=bridge.incoming_authorizer,
                    authorization_watcher=bridge.authorization_watcher,
                    connection_controller=budget,
                    listener_id=f"secure-pipeline-worker-{index}",
                    listener_slots=1,
                    acceptor_directory=str(acceptor_directory))
                cleanup_owner.add(
                    f"{name} worker listener stop",
                    lambda node=node: stop_worker_listener(node))

            # The coordinator's outbound worker channels are all pinned and
            # authenticated before start() performs its own readiness probes.
            coordinator_principal = authority.principals["coordinator"]
            coordinator_local = LocalIdentity(
                coordinator_principal.certificate_pem,
                coordinator_principal.boot_id,
                fingerprint)
            watcher = AuthorizationWatcher(poll_interval_seconds=0.5)
            tls_verifier = C0ExpectedServerLeafAdapter(verify_expected_server_leaf)
            for index, node in enumerate(worker_nodes, start=1):
                principal = node["principal"]
                target = OutboundTarget.from_record(
                    service=WORKER_SERVICE,
                    record=principal.record,
                    boot_id=principal.boot_id,
                    model_id=fingerprint,
                    assignment_id=principal.assignment_id)
                store, clock = authority.new_store()
                outbound = OutboundAuthorizer(
                    local_identity=coordinator_local,
                    snapshot_store=store,
                    clock=clock,
                    target=target,
                    worker_request_type=Request,
                    trusted_request_context_type=TrustedRequestContext,
                    allow_bootstrap_describe=True)
                peer = FixedPeer(
                    endpoint=f"127.0.0.1:{node['server'].port}",
                    allowed_addresses=("127.0.0.1",),
                    device_id=principal.device_id,
                    server_leaf_pem=principal.certificate_pem,
                    cohort_ca_pem=authority.cohort_ca_pem,
                    expected_server=_expected_server(principal,
                                                     ExpectedServerIdentity))
                secure_client = await create_secure_worker_client(
                    peer,
                    local_identity=LocalTlsIdentity(
                        coordinator_principal.certificate_pem,
                        coordinator_principal.private_key_pem),
                    outbound_authorizer=outbound,
                    authorization_watcher=watcher,
                    verify_expected_server_leaf=tls_verifier,
                    connection_controller=budget)
                client_holder = {"client": secure_client}
                cleanup_owner.add(
                    f"worker-{index} outbound client",
                    lambda holder=client_holder: close_owned_worker_client(holder))
                bootstrap = outbound.create_bootstrap_context(
                    lifetime_seconds=120, max_describes=2)
                wrapped_client = BootstrapWorkerClient(secure_client, bootstrap)
                client_holder["client"] = wrapped_client
                worker_clients.append(wrapped_client)
                probe = Request(
                    protocol_version=1,
                    manifest_fingerprint=fingerprint,
                    timeout_ms=5_000)
                self.assertIs(type(probe), Request)
                response = await wrapped_client.execute("Describe", probe)
                self.assertEqual(response.worker_boot_id, principal.boot_id)
                self.assertEqual(response.manifest_fingerprint, fingerprint)
                self.assertIs(type(secure_client._subchannel.connector), SecureConnector)
                self.assertEqual(budget.reserved_outbound_pending, 0)

            # These are the only reference and coordinator model instances in
            # the harness. Both load the same already-pinned local files offline.
            from steamboat_runtime.prepare import verify_snapshot

            verify_snapshot(self.reference_dir)
            reference = AutoModelForCausalLM.from_pretrained(
                str(self.reference_dir),
                dtype=torch.float32,
                attn_implementation="eager",
                local_files_only=True,
                use_safetensors=True,
            )
            cleanup_owner.add("complete-model reference release", release_reference)
            reference = reference.to("cpu").eval().requires_grad_(False)
            model_class = supervised_model_class()
            model = model_class.from_artifacts(
                self.artifact_dir, self.reference_dir)
            model_cleanup = cleanup_owner.add(
                "supervised coordinator model close", model.close)
            coordinator = Coordinator(self.manifest, worker_clients, model)
            cleanup_owner.add("coordinator close", coordinator.close)
            cleanup_owner.disarm(model_cleanup)
            await coordinator.start()

            coordinator_store, coordinator_clock = authority.new_store()
            coordinator_authorizer = Authorizer(
                local_identity=coordinator_local,
                snapshot_store=coordinator_store,
                clock=coordinator_clock)
            context_factory = ConsumerContextFactory(
                account_id=coordinator_principal.account_id,
                device_id=coordinator_principal.device_id,
                coordinator_boot_id=coordinator_principal.boot_id,
                model_id=fingerprint)
            self.assertEqual(self.manifest["config"]["vocab_size"], 32_000)
            self.assertEqual(coordinator.limits.output_queue_tokens, 16)
            capture_budget = CaptureBudget(CaptureBudgetConfig(
                vocabulary_size=32_000,
                output_queue_slots=coordinator.limits.output_queue_tokens,
                max_active_captures=8,
                capacity_bytes=1 << 30,
            ))
            self.assertEqual(capture_budget.status().per_capture.vocabulary_size,
                             32_000)
            self.assertEqual(capture_budget.status().per_capture.output_queue_slots,
                             16)
            self.assertEqual(capture_budget.status().capacity_bytes, 1 << 30)
            service = CoordinatorService(coordinator)
            coordinator_server, coordinator_secure_service = (
                await create_secure_coordinator_server(
                    service,
                    listen_endpoint="127.0.0.1:0",
                    allowed_listen_addresses=("127.0.0.1",),
                    server_identity=LocalTlsIdentity(
                        coordinator_principal.certificate_pem,
                        coordinator_principal.private_key_pem),
                    client_ca_pem=authority.cohort_ca_pem,
                    authorizer=coordinator_authorizer,
                    authorization_watcher=watcher,
                    request_context_factory=context_factory,
                    connection_controller=budget,
                    listener_id="secure-pipeline-coordinator",
                    listener_slots=1,
                    acceptor_directory=str(acceptor_directory),
                    capture_budget=capture_budget))
            cleanup_owner.add(
                "coordinator listener stop",
                lambda: coordinator_server.stop(0))

            consumer_principal = authority.principals["consumer"]
            consumer_store, consumer_clock = authority.new_store()
            consumer_target = OutboundTarget.from_record(
                service=COORDINATOR_SERVICE,
                record=coordinator_principal.record,
                boot_id=coordinator_principal.boot_id,
                model_id=fingerprint)
            consumer_outbound = OutboundAuthorizer(
                local_identity=LocalIdentity(
                    consumer_principal.certificate_pem,
                    consumer_principal.boot_id,
                    fingerprint),
                snapshot_store=consumer_store,
                clock=consumer_clock,
                target=consumer_target)
            consumer_peer = FixedPeer(
                endpoint=f"127.0.0.1:{coordinator_server.port}",
                allowed_addresses=("127.0.0.1",),
                device_id=coordinator_principal.device_id,
                server_leaf_pem=coordinator_principal.certificate_pem,
                cohort_ca_pem=authority.cohort_ca_pem,
                expected_server=_expected_server(
                    coordinator_principal, ExpectedServerIdentity))
            coordinator_client = await create_secure_coordinator_client(
                consumer_peer,
                local_identity=LocalTlsIdentity(
                    consumer_principal.certificate_pem,
                    consumer_principal.private_key_pem),
                outbound_authorizer=consumer_outbound,
                authorization_watcher=watcher,
                verify_expected_server_leaf=tls_verifier,
                connection_controller=budget)
            cleanup_owner.add(
                "consumer coordinator client close", coordinator_client.close)

            self.assertEqual(budget.reserved_connections, 16)
            self.assertEqual(budget.reserved_listener_pending_capacity, 4)
            self.assertEqual(budget.reserved_pending, 0)
            self.assertEqual(budget.reserved_outbound_pending, 0)

            request_ids = []
            session_ids = []
            prompt_ids = [7, 13, 31]
            with torch.inference_mode():
                reference_output = reference(
                    input_ids=torch.tensor([prompt_ids], dtype=torch.long),
                    use_cache=False,
                    return_dict=True)
                expected_token = int(reference_output.logits[0, -1].argmax().item())
            del reference_output

            request_context, events = await self._secure_generate(
                coordinator_client, consumer_outbound, prompt_ids,
                new_tokens=1, capture_logits=False)

            self.assertRegex(request_context.request_id, TYPED_REQUEST)
            request_ids.append(request_context.request_id)
            self.assertEqual([event["type"] for event in events], ["token", "result"])
            token_event, result_event = events
            self.assertRegex(token_event["session_id"], TYPED_SESSION)
            session_ids.append(token_event["session_id"])
            self.assertEqual(result_event["session_id"], token_event["session_id"])
            self.assertEqual(result_event["status"], "completed")
            self.assertIs(result_event["cleanup_complete"], True)
            self.assertEqual(token_event["token_id"], expected_token)
            self.assertEqual(result_event["token_ids"], [expected_token])
            await self._assert_request_reclaimed(
                coordinator=coordinator, service=service,
                secure_service=coordinator_secure_service,
                worker_nodes=worker_nodes, capture_budget=capture_budget,
                transport_budget=budget)

            # Keep one real coordinator/reference/cohort resident for this
            # authenticated numerical matrix. Each case gets a fresh typed
            # request context and completed worker session.
            for prompt_length in (1, 128, 1024):
                prompt = [3 + ((index * 37 + 11) % (32_000 - 3))
                          for index in range(prompt_length)]
                forced_token, expected_vectors = _reference_forced_last_positions(
                    reference, torch, prompt)
                forced_tokens = [forced_token] * 8
                self.assertEqual(len(forced_tokens), 8)
                self.assertLessEqual(prompt_length + 9,
                                     self.manifest["limits"]["max_positions"])
                comparisons = []

                def compare_capture(event):
                    index = len(comparisons)
                    self.assertLess(index, 9)
                    self.assertEqual(len(event["logits"]), 32_000)
                    actual = torch.tensor(event["logits"], dtype=torch.float32)
                    expected = expected_vectors[index]
                    self.assertTrue(bool(torch.isfinite(actual).all().item()))
                    error = float(torch.max(torch.abs(actual - expected)).item())
                    self.assertTrue(
                        bool(torch.allclose(actual, expected, atol=1e-3, rtol=0.0)),
                        msg=(f"last-position logits differ: prompt={prompt_length}, "
                             f"index={index}, max_abs_error={error}"),
                    )
                    expected_token = int(expected.argmax().item())
                    self.assertEqual(event["token_id"], expected_token)
                    comparisons.append((event["index"], event["sequence"],
                                        event["position"], event["token_id"]))
                    del actual

                context, matrix_events = await self._secure_generate(
                    coordinator_client, consumer_outbound, prompt,
                    new_tokens=9, forced_tokens=forced_tokens,
                    capture_logits=True, on_token=compare_capture)
                request_ids.append(context.request_id)
                self.assertRegex(context.request_id, TYPED_REQUEST)
                self.assertEqual(
                    [event["type"] for event in matrix_events],
                    ["token"] * 9 + ["result"],
                )
                matrix_tokens = matrix_events[:-1]
                terminal = matrix_events[-1]
                self.assertEqual(len(comparisons), 9)
                self.assertEqual(tuple(item[0] for item in comparisons), tuple(range(9)))
                self.assertEqual(tuple(item[1] for item in comparisons), tuple(range(9)))
                self.assertEqual(
                    tuple(item[2] for item in comparisons),
                    tuple(prompt_length + index for index in range(9)),
                )
                self.assertEqual(
                    tuple(item[3] for item in comparisons),
                    tuple(event["token_id"] for event in matrix_tokens),
                )
                self.assertTrue(all(
                    event["session_id"] == matrix_tokens[0]["session_id"]
                    for event in matrix_tokens))
                self.assertRegex(matrix_tokens[0]["session_id"], TYPED_SESSION)
                session_ids.append(matrix_tokens[0]["session_id"])
                self.assertEqual(terminal["session_id"], matrix_tokens[0]["session_id"])
                self.assertEqual(terminal["status"], "completed")
                self.assertIs(terminal["cleanup_complete"], True)
                self.assertEqual(len(terminal["token_ids"]), 9)
                self.assertEqual(
                    terminal["token_ids"],
                    [event["token_id"] for event in matrix_tokens],
                )
                self.assertEqual(len(comparisons), len(terminal["token_ids"]))
                self.assertNotEqual(forced_token, comparisons[0][3])
                await self._assert_request_reclaimed(
                    coordinator=coordinator, service=service,
                    secure_service=coordinator_secure_service,
                    worker_nodes=worker_nodes, capture_budget=capture_budget,
                    transport_budget=budget)
                del expected_vectors, matrix_events, matrix_tokens, comparisons
                gc.collect()

            self.assertEqual(len(request_ids), 4)
            self.assertEqual(len(set(request_ids)), len(request_ids))
            self.assertTrue(all(TYPED_REQUEST.fullmatch(value) for value in request_ids))
            self.assertEqual(len(session_ids), 4)
            self.assertEqual(len(set(session_ids)), len(session_ids))
            self.assertTrue(all(TYPED_SESSION.fullmatch(value) for value in session_ids))

            await self._run_lifecycle_extensions({
                "torch": torch,
                "reference": reference,
                "coordinator": coordinator,
                "coordinator_client": coordinator_client,
                "consumer_outbound": consumer_outbound,
                "service": service,
                "secure_service": coordinator_secure_service,
                "worker_nodes": worker_nodes,
                "capture_budget": capture_budget,
                "transport_budget": budget,
                "cleanup_owner": cleanup_owner,
                "manifest": self.manifest,
            })

        except BaseException as error:
            primary_error = error
        finally:
            teardown_failures = []
            try:
                teardown_failures.extend(await cleanup_owner.aclose())
            except BaseException as error:
                # Keep verification and the original test failure observable if
                # the cleanup owner itself ever fails unexpectedly.
                teardown_failures.append(
                    _CleanupFailure("cleanup owner drain", error))

            if budget is not None:
                verify_after_cleanup(
                    "connection reservations",
                    lambda: self.assertEqual(budget.reserved_connections, 0),
                    teardown_failures)
                verify_after_cleanup(
                    "pending reservations",
                    lambda: self.assertEqual(budget.reserved_pending, 0),
                    teardown_failures)
                verify_after_cleanup(
                    "listener pending capacity",
                    lambda: self.assertEqual(
                        budget.reserved_listener_pending_capacity, 0),
                    teardown_failures)
                verify_after_cleanup(
                    "outbound pending reservations",
                    lambda: self.assertEqual(budget.reserved_outbound_pending, 0),
                    teardown_failures)
            if capture_budget is not None:
                def verify_capture_budget():
                    capture_status = capture_budget.status()
                    self.assertEqual(capture_status.active_captures, 0)
                    self.assertEqual(capture_status.cleanup_pending_captures, 0)
                    self.assertEqual(capture_status.reserved_bytes, 0)

                verify_after_cleanup(
                    "capture reservations", verify_capture_budget,
                    teardown_failures)
            gc.collect()

            combined = _combined_pipeline_failure(primary_error, teardown_failures)
            if combined is not None:
                if combined is primary_error:
                    raise combined.with_traceback(primary_error.__traceback__)
                raise combined


def _expected_server(principal, identity_type):
    record = principal.record
    return identity_type(
        account_id=principal.account_id,
        device_id=principal.device_id,
        role=principal.role,
        serial=int(record["serial"], 16),
        public_key_hash=record["public_key_sha256"],
        certificate_hash=record["certificate_sha256"],
        expected_ip="127.0.0.1",
        ekus=tuple(record["ekus"]))


if __name__ == "__main__":
    unittest.main()
