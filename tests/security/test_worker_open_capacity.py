"""Opt-in proof that raw gRPC receive exhaustion is unknown OpenSession state.

This uses real C0 identities, a native mTLS Worker listener, and the actual
Coordinator reservation/cleanup methods. It does not run a model stage. Raw
transport failures and handler failures that invalidate authorization remain
unknown OpenSession outcomes; this does not claim to prove a safe protobuf
capacity response through the native authorization bridge.
"""
from __future__ import annotations

import asyncio
import inspect
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


_RETAINED_UNCONFIRMED_TEST_OWNERS = []


@unittest.skipUnless(os.environ.get("STEAMBOAT_SECURE_PIPELINE_TESTS") == "1",
                     "set STEAMBOAT_SECURE_PIPELINE_TESTS=1 for native TLS tests")
class WorkerOpenCapacityClassificationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != "posix" or sys.platform != "linux":
            raise RuntimeError("worker capacity regression requires native Linux")
        artifacts = os.environ.get("STEAMBOAT_ARTIFACT_DIR")
        if not artifacts or not Path(artifacts).is_dir():
            raise RuntimeError("required test needs STEAMBOAT_ARTIFACT_DIR")
        from steamboat_runtime.manifest import load_manifest
        cls.artifact_directory = Path(artifacts).resolve(strict=True)
        cls.manifest = load_manifest(cls.artifact_directory)
        cls.fingerprint = cls.manifest["fingerprint"]

    async def test_raw_receive_cap_and_invalidated_handler_capacity_keep_open_unknown(self):
        from steamboat_runtime.coordinator import Coordinator, _RequestState
        from steamboat_runtime.protocol.secure_transport import (
            C0ExpectedServerLeafAdapter, ExpectedServerIdentity, FixedPeer,
            LocalTlsIdentity, NodeConnectionBudget,
            create_secure_worker_client, create_secure_worker_server,
            outgoing_binding_metadata,
        )
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_runtime.protocol import MAX_MESSAGE_BYTES
        from steamboat_runtime.protocol.errors import ProtocolError
        from steamboat_runtime.secure_worker_runtime import SecureWorkerRuntimeBridge
        from steamboat_runtime.worker_state import StageExecutor, WorkerHandler
        from steamboat_security import (
            AuthorizationWatcher, Authorizer, LocalIdentity,
            OutboundAuthorizer, OutboundTarget, SessionBindings,
            verify_expected_server_leaf,
        )
        from steamboat_security.codec import COORDINATOR_SERVICE, WORKER_SERVICE
        from steamboat_runtime.secure_context import (
            BootstrapWorkerClient, ConsumerContextFactory,
        )
        from steamboat_runtime.participant_context import TrustedRequestContext
        from steamboat_runtime.remote_client import validate_generate
        from tests.security.secure_pipeline_fixture import SecurePipelineIdentityFixture
        from tests.security.test_secure_pipeline import _expected_server

        fixture = SecurePipelineIdentityFixture(self.fingerprint)
        temp = tempfile.TemporaryDirectory(prefix="worker-open-capacity-")
        acceptor_directory = Path(temp.name) / "acceptors"
        acceptor_directory.mkdir(mode=0o700)
        budget = NodeConnectionBudget(max_connections=16, max_pending=4)
        nodes = []
        clients = []
        core_authorizations = []
        outbound_authorizations = []
        trusted_contexts = []
        context_factories = []
        coordinator = None
        handle = None
        state = None
        primary = None
        cleanup_errors = []

        async def cleanup(label, callback, *, false_is_failure=False):
            try:
                value = callback()
                if inspect.isawaitable(value):
                    value = await value
                if false_is_failure and value is False:
                    raise RuntimeError(f"{label} did not confirm cleanup")
            except BaseException as error:
                try:
                    error.add_note(f"worker OpenSession test teardown: {label}")
                except (AttributeError, TypeError):
                    pass
                cleanup_errors.append(error)

        def make_context(timeout_seconds=60.0):
            coordinator_principal = fixture.principals["coordinator"]
            consumer = fixture.principals["consumer"]
            coordinator_store, coordinator_clock = fixture.new_store()
            consumer_target = OutboundTarget.from_record(
                service=COORDINATOR_SERVICE, record=coordinator_principal.record,
                boot_id=coordinator_principal.boot_id, model_id=self.fingerprint)
            consumer_outbound = OutboundAuthorizer(
                local_identity=LocalIdentity(
                    consumer.certificate_pem, consumer.boot_id, self.fingerprint,
                    consumer.assignment_id),
                snapshot_store=coordinator_store, clock=coordinator_clock,
                target=consumer_target)
            payload = validate_generate({
                "input_ids": [7], "new_tokens": 1, "forced_tokens": None,
                "capture_logits": False, "timeout_seconds": timeout_seconds,
            })
            request_context = consumer_outbound.create_consumer_request_context(
                lifetime_seconds=60)
            outbound_auth = consumer_outbound.authorize_outbound(
                service=COORDINATOR_SERVICE, method="Generate", payload=payload,
                trusted_request_context=request_context,
                peer_certificate_pem=coordinator_principal.certificate_pem)
            outbound_authorizations.append(outbound_auth)
            incoming = Authorizer(
                local_identity=LocalIdentity(
                    coordinator_principal.certificate_pem,
                    coordinator_principal.boot_id, self.fingerprint),
                snapshot_store=coordinator_store, clock=coordinator_clock,
            ).authorize(
                COORDINATOR_SERVICE, "Generate", payload,
                outgoing_binding_metadata(outbound_auth.binding_bytes),
                consumer.certificate_pem)
            core_authorizations.append(incoming)
            factory = ConsumerContextFactory(
                account_id=coordinator_principal.account_id,
                device_id=coordinator_principal.device_id,
                coordinator_boot_id=coordinator_principal.boot_id,
                model_id=self.fingerprint)
            context_factories.append(factory)
            context = factory.create_with_deadline(
                incoming, payload, absolute_deadline=time.monotonic() + 60)
            trusted_contexts.append(context)
            return context

        def make_state(context, lifetime_seconds=10):
            now = time.monotonic()
            return _RequestState(
                session_id=context.session_id, input_ids=None, prompt_length=1,
                new_tokens=1, forced_tokens=None, capture_logits=False,
                submitted_at=now, deadline=now + lifetime_seconds,
                output=asyncio.Queue(), completion=asyncio.get_running_loop().create_future(),
                admission=asyncio.get_running_loop().create_future(),
                trusted_request_context=context)

        primary_error = None
        try:
            coordinator_principal = fixture.principals["coordinator"]
            coordinator_store, coordinator_clock = fixture.new_store()
            coordinator_local = LocalIdentity(
                coordinator_principal.certificate_pem,
                coordinator_principal.boot_id, self.fingerprint)
            watcher = AuthorizationWatcher(poll_interval_seconds=0.1)
            tls_verifier = C0ExpectedServerLeafAdapter(verify_expected_server_leaf)

            for worker_index in (1, 2, 3):
                principal = fixture.principals[f"worker-{worker_index}"]
                store, clock = fixture.new_store()
                session_bindings = SessionBindings(clock=clock)
                authorizer = Authorizer(
                    local_identity=LocalIdentity(
                        principal.certificate_pem, principal.boot_id,
                        self.fingerprint, principal.assignment_id),
                    snapshot_store=store, clock=clock,
                    session_bindings=session_bindings, worker_request_type=Request)
                executor = StageExecutor(self.artifact_directory, f"worker-{worker_index}")
                handler = WorkerHandler(
                    self.manifest, f"worker-{worker_index}", executor,
                    boot_id=principal.boot_id, enable_queue=True,
                    max_tombstones=1 if worker_index == 3 else 4096)
                node = {
                    "principal": principal, "store": store, "clock": clock,
                    "bindings": session_bindings, "handler": handler,
                    "executor": executor, "bridge": None, "server": None,
                    "calls": [], "responses": [], "request_sizes": [],
                    "outbound": None, "peer": None, "raw_client": None,
                }
                nodes.append(node)
                bridge = SecureWorkerRuntimeBridge(
                    authorizer, handler, sweep_interval_seconds=0.1)
                node["bridge"] = bridge
                await bridge.start()
                node["server"] = await create_secure_worker_server(
                    bridge.handler, listen_endpoint="127.0.0.1:0",
                    allowed_listen_addresses=("127.0.0.1",),
                    server_identity=LocalTlsIdentity(
                        principal.certificate_pem, principal.private_key_pem),
                    client_ca_pem=fixture.cohort_ca_pem,
                    authorizer=bridge.incoming_authorizer,
                    authorization_watcher=bridge.authorization_watcher,
                    connection_controller=budget,
                    listener_id=f"worker-open-capacity-{worker_index}",
                    listener_slots=1, acceptor_directory=str(acceptor_directory))

                original_handle = handler.handle
                async def record_handle(method, request, *, original=original_handle,
                                        node=node):
                    node["calls"].append(method)
                    node["request_sizes"].append((method, request.ByteSize()))
                    response = await original(method, request)
                    node["responses"].append((method, response.ByteSize(), response.code))
                    return response
                handler.handle = record_handle

                worker_store, worker_clock = fixture.new_store()
                target = OutboundTarget.from_record(
                    service=WORKER_SERVICE, record=principal.record,
                    boot_id=principal.boot_id, model_id=self.fingerprint,
                    assignment_id=principal.assignment_id)
                outbound = OutboundAuthorizer(
                    local_identity=coordinator_local,
                    snapshot_store=worker_store, clock=worker_clock,
                    target=target, worker_request_type=Request,
                    trusted_request_context_type=TrustedRequestContext,
                    allow_bootstrap_describe=True)
                node["outbound"] = outbound
                peer = FixedPeer(
                    endpoint=f"127.0.0.1:{node['server'].port}",
                    allowed_addresses=("127.0.0.1",),
                    device_id=principal.device_id,
                    server_leaf_pem=principal.certificate_pem,
                    cohort_ca_pem=fixture.cohort_ca_pem,
                    expected_server=_expected_server(principal, ExpectedServerIdentity))
                node["peer"] = peer
                max_bytes = 256 if worker_index == 2 else MAX_MESSAGE_BYTES
                client = await create_secure_worker_client(
                    peer, local_identity=LocalTlsIdentity(
                        coordinator_principal.certificate_pem,
                        coordinator_principal.private_key_pem),
                    outbound_authorizer=outbound, authorization_watcher=watcher,
                    verify_expected_server_leaf=tls_verifier,
                    connection_controller=budget, max_message_bytes=max_bytes)
                node["raw_client"] = client
                bootstrap = outbound.create_bootstrap_context(
                    lifetime_seconds=60, max_describes=2)
                clients.append(BootstrapWorkerClient(client, bootstrap))

            class AdmissionOnlyModel:
                def validate_tokens(self, value):
                    if (getattr(value, "ndim", None) != 2
                            or tuple(value.shape)[0] != 1
                            or tuple(value.shape)[1] < 1):
                        raise ValueError("test input shape is invalid")
                    return int(value.shape[1])

                async def embed(self, _tokens):
                    raise AssertionError("unknown OpenSession must prevent generation")

                async def close(self):
                    return True

            coordinator = Coordinator(
                self.manifest, clients, AdmissionOnlyModel())
            await coordinator.start()

            # The second worker's small C-core receive cap passes both real
            # Describe preflights but is below the larger OpenSession reply.
            context = make_context(timeout_seconds=10.0)
            import torch
            torch.set_num_threads(2)
            handle = coordinator.submit(
                torch.tensor([[7]], dtype=torch.long), 1,
                timeout_seconds=10, trusted_request_context=context)
            result = await asyncio.wait_for(handle.result(), timeout=20)
            state = handle._state
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.error_code, "EXECUTION_FAILED")
            self.assertIs(result.cleanup_complete, False)
            self.assertEqual(state.unknown_opens, {1})
            self.assertEqual(state.leases, {})
            self.assertEqual(coordinator.stats()["ready"], False)
            self.assertEqual(coordinator.stats()["active_requests"], 1)
            self.assertEqual(nodes[0]["calls"].count("OpenSession"), 1)
            self.assertEqual(nodes[0]["calls"].count("CancelSession"), 1)
            self.assertEqual(nodes[1]["calls"].count("OpenSession"), 1)
            self.assertEqual(nodes[2]["calls"].count("OpenSession"), 0)
            self.assertFalse(any("Step" in node["calls"] for node in nodes))
            self.assertTrue(any(
                method == "OpenSession" and code == "OK"
                and size > nodes[1]["raw_client"].max_message_bytes
                for method, size, code in nodes[1]["responses"]))
            self.assertTrue(all(
                size <= nodes[1]["raw_client"].max_message_bytes
                for method, size in nodes[1]["request_sizes"]
                if method == "OpenSession"))
            describe_sizes = [size for method, size, _code in nodes[1]["responses"]
                              if method == "Describe"]
            self.assertEqual(len(describe_sizes), 2)
            self.assertTrue(all(size <= nodes[1]["raw_client"].max_message_bytes
                                for size in describe_sizes))
            self.assertNotIn(state.session_id, nodes[0]["handler"].sessions)
            self.assertIn(state.session_id, nodes[1]["handler"].sessions)
            self.assertEqual(nodes[1]["handler"].supervision_status()["active_compute"], False)
            self.assertEqual(nodes[1]["bridge"].status()["owned_sessions"], 1)

            # The coordinator keeps its unknown owner charged and fenced even
            # after the real worker lease expires and the worker cache retires.
            expires_at = nodes[1]["handler"].sessions[state.session_id].deadline
            self.assertGreater(expires_at, time.monotonic())
            deadline = time.monotonic() + 15
            while (state.session_id in nodes[1]["handler"].sessions
                   or nodes[1]["bridge"].status()["owned_sessions"] != 0):
                if time.monotonic() >= deadline:
                    self.fail("unknown OpenSession owner did not expire its real lease")
                await asyncio.sleep(0.05)
            self.assertEqual(nodes[1]["handler"].supervision_status()["active_compute"], False)
            self.assertEqual(nodes[1]["bridge"].status()["owned_sessions"], 0)
            self.assertEqual(state.unknown_opens, {1})
            self.assertEqual(coordinator.stats()["ready"], False)
            self.assertEqual(coordinator.stats()["active_requests"], 1)

            # A completely delivered successful response with a mismatched
            # session identifier has the same unknown-admission semantics.
            mismatch_context = make_context()
            mismatch_context.claim_admission()
            mismatch_state = make_state(mismatch_context, lifetime_seconds=2)
            from steamboat_runtime.protocol.worker_pb2 import Response
            from steamboat_runtime.protocol import secure_transport as transport_module
            original_parse = transport_module.parse_message

            def mismatched_parse(data, message_type, maximum):
                parsed = original_parse(data, message_type, maximum)
                if message_type is Response and parsed.code == "OK":
                    suffix = "0" * 31 + ("1" if parsed.session_id[-1] != "1" else "2")
                    parsed.session_id = "ses_" + suffix
                return parsed

            with patch.object(transport_module, "parse_message",
                              side_effect=mismatched_parse):
                with self.assertRaises(ProtocolError) as mismatch_error:
                    await coordinator._reserve(mismatch_state, 2)
            self.assertEqual(getattr(mismatch_error.exception, "code", None),
                             "EXECUTION_FAILED")
            self.assertEqual(mismatch_state.unknown_opens, {2})
            self.assertIn(mismatch_state.session_id, nodes[2]["handler"].sessions)
            self.assertEqual(nodes[2]["calls"].count("OpenSession"), 1)
            mismatch_deadline = time.monotonic() + 5
            while mismatch_state.session_id in nodes[2]["handler"].sessions:
                if time.monotonic() >= mismatch_deadline:
                    self.fail("mismatched OpenSession owner did not expire its real lease")
                await asyncio.sleep(0.05)
            self.assertEqual(mismatch_state.unknown_opens, {2})

            # The expired mismatched OpenSession has left one real tombstone
            # in this worker. Its bounded tombstone table is now genuinely
            # full, so the next authorized OpenSession reaches WorkerHandler
            # and raises its real capacity error. The bridge invalidates the
            # authorization owner before delivery, so transport correctly
            # treats the outcome as unknown rather than claiming a known
            # pre-admission rejection.
            self.assertEqual(len(nodes[2]["handler"].tombstones), 1)
            capacity_context = make_context()
            capacity_context.claim_admission()
            capacity_state = make_state(capacity_context)
            coordinator.boot_ids[2] = nodes[2]["principal"].boot_id
            with self.assertRaises(ProtocolError) as unknown_capacity:
                await coordinator._reserve(capacity_state, 2)
            self.assertEqual(getattr(unknown_capacity.exception, "code", None),
                             "EXECUTION_FAILED")
            self.assertEqual(capacity_state.unknown_opens, {2})
            self.assertNotIn(capacity_state.session_id, nodes[2]["handler"].sessions)
            self.assertEqual(nodes[2]["calls"][-1], "OpenSession")
            self.assertEqual(nodes[2]["responses"][-1][0], "OpenSession")
            self.assertEqual(nodes[2]["responses"][-1][2], "CAPACITY_EXHAUSTED")

            # Logical shutdown remains fenced by the unknown owner; retain the
            # whole scheduler/context/client graph as test evidence.
            self.assertIs(await coordinator.close(), False)
            _RETAINED_UNCONFIRMED_TEST_OWNERS.append(
                (coordinator, handle, state, context, context_factories,
                 core_authorizations, clients, nodes, fixture))
        except BaseException as error:
            primary = error
            raise
        finally:
            if coordinator is not None:
                if not coordinator._closed:
                    async def close_fenced_coordinator():
                        await coordinator.close()
                    await cleanup("coordinator shutdown", close_fenced_coordinator)
                if (coordinator._requests
                        and not any(entry[0] is coordinator
                                    for entry in _RETAINED_UNCONFIRMED_TEST_OWNERS)):
                    _RETAINED_UNCONFIRMED_TEST_OWNERS.append(
                        (coordinator, handle, state, trusted_contexts,
                         context_factories, core_authorizations,
                         outbound_authorizations, clients, nodes, fixture))
            for client in reversed(clients):
                await cleanup("outbound client", client.close)
            for node in reversed(nodes):
                if node["server"] is not None:
                    await cleanup("worker listener", lambda node=node: node["server"].stop(0))
                if node["bridge"] is not None and node["bridge"]._started and not node["bridge"]._closed:
                    await cleanup("worker runtime bridge",
                                  lambda node=node: node["bridge"].stop(grace_seconds=5),
                                  false_is_failure=True)
                if node["handler"] is not None:
                    await cleanup("worker handler",
                                  lambda node=node: node["handler"].shutdown(grace_seconds=5),
                                  false_is_failure=True)
            import gc
            gc.collect()
            if coordinator is None or not coordinator._requests:
                for factory, context in zip(context_factories, trusted_contexts):
                    await cleanup("consumer context release",
                                  lambda factory=factory, context=context:
                                      factory.release(context))
                for authorization in core_authorizations:
                    await cleanup("consumer core authorization", authorization.close)
                for authorization in outbound_authorizations:
                    await cleanup("consumer outbound authorization", authorization.close)
            await cleanup("connection accounting", lambda: self.assertEqual(
                (budget.reserved_connections, budget.reserved_pending,
                 budget.reserved_outbound_pending), (0, 0, 0)))
            if cleanup_errors:
                if not any(entry[0] is coordinator
                           for entry in _RETAINED_UNCONFIRMED_TEST_OWNERS):
                    _RETAINED_UNCONFIRMED_TEST_OWNERS.append(
                        (coordinator, handle, state, trusted_contexts,
                         context_factories, core_authorizations,
                         outbound_authorizations, clients, nodes, fixture, temp))
            else:
                await cleanup("identity fixture", fixture.close)
                await cleanup("temporary acceptor root", temp.cleanup)
            if cleanup_errors:
                errors = ([primary] if primary is not None else []) + cleanup_errors
                raise BaseExceptionGroup(
                    "worker OpenSession capacity test and teardown failures", errors)


if __name__ == "__main__":
    unittest.main()
