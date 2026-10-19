"""Coordinator SDK checks over the genuine two-hop TLS/HELLO fixture."""
import asyncio
import secrets
import time
import traceback
import unittest
from unittest import mock

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_client import (
    ChannelClientOwnershipUncertain, CoordinatorChannelClient,
    _CONTROL_CAPTURE, _CONTROL_SLOTS,
    _DATA_CAPTURE, _DATA_SLOTS,
)
from steamboat_runtime.protocol.wire import Request, Response, serialize_message
from steamboat_runtime.protocol.secure_transport import SecureTaskPending
from steamboat_runtime.protocol.errors import ProtocolError
from steamboat_runtime.participant_context import TrustedRequestContext
from steamboat_security.outbound import AuthorizationWatcher
from steamboat_security.errors import SessionError
from steamboat_security.ids import new_id
from tests.connector import test_gateway_router as gateway_router_tests
from tests.security import test_identity_core as identity_tests


class CoordinatorChannelClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fx = gateway_router_tests.GatewayRouterTwoHopTests(
            methodName="test_submit_binds_real_two_hops_hello_generation_and_core_c1")
        # Register nested fixture cleanup before setup so partial setup also cleans.
        self.addCleanup(self.fx.doCleanups)
        self.fx.setUp()
        # The shared two-hop fixture normally uses a portable request wrapper
        # for its RPC tests. This adapter exercises the real generated worker
        # protobuf, so configure the same genuine C1 authorizer accordingly.
        self.fx.base.adapter.worker_request_type = Request
        self.client = None
        self._call_tasks = []
        self._release_events = []

    def _track_call(self, awaitable):
        task = asyncio.create_task(awaitable)
        self._call_tasks.append(task)
        return task

    def _unique_context(self, *, hard_lifetime):
        base = self.fx.base
        fixture = base.fx
        authorizer, _ = fixture.coordinator_authorizer(
            time_source=base.time_source, store=base.snapshot_store)
        request_id, session_id, route_id, operation_id = (
            new_id("req"), new_id("ses"), new_id("route"), new_id("op"))
        fields = {
            "binding_version": 1, "operation_id": operation_id,
            "account_id": identity_tests.ACCOUNT_A,
            "device_id": identity_tests.DEVICE_CONSUMER,
            "role": "consumer", "credential_epoch": 1,
            "target_device_id": identity_tests.DEVICE_COORDINATOR,
            "request_id": request_id,
        }
        authorization = authorizer.authorize(
            "steamboat.v1.Coordinator", "Generate",
            {"input_ids": [1], "new_tokens": 1, "timeout_seconds": 20,
             "capture_logits": False},
            fixture.metadata("steamboat.v1.Coordinator", "Generate", fields),
            fixture.credentials["consumer"]["certificate"])
        return TrustedRequestContext(
            tenant_account_id=identity_tests.ACCOUNT_A, request_id=request_id,
            session_id=session_id, route_id=route_id,
            coordinator_boot_id=identity_tests.BOOT_COORDINATOR,
            route_epoch=1, attempt=1, authorization=authorization,
            hard_monotonic_deadline=time.monotonic() + hard_lifetime)

    async def asyncTearDown(self):
        for release in self._release_events:
            release.set()
        active = [task for task in self._call_tasks if not task.done()]
        for task in active:
            task.cancel()
        if self._call_tasks:
            await asyncio.gather(*self._call_tasks, return_exceptions=True)
        if self.client is not None:
            retirements = tuple(self.client._retirement_tasks)
            if retirements:
                await asyncio.gather(*retirements, return_exceptions=True)
            try:
                await self.client.close()
            except (ChannelClientOwnershipUncertain, SecureTaskPending):
                pass

    def _client(self, *, data_bytes=None, control_bytes=None):
        return CoordinatorChannelClient(
            egress=self.fx.coordinator_egress,
            stream=self.fx.coordinator_client_stream,
            authorization_watcher=AuthorizationWatcher(),
            data_capture_reservation_bytes=(
                _DATA_SLOTS * _DATA_CAPTURE if data_bytes is None else data_bytes),
            control_capture_reservation_bytes=(
                _CONTROL_SLOTS * _CONTROL_CAPTURE if control_bytes is None else control_bytes))

    async def _server_request(self, call, *, description):
        for _ in range(500):
            self.fx.coordinator_server_stream.pump()
            incoming = self.fx.coordinator_server_stream.pop_message()
            if incoming is not None:
                return incoming
            if call.done():
                # Surface the actual C1/SDK failure immediately instead of
                # hiding it behind a timeout waiting for a wire message.
                await call
            await asyncio.sleep(0.001)
        self.fail(f"{description}: coordinator did not receive the authorized request")

    async def test_describe_authorizes_on_genuine_route_and_correlates_local_c2_response(self):
        self.client = self._client()
        context = self.fx.base.adapter.create_bootstrap_context()
        request = Request(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                          worker_boot_id=self.fx.worker_boot_id, timeout_ms=5000)
        call = self._track_call(self.client.execute(
            "Describe", request, trusted_request_context=context))
        server_request = await self._server_request(
            call, description="Describe request")
        self.assertEqual(server_request.kind, wire.DATA)
        forwarded = wire.decode_bundle(server_request.payload,
                                       fragment_kind=server_request.kind)
        self.assertEqual(forwarded.method, "Describe")
        self.assertTrue(forwarded.binding)
        echoed_request = Request()
        echoed_request.ParseFromString(forwarded.protobuf)
        self.assertGreaterEqual(echoed_request.timeout_ms, 1)
        response = Response(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                            worker_boot_id=self.fx.worker_boot_id, code="OK")
        self.fx.coordinator_server_stream.enqueue(
            kind=wire.RESPONSE, message_id=server_request.message_id,
            payload=wire.encode_bundle(
                "Describe", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
                protobuf=serialize_message(response)))
        for _ in range(500):
            self.fx.coordinator_server_stream.pump()
            if call.done():
                break
            await asyncio.sleep(0.001)
        result = await asyncio.wait_for(call, timeout=2)
        self.assertEqual(result.worker_boot_id, self.fx.worker_boot_id)
        self.assertEqual(self.client._data_bytes, 0)
        self.assertEqual(len(self.client._pending), 0)

    def test_constructor_requires_full_separate_capture_reservations(self):
        with self.assertRaises(ValueError):
            self._client(data_bytes=_DATA_SLOTS * _DATA_CAPTURE - 1)

    async def test_one_client_exclusively_owns_the_genuine_stream(self):
        self.client = self._client()
        with self.assertRaisesRegex(TypeError, "already has a client owner"):
            self._client()
        self.assertFalse(self.fx.coordinator_client_stream.closed)

    async def test_stream_loss_fails_pending_call_and_releases_local_capture(self):
        self.client = self._client()
        context = self.fx.base.adapter.create_bootstrap_context()
        request = Request(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                          worker_boot_id=self.fx.worker_boot_id, timeout_ms=5000)
        call = self._track_call(self.client.execute(
            "Describe", request, trusted_request_context=context))
        incoming = await self._server_request(call, description="stream-loss request")
        self.fx.coordinator_server_stream.close()
        with self.assertRaises(ProtocolError):
            await asyncio.wait_for(call, timeout=2)
        self.assertTrue(self.client._unavailable)
        self.assertEqual(self.client._data_bytes, 0)
        self.assertEqual(self.client._pending, {})
        self.assertTrue(self.fx.coordinator_client_stream.closed)

    async def test_oversized_control_request_is_rejected_before_copy_or_auth(self):
        self.client = self._client()
        context = self.fx.base.context
        request = Request(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                          worker_boot_id=self.fx.worker_boot_id,
                          session_id=context.session_id, lease_token="x" * 9000,
                          timeout_ms=5000)
        self.assertGreater(request.ByteSize(), wire.MAX_CONTROL_PROTOBUF_BYTES)
        copy_from = Request.CopyFrom
        copied = []
        def record_copy(self, other):
            copied.append(True)
            return copy_from(self, other)
        with mock.patch.object(Request, "CopyFrom", record_copy), \
             mock.patch.object(self.client.authorizer, "authorize_gateway_outbound") as authorize, \
             mock.patch.object(type(self.client.stream), "enqueue") as enqueue:
            with self.assertRaises(ProtocolError) as caught:
                await self.client.execute("CancelSession", request,
                                          trusted_request_context=context)
        self.assertEqual(caught.exception.code, "INVALID_INPUT")
        self.assertEqual(copied, [])
        authorize.assert_not_called()
        enqueue.assert_not_called()
        self.assertEqual(self.client._control_bytes, 0)
        self.assertEqual(self.client._control_count, 0)

    async def test_close_fault_sticks_capture_and_auth_without_retry(self):
        self.client = self._client()
        context = self.fx.base.adapter.create_bootstrap_context()
        request = Request(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                          worker_boot_id=self.fx.worker_boot_id, timeout_ms=5000)
        captured = {}
        original = self.client.authorizer.authorize_gateway_outbound

        close_calls = []
        def uncertain_close():
            close_calls.append(True)
            raise RuntimeError("injected uncertain C1 close")

        def capture_auth(**kwargs):
            captured["auth"] = original(**kwargs)
            # Inject the failure onto this exact genuine C1 authorization.
            captured["auth"].close = uncertain_close
            return captured["auth"]

        with mock.patch.object(self.client.authorizer, "authorize_gateway_outbound",
                               side_effect=capture_auth), \
             mock.patch.object(type(self.client.stream), "enqueue",
                               side_effect=RuntimeError("injected enqueue fault")):
            with self.assertRaises(ChannelClientOwnershipUncertain) as caught:
                await self.client.execute("Describe", request,
                                          trusted_request_context=context)
        self.assertIsInstance(caught.exception.__cause__, RuntimeError)
        self.assertEqual(len(close_calls), 1)
        self.assertEqual(self.client._data_bytes, _DATA_CAPTURE)
        self.assertEqual(self.client._data_count, 1)
        self.assertEqual(len(self.client._owners), 1)
        owner = next(iter(self.client._owners.values()))
        self.assertIs(owner["auth"], captured["auth"])
        self.assertIsNotNone(owner["request"])
        self.assertIsNotNone(owner["route"])
        self.assertEqual(owner["state"], "uncertain")
        with self.assertRaises(ChannelClientOwnershipUncertain):
            await self.client.close()
        self.assertEqual(len(close_calls), 1)
        self.assertFalse(self.client._close_complete)

    async def test_recursive_pending_retains_capture_until_auth_fail_and_close(self):
        self.client = self._client()
        context = self.fx.base.adapter.create_bootstrap_context()
        request = Request(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                          worker_boot_id=self.fx.worker_boot_id, timeout_ms=5000)
        captured = {}
        original = self.client.authorizer.authorize_gateway_outbound

        def capture_auth(**kwargs):
            captured["auth"] = original(**kwargs)
            return captured["auth"]

        release = asyncio.Event()
        self._release_events.append(release)
        async def remote_owner():
            await release.wait()

        async def child_owner():
            raise SecureTaskPending((grandchild,))

        grandchild = asyncio.create_task(remote_owner())
        child = asyncio.create_task(child_owner())

        async def handoff(awaitable, authorization, watcher, **kwargs):
            kwargs["on_pending"]((child,))
            pending = SecureTaskPending((child,))
            pending.authorization_transferred = True
            raise pending

        with mock.patch.object(self.client.authorizer, "authorize_gateway_outbound",
                               side_effect=capture_auth), \
             mock.patch("steamboat_connector.channel_client._run_guarded",
                        side_effect=handoff):
            with self.assertRaises(SecureTaskPending):
                await self.client.execute("Describe", request,
                                          trusted_request_context=context)
        self.assertEqual(self.client._data_bytes, _DATA_CAPTURE)
        self.assertEqual(self.client._data_count, 1)
        owner = next(iter(self.client._owners.values()))
        self.assertIs(owner["auth"], captured["auth"])
        self.assertTrue(owner["dispatched"])
        self.assertIsNotNone(owner["request"])
        self.assertIsNotNone(owner["raw_request"])
        self.assertNotEqual(owner["state"], "closed")
        self.assertFalse(owner["auth"]._closed)
        cleanup = next(iter(self.client._retirement_tasks))
        release.set()
        await asyncio.wait_for(cleanup, timeout=2)
        self.assertEqual(self.client._data_bytes, 0)
        self.assertEqual(self.client._data_count, 0)
        self.assertEqual(self.client._owners, {})
        self.assertTrue(captured["auth"]._failed)
        self.assertTrue(captured["auth"]._closed)

    async def test_real_guarded_pending_handoff_retains_auth_and_capture(self):
        self.client = self._client()
        context = self.fx.base.adapter.create_bootstrap_context()
        request = Request(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                          worker_boot_id=self.fx.worker_boot_id, timeout_ms=5000)
        release = asyncio.Event()
        receipt = asyncio.Event()
        self._release_events.append(release)
        captured, children = {}, []

        async def remote_owner():
            await release.wait()

        async def watcher(_authorization):
            await receipt.wait()
            child = asyncio.create_task(remote_owner())
            children.append(child)
            await asyncio.sleep(0)
            raise SecureTaskPending((child,))

        self.client.authorization_watcher = watcher
        original = self.client.authorizer.authorize_gateway_outbound
        def capture_auth(**kwargs):
            captured["auth"] = original(**kwargs)
            return captured["auth"]

        with mock.patch.object(self.client.authorizer, "authorize_gateway_outbound",
                               side_effect=capture_auth):
            call = self._track_call(self.client.execute(
                "Describe", request, trusted_request_context=context))
            pending_error = None
            received = False
            for _ in range(500):
                self.fx.coordinator_server_stream.pump()
                if self.fx.coordinator_server_stream.pop_message() is not None:
                    received = True
                    receipt.set()
                    break
                if call.done():
                    try:
                        await call
                    except SecureTaskPending as error:
                        pending_error = error
                        break
                await asyncio.sleep(0.001)
            if not received and pending_error is None:
                self.fail("coordinator did not receive the authorized request")
            if pending_error is None:
                with self.assertRaises(SecureTaskPending) as caught:
                    await asyncio.wait_for(call, timeout=2)
                pending_error = caught.exception

        self.assertTrue(pending_error.authorization_transferred)
        self.assertEqual(len(children), 1)
        self.assertEqual(self.client._data_bytes, _DATA_CAPTURE)
        self.assertEqual(self.client._data_count, 1)
        owner = next(iter(self.client._owners.values()))
        self.assertIs(owner["auth"], captured["auth"])
        self.assertTrue(owner["dispatched"])
        self.assertIsNotNone(owner["request"])
        self.assertIsNotNone(owner["raw_request"])
        self.assertIsNotNone(owner["bundle"])
        self.assertEqual(owner["state"], "pending")
        self.assertFalse(captured["auth"]._closed)

        cleanup = next(iter(self.client._retirement_tasks))
        release.set()
        await asyncio.wait_for(cleanup, timeout=2)
        self.assertEqual(self.client._data_bytes, 0)
        self.assertEqual(self.client._owners, {})
        self.assertTrue(captured["auth"]._failed)
        self.assertTrue(captured["auth"]._closed)

    async def test_expired_call_does_not_block_independent_context_or_control_cleanup(self):
        self.client = self._client()
        short_context = self._unique_context(hard_lifetime=2)
        long_context = self._unique_context(hard_lifetime=30)

        def open_request(context):
            return Request(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                           worker_boot_id=self.fx.worker_boot_id,
                           session_id=context.session_id, timeout_ms=5000,
                           max_positions=8, lifetime_ms=20000, idle_lease_ms=10000)

        short_call = self._track_call(self.client.execute(
            "OpenSession", open_request(short_context),
            trusted_request_context=short_context))
        long_call = self._track_call(self.client.execute(
            "OpenSession", open_request(long_context),
            trusted_request_context=long_context))
        short_wire = await self._server_request(short_call, description="short OpenSession")
        long_wire = await self._server_request(long_call, description="long OpenSession")
        self.fx.base.time_source.advance(3)
        with self.assertRaises(SessionError) as expired:
            await asyncio.wait_for(short_call, timeout=2)
        self.assertIsNone(expired.exception.__cause__)
        self.assertIsNone(expired.exception.__context__)
        self.assertNotIn("_pump", tuple(
            frame.f_code.co_name for frame, _line in traceback.walk_tb(
                expired.exception.__traceback__)))
        self.assertFalse(self.client._unavailable,
                         "request-local expiry fenced channel: "
                         f"{self.client._unavailable_reason} "
                         f"({self.client._unavailable_cause})")

        def open_response(context):
            return Response(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                            worker_boot_id=self.fx.worker_boot_id,
                            session_id=context.session_id, lease_token="lease_0123456789",
                            max_positions=8, code="OK")

        # The sent, expired call is abandoned locally. Its one matching late
        # response is discarded while the other context completes normally.
        self.fx.coordinator_server_stream.enqueue(
            kind=wire.RESPONSE, message_id=short_wire.message_id,
            payload=wire.encode_bundle(
                "OpenSession", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
                protobuf=serialize_message(open_response(short_context))))
        self.fx.coordinator_server_stream.enqueue(
            kind=wire.RESPONSE, message_id=long_wire.message_id,
            payload=wire.encode_bundle(
                "OpenSession", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
                protobuf=serialize_message(open_response(long_context))))
        for _ in range(500):
            self.fx.coordinator_server_stream.pump()
            if long_call.done():
                break
            await asyncio.sleep(0.001)
        opened = await asyncio.wait_for(long_call, timeout=2)
        self.assertEqual(opened.lease_token, "lease_0123456789")

        close_request = Request(
            protocol_version=1, manifest_fingerprint=self.fx.model_id,
            worker_boot_id=self.fx.worker_boot_id, session_id=long_context.session_id,
            lease_token=opened.lease_token, timeout_ms=5000)
        close_call = self._track_call(self.client.execute(
            "CloseSession", close_request, trusted_request_context=long_context))
        close_wire = await self._server_request(close_call, description="CloseSession")
        self.assertEqual(close_wire.kind, wire.CONTROL)
        closed = Response(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                          worker_boot_id=self.fx.worker_boot_id,
                          session_id=long_context.session_id,
                          lease_token=opened.lease_token, code="OK")
        self.fx.coordinator_server_stream.enqueue(
            kind=wire.CONTROL_RESPONSE, message_id=close_wire.message_id,
            payload=wire.encode_bundle(
                "CloseSession", wire.BUNDLE_RESPONSE,
                fragment_kind=wire.CONTROL_RESPONSE,
                protobuf=serialize_message(closed)))
        for _ in range(500):
            self.fx.coordinator_server_stream.pump()
            if close_call.done():
                break
            await asyncio.sleep(0.001)
        self.assertEqual((await asyncio.wait_for(close_call, timeout=2)).code, "OK")

    async def test_dispatched_request_timeout_retains_late_response_tombstone(self):
        self.client = self._client()
        request = Request(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                          worker_boot_id=self.fx.worker_boot_id, timeout_ms=200)
        call = self._track_call(self.client.execute(
            "Describe", request,
            trusted_request_context=self.fx.base.adapter.create_bootstrap_context()))
        timed_out_wire = await self._server_request(call, description="timed Describe")
        with self.assertRaises(TimeoutError):
            await asyncio.wait_for(call, timeout=2)
        self.assertEqual(self.client._abandoned.get(timed_out_wire.message_id),
                         ("Describe", wire.RESPONSE, self.client._generation))
        self.assertFalse(self.client._unavailable)

        next_call = self._track_call(self.client.execute(
            "Describe", Request(protocol_version=1,
                                manifest_fingerprint=self.fx.model_id,
                                worker_boot_id=self.fx.worker_boot_id,
                                timeout_ms=5000),
            trusted_request_context=self.fx.base.adapter.create_bootstrap_context()))
        next_wire = await self._server_request(next_call, description="next Describe")
        response = Response(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                            worker_boot_id=self.fx.worker_boot_id, code="OK")
        self.fx.coordinator_server_stream.enqueue(
            kind=wire.RESPONSE, message_id=timed_out_wire.message_id,
            payload=wire.encode_bundle(
                "Describe", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
                protobuf=serialize_message(response)))
        self.fx.coordinator_server_stream.enqueue(
            kind=wire.RESPONSE, message_id=next_wire.message_id,
            payload=wire.encode_bundle(
                "Describe", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
                protobuf=serialize_message(response)))
        for _ in range(500):
            self.fx.coordinator_server_stream.pump()
            if next_call.done():
                break
            await asyncio.sleep(0.001)
        self.assertEqual((await asyncio.wait_for(next_call, timeout=2)).code, "OK")

    async def test_cancellation_fails_dispatched_auth_before_close(self):
        self.client = self._client()
        context = self.fx.base.context
        request = Request(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                          worker_boot_id=self.fx.worker_boot_id,
                          session_id=context.session_id, timeout_ms=5000,
                          max_positions=32, lifetime_ms=20000, idle_lease_ms=10000)
        captured, events = {}, []
        original_authorize = self.client.authorizer.authorize_gateway_outbound

        def capture_auth(**kwargs):
            auth = original_authorize(**kwargs)
            captured["auth"] = auth
            original_fail, original_close = auth.fail, auth.close
            def record_fail(*, cache_may_exist):
                events.append(("fail", cache_may_exist))
                return original_fail(cache_may_exist=cache_may_exist)
            def record_close():
                events.append(("close",))
                return original_close()
            auth.fail, auth.close = record_fail, record_close
            return auth

        with mock.patch.object(self.client.authorizer, "authorize_gateway_outbound",
                               side_effect=capture_auth):
            call = self._track_call(self.client.execute(
                "OpenSession", request, trusted_request_context=context))
            incoming = await self._server_request(
                call, description="cancellation request")
            call.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await call
        self.assertEqual(events, [("fail", True), ("close",)])
        self.assertEqual(self.client._data_bytes, 0)
        self.assertEqual(self.client._owners, {})
        self.assertFalse(self.client._unavailable)
        self.assertEqual(len(self.client._abandoned), 1)

        # A canceled call must not fence another independent request on the
        # still-live genuine HELLO generation.
        describe = self._track_call(self.client.execute(
            "Describe", Request(protocol_version=1,
                                manifest_fingerprint=self.fx.model_id,
                                worker_boot_id=self.fx.worker_boot_id,
                                timeout_ms=5000),
            trusted_request_context=self.fx.base.adapter.create_bootstrap_context()))
        incoming = None
        for _ in range(500):
            self.fx.coordinator_server_stream.pump()
            incoming = self.fx.coordinator_server_stream.pop_message()
            if incoming is not None:
                break
            await asyncio.sleep(0.001)
        self.assertIsNotNone(incoming)
        canceled_id = next(iter(self.client._abandoned))
        self.fx.coordinator_server_stream.enqueue(
            kind=wire.RESPONSE, message_id=canceled_id,
            payload=wire.encode_bundle(
                "OpenSession", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
                protobuf=serialize_message(Response(code="OK"))))
        self.fx.coordinator_server_stream.enqueue(
            kind=wire.RESPONSE, message_id=incoming.message_id,
            payload=wire.encode_bundle(
                "Describe", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
                protobuf=serialize_message(Response(
                    protocol_version=1, manifest_fingerprint=self.fx.model_id,
                    worker_boot_id=self.fx.worker_boot_id, code="OK"))))
        for _ in range(500):
            self.fx.coordinator_server_stream.pump()
            if describe.done():
                break
            await asyncio.sleep(0.001)
        self.assertEqual((await asyncio.wait_for(describe, 2)).code, "OK")

    async def test_unknown_message_id_and_wrong_response_method_are_rejected(self):
        self.client = self._client()
        wrong = type("Message", (), {
            "message_id": secrets.token_bytes(16), "kind": wire.RESPONSE,
            "generation": self.client._generation, "payload": b""})()
        with self.assertRaises(ProtocolError):
            self.client._dispatch_response(wrong)
        self.assertFalse(self.client.stream.closed)
        message_id = secrets.token_bytes(16)
        self.client._pending[message_id] = {
            "future": asyncio.get_running_loop().create_future(),
            "method": "Describe", "response_lane": wire.RESPONSE,
        }
        payload = wire.encode_bundle(
            "OpenSession", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
            protobuf=b"x")
        wrong.message_id = message_id
        wrong.payload = payload
        with self.assertRaises(ProtocolError):
            self.client._dispatch_response(wrong)
        self.client._pending[message_id]["future"].cancel()
        self.client._pending.clear()
        self.assertFalse(self.client.stream.closed)

