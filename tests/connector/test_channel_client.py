"""Coordinator SDK checks over the genuine two-hop TLS/HELLO fixture."""
import asyncio
import secrets
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
from steamboat_security.outbound import AuthorizationWatcher
from tests.connector import test_gateway_router as gateway_router_tests


class CoordinatorChannelClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fx = gateway_router_tests.GatewayRouterTwoHopTests(
            methodName="test_submit_binds_real_two_hops_hello_generation_and_core_c1")
        # Register nested fixture cleanup before setup so partial setup also cleans.
        self.addCleanup(self.fx.doCleanups)
        self.fx.setUp()
        self.client = None

    async def asyncTearDown(self):
        if self.client is not None:
            try:
                await self.client.close()
            except ChannelClientOwnershipUncertain:
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

    async def test_describe_authorizes_on_genuine_route_and_correlates_local_c2_response(self):
        self.client = self._client()
        context = self.fx.base.adapter.create_bootstrap_context()
        request = Request(protocol_version=1, manifest_fingerprint=self.fx.model_id,
                          worker_boot_id=self.fx.worker_boot_id, timeout_ms=5000)
        call = asyncio.create_task(self.client.execute(
            "Describe", request, trusted_request_context=context))
        server_request = None
        for _ in range(500):
            self.fx.coordinator_server_stream.pump()
            server_request = self.fx.coordinator_server_stream.pop_message()
            if server_request is not None:
                break
            await asyncio.sleep(0.001)
        self.assertIsNotNone(server_request)
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
        call = asyncio.create_task(self.client.execute(
            "Describe", request, trusted_request_context=context))
        for _ in range(500):
            self.fx.coordinator_server_stream.pump()
            incoming = self.fx.coordinator_server_stream.pop_message()
            if incoming is not None:
                break
            await asyncio.sleep(0.001)
        else:
            self.fail("coordinator did not receive the authorized request")
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
        captured, children = {}, []

        async def remote_owner():
            await release.wait()

        async def watcher(_authorization):
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
            call = asyncio.create_task(self.client.execute(
                "Describe", request, trusted_request_context=context))
            for _ in range(500):
                self.fx.coordinator_server_stream.pump()
                if self.fx.coordinator_server_stream.pop_message() is not None:
                    break
                await asyncio.sleep(0.001)
            else:
                self.fail("coordinator did not receive the authorized request")
            with self.assertRaises(SecureTaskPending) as caught:
                await asyncio.wait_for(call, timeout=2)

        self.assertTrue(caught.exception.authorization_transferred)
        self.assertEqual(len(children), 1)
        self.assertEqual(self.client._data_bytes, _DATA_CAPTURE)
        self.assertEqual(self.client._data_count, 1)
        owner = next(iter(self.client._owners.values()))
        self.assertIs(owner["auth"], captured["auth"])
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
            call = asyncio.create_task(self.client.execute(
                "OpenSession", request, trusted_request_context=context))
            for _ in range(500):
                self.fx.coordinator_server_stream.pump()
                incoming = self.fx.coordinator_server_stream.pop_message()
                if incoming is not None:
                    break
                await asyncio.sleep(0.001)
            else:
                self.fail("coordinator did not receive the authorized request")
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
        describe = asyncio.create_task(self.client.execute(
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

