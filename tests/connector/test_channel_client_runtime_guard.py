"""Runtime-owner fencing on the genuine coordinator channel client."""
import asyncio
import unittest
from unittest import mock

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_client import CoordinatorChannelClient
from steamboat_runtime.protocol.errors import ProtocolError
from steamboat_runtime.protocol.wire import Request, Response, serialize_message
from steamboat_security.outbound import AuthorizationWatcher
from tests.connector import test_channel_client as channel_client_tests


class CoordinatorChannelRuntimeGuardTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fx = channel_client_tests.CoordinatorChannelClientTests(
            methodName="test_describe_authorizes_on_genuine_route_and_correlates_local_c2_response")
        self.addCleanup(self.fx.doCleanups)
        self.fx.setUp()
        self.base = self.fx
        self.client = None
        self.calls = []

    def _client(self, guard=None):
        base = self.fx.fx
        return CoordinatorChannelClient(
            egress=base.coordinator_egress,
            stream=base.coordinator_client_stream,
            authorization_watcher=AuthorizationWatcher(),
            data_capture_reservation_bytes=(channel_client_tests._DATA_SLOTS
                                            * channel_client_tests._DATA_CAPTURE),
            control_capture_reservation_bytes=(channel_client_tests._CONTROL_SLOTS
                                               * channel_client_tests._CONTROL_CAPTURE),
            runtime_guard=guard)

    def _track(self, awaitable):
        task = asyncio.create_task(awaitable)
        self.calls.append(task)
        return task

    def _request(self):
        return Request(protocol_version=1, manifest_fingerprint=self.fx.fx.model_id,
                       worker_boot_id=self.fx.fx.worker_boot_id, timeout_ms=5000)

    async def asyncTearDown(self):
        for task in self.calls:
            if not task.done():
                task.cancel()
        if self.calls:
            await asyncio.gather(*self.calls, return_exceptions=True)
        if self.client is not None:
            try:
                await self.client.close()
            except BaseException:
                pass
        await self.fx.asyncTearDown()

    async def _receive_request(self, call):
        return await self.fx._server_request(call, description="runtime-guard request")

    async def test_guard_failure_before_admission_and_async_guard_are_rejected(self):
        def deny():
            raise RuntimeError("binding revoked")

        self.client = self._client(deny)
        context = self.fx.fx.base.adapter.create_bootstrap_context()
        original = self.client.authorizer.authorize_gateway_outbound
        with mock.patch.object(self.client.authorizer, "authorize_gateway_outbound",
                               wraps=original) as authorize:
            with self.assertRaises(ProtocolError):
                await self.client.execute("Describe", self._request(),
                                          trusted_request_context=context)
        authorize.assert_not_called()
        self.assertEqual(self.client._owners, {})
        self.assertEqual(self.client._data_count, 0)
        self.assertTrue(self.client._unavailable)

        async def async_guard():
            return None

        with self.assertRaises(TypeError):
            self._client(async_guard)

    async def test_guard_returning_awaitable_is_closed_and_fences(self):
        async def awaitable_result():
            return None
        # A callable can hide an async result from inspect.iscoroutinefunction;
        # the client must close that coroutine and fence when it is invoked.
        self.client = self._client(lambda: awaitable_result())
        context = self.fx.fx.base.adapter.create_bootstrap_context()
        with self.assertRaises(ProtocolError):
            await self.client.execute(
                "Describe", self._request(), trusted_request_context=context)
        self.assertTrue(self.client._runtime_invalidated.is_set())

    async def test_guard_rechecks_after_callback_self_invalidation(self):
        holder = {}
        calls = []

        def revoke_during_check():
            calls.append(True)
            holder["client"].request_runtime_invalidation("owner stopped")
            return None

        self.client = self._client(revoke_during_check)
        holder["client"] = self.client
        context = self.fx.fx.base.adapter.create_bootstrap_context()
        with self.assertRaises(ProtocolError):
            await self.client.execute("Describe", self._request(),
                                      trusted_request_context=context)
        self.assertTrue(calls)
        self.assertTrue(self.client._runtime_invalidated.is_set())
        self.assertEqual(self.client._owners, {})
        self.assertEqual(self.client._data_count, 0)

    async def test_minted_target_inherits_guard_through_reply_delivery(self):
        checks = []

        def allow():
            checks.append(True)
            return None

        self.client = self._client(allow)
        target = self.fx.fx.coordinator_egress._primary_view
        proxy = self.client.bind_target(target)
        context = self.fx.fx.base.adapter.create_bootstrap_context()
        call = self._track(proxy.execute("Describe", self._request(),
                                         trusted_request_context=context))
        incoming = await self._receive_request(call)
        self.assertEqual(incoming.kind, wire.DATA)
        response = Response(protocol_version=1,
                            manifest_fingerprint=self.fx.fx.model_id,
                            worker_boot_id=self.fx.fx.worker_boot_id,
                            code="OK")
        self.fx.fx.coordinator_server_stream.enqueue(
            kind=wire.RESPONSE, message_id=incoming.message_id,
            payload=wire.encode_bundle(
                "Describe", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
                protobuf=serialize_message(response)))
        for _ in range(500):
            self.fx.fx.coordinator_server_stream.pump()
            if call.done():
                break
            await asyncio.sleep(0.001)
        result = await asyncio.wait_for(call, timeout=2)
        self.assertEqual(result.code, "OK")
        self.assertGreaterEqual(len(checks), 5)
        self.assertEqual(self.client._owners, {})

    async def test_off_thread_invalidation_fences_queued_reply_before_delivery(self):
        checks = []

        def allow():
            checks.append(True)
            return None

        self.client = self._client(allow)
        context = self.fx.fx.base.adapter.create_bootstrap_context()
        call = self._track(self.client.execute(
            "Describe", self._request(), trusted_request_context=context))
        incoming = await self._receive_request(call)
        await asyncio.to_thread(
            self.client.request_runtime_invalidation, "selected binding retired")
        with self.assertRaises(ProtocolError):
            await asyncio.wait_for(call, timeout=2)
        self.assertTrue(self.client._runtime_invalidated.is_set())
        self.assertTrue(self.client._unavailable)
        self.assertTrue(self.client.stream.closed)
        self.assertEqual(self.client._data_count, 0)
        self.assertNotEqual(incoming.message_id, b"")

    async def test_guard_is_rechecked_after_response_parse_before_publication(self):
        self.client = self._client(lambda: None)
        context = self.fx.fx.base.adapter.create_bootstrap_context()
        call = self._track(self.client.execute(
            "Describe", self._request(), trusted_request_context=context))
        incoming = await self._receive_request(call)
        response = Response(protocol_version=1,
                            manifest_fingerprint=self.fx.fx.model_id,
                            worker_boot_id=self.fx.fx.worker_boot_id,
                            code="OK")
        self.fx.fx.coordinator_server_stream.enqueue(
            kind=wire.RESPONSE, message_id=incoming.message_id,
            payload=wire.encode_bundle(
                "Describe", wire.BUNDLE_RESPONSE, fragment_kind=wire.RESPONSE,
                protobuf=serialize_message(response)))
        original_parse = __import__(
            "steamboat_connector.channel_client", fromlist=["parse_message"]).parse_message

        def invalidate_while_parsing(*args, **kwargs):
            parsed = original_parse(*args, **kwargs)
            self.client.request_runtime_invalidation("binding retired before delivery")
            return parsed

        with mock.patch("steamboat_connector.channel_client.parse_message",
                        side_effect=invalidate_while_parsing):
            with self.assertRaises(ProtocolError):
                await asyncio.wait_for(call, timeout=2)
        self.assertTrue(self.client._runtime_invalidated.is_set())
        self.assertTrue(self.client._unavailable)
        self.assertEqual(self.client._owners, {})
        self.assertEqual(self.client._data_count, 0)

    async def test_default_c1_path_rejects_runtime_invalidation_without_mutation(self):
        self.client = self._client()
        self.assertFalse(self.client._runtime_invalidated.is_set())
        with self.assertRaises(RuntimeError):
            self.client.request_runtime_invalidation("not configured")
        self.assertFalse(self.client._runtime_invalidated.is_set())
        self.assertFalse(self.client._unavailable)
        self.assertFalse(self.client.stream.closed)


if __name__ == "__main__":
    unittest.main()
