"""Runtime-owner fencing on the genuine coordinator channel client."""
import asyncio
import threading
import unittest
from unittest import mock

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_client import CoordinatorChannelClient
from steamboat_connector.channel_stream import ChannelStreamError
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
        for release in self.fx._release_events:
            release.set()
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


    async def test_async_guard_rejected_on_fresh_genuine_stream(self):
        async def async_guard():
            return None

        with self.assertRaisesRegex(TypeError, "synchronous callback"):
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

    async def test_guard_non_none_return_fences_before_authorization(self):
        self.client = self._client(lambda: True)
        context = self.fx.fx.base.adapter.create_bootstrap_context()
        with mock.patch.object(self.client.authorizer,
                               "authorize_gateway_outbound") as authorize:
            with self.assertRaises(ProtocolError):
                await self.client.execute(
                    "Describe", self._request(), trusted_request_context=context)
        authorize.assert_not_called()
        self.assertTrue(self.client._runtime_invalidated.is_set())
        self.assertEqual(self.client._owners, {})

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
            checks.append(not self.client._lock.locked())
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
        self.assertTrue(all(checks), "runtime guard ran while the admission lock was held")
        self.assertEqual(self.client._owners, {})

    async def test_off_thread_invalidation_fences_queued_reply_before_delivery(self):
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
        from steamboat_connector.channel_stream import ChannelStream
        original_pop = ChannelStream.pop_message

        def pop_then_invalidate(stream):
            message = original_pop(stream)
            if (stream is self.client.stream and message is not None
                    and message.message_id == incoming.message_id
                    and message.kind == wire.RESPONSE):
                completed = threading.Event()
                def invalidate():
                    try:
                        self.client.request_runtime_invalidation("selected binding retired")
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        completed.set()
                errors = []
                thread = threading.Thread(target=invalidate)
                thread.start()
                self.assertTrue(completed.wait(1), "off-thread invalidation did not return promptly")
                thread.join(1)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
            return message

        with mock.patch.object(ChannelStream, "pop_message", pop_then_invalidate):
            for _ in range(500):
                try:
                    self.fx.fx.coordinator_server_stream.pump()
                except ChannelStreamError:
                    if not self.client._runtime_invalidated.is_set():
                        raise
                    break
                if call.done():
                    break
                await asyncio.sleep(0.001)
        with self.assertRaises(ProtocolError):
            await asyncio.wait_for(call, timeout=2)
        self.assertTrue(self.client._runtime_invalidated.is_set())
        self.assertTrue(self.client._unavailable)
        self.assertTrue(self.client.stream.closed)
        self.assertEqual(self.client._data_count, 0)
        self.assertEqual(self.client._pending, {})

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

        parsed = asyncio.Event()
        def parse_and_signal(*args, **kwargs):
            result = original_parse(*args, **kwargs)
            if len(args) > 1 and args[1] is Response:
                self.client.request_runtime_invalidation(
                    "binding retired before delivery")
                parsed.set()
            return result
        with mock.patch("steamboat_connector.channel_client.parse_message",
                        side_effect=parse_and_signal):
            for _ in range(500):
                try:
                    self.fx.fx.coordinator_server_stream.pump()
                except ChannelStreamError:
                    if not (parsed.is_set()
                            and self.client._runtime_invalidated.is_set()):
                        raise
                    break
                if parsed.is_set():
                    break
                await asyncio.sleep(0.001)
            self.assertTrue(parsed.is_set(), "genuine queued response was not parsed")
            with self.assertRaises(ProtocolError):
                await asyncio.wait_for(call, timeout=2)
        self.assertTrue(self.client._runtime_invalidated.is_set())
        self.assertTrue(self.client._unavailable)
        self.assertEqual(self.client._owners, {})
        self.assertEqual(self.client._data_count, 0)

    async def test_invalidation_after_authorization_return_retires_exact_owner(self):
        self.client = self._client(lambda: None)
        context = self.fx.fx.base.adapter.create_bootstrap_context()
        original = self.client.authorizer.authorize_gateway_outbound
        captured = {}
        close_started = asyncio.Event()
        release_close = asyncio.Event()
        self.fx._release_events.append(release_close)

        def authorize_then_revoke(**kwargs):
            auth = original(**kwargs)
            captured["auth"] = auth
            close = auth.close
            calls = []
            async def counted_close():
                calls.append(True)
                close_started.set()
                await release_close.wait()
                return close()
            auth.close = counted_close
            captured["close_calls"] = calls
            self.client.request_runtime_invalidation("owner retired after authorize")
            return auth

        with mock.patch.object(self.client.authorizer,
                               "authorize_gateway_outbound",
                               side_effect=authorize_then_revoke):
            call = self._track(self.client.execute(
                "Describe", self._request(), trusted_request_context=context))
            await asyncio.wait_for(close_started.wait(), timeout=2)
            self.assertEqual(self.client._data_count, 1)
            owner = next(iter(self.client._owners.values()))
            self.assertIs(owner["auth"], captured["auth"])
            release_close.set()
            with self.assertRaises(ProtocolError):
                await asyncio.wait_for(call, timeout=2)
        self.assertEqual(len(captured["close_calls"]), 1)
        self.assertTrue(captured["auth"]._closed)
        self.assertEqual(self.client._owners, {})
        self.assertEqual(self.client._data_count, 0)

    async def test_invalidation_during_success_cleanup_blocks_result_delivery(self):
        self.client = self._client(lambda: None)
        context = self.fx.fx.base.adapter.create_bootstrap_context()
        captured = {}
        original = self.client.authorizer.authorize_gateway_outbound
        close_started = asyncio.Event()
        release_close = asyncio.Event()
        self.fx._release_events.append(release_close)

        def capture(**kwargs):
            auth = original(**kwargs)
            captured["auth"] = auth
            original_close = auth.close
            async def delayed_close():
                close_started.set()
                await release_close.wait()
                original_close()
            auth.close = delayed_close
            return auth

        with mock.patch.object(self.client.authorizer,
                               "authorize_gateway_outbound", side_effect=capture):
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
                    "Describe", wire.BUNDLE_RESPONSE,
                    fragment_kind=wire.RESPONSE,
                    protobuf=serialize_message(response)))
            for _ in range(500):
                self.fx.fx.coordinator_server_stream.pump()
                if close_started.is_set():
                    break
                await asyncio.sleep(0.001)
            self.assertTrue(close_started.is_set(), "request did not reach owner cleanup")
            self.client.request_runtime_invalidation("retired during authorization cleanup")
            release_close.set()
            with self.assertRaises(ProtocolError):
                await asyncio.wait_for(call, timeout=2)
        self.assertTrue(captured["auth"]._closed)
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
