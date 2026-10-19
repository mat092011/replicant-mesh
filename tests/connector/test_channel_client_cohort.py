"""Several signed worker targets multiplex over one real coordinator stream."""

import asyncio
import json
import unittest
from unittest import mock

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_client import CoordinatorChannelTargetClient
from steamboat_runtime.participant_context import TrustedRequestContext
from steamboat_runtime.protocol.errors import ProtocolError
from steamboat_runtime.protocol.wire import Request, Response, serialize_message
from steamboat_security.outbound import OutboundAuthorizer, OutboundTarget
from steamboat_security.gateway_egress import GatewayEgressError
from steamboat_security.snapshot import sign_snapshot
from tests.connector.test_channel_client import CoordinatorChannelClientTests
from tests.connector import test_gateway_router as router_fixture
from tests.security import test_identity_core as identity_tests


class CoordinatorChannelCohortTests(CoordinatorChannelClientTests):
    def setUp(self):
        self._fixture_patches = []
        original_sign = router_fixture.sign_channel_policy
        original_accept = router_fixture.OwnedGatewayCoordinatorTLS.accept

        def sign_with_second_route(payload, signing_key):
            payload = json.loads(json.dumps(payload))
            for boot in ("e" * 32, "f" * 32):
                if not any(route["worker_boot_id"] == boot
                           for route in payload["routes"]):
                    route = dict(payload["routes"][0])
                    route["worker_boot_id"] = boot
                    payload["routes"].append(route)
            payload["routes"].sort(key=lambda item: (
                item["gateway_id"], item["account_id"], item["device_id"],
                item["actor_serial"], item["actor_credential_epoch"],
                item["actor_certificate_sha256"],
                item["coordinator_boot_id"], item["target_device_id"],
                item["worker_boot_id"], item["assignment_id"], item["model_id"]))
            if not any(worker["worker_boot_id"] == "f" * 32
                       for worker in payload["workers"]):
                worker = dict(payload["workers"][0])
                worker.update(worker_boot_id="f" * 32,
                    channel_serial="f123456789abcdef",
                    channel_certificate_sha256="9" * 64,
                    channel_public_key_sha256="a" * 64)
                payload["workers"].append(worker)
                payload["workers"].sort(key=lambda item: (
                    item["device_id"], item["worker_boot_id"]))
            return original_sign(payload, signing_key)

        def accept_with_second_target(*args, **kwargs):
            targets = dict(kwargs["target_certificates"])
            (device, _boot, assignment, model), cert = next(iter(targets.items()))
            targets[(device, "e" * 32, assignment, model)] = cert
            targets[(device, "f" * 32, assignment, model)] = cert
            kwargs["target_certificates"] = targets
            return original_accept(*args, **kwargs)

        self._fixture_patches.extend((
            mock.patch.object(router_fixture, "sign_channel_policy",
                              side_effect=sign_with_second_route),
            mock.patch.object(router_fixture.OwnedGatewayCoordinatorTLS,
                              "accept", side_effect=accept_with_second_target),
        ))
        for patcher in self._fixture_patches:
            patcher.start()
        try:
            super().setUp()
        finally:
            for patcher in reversed(self._fixture_patches):
                patcher.stop()
        self._add_second_c1_target()

    def _add_second_c1_target(self):
        base = self.fx.base
        fixture = self.fx.fx
        second_boot = self.fx.second_worker_boot_id
        coordinator = fixture.records["coordinator"]
        host = fixture.records["host"]
        methods = ("Describe", "OpenSession", "RenewSession", "Step",
                   "CloseSession", "CancelSession", "SessionStatus")
        extra = [fixture._grant(
            actor=coordinator, tenant=coordinator["account_id"], target=host,
            target_boot=boot, actor_boot=identity_tests.BOOT_COORDINATOR,
            assignment=identity_tests.ASSIGNMENT, model=identity_tests.MODEL,
            method=f"steamboat.v1.Worker/{method}",
            not_after=identity_tests.NOW + 300)
            for boot in (second_boot, "f" * 32) for method in methods]
        current = base.snapshot_store.current()
        payload = fixture.payload(
            now=identity_tests.NOW, revision=current.revision + 1,
            expiry=identity_tests.NOW + 300,
            grants=fixture.grants(expires=identity_tests.NOW + 300) + extra)
        base.snapshot_store.install(sign_snapshot(payload, fixture.signing_key))
        target = OutboundTarget.from_record(
            service="steamboat.v1.Worker", record=host, boot_id=second_boot,
            model_id=identity_tests.MODEL, assignment_id=identity_tests.ASSIGNMENT)
        self.second_authorizer = OutboundAuthorizer(
            local_identity=base.adapter.local_identity,
            snapshot_store=base.snapshot_store, clock=base.clock, target=target,
            worker_request_type=Request,
            trusted_request_context_type=TrustedRequestContext,
            allow_bootstrap_describe=True)
        third_target = OutboundTarget.from_record(
            service="steamboat.v1.Worker", record=host, boot_id="f" * 32,
            model_id=identity_tests.MODEL, assignment_id=identity_tests.ASSIGNMENT)
        self.third_authorizer = OutboundAuthorizer(
            local_identity=base.adapter.local_identity,
            snapshot_store=base.snapshot_store, clock=base.clock,
            target=third_target, worker_request_type=Request,
            trusted_request_context_type=TrustedRequestContext,
            allow_bootstrap_describe=True)

    def _client(self, *, data_bytes=None, control_bytes=None):
        return super()._client(data_bytes=data_bytes, control_bytes=control_bytes)

    async def test_three_worker_targets_share_one_stream_pump_and_capture_budget(self):
        self.client = self._client()
        root = self.fx.coordinator_egress
        with self.assertRaises(TypeError):
            self.client.bind_target(object())
        target_view = root.register_target(
            self.second_authorizer, self.fx.host["certificate"])
        proxy = self.client.bind_target(target_view)
        self.assertIsInstance(proxy, CoordinatorChannelTargetClient)
        self.assertIs(proxy, self.client.bind_target(target_view))
        third_view = root.register_target(
            self.third_authorizer, self.fx.host["certificate"])
        third_proxy = self.client.bind_target(third_view)
        fourth_target = OutboundTarget.from_record(
            service="steamboat.v1.Worker", record=self.fx.host_record,
            boot_id="g" * 32, model_id=self.fx.model_id,
            assignment_id=self.fx.assignment_id)
        fourth_authorizer = OutboundAuthorizer(
            local_identity=self.fx.base.adapter.local_identity,
            snapshot_store=self.fx.base.snapshot_store, clock=self.fx.base.clock,
            target=fourth_target, worker_request_type=Request,
            trusted_request_context_type=TrustedRequestContext,
            allow_bootstrap_describe=True)
        with self.assertRaises(GatewayEgressError):
            root.register_target(fourth_authorizer, self.fx.host["certificate"])
        self.assertIs(self.client.stream, self.fx.coordinator_client_stream)

        primary_context = self.fx.base.adapter.create_bootstrap_context()
        secondary_context = self.second_authorizer.create_bootstrap_context()
        third_context = self.third_authorizer.create_bootstrap_context()
        primary_request = Request(
            protocol_version=1, manifest_fingerprint=self.fx.model_id,
            worker_boot_id=self.fx.worker_boot_id, timeout_ms=5000)
        secondary_request = Request(
            protocol_version=1, manifest_fingerprint=self.fx.model_id,
            worker_boot_id=self.fx.second_worker_boot_id, timeout_ms=5000)
        third_request = Request(
            protocol_version=1, manifest_fingerprint=self.fx.model_id,
            worker_boot_id="f" * 32, timeout_ms=5000)
        primary_call = self._track_call(self.client.execute(
            "Describe", primary_request,
            trusted_request_context=primary_context))
        secondary_call = self._track_call(proxy.execute(
            "Describe", secondary_request,
            trusted_request_context=secondary_context))
        third_call = self._track_call(third_proxy.execute(
            "Describe", third_request,
            trusted_request_context=third_context))
        first = await self._server_request(primary_call, description="primary target")
        second = await self._server_request(secondary_call, description="secondary target")
        third = await self._server_request(third_call, description="third target")
        decoded = [wire.decode_bundle(item.payload, fragment_kind=item.kind)
                   for item in (first, second, third)]
        requests = []
        for bundle in decoded:
            request = Request()
            request.ParseFromString(bundle.protobuf)
            requests.append((bundle, request.worker_boot_id))
        self.assertEqual({boot for _bundle, boot in requests}, {
            self.fx.worker_boot_id, self.fx.second_worker_boot_id, "f" * 32})
        self.assertEqual(self.client._data_count, 3)
        self.assertEqual(len(self.client._owners), 3)
        self.assertIsNotNone(self.client._pump_task)

        # Deliver replies in reverse request order; the shared ID map must
        # correlate each response with its target-specific authorization.
        for bundle, boot in reversed(requests):
            response = Response(protocol_version=1,
                manifest_fingerprint=self.fx.model_id,
                worker_boot_id=boot, code="OK")
            self.fx.coordinator_server_stream.enqueue(
                kind=wire.RESPONSE, message_id=bundle.message_id,
                payload=wire.encode_bundle(
                    "Describe", wire.BUNDLE_RESPONSE,
                    fragment_kind=wire.RESPONSE,
                    protobuf=serialize_message(response)))
        for _ in range(500):
            self.fx.coordinator_server_stream.pump()
            if primary_call.done() and secondary_call.done() and third_call.done():
                break
            await asyncio.sleep(0.001)
        primary_result, secondary_result, third_result = await asyncio.gather(
            primary_call, secondary_call, third_call)
        self.assertEqual(primary_result.worker_boot_id, self.fx.worker_boot_id)
        self.assertEqual(secondary_result.worker_boot_id,
                         self.fx.second_worker_boot_id)
        self.assertEqual(third_result.worker_boot_id, "f" * 32)
        self.assertEqual(self.client._data_count, 0)
        self.assertEqual(self.client._owners, {})
        await proxy.close()
        self.assertTrue(self.client._close_complete)
        with self.assertRaises(GatewayEgressError):
            root.assert_transport_live()
        with self.assertRaises(ProtocolError):
            await third_proxy.execute("Describe", third_request,
                trusted_request_context=third_context)


if __name__ == "__main__":
    unittest.main()
