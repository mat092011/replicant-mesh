"""Actual loopback TCP/TLS/HELLO tests for the fixed gateway service."""
from __future__ import annotations

import socket
import time
import unittest
from unittest.mock import patch

from steamboat_connector import channel_wire as wire
from steamboat_connector.channel_hello import CoordinatorHelloClient, WorkerHelloClient
from steamboat_connector.channel_socket import ChannelSocket
from steamboat_connector.channel_stream import (
    TLS_OWNER_MIN_RESERVATION_BYTES, ChannelStream,
)
from steamboat_connector.channel_writer import writer_reservation_overhead_bytes
from steamboat_connector.gateway_service import (
    GatewayService, GatewayServiceError, required_communication_memory_bytes,
)
from steamboat_runtime.protocol import PROTOCOL_VERSION
from steamboat_runtime.protocol.wire import Request, Response, serialize_message
from steamboat_security.gateway_egress import GatewayCoordinatorEgress
from steamboat_security.gateway_ingress import GatewayWorkerIngress
from steamboat_security.channel_tls import OwnedWorkerTLS
from steamboat_security.gateway_delegation import GatewayDelegationVerifier
from steamboat_security.sessions import SessionBindings
from tests.connector import test_gateway_mux as mux_fixtures
from tests.connector import test_gateway_router as router_fixtures
from steamboat_security.codec import WORKER_SERVICE, encode_binding
from steamboat_security.ids import new_id


class GatewayServiceLoopbackTests(unittest.TestCase):
    def setUp(self):
        # Import the fixture module, not its TestCase into this module's globals,
        # so unittest discovery does not duplicate any fixture test IDs.
        self.fixture = mux_fixtures.GatewayMuxActualStreamTests(
            methodName="test_actual_two_hop_submit_uses_one_coordinator_pop_and_core_ingress")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fx = self.fixture.fx
        self.listeners = []
        self.clients = []
        self._client_cleanup = {}
        self.service = None

    def _listener(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        self.listeners.append(listener)
        self.addCleanup(self._close_test_listener, listener)
        return listener

    def _close_test_listener(self, listener):
        if listener.fileno() != -1 and (self.service is None
                or id(listener) not in self.service._listeners_closed):
            listener.close()

    def _service(self, *, expected=None):
        fx = self.fx
        expected = tuple(expected or ((fx.device_id, fx.worker_boot_id),
                                      (fx.device_id, fx.second_worker_boot_id)))
        targets = {
            (fx.device_id, boot, fx.assignment_id, fx.model_id): fx.host["certificate"]
            for _device, boot in expected
        }
        service = GatewayService(
            worker_listener=self._listener(), coordinator_listener=self._listener(),
            expected_workers=expected,
            coordinator_boot_id=fx.coordinator_boot_id,
            tenant_account_id=fx.actor_record["account_id"], gateway_id="gw-east",
            gateway_certificate_pem=fx.base.gateway_cert,
            gateway_private_key_pem=fx.base.gateway_key,
            cohort_ca_pem=fx.base.gateway_ca, gateway_ca_pem=fx.base.gateway_ca,
            target_certificates=targets,
            snapshot_store=fx.base.snapshot_store, policy_store=fx.base.policy_store,
            clock=fx.base.clock, traffic_budget=fx.meter_budget,
            gateway_traffic_boot_id=fx.socket_gateway_boot,
            communication_memory_ceiling_bytes=required_communication_memory_bytes(
                len(expected)))
        self.service = service
        self.addCleanup(service.stop)
        return service

    def _worker_client(self, boot_id):
        fx = self.fx
        if boot_id == fx.worker_boot_id:
            channel_pem, channel_key = fx.worker_channel_pem, fx.worker_channel_key
        else:
            channel_pem, channel_key = (fx.second_worker_channel_pem,
                                        fx.second_worker_channel_key)
        owner = OwnedWorkerTLS.connect(
            worker_certificate_pem=channel_pem, worker_private_key_pem=channel_key,
            gateway_ca_pem=fx.base.gateway_ca,
            endpoint_host="worker.gateway.example", endpoint_port=443,
            clock=fx.base.clock)
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(self.service.worker_address[:2])
        driver = ChannelSocket(client_socket, owner, fx.meter_budget,
                               role="host", boot_id=fx.socket_host_boot)
        cleanup = {"owner": owner, "driver": driver, "stream": None,
                   "socket": client_socket}
        self._client_cleanup[id(driver)] = cleanup
        self.addCleanup(self._close_client, cleanup)
        cleanup["worker_boot_id"] = boot_id
        self.clients.append((owner, driver, None, None, client_socket, None))
        return owner, driver, None, None

    def _ensure_worker_hello(self, owner, driver):
        index = next(i for i, item in enumerate(self.clients) if item[1] is driver)
        current = self.clients[index]
        if current[2] is not None:
            return current[2], current[5]
        if (not owner.handshake_complete or driver.pending_plaintext_bytes
                or driver.pending_ciphertext_bytes or owner.pending_encrypted_bytes):
            return None, None
        fx = self.fx
        boot_id = self._client_cleanup[id(driver)]["worker_boot_id"]
        verifier = GatewayDelegationVerifier(
            fx.base.policy_store, clock=fx.base.clock,
            gateway_ca_pem=fx.base.gateway_ca,
            participant_ca_pem=fx.fx.ca_pem,
            local_identity=router_fixtures.LocalIdentity(
                fx.host["certificate"], boot_id, fx.model_id, fx.assignment_id),
            endpoint_host="worker.gateway.example", endpoint_port=443)
        ingress = GatewayWorkerIngress.from_tls(
            owner, verifier=verifier, sessions=SessionBindings(clock=fx.base.clock),
            gateway_id="gw-east")
        hello = WorkerHelloClient(ingress, owner, reassembly_capacity=wire.MAX_BUNDLE_BYTES)
        self.clients[index] = (owner, driver, hello, current[3], current[4], ingress)
        return hello, ingress

    def _coordinator_client(self):
        fx = self.fx
        owner = GatewayCoordinatorEgress.connect(
            authorizer=fx.base.adapter, policy_store=fx.base.policy_store,
            logical_host_certificate_pem=fx.host["certificate"],
            gateway_id="gw-east", gateway_ca_pem=fx.base.gateway_ca,
            coordinator_private_key_pem=fx.actor["key"])
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(self.service.coordinator_address[:2])
        driver = ChannelSocket(client_socket, owner, fx.meter_budget,
                               role="host", boot_id=fx.socket_host_boot)
        cleanup = {"owner": owner, "driver": driver, "stream": None,
                   "socket": client_socket, "coordinator": True}
        self._client_cleanup[id(driver)] = cleanup
        self.addCleanup(self._close_client, cleanup)
        self.clients.append((owner, driver, None, None, client_socket, None))
        return owner, driver, None

    def _ensure_coordinator_hello(self, owner, driver):
        index = next(i for i, item in enumerate(self.clients) if item[1] is driver)
        current = self.clients[index]
        if current[2] is not None:
            return current[2]
        if (not owner.handshake_complete or driver.pending_plaintext_bytes
                or driver.pending_ciphertext_bytes or owner.pending_encrypted_bytes):
            return None
        hello = CoordinatorHelloClient(owner, reassembly_capacity=wire.MAX_BUNDLE_BYTES)
        self.clients[index] = (owner, driver, hello, current[3], current[4], current[5])
        return hello

    @staticmethod
    def _close_client(cleanup):
        stream = cleanup["stream"]
        driver = cleanup["driver"]
        if stream is not None:
            stream.close()
        elif driver is not None:
            driver.close()
        elif cleanup["owner"] is not None:
            cleanup["owner"].close()
        else:
            cleanup["socket"].close()

    def _drive_handshakes_and_hello(self):
        # Pump client-side TCP/TLS using the same durable traffic ledger as the
        # server service, then create the client streams only once BIO/socket
        # handshake output is drained.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            self.service.pump_once()
            for owner, driver, _hello, stream, _sock, _ingress in self.clients:
                if not owner.handshake_complete:
                    driver.pump()
                elif stream is None and (driver.pending_plaintext_bytes
                        or driver.pending_ciphertext_bytes
                        or owner.pending_encrypted_bytes):
                    driver.pump()
            for index, item in enumerate(tuple(self.clients)):
                owner, driver, hello, stream, sock, ingress = item
                if (stream is None and owner.handshake_complete
                        and not driver.pending_plaintext_bytes
                        and not driver.pending_ciphertext_bytes
                        and not owner.pending_encrypted_bytes):
                    if hello is None and self._client_cleanup[id(driver)].get("worker_boot_id"):
                        hello, ingress = self._ensure_worker_hello(owner, driver)
                        self.clients[index] = (owner, driver, hello, stream, sock, ingress)
                    elif hello is None and self._client_cleanup[id(driver)].get("coordinator"):
                        hello = self._ensure_coordinator_hello(owner, driver)
                        self.clients[index] = (owner, driver, hello, stream, sock, ingress)
                if (stream is None and hello is not None and owner.handshake_complete
                        and not driver.pending_plaintext_bytes
                        and not driver.pending_ciphertext_bytes
                        and not owner.pending_encrypted_bytes):
                    common = dict(
                        writer_reservation_bytes=(writer_reservation_overhead_bytes()
                            + wire.MAX_BUNDLE_BYTES
                            + 8 * wire.MAX_CONTROL_BUNDLE_BYTES),
                        decoded_byte_capacity=wire.MAX_BUNDLE_BYTES,
                        tls_owner_reservation_bytes=TLS_OWNER_MIN_RESERVATION_BYTES)
                    self.clients[index] = (
                        owner, driver, hello, ChannelStream(driver, hello, **common),
                        sock, ingress)
                    self._client_cleanup[id(driver)]["stream"] = self.clients[index][3]
            for item in self.clients:
                if item[3] is not None:
                    item[3].pump()
            if self.service.route_connected:
                return
            time.sleep(0.001)
        self.fail("actual two-listener TLS/HELLO cohort did not connect within five seconds")

    def test_two_listener_two_worker_cohort_routes_open_response_and_describe(self):
        service = self._service()
        worker_clients = [self._worker_client(boot) for boot in
                          (self.fx.worker_boot_id, self.fx.second_worker_boot_id)]
        _coordinator_owner, _coordinator_driver, _coordinator_hello = self._coordinator_client()
        self._drive_handshakes_and_hello()
        self.addCleanup(service.stop)
        fx = self.fx
        worker_streams = tuple(
            item[3] for item in self.clients if type(item[2]) is WorkerHelloClient)
        coordinator_client = next(item[3] for item in self.clients
                                  if type(item[2]) is CoordinatorHelloClient)
        fx.coordinator_client_stream = coordinator_client
        fx.worker_client_streams = worker_streams
        fx.worker_ingresses = tuple(
            item[5] for item in self.clients if type(item[2]) is WorkerHelloClient)
        self.assertTrue(service.route_connected)
        self.assertEqual(set(service._workers), {
            (fx.device_id, fx.worker_boot_id),
            (fx.device_id, fx.second_worker_boot_id)})

        # Existing fixture helper creates a canonical request over the actual
        # coordinator client ChannelStream. The service's one mux forwards it.
        request, raw, binding, message_id = self.fixture._enqueue_open()
        selected = 0
        deadline = time.monotonic() + 2.0
        delivered = None
        while time.monotonic() < deadline and delivered is None:
            service.pump_once()
            worker_streams[selected].pump()
            delivered = worker_streams[selected].pop_message()
            time.sleep(0.001)
        self.assertIsNotNone(delivered)
        self.assertEqual((delivered.kind, delivered.message_id), (wire.DATA, message_id))
        self.fixture._verify_ingress(selected, request, raw, binding, delivered)
        response = Response(code="OK", protocol_version=PROTOCOL_VERSION,
                            manifest_fingerprint=fx.model_id,
                            worker_boot_id=fx.worker_boot_id,
                            session_id=request.session_id,
                            lease_token="lease_service_0123456789", max_positions=64)
        worker_streams[selected].enqueue(
            kind=wire.RESPONSE, message_id=message_id,
            payload=wire.encode_bundle("OpenSession", wire.BUNDLE_RESPONSE,
                fragment_kind=wire.RESPONSE, protobuf=serialize_message(response)))
        deadline = time.monotonic() + 2.0
        received = None
        while time.monotonic() < deadline and received is None:
            worker_streams[selected].pump()
            service.pump_once()
            coordinator_client.pump()
            received = coordinator_client.pop_message()
            time.sleep(0.001)
        self.assertIsNotNone(received)
        self.assertEqual((received.kind, received.message_id), (wire.RESPONSE, message_id))
        self.assertEqual(wire.decode_bundle(received.payload,
                         fragment_kind=wire.RESPONSE).method, "OpenSession")

        # Describe is a separate real route to the second exact boot and uses
        # the legacy bootstrap binding shape, resolved by protobuf worker_boot_id.
        fields = {
            "binding_version": 1, "operation_id": new_id("op"),
            "account_id": fx.actor_record["account_id"],
            "device_id": fx.actor_record["device_id"],
            "role": "personal_coordinator",
            "credential_epoch": fx.actor_record["credential_epoch"],
            "target_device_id": fx.device_id,
        }
        binding_bytes = encode_binding(WORKER_SERVICE, "Describe", fields)
        describe = Request(protocol_version=PROTOCOL_VERSION,
                           manifest_fingerprint=fx.model_id,
                           worker_boot_id=fx.second_worker_boot_id,
                           timeout_ms=5000)
        describe_id = b"S" * 16
        describe_payload = wire.encode_bundle(
            "Describe", wire.REQUEST, fragment_kind=wire.DATA,
            binding=binding_bytes, protobuf=serialize_message(describe))
        coordinator_client.enqueue(kind=wire.DATA, message_id=describe_id,
                                   payload=describe_payload)
        deadline = time.monotonic() + 2.0
        delivered_second = None
        while time.monotonic() < deadline and delivered_second is None:
            coordinator_client.pump()
            service.pump_once()
            worker_streams[1].pump()
            delivered_second = worker_streams[1].pop_message()
            time.sleep(0.001)
        self.assertIsNotNone(delivered_second)
        self.assertEqual(delivered_second.message_id, describe_id)
        from steamboat_connector import channel_protobuf
        decoded = wire.decode_bundle(delivered_second.payload, fragment_kind=wire.DATA)
        self.assertEqual(decoded.method, "Describe")
        self.assertEqual(decoded.binding, binding_bytes)
        describe_response = Response(
            code="OK", protocol_version=PROTOCOL_VERSION,
            manifest_fingerprint=fx.model_id,
            worker_boot_id=fx.second_worker_boot_id)
        worker_streams[1].enqueue(
            kind=wire.RESPONSE, message_id=describe_id,
            payload=wire.encode_bundle("Describe", wire.BUNDLE_RESPONSE,
                fragment_kind=wire.RESPONSE,
                protobuf=serialize_message(describe_response)))
        deadline = time.monotonic() + 2.0
        describe_received = None
        while time.monotonic() < deadline and describe_received is None:
            worker_streams[1].pump()
            service.pump_once()
            coordinator_client.pump()
            describe_received = coordinator_client.pop_message()
            time.sleep(0.001)
        self.assertIsNotNone(describe_received)
        self.assertEqual((describe_received.message_id, describe_received.kind),
                         (describe_id, wire.RESPONSE))

    def test_listener_purpose_and_memory_bound_fail_before_tls_accept(self):
        worker = self._listener()
        coordinator = self._listener()
        kwargs = dict(
            worker_listener=worker, coordinator_listener=coordinator,
            expected_workers=((self.fx.device_id, self.fx.worker_boot_id),),
            coordinator_boot_id=self.fx.coordinator_boot_id,
            tenant_account_id=self.fx.actor_record["account_id"], gateway_id="gw-east",
            gateway_certificate_pem=self.fx.base.gateway_cert,
            gateway_private_key_pem=self.fx.base.gateway_key,
            cohort_ca_pem=self.fx.base.gateway_ca, gateway_ca_pem=self.fx.base.gateway_ca,
            target_certificates={(self.fx.device_id, self.fx.worker_boot_id,
                                  self.fx.assignment_id, self.fx.model_id):
                                 self.fx.host["certificate"]},
            snapshot_store=self.fx.base.snapshot_store,
            policy_store=self.fx.base.policy_store, clock=self.fx.base.clock,
            traffic_budget=self.fx.meter_budget,
            gateway_traffic_boot_id=self.fx.socket_gateway_boot,
            communication_memory_ceiling_bytes=1)
        with self.assertRaisesRegex(ValueError, "memory ceiling"):
            GatewayService(**kwargs)
        self.assertFalse(worker.fileno() < 0)
        self.assertFalse(coordinator.fileno() < 0)

    def test_partial_handshake_deadline_stops_without_adopting_replacement(self):
        service = self._service(expected=((self.fx.device_id, self.fx.worker_boot_id),))
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(service.worker_address[:2])
        self.addCleanup(client.close)
        service.pump_once()
        self.assertEqual(service.pending_channels, 1)
        accepted = service._accepted[0]
        service._monotonic = lambda: accepted.accepted_at + 6.0
        with self.assertRaisesRegex(GatewayServiceError, "five seconds"):
            service.pump_once()
        self.assertFalse(service._accepting)
        self.assertEqual(service.pending_channels, 1)
        self.assertTrue(accepted.close_started)
        self.assertTrue(accepted.close_complete)
        replacement = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with self.assertRaises(OSError):
            replacement.connect(service.worker_address[:2])
        replacement.close()

    def test_stop_during_tls_factory_is_nonblocking_and_retains_publication_until_quiescent(self):
        service = self._service(expected=((self.fx.device_id, self.fx.worker_boot_id),))
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(service.worker_address[:2])
        self.addCleanup(client.close)
        entered = __import__("threading").Event()
        release = __import__("threading").Event()
        errors = []
        original_accept = mux_fixtures.router_fixtures.OwnedGatewayWorkerTLS.accept

        def blocked_accept(**kwargs):
            entered.set()
            if not release.wait(2.0):
                raise TimeoutError("test did not release the TLS factory barrier")
            return original_accept(**kwargs)

        def pump():
            try:
                service.pump_once()
            except BaseException as error:
                errors.append(error)

        thread = __import__("threading").Thread(target=pump, daemon=True)
        with patch.object(mux_fixtures.router_fixtures.OwnedGatewayWorkerTLS,
                          "accept", new=blocked_accept):
            thread.start()
            self.assertTrue(entered.wait(1.0))
            before = time.monotonic()
            service.stop()
            self.assertLess(time.monotonic() - before, 0.5)
            self.assertFalse(service._resources_closed)
            release.set()
            thread.join(2.0)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(service._resources_closed)
        self.assertEqual(service.pending_channels, 1)
        accepted = service._accepted[0]
        self.assertTrue(accepted.close_started)
        self.assertTrue(accepted.close_complete)
        self.assertIsNotNone(accepted.owner)
        self.assertFalse(service.route_connected)

    def test_stop_after_accept_keeps_pending_socket_owned_until_pump_quiesces(self):
        service = self._service(expected=((self.fx.device_id, self.fx.worker_boot_id),))
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(service.worker_address[:2])
        self.addCleanup(client.close)
        entered = __import__("threading").Event()
        release = __import__("threading").Event()
        errors = []
        original_ready = GatewayService._accept_ready

        def blocked_after_accept(instance, listener, purpose):
            result = original_ready(instance, listener, purpose)
            if purpose == "worker" and instance._accepted:
                entered.set()
                if not release.wait(2.0):
                    raise TimeoutError("test did not release accepted-socket barrier")
            return result

        def pump():
            try:
                service.pump_once()
            except BaseException as error:
                errors.append(error)

        thread = __import__("threading").Thread(target=pump, daemon=True)
        with patch.object(GatewayService, "_accept_ready", new=blocked_after_accept):
            thread.start()
            self.assertTrue(entered.wait(1.0))
            self.assertEqual(service.pending_channels, 1)
            accepted = service._accepted[0]
            self.assertIsNone(accepted.owner)
            service.stop()
            self.assertFalse(service._resources_closed)
            release.set()
            thread.join(2.0)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(service._resources_closed)
        self.assertTrue(accepted.close_complete)
        self.assertIsNone(accepted.owner)

    def test_stop_does_not_finalize_while_listener_close_outcome_is_unknown(self):
        service = self._service(expected=((self.fx.device_id, self.fx.worker_boot_id),))
        listener = service.worker_listener
        entered = __import__("threading").Event()
        release = __import__("threading").Event()
        errors = []

        def blocked_close(exact_listener):
            exact_listener.close()
            entered.set()
            if not release.wait(2.0):
                raise TimeoutError("test did not release listener-close barrier")
            raise OSError("injected post-close syscall uncertainty")

        def stop():
            try:
                service.stop()
            except BaseException as error:
                errors.append(error)

        thread = __import__("threading").Thread(target=stop, daemon=True)
        with patch.object(GatewayService, "_perform_listener_close",
                          staticmethod(blocked_close)):
            thread.start()
            self.assertTrue(entered.wait(1.0))
            self.assertFalse(service._resources_closed)
            self.assertIn(id(listener), service._listeners_close_started)
            self.assertNotIn(id(listener), service._listeners_close_finished)
            self.assertIs(service, __import__(
                "steamboat_connector.gateway_service", fromlist=["_LISTENER_OWNERS"]
            )._LISTENER_OWNERS[id(listener)][1])
            # A concurrent pump-side finalizer cannot release listener claims
            # while Stop still has an unresolved close outcome.
            service.pump_once()
            self.assertFalse(service._resources_closed)
            release.set()
            thread.join(2.0)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(service._resources_closed)
        self.assertIn(service, __import__(
            "steamboat_connector.gateway_service", fromlist=["_RETAINED_SERVICES"]
        )._RETAINED_SERVICES)
        self.assertIs(service, __import__(
            "steamboat_connector.gateway_service", fromlist=["_LISTENER_OWNERS"]
        )._LISTENER_OWNERS[id(listener)][1])

    def test_stop_during_last_stream_pump_prevents_hello_commit_and_mux(self):
        service = self._service(expected=((self.fx.device_id, self.fx.worker_boot_id),))
        owner, driver, hello, _ingress = self._worker_client(self.fx.worker_boot_id)
        deadline = time.monotonic() + 3.0
        client_stream = None
        while time.monotonic() < deadline:
            service.pump_once()
            if not owner.handshake_complete:
                driver.pump()
            hello, _ingress = self._ensure_worker_hello(owner, driver)
            pending = next((item for item in service._accepted
                            if item.purpose == "worker"), None)
            if (pending is not None and pending.stream is not None
                    and owner.handshake_complete and not driver.pending_plaintext_bytes
                    and not driver.pending_ciphertext_bytes
                    and not owner.pending_encrypted_bytes):
                client_stream = ChannelStream(
                    driver, hello,
                    writer_reservation_bytes=(writer_reservation_overhead_bytes()
                        + wire.MAX_BUNDLE_BYTES
                        + 8 * wire.MAX_CONTROL_BUNDLE_BYTES),
                    decoded_byte_capacity=wire.MAX_BUNDLE_BYTES,
                    tls_owner_reservation_bytes=TLS_OWNER_MIN_RESERVATION_BYTES)
                self._client_cleanup[id(driver)]["stream"] = client_stream
                break
            time.sleep(0.001)
        self.assertIsNotNone(client_stream, "real worker TLS stream did not bootstrap")
        server_stream = pending.stream
        entered = __import__("threading").Event()
        release = __import__("threading").Event()
        errors = []
        original_pump = ChannelStream.pump

        def blocked_pump(stream):
            result = original_pump(stream)
            if stream is server_stream and stream.transport_bootstrap_complete:
                entered.set()
                if not release.wait(2.0):
                    raise TimeoutError("test did not release stream-pump barrier")
            return result

        def pump_service():
            try:
                while service._accepting:
                    service.pump_once()
                    time.sleep(0.001)
            except BaseException as error:
                errors.append(error)

        thread = __import__("threading").Thread(target=pump_service, daemon=True)
        with patch.object(ChannelStream, "pump", new=blocked_pump):
            thread.start()
            client_deadline = time.monotonic() + 1.0
            while time.monotonic() < client_deadline and not entered.is_set():
                client_stream.pump()
                time.sleep(0.001)
            self.assertTrue(entered.wait(1.0), "server did not reach HELLO bootstrap barrier")
            service.stop()
            self.assertFalse(service._resources_closed)
            release.set()
            thread.join(2.0)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(service._resources_closed)
        self.assertIsNone(service.multiplexer)
        self.assertEqual(service._workers, {})
        self.assertEqual(service.pending_channels, 1)

    def _exercise_router_registration_barrier(self, *, stop_before_release, expire):
        service = self._service(expected=((self.fx.device_id, self.fx.worker_boot_id),))
        self._worker_client(self.fx.worker_boot_id)
        self._coordinator_client()
        entered = __import__("threading").Event()
        release = __import__("threading").Event()
        errors = []
        from steamboat_connector.gateway_router import GatewayRouter
        original_router_register = GatewayRouter.register_worker

        def blocked_register(router, stream):
            result = original_router_register(router, stream)
            entered.set()
            if not release.wait(2.0):
                raise TimeoutError("test did not release router-registration barrier")
            return result

        def pump_service():
            try:
                while service._accepting:
                    service.pump_once()
                    time.sleep(0.001)
            except BaseException as error:
                errors.append(error)

        def pump_clients():
            for index, item in enumerate(tuple(self.clients)):
                owner, driver, hello, stream, sock, ingress = item
                if (not owner.handshake_complete or stream is None
                        and (driver.pending_plaintext_bytes
                             or driver.pending_ciphertext_bytes
                             or owner.pending_encrypted_bytes)):
                    driver.pump()
                if hello is None and self._client_cleanup[id(driver)].get("worker_boot_id"):
                    hello, ingress = self._ensure_worker_hello(owner, driver)
                    if hello is not None:
                        self.clients[index] = (owner, driver, hello, stream, sock, ingress)
                elif hello is None and self._client_cleanup[id(driver)].get("coordinator"):
                    hello = self._ensure_coordinator_hello(owner, driver)
                    if hello is not None:
                        self.clients[index] = (owner, driver, hello, stream, sock, ingress)
                if (stream is None and hello is not None and owner.handshake_complete
                        and not driver.pending_plaintext_bytes
                        and not driver.pending_ciphertext_bytes
                        and not owner.pending_encrypted_bytes):
                    stream = ChannelStream(
                        driver, hello,
                        writer_reservation_bytes=(writer_reservation_overhead_bytes()
                            + wire.MAX_BUNDLE_BYTES
                            + 8 * wire.MAX_CONTROL_BUNDLE_BYTES),
                        decoded_byte_capacity=wire.MAX_BUNDLE_BYTES,
                        tls_owner_reservation_bytes=TLS_OWNER_MIN_RESERVATION_BYTES)
                    self.clients[index] = (owner, driver, hello, stream, sock, ingress)
                    self._client_cleanup[id(driver)]["stream"] = stream
                if stream is not None:
                    stream.pump()

        service_thread = __import__("threading").Thread(
            target=pump_service, daemon=True)
        with patch.object(GatewayRouter, "register_worker", new=blocked_register):
            service_thread.start()
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and not entered.is_set():
                pump_clients()
                time.sleep(0.001)
            self.assertTrue(entered.wait(1.0),
                            "genuine worker HELLO did not reach router registration")
            accepted_at = service._accepted[0].accepted_at
            if stop_before_release:
                service.stop()
                self.assertFalse(service._resources_closed)
            else:
                self.assertTrue(service._accepting,
                                "deadline-only case must not Stop before callback return")
            if expire:
                service._monotonic = lambda: accepted_at + 5.01
                release.set()
                service_thread.join(2.0)
            else:
                release.set()
                service_thread.join(2.0)
        self.assertFalse(service_thread.is_alive())
        if expire:
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], GatewayServiceError)
            self.assertIn("five seconds", str(errors[0]))
        else:
            self.assertEqual(errors, [])
        self.assertTrue(service._resources_closed)
        self.assertEqual(service._workers, {})
        self.assertIsNone(service.multiplexer)
        self.assertEqual(service.router._workers, {})
        self.assertEqual(service.pending_channels, 1)

    def test_stop_during_router_registration_retires_late_registration(self):
        self._exercise_router_registration_barrier(stop_before_release=True, expire=False)

    def test_bootstrap_deadline_expires_after_router_registration_callback(self):
        self._exercise_router_registration_barrier(stop_before_release=False, expire=True)

    def test_coordinator_tls_on_worker_listener_is_rejected_by_fixed_purpose(self):
        service = self._service(expected=((self.fx.device_id, self.fx.worker_boot_id),))
        fx = self.fx
        owner = GatewayCoordinatorEgress.connect(
            authorizer=fx.base.adapter, policy_store=fx.base.policy_store,
            logical_host_certificate_pem=fx.host["certificate"],
            gateway_id="gw-east", gateway_ca_pem=fx.base.gateway_ca,
            coordinator_private_key_pem=fx.actor["key"])
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(service.worker_address[:2])
        driver = ChannelSocket(client, owner, fx.meter_budget,
                               role="host", boot_id=fx.socket_host_boot)
        self.addCleanup(driver.close)
        deadline = time.monotonic() + 2.0
        rejected = False
        while time.monotonic() < deadline and service._accepting:
            try:
                service.pump_once()
            except (GatewayServiceError, RuntimeError):
                rejected = True
                break
            try:
                driver.pump()
            except RuntimeError:
                rejected = True
                break
            time.sleep(0.001)
        self.assertTrue(rejected or not service._accepting)
        self.assertFalse(service.route_connected)

    def test_valid_but_uninvited_worker_boot_is_rejected_without_replacement(self):
        service = self._service(expected=((self.fx.device_id, self.fx.worker_boot_id),))
        owner, driver, hello, _ingress = self._worker_client(self.fx.second_worker_boot_id)
        stream = None
        deadline = time.monotonic() + 5.0
        failure = None
        while time.monotonic() < deadline and service._accepting:
            try:
                service.pump_once()
                if not owner.handshake_complete or stream is None:
                    driver.pump()
                if hello is None:
                    hello, _ingress = self._ensure_worker_hello(owner, driver)
                if (stream is None and hello is not None and owner.handshake_complete
                        and not driver.pending_plaintext_bytes
                        and not driver.pending_ciphertext_bytes
                        and not owner.pending_encrypted_bytes):
                    stream = ChannelStream(
                        driver, hello,
                        writer_reservation_bytes=(writer_reservation_overhead_bytes()
                            + wire.MAX_BUNDLE_BYTES
                            + 8 * wire.MAX_CONTROL_BUNDLE_BYTES),
                        decoded_byte_capacity=wire.MAX_BUNDLE_BYTES,
                        tls_owner_reservation_bytes=TLS_OWNER_MIN_RESERVATION_BYTES)
                    self._client_cleanup[id(driver)]["stream"] = stream
                if stream is not None:
                    stream.pump()
            except GatewayServiceError as error:
                failure = error
                break
            time.sleep(0.001)
        self.assertIsNotNone(failure, "service accepted a worker boot outside its invited tuple")
        self.assertIn("outside the fixed invited cohort", str(failure))
        self.assertFalse(service._accepting)
        self.assertFalse(service.route_connected)
        self.assertNotIn((self.fx.device_id, self.fx.second_worker_boot_id), service._workers)


if __name__ == "__main__":
    unittest.main()
