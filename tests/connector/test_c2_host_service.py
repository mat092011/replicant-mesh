"""Closed-boundary tests for the fixed supervised C2 host service."""
from __future__ import annotations

import asyncio
import contextlib
import io
import socket
import subprocess
import sys
import os
import threading
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_connector.c2_host_service import (
    C2HostService, C2HostServiceError, _stream_bound_bytes,
    _validate_channel_reservations, _validate_outer,
)
from steamboat_connector.policy import RESERVATION_FIELDS


def _policy(*, communication=0, capture=0):
    from tests.connector.test_process_supervisor import sample_policy
    value = sample_policy()
    for role in value["reservations"].values():
        for name in RESERVATION_FIELDS:
            role[name] = max(role[name], 1)
        role["communication_bytes"] = communication
        role["capture_bytes"] = capture
        role["disk_bytes"] = 32 * 1024 * 1024
    value["limits"]["disk_ceiling_bytes"] = 64 * 1024 * 1024
    value["limits"]["memory_headroom_bytes"] = 16 * 1024 * 1024
    return value


class C2HostServiceContractTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix" and sys.platform.startswith("linux"),
                         "real SIGTERM delivery requires Linux")
    def test_real_sigterm_fences_service_while_loop_is_stopped(self):
        code = "\n".join((
            "import asyncio, os, signal, sys",
            "sys.path.insert(0, " + repr(str(ROOT / "src")) + ")",
            "from steamboat_connector.c2_host_service import C2HostService",
            "service = C2HostService('/protected/host-runtime.json')",
            "loop = asyncio.new_event_loop()",
            "service._loop = loop",
            "service._stop_event = asyncio.Event()",
            "service._install_signal_handlers()",
            "service._stop_requested._cond.acquire()",
            "os.kill(os.getpid(), signal.SIGTERM)",
            "assert service._signal_stop",
            "assert not service.ready",
            "service._stop_requested._cond.release()",
            "service._restore_sigterm_handler()",
            "loop.close()",
            "service._runner.close()",
        ))
        subprocess.run([sys.executable, "-I", "-c", code], check=True,
                       capture_output=True, text=True, timeout=10)

    def test_import_and_fixed_role_entrypoint_do_not_load_torch(self):
        code = (
            "import sys; sys.path.insert(0, " + repr(str(ROOT / "src")) + "); "
            "import steamboat_connector.role_worker; "
            "assert callable(steamboat_connector.role_worker.start); "
            "assert 'torch' not in sys.modules"
        )
        subprocess.run([sys.executable, "-I", "-c", code], check=True,
                       capture_output=True, text=True, timeout=10)

    def test_outer_document_is_closed_before_clock_or_runtime_construction(self):
        invalid = {
            "version": 1, "role": "host", "config": {}, "policy": {},
            "artifact_pin": {}, "clock_handoff": {}, "entrypoint": "evil.module",
        }
        service = C2HostService("/protected/host-runtime.json")
        try:
            with (mock.patch("steamboat_connector.c2_host_service.read_private_json",
                             return_value=invalid),
                  mock.patch("steamboat_connector.c2_host_service.ChildClockBridge") as bridge,
                  mock.patch("steamboat_connector.c2_host_service.build_c2_host_runtime") as build):
                with self.assertRaisesRegex(C2HostServiceError, "closed version 1"):
                    service.start()
                bridge.assert_not_called()
                build.assert_not_called()
        finally:
            service._restore_sigterm_handler()
            service._runner.close()

    def test_stop_before_startup_denies_read_without_constructing_owners(self):
        service = C2HostService("/protected/host-runtime.json")
        try:
            service.request_stop()
            with (mock.patch("steamboat_connector.c2_host_service.read_private_json") as read,
                  mock.patch("steamboat_connector.c2_host_service.ChildClockBridge") as bridge):
                with self.assertRaisesRegex(C2HostServiceError, "readiness denied"):
                    service.start()
                read.assert_not_called()
                bridge.assert_not_called()
                self.assertFalse(service._ready)
        finally:
            service._restore_sigterm_handler()
            service._runner.close()

    def test_service_final_publication_gate_rejects_stop_after_start(self):
        service = C2HostService("/protected/host-runtime.json")
        service._ready = True
        service.request_stop()
        self.assertFalse(service.ready)
        with self.assertRaisesRegex(C2HostServiceError, "readiness denied"):
            service.assert_ready_for_publication()
        service._runner.close()

    def test_bootstrap_rechecks_stop_after_start_and_emits_no_ready(self):
        from types import SimpleNamespace
        from steamboat_connector import process_bootstrap

        class Service:
            stopped = False
            started = False

            def start(self, _path):
                self.started = True
                return self

            def request_stop(self):
                self.stopped = True

            def assert_ready_for_publication(self):
                if self.stopped:
                    raise RuntimeError("stop before publication")
                return None

            def run(self):
                return None

        service = Service()
        def start_then_stop(path):
            service.start(path)
            service.request_stop()
            return service

        module = SimpleNamespace(start=start_then_stop)
        output = io.StringIO()
        with (mock.patch.object(process_bootstrap.os, "read", return_value=b"R"),
              mock.patch.object(process_bootstrap.os, "close"),
              mock.patch.object(process_bootstrap.site, "getsitepackages", return_value=[]),
              mock.patch.object(process_bootstrap.importlib, "import_module", return_value=module),
              contextlib.redirect_stdout(output)):
            with self.assertRaisesRegex(RuntimeError, "stop before publication"):
                process_bootstrap.main(["host", "/protected/config.json", "41"])
        self.assertEqual(output.getvalue(), "")
        self.assertTrue(service.started)

    def test_failed_driver_factory_keeps_raw_transport_and_tls_owner_captured(self):
        left, right = socket.socketpair()
        tls = object()
        service = object.__new__(C2HostService)
        service._signal_stop = False
        service._traffic = object()
        owner = {"socket": left, "status": "open", "driver": None}
        channel = {"socket": left, "tls": tls, "driver": None,
                   "_current_socket_owner": owner, "_socket_owners": [owner]}
        try:
            with mock.patch("steamboat_connector.c2_host_service.ChannelSocket",
                            side_effect=RuntimeError("factory failure")):
                with self.assertRaisesRegex(RuntimeError, "factory failure"):
                    service._create_driver(channel, "parent-boot")
            self.assertIs(channel["socket"], left)
            self.assertIs(channel["tls"], tls)
            self.assertIsNone(channel["driver"])
        finally:
            left.close()
            right.close()

    def test_valid_outer_policy_does_not_accept_nonhost_child(self):
        from cryptography.hazmat.primitives import serialization
        from steamboat_security.certificates import generate_private_key_pem
        from steamboat_security.root_transition_launch import RoleLaunchSpec
        from steamboat_connector.c2_child_config import build_c2_child_config

        private = serialization.load_pem_private_key(generate_private_key_pem(), password=None)
        public = private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        spec = RoleLaunchSpec("a" * 64, "acct_" + "1" * 32, "dev_" + "2" * 32,
            "personal_coordinator", "1a", "b" * 64, "c" * 64, 1,
            "d" * 32, 1, "e" * 64, "f" * 32)
        config = build_c2_child_config(role="coordinator", selected_root="/selected",
            protected_root="/protected", configuration_path="/protected/config.json",
            launch_spec=spec)
        outer = {"version": 1, "role": "host", "config": config,
            "policy": _policy(), "artifact_pin": {}, "clock_handoff": {}}
        with self.assertRaisesRegex(C2HostServiceError, "not for the host"):
            _validate_outer(outer)

    def test_aggregate_stream_and_capture_reservations_are_checked_before_assembly(self):
        stream_bytes = _stream_bound_bytes()
        # Three independent streams require three full stream reservations and
        # one bounded RPC capture budget apiece.
        good = _policy(communication=3 * stream_bytes, capture=3 * 8_000_000_000)
        communication, capture = _validate_channel_reservations(good, 3)
        self.assertEqual(communication, 3 * stream_bytes)
        self.assertGreater(capture, 0)

        with self.assertRaisesRegex(C2HostServiceError, "communication reservation"):
            _validate_channel_reservations(_policy(communication=stream_bytes), 2)
        with self.assertRaisesRegex(C2HostServiceError, "capture reservation"):
            _validate_channel_reservations(
                _policy(communication=3 * stream_bytes, capture=1), 3)

    @unittest.skipUnless(os.name == "posix" and sys.platform.startswith("linux"),
                         "durable channel policy owners are Linux-only")
    def test_core_policy_accessor_requires_live_durable_owner(self):
        from tests.connector.test_channel_policy_store import (
            PersistentChannelPolicyStoreTests,
        )
        from steamboat_security.channel_policy import ChannelPolicyStore
        from steamboat_security.errors import StorageError

        fixture = PersistentChannelPolicyStoreTests()
        fixture.setUp()
        owner = None
        try:
            owner = fixture.provision()
            core = owner.core_store
            self.assertIs(type(core), ChannelPolicyStore)
            self.assertIs(core, owner._store)
            owner.close()
            with self.assertRaises(StorageError):
                _ = owner.core_store
        finally:
            if owner is not None and not owner._closed and not owner.faulted:
                owner.close()
            fixture.tearDown()


_ARTIFACTS = Path(os.environ.get("STEAMBOAT_C2_STARTUP_ARTIFACTS", "/artifacts"))
_NATIVE_STAGE_FIXTURE = (os.name == "posix" and sys.platform.startswith("linux")
                         and _ARTIFACTS.is_dir())


@unittest.skipUnless(_NATIVE_STAGE_FIXTURE,
    "requires Linux protected storage and the approved offline model fixture")
class C2HostServiceNativeTests(unittest.IsolatedAsyncioTestCase):
    async def test_readiness_probe_executes_and_reclaims_actual_signed_stage(self):
        from tests.connector.test_c2_host_runtime import C2HostRuntimeNativeTests
        from steamboat_connector.c2_host_runtime import build_c2_host_runtime

        fixture_case = C2HostRuntimeNativeTests(
            methodName="test_real_signed_assigned_stage_forced_steps_and_confirmed_close")
        with tempfile.TemporaryDirectory(prefix="c2-host-service-probe-") as scratch:
            os.chmod(scratch, 0o700)
            with fixture_case.resources(scratch) as (fx, child_owner, child_pins, installer):
                runtime = await build_c2_host_runtime(child_owner, child_pins, installer,
                    owner_policy=fixture_case.owner_policy(),
                    component_allocations=fixture_case.allocations())
                service = object.__new__(C2HostService)
                service._signal_stop = False
                service._runtime = runtime
                service._lifecycle_lock = threading.Lock()
                service._stop_requested = threading.Event()
                service._stop_event = asyncio.Event()
                service._uncertain_startup_tasks = []
                try:
                    await service._probe_assigned_stages()
                    handler = runtime._handlers["worker-1"]
                    self.assertEqual(handler.sessions, {})
                    self.assertEqual(handler._active_operation, None)
                finally:
                    self.assertTrue(await runtime.close(grace_seconds=5.0))


class C2HostServiceCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_unresolved_startup_task_retains_every_owner(self):
        service = object.__new__(C2HostService)
        service._signal_stop = False
        service._stopping = False
        service._ready = False
        service._stop_event = asyncio.Event()
        service._channels = []
        service._uncertain_startup_tasks = []
        service._runtime = None
        service._child_pins = object()
        service._binding_lease = object()
        service._child_binding = object()
        service._channel_policy_owner = object()
        service._clock_bridge = object()
        service._close_error = None
        service._shutdown_proven = False
        owner_refs = (service._child_pins, service._binding_lease,
                      service._child_binding, service._channel_policy_owner,
                      service._clock_bridge)
        never = asyncio.Event()
        startup = asyncio.create_task(never.wait())
        service._uncertain_startup_tasks.append(startup)
        with self.assertRaisesRegex(C2HostServiceError, "startup task ownership"):
            await service._shutdown([])
        self.assertFalse(startup.done())
        self.assertEqual(owner_refs, (service._child_pins, service._binding_lease,
            service._child_binding, service._channel_policy_owner, service._clock_bridge))
        self.assertFalse(service._shutdown_proven)
        startup.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await startup

    async def test_actual_uncertain_socket_close_retains_host_pins(self):
        from tests.connector.test_channel_socket import ChannelSocketTests

        fixture = ChannelSocketTests()
        fixture.setUp()
        try:
            class ReleaseThenRaiseSocket:
                def __init__(self, sock):
                    self.sock = sock

                def setblocking(self, value):
                    self.sock.setblocking(value)

                def send(self, data):
                    return self.sock.send(data)

                def recv(self, size):
                    return self.sock.recv(size)

                def close(self):
                    self.sock.close()
                    raise OSError("close acknowledgement lost after release")

            from steamboat_connector.channel_socket import ChannelSocket
            client_socket, peer_socket = fixture._connected_pair()
            tls, _unused_tls = fixture._owners()
            driver = ChannelSocket(ReleaseThenRaiseSocket(client_socket), tls,
                fixture.budget, role="coordinator", boot_id="b" * 32,
                test_socket=True)
            pins = object()
            service = object.__new__(C2HostService)
            service._signal_stop = False
            service._stopping = False
            service._ready = False
            service._stop_event = asyncio.Event()
            service._channels = [{"rpc": None, "stream": None,
                                  "driver": driver, "socket": None, "tls": tls}]
            service._uncertain_startup_tasks = []
            service._runtime = None
            service._child_pins = pins
            service._close_error = None
            service._shutdown_proven = False
            with self.assertRaisesRegex(C2HostServiceError, "socket close is uncertain"):
                await service._shutdown([])
            self.assertEqual(driver.socket_close_status, "uncertain")
            self.assertIs(service._child_pins, pins)
            self.assertFalse(service._shutdown_proven)
            peer_socket.close()
            _unused_tls.close()
        finally:
            fixture.tearDown()

    async def test_actual_uncertain_tls_cleanup_in_raw_channel_retains_pins(self):
        from tests.security.test_gateway_ingress import GatewayIngressTests
        from steamboat_security import channel_tls
        from steamboat_security.channel_tls import OwnedWorkerTLS

        fixture = GatewayIngressTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        original_remove = channel_tls.shutil.rmtree
        with mock.patch.object(channel_tls.shutil, "rmtree",
                               side_effect=OSError("credential removal uncertain")):
            tls = OwnedWorkerTLS.connect(
                worker_certificate_pem=fixture.worker_channel,
                worker_private_key_pem=fixture.worker_channel_key,
                gateway_ca_pem=fixture.fixture.gateway_ca,
                endpoint_host="gateway.example.net", endpoint_port=443,
                clock=fixture.fixture.clock)
        private_directory = tls._private_directory
        self.addCleanup(lambda: original_remove(private_directory, ignore_errors=True)
                        if private_directory else None)
        self.addCleanup(fixture.tls_owner.close)
        self.assertTrue(private_directory and os.path.isdir(private_directory))
        self.assertFalse(channel_tls.is_owned_worker_tls(tls))
        self.assertTrue(tls.cleanup_uncertain)
        self.assertEqual(tls.cleanup_status, "uncertain")
        pins, runner = object(), object()
        service = object.__new__(C2HostService)
        service._signal_stop = False
        service._stopping = False
        service._ready = False
        service._stop_event = asyncio.Event()
        service._channels = [{"rpc": None, "stream": None, "driver": None,
                              "socket": None, "tls": tls}]
        service._uncertain_startup_tasks = []
        service._runtime = None
        service._child_pins = pins
        service._runner = runner
        service._close_error = None
        service._shutdown_proven = False
        with self.assertRaisesRegex(C2HostServiceError,
                                    "not the fixed worker TLS type"):
            await service._shutdown([])
        self.assertTrue(tls.cleanup_uncertain)
        self.assertEqual(tls.cleanup_status, "uncertain")
        self.assertIs(service._child_pins, pins)
        self.assertIs(service._runner, runner)
        self.assertFalse(service._shutdown_proven)

    async def test_raw_socket_close_uncertainty_is_not_retried_on_shutdown(self):
        from tests.connector.test_channel_socket import ChannelSocketTests

        fixture = ChannelSocketTests()
        fixture.setUp()
        class ReleaseThenRaiseSocket:
            def __init__(self, sock):
                self.sock = sock
                self.close_calls = 0

            def close(self):
                self.close_calls += 1
                self.sock.close()
                raise OSError("raw close acknowledgement lost")

        left, peer = fixture._connected_pair()
        wrapper = ReleaseThenRaiseSocket(left)
        pins = object()
        service = object.__new__(C2HostService)
        service._signal_stop = False
        service._stopping = False
        service._ready = False
        service._stop_event = asyncio.Event()
        socket_owner = {"socket": wrapper, "status": "open", "driver": None}
        service._channels = [{"rpc": None, "stream": None, "driver": None,
                              "socket": wrapper, "tls": None,
                              "_current_socket_owner": socket_owner,
                              "_socket_owners": [socket_owner]}]
        service._uncertain_startup_tasks = []
        service._runtime = None
        service._child_pins = pins
        service._close_error = None
        service._shutdown_proven = False
        try:
            with self.assertRaisesRegex(C2HostServiceError, "raw gateway socket close"):
                await service._shutdown([])
            self.assertEqual(socket_owner["status"], "uncertain")
            self.assertEqual(wrapper.close_calls, 1)
            self.assertIs(service._child_pins, pins)
            self.assertFalse(service._shutdown_proven)
            await service._shutdown([])
            self.assertEqual(wrapper.close_calls, 1)
            self.assertIs(service._child_pins, pins)
        finally:
            peer.close()
            fixture.tearDown()

    async def test_false_runtime_close_retains_all_downstream_owners(self):
        class Runtime:
            _bridges = {}

            async def close(self, *, grace_seconds):
                return False

        service = object.__new__(C2HostService)
        service._signal_stop = False
        service._stopping = False
        service._ready = False
        service._stop_event = asyncio.Event()
        service._channels = []
        service._runtime = Runtime()
        service._child_pins = object()
        service._binding_lease = object()
        service._child_binding = object()
        service._channel_policy_owner = object()
        service._clock_bridge = object()
        service._close_error = None
        service._shutdown_proven = False
        with self.assertRaisesRegex(C2HostServiceError, "uncertain"):
            await service._shutdown([])
        self.assertIsNotNone(service._child_pins)
        self.assertIsNotNone(service._binding_lease)
        self.assertIsNotNone(service._channel_policy_owner)
        self.assertFalse(service._shutdown_proven)

    async def test_hung_admitted_rpc_is_not_cancelled_or_released_on_stop(self):
        class Rpc:
            def __init__(self):
                self._active = set()
                self._retained_releases = set()
                self._stuck_captures = set()
                self._data_count = self._control_count = 1
                self._data_bytes = self._control_bytes = 1
                self.stopped = False

            def stop(self):
                self.stopped = True

        service = object.__new__(C2HostService)
        service._signal_stop = False
        rpc = Rpc()
        never = asyncio.Event()
        admitted = asyncio.create_task(never.wait())
        rpc._active.add(admitted)
        service._stopping = False
        service._ready = False
        service._stop_event = asyncio.Event()
        service._channels = [{"rpc": rpc}]
        service._runtime = None
        service._child_pins = object()
        service._close_error = None
        service._shutdown_proven = False
        with mock.patch("steamboat_connector.c2_host_service.STOP_CLEANUP_SECONDS", 0.01):
            with self.assertRaisesRegex(C2HostServiceError, "cleanup deadline"):
                await service._shutdown([])
        self.assertTrue(rpc.stopped)
        self.assertFalse(admitted.done())
        self.assertIn(admitted, rpc._active)
        self.assertIsNotNone(service._child_pins)
        admitted.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await admitted


class C2HostServiceSocketOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def _connect_fixture(self, *, first_close_raises):
        from tests.security.test_gateway_ingress import GatewayIngressTests
        from steamboat_security.channel_tls import OwnedWorkerTLS
        import steamboat_connector.c2_host_service as host_service_module

        fixture = GatewayIngressTests()
        fixture.setUp()
        tls = OwnedWorkerTLS.connect(
            worker_certificate_pem=fixture.worker_channel,
            worker_private_key_pem=fixture.worker_channel_key,
            gateway_ca_pem=fixture.fixture.gateway_ca,
            endpoint_host="gateway.example.net", endpoint_port=443,
            clock=fixture.fixture.clock)

        class TrackedSocket:
            def __init__(self, sock, *, fail_close=False):
                self.sock = sock
                self.fail_close = fail_close
                self.close_calls = 0

            def setblocking(self, value):
                self.sock.setblocking(value)

            def close(self):
                self.close_calls += 1
                self.sock.close()
                if self.fail_close:
                    raise OSError("close acknowledgement lost")

        sockets = [TrackedSocket(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                                 fail_close=first_close_raises),
                   TrackedSocket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]

        def close_fixture_fds():
            for tracked in sockets:
                if tracked.sock.fileno() != -1:
                    tracked.sock.close()

        service = object.__new__(C2HostService)
        service._signal_stop = False
        service._stop_requested = threading.Event()
        service._lifecycle_lock = threading.Lock()
        service._stop_event = asyncio.Event()
        service._uncertain_startup_tasks = []
        service._channels = []
        loop = asyncio.get_running_loop()
        infos = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                  "", ("127.0.0.1", 41001)),
                 (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                  "", ("127.0.0.1", 41002))]
        connect_calls = 0

        async def sock_connect(_sock, _address):
            nonlocal connect_calls
            connect_calls += 1
            raise OSError(f"signed address {connect_calls} refused")

        patches = [
            mock.patch.object(host_service_module.socket, "socket",
                              side_effect=sockets),
            mock.patch.object(loop, "getaddrinfo", new=mock.AsyncMock(return_value=infos)),
            mock.patch.object(loop, "sock_connect", new=mock.AsyncMock(side_effect=sock_connect)),
            mock.patch.object(OwnedWorkerTLS, "connect", return_value=tls),
        ]
        try:
            started = [patcher.start() for patcher in patches]
            return_value = None
            error = None
            try:
                return_value = await service._connect_worker(
                    b"certificate", b"private-key", b"ca", "signed.host", 443,
                    fixture.fixture.clock)
            except BaseException as caught:
                error = caught
            return fixture, tls, service, sockets, return_value, error, patches, started[0]
        except BaseException:
            for patcher in reversed(patches):
                patcher.stop()
            close_fixture_fds()
            tls.close()
            fixture.tls_owner.close()
            fixture.tearDown()
            raise

    async def test_each_failed_address_socket_has_independent_close_proof(self):
        fixture, tls, service, sockets, channel, error, patches, socket_factory = await self._connect_fixture(
            first_close_raises=False)
        try:
            self.assertIsNone(channel)
            self.assertRegex(str(error), "signed gateway endpoint could not be reached")
            owners = service._channels[0]["_socket_owners"]
            self.assertEqual([owner["status"] for owner in owners], ["closed", "closed"])
            self.assertEqual([sock.close_calls for sock in sockets], [1, 1])
            self.assertEqual(socket_factory.call_count, 2)
            for owner in owners:
                service._close_raw_socket_once(owner)
            self.assertEqual([sock.close_calls for sock in sockets], [1, 1])
        finally:
            for patcher in reversed(patches):
                patcher.stop()
            for tracked in sockets:
                if tracked.sock.fileno() != -1:
                    tracked.sock.close()
            tls.close()
            fixture.tls_owner.close()
            fixture.tearDown()

    async def test_uncertain_first_socket_close_blocks_second_address_and_shutdown(self):
        fixture, tls, service, sockets, channel, error, patches, socket_factory = await self._connect_fixture(
            first_close_raises=True)
        pins = object()
        service._stopping = False
        service._ready = False
        service._runtime = None
        service._child_pins = pins
        service._close_error = None
        service._shutdown_proven = False
        try:
            self.assertIsNone(channel)
            self.assertRegex(str(error), "failed gateway socket close is uncertain")
            owned_channel = service._channels[0]
            self.assertEqual(len(owned_channel["_socket_owners"]), 1)
            self.assertEqual(owned_channel["_socket_owners"][0]["status"], "uncertain")
            self.assertEqual([sock.close_calls for sock in sockets], [1, 0])
            self.assertEqual(socket_factory.call_count, 1)
            with self.assertRaisesRegex(C2HostServiceError, "raw gateway socket close"):
                await service._shutdown([])
            await service._shutdown([])
            self.assertEqual([sock.close_calls for sock in sockets], [1, 0])
            self.assertIs(service._child_pins, pins)
            self.assertFalse(service._shutdown_proven)
        finally:
            for patcher in reversed(patches):
                patcher.stop()
            for tracked in sockets:
                if tracked.sock.fileno() != -1:
                    tracked.sock.close()
            tls.close()
            fixture.tls_owner.close()
            fixture.tearDown()


@unittest.skipUnless(os.name == "posix" and sys.platform.startswith("linux"),
                     "actual signed loopback TLS gateway fixture is native Linux")
class C2HostServiceTlsFactoryNativeTests(unittest.IsolatedAsyncioTestCase):
    async def test_tls_factory_starts_before_tcp_handshake_then_pumps_real_gateway_tls(self):
        from tests.connector.test_gateway_service import GatewayServiceLoopbackTests

        fixture = GatewayServiceLoopbackTests(
            methodName="test_two_listener_two_worker_cohort_routes_open_response_and_describe")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fx = fixture.fx
        gateway = fixture._service(expected=((fx.device_id, fx.worker_boot_id),))
        service = object.__new__(C2HostService)
        service._signal_stop = False
        service._channels = []
        service._uncertain_startup_tasks = []
        service._stop_requested = threading.Event()
        service._lifecycle_lock = threading.Lock()
        service._stop_event = asyncio.Event()
        service._traffic = fx.meter_budget
        service._loop = asyncio.get_running_loop()
        pump_stop = asyncio.Event()

        async def pump_gateway():
            while not pump_stop.is_set():
                gateway.pump_once()
                await asyncio.sleep(0.001)

        pump_task = asyncio.create_task(pump_gateway())

        async def stop_pump():
            pump_stop.set()
            if not pump_task.done():
                pump_task.cancel()
            try:
                await pump_task
            except asyncio.CancelledError:
                pass

        self.addAsyncCleanup(stop_pump)
        endpoint = gateway.worker_address
        loop = asyncio.get_running_loop()
        real_getaddrinfo = loop.getaddrinfo

        async def loopback_resolution(host, port, **kwargs):
            if host == "worker.gateway.example" and port == 443:
                return await real_getaddrinfo(endpoint[0], endpoint[1], **kwargs)
            return await real_getaddrinfo(host, port, **kwargs)

        channel = None
        try:
            with mock.patch.object(loop, "getaddrinfo", side_effect=loopback_resolution):
                channel = await service._connect_worker(
                    fx.worker_channel_pem, fx.worker_channel_key, fx.base.gateway_ca,
                    "worker.gateway.example", 443, fx.base.clock)
            owner = channel["tls"]
            self.assertFalse(owner.handshake_complete,
                             "MemoryBIO TLS starts before transport handshake bytes arrive")
            driver = service._create_driver(channel, fx.socket_host_boot)
            await service._pump_tls(driver)
            self.assertTrue(owner.handshake_complete)
            self.assertEqual(driver.pending_ciphertext_bytes, 0)
            self.assertEqual(driver.pending_plaintext_bytes, 0)
        finally:
            if channel is not None:
                driver = channel.get("driver")
                if driver is not None:
                    driver.close()
                else:
                    raw_socket = channel.get("socket")
                    if raw_socket is not None:
                        raw_socket.close()
                    tls = channel.get("tls")
                    if tls is not None:
                        tls.close()
            pump_stop.set()
            await stop_pump()


if __name__ == "__main__":
    unittest.main()
