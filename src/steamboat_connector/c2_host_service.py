"""Fixed supervised C2 host process composition.

This module accepts only the supervisor's closed outer document and composes
the existing selected-root, artifact, runtime, policy, TLS, HELLO, and RPC
owners. It never imports an entrypoint or callback named by configuration.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import signal
import socket
import time

from steamboat_connector import channel_wire as wire
from steamboat_connector.artifacts import ArtifactInstaller
from steamboat_connector.channel_hello import WorkerHelloClient
from steamboat_connector.channel_policy_store import PersistentChannelPolicyStore
from steamboat_connector.channel_rpc import (
    WorkerChannelRpc, _CONTROL_CAPTURE_BYTES, _CONTROL_LIMIT,
    _DATA_CAPTURE_BYTES, _DATA_LIMIT,
)
from steamboat_connector.channel_socket import ChannelSocket
from steamboat_connector.channel_stream import (
    DECODED_METADATA_RESERVATION_BYTES, HELLO_RESERVATION_BYTES,
    SOCKET_SCRATCH_RESERVATION_BYTES, TLS_OWNER_MIN_RESERVATION_BYTES,
    ChannelStream,
)
from steamboat_connector.channel_writer import writer_reservation_overhead_bytes
from steamboat_connector.catalog import CatalogVerifier
from steamboat_connector.c2_child_config import (
    open_c2_child_binding, parse_c2_child_config,
)
from steamboat_connector.c2_host_runtime import build_c2_host_runtime
from steamboat_connector.c2_host_settings import load_c2_host_settings
from steamboat_connector.clock_bridge import ChildClockBridge
from steamboat_connector.policy import validate_policy
from steamboat_connector.runtime_pin_handoff import validate_child_pin
from steamboat_connector.artifacts import MIN_DISK_HEADROOM_BYTES
from steamboat_connector.storage import read_private_json
from steamboat_connector.traffic_budget import TrafficBudget
from steamboat_security.channel_policy import MAX_CHANNEL_POLICY_BYTES
from steamboat_security.gateway_delegation import GatewayDelegationVerifier
from steamboat_security.gateway_ingress import GatewayWorkerIngress
from steamboat_security.files import safe_read


MAX_BOOTSTRAP_SECONDS = 5.0
HEALTH_INTERVAL_SECONDS = 0.25
HEALTH_PROBE_SECONDS = 10.0
OUTER_FIELDS = frozenset({
    "version", "role", "config", "policy", "artifact_pin", "clock_handoff",
})


class C2HostServiceError(RuntimeError):
    """The fixed host role could not reach or retain authenticated readiness."""


def _validate_outer(value):
    if (type(value) is not dict or set(value) != OUTER_FIELDS
            or type(value.get("version")) is not int or value["version"] != 1
            or value.get("role") != "host"
            or type(value.get("config")) is not dict
            or type(value.get("policy")) is not dict
            or type(value.get("artifact_pin")) is not dict
            or type(value.get("clock_handoff")) is not dict):
        raise C2HostServiceError("supervisor host configuration is not the exact closed version 1 document")
    config = parse_c2_child_config(value["config"])
    if config.role != "host":
        raise C2HostServiceError("supervisor child configuration is not for the host role")
    try:
        policy = validate_policy(value["policy"])
    except (TypeError, ValueError) as error:
        raise C2HostServiceError("supervisor owner policy is invalid") from error
    if "host" not in policy["reservations"]:
        raise C2HostServiceError("supervisor owner policy has no host reservation")
    return config, policy


def _stream_bound_bytes():
    writer = (writer_reservation_overhead_bytes() + wire.MAX_BUNDLE_BYTES
              + 8 * wire.MAX_CONTROL_BUNDLE_BYTES)
    decoder = (2 * wire.MAX_BUNDLE_BYTES + wire.MAX_WIRE_FRAME_BYTES
               + wire.MAX_FEED_BYTES + wire.MAX_BUNDLE_BYTES + 64 * 1024)
    return (decoder + writer + wire.MAX_BUNDLE_BYTES
            + DECODED_METADATA_RESERVATION_BYTES + SOCKET_SCRATCH_RESERVATION_BYTES
            + HELLO_RESERVATION_BYTES + TLS_OWNER_MIN_RESERVATION_BYTES)


def _validate_channel_reservations(policy, component_count):
    reservation = policy["reservations"]["host"]
    communication = component_count * _stream_bound_bytes()
    capture_per_stream = _DATA_LIMIT * _DATA_CAPTURE_BYTES + _CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES
    capture = component_count * capture_per_stream
    if reservation["communication_bytes"] < communication:
        raise C2HostServiceError("host communication reservation cannot cover all bounded channel streams")
    if reservation["capture_bytes"] < capture:
        raise C2HostServiceError("host capture reservation cannot cover all bounded RPC streams")
    return communication, capture


def _read_pinned_material(pin, *, root, uid, maximum, label):
    try:
        encoded = safe_read(pin.path, root=root, expected_uid=uid,
                            max_bytes=maximum)
    except (OSError, ValueError) as error:
        raise C2HostServiceError(f"protected {label} is unavailable") from error
    if not encoded or hashlib.sha256(encoded).hexdigest() != pin.sha256:
        raise C2HostServiceError(f"protected {label} differs from its declared SHA-256")
    return encoded


class C2HostService:
    """One event-loop owner for the complete selected host generation."""

    def __init__(self, config_path):
        if type(config_path) is not str or not config_path.startswith("/"):
            raise C2HostServiceError("supervisor configuration path must be absolute")
        self._config_path = config_path
        self._runner = asyncio.Runner()
        self._loop = None
        self._stop_event = None
        self._ready = False
        self._stopping = False
        self._close_error = None
        self._clock_bridge = None
        self._child_binding = None
        self._binding_lease = None
        self._child_pins = None
        self._installer = None
        self._channel_policy_owner = None
        self._traffic = None
        self._runtime = None
        self._channels = []
        self._rpc_tasks = []
        self._uncertain_startup_tasks = []

    def start(self):
        """Load and authenticate the full host generation before returning."""
        try:
            self._runner.run(self._async_start())
            return self
        except BaseException as error:
            try:
                error.c2_host_service_owner = self
            except BaseException:
                pass
            raise

    async def _async_start(self):
        self._loop = asyncio.get_running_loop()
        self._stop_event = asyncio.Event()
        self._install_signal_handlers()
        try:
            document = read_private_json(
                self._config_path, maximum_size=65_536, uid=os.getuid())
            config, policy = _validate_outer(document)
            self._clock_bridge = ChildClockBridge(document["clock_handoff"])
            clock = self._clock_bridge.clock
            clock.sample()
            self._child_binding = open_c2_child_binding(
                config, clock=clock, expected_uid=os.getuid())
            self._binding_lease = self._child_binding.borrow()
            binding = self._binding_lease.__enter__()
            settings = load_c2_host_settings(binding)
            catalog_key = bytes.fromhex(settings.catalog_public_key_hex)
            verifier = CatalogVerifier(catalog_key, clock=clock)
            self._child_pins = validate_child_pin(
                document["artifact_pin"], clock=clock, verifier=verifier)
            self._installer = ArtifactInstaller(
                settings.artifact_root, verifier,
                disk_ceiling_bytes=policy["limits"]["disk_ceiling_bytes"],
                disk_headroom_bytes=MIN_DISK_HEADROOM_BYTES,
                uid=os.getuid(), read_only=True)

            initial_policy = _read_pinned_material(
                settings.gateway.initial_policy, root=config.protected_root,
                uid=os.getuid(), maximum=MAX_CHANNEL_POLICY_BYTES,
                label="initial channel policy")
            gateway_ca = _read_pinned_material(
                settings.gateway.gateway_ca, root=config.protected_root,
                uid=os.getuid(), maximum=64 * 1024, label="gateway CA")
            self._channel_policy_owner = PersistentChannelPolicyStore.open_existing(
                settings.gateway.policy_root, expected_uid=os.getuid(),
                verification_key_pem=settings.gateway.verification_key_pem,
                clock=clock, minimum_revision=settings.gateway.minimum_revision,
                minimum_policy_digest=settings.gateway.minimum_policy_digest)
            self._channel_policy_owner.install(initial_policy)
            channel_store = self._channel_policy_owner.core_store
            current = self._channel_policy_owner.current()
            gateway = current.gateway(settings.gateway.gateway_id)
            if gateway is None:
                raise C2HostServiceError("signed channel policy has no selected gateway")

            count = len(settings.component_allocations)
            _validate_channel_reservations(policy, count)
            self._traffic = TrafficBudget(
                settings.traffic.state_path,
                allocation_id=settings.traffic.allocation_id, uid=os.getuid(),
                clock=clock, clock_domain=settings.traffic.clock_domain,
                policy=policy)
            parent_boot_id = binding._spec.boot_id
            self._traffic.bind_role("host", parent_boot_id)

            self._runtime = await build_c2_host_runtime(
                self._child_binding, self._child_pins, self._installer,
                owner_policy=policy,
                component_allocations={
                    component: {
                        "sessions": allocation.sessions,
                        "kv_bytes": allocation.kv_bytes,
                        "cache_positions": allocation.cache_positions,
                        "queued_calls": allocation.queued_calls,
                    }
                    for component, allocation in settings.component_allocations.items()
                })
            await self._probe_assigned_stages()
            # Network authority is read only from the signed channel policy.
            endpoint_host = gateway["endpoint_host"]
            endpoint_port = gateway["endpoint_port"]
            for component in self._runtime.components:
                binding.assert_live()
                runtime_binding = next(item for item in binding.components
                                       if item.component == component)
                tls_material = runtime_binding.tls_materials
                identity = runtime_binding.identity
                delegation = GatewayDelegationVerifier(
                    channel_store, clock=clock, gateway_ca_pem=gateway_ca,
                    participant_ca_pem=binding._snapshot_store.ca_certificate_pem,
                    local_identity=identity, endpoint_host=endpoint_host,
                    endpoint_port=endpoint_port)
                tls_owner, connected = await self._connect_worker(
                    tls_material.certificate_pem, tls_material.private_key_pem,
                    gateway_ca, endpoint_host, endpoint_port, clock)
                driver = ChannelSocket(connected, tls_owner, self._traffic,
                    role="host", boot_id=parent_boot_id)
                self._channels.append({"tls": tls_owner, "driver": driver,
                                       "stream": None, "rpc": None})
                await self._pump_tls(driver)
                if (driver.pending_ciphertext_bytes or driver.pending_plaintext_bytes
                        or tls_owner.pending_encrypted_bytes):
                    raise C2HostServiceError("TLS handshake output did not drain")
                ingress = GatewayWorkerIngress.from_tls(
                    tls_owner, verifier=delegation,
                    sessions=self._runtime._sessions[component],
                    gateway_id=settings.gateway.gateway_id)
                hello = WorkerHelloClient(
                    ingress, tls_owner, reassembly_capacity=wire.MAX_BUNDLE_BYTES)
                from steamboat_connector.channel_wire import MAX_CONTROL_BUNDLE_BYTES
                stream = ChannelStream(
                    driver, hello,
                    writer_reservation_bytes=(writer_reservation_overhead_bytes()
                        + wire.MAX_BUNDLE_BYTES + 8 * MAX_CONTROL_BUNDLE_BYTES),
                    decoded_byte_capacity=wire.MAX_BUNDLE_BYTES,
                    tls_owner_reservation_bytes=TLS_OWNER_MIN_RESERVATION_BYTES)
                channel = self._channels[-1]
                channel["stream"] = stream
                await self._pump_hello(stream)
                if not stream.transport_bootstrap_complete:
                    raise C2HostServiceError("worker HELLO was not fully committed")
                if (driver.pending_ciphertext_bytes or driver.pending_plaintext_bytes
                        or tls_owner.pending_encrypted_bytes):
                    raise C2HostServiceError("HELLO transport output did not drain")
                rpc = WorkerChannelRpc(
                    stream=stream, bridge=self._runtime._bridges[component],
                    data_capture_reservation_bytes=_DATA_LIMIT * _DATA_CAPTURE_BYTES,
                    control_capture_reservation_bytes=_CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES)
                channel["rpc"] = rpc
            self._runtime.assert_live()
            self._channel_policy_owner.current()
            self._ready = True
        except BaseException:
            self._ready = False
            raise

    async def _probe_assigned_stages(self):
        """Execute one synthetic token per assigned stage and reclaim its cache."""
        import torch
        from steamboat_runtime.protocol.codec import decode_tensor, encode_tensor
        from steamboat_runtime.protocol.wire import Request

        deadline = asyncio.get_running_loop().time() + HEALTH_PROBE_SECONDS
        for component in self._runtime.components:
            self._runtime.assert_live()
            handler = self._runtime._handlers[component]
            session_id = "host-health-" + os.urandom(8).hex()
            timeout_ms = max(1, min(5_000,
                handler.limits["request_timeout_seconds"] * 1000))
            lifetime_ms = min(timeout_ms,
                handler.limits["idle_lease_seconds"] * 1000)
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise C2HostServiceError("shared assigned-stage health deadline elapsed")
            described = await self._bounded_startup_operation(
                handler.handle("Describe", Request(
                    protocol_version=1, timeout_ms=timeout_ms)), deadline,
                "assigned-stage health description")
            if (described.code != "OK" or not described.ready
                    or described.requires_restart or described.active_operations):
                raise C2HostServiceError("assigned stage failed its initial health description")
            opened = await self._bounded_startup_operation(
                handler.handle("OpenSession", Request(
                    protocol_version=1, manifest_fingerprint=described.manifest_fingerprint,
                    worker_boot_id=handler.boot_id, session_id=session_id,
                    timeout_ms=timeout_ms, max_positions=1,
                    lifetime_ms=lifetime_ms, idle_lease_ms=lifetime_ms)), deadline,
                "assigned-stage health cache reservation")
            if opened.code != "OK" or not opened.lease_token:
                raise C2HostServiceError("assigned stage could not reserve its bounded health cache")

            activation = torch.zeros((1, 1, handler.manifest["config"]["hidden_size"]),
                                     dtype=torch.float32, device="cpu")
            step_request = Request(
                protocol_version=1,
                manifest_fingerprint=described.manifest_fingerprint,
                worker_boot_id=handler.boot_id, session_id=session_id,
                lease_token=opened.lease_token, timeout_ms=timeout_ms,
                sequence=0, start_position=0, token_count=1)
            step_request.tensor.CopyFrom(encode_tensor(
                activation, hidden_size=handler.manifest["config"]["hidden_size"],
                max_tokens=handler.limits["max_positions"],
                max_bytes=handler.limits["max_message_bytes"]))
            step = await self._bounded_startup_operation(
                handler.handle("Step", step_request), deadline,
                "assigned-stage synthetic execution")
            if step.code != "OK" or step.active_operations or not step.cache_bytes_exact:
                raise C2HostServiceError("assigned stage failed its synthetic token health step")
            result = decode_tensor(step.tensor, 1,
                hidden_size=handler.manifest["config"]["hidden_size"],
                max_tokens=handler.limits["max_positions"],
                max_bytes=handler.limits["max_message_bytes"])
            if result.shape != activation.shape or not bool(torch.isfinite(result).all()):
                raise C2HostServiceError("assigned stage health output is malformed or nonfinite")

            closed = await self._bounded_startup_operation(
                handler.handle("CloseSession", Request(
                    protocol_version=1, manifest_fingerprint=described.manifest_fingerprint,
                    worker_boot_id=handler.boot_id, session_id=session_id,
                    lease_token=opened.lease_token, timeout_ms=timeout_ms)), deadline,
                "assigned-stage health cache close")
            post = await self._bounded_startup_operation(
                handler.handle("Describe", Request(
                    protocol_version=1, timeout_ms=timeout_ms)), deadline,
                "assigned-stage post-health description")
            reclaimed = handler.tombstones.get(session_id)
            if (closed.code != "OK" or post.code != "OK"
                    or post.active_sessions != 0 or post.active_operations != 0
                    or post.allocated_cache_bytes != 0 or not post.cache_bytes_exact
                    or post.requires_restart or reclaimed is None
                    or reclaimed.committed_bytes != 0
                    or reclaimed.cache.allocated_bytes() != 0
                    or any(reclaimed.cache.lengths())):
                raise C2HostServiceError("assigned stage health cache was not fully reclaimed")
            del activation, step_request, step, result, opened, closed, post, reclaimed
            self._runtime.assert_live()

    async def _bounded_startup_operation(self, awaitable, deadline, label):
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            if asyncio.iscoroutine(awaitable):
                awaitable.close()
            raise C2HostServiceError(f"shared {label} deadline elapsed")
        task = asyncio.create_task(awaitable)
        done, _pending = await asyncio.wait({task}, timeout=remaining)
        if not done:
            # Do not cancel a handler coroutine that may own a cache or be
            # awaiting noninterruptible assigned-stage compute. Keep it and all
            # model owners until the supervising process actually reaps us.
            self._uncertain_startup_tasks.append(task)
            raise C2HostServiceError(f"shared {label} deadline elapsed; owner retained")
        return task.result()

    async def _connect_worker(self, certificate, private_key, ca, host, port, clock):
        from steamboat_security.channel_tls import OwnedWorkerTLS
        owner = OwnedWorkerTLS.connect(worker_certificate_pem=certificate,
            worker_private_key_pem=private_key, gateway_ca_pem=ca,
            endpoint_host=host, endpoint_port=port, clock=clock)
        if not owner.handshake_complete:
            owner.close()
            raise C2HostServiceError("owned TLS client could not initialize its handshake")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + MAX_BOOTSTRAP_SECONDS
        try:
            infos = await asyncio.wait_for(loop.getaddrinfo(
                host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP),
                timeout=max(0.001, deadline - loop.time()))
        except BaseException:
            owner.close()
            raise
        last_error = None
        for family, socktype, proto, _canon, address in infos[:8]:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            connected = socket.socket(family, socktype, proto)
            connected.setblocking(False)
            try:
                await asyncio.wait_for(loop.sock_connect(connected, address),
                                       timeout=remaining)
                return owner, connected
            except BaseException as error:
                connected.close()
                last_error = error
        owner.close()
        raise C2HostServiceError("signed gateway endpoint could not be reached") from last_error

    async def _pump_tls(self, driver):
        deadline = time.monotonic() + MAX_BOOTSTRAP_SECONDS
        while time.monotonic() < deadline:
            driver.pump()
            tls = driver._tls
            if (driver.tls_handshake_complete
                    and not driver.pending_ciphertext_bytes
                    and not driver.pending_plaintext_bytes
                    and not tls.pending_encrypted_bytes):
                return
            await asyncio.sleep(0.001)
        raise C2HostServiceError("bounded TLS handshake deadline elapsed")

    async def _pump_hello(self, stream):
        deadline = time.monotonic() + MAX_BOOTSTRAP_SECONDS
        while time.monotonic() < deadline:
            stream.pump()
            if stream.transport_bootstrap_complete:
                return
            await asyncio.sleep(0.001)
        raise C2HostServiceError("bounded worker HELLO deadline elapsed")

    def _install_signal_handlers(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                self._loop.add_signal_handler(signum, self.request_stop)
            except (NotImplementedError, RuntimeError, ValueError):
                continue

    def request_stop(self):
        """Fence the event loop promptly; bounded owner cleanup runs in-loop."""
        if self._loop is not None and self._stop_event is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)

    def run(self):
        if not self._ready:
            raise C2HostServiceError("fixed host service cannot run before complete readiness")
        try:
            self._runner.run(self._async_run())
        finally:
            try:
                self._runner.close()
            except BaseException as error:
                self._close_error = error
                raise C2HostServiceError("host event-loop shutdown is uncertain") from error

    async def _async_run(self):
        for channel in self._channels:
            channel["task"] = asyncio.create_task(channel["rpc"].run())
        health = asyncio.create_task(self._health_loop())
        stop = asyncio.create_task(self._stop_event.wait())
        tasks = [item["task"] for item in self._channels] + [health, stop]
        try:
            done, _pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if stop not in done:
                for task in done:
                    if task is not stop and task.exception() is not None:
                        raise C2HostServiceError("host RPC or health task failed") from task.exception()
                raise C2HostServiceError("host service task stopped unexpectedly")
        finally:
            await self._shutdown(tasks)

    async def _health_loop(self):
        while not self._stop_event.is_set():
            self._runtime.assert_live()
            self._channel_policy_owner.current()
            for channel in self._channels:
                stream = channel["stream"]
                if stream.closed or not stream.transport_bootstrap_complete:
                    raise C2HostServiceError("authenticated worker channel became unavailable")
            try:
                await asyncio.wait_for(self._stop_event.wait(), HEALTH_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                pass

    async def _shutdown(self, tasks):
        if self._stopping:
            return
        self._stopping = True
        self._ready = False
        deadline = asyncio.get_running_loop().time() + 5.0
        for channel in self._channels:
            rpc = channel.get("rpc")
            if rpc is not None:
                rpc.stop()
            stream = channel.get("stream")
            if stream is not None:
                stream.close()
            driver = channel.get("driver")
            if driver is not None:
                driver.close()
            tls = channel.get("tls")
            if tls is not None:
                tls.close()
        current = asyncio.current_task()
        pending = [task for task in tasks if task is not current and not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            done, still = await asyncio.wait(
                pending, timeout=max(0.0, deadline - asyncio.get_running_loop().time()))
            if still:
                self._close_error = C2HostServiceError("worker task cleanup deadline elapsed")
                return
            for task in done:
                if task.cancelled():
                    continue
                try:
                    task.result()
                except BaseException as error:
                    self._close_error = self._close_error or error
        try:
            if self._runtime is not None:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise C2HostServiceError("shared host cleanup deadline elapsed")
                await self._runtime.close(grace_seconds=min(5.0, remaining))
            if self._child_pins is not None and self._child_pins._state == "open":
                self._child_pins.close()
            if self._binding_lease is not None:
                self._binding_lease.__exit__(None, None, None)
                self._binding_lease = None
            if self._child_binding is not None:
                self._child_binding.close()
            if self._channel_policy_owner is not None:
                self._channel_policy_owner.close()
            if self._traffic is not None:
                self._traffic.close()
            if self._clock_bridge is not None and not self._clock_bridge.stop():
                raise C2HostServiceError("parent clock bridge close is uncertain")
        except BaseException as error:
            self._close_error = error
            raise C2HostServiceError("host owner shutdown is uncertain; retain owners until process reap") from error
        if self._close_error is not None:
            raise C2HostServiceError("host task shutdown is uncertain; retain owners until process reap") from self._close_error


def start(config_path):
    """Fixed `process_bootstrap` entrypoint for the supervised host role."""
    return C2HostService(config_path).start()
