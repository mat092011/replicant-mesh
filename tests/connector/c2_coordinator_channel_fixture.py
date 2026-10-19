"""Genuine selected-root and loopback gateway fixture for C2 channel tests.

The fixture uses the repository's signed selected coordinator/artifact fixture,
then rebuilds that same selected generation with signed gateway locators and
three real selected host tuples. It owns no model runtime or READY state.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from steamboat_security.certificates import (
    certificate_sha256, generate_ca, generate_private_key_pem,
    public_key_sha256, serial_hex,
)
from steamboat_security.channel_certificates import (
    issue_channel_certificate, make_channel_csr,
)
from steamboat_security.channel_policy import sign_channel_policy
from steamboat_security.codec import canonical_json, WORKER_METHODS


_RETAINED = []
_RETAINED_LOCK = threading.Lock()
_RETAINED_LIMIT = 8


def _listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(4)
    return sock


def _private(path, data):
    path = Path(path)
    path.write_bytes(data)
    os.chmod(path, 0o600)


class C2CoordinatorChannelFixture:
    """One actual selected coordinator and a loopback three-worker gateway."""

    def __init__(self, artifacts_dir="/artifacts"):
        if os.name != "posix" or not hasattr(os, "geteuid"):
            raise RuntimeError("C2 coordinator channel fixture requires POSIX")
        with _RETAINED_LOCK:
            if len(_RETAINED) >= _RETAINED_LIMIT:
                raise RuntimeError("uncertain C2 channel fixture retention bound exhausted")
            self._retention = {"fixture": self, "state": "building"}
            _RETAINED.append(self._retention)
        self._closed = False
        self._reclaimed = False
        self._pump_stop = threading.Event()
        self._pump_thread = None
        self.runtime_case = None
        self.channel = None
        self.gateway = None
        self.listeners = []
        self.worker_clients = []
        self.policy_owners = []
        self.traffic_owners = []
        self._temporary = None
        try:
            self._build(Path(artifacts_dir))
        except BaseException:
            self.close()
            raise

    def _build(self, artifacts_dir):
        import tests.connector.test_c2_coordinator_runtime as runtime_tests
        self.runtime_case = runtime_tests.C2CoordinatorRuntimeNativeTests(
            methodName="test_actual_selected_pin_loads_assigned_head_health_and_confirmed_close")
        self.runtime_case.setUp()
        case = self.runtime_case
        self.fx = case.fx
        self.binding = case.child_owner._binding
        self.clock = self.fx.clock
        self._temporary = Path(self.fx.protected) / "coordinator-channel-fixture"
        self._temporary.mkdir(mode=0o700)
        scope = json.loads(self.fx.artifacts["activation_manifest.json"])[
            "new_host_group_scopes"][0]
        self.components = tuple(scope["components"])
        self.host_spec = self.fx.host_spec
        self.host_certificate = (self.fx.protected / "host.pem").read_bytes()
        self.host_record = self.binding._snapshot_store.current().credential(
            self.host_spec.serial)
        if self.host_record is None:
            raise RuntimeError("selected C1 snapshot lacks the selected host credential")

        self.worker_listener = _listener()
        self.coordinator_listener = _listener()
        self.listeners = [self.worker_listener, self.coordinator_listener]
        self.gateway_ca, self.gateway_ca_key = generate_ca(
            common_name="C2 coordinator channel fixture gateway CA",
            now=self.clock.sample().wall)
        self.gateway_key = generate_private_key_pem()
        gateway_identity = "gw-coordinator-fixture"
        gateway_csr = make_channel_csr(
            self.gateway_key, kind="gateway", identity=gateway_identity,
            ip_addresses=("127.0.0.1",))
        self.gateway_certificate = issue_channel_certificate(
            self.gateway_ca, self.gateway_ca_key, gateway_csr,
            kind="gateway", identity=gateway_identity,
            now=datetime.fromtimestamp(self.clock.sample().wall, timezone.utc),
            lifetime_seconds=240, ip_addresses=("127.0.0.1",))
        self.worker_channel_materials = {}
        worker_records = []
        for component in self.components:
            cert_path, key_path = self.fx.channel_paths[component["component"]]
            cert_pem, key_pem = cert_path.read_bytes(), key_path.read_bytes()
            cert = x509.load_pem_x509_certificate(cert_pem)
            self.worker_channel_materials[component["component"]] = (cert_pem, key_pem)
            worker_records.append({
                "account_id": self.host_record.account_id,
                "device_id": self.host_record.device_id,
                "host_serial": self.host_record.serial,
                "host_credential_epoch": self.host_record.credential_epoch,
                "host_certificate_sha256": self.host_record.certificate_sha256,
                "worker_boot_id": component["worker_boot_id"],
                "assignment_id": component["assignment_id"],
                "model_id": scope["model_id"],
                "channel_serial": serial_hex(cert.serial_number),
                "channel_certificate_sha256": certificate_sha256(cert),
                "channel_public_key_sha256": public_key_sha256(cert.public_key()),
                "not_before": int(cert.not_valid_before.timestamp()),
                "not_after": int(cert.not_valid_after.timestamp()),
                "gateway_id": gateway_identity,
            })
        coordinator = self.binding.local_identity
        coordinator_cert = x509.load_pem_x509_certificate(coordinator.certificate_pem)
        sample = self.clock.sample()
        issued = int(sample.wall)
        expires = min(issued + 100,
            int(x509.load_pem_x509_certificate(self.gateway_certificate).not_valid_after.timestamp()) - 1,
            *(int(x509.load_pem_x509_certificate(item[0]).not_valid_after.timestamp()) - 1
              for item in self.worker_channel_materials.values()))
        gateways = [{
            "gateway_id": gateway_identity,
            "serial": serial_hex(x509.load_pem_x509_certificate(self.gateway_certificate).serial_number),
            "certificate_sha256": certificate_sha256(
                x509.load_pem_x509_certificate(self.gateway_certificate)),
            "public_key_sha256": public_key_sha256(
                x509.load_pem_x509_certificate(self.gateway_certificate).public_key()),
            "not_before": int(x509.load_pem_x509_certificate(self.gateway_certificate).not_valid_before.timestamp()),
            "not_after": int(x509.load_pem_x509_certificate(self.gateway_certificate).not_valid_after.timestamp()),
            "endpoint_host": "127.0.0.1",
            "endpoint_port": self.worker_listener.getsockname()[1],
            "coordinator_endpoint_host": "127.0.0.1",
            "coordinator_endpoint_port": self.coordinator_listener.getsockname()[1],
        }]
        workers = sorted(worker_records, key=lambda item: (item["device_id"], item["worker_boot_id"]))
        routes = []
        for worker in workers:
            routes.append({
                "gateway_id": gateway_identity,
                "account_id": coordinator.account_id,
                "device_id": coordinator.device_id,
                "actor_serial": serial_hex(coordinator_cert.serial_number),
                "actor_credential_epoch": self.binding.launch_spec.credential_epoch,
                "actor_certificate_sha256": certificate_sha256(coordinator_cert),
                "coordinator_boot_id": coordinator.boot_id,
                "tenant_account_id": coordinator.account_id,
                "target_device_id": worker["device_id"],
                "worker_boot_id": worker["worker_boot_id"],
                "assignment_id": worker["assignment_id"],
                "model_id": worker["model_id"],
                "methods": sorted(WORKER_METHODS),
            })
        policy_key = generate_private_key_pem()
        from steamboat_security.certificates import _key_pem_public
        policy_public = _key_pem_public(policy_key)
        payload = {"version": 2, "revision": 1, "issued_at": issued,
            "expires_at": expires, "gateways": gateways, "workers": workers,
            "routes": routes}
        self.signed_policy = sign_channel_policy(payload, policy_key)
        from steamboat_security.channel_policy import canonical_json as policy_json
        self.policy_digest = hashlib.sha256(policy_json(payload)).hexdigest()
        self.gateway_id = gateway_identity
        self.coordinator_boot = coordinator.boot_id
        self.gateway_boot = "d" * 32
        self.owner_policy = runtime_tests.C2CoordinatorRuntimeNativeTests.owner_policy(
            1 << 30, sessions=2)
        from steamboat_connector.c2_coordinator_channel import _stream_reservation
        from steamboat_connector.channel_client import (
            _CONTROL_CAPTURE, _CONTROL_SLOTS, _DATA_CAPTURE, _DATA_SLOTS)
        role = self.owner_policy["reservations"]["coordinator"]
        role["communication_bytes"] = max(role["communication_bytes"], _stream_reservation())
        role["capture_bytes"] = max(role["capture_bytes"],
            _DATA_SLOTS * _DATA_CAPTURE + _CONTROL_SLOTS * _CONTROL_CAPTURE)
        self.owner_policy["limits"].update(
            send_bytes_per_second=1 << 30, receive_bytes_per_second=1 << 30,
            total_network_bytes=1 << 34, cleanup_send_bytes_per_second=1 << 28,
            cleanup_receive_bytes_per_second=1 << 28,
            cleanup_total_network_bytes=1 << 32)
        for allocation in self.owner_policy["reservations"].values():
            allocation.update(send_bytes_per_second=1 << 20,
                receive_bytes_per_second=1 << 20, total_network_bytes=1 << 30,
                cleanup_send_bytes_per_second=1 << 20,
                cleanup_receive_bytes_per_second=1 << 20,
                cleanup_total_network_bytes=1 << 28)
        from steamboat_connector.policy import validate_policy
        self.owner_policy = validate_policy(self.owner_policy)

        from steamboat_connector.channel_policy_store import PersistentChannelPolicyStore
        from steamboat_connector.traffic_budget import TrafficBudget
        self.client_policy_root = self._temporary / "client-policy"
        self.gateway_policy_root = self._temporary / "gateway-policy"
        for root in (self.client_policy_root, self.gateway_policy_root):
            root.mkdir(mode=0o700)
            owner = PersistentChannelPolicyStore.provision(root,
                expected_uid=os.geteuid(), verification_key_pem=policy_public,
                clock=self.clock, minimum_revision=1,
                minimum_policy_digest=self.policy_digest)
            owner.install(self.signed_policy)
            self.policy_owners.append(owner)
        self.client_policy_owner, self.gateway_policy_owner = self.policy_owners
        self.client_traffic = self._traffic(TrafficBudget, "coordinator-client")
        self.gateway_traffic = self._traffic(TrafficBudget, "gateway-server")
        self.gateway_traffic.bind_role("coordinator", self.gateway_boot)
        self.worker_traffic = []
        for component in self.components:
            budget = self._traffic(TrafficBudget, "worker-" + component["component"])
            budget.bind_role("host", component["worker_boot_id"])
            self.worker_traffic.append(budget)

        self._rewrite_selected_settings(policy_public, workers)
        self._reopen_selected_binding()
        from steamboat_connector.gateway_service import GatewayService, required_communication_memory_bytes
        targets = {(item["device_id"], item["worker_boot_id"], item["assignment_id"], item["model_id"]):
                   self.host_certificate for item in workers}
        self.gateway = GatewayService(
            worker_listener=self.worker_listener,
            coordinator_listener=self.coordinator_listener,
            expected_workers=tuple((item["device_id"], item["worker_boot_id"]) for item in workers),
            coordinator_boot_id=self.coordinator_boot,
            tenant_account_id=coordinator.account_id, gateway_id=gateway_identity,
            gateway_certificate_pem=self.gateway_certificate,
            gateway_private_key_pem=self.gateway_key,
            cohort_ca_pem=self.binding._snapshot_store.ca_certificate_pem,
            gateway_ca_pem=self.gateway_ca,
            target_certificates=targets,
            snapshot_store=self.binding._snapshot_store,
            policy_store=self.gateway_policy_owner.core_store,
            clock=self.clock, traffic_budget=self.gateway_traffic,
            gateway_traffic_boot_id=self.gateway_boot,
            communication_memory_ceiling_bytes=required_communication_memory_bytes(3))
        self._start_service_pump()

    def _traffic(self, traffic_type, label):
        from steamboat_runtime.protocol.clock import clock_identity
        state = self._temporary / f"{label}-traffic.json"
        owner = traffic_type.create_fresh(state,
            allocation_id=uuid.uuid4().hex * 2, uid=os.geteuid(),
            clock=self.clock, clock_domain=clock_identity(), policy=self.owner_policy)
        self.traffic_owners.append(owner)
        return owner

    def _rewrite_selected_settings(self, policy_public, workers):
        """Re-seal the fixture's selected generation with actual local locators."""
        case = self.runtime_case
        fx = self.fx
        old_binding = case.child_owner
        old_binding.close()
        case.child_owner = None
        settings_path = fx.coordinator_header_path.parent / "coordinator-runtime.json"
        # The settings document itself was created in protected storage by the
        # trusted fixture; retain all selected artifact anchors and replace only
        # transport locators/worker tuple declarations.
        from steamboat_connector.c2_coordinator_settings import parse_c2_coordinator_settings
        header = json.loads(fx.coordinator_header_path.read_bytes())
        settings_path = Path(header["runtime_configuration_path"])
        settings = json.loads(settings_path.read_bytes())
        settings["workers"] = {
            f"worker-{index}": {
                "device_id": item["device_id"],
                "worker_boot_id": item["worker_boot_id"],
                "assignment_id": item["assignment_id"],
                "host_certificate": {"path": str(fx.protected / "host.pem"),
                    "sha256": hashlib.sha256(self.host_certificate).hexdigest()},
            } for index, item in enumerate(workers, 1)}
        policy_file = self._temporary / "initial-policy.json"
        _private(policy_file, self.signed_policy)
        ca_file = self._temporary / "gateway-ca.pem"
        _private(ca_file, self.gateway_ca)
        settings["gateway"] = {
            "gateway_id": self.gateway_id,
            "policy_root": str(self.client_policy_root),
            "initial_policy": {"path": str(policy_file),
                "sha256": hashlib.sha256(self.signed_policy).hexdigest()},
            "verification_key_pem": policy_public.decode("ascii"),
            "minimum_revision": 1,
            "minimum_policy_digest": self.policy_digest,
            "gateway_ca": {"path": str(ca_file),
                "sha256": hashlib.sha256(self.gateway_ca).hexdigest()},
        }
        settings["traffic"].update(state_path=str(self.client_traffic.path),
            allocation_id=self.client_traffic.allocation_id,
            clock_domain=self.client_traffic.clock_domain)
        settings_bytes = canonical_json(settings)
        parse_c2_coordinator_settings(settings_bytes)
        _private(settings_path, settings_bytes)
        header["runtime_configuration_sha256"] = hashlib.sha256(settings_bytes).hexdigest()
        header_bytes = canonical_json(header)
        _private(fx.coordinator_header_path, header_bytes)
        fx.header_path = fx.coordinator_header_path
        activation = json.loads(fx.artifacts["activation_manifest.json"])
        specs = json.loads(fx.artifacts["new_launch_specs.json"])
        from steamboat_security.root_transition_launch import (
            canonical_role_launch_digest, parse_role_launch_spec)
        for spec in specs:
            if spec["role"] == "personal_coordinator":
                spec["configuration_sha256"] = hashlib.sha256(header_bytes).hexdigest()
        activation["new_launch_specs"] = specs
        activation["new_launch_digest"] = canonical_role_launch_digest(
            tuple(parse_role_launch_spec(item) for item in specs))
        fx.artifacts["new_launch_specs.json"] = canonical_json(specs)
        fx.artifacts["activation_manifest.json"] = canonical_json(activation)
        self._rebuild_root_generation()

    def _rebuild_root_generation(self):
        fx = self.fx
        from steamboat_security.root_transition_storage import (
            RootGenerationSelector, root_generation_selector_document)
        from steamboat_security.snapshot import canonical_policy_digest
        from steamboat_security.codec import canonical_json
        from steamboat_security.root_transition_launch import parse_role_launch_spec
        from steamboat_security.snapshot import sign_snapshot
        # Current fixture already has the exact model-pinned policy. The new
        # C1 worker grants use the selected C2 component boots and assignments.
        scope = json.loads(fx.artifacts["activation_manifest.json"])["new_host_group_scopes"][0]
        coordinator_spec = fx.coordinator_spec
        source = next((grant for grant in json.loads(fx.active)["payload"]["grants"]
            if grant["actor_serial"] == coordinator_spec.serial and grant["target_role"] == "host"), None)
        if source is None:
            raise RuntimeError("selected C1 fixture lacks a coordinator-to-host grant template")
        for encoded in ("policy_snapshot.json",):
            payload = json.loads(fx.artifacts[encoded])["payload"]
            payload["grants"] = [g for g in payload["grants"] if not (
                g["actor_serial"] == coordinator_spec.serial and g["target_role"] == "host")]
            for component in scope["components"]:
                grant = dict(source)
                grant.update(target_boot_id=component["worker_boot_id"],
                    assignment_id=component["assignment_id"], model_id=scope["model_id"])
                payload["grants"].append(grant)
            fx.artifacts[encoded] = sign_snapshot(payload, fx.fx.new_snapshot_key)
        active = json.loads(fx.active)
        active_payload = active["payload"]
        active_payload["grants"] = [g for g in active_payload["grants"] if not (
            g["actor_serial"] == coordinator_spec.serial and g["target_role"] == "host")]
        for component in scope["components"]:
            grant = dict(source)
            grant.update(target_boot_id=component["worker_boot_id"],
                assignment_id=component["assignment_id"], model_id=scope["model_id"])
            active_payload["grants"].append(grant)
        fx.active = sign_snapshot(active_payload, fx.fx.new_snapshot_key)
        activation = json.loads(fx.artifacts["activation_manifest.json"])
        activation["policy_revision"] = active_payload["revision"]
        activation["policy_digest"] = canonical_policy_digest(active_payload)
        activation["policy_payload_sha256"] = hashlib.sha256(
            canonical_json(active_payload)).hexdigest()
        fx.artifacts["activation_manifest.json"] = canonical_json(activation)
        old = fx.selector
        specs = tuple(parse_role_launch_spec(item)
            for item in activation["new_launch_specs"])
        fx.coordinator_spec = next(spec for spec in specs if spec.role == "personal_coordinator")
        fx.artifacts["new_launch_specs.json"] = canonical_json(
            activation["new_launch_specs"])
        selector = RootGenerationSelector(old.generation_sha256,
            hashlib.sha256(fx.artifacts["activation_manifest.json"]).hexdigest(),
            active_payload["revision"], canonical_policy_digest(active_payload),
            hashlib.sha256(fx.active).hexdigest(),
            {name: hashlib.sha256(data).hexdigest() for name, data in fx.artifacts.items()})
        generation = fx.root / "generations" / selector.generation_sha256
        descriptor = {"schema_version": 1, "purpose": "root_generation_descriptor",
            "generation_sha256": selector.generation_sha256,
            "activation_manifest_sha256": selector.activation_manifest_sha256,
            "artifact_sha256": dict(selector.artifact_sha256)}
        fx._private(generation / "descriptor.json", canonical_json(descriptor))
        for name, data in fx.artifacts.items():
            fx._private(generation / name, data)
        for path in (fx.root / "policies").iterdir():
            path.unlink()
        fx._private(fx.root / "policies" / f"{hashlib.sha256(fx.active).hexdigest()}.json", fx.active)
        fx._private(fx.root / "selector.json",
            canonical_json(root_generation_selector_document(selector)))
        fx.selector = selector

    def _reopen_selected_binding(self):
        from steamboat_connector.c2_child_config import C2ChildBinding
        root_store, binding = self.runtime_case.root_fixture._load()
        self.runtime_case.child_owner = C2ChildBinding(root_store, binding)
        self.binding = binding

    def _start_service_pump(self):
        def run():
            while not self._pump_stop.is_set():
                try:
                    self.gateway.pump_once()
                except BaseException:
                    if not self._pump_stop.is_set():
                        self._pump_error = True
                    return
                self._pump_stop.wait(0.001)
        self._pump_error = False
        self._pump_thread = threading.Thread(target=run,
            name="c2-channel-gateway-fixture", daemon=True)
        self._pump_thread.start()

    def wait_route_connected(self, timeout=5.0):
        from steamboat_connector.channel_hello import WorkerHelloClient
        from steamboat_connector.channel_stream import ChannelStream
        from steamboat_connector.channel_socket import ChannelSocket
        from steamboat_security.channel_tls import OwnedWorkerTLS
        from steamboat_security.authorization import LocalIdentity
        from steamboat_security.gateway_delegation import GatewayDelegationVerifier
        from steamboat_security.sessions import SessionBindings
        from steamboat_connector import channel_wire as wire
        from steamboat_connector.channel_stream import TLS_OWNER_MIN_RESERVATION_BYTES
        from steamboat_connector.channel_writer import writer_reservation_overhead_bytes
        from steamboat_connector.channel_wire import MAX_CONTROL_BUNDLE_BYTES
        deadline = time.monotonic() + timeout
        for index, component in enumerate(self.components):
            cert, key = self.worker_channel_materials[component["component"]]
            owner = OwnedWorkerTLS.connect(worker_certificate_pem=cert,
                worker_private_key_pem=key, gateway_ca_pem=self.gateway_ca,
                endpoint_host="127.0.0.1", endpoint_port=self.gateway.worker_address[1],
                clock=self.clock)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            sock.connect(self.gateway.worker_address[:2])
            sock.setblocking(False)
            driver = ChannelSocket(sock, owner, self.worker_traffic[index],
                role="host", boot_id=component["worker_boot_id"])
            self.worker_clients.append({"owner": owner, "socket": sock, "driver": driver})
        while time.monotonic() < deadline:
            for item in self.worker_clients:
                try:
                    item["driver"].pump()
                except (BlockingIOError, OSError):
                    pass
            time.sleep(0.001)
            if len(self.gateway._workers) == 3:
                break
        if len(self.gateway._workers) != 3:
            raise RuntimeError("three actual worker HELLO registrations did not complete")
        # HELLO clients are created only after the true TCP/TLS owner exists.
        from steamboat_security.gateway_delegation import GatewayDelegationVerifier
        from steamboat_security.authorization import LocalIdentity
        from steamboat_security.sessions import SessionBindings
        from steamboat_connector.channel_hello import WorkerHelloClient
        from steamboat_connector.channel_stream import ChannelStream
        from steamboat_connector.channel_wire import MAX_BUNDLE_BYTES
        from steamboat_connector.channel_writer import writer_reservation_overhead_bytes
        from steamboat_connector.channel_wire import MAX_CONTROL_BUNDLE_BYTES
        from steamboat_connector.channel_stream import TLS_OWNER_MIN_RESERVATION_BYTES
        for index, (item, component) in enumerate(zip(self.worker_clients, self.components)):
            owner, driver = item["owner"], item["driver"]
            deadline_tls = time.monotonic() + timeout
            while (not owner.handshake_complete or driver.pending_ciphertext_bytes
                    or owner.pending_encrypted_bytes) and time.monotonic() < deadline_tls:
                driver.pump(); time.sleep(0.001)
            cert = self.host_certificate
            local = LocalIdentity(cert, component["worker_boot_id"],
                json.loads(self.fx.artifacts["activation_manifest.json"])[
                    "new_host_group_scopes"][0]["model_id"], component["assignment_id"])
            verifier = GatewayDelegationVerifier(self.client_policy_owner.core_store,
                clock=self.clock, gateway_ca_pem=self.gateway_ca,
                participant_ca_pem=self.binding._snapshot_store.ca_certificate_pem,
                local_identity=local, endpoint_host="127.0.0.1",
                endpoint_port=self.gateway.worker_address[1])
            ingress = __import__("steamboat_security.gateway_ingress", fromlist=[
                "GatewayWorkerIngress"]).GatewayWorkerIngress.from_tls(
                    owner, verifier=verifier, sessions=SessionBindings(clock=self.clock),
                    gateway_id=self.gateway_id)
            hello = WorkerHelloClient(ingress, owner,
                reassembly_capacity=wire.MAX_BUNDLE_BYTES)
            item["stream"] = ChannelStream(driver, hello,
                writer_reservation_bytes=(writer_reservation_overhead_bytes()
                    + wire.MAX_BUNDLE_BYTES + 8 * MAX_CONTROL_BUNDLE_BYTES),
                decoded_byte_capacity=wire.MAX_BUNDLE_BYTES,
                tls_owner_reservation_bytes=TLS_OWNER_MIN_RESERVATION_BYTES)
        # Continue real client HELLO streams until the gateway has its fixed mux.
        while not self.gateway.route_connected and time.monotonic() < deadline:
            for item in self.worker_clients:
                item["stream"].pump()
            time.sleep(0.001)
        if not self.gateway.route_connected:
            raise RuntimeError("selected coordinator and all workers did not reach route-connected state")

    async def build_channel(self):
        from steamboat_connector.c2_coordinator_channel import build_c2_coordinator_channel
        self.channel = await build_c2_coordinator_channel(self.runtime_case.child_owner,
            owner_policy=self.owner_policy,
            policy_owner=self.client_policy_owner, traffic=self.client_traffic)
        return self.channel

    async def close_channel(self):
        if self.channel is not None and self.channel._state != "closed":
            try:
                await self.channel.close(grace_seconds=5)
            except BaseException:
                pass

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._pump_stop.set()
        if self._pump_thread is not None:
            self._pump_thread.join(timeout=2)
        if self.gateway is not None:
            self.gateway.stop()
        for item in reversed(self.worker_clients):
            driver = item.get("driver")
            owner = item.get("owner")
            if driver is not None:
                driver.close()
            elif owner is not None:
                owner.close()
            sock = item.get("socket")
            if sock is not None and sock.fileno() != -1:
                sock.close()
        for listener in self.listeners:
            if listener.fileno() != -1 and (self.gateway is None or
                    id(listener) not in self.gateway._listeners_closed):
                listener.close()
        gateway_closed = (self.gateway is None or self.gateway._resources_closed is True)
        listeners_closed = all(s.fileno() == -1 for s in self.listeners)
        service_quiescent = (self._pump_thread is None or not self._pump_thread.is_alive())
        if gateway_closed and listeners_closed and service_quiescent:
            for owner in reversed(self.policy_owners):
                if not owner._closed:
                    owner.close()
            for owner in reversed(self.traffic_owners):
                owner.close()
            if self.runtime_case is not None:
                try:
                    asyncio.run(self.runtime_case.asyncTearDown())
                except RuntimeError:
                    # The integration test calls close from its own event loop;
                    # this path is handled by async_close below.
                    pass
            self._reclaimed = True
        else:
            self._retention["state"] = "uncertain"
        if self._reclaimed:
            with _RETAINED_LOCK:
                if self._retention in _RETAINED:
                    _RETAINED.remove(self._retention)

    async def async_close(self):
        await self.close_channel()
        self._pump_stop.set()
        if self._pump_thread is not None:
            await asyncio.to_thread(self._pump_thread.join, 2)
        if self.gateway is not None:
            self.gateway.stop()
        for item in reversed(self.worker_clients):
            driver, owner, sock = item.get("driver"), item.get("owner"), item.get("socket")
            if driver is not None:
                driver.close()
            elif owner is not None:
                owner.close()
            if sock is not None and sock.fileno() != -1:
                sock.close()
        for listener in self.listeners:
            if listener.fileno() != -1 and (self.gateway is None or
                    id(listener) not in self.gateway._listeners_closed):
                listener.close()
        gateway_closed = self.gateway is None or self.gateway._resources_closed is True
        if (gateway_closed and all(s.fileno() == -1 for s in self.listeners)
                and (self._pump_thread is None or not self._pump_thread.is_alive())):
            for owner in reversed(self.policy_owners):
                if not owner._closed:
                    owner.close()
            for owner in reversed(self.traffic_owners):
                owner.close()
            if self.runtime_case is not None:
                await self.runtime_case.asyncTearDown()
            self._reclaimed = True
            self._retention["state"] = "reclaimed"
            with _RETAINED_LOCK:
                if self._retention in _RETAINED:
                    _RETAINED.remove(self._retention)
        else:
            self._retention["state"] = "uncertain"

