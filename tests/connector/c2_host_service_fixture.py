"""Native fixture for one selected C2 host child and signed loopback gateway.

The filesystem cgroup below models only the supervisor lifecycle markers. It
does not enforce CPU or memory limits; the worker process, ClockBridge, root
binding, artifact pin, TLS, policy and HELLO paths remain real.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from contextlib import ExitStack
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from steamboat_security.certificates import (
    certificate_sha256, generate_private_key_pem,
    public_key_sha256, serial_hex,
)
from steamboat_security.channel_policy import sign_channel_policy
from steamboat_security.channel_certificates import (
    issue_channel_certificate, make_channel_csr,
)

_RETAINED_UNCERTAIN_FIXTURES = []
_RETENTION_LOCK = threading.Lock()
_MAX_RETAINED_FIXTURES = 8
_MISSING = object()


def _reserve_retention_slot():
    with _RETENTION_LOCK:
        if len(_RETAINED_UNCERTAIN_FIXTURES) >= _MAX_RETAINED_FIXTURES:
            raise RuntimeError("C2 fixture retention capacity is exhausted")
        slot = {"fixture": None}
        _RETAINED_UNCERTAIN_FIXTURES.append(slot)
        return slot


def _release_retention_slot(slot):
    with _RETENTION_LOCK:
        if slot in _RETAINED_UNCERTAIN_FIXTURES:
            _RETAINED_UNCERTAIN_FIXTURES.remove(slot)


def _pem_private(key):
    return key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _pem_public(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def _gateway_certificate(ca_pem, ca_key_pem, *, now, identity="gw-c2-host"):
    key_pem = generate_private_key_pem()
    csr = make_channel_csr(key_pem, kind="gateway", identity=identity,
                           ip_addresses=("127.0.0.1",))
    certificate_pem = issue_channel_certificate(
        ca_pem, ca_key_pem, csr, kind="gateway", identity=identity,
        now=datetime.fromtimestamp(now, timezone.utc), lifetime_seconds=240,
        ip_addresses=("127.0.0.1",))
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    return certificate_pem, key_pem, certificate


def _listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    return sock


class LifecycleCgroupStandIn:
    """Filesystem lifecycle markers only; never claims resource enforcement."""
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(mode=0o700)
        self._lock = threading.Lock()
        self._groups = set()
        self._watchers = []

    def create_group(self, name, _policy, _role):
        group = self.root / name
        group.mkdir(mode=0o700)
        (group / "cgroup.events").write_text("populated 0\n", encoding="ascii")
        (group / "cgroup.procs").write_text("", encoding="ascii")
        with self._lock:
            self._groups.add(group)
        return group

    def attach_child(self, group, process):
        group = Path(group)
        (group / "cgroup.events").write_text("populated 1\n", encoding="ascii")
        (group / "cgroup.procs").write_text(str(process.pid), encoding="ascii")
        watcher = threading.Thread(target=self._observe_reaped_process,
            args=(group, process.pid), name="c2-test-cgroup-observer", daemon=True)
        self._watchers.append(watcher)
        watcher.start()

    @staticmethod
    def _observe_reaped_process(group, pid):
        # Observation only: backend.poll()/wait() owns the actual reap.
        deadline = time.monotonic() + 20.0
        proc = Path("/proc") / str(pid)
        while proc.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not proc.exists():
            (group / "cgroup.events").write_text("populated 0\n", encoding="ascii")
            (group / "cgroup.procs").write_text("", encoding="ascii")

    def remove_empty_group(self, group):
        group = Path(group)
        if not self._events_empty(group):
            return False
        for name in ("cgroup.events", "cgroup.procs"):
            try:
                (group / name).unlink()
            except FileNotFoundError:
                pass
        group.rmdir()
        with self._lock:
            self._groups.discard(group)
        return not group.exists()

    @staticmethod
    def _events_empty(group):
        try:
            return (Path(group) / "cgroup.events").read_text(encoding="ascii") == "populated 0\n"
        except OSError:
            return False

    def close(self):
        for watcher in self._watchers:
            watcher.join(timeout=1)


class C2HostProcessFixture:
    """Own all parents needed to start and stop one real selected host child."""
    def __init__(self, artifacts_dir="/artifacts", scratch_dir=None):
        if not sys_platform_linux():
            raise RuntimeError("actual C2 host process fixture requires Linux")
        self._retention_slot = _reserve_retention_slot()
        self._retention_slot["fixture"] = self
        self._cleanup_confirmed = False
        self._closed = False
        self._stack = ExitStack()
        self._temp = None
        self.root = None
        self.listeners = ()
        self._listener_close_states = {}
        self._gateway_owns_listeners = False
        self.gateway = self.startup = self.backend = self.cgroup = None
        self._partial_startup = None
        self._startup_construction_failed = False
        self.policy_owner = self.traffic = self.clock = None
        self.gateway_ca = self.gateway_ca_key = None
        self.gateway_cert = self.gateway_key = self.gateway_x509 = None
        # Establish cleanup coverage before imports, manifest reads, directory
        # creation, listener allocation, or any selected-root construction.
        self._stack.callback(self._cleanup_owners)
        try:
            from steamboat_runtime.manifest import load_manifest
            from steamboat_runtime.protocol.clock import clock_identity
            from tests.connector.test_artifacts import _PUBLIC
            from tests.security import test_root_c2_runtime as c2_runtime_tests
            self._c2_runtime_tests = c2_runtime_tests
            self.artifacts_dir = Path(artifacts_dir).resolve(strict=True)
            self._temp = tempfile.TemporaryDirectory(prefix="c2-host-process-",
                dir=scratch_dir)
            self.root = Path(self._temp.name)
            os.chmod(self.root, 0o700)
            listeners = []
            for _ in range(2):
                listener = _listener()
                listeners.append(listener)
                self._listener_close_states[id(listener)] = [listener, "open"]
                self._stack.callback(self._close_untransferred_listener, listener)
            self.listeners = tuple(listeners)
            from cryptography.hazmat.primitives.asymmetric import ec
            self.policy_key = ec.generate_private_key(ec.SECP256R1())
            self.policy_private_pem = _pem_private(self.policy_key)
            self.policy_public_pem = _pem_public(self.policy_key)
            self.model_fingerprint = load_manifest(self.artifacts_dir)["fingerprint"]
            self.catalog_public_key_hex = _PUBLIC.hex()
            self._runtime_case = None
            self._prepare_fixture(c2_runtime_tests, _PUBLIC, clock_identity)
        except BaseException:
            self.close()
            raise

    def _close_untransferred_listener(self, listener):
        if self._gateway_owns_listeners:
            return
        record = self._listener_close_states.get(id(listener))
        if record is None or record[0] is not listener or record[1] != "open":
            return
        record[1] = "closing"
        try:
            listener.close()
            record[1] = "closed" if listener.fileno() == -1 else "uncertain"
        except BaseException:
            record[1] = "uncertain"

    def _prepare_fixture(self, runtime_tests, catalog_key, clock_identity):
        from tests.connector.c2_startup_fixture import C2StartupFixture
        startup_type = C2StartupFixture
        original_selected_build = startup_type._build_selected_root
        original_clock = runtime_tests.Clock
        original_private = runtime_tests.C2RuntimeStoreIntegrationTests._private
        original_build = runtime_tests.C2RuntimeStoreIntegrationTests._build

        def capture_startup_pin_root(startup):
            self._partial_startup = startup
            self._actual_pin_root = startup.pin_root
            return original_selected_build(startup)

        def native_clock(*, wall, monotonic, uncertainty_seconds=None, **kwargs):
            # Signed fixture time advances with the actual Linux monotonic
            # source required by inherited ClockBridge checks.
            initial_wall = float(wall())
            initial_mono = time.monotonic()
            return original_clock(wall=lambda: initial_wall + time.monotonic() - initial_mono,
                monotonic=time.monotonic,
                uncertainty_seconds=uncertainty_seconds, **kwargs)

        def build(case, **kwargs):
            # Give the selected group policy enough monotonic runway for the
            # real offline resident-stage load in the native integration test.
            case._testMethodName = "test_final_uncertainty_deadline_is_retained_across_clock_drift"
            self._runtime_case = case
            return original_build(case, **kwargs)

        def write_private(path, data):
            path = Path(path)
            if path.name == "runtime.json" and self._runtime_case is not None:
                data = self._make_runtime_settings(self._runtime_case, catalog_key,
                                                   clock_identity)
            elif path.name == "header.json" and self._runtime_case is not None:
                from steamboat_security.codec import canonical_json
                header = json.loads(data.decode("utf-8", "strict"))
                runtime_bytes = (path.parent / "runtime.json").read_bytes()
                header["runtime_configuration_sha256"] = hashlib.sha256(
                    runtime_bytes).hexdigest()
                data = canonical_json(header)
            return original_private(path, data)

        import tests.security.test_root_transition_issuance as issuance_fixture
        baseline = int(time.time())
        original_mutable_init = issuance_fixture.MutableClock.__init__
        issuance_class = issuance_fixture.RootTransitionIssuanceTests
        class_fields = ("old_ca", "old_ca_key", "new_ca", "new_ca_key",
            "old_snapshot_key", "new_snapshot_key", "old_snapshot_public",
            "new_snapshot_public", "clock_source", "account", "roles",
            "intent_document", "payload", "intent")
        prior_class_state = {name: getattr(issuance_class, name, _MISSING)
                             for name in class_fields}

        def current_mutable_clock(clock, wall=None):
            return original_mutable_init(clock, wall=baseline if wall is None else wall)

        try:
            with (unittest_mock_patch(startup_type, "_build_selected_root",
                                      capture_startup_pin_root),
                  unittest_mock_patch(issuance_fixture, "NOW", baseline),
                  unittest_mock_patch(issuance_fixture.MutableClock, "__init__",
                                      current_mutable_clock),
                  unittest_mock_patch(runtime_tests, "Clock", native_clock),
                  unittest_mock_patch(runtime_tests.C2RuntimeStoreIntegrationTests,
                                      "_build", build),
                  unittest_mock_patch(runtime_tests.C2RuntimeStoreIntegrationTests,
                                      "_private", staticmethod(write_private))):
                try:
                    self.startup = C2StartupFixture(self.artifacts_dir, self.root)
                except BaseException:
                    self._startup_construction_failed = True
                    raise
        finally:
            for name, value in prior_class_state.items():
                if value is _MISSING:
                    try:
                        delattr(issuance_class, name)
                    except AttributeError:
                        pass
                else:
                    setattr(issuance_class, name, value)
        if Path(self._actual_pin_root).resolve() != self.startup.pin_root.resolve():
            raise RuntimeError("captured runtime artifact root differs from selected pin root")
        runtime_bytes = (self.startup.selected_store.protected / "runtime.json").read_bytes()
        header = json.loads(self.startup.selected_store.header_path.read_bytes())
        if header["runtime_configuration_sha256"] != hashlib.sha256(runtime_bytes).hexdigest():
            raise RuntimeError("selected header does not bind the exact runtime configuration")
        self.clock = self.startup.clock
        self.selected_spec = self.startup.selected_host
        self.binding = self.startup.binding
        self.root_store = self.startup.root_store
        self.pin = self.startup.pin
        self.verifier = self.startup.verifier
        self.scope = self.startup.selected_scope
        if self.gateway_ca != self.binding._snapshot_store.ca_certificate_pem:
            raise RuntimeError("gateway peer CA differs from the selected cohort CA")
        self.worker = self.startup.binding.components[0]
        self._open_policy_and_traffic()

    def _make_runtime_settings(self, case, catalog_key, clock_identity):
        from steamboat_security.channel_policy import canonical_json as policy_json
        from steamboat_security.certificates import _pem_certificate
        from steamboat_security.channel_policy import sign_channel_policy
        now = int(case.clock.sample().wall)
        if self.gateway_ca is None:
            # This actual GatewayService uses the selected cohort CA to verify
            # both its local gateway leaf and the worker-stream peer leaf.
            # Issue only the gateway fixture leaf from that same real root.
            self.gateway_ca = case.fx.new_ca
            self.gateway_ca_key = case.fx.new_ca_key
            self.gateway_cert, self.gateway_key, self.gateway_x509 = _gateway_certificate(
                self.gateway_ca, self.gateway_ca_key, now=now)
        candidate = case.fixture.candidate
        spec = next(item for item in candidate.new_launch_specs if item.role == "host")
        component = case.components[0]
        cert_path, key_path = case.channel_paths[component["component"]]
        channel_cert = _pem_certificate(cert_path.read_bytes())
        host_cert = _pem_certificate((case.protected / "host.pem").read_bytes())
        worker_port = self.listeners[0].getsockname()[1]
        coordinator_port = self.listeners[1].getsockname()[1]
        gateway = self.gateway_x509
        gateway_ca_path = case.protected / "gateway-ca.pem"
        policy_path = case.protected / "initial-channel-policy.json"
        policy_root = case.protected / "channel-policy-store"
        traffic_path = case.protected / "traffic-state.json"
        for path, content in ((gateway_ca_path, self.gateway_ca),):
            path.write_bytes(content); os.chmod(path, 0o600)
        policy_expires = min(now + 100, int(channel_cert.not_valid_after.timestamp()) - 1)
        payload = {
            "version": 2, "revision": 1, "issued_at": now,
            "expires_at": policy_expires,
            "gateways": [{"gateway_id": "gw-c2-host", "serial": serial_hex(gateway.serial_number),
                "certificate_sha256": certificate_sha256(gateway),
                "public_key_sha256": public_key_sha256(gateway.public_key()),
                "not_before": int(gateway.not_valid_before.timestamp()),
                "not_after": int(gateway.not_valid_after.timestamp()),
                "endpoint_host": "127.0.0.1", "endpoint_port": worker_port,
                "coordinator_endpoint_host": "127.0.0.1",
                "coordinator_endpoint_port": coordinator_port}],
            "workers": [{"account_id": spec.account_id, "device_id": spec.device_id,
                "host_serial": spec.serial, "host_credential_epoch": spec.credential_epoch,
                "host_certificate_sha256": certificate_sha256(host_cert),
                "worker_boot_id": component["worker_boot_id"],
                "assignment_id": component["assignment_id"],
                "model_id": self.model_fingerprint,
                "channel_serial": serial_hex(channel_cert.serial_number),
                "channel_certificate_sha256": certificate_sha256(channel_cert),
                "channel_public_key_sha256": public_key_sha256(channel_cert.public_key()),
                "not_before": int(channel_cert.not_valid_before.timestamp()),
                "not_after": int(channel_cert.not_valid_after.timestamp()),
                "gateway_id": "gw-c2-host"}],
            "routes": [],
        }
        signed = sign_channel_policy(payload, self.policy_private_pem)
        policy_path.write_bytes(signed); os.chmod(policy_path, 0o600)
        digest = hashlib.sha256(policy_json(payload)).hexdigest()
        from steamboat_connector.channel_policy_store import PersistentChannelPolicyStore
        policy_root.mkdir(mode=0o700)
        owner = PersistentChannelPolicyStore.provision(policy_root,
            expected_uid=os.geteuid(), verification_key_pem=self.policy_public_pem,
            clock=case.clock, minimum_revision=1, minimum_policy_digest=digest)
        owner.install(signed)
        owner.close()
        from steamboat_security.codec import canonical_json
        settings = {"schema_version": 1, "profile": "native_posix_c2_host_runtime_v1",
            "artifact_root": str(self._actual_pin_root),
            "catalog_public_key_hex": catalog_key.hex(),
            "component_allocations": {"worker-1": {"sessions": 1,
                "kv_bytes": 32768, "cache_positions": 32, "queued_calls": 0}},
            "gateway": {"gateway_id": "gw-c2-host", "policy_root": str(policy_root),
                "initial_policy": {"path": str(policy_path),
                    "sha256": hashlib.sha256(signed).hexdigest()},
                "verification_key_pem": self.policy_public_pem.decode("ascii"),
                "minimum_revision": 1, "minimum_policy_digest": digest,
                "gateway_ca": {"path": str(gateway_ca_path),
                    "sha256": hashlib.sha256(self.gateway_ca).hexdigest()}},
            "traffic": {"state_path": str(traffic_path),
                "allocation_id": uuid.uuid4().hex * 2,
                "clock_domain": clock_identity()},
        }
        return canonical_json(settings)

    def _open_policy_and_traffic(self):
        from steamboat_connector.channel_policy_store import PersistentChannelPolicyStore
        from steamboat_connector.traffic_budget import TrafficBudget
        from steamboat_security.channel_policy import canonical_json
        settings = json.loads((self.startup.selected_store.protected / "runtime.json").read_bytes())
        signed = Path(settings["gateway"]["initial_policy"]["path"]).read_bytes()
        # The durable owner validates the signed head; its core accessor is the
        # sole policy object passed to the actual GatewayService.
        document = json.loads(signed.decode("utf-8", "strict"))
        payload = document["payload"]
        policy_digest = hashlib.sha256(canonical_json(payload)).hexdigest()
        parent_policy_root = self.root / "gateway-policy-parent"
        parent_policy_root.mkdir(mode=0o700)
        self.policy_owner = PersistentChannelPolicyStore.provision(
            parent_policy_root, expected_uid=os.geteuid(),
            verification_key_pem=settings["gateway"]["verification_key_pem"].encode("ascii"),
            clock=self.clock, minimum_revision=1,
            minimum_policy_digest=policy_digest)
        self.policy_owner.install(signed)
        owner_policy = self._owner_policy()
        self.backend_policy = owner_policy
        traffic = settings["traffic"]
        self.traffic = TrafficBudget.create_fresh(traffic["state_path"],
            allocation_id=traffic["allocation_id"], uid=os.geteuid(),
            clock=self.clock, clock_domain=traffic["clock_domain"], policy=owner_policy)
        self.traffic.bind_role("coordinator", "c" * 32)
        self.gateway = self._make_gateway(payload, owner_policy)

    def _make_gateway(self, payload, owner_policy):
        from steamboat_connector.gateway_service import GatewayService, required_communication_memory_bytes
        component = self.scope["components"][0]
        spec = self.selected_spec
        target = (spec.device_id, component["worker_boot_id"],
                  component["assignment_id"], self.model_fingerprint)
        service = GatewayService(worker_listener=self.listeners[0],
            coordinator_listener=self.listeners[1], expected_workers=((spec.device_id,
                component["worker_boot_id"]),), coordinator_boot_id="c" * 32,
            tenant_account_id=spec.account_id, gateway_id="gw-c2-host",
            gateway_certificate_pem=self.gateway_cert,
            gateway_private_key_pem=self.gateway_key,
            cohort_ca_pem=self.binding._snapshot_store.ca_certificate_pem,
            gateway_ca_pem=self.gateway_ca, target_certificates={
                target: self.binding.host_tls_materials.certificate_pem},
            snapshot_store=self.binding._snapshot_store,
            policy_store=self.policy_owner.core_store, clock=self.clock,
            traffic_budget=self.traffic, gateway_traffic_boot_id="c" * 32,
            communication_memory_ceiling_bytes=required_communication_memory_bytes(1))
        self._gateway_owns_listeners = True
        return service

    def configure_backend(self):
        from steamboat_connector.c2_child_config import build_c2_child_config
        from steamboat_connector.process_supervisor import ProcessRoleBackend
        from steamboat_connector.catalog import CatalogVerifier
        self.cgroup = LifecycleCgroupStandIn(self.root / "cgroup-lifecycle")
        supervisor_root = self.root / "supervisor"
        supervisor_root.mkdir(mode=0o700)
        self.backend = ProcessRoleBackend(supervisor_root, self.cgroup)
        self.backend.bind_authority_clock(self.clock)
        config = build_c2_child_config(role="host",
            selected_root=str(self.startup.selected_store.root),
            protected_root=str(self.startup.selected_store.protected),
            configuration_path=str(self.startup.selected_store.header_path),
            launch_spec=self.selected_spec,
            operator_verification_key_pem=self.startup.operator_verification_key_pem)
        if (Path(config["selected_root"]).resolve()
                != self.startup.selected_store.root.resolve()
                or Path(config["protected_root"]).resolve()
                != self.startup.selected_store.protected.resolve()):
            raise RuntimeError("child configuration differs from the verified selected roots")
        if not self.backend.configure_pinned_role("host", config, self.pin,
                                                  catalog_verifier=self.verifier):
            raise RuntimeError("actual selected host pin could not be configured")
        self.backend_policy = self._owner_policy()
        return self.backend_policy

    @staticmethod
    def _owner_policy():
        from tests.connector.test_c2_host_service import _policy
        from steamboat_connector.c2_host_service import _stream_bound_bytes
        from steamboat_connector.channel_rpc import (
            _CONTROL_CAPTURE_BYTES, _DATA_CAPTURE_BYTES, _CONTROL_LIMIT, _DATA_LIMIT,
        )
        communication = _stream_bound_bytes()
        capture = _DATA_LIMIT * _DATA_CAPTURE_BYTES + _CONTROL_LIMIT * _CONTROL_CAPTURE_BYTES
        policy = _policy(communication=communication, capture=capture)
        policy["limits"].update(memory_ceiling_bytes=1 << 31,
            memory_headroom_bytes=16 << 20, disk_ceiling_bytes=256 << 20,
            send_bytes_per_second=1 << 30, receive_bytes_per_second=1 << 30,
            total_network_bytes=1 << 34, cleanup_send_bytes_per_second=1 << 28,
            cleanup_receive_bytes_per_second=1 << 28,
            cleanup_total_network_bytes=1 << 32, max_sessions=8,
            max_queued_calls=8, max_request_seconds=300)
        for role in policy["reservations"].values():
            role.update(disk_bytes=64 << 20, runtime_bytes=1 << 20,
                        temporary_bytes=16 << 20, weights_bytes=256 << 20,
                        kv_bytes=64 << 20, sessions=1, queued_calls=0,
                        max_request_seconds=300, send_bytes_per_second=1 << 20,
                        receive_bytes_per_second=1 << 20, total_network_bytes=1 << 30,
                        cleanup_send_bytes_per_second=1 << 20,
                        cleanup_receive_bytes_per_second=1 << 20,
                        cleanup_total_network_bytes=1 << 28)
        return policy

    def _cleanup_owners(self):
        gateway_reclaimed = (self._gateway_owns_listeners or all(
            record[1] == "closed" for record in self._listener_close_states.values()))
        if self.gateway is not None:
            self.gateway.stop()
            gateway_reclaimed = self.gateway_reclamation_confirmed()
        if not gateway_reclaimed:
            if self.backend is not None:
                self.backend.request_stop(("host",))
            return
        if self._startup_construction_failed:
            return
        reclaimed = True
        if self.backend is not None:
            result = self.backend.stop(("host",), 15.0)
            reclaimed = (result.get("host") is True
                         and "host" not in self.backend._owned)
        if (reclaimed and self.backend is not None
                and "host" in self.backend._pinned_roles):
            reclaimed = self.backend.release_configured_pin("host") is True
        if not reclaimed:
            # Keep every downstream descriptor/lease reachable when process
            # reclamation is uncertain; test teardown must not manufacture a
            # cleanup proof by closing parent pins or the selected root.
            return
        if self.policy_owner is not None and not self.policy_owner._closed:
            self.policy_owner.close()
        if self.cgroup is not None:
            self.cgroup.close()
        if self.startup is not None:
            self.startup.close()
        self._cleanup_confirmed = True

    def gateway_reclamation_confirmed(self):
        if self.gateway is None:
            return True
        from steamboat_connector import gateway_service as gateway_module
        from steamboat_connector.channel_socket import ChannelSocket
        stream_closes_confirmed = True
        for _registration, stream, _pending in self.gateway._workers.values():
            driver = stream if type(stream) is ChannelSocket else getattr(stream, "_driver", None)
            tls = None if driver is None else getattr(driver, "_tls", None)
            if (driver is None or driver.socket_close_status != "closed"
                    or tls is None or tls.cleanup_status != "removed"
                    or tls.cleanup_uncertain):
                stream_closes_confirmed = False
                break
        return (
            self.gateway._resources_closed is True
            and not self.gateway._stuck
            and stream_closes_confirmed
            and all(id(listener) in self.gateway._listeners_closed
                    for listener in self.listeners)
            and all(item.close_complete for item in self.gateway._accepted)
            and self.gateway not in gateway_module._LIVE_SERVICES
            and self.gateway not in gateway_module._RETAINED_SERVICES
            and all(gateway_module._LISTENER_OWNERS.get(id(listener), (None,))[0]
                    is not listener for listener in self.listeners))

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._stack.close()
        if self._cleanup_confirmed:
            if self._temp is not None:
                self._temp.cleanup()
            _release_retention_slot(self._retention_slot)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def sys_platform_linux():
    import sys
    return os.name == "posix" and sys.platform.startswith("linux")


def unittest_mock_patch(target, name, value):
    from unittest.mock import patch
    return patch.object(target, name, value)
