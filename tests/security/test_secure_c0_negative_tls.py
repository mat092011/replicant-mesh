"""Native TLS regressions for negative C0 worker admission.

This is a small non-model integration fixture.  It uses the signed synthetic
identities from ``secure_pipeline_fixture`` and the real C0 Authorizer,
SnapshotStore, SessionBindings, SecureWorkerRuntimeBridge, WorkerHandler and
native gRPC TLS server.  A counting executor is present only to prove rejected
requests do not reach application dispatch or compute.
"""

from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import time
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
SECURITY_TESTS = Path(__file__).resolve().parent
RUNTIME_TESTS = ROOT / "tests" / "runtime"
for _path in (SRC, SECURITY_TESTS, RUNTIME_TESTS):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


from secure_pipeline_fixture import SecurePipelineIdentityFixture  # noqa: E402
from test_manifest import sample_manifest  # noqa: E402


class _ZeroCache:
    """Counting cache for protocol controls; no model weights are loaded."""

    def __init__(self):
        self._lengths = (0,)

    def lengths(self):
        return self._lengths

    def allocated_bytes(self):
        return 0

    def clear(self):
        self._lengths = (0,)

    def advance(self, position, sequence_width):
        if any(length != position for length in self._lengths):
            raise AssertionError("test cache position differs from the supplied position")
        self._lengths = tuple(length + sequence_width for length in self._lengths)


class _CountingExecutor:
    def __init__(self):
        self.execute_calls = 0

    def new_cache(self):
        return _ZeroCache()

    def execute(self, hidden, cache, position):
        self.execute_calls += 1
        sequence_width = int(hidden.shape[-2])
        if sequence_width < 1:
            raise AssertionError("test activation has no sequence positions")
        cache.advance(position, sequence_width)
        return hidden


async def _never_revoked(_authorization):
    await asyncio.Future()


class _VirtualTime:
    """Advance the C0 policy clock while native TLS keeps using host time."""

    def __init__(self):
        self.base_wall = time.time()
        self.base_monotonic = time.monotonic()
        self.offset = 0.0

    def wall(self):
        return self.base_wall + self.offset

    def monotonic(self):
        return self.base_monotonic + self.offset

    def advance(self, seconds):
        self.offset += seconds


class _NativeTlsHarness:
    """Own a bounded real C0 mTLS server and every resource it creates."""

    def __init__(self):
        self.authority = None
        self.virtual_time = None
        self.clock = None
        self.store = None
        self.bindings = None
        self.authorizer = None
        self.executor = None
        self.handler = None
        self.bridge = None
        self.server = None
        self.coordinator_server = None
        self.coordinator_authorizer = None
        self.coordinator_service_calls = []
        self.budget = None
        self.acceptor_directory = None
        self.channels = []
        self.handler_methods = []
        self.authorization_decisions = []
        self.credential_verification_decisions = []
        self._cleanup_actions = []
        self._closed = False

    def _own(self, label, callback):
        self._cleanup_actions.append((label, callback))

    async def start(self, *, virtual_clock=False, short_peer_leaf=False,
                    listener_slots=2):
        import grpc

        from steamboat_runtime.protocol.secure_transport import (
            LocalTlsIdentity,
            NodeConnectionBudget,
            create_secure_worker_server,
        )
        from steamboat_runtime.secure_worker_runtime import SecureWorkerRuntimeBridge
        from steamboat_runtime.worker_state import WorkerHandler
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_security import (
            Authorizer,
            Clock,
            LocalIdentity,
            SessionBindings,
            SnapshotStore,
        )

        _ = grpc  # Import here so missing native runtime dependencies fail clearly.
        self.manifest = sample_manifest()
        self.model_id = self.manifest["fingerprint"]
        self.authority = SecurePipelineIdentityFixture(self.model_id)
        self._own("signed identity fixture", self.authority.close)

        if virtual_clock:
            self.virtual_time = _VirtualTime()
        if short_peer_leaf:
            if not virtual_clock:
                raise ValueError("short-lived peer fixture requires the controlled C0 clock")
            self._issue_short_lived_coordinator_leaf()

        if virtual_clock:
            self.clock = Clock(
                wall=self.virtual_time.wall,
                monotonic=self.virtual_time.monotonic,
                uncertainty_seconds=lambda: 0.0,
            )
            self.store = SnapshotStore(
                verification_key_pem=self.authority.snapshot_verification_key_pem,
                ca_certificate_pem=self.authority.cohort_ca_pem,
                clock=self.clock,
            )
            self.store.install(self.authority.signed_snapshot)
        else:
            self.store, self.clock = self.authority.new_store()

        worker = self.authority.principals["worker-1"]
        coordinator = self.authority.principals["coordinator"]
        self.worker = worker
        self.coordinator = coordinator
        self.consumer = self.authority.principals["consumer"]
        self.bindings = SessionBindings(clock=self.clock)
        self.authorizer = Authorizer(
            local_identity=LocalIdentity(
                worker.certificate_pem, worker.boot_id, self.model_id,
                worker.assignment_id),
            snapshot_store=self.store,
            clock=self.clock,
            session_bindings=self.bindings,
            worker_request_type=Request,
        )
        actual_authorize = self.authorizer.authorize

        def record_actual_c0_decision(*, service, method, payload, metadata,
                                      peer_certificate_pem):
            try:
                authorization = actual_authorize(
                    service=service, method=method, payload=payload,
                    metadata=metadata,
                    peer_certificate_pem=peer_certificate_pem)
            except BaseException as error:
                code = getattr(type(error), "code", "")
                self.authorization_decisions.append({
                    "service": service,
                    "method": method,
                    "outcome": "denied",
                    "category": type(error).__name__,
                    "code": code if type(code) is str else "",
                })
                raise
            self.authorization_decisions.append({
                "service": service,
                "method": method,
                "outcome": "allowed",
                "category": "",
                "code": "",
            })
            return authorization

        # This observer calls the real C0 Authorizer once and rethrows its
        # original decision; it is not an alternate authorization policy.
        self.authorizer.authorize = record_actual_c0_decision
        self.executor = _CountingExecutor()
        self.handler = WorkerHandler(
            self.manifest, "worker-1", self.executor,
            boot_id=worker.boot_id, enable_queue=True)
        original_handle = self.handler.handle

        async def observe_real_handler(method, request):
            self.handler_methods.append(method)
            return await original_handle(method, request)

        # This observes dispatch while preserving the actual WorkerHandler path.
        self.handler.handle = observe_real_handler
        self._own("worker handler", self._shutdown_handler)

        actual_verify_certificate = self.authorizer._verify_certificate
        from cryptography import x509

        endpoint_by_serial = {
            principal.record["serial"]: endpoint
            for principal, endpoint in (
                (self.coordinator, "coordinator_peer"),
                (self.consumer, "consumer_peer"),
                (self.worker, "worker_local"),
            )
        }

        def record_actual_credential_verification(pem, view, sample):
            try:
                serial = format(x509.load_pem_x509_certificate(pem).serial_number, "x")
            except (TypeError, ValueError):
                serial = ""
            endpoint = endpoint_by_serial.get(serial, "unknown")
            try:
                credential = actual_verify_certificate(pem, view, sample)
            except BaseException as error:
                code = getattr(type(error), "code", "")
                self.credential_verification_decisions.append({
                    "endpoint": endpoint,
                    "serial": serial,
                    "outcome": "denied",
                    "category": type(error).__name__,
                    "code": code if type(code) is str else "",
                })
                raise
            self.credential_verification_decisions.append({
                "endpoint": endpoint,
                "serial": credential.serial,
                "outcome": "allowed",
                "category": "",
                "code": "",
            })
            return credential

        # Observe the production peer/local certificate verifier while calling
        # it once and preserving its original return or exception unchanged.
        self.authorizer._verify_certificate = record_actual_credential_verification
        self.bridge = SecureWorkerRuntimeBridge(
            self.authorizer, self.handler, sweep_interval_seconds=0.25)
        self._own("runtime bridge", self._stop_bridge)
        await self.bridge.start()
        self.credential_verification_decisions.clear()

        self.acceptor_directory = self.authority.root / "negative-tls-acceptors"
        self.acceptor_directory.mkdir(mode=0o700)
        if os.name == "posix":
            os.chmod(self.acceptor_directory, 0o700)
        self._own("private acceptor directory", self._remove_acceptor_directory)

        self.budget = NodeConnectionBudget(max_connections=4, max_pending=4)
        self.server = await create_secure_worker_server(
            self.bridge.handler,
            listen_endpoint="127.0.0.1:0",
            allowed_listen_addresses=("127.0.0.1",),
            server_identity=LocalTlsIdentity(
                worker.certificate_pem, worker.private_key_pem),
            client_ca_pem=self.authority.cohort_ca_pem,
            authorizer=self.bridge.incoming_authorizer,
            authorization_watcher=self.bridge.authorization_watcher,
            connection_controller=self.budget,
            listener_id=f"c0-negative-tls-{uuid.uuid4().hex}",
            listener_slots=listener_slots,
            acceptor_directory=str(self.acceptor_directory),
        )
        self._own("native TLS worker listener", self._stop_server)
        return self

    def _issue_short_lived_coordinator_leaf(self, *, lifetime_seconds=240):
        """Replace only the client peer leaf before store/server construction."""
        from steamboat_security import (
            Clock,
            InvitationRegistry,
            create_invitation,
            enroll_invited,
            generate_private_key_pem,
            make_csr,
            snapshot_public_key_pem,
        )

        authority = self.authority
        coordinator = authority.principals["coordinator"]
        enrollment_key = (authority.root / "enrollment-authority.key.pem").read_bytes()
        snapshot_key = (authority.root / "snapshot-signing-root.key.pem").read_bytes()
        ca_key = (authority.root / "cohort-ca.key.pem").read_bytes()
        now = int(time.time()) - 2
        enrollment_clock = Clock.system(uncertainty_seconds=lambda: 0.0)
        registry = InvitationRegistry(
            verification_key_pem=snapshot_public_key_pem(enrollment_key),
            clock=enrollment_clock,
        )
        invitation = create_invitation(
            enrollment_key,
            account_id=coordinator.account_id,
            device_id=coordinator.device_id,
            roles=(coordinator.role,),
            now=now,
            lifetime_seconds=120,
        )
        private_key = generate_private_key_pem()
        authority._write_private("short-coordinator.role.key.pem", private_key)
        csr = make_csr(
            private_key,
            account_id=coordinator.account_id,
            device_id=coordinator.device_id,
            role=coordinator.role,
            ip_sans=authority.ip_sans_by_principal["coordinator"],
        )
        leaves, records = enroll_invited(
            invitation_registry=registry,
            invitation=invitation,
            csr_by_role={coordinator.role: csr},
            ca_certificate_pem=authority.cohort_ca_pem,
            ca_private_key_pem=ca_key,
            now=now,
            leaf_lifetime_seconds=lifetime_seconds,
        )
        certificate = leaves[coordinator.role]
        authority._write_public("short-coordinator.role.crt.pem", certificate)
        authority.principals["coordinator"] = replace(
            coordinator,
            private_key_pem=private_key,
            certificate_pem=certificate,
            record=records[0],
        )

        payload = json.loads(authority.signed_snapshot.decode("utf-8"))["payload"]
        credentials = [
            record for record in payload["credentials"]
            if record["serial"] != coordinator.record["serial"]
        ]
        credentials.append(records[0])
        authority._build_signed_snapshot(credentials, snapshot_key)

    async def channel(self, principal):
        import grpc

        credentials = grpc.ssl_channel_credentials(
            root_certificates=self.authority.cohort_ca_pem,
            private_key=principal.private_key_pem,
            certificate_chain=principal.certificate_pem,
        )
        channel = grpc.aio.secure_channel(
            f"127.0.0.1:{self.server.port}", credentials,
            options=(
                ("grpc.max_send_message_length", 1024 * 1024),
                ("grpc.max_receive_message_length", 1024 * 1024),
                ("grpc.enable_retries", 0),
            ),
            compression=grpc.Compression.NoCompression,
        )
        self.channels.append(channel)
        self._own(f"native TLS client channel {len(self.channels)}", channel.close)
        return channel

    async def start_coordinator_server(self, *, listener_slots=1):
        """Start the real C0 coordinator path without loading or submitting a model."""
        from steamboat_runtime.protocol.secure_transport import (
            LocalTlsIdentity)
        from steamboat_runtime.secure_coordinator_service import (
            create_secure_coordinator_server)
        from steamboat_security import Authorizer, LocalIdentity

        class ModelCoordinator:
            def submit(self, _input_ids, _new_tokens, *, forced_tokens=None,
                       trusted_request_context=None):
                raise AssertionError("negative C0 test must not submit inference")

        harness = self
        class Service:
            max_streams = 1
            active_streams = 0
            counters = {"rejected_requests": 0, "transport_stalls": 0,
                        "disconnected_streams": 0}
            coordinator = ModelCoordinator()

            async def describe_rpc(self, _data, _context):
                harness.coordinator_service_calls.append("Describe")
                return b"{}"

            async def tokenize_rpc(self, _data, _context):
                harness.coordinator_service_calls.append("Tokenize")
                return b"{}"

        principal = self.authority.principals["coordinator"]
        self.coordinator_authorizer = Authorizer(
            local_identity=LocalIdentity(principal.certificate_pem,
                                         principal.boot_id, self.model_id),
            snapshot_store=self.store, clock=self.clock)
        actual_authorize = self.coordinator_authorizer.authorize

        def observe_actual_decision(**kwargs):
            try:
                result = actual_authorize(**kwargs)
            except BaseException as error:
                code = getattr(type(error), "code", "")
                self.authorization_decisions.append({
                    "service": kwargs["service"], "method": kwargs["method"],
                    "outcome": "denied", "category": type(error).__name__,
                    "code": code if type(code) is str else ""})
                raise
            self.authorization_decisions.append({
                "service": kwargs["service"], "method": kwargs["method"],
                "outcome": "allowed", "category": "", "code": ""})
            return result

        self.coordinator_authorizer.authorize = observe_actual_decision
        root = self.authority.root / "coordinator-acceptors"
        root.mkdir(mode=0o700)
        if os.name == "posix":
            os.chmod(root, 0o700)
        self._own("coordinator acceptor directory", self._remove_coordinator_acceptor_directory)
        self.coordinator_server, secure_service = await create_secure_coordinator_server(
            Service(), listen_endpoint="127.0.0.1:0",
            allowed_listen_addresses=("127.0.0.1",),
            server_identity=LocalTlsIdentity(principal.certificate_pem,
                                             principal.private_key_pem),
            client_ca_pem=self.authority.cohort_ca_pem,
            authorizer=self.coordinator_authorizer,
            authorization_watcher=_never_revoked,
            request_context_factory=lambda _authorization, _payload: object(),
            connection_controller=self.budget,
            listener_id=f"c0-negative-coordinator-{uuid.uuid4().hex}",
            listener_slots=listener_slots, acceptor_directory=str(root),
            max_generate_streams=1)
        self._own("native TLS coordinator listener", self._stop_coordinator_server)
        self.secure_coordinator_service = secure_service
        return self.coordinator_server

    def _remove_coordinator_acceptor_directory(self):
        if self.authority is None:
            return
        path = self.authority.root / "coordinator-acceptors"
        if path.exists():
            shutil.rmtree(path)

    async def _stop_coordinator_server(self):
        if self.coordinator_server is not None:
            await self.coordinator_server.stop(0)
            self.coordinator_server = None

    async def coordinator_channel(self, principal):
        import grpc

        credentials = grpc.ssl_channel_credentials(
            root_certificates=self.authority.cohort_ca_pem,
            private_key=principal.private_key_pem,
            certificate_chain=principal.certificate_pem)
        channel = grpc.aio.secure_channel(
            f"127.0.0.1:{self.coordinator_server.port}", credentials,
            options=(("grpc.enable_retries", 0),))
        self.channels.append(channel)
        self._own(f"native TLS coordinator client channel {len(self.channels)}", channel.close)
        return channel

    def coordinator_binding_fields(self, actor, method="Describe", *, account_id=None):
        from steamboat_security.ids import new_id
        return {
            "binding_version": 1, "operation_id": new_id("op"),
            "account_id": account_id or actor.account_id,
            "device_id": actor.device_id, "role": actor.role,
            "credential_epoch": actor.record["credential_epoch"],
            "target_device_id": self.coordinator.device_id,
        }

    async def coordinator_call(self, channel, method, fields):
        from steamboat_security.codec import COORDINATOR_SERVICE, encode_binding

        rpc = channel.unary_unary(f"/{COORDINATOR_SERVICE}/{method}")
        metadata = (("steamboat-binding-bin",
                     encode_binding(COORDINATOR_SERVICE, method, fields)),)
        return await asyncio.wait_for(
            rpc(b"{}", timeout=2.0, wait_for_ready=False, metadata=metadata),
            timeout=3.0)

    def trusted_worker_context(self, request_id=None):
        """Build a worker context from a genuine, immutable C0 Generate authorization."""
        from steamboat_runtime.secure_context import ConsumerContextFactory
        from steamboat_security import Authorizer, LocalIdentity
        from steamboat_security.codec import COORDINATOR_SERVICE, encode_binding
        from steamboat_security.ids import new_id

        store, clock = self.authority.new_store()
        principal = self.authority.principals["coordinator"]
        core = Authorizer(
            local_identity=LocalIdentity(principal.certificate_pem,
                                         principal.boot_id, self.model_id),
            snapshot_store=store, clock=clock)
        request_id = request_id or new_id("req")
        fields = self.coordinator_binding_fields(self.consumer, "Generate")
        fields["request_id"] = request_id
        payload = {"input_ids": [1], "new_tokens": 1, "timeout_seconds": 60,
                   "capture_logits": False}
        metadata = (("steamboat-binding-bin", encode_binding(
            COORDINATOR_SERVICE, "Generate", fields)),)
        authorization = core.authorize(
            service=COORDINATOR_SERVICE, method="Generate", payload=payload,
            metadata=metadata, peer_certificate_pem=self.consumer.certificate_pem)
        factory = ConsumerContextFactory(
            account_id=self.coordinator.account_id, device_id=self.coordinator.device_id,
            coordinator_boot_id=principal.boot_id, model_id=self.model_id)
        context = factory(authorization, payload)
        return context, factory, authorization

    async def public_worker_client(self):
        """Create one pinned public SecureWorkerClient with real outbound C0 policy."""
        from steamboat_runtime.protocol.secure_transport import (
            C0ExpectedServerLeafAdapter, ExpectedServerIdentity, FixedPeer,
            LocalTlsIdentity, create_secure_worker_client)
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_security import (
            LocalIdentity, OutboundAuthorizer, verify_expected_server_leaf,
        )
        from steamboat_security.codec import WORKER_SERVICE
        from steamboat_security.outbound import OutboundTarget
        from steamboat_runtime.participant_context import TrustedRequestContext

        store, clock = self.authority.new_store()
        coordinator = self.authority.principals["coordinator"]
        worker = self.worker
        target = OutboundTarget.from_record(
            service=WORKER_SERVICE, record=worker.record, boot_id=worker.boot_id,
            model_id=self.model_id, assignment_id=worker.assignment_id)
        outbound = OutboundAuthorizer(
            local_identity=LocalIdentity(coordinator.certificate_pem,
                                         coordinator.boot_id, self.model_id),
            snapshot_store=store, clock=clock, target=target,
            worker_request_type=Request,
            trusted_request_context_type=TrustedRequestContext)
        expected = ExpectedServerIdentity(
            account_id=worker.account_id, device_id=worker.device_id,
            role="host", serial=int(worker.record["serial"], 16),
            public_key_hash=worker.record["public_key_sha256"],
            certificate_hash=worker.record["certificate_sha256"],
            expected_ip="127.0.0.1")

        peer = FixedPeer(
            endpoint=f"127.0.0.1:{self.server.port}",
            allowed_addresses=("127.0.0.1",), device_id=worker.device_id,
            server_leaf_pem=worker.certificate_pem,
            cohort_ca_pem=self.authority.cohort_ca_pem,
            expected_server=expected)
        client = await create_secure_worker_client(
            peer, local_identity=LocalTlsIdentity(
                coordinator.certificate_pem, coordinator.private_key_pem),
            outbound_authorizer=outbound,
            authorization_watcher=_never_revoked,
            verify_expected_server_leaf=C0ExpectedServerLeafAdapter(
                verify_expected_server_leaf),
            connection_controller=self.budget)
        return client, outbound, store

    async def call(self, channel, method, request, fields):
        from steamboat_runtime.protocol.secure_transport import WORKER_SERVICE
        from steamboat_runtime.protocol.worker_pb2 import Response
        from steamboat_security.codec import encode_binding

        from steamboat_runtime.protocol.worker_pb2 import Request

        if type(request) is not Request:
            raise TypeError("test RPC must use the generated worker Request")
        rpc = channel.unary_unary(
            f"/{WORKER_SERVICE}/{method}",
            request_serializer=Request.SerializeToString,
            response_deserializer=Response.FromString,
        )
        metadata = (("steamboat-binding-bin",
                     encode_binding(WORKER_SERVICE, method, fields)),)
        return await asyncio.wait_for(
            rpc(request, timeout=2.0, wait_for_ready=False, metadata=metadata),
            timeout=3.0,
        )

    async def wait_channel_ready(self, channel):
        await asyncio.wait_for(channel.channel_ready(), timeout=3.0)

    def binding_fields(self, actor, method, *, session_id=None,
                       request_id=None, route_id=None, account_id=None):
        from steamboat_security.ids import new_id

        record = actor.record
        fields = {
            "binding_version": 1,
            "operation_id": new_id("op"),
            "account_id": account_id or actor.account_id,
            "device_id": actor.device_id,
            "role": actor.role,
            "credential_epoch": record["credential_epoch"],
            "target_device_id": self.worker.device_id,
        }
        if method != "Describe":
            fields.update({
                "coordinator_boot_id": self.coordinator.boot_id,
                "tenant_account_id": self.coordinator.account_id,
                "request_id": request_id or new_id("req"),
                "session_id": session_id or new_id("ses"),
                "route_id": route_id or new_id("route"),
                "route_epoch": 1,
                "attempt": 1,
                "assignment_id": self.worker.assignment_id,
                "worker_boot_id": self.worker.boot_id,
            })
        return fields

    def describe_request(self):
        from steamboat_runtime.protocol.worker_pb2 import Request

        return Request(
            protocol_version=1,
            manifest_fingerprint=self.model_id,
            worker_boot_id=self.worker.boot_id,
            timeout_ms=1500,
        )

    def open_request(self, session_id):
        from steamboat_runtime.protocol.worker_pb2 import Request

        return Request(
            protocol_version=1,
            manifest_fingerprint=self.model_id,
            worker_boot_id=self.worker.boot_id,
            session_id=session_id,
            timeout_ms=3000,
            max_positions=16,
            lifetime_ms=120_000,
            idle_lease_ms=30_000,
        )

    def session_request(self, session_id, lease, *, step=False):
        from steamboat_runtime.protocol.worker_pb2 import Request

        request = Request(
            protocol_version=1,
            manifest_fingerprint=self.model_id,
            worker_boot_id=self.worker.boot_id,
            session_id=session_id,
            lease_token=lease,
            timeout_ms=3000,
        )
        if step:
            hidden_size = self.manifest["config"]["hidden_size"]
            request.sequence = 0
            request.start_position = 0
            request.token_count = 1
            request.tensor.shape.extend((1, 1, hidden_size))
            request.tensor.dtype = "float32_le"
            request.tensor.layout = "batch_sequence_hidden"
            request.tensor.byte_count = hidden_size * 4
            request.tensor.data = bytes(hidden_size * 4)
        return request

    async def _stop_server(self):
        if self.server is not None:
            server, self.server = self.server, None
            await server.stop(0)

    async def _stop_bridge(self):
        bridge = self.bridge
        if bridge is not None and bridge._started and not bridge._closed:
            result = await bridge.stop(grace_seconds=5)
            if result is not True:
                raise RuntimeError("C0 runtime bridge did not confirm shutdown")

    async def _shutdown_handler(self):
        if self.handler is not None:
            result = await self.handler.shutdown(grace_seconds=5)
            if result is not True:
                raise RuntimeError("non-model WorkerHandler did not confirm shutdown")

    def _remove_acceptor_directory(self):
        if self.acceptor_directory is not None and self.acceptor_directory.exists():
            shutil.rmtree(self.acceptor_directory)

    async def aclose(self):
        if self._closed:
            return
        self._closed = True
        failures = []
        for label, callback in reversed(self._cleanup_actions):
            try:
                result = callback()
                if asyncio.iscoroutine(result):
                    await result
            except BaseException as error:
                try:
                    error.add_note(f"negative TLS cleanup: {label}")
                except (AttributeError, TypeError):
                    pass
                failures.append(error)
        self._cleanup_actions.clear()
        if self.budget is not None and (
                self.budget.reserved_connections != 0
                or self.budget.reserved_pending != 0
                or self.budget.reserved_listener_pending_capacity != 0):
            failures.append(RuntimeError("native TLS connection budget was not fully released"))
        if failures:
            raise BaseExceptionGroup("native C0 TLS fixture cleanup failed", failures)

    async def advance_to_expired_credentials(self):
        """Refresh signed policy after both actual endpoint leaves expire."""
        from steamboat_security import sign_snapshot

        if self.virtual_time is None:
            raise RuntimeError("virtual time was not configured")
        signing_key = (self.authority.root / "snapshot-signing-root.key.pem").read_bytes()
        original = json.loads(self.authority.signed_snapshot.decode("utf-8"))["payload"]
        expire_after = max(
            self.coordinator.record["not_after"],
            self.worker.record["not_after"],
        ) + 2
        while self.virtual_time.wall() <= expire_after:
            self.virtual_time.advance(min(20.0, expire_after + 1 - self.virtual_time.wall()))
            self.clock.sample()
            current_view = self.store.current()
            if current_view.expires_at - self.virtual_time.wall() <= 60:
                payload = deepcopy(original)
                payload["revision"] = current_view.revision + 1
                issued_at = int(self.virtual_time.wall())
                payload["issued_at"] = issued_at
                payload["expires_at"] = issued_at + 300
                for grant in payload["grants"]:
                    grant["not_before"] = issued_at
                    grant["not_after"] = issued_at + 300
                self.store.install(sign_snapshot(payload, signing_key))
        current = self.store.current()
        if current.expires_at <= self.virtual_time.wall():
            raise AssertionError("expired-credential fixture lost its current signed policy")

    def advance_past_coordinator_expiry(self):
        if self.virtual_time is None:
            raise RuntimeError("peer-expiry fixture requires its controlled C0 clock")
        target_wall = float(self.coordinator.record["not_after"] + 1)
        delta = target_wall - self.virtual_time.wall()
        if delta <= 0:
            raise AssertionError("coordinator peer leaf expired before the valid RPC control")
        self.virtual_time.advance(delta)
        sample = self.clock.sample()
        if sample.latest_wall <= self.coordinator.record["not_after"]:
            raise AssertionError("controlled C0 clock did not pass peer certificate expiry")
        return sample


@unittest.skipUnless(
    os.name == "posix",
    "the secure worker acceptor requires an owner-checked POSIX UDS directory",
)
class SecureC0NegativeTlsTests(unittest.IsolatedAsyncioTestCase):
    async def _harness(self, *, virtual_clock=False, short_peer_leaf=False,
                       listener_slots=2):
        harness = _NativeTlsHarness()
        try:
            await harness.start(
                virtual_clock=virtual_clock, short_peer_leaf=short_peer_leaf,
                listener_slots=listener_slots)
        except BaseException as primary:
            try:
                await harness.aclose()
            except BaseException as cleanup:
                raise BaseExceptionGroup(
                    "native C0 TLS setup and cleanup failed", [primary, cleanup])
            raise
        self.addAsyncCleanup(harness.aclose)
        return harness

    async def _assert_rejected(self, harness, channel, method, request, fields,
                               expected_status, expected_c0_category,
                               expected_c0_code):
        import grpc

        decision_count = len(harness.authorization_decisions)
        handler_count = len(harness.handler_methods)
        compute_count = harness.executor.execute_calls
        observed_status = None
        try:
            await harness.call(channel, method, request, fields)
        except grpc.aio.AioRpcError as error:
            observed_status = error.code()
        else:
            self.fail(f"unauthorized native TLS {method} unexpectedly reached a response")
        self.assertEqual(len(harness.authorization_decisions), decision_count + 1,
                         "the real C0 Authorizer callback did not decide this RPC exactly once")
        decision = harness.authorization_decisions[-1]
        from steamboat_runtime.protocol.secure_transport import WORKER_SERVICE

        self.assertEqual(decision["service"], WORKER_SERVICE)
        self.assertEqual(decision["method"], method)
        self.assertEqual(decision["outcome"], "denied")
        self.assertEqual(decision["category"], expected_c0_category)
        self.assertEqual(decision["code"], expected_c0_code)
        self.assertEqual(len(harness.handler_methods), handler_count,
                         "rejected RPC crossed the WorkerHandler dispatch boundary")
        self.assertEqual(harness.executor.execute_calls, compute_count,
                         "rejected RPC reached the test executor")
        self.assertEqual(observed_status, expected_status,
                         "native TLS transport status differs from the pinned rejection path")

    async def test_wrong_role_account_stolen_binding_and_lease_are_pre_handler(self):
        import grpc

        from steamboat_runtime.protocol.secure_transport import WORKER_SERVICE
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_security.ids import new_id

        harness = await self._harness()
        coordinator_channel = await harness.channel(harness.coordinator)
        consumer_channel = await harness.channel(harness.consumer)

        # Prove both native TLS channels complete their handshake. The valid
        # coordinator RPC then proves the actual listener/C0 path before the
        # first unauthenticated-role call can retire its stream.
        await harness.wait_channel_ready(coordinator_channel)
        await harness.wait_channel_ready(consumer_channel)
        sentinel = await harness.call(
            coordinator_channel, "Describe", harness.describe_request(),
            harness.binding_fields(harness.coordinator, "Describe"))
        self.assertEqual(sentinel.code, "OK")
        self.assertEqual(harness.authorization_decisions[-1]["service"], WORKER_SERVICE)
        self.assertEqual(harness.authorization_decisions[-1]["outcome"], "allowed")
        self.assertEqual(harness.authorization_decisions[-1]["method"], "Describe")
        self.assertEqual(harness.handler_methods, ["Describe"])

        # The consumer's certificate and binding agree, but that role has no
        # worker-service authority. This first RPC on its TLS-valid channel must
        # preserve C0's native PERMISSION_DENIED status for the scope failure.
        consumer_describe = harness.binding_fields(harness.consumer, "Describe")
        await self._assert_rejected(
            harness, consumer_channel, "Describe", harness.describe_request(),
            consumer_describe, grpc.StatusCode.PERMISSION_DENIED,
            "ScopeError", "PERMISSION_DENIED")
        self.assertEqual(harness.handler_methods, ["Describe"])

        # The TLS peer is the real coordinator, but its signed actor account is
        # intentionally replaced in the canonical binding.
        wrong_account = harness.binding_fields(
            harness.coordinator, "Describe", account_id=new_id("acct"))
        await self._assert_rejected(
            harness, coordinator_channel, "Describe", harness.describe_request(),
            wrong_account, grpc.StatusCode.UNAUTHENTICATED,
            "CredentialError", "UNAUTHENTICATED")
        self.assertEqual(harness.handler_methods, ["Describe"])
        self.assertEqual(harness.executor.execute_calls, 0)

        # The prior stream was intentionally retired. Wait for a fresh native
        # TLS connection, then send one new operation with a fresh operation ID.
        await harness.wait_channel_ready(consumer_channel)

        # Valid C0 OpenSession is the positive sentinel and creates a real
        # SessionBindings owner plus the WorkerHandler's zero-sized test cache.
        session_id = new_id("ses")
        open_fields = harness.binding_fields(
            harness.coordinator, "OpenSession", session_id=session_id)
        opened = await harness.call(
            coordinator_channel, "OpenSession", harness.open_request(session_id),
            open_fields)
        self.assertEqual(opened.code, "OK")
        self.assertEqual(opened.session_id, session_id)
        self.assertTrue(opened.lease_token)
        self.assertEqual(harness.authorization_decisions[-1]["service"], WORKER_SERVICE)
        self.assertEqual(harness.authorization_decisions[-1]["method"], "OpenSession")
        self.assertEqual(harness.authorization_decisions[-1]["outcome"], "allowed")
        self.assertEqual(harness.handler_methods, ["Describe", "OpenSession"])

        # A copied owner binding sent under a different enrolled TLS identity
        # must not transfer the session to that identity.
        stolen_binding = dict(open_fields)
        stolen_binding["operation_id"] = new_id("op")
        status_request = harness.session_request(session_id, opened.lease_token)
        await self._assert_rejected(
            harness, consumer_channel, "SessionStatus", status_request,
            stolen_binding, grpc.StatusCode.UNAUTHENTICATED,
            "CredentialError", "UNAUTHENTICATED")
        self.assertEqual(harness.handler_methods, ["Describe", "OpenSession"])

        # Correct TLS identity and owner fields with a stolen lease are rejected
        # by the actual SessionBindings check before WorkerHandler can inspect
        # or decode this otherwise well-formed Step tensor.
        bad_lease_fields = dict(open_fields)
        bad_lease_fields["operation_id"] = new_id("op")
        step_request = harness.session_request(session_id, "stolen-lease", step=True)
        await self._assert_rejected(
            harness, coordinator_channel, "Step", step_request,
            bad_lease_fields, grpc.StatusCode.PERMISSION_DENIED,
            "SessionError", "PERMISSION_DENIED")
        self.assertEqual(harness.handler_methods, ["Describe", "OpenSession"])
        self.assertEqual(harness.executor.execute_calls, 0)
        self.assertEqual(tuple(harness.handler.sessions), (session_id,))

        # The real owner can still use its actual lease and reclaim the cache.
        cancel_fields = dict(open_fields)
        cancel_fields["operation_id"] = new_id("op")
        cancelled = await harness.call(
            coordinator_channel, "CancelSession",
            harness.session_request(session_id, opened.lease_token), cancel_fields)
        self.assertEqual(cancelled.code, "OK")
        self.assertTrue(cancelled.reclaimed)
        self.assertEqual(harness.authorization_decisions[-1]["method"], "CancelSession")
        self.assertEqual(harness.authorization_decisions[-1]["outcome"], "allowed")
        self.assertEqual(harness.handler.sessions, {})
        self.assertEqual(harness.bridge.status()["owned_sessions"], 0)
        self.assertEqual(harness.executor.execute_calls, 0)

        # Establish a successful RPC on this same native TLS channel, then
        # revoke its peer in a new signed snapshot.  The connection remains a
        # valid TLS socket, while C0 must reject its next RPC on policy liveness.
        describe_fields = harness.binding_fields(harness.coordinator, "Describe")
        described = await harness.call(
            coordinator_channel, "Describe", harness.describe_request(),
            describe_fields)
        self.assertEqual(described.code, "OK")
        self.assertEqual(harness.authorization_decisions[-1]["outcome"], "allowed")
        handler_call_count = len(harness.handler_methods)
        self._install_revoking_snapshot(harness)
        await self._assert_rejected(
            harness, coordinator_channel, "Describe", harness.describe_request(),
            harness.binding_fields(harness.coordinator, "Describe"),
            grpc.StatusCode.UNAUTHENTICATED,
            "CredentialError", "UNAUTHENTICATED")
        self.assertEqual(len(harness.handler_methods), handler_call_count)
        self.assertEqual(harness.executor.execute_calls, 0)
        self.assertEqual(harness.handler.sessions, {})
        self.assertEqual(harness.budget.reserved_connections, 2)

    def _install_revoking_snapshot(self, harness, principal=None, *, revoke_device=False):
        from steamboat_security import sign_snapshot

        signer = (harness.authority.root / "snapshot-signing-root.key.pem").read_bytes()
        payload = json.loads(harness.authority.signed_snapshot.decode("utf-8"))["payload"]
        target = harness.coordinator if principal is None else principal
        serial = target.record["serial"]
        device_id = target.device_id
        payload["revision"] += 1
        issued_at = int(time.time())
        payload["issued_at"] = max(payload["issued_at"], issued_at)
        payload["expires_at"] = payload["issued_at"] + 300
        if revoke_device:
            device_serials = {
                record["serial"] for record in payload["credentials"]
                if record["device_id"] == device_id}
            payload["revoked_devices"] = sorted(
                set(payload["revoked_devices"]) | {device_id})
            payload["revoked_serials"] = sorted(
                set(payload["revoked_serials"]) | device_serials)
            payload["credentials"] = [
                record for record in payload["credentials"]
                if record["device_id"] != device_id]
            payload["grants"] = [
                grant for grant in payload["grants"]
                if grant["device_id"] != device_id
                and grant["target_device_id"] != device_id]
        else:
            payload["revoked_serials"] = sorted(
                set(payload["revoked_serials"]) | {serial})
            payload["credentials"] = [
                record for record in payload["credentials"]
                if record["serial"] != serial]
            payload["grants"] = [
                grant for grant in payload["grants"]
                if grant["actor_serial"] != serial
                and grant["target_serial"] != serial]
        harness.store.install(sign_snapshot(payload, signer))
        return device_id, device_serials if revoke_device else {serial}

    async def test_expired_peer_leaf_is_rejected_while_worker_policy_stays_live(self):
        import grpc

        from steamboat_runtime.protocol.secure_transport import WORKER_SERVICE

        harness = await self._harness(virtual_clock=True, short_peer_leaf=True)
        tls_host_time_before = time.time()
        coordinator_channel = await harness.channel(harness.coordinator)
        await harness.wait_channel_ready(coordinator_channel)
        response = await harness.call(
            coordinator_channel, "Describe", harness.describe_request(),
            harness.binding_fields(harness.coordinator, "Describe"))
        self.assertEqual(response.code, "OK")
        self.assertEqual(harness.handler_methods, ["Describe"])
        self.assertEqual(
            [(event["endpoint"], event["outcome"])
             for event in harness.credential_verification_decisions],
            [("coordinator_peer", "allowed"), ("worker_local", "allowed")],
        )
        peer_expiry = harness.coordinator.record["not_after"]
        from cryptography import x509

        peer_certificate = x509.load_pem_x509_certificate(
            harness.coordinator.certificate_pem)
        self.assertEqual(
            int(peer_certificate.not_valid_after_utc.timestamp()), peer_expiry)
        self.assertLess(tls_host_time_before, peer_expiry)
        self.assertLess(time.time(), peer_expiry)
        self.assertEqual(
            harness.coordinator.record["not_after"]
            - harness.coordinator.record["not_before"],
            240,
        )
        self.assertGreater(harness.worker.record["not_after"], peer_expiry)

        # Advance only the C0 policy clock. The live native TLS channel and the
        # host wall clock remain unchanged, while all non-peer policy bounds
        # stay live beyond the peer's actual issued certificate expiry.
        sample = harness.advance_past_coordinator_expiry()
        view = harness.store.current(sample=sample)
        self.assertLessEqual(peer_expiry, sample.latest_wall)
        self.assertGreater(harness.worker.record["not_after"], sample.latest_wall)
        self.assertGreater(view.expires_at, sample.latest_wall)
        self.assertGreater(view.deadline_monotonic, sample.monotonic)
        self.assertEqual(
            view.credentials_by_serial[harness.coordinator.record["serial"]].not_after,
            peer_expiry,
        )
        active_describe_grants = [
            grant for grant in view.active_grants(sample)
            if grant.actor_serial == harness.coordinator.record["serial"]
            and grant.target_serial == harness.worker.record["serial"]
            and grant.method == f"{WORKER_SERVICE}/Describe"
        ]
        self.assertEqual(len(active_describe_grants), 1)
        self.assertGreater(active_describe_grants[0].not_after, sample.latest_wall)

        from steamboat_security import CredentialError, verify_ca, verify_leaf

        verify_ca(
            harness.authority.cohort_ca_pem,
            now=sample.wall,
            uncertainty_seconds=sample.uncertainty,
        )
        with self.assertRaises(CredentialError):
            verify_leaf(
                harness.authority.cohort_ca_pem,
                harness.coordinator.certificate_pem,
                now=sample.wall,
                uncertainty_seconds=sample.uncertainty,
                account_id=harness.coordinator.account_id,
                device_id=harness.coordinator.device_id,
                role=harness.coordinator.role,
                serial=harness.coordinator.record["serial"],
                public_key_hash=harness.coordinator.record["public_key_sha256"],
                certificate_hash=harness.coordinator.record["certificate_sha256"],
                ekus=tuple(harness.coordinator.record["ekus"]),
                dns_sans=tuple(harness.coordinator.record["dns_sans"]),
                ip_sans=tuple(harness.coordinator.record["ip_sans"]),
            )
        self.assertLess(time.time(), peer_expiry)
        verification_start = len(harness.credential_verification_decisions)
        handler_count = len(harness.handler_methods)
        # Exercise the C0 expiry on a fresh TLS-valid connection. TLS readiness
        # proves the synthetic leaf is still valid under host time; this is its
        # first application RPC and must carry the native C0 denial.
        await coordinator_channel.close()
        expired_first_rpc_channel = await harness.channel(harness.coordinator)
        await harness.wait_channel_ready(expired_first_rpc_channel)
        await self._assert_rejected(
            harness, expired_first_rpc_channel, "Describe", harness.describe_request(),
            harness.binding_fields(harness.coordinator, "Describe"),
            grpc.StatusCode.UNAUTHENTICATED,
            "CredentialError", "UNAUTHENTICATED")
        self.assertEqual(
            harness.credential_verification_decisions[verification_start:],
            [{
                "endpoint": "coordinator_peer",
                "serial": harness.coordinator.record["serial"],
                "outcome": "denied",
                "category": "CredentialError",
                "code": "UNAUTHENTICATED",
            }],
            "the real peer certificate verifier did not cause the C0 denial",
        )
        self.assertEqual(len(harness.handler_methods), handler_count)
        self.assertEqual(harness.executor.execute_calls, 0)

        # Independently verify the actual local worker leaf through the same
        # production C0 verifier at the expired-peer sample. This proves the
        # rejection was isolated to the peer certificate, not the local leaf.
        current_view, current_sample = harness.authorizer._current_view()
        worker_identity = harness.authorizer._verify_certificate(
            harness.worker.certificate_pem, current_view, current_sample)
        self.assertEqual(worker_identity.serial, harness.worker.record["serial"])
        self.assertEqual(worker_identity.role, "host")
        self.assertGreater(harness.worker.record["not_after"], current_sample.latest_wall)
        self.assertEqual(
            harness.credential_verification_decisions[-1],
            {
                "endpoint": "worker_local",
                "serial": harness.worker.record["serial"],
                "outcome": "allowed",
                "category": "",
                "code": "",
            },
        )
        self.assertEqual(harness.handler.sessions, {})

    async def test_first_worker_actor_credential_failure_is_native_unauthenticated(self):
        import grpc

        from steamboat_security.ids import new_id

        harness = await self._harness()
        channel = await harness.channel(harness.coordinator)
        await harness.wait_channel_ready(channel)
        bad_fields = harness.binding_fields(
            harness.coordinator, "Describe", account_id=new_id("acct"))
        await self._assert_rejected(
            harness, channel, "Describe", harness.describe_request(), bad_fields,
            grpc.StatusCode.UNAUTHENTICATED,
            "CredentialError", "UNAUTHENTICATED")
        self.assertEqual(harness.handler_methods, [])
        self.assertEqual(harness.executor.execute_calls, 0)
        self.assertEqual(harness.handler.sessions, {})
        self.assertEqual(harness.bridge.status()["owned_sessions"], 0)

    async def test_rejected_channel_cannot_open_session_and_reclaims_provisional_c0_claim(self):
        import grpc

        from steamboat_security.ids import new_id
        harness = await self._harness()
        channel = await harness.channel(harness.coordinator)
        await harness.wait_channel_ready(channel)
        acceptor = harness.server._acceptor
        await self._wait_for_native_connection(acceptor)
        connection = next(iter(acceptor._connections))
        await self._assert_rejected(
            harness, channel, "Describe", harness.describe_request(),
            harness.binding_fields(harness.coordinator, "Describe",
                                   account_id=new_id("acct")),
            grpc.StatusCode.UNAUTHENTICATED,
            "CredentialError", "UNAUTHENTICATED")

        session_id = new_id("ses")
        fields = harness.binding_fields(
            harness.coordinator, "OpenSession", session_id=session_id)
        native_status = None
        try:
            await harness.call(
                channel, "OpenSession", harness.open_request(session_id), fields)
        except grpc.aio.AioRpcError as error:
            native_status = error.code()
        self.assertEqual(native_status, grpc.StatusCode.UNAUTHENTICATED)
        self.assertEqual(harness.authorization_decisions[-1]["outcome"], "allowed",
                         "C0 must reach the real provisional claim before acceptor latch refusal")
        self.assertEqual(harness.handler_methods, [])
        self.assertEqual(harness.executor.execute_calls, 0)
        self.assertEqual(harness.handler.sessions, {})
        key = (harness.worker.device_id, harness.worker.boot_id, session_id)
        self.assertNotIn(key, harness.bindings._records,
                         "the failed authenticated-state transition must reclaim its provisional C0 claim")
        self.assertTrue(connection.rejecting)
        self.assertFalse(connection.retired)
        self.assertEqual(harness.budget.reserved_pending, 1)
        self.assertEqual(harness.server._acceptor._active, 1)
        await channel.close()
        self.assertTrue(await acceptor.wait_for_idle(1))
        self.assertEqual(harness.budget.reserved_pending, 0)
        self.assertEqual(acceptor._active, 0)

    async def test_draining_worker_fresh_open_is_native_unauthenticated_before_c0(self):
        import grpc

        from steamboat_security.ids import new_id

        harness = await self._harness(listener_slots=1)
        deadline = harness.bridge.begin_drain(30)
        self.assertEqual(harness.bridge.begin_drain(10), deadline,
                         "a repeated drain request must preserve the original deadline")
        self.assertGreater(deadline, harness.clock.sample().monotonic)

        channel = await harness.channel(harness.coordinator)
        await harness.wait_channel_ready(channel)
        acceptor = harness.server._acceptor
        await self._wait_for_native_connection(acceptor)
        connection = next(iter(acceptor._connections))
        original_deadline = connection.pending_deadline
        self.assertEqual(harness.budget.reserved_pending, 1)
        self.assertEqual(acceptor._active, 1)

        session_id = new_id("ses")
        request = harness.open_request(session_id)
        fields = harness.binding_fields(
            harness.coordinator, "OpenSession", session_id=session_id)
        decision_count = len(harness.authorization_decisions)
        verification_count = len(harness.credential_verification_decisions)
        handler_count = len(harness.handler_methods)
        compute_count = harness.executor.execute_calls
        with self.assertRaises(grpc.aio.AioRpcError) as raised:
            await harness.call(channel, "OpenSession", request, fields)

        self.assertEqual(raised.exception.code(), grpc.StatusCode.UNAUTHENTICATED)
        self.assertEqual(len(harness.authorization_decisions), decision_count,
                         "drain admission must reject before the C0 authorizer")
        self.assertEqual(len(harness.credential_verification_decisions), verification_count,
                         "drain admission must not verify/claim a C0 credential")
        self.assertEqual(len(harness.handler_methods), handler_count,
                         "drain-rejected OpenSession crossed handler dispatch")
        self.assertEqual(harness.executor.execute_calls, compute_count,
                         "drain-rejected OpenSession reached compute")
        key = (harness.worker.device_id, harness.worker.boot_id, session_id)
        self.assertNotIn(key, harness.bindings._records)
        self.assertEqual(harness.bridge._operations, {})
        self.assertEqual(harness.bridge._admitting, 0)
        self.assertTrue(connection.rejecting)
        self.assertFalse(connection.retired)
        self.assertEqual(connection.pending_deadline, original_deadline)
        self.assertEqual(acceptor._active, 1,
                         "native rejection must retain the open channel's listener slot")
        self.assertEqual(harness.budget.reserved_pending, 1,
                         "native rejection must retain pending capacity until channel close")

        await channel.close()
        self.assertTrue(await acceptor.wait_for_idle(1))
        self.assertTrue(connection.retired)
        self.assertEqual(acceptor._active, 0)
        self.assertEqual(harness.budget.reserved_pending, 0)
        self.assertEqual(connection.remote.fileno(), -1)
        self.assertEqual(connection.backend.fileno(), -1)

    async def _wait_for_native_connection(self, acceptor):
        deadline = asyncio.get_running_loop().time() + 1
        while not acceptor._connections:
            if asyncio.get_running_loop().time() >= deadline:
                self.fail("TLS-ready channel did not acquire its native acceptor slot")
            await asyncio.sleep(0.001)

    async def test_first_coordinator_actor_account_failure_is_real_c0_native_unauthenticated(self):
        import grpc

        from steamboat_security.codec import COORDINATOR_SERVICE
        from steamboat_security.ids import new_id

        harness = await self._harness()
        await harness.start_coordinator_server(listener_slots=1)
        channel = await harness.coordinator_channel(harness.consumer)
        await harness.wait_channel_ready(channel)
        acceptor = harness.secure_coordinator_service.acceptor
        connection = next(iter(acceptor._connections))
        bad_fields = harness.coordinator_binding_fields(
            harness.consumer, account_id=new_id("acct"))
        observed = None
        try:
            await harness.coordinator_call(channel, "Describe", bad_fields)
        except grpc.aio.AioRpcError as error:
            observed = error.code()
        self.assertEqual(observed, grpc.StatusCode.UNAUTHENTICATED)
        decision = harness.authorization_decisions[-1]
        self.assertEqual(decision["service"], COORDINATOR_SERVICE)
        self.assertEqual(decision["method"], "Describe")
        self.assertEqual((decision["outcome"], decision["category"], decision["code"]),
                         ("denied", "CredentialError", "UNAUTHENTICATED"))
        self.assertEqual(harness.coordinator_service_calls, [])
        self.assertEqual(harness.coordinator_authorizer._operation_ids, {})
        self.assertEqual(acceptor._active, 1,
                         "first-RPC rejection must retain its slot while the channel is open")
        self.assertEqual(harness.budget.reserved_pending, 1,
                         "first-RPC rejection must retain its pending reservation")
        await channel.close()
        self.assertTrue(await acceptor.wait_for_idle(1))
        self.assertTrue(connection.retired)
        self.assertEqual(connection.remote.fileno(), -1)
        self.assertEqual(connection.backend.fileno(), -1)
        self.assertEqual(harness.budget.reserved_pending, 0)

    async def test_rejected_coordinator_channel_stays_charged_until_original_deadline(self):
        import grpc

        from steamboat_security.ids import new_id

        harness = await self._harness()
        server = await harness.start_coordinator_server(listener_slots=1)
        channel = await harness.coordinator_channel(harness.consumer)
        await harness.wait_channel_ready(channel)
        acceptor = harness.secure_coordinator_service.acceptor
        deadline_wait = asyncio.get_running_loop().time() + 1
        while not acceptor._connections:
            if asyncio.get_running_loop().time() >= deadline_wait:
                self.fail("TLS-ready connection did not acquire its listener slot")
            await asyncio.sleep(0.001)
        connection = next(iter(acceptor._connections))
        original_deadline = connection.pending_deadline
        self.assertEqual(acceptor._active, 1)
        self.assertEqual(harness.budget.reserved_pending, 1)

        bad_fields = harness.coordinator_binding_fields(
            harness.consumer, account_id=new_id("acct"))
        with self.assertRaises(grpc.aio.AioRpcError) as raised:
            await harness.coordinator_call(channel, "Describe", bad_fields)
        self.assertEqual(raised.exception.code(), grpc.StatusCode.UNAUTHENTICATED)
        self.assertTrue(connection.rejecting)
        self.assertFalse(connection.established)
        self.assertEqual(connection.pending_deadline, original_deadline)

        # A second raw TCP peer cannot consume the sole listener slot while the
        # rejected gRPC channel continues to own its pending connection.
        extra = await asyncio.to_thread(
            socket.create_connection, ("127.0.0.1", server.port), 1)
        try:
            extra.settimeout(1)
            peer_bytes = await asyncio.to_thread(extra.recv, 1)
            self.assertEqual(peer_bytes, b"")
        finally:
            await asyncio.to_thread(extra.close)
        self.assertEqual(acceptor._active, 1)
        self.assertEqual(harness.budget.reserved_pending, 1)

        remaining = original_deadline - time.monotonic()
        self.assertGreater(remaining, 0.5,
                           "rejected connection must retain its original admission window")
        await asyncio.sleep(remaining - 0.2)
        self.assertFalse(connection.retired)
        self.assertEqual(connection.pending_deadline, original_deadline)
        self.assertEqual(acceptor._active, 1)
        self.assertEqual(harness.budget.reserved_pending, 1)
        self.assertTrue(await acceptor.wait_for_idle(1))
        self.assertTrue(connection.retired)
        self.assertEqual(acceptor._active, 0)
        self.assertEqual(harness.budget.reserved_pending, 0)
        self.assertEqual(connection.remote.fileno(), -1)
        self.assertEqual(connection.backend.fileno(), -1)

    async def test_server_shutdown_retires_native_rejected_connection(self):
        import grpc

        from steamboat_security.ids import new_id

        harness = await self._harness()
        await harness.start_coordinator_server(listener_slots=1)
        channel = await harness.coordinator_channel(harness.consumer)
        await harness.wait_channel_ready(channel)
        acceptor = harness.secure_coordinator_service.acceptor
        bad_fields = harness.coordinator_binding_fields(
            harness.consumer, account_id=new_id("acct"))
        with self.assertRaises(grpc.aio.AioRpcError) as raised:
            await harness.coordinator_call(channel, "Describe", bad_fields)
        self.assertEqual(raised.exception.code(), grpc.StatusCode.UNAUTHENTICATED)
        connection = next(iter(acceptor._connections))
        self.assertTrue(connection.rejecting)
        self.assertEqual(harness.budget.reserved_pending, 1)
        await harness._stop_coordinator_server()
        self.assertTrue(connection.retired)
        self.assertEqual(acceptor._active, 0)
        self.assertEqual(harness.budget.reserved_pending, 0)
        self.assertEqual(connection.remote.fileno(), -1)
        self.assertEqual(connection.backend.fileno(), -1)
        await channel.close()

    async def test_one_slot_remove_status_then_fresh_open_are_native_denials(self):
        """Use serial public clients and the real C0 worker policy for Remove probes."""
        import grpc
        from unittest.mock import patch

        from steamboat_runtime.protocol import secure_transport
        from steamboat_runtime.protocol.errors import ProtocolError

        harness = await self._harness(listener_slots=1)
        original_context, original_factory, original_generate_auth = (
            harness.trusted_worker_context())
        fresh_context, fresh_factory, fresh_generate_auth = (
            harness.trusted_worker_context())
        baseline_connections = harness.budget.reserved_connections
        clients = []
        close_attempts = {}
        close_results = {}
        close_failures = {}
        original_session = original_context.session_id
        self.assertNotEqual(original_session, fresh_context.session_id)
        self.assertNotEqual(original_context.request_id, fresh_context.request_id)
        self.assertNotEqual(original_context.route_id, fresh_context.route_id)

        async def create_client(label):
            client, outbound, store = await harness.public_worker_client()
            # Keep the constructed public owner immediately, including if a
            # later assertion or operation fails partway through this sequence.
            clients.append((label, client, outbound, store))
            self.assertEqual(harness.budget.reserved_connections,
                             baseline_connections + secure_transport.OUTBOUND_STATIC_CONNECTION_SLOTS)
            return client

        async def close_once(client):
            key = id(client)
            if key not in close_attempts:
                task = asyncio.create_task(client.close())
                close_attempts[key] = task
            try:
                result = await asyncio.shield(close_attempts[key])
            except BaseException as error:
                close_failures[key] = error
                raise
            close_results[key] = result
            return result

        async def assert_server_connection_retired(acceptor, *, client_slots):
            self.assertTrue(await acceptor.wait_for_idle(1))
            self.assertEqual(acceptor._active, 0)
            self.assertEqual(harness.budget.reserved_pending, 0)
            self.assertEqual(harness.budget.reserved_outbound_pending, 0)
            self.assertEqual(
                harness.budget.reserved_connections,
                baseline_connections + client_slots)

        original_receive = secure_transport._receive_unary_response

        def status_observer(statuses):
            async def observe_native_status(call):
                try:
                    return await original_receive(call)
                except grpc.aio.AioRpcError as error:
                    statuses.append(error.code())
                    raise
            return observe_native_status

        def capture_first_fenced_connector(client):
            subchannel = client._subchannel
            original_fence = subchannel.fence
            captured = {}

            async def capture_then_fence():
                captured.setdefault("connector", subchannel.connector)
                return await original_fence()

            subchannel.fence = capture_then_fence
            return captured

        try:
            initial_client = await create_client("initial")
            opened = await initial_client.execute(
                "OpenSession", harness.open_request(original_session),
                trusted_request_context=original_context)
            self.assertTrue(opened.lease_token)
            step = harness.session_request(original_session, opened.lease_token, step=True)
            stepped = await initial_client.execute(
                "Step", step, trusted_request_context=original_context)
            self.assertEqual(stepped.code, "OK", stepped.message)
            self.assertEqual(stepped.end_position, 1)
            self.assertEqual(stepped.next_sequence, 1)
            self.assertEqual(
                harness.handler.sessions[original_session].cache.lengths(), (1,))
            self.assertEqual(harness.executor.execute_calls, 1)
            self.assertIn(original_session, harness.handler.sessions)
            initial_connector = initial_client._subchannel.connector
            self.assertIsNotNone(initial_connector)
            self.assertEqual(
                harness.budget.reserved_connections,
                baseline_connections + secure_transport.OUTBOUND_STATIC_CONNECTION_SLOTS)
            self.assertIsNone(await close_once(initial_client))
            self.assertTrue(initial_connector.closure_evidence)
            await assert_server_connection_retired(
                harness.server._acceptor, client_slots=0)

            # Revoke the service's actual worker target serial. Each following
            # public client keeps a separately-created immutable original store.
            handlers_before_revocation = tuple(harness.handler_methods)
            executions_before_revocation = harness.executor.execute_calls
            original_outbound_store = clients[0][3]
            worker_device, worker_serials = self._install_revoking_snapshot(
                harness, principal=harness.worker, revoke_device=True)
            live_view = harness.store.current(sample=harness.clock.sample())
            worker_serial = harness.worker.record["serial"]
            self.assertIn(worker_device, live_view.revoked_devices)
            self.assertTrue(worker_serials.issubset(live_view.revoked_serials))
            self.assertFalse(any(record.device_id == worker_device
                                 for record in live_view.credentials_by_serial.values()))
            self.assertFalse(any(grant.device_id == worker_device
                                 or grant.target_device_id == worker_device
                                 for grant in live_view.grants))
            self.assertIsNot(original_outbound_store, harness.store)
            acceptor = harness.server._acceptor

            status_client = await create_client("status")
            status_outbound_store = clients[-1][3]
            self.assertIsNot(status_outbound_store, harness.store)
            status_view = status_outbound_store.current(
                sample=status_outbound_store.clock.sample())
            self.assertIn(worker_serial, status_view.credentials_by_serial)
            self.assertNotIn(worker_serial, status_view.revoked_serials)
            native_status = []
            status_decisions_before = len(harness.authorization_decisions)
            status_connector_holder = capture_first_fenced_connector(status_client)
            with patch.object(
                    secure_transport, "_receive_unary_response",
                    status_observer(native_status)):
                with self.assertRaises(ProtocolError):
                    await status_client.execute(
                        "SessionStatus",
                        harness.session_request(original_session, opened.lease_token),
                        trusted_request_context=original_context)
            self.assertEqual(native_status, [grpc.StatusCode.UNAUTHENTICATED])
            self.assertEqual(len(harness.authorization_decisions), status_decisions_before + 1)
            self.assertEqual(
                (harness.authorization_decisions[-1]["service"],
                 harness.authorization_decisions[-1]["method"],
                 harness.authorization_decisions[-1]["outcome"],
                 harness.authorization_decisions[-1]["category"],
                 harness.authorization_decisions[-1]["code"]),
                (secure_transport.WORKER_SERVICE, "SessionStatus", "denied",
                 "CredentialError", "UNAUTHENTICATED"))
            self.assertEqual(tuple(harness.handler_methods), handlers_before_revocation)
            self.assertEqual(harness.executor.execute_calls, executions_before_revocation)
            status_connector = status_connector_holder.get("connector")
            self.assertIsNotNone(status_connector,
                                 "execute must fence the actual dispatched connector")
            await assert_server_connection_retired(
                acceptor, client_slots=secure_transport.OUTBOUND_STATIC_CONNECTION_SLOTS)
            self.assertTrue(status_connector.closure_evidence,
                            "the rejected public Status call must fence its actual connector")
            self.assertIsNone(await close_once(status_client))
            await assert_server_connection_retired(acceptor, client_slots=0)

            fresh_client = await create_client("fresh")
            fresh_outbound_store = clients[-1][3]
            self.assertIsNot(fresh_outbound_store, harness.store)
            fresh_view = fresh_outbound_store.current(
                sample=fresh_outbound_store.clock.sample())
            self.assertIn(worker_serial, fresh_view.credentials_by_serial)
            self.assertNotIn(worker_serial, fresh_view.revoked_serials)
            native_status.clear()
            open_decisions_before = len(harness.authorization_decisions)
            fresh_connector_holder = capture_first_fenced_connector(fresh_client)
            with patch.object(
                    secure_transport, "_receive_unary_response",
                    status_observer(native_status)):
                with self.assertRaises(ProtocolError):
                    await fresh_client.execute(
                        "OpenSession", harness.open_request(fresh_context.session_id),
                        trusted_request_context=fresh_context)
            self.assertEqual(native_status, [grpc.StatusCode.UNAUTHENTICATED])
            self.assertEqual(len(harness.authorization_decisions), open_decisions_before + 1)
            self.assertEqual(
                (harness.authorization_decisions[-1]["service"],
                 harness.authorization_decisions[-1]["method"],
                 harness.authorization_decisions[-1]["outcome"],
                 harness.authorization_decisions[-1]["category"],
                 harness.authorization_decisions[-1]["code"]),
                (secure_transport.WORKER_SERVICE, "OpenSession", "denied",
                 "CredentialError", "UNAUTHENTICATED"))
            self.assertEqual(tuple(harness.handler_methods), handlers_before_revocation)
            self.assertEqual(harness.executor.execute_calls, executions_before_revocation)
            fresh_connector = fresh_connector_holder.get("connector")
            self.assertIsNotNone(fresh_connector,
                                 "execute must fence the actual dispatched connector")
            self.assertNotIn(fresh_context.session_id, harness.handler.sessions)
            self.assertFalse(any(key[2] == fresh_context.session_id
                                 for key in harness.bindings._records))
            await assert_server_connection_retired(
                acceptor, client_slots=secure_transport.OUTBOUND_STATIC_CONNECTION_SLOTS)
            self.assertTrue(fresh_connector.closure_evidence,
                            "the rejected public Open call must fence its actual connector")
            self.assertIsNone(await close_once(fresh_client))
            await assert_server_connection_retired(acceptor, client_slots=0)
            self.assertEqual(len(close_results), 3)
            self.assertEqual(len(close_failures), 0)
            self.assertEqual(len(close_attempts), 3,
                             "each public client has exactly one memoized close attempt")
        finally:
            # Never invoke close a second time after an uncertain first result.
            # A task retains each result or failure, and clients remain strongly
            # owned until all fixture cleanup has finished.
            for _label, client, _outbound, _store in clients:
                if id(client) not in close_attempts:
                    try:
                        await close_once(client)
                    except BaseException:
                        pass
                else:
                    try:
                        await asyncio.shield(close_attempts[id(client)])
                    except BaseException:
                        pass
            original_factory.release(original_context)
            fresh_factory.release(fresh_context)
            original_generate_auth.close()
            fresh_generate_auth.close()

    async def test_both_endpoint_leaves_expired_on_an_existing_tls_channel(self):
        import grpc

        harness = await self._harness(virtual_clock=True)
        coordinator_channel = await harness.channel(harness.coordinator)
        fields = harness.binding_fields(harness.coordinator, "Describe")
        response = await harness.call(
            coordinator_channel, "Describe", harness.describe_request(), fields)
        self.assertEqual(response.code, "OK")
        self.assertEqual(harness.authorization_decisions[-1]["outcome"], "allowed")
        self.assertEqual(harness.handler_methods, ["Describe"])

        # This is explicitly a both-endpoints policy-expiry case: native TLS
        # retains its real host clock, while C0 advances past both actual leaf
        # validity intervals and refreshes signed snapshots/grants as needed.
        await harness.advance_to_expired_credentials()
        before = len(harness.handler_methods)
        await self._assert_rejected(
            harness, coordinator_channel, "Describe", harness.describe_request(),
            harness.binding_fields(harness.coordinator, "Describe"),
            grpc.StatusCode.UNAUTHENTICATED,
            "CredentialError", "UNAUTHENTICATED")
        self.assertEqual(len(harness.handler_methods), before)
        self.assertEqual(harness.executor.execute_calls, 0)
        self.assertEqual(harness.handler.sessions, {})


if __name__ == "__main__":
    unittest.main()
