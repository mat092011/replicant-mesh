"""Offline adversarial tests for the transport-neutral outbound adapter.

Worker Request/Response classes here are clearly marked dependency-free parsed
protobuf fixtures. The parent transport runs the same policy with generated
protobuf classes, real TLS, and the sibling runtime's actual request context.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import time
import unittest
from dataclasses import replace
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "security"))

from test_identity_core import (ACCOUNT_A, ACCOUNT_B, ASSIGNMENT, BOOT_CONSUMER,
    BOOT_COORDINATOR, BOOT_HOST, DEVICE_COORDINATOR, DEVICE_HOST, MODEL, NOW,
    FakeTime, IdentityFixture, ParsedWorkerRequest as _ParsedWorkerRequest)
from steamboat_security import (AuthorizationWatcher, BindingError, ConsumerRequestContext,
    CredentialError, LocalIdentity, OutboundAuthorizer, OutboundTarget, ScopeError,
    SessionError, SnapshotError, generate_private_key_pem, issue_leaf, make_csr,
    new_id, parse_metadata, sign_snapshot)
from steamboat_security.codec import COORDINATOR_SERVICE, WORKER_SERVICE
from steamboat_security.operator import _record_from_leaf
from steamboat_runtime.participant_context import TrustedRequestContext


class ParsedWorkerRequest(_ParsedWorkerRequest):
    """Parsed protobuf fixture with ListFields() default omission semantics."""

    _DEFAULTS = {"protocol_version": 0, "manifest_fingerprint": "",
                 "worker_boot_id": "", "session_id": "", "lease_token": "",
                 "timeout_ms": 0, "sequence": 0, "start_position": 0,
                 "token_count": 0, "max_positions": 0, "lifetime_ms": 0,
                 "idle_lease_ms": 0, "tensor": None}

    def __getattr__(self, name):
        try:
            return self._DEFAULTS[name]
        except KeyError:
            raise AttributeError(name) from None

    def ListFields(self):
        return [
            (SimpleNamespace(name=name), value)
            for name, value in vars(self).items()
            if name not in self._DEFAULTS or value != self._DEFAULTS[name]
        ]


class ParsedWorkerResponse:
    """Dependency-free exact Response fixture; production uses generated Response."""

    DESCRIPTOR = SimpleNamespace(full_name="steamboat.v1.Response")

    def __init__(self, **values):
        self.__dict__.update(values)

    def ByteSize(self):
        return sum(len(str(key)) + len(str(value)) for key, value in vars(self).items())


class OutboundAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        IdentityFixture.setUpClass()

    def setUp(self):
        self.fx = IdentityFixture("runTest")
        self.time_source = FakeTime()
        self.store, self.clock = self.fx.store(self.time_source)

    def target(self, name, service):
        record = self.fx.records[name]
        boot = self.fx.identities[name][3]
        assignment = ASSIGNMENT if service == WORKER_SERVICE else None
        return OutboundTarget.from_record(service=service, record=record,
            boot_id=boot, model_id=MODEL, assignment_id=assignment)

    def worker_adapter(self, *, allow_bootstrap=False, max_context_records=4096):
        local = LocalIdentity(self.fx.credentials["coordinator"]["certificate"],
                              BOOT_COORDINATOR, MODEL)
        return OutboundAuthorizer(local_identity=local, snapshot_store=self.store,
            clock=self.clock, target=self.target("host", WORKER_SERVICE),
            worker_request_type=ParsedWorkerRequest,
            trusted_request_context_type=TrustedRequestContext,
            allow_bootstrap_describe=allow_bootstrap,
            max_context_records=max_context_records)

    def coordinator_adapter(self):
        local = LocalIdentity(self.fx.credentials["consumer"]["certificate"],
                              BOOT_CONSUMER, MODEL)
        return OutboundAuthorizer(local_identity=local, snapshot_store=self.store,
            clock=self.clock, target=self.target("coordinator", COORDINATOR_SERVICE))

    def trusted_worker_context(self):
        coordinator_authorizer, _ = self.fx.coordinator_authorizer(
            time_source=self.time_source, store=self.store)
        request_id = new_id("req")
        fields = {"binding_version": 1, "operation_id": new_id("op"),
                  "account_id": ACCOUNT_A, "device_id": self.fx.records["consumer"]["device_id"],
                  "role": "consumer", "credential_epoch": 1,
                  "target_device_id": DEVICE_COORDINATOR, "request_id": request_id}
        payload = {"input_ids": [1], "new_tokens": 1,
                   "timeout_seconds": 30, "capture_logits": False}
        authorization = coordinator_authorizer.authorize(
            COORDINATOR_SERVICE, "Generate", payload,
            self.fx.metadata(COORDINATOR_SERVICE, "Generate", fields),
            self.fx.credentials["consumer"]["certificate"])
        context = TrustedRequestContext(
            tenant_account_id=ACCOUNT_A, request_id=request_id,
            session_id=new_id("ses"), route_id=new_id("route"),
            coordinator_boot_id=BOOT_COORDINATOR, route_epoch=1, attempt=1,
            authorization=authorization,
            hard_monotonic_deadline=time.monotonic() + 3600)
        # This proves the adapter consumes a real core Authorization rather
        # than a stubbed `assert_live() -> None` test double.
        self.assertIs(type(authorization), __import__(
            "steamboat_security.authorization", fromlist=["Authorization"]).Authorization)
        self.assertIn(authorization.assert_live(), (None, True))
        context.assert_data_live()
        return context

    @staticmethod
    def worker_payload(method, context, *, lease=""):
        if method == "Describe":
            return ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000)
        common = dict(protocol_version=1, manifest_fingerprint=MODEL,
                      worker_boot_id=BOOT_HOST, session_id=context.session_id,
                      timeout_ms=5_000)
        if method == "OpenSession":
            common.update(lease_token="", max_positions=64,
                          lifetime_ms=30_000, idle_lease_ms=10_000)
        else:
            common["lease_token"] = lease
        if method == "Step":
            common.update(sequence=0, start_position=0, token_count=1,
                          tensor=SimpleNamespace(shape=[1, 1, 1], dtype="float32",
                                                 layout="contiguous", byte_count=4,
                                                 data=b"\0\0\0\0"))
        return ParsedWorkerRequest(**common)

    def response(self, context, *, method="OpenSession", code="OK"):
        return ParsedWorkerResponse(
            protocol_version=1, manifest_fingerprint=MODEL, worker_boot_id=BOOT_HOST,
            session_id="" if method == "Describe" else context.session_id,
            lease_token="l" * 32 if method == "OpenSession" else "",
            code=code, message="", max_positions=64)

    @staticmethod
    def binding_fields(encoded, service, method):
        return dict(parse_metadata(service, method,
            (("steamboat-binding-bin", encoded),)).fields)

    def test_worker_open_is_bound_to_real_core_context_and_fixed_target(self):
        context = self.trusted_worker_context()
        adapter = self.worker_adapter()
        payload = self.worker_payload("OpenSession", context)
        auth = adapter.authorize_outbound(
            service=WORKER_SERVICE, method="OpenSession", payload=payload,
            trusted_request_context=context,
            peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        fields = self.binding_fields(auth.binding_bytes, WORKER_SERVICE, "OpenSession")
        self.assertEqual(fields["account_id"], ACCOUNT_A)
        self.assertEqual(fields["tenant_account_id"], ACCOUNT_A)
        self.assertEqual(fields["target_device_id"], DEVICE_HOST)
        self.assertEqual(fields["session_id"], context.session_id)
        self.assertEqual(fields["assignment_id"], ASSIGNMENT)
        self.assertEqual(fields["route_epoch"], 1)
        self.assertEqual(fields["attempt"], 1)
        self.assertTrue(fields["operation_id"].startswith("op_"))
        first_operation = fields["operation_id"]
        auth.assert_live()
        self.assertGreater(auth.remaining_seconds(), 0)
        auth.complete(self.response(context))
        self.assertTrue(auth.assert_live())
        auth.close()

        second = adapter.authorize_outbound(
            service=WORKER_SERVICE, method="Step",
            payload=self.worker_payload("Step", context, lease="l" * 32),
            trusted_request_context=context,
            peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        step_fields = self.binding_fields(second.binding_bytes, WORKER_SERVICE, "Step")
        self.assertNotEqual(first_operation, step_fields["operation_id"])
        second.close()

    def test_worker_contextless_data_cross_tenant_wrong_boot_and_wrong_peer_reject(self):
        adapter = self.worker_adapter(allow_bootstrap=True)
        context = self.trusted_worker_context()
        with self.assertRaises(ScopeError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="OpenSession",
                payload=self.worker_payload("OpenSession", context),
                trusted_request_context=None,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        wrong_tenant = TrustedRequestContext(
            tenant_account_id=ACCOUNT_B, request_id=context.request_id,
            session_id=context.session_id, route_id=context.route_id,
            coordinator_boot_id=BOOT_COORDINATOR, route_epoch=1, attempt=1,
            authorization=context.authorization,
            hard_monotonic_deadline=time.monotonic() + 3600)
        with self.assertRaises(ScopeError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="Step",
                payload=self.worker_payload("Step", wrong_tenant, lease="l" * 32),
                trusted_request_context=wrong_tenant,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        wrong_boot = TrustedRequestContext(
            tenant_account_id=ACCOUNT_A, request_id=context.request_id,
            session_id=context.session_id, route_id=context.route_id,
            coordinator_boot_id="f" * 32, route_epoch=1, attempt=1,
            authorization=context.authorization,
            hard_monotonic_deadline=time.monotonic() + 3600)
        with self.assertRaises(ScopeError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="Step",
                payload=self.worker_payload("Step", wrong_boot, lease="l" * 32),
                trusted_request_context=wrong_boot,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        with self.assertRaises(ScopeError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="Describe",
                payload=self.worker_payload("Describe", context),
                trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["alt_coordinator"]["certificate"])

    def test_worker_fixed_role_assignment_boot_epoch_and_missing_grant_reject(self):
        context = self.trusted_worker_context()
        base_target = self.target("host", WORKER_SERVICE)
        local = LocalIdentity(self.fx.credentials["coordinator"]["certificate"],
                              BOOT_COORDINATOR, MODEL)
        wrong_assignment = replace(base_target, assignment_id="asg_" + "9" * 32)
        assignment_adapter = OutboundAuthorizer(local_identity=local,
            snapshot_store=self.store, clock=self.clock, target=wrong_assignment,
            worker_request_type=ParsedWorkerRequest,
            trusted_request_context_type=TrustedRequestContext)
        with self.assertRaises(ScopeError):
            assignment_adapter.authorize_outbound(service=WORKER_SERVICE, method="Describe",
                payload=ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000),
                trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])

        wrong_boot = replace(base_target, boot_id="f" * 32)
        boot_adapter = OutboundAuthorizer(local_identity=local,
            snapshot_store=self.store, clock=self.clock, target=wrong_boot,
            worker_request_type=ParsedWorkerRequest,
            trusted_request_context_type=TrustedRequestContext)
        with self.assertRaises(ScopeError):
            boot_adapter.authorize_outbound(service=WORKER_SERVICE, method="Describe",
                payload=ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000),
                trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])

        wrong_epoch_record = dict(self.fx.records["host"], credential_epoch=2)
        wrong_epoch_target = OutboundTarget.from_record(service=WORKER_SERVICE,
            record=wrong_epoch_record, boot_id=BOOT_HOST, model_id=MODEL,
            assignment_id=ASSIGNMENT)
        epoch_adapter = OutboundAuthorizer(local_identity=local,
            snapshot_store=self.store, clock=self.clock, target=wrong_epoch_target,
            worker_request_type=ParsedWorkerRequest,
            trusted_request_context_type=TrustedRequestContext)
        with self.assertRaises(CredentialError):
            epoch_adapter.authorize_outbound(service=WORKER_SERVICE, method="Describe",
                payload=ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000),
                trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])

        wrong_local = LocalIdentity(self.fx.credentials["consumer"]["certificate"],
                                    BOOT_CONSUMER, MODEL)
        with self.assertRaises(CredentialError):
            OutboundAuthorizer(local_identity=wrong_local,
                snapshot_store=self.store, clock=self.clock, target=base_target,
                worker_request_type=ParsedWorkerRequest,
                trusted_request_context_type=TrustedRequestContext)

        no_step_grants = [g for g in self.fx.grants()
                          if g["method"] != "steamboat.v1.Worker/Step"]
        self.store, self.clock = self.fx.store(self.time_source,
            self.fx.payload(revision=2, grants=no_step_grants))
        context = self.trusted_worker_context()
        denied_adapter = self.worker_adapter()
        with self.assertRaises(ScopeError):
            denied_adapter.authorize_outbound(service=WORKER_SERVICE, method="Step",
                payload=self.worker_payload("Step", context, lease="l" * 32),
                trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])

    def test_actual_target_certificate_rotation_invalidates_old_peer_pin(self):
        context = self.trusted_worker_context()
        adapter = self.worker_adapter()
        old_peer = self.fx.credentials["host"]["certificate"]
        key = generate_private_key_pem()
        csr = make_csr(key, account_id=ACCOUNT_B, device_id=DEVICE_HOST,
                       role="host", dns_sans=("worker.example",))
        cert = issue_leaf(self.fx.ca_pem, self.fx.ca_key, csr,
            account_id=ACCOUNT_B, device_id=DEVICE_HOST, role="host",
            not_before=NOW - 60, not_after=NOW + 840, ekus=("server",))
        record = _record_from_leaf(cert, account_id=ACCOUNT_B,
                                   device_id=DEVICE_HOST, role="host",
                                   credential_epoch=2)
        records = [item for name, item in self.fx.records.items() if name != "host"]
        records.append(record)
        self.store.install(sign_snapshot(self.fx.payload(revision=2,
            records=records, grants=self.fx.grants(host_record=record)),
            self.fx.signing_key))
        with self.assertRaises(CredentialError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="Describe",
                payload=ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000),
                trusted_request_context=context, peer_certificate_pem=old_peer)

    def test_bootstrap_is_finite_describe_only_and_uses_exact_wire_method(self):
        adapter = self.worker_adapter(allow_bootstrap=True)
        bootstrap = adapter.create_bootstrap_context(max_describes=1)
        auth = adapter.authorize_outbound(service=WORKER_SERVICE, method="Describe",
            payload=ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000),
            trusted_request_context=bootstrap,
            peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        fields = self.binding_fields(auth.binding_bytes, WORKER_SERVICE, "Describe")
        self.assertEqual(fields["worker_boot_id"], BOOT_HOST)
        self.assertEqual(fields["assignment_id"], ASSIGNMENT)
        auth.complete(ParsedWorkerResponse(protocol_version=1, manifest_fingerprint=MODEL,
            worker_boot_id=BOOT_HOST, session_id="", lease_token="", code="OK"))
        auth.close()
        with self.assertRaises(ScopeError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="Describe",
                payload=ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000),
                trusted_request_context=bootstrap,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        context = self.trusted_worker_context()
        with self.assertRaises(BindingError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="Open",
                payload=self.worker_payload("OpenSession", context),
                trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])

    def test_worker_method_specific_payload_fields_are_rejected(self):
        adapter = self.worker_adapter()
        context = self.trusted_worker_context()
        bad_describe = ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000,
                                           session_id=context.session_id)
        with self.assertRaises(BindingError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="Describe",
                payload=bad_describe, trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        bad_open = self.worker_payload("OpenSession", context)
        bad_open.lease_token = "not-empty"
        with self.assertRaises(BindingError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="OpenSession",
                payload=bad_open, trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        bad_step = self.worker_payload("Step", context, lease="l" * 32)
        bad_step.lifetime_ms = 5
        with self.assertRaises(BindingError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="Step",
                payload=bad_step, trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        wrong_model = self.worker_payload("Step", context, lease="l" * 32)
        wrong_model.manifest_fingerprint = "b" * 64
        with self.assertRaises(ScopeError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="Step",
                payload=wrong_model, trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])

    def test_cleanup_uses_only_a_previously_live_exact_context_for_twenty_seconds(self):
        self.time_source = FakeTime(monotonic=time.monotonic())
        self.store, self.clock = self.fx.store(self.time_source)
        context = self.trusted_worker_context()
        context = TrustedRequestContext(
            tenant_account_id=context.tenant_account_id, request_id=context.request_id,
            session_id=context.session_id, route_id=context.route_id,
            coordinator_boot_id=context.coordinator_boot_id, route_epoch=1, attempt=1,
            authorization=context.authorization,
            hard_monotonic_deadline=self.time_source.monotonic + 2.0)
        adapter = self.worker_adapter()
        opened = adapter.authorize_outbound(service=WORKER_SERVICE, method="OpenSession",
            payload=self.worker_payload("OpenSession", context),
            trusted_request_context=context,
            peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        opened.complete(self.response(context))
        opened.close()
        self.time_source.advance(3)
        with self.assertRaises(SessionError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="Step",
                payload=self.worker_payload("Step", context, lease="l" * 32),
                trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        cleanup = adapter.authorize_outbound(service=WORKER_SERVICE, method="CancelSession",
            payload=self.worker_payload("CancelSession", context, lease="l" * 32),
            trusted_request_context=context,
            peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        self.assertLessEqual(cleanup.remaining_seconds(), 19.0)
        cleanup.close()
        self.time_source.monotonic = context.hard_monotonic_deadline + 21.0
        with self.assertRaises(SessionError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="CancelSession",
                payload=self.worker_payload("CancelSession", context, lease="l" * 32),
                trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])

    def test_coordinator_consumer_scope_fresh_generate_id_and_method_fields(self):
        adapter = self.coordinator_adapter()
        context = adapter.create_consumer_request_context(lifetime_seconds=30)
        second_context = adapter.create_consumer_request_context(lifetime_seconds=30)
        self.assertIs(type(context), ConsumerRequestContext)
        self.assertNotEqual(context.request_id, second_context.request_id)
        request = {"input_ids": [1, 2], "new_tokens": 2,
                   "forced_tokens": [3], "capture_logits": False,
                   "timeout_seconds": 20}
        auth = adapter.authorize_outbound(service=COORDINATOR_SERVICE, method="Generate",
            payload=request, trusted_request_context=context,
            peer_certificate_pem=self.fx.credentials["coordinator"]["certificate"])
        fields = self.binding_fields(auth.binding_bytes, COORDINATOR_SERVICE, "Generate")
        self.assertEqual(fields["account_id"], ACCOUNT_A)
        self.assertEqual(fields["target_device_id"], DEVICE_COORDINATOR)
        self.assertEqual(fields["request_id"], context.request_id)
        auth.complete({"type": "result"})
        auth.close()
        token_auth = adapter.authorize_outbound(service=COORDINATOR_SERVICE, method="Tokenize",
            payload={"text": "synthetic prompt", "add_special_tokens": True},
            trusted_request_context=second_context,
            peer_certificate_pem=self.fx.credentials["coordinator"]["certificate"])
        token_fields = self.binding_fields(token_auth.binding_bytes,
                                           COORDINATOR_SERVICE, "Tokenize")
        self.assertNotIn("request_id", token_fields)
        token_auth.complete({"input_ids": [1, 2]})
        token_auth.close()
        with self.assertRaises(ScopeError):
            adapter.authorize_outbound(service=COORDINATOR_SERVICE, method="Generate",
                payload=request, trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["coordinator"]["certificate"])
        with self.assertRaises(BindingError):
            adapter.authorize_outbound(service=COORDINATOR_SERVICE, method="Tokenize",
                payload={"text": "valid", "add_special_tokens": 1},
                trusted_request_context=adapter.create_consumer_request_context(),
                peer_certificate_pem=self.fx.credentials["coordinator"]["certificate"])
        with self.assertRaises(ScopeError):
            adapter.authorize_outbound(service=COORDINATOR_SERVICE, method="Describe",
                payload={}, trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])

    def test_outbound_snapshot_revocation_expiry_and_target_rotation_fail_closed(self):
        adapter = self.coordinator_adapter()
        context = adapter.create_consumer_request_context()
        auth = adapter.authorize_outbound(service=COORDINATOR_SERVICE, method="Describe",
            payload={}, trusted_request_context=context,
            peer_certificate_pem=self.fx.credentials["coordinator"]["certificate"])
        actor_serial = self.fx.records["consumer"]["serial"]
        records = [record for name, record in self.fx.records.items() if name != "consumer"]
        grants = [grant for grant in self.fx.grants()
                  if grant["actor_serial"] != actor_serial]
        self.store.install(sign_snapshot(self.fx.payload(revision=2, records=records,
            grants=grants, revoked_serials=(actor_serial,)), self.fx.signing_key))
        with self.assertRaises(CredentialError):
            auth.assert_live()
        auth.close()

        time_source = FakeTime()
        store, clock = self.fx.store(time_source)
        expiring = OutboundAuthorizer(
            local_identity=LocalIdentity(self.fx.credentials["consumer"]["certificate"],
                                         BOOT_CONSUMER, MODEL),
            snapshot_store=store, clock=clock,
            target=self.target("coordinator", COORDINATOR_SERVICE))
        ctx = expiring.create_consumer_request_context()
        live = expiring.authorize_outbound(service=COORDINATOR_SERVICE, method="Describe",
            payload={}, trusted_request_context=ctx,
            peer_certificate_pem=self.fx.credentials["coordinator"]["certificate"])
        time_source.advance(301)
        with self.assertRaises((SnapshotError, CredentialError, ScopeError, SessionError)):
            live.assert_live()

        # The adapter's immutable target pin rejects a different enrolled
        # coordinator certificate even when it belongs to the same account.
        fresh_time = FakeTime()
        fresh_store, fresh_clock = self.fx.store(fresh_time)
        fresh_adapter = OutboundAuthorizer(
            local_identity=LocalIdentity(self.fx.credentials["consumer"]["certificate"],
                                         BOOT_CONSUMER, MODEL),
            snapshot_store=fresh_store, clock=fresh_clock,
            target=self.target("coordinator", COORDINATOR_SERVICE))
        fresh_context = fresh_adapter.create_consumer_request_context()
        with self.assertRaises((ScopeError, CredentialError)):
            fresh_adapter.authorize_outbound(service=COORDINATOR_SERVICE, method="Describe",
                payload={}, trusted_request_context=fresh_context,
                peer_certificate_pem=self.fx.credentials["alt_coordinator"]["certificate"])

    def test_context_table_is_bounded_without_evicting_live_contexts(self):
        adapter = self.worker_adapter(max_context_records=1)
        first = self.trusted_worker_context()
        second = self.trusted_worker_context()
        first_auth = adapter.authorize_outbound(service=WORKER_SERVICE, method="Describe",
            payload=ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000),
            trusted_request_context=first,
            peer_certificate_pem=self.fx.credentials["host"]["certificate"])
        first_auth.close()
        with self.assertRaises(ScopeError):
            adapter.authorize_outbound(service=WORKER_SERVICE, method="Describe",
                payload=ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000),
                trusted_request_context=second,
                peer_certificate_pem=self.fx.credentials["host"]["certificate"])

    def test_watcher_polls_clips_deadline_parks_after_complete_and_propagates_cancel(self):
        async def scenario():
            adapter = self.coordinator_adapter()
            context = adapter.create_consumer_request_context(lifetime_seconds=5)
            auth = adapter.authorize_outbound(service=COORDINATOR_SERVICE, method="Describe",
                payload={}, trusted_request_context=context,
                peer_certificate_pem=self.fx.credentials["coordinator"]["certificate"])
            watcher = AuthorizationWatcher(poll_interval_seconds=0.01)
            task = asyncio.create_task(watcher(auth))
            auth.complete({"ready": True})
            await asyncio.sleep(0.03)
            self.assertFalse(task.done())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            auth.close()

            expired_context = adapter.create_consumer_request_context(lifetime_seconds=1)
            expired = adapter.authorize_outbound(service=COORDINATOR_SERVICE, method="Describe",
                payload={}, trusted_request_context=expired_context,
                peer_certificate_pem=self.fx.credentials["coordinator"]["certificate"])
            expire_at = self.time_source.monotonic + 2
            task2 = asyncio.create_task(watcher(expired))
            self.time_source.monotonic = expire_at
            for _ in range(30):
                if task2.done():
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(task2.done())
            await task2
            expired.close()
        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
