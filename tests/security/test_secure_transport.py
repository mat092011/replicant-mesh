"""Isolated transport boundary checks; these do not establish C-core behavior."""

import asyncio
import hashlib
import inspect
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_runtime.protocol.secure_connector import SecureConnectorPending
from steamboat_runtime.protocol import METHODS
from steamboat_runtime.protocol.secure_transport import (
    AuthorizationRejected,
    AuthorizationRevoked,
    BINDING_METADATA_KEY,
    CAPACITY_REJECTION_METADATA_KEY,
    C0ExpectedServerLeafAdapter,
    COORDINATOR_SERVICE,
    ExpectedServerIdentity,
    MAX_METADATA_BYTES,
    _RETAINED_TASKS,
    _SecureRuntimeOwner,
    NodeConnectionBudget,
    SecureTaskPending,
    SecureServerHandle,
    SecureWorkerClient,
    SecureCoordinatorClient,
    SecureTransportError,
    WORKER_SERVICE,
    _call_authorize,
    _assert_live,
    _canonical_binding,
    _cancel_tasks_bounded,
    _fail_authorization,
    _peer_certificate_from_auth_context,
    _retain_authorization_close_until_done,
    _run_guarded,
    _SecureSubchannel,
    _secure_options,
    _wait_owned_tasks,
    capacity_rejection_metadata,
    has_capacity_rejection_metadata,
    outgoing_binding_metadata,
    parse_fixed_ipv4_endpoint,
    validate_metadata,
)
from steamboat_runtime.protocol.worker_pb2 import Request


class FakeAuthorization:
    binding_bytes = b'{"account_id":"acct_test","binding_version":1}'

    def __init__(self, remaining=2.0):
        self.remaining = remaining
        self.completed = []
        self.failed = []
        self.closed = False

    def assert_live(self):
        return None

    def complete(self, response):
        self.completed.append(response)

    def fail(self, *, cache_may_exist=True):
        self.failed.append(cache_may_exist)

    def close(self):
        self.closed = True

    def remaining_seconds(self):
        return self.remaining


class EndpointAndIdentityAdapterTests(unittest.TestCase):
    def test_endpoint_acceptance_requires_canonical_literal_and_exact_allowlist(self):
        self.assertEqual(parse_fixed_ipv4_endpoint(
            "127.0.0.1:50051", ("127.0.0.1",)), ("127.0.0.1", 50051))
        self.assertEqual(parse_fixed_ipv4_endpoint(
            "192.168.1.9:50051", ["192.168.1.9"], listen=True),
            ("192.168.1.9", 50051))
        self.assertEqual(parse_fixed_ipv4_endpoint(
            "8.8.8.8:50051", ("8.8.8.8",)), ("8.8.8.8", 50051))
        for endpoint, allowlist in (
                ("worker.example:50051", ("192.168.1.9",)),
                ("[::1]:50051", ("127.0.0.1",)),
                ("0.0.0.0:50051", ("0.0.0.0",)),
                ("8.8.8.8:50051", ("1.1.1.1",)),
                ("127.0.0.1:050051", ("127.0.0.1",)),
                ("127.0.0.1:0", ("127.0.0.1",))):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                parse_fixed_ipv4_endpoint(endpoint, allowlist)
        with self.assertRaises(ValueError):
            parse_fixed_ipv4_endpoint("8.8.8.8:50051", ("8.8.8.8",), listen=True)

    def test_listener_endpoint_may_use_ephemeral_port_only_when_listening(self):
        self.assertEqual(parse_fixed_ipv4_endpoint(
            "127.0.0.1:0", ("127.0.0.1",), listen=True), ("127.0.0.1", 0))

    def test_leaf_adapter_maps_the_real_c0_keyword_only_api(self):
        seen = {}

        def core(ca_pem, leaf_pem, *, now, account_id, device_id, role,
                 serial, public_key_hash, certificate_hash, expected_ip, ekus):
            seen.update(locals())
            return leaf_pem

        expected = ExpectedServerIdentity(
            account_id="acct_test", device_id="dev_test", role="host", serial=19,
            public_key_hash=b"p" * 32, certificate_hash=b"c" * 32,
            expected_ip="192.168.1.9")
        leaf, ca = b"synthetic leaf PEM", b"synthetic CA PEM"
        approved = C0ExpectedServerLeafAdapter(core)(leaf, ca, expected, now=123.5)

        self.assertEqual(approved, leaf)
        self.assertEqual(seen["ca_pem"], ca)
        self.assertEqual(seen["leaf_pem"], leaf)
        self.assertEqual(seen["now"], 123.5)
        self.assertEqual(seen["role"], "host")
        self.assertEqual(seen["expected_ip"], "192.168.1.9")
        self.assertEqual(seen["ekus"], ("server",))
        self.assertEqual(seen["serial"], "13")
        self.assertEqual(seen["public_key_hash"], (b"p" * 32).hex())
        self.assertEqual(seen["certificate_hash"], (b"c" * 32).hex())

    def test_personal_coordinator_leaf_requires_both_client_and_server_eku(self):
        expected = ExpectedServerIdentity(
            account_id="acct_test", device_id="dev_coord", role="personal_coordinator",
            serial=1, public_key_hash="a" * 64, certificate_hash="b" * 64,
            expected_ip="192.168.1.9")
        self.assertEqual(expected.ekus, ("client", "server"))
        with self.assertRaises(ValueError):
            ExpectedServerIdentity(account_id="acct_test", device_id="dev_coord",
                role="personal_coordinator", serial=1, public_key_hash="a" * 64,
                certificate_hash="b" * 64, expected_ip="192.168.1.9", ekus=("server",))

    def test_expected_server_identity_rejects_invalid_role_hash_and_dns(self):
        common = dict(account_id="acct_test", device_id="dev_test", serial=1,
                      public_key_hash=b"p" * 32, certificate_hash=b"c" * 32,
                      expected_ip="192.168.1.9")
        for changed in (dict(role="consumer"), dict(role="host", public_key_hash=b"x"),
                        dict(role="host", expected_ip="worker.example")):
            values = {**common, **changed}
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                ExpectedServerIdentity(**values)

    def test_fixed_service_names_and_worker_methods_match_wire_contract(self):
        self.assertEqual(WORKER_SERVICE, "steamboat.v1.Worker")
        self.assertEqual(COORDINATOR_SERVICE, "steamboat.v1.Coordinator")
        self.assertEqual(METHODS, ("Describe", "OpenSession", "RenewSession", "Step",
                                   "CloseSession", "CancelSession", "SessionStatus"))


class BindingAndPeerTests(unittest.TestCase):
    def test_canonical_binding_is_exact_utf8_json_and_flat_scalar_only(self):
        canonical = b'{"account_id":"acct_test","binding_version":1}'
        self.assertEqual(_canonical_binding(canonical),
                         {"account_id": "acct_test", "binding_version": 1})
        for malformed in (
                b'{ "account_id":"acct_test","binding_version":1}',
                b'{"account_id":"acct_test","account_id":"acct_other"}',
                b'{"binding_version":NaN}',
                b'{"binding_version":1.0}',
                b'{"nested":{"binding_version":1}}',
                b"\xff", b"", b" " * 4097):
            with self.subTest(malformed=malformed[:50]), self.assertRaises(AuthorizationRejected):
                _canonical_binding(malformed)

    def test_metadata_requires_one_binding_and_has_an_application_hard_cap(self):
        binding = FakeAuthorization.binding_bytes
        metadata = outgoing_binding_metadata(binding)
        self.assertEqual(metadata, ((BINDING_METADATA_KEY, binding),))
        normalized, parsed, total = validate_metadata(metadata)
        self.assertEqual(normalized, metadata)
        self.assertEqual(parsed, binding)
        self.assertLessEqual(total, MAX_METADATA_BYTES)
        with self.assertRaises(AuthorizationRejected):
            validate_metadata(((BINDING_METADATA_KEY, binding),
                               (BINDING_METADATA_KEY, binding)))
        oversized = tuple(("x-test", b"x" * 128) for _ in range(80))
        with self.assertRaises(AuthorizationRejected):
            validate_metadata(oversized, require_binding=False)

    def test_capacity_rejection_marker_is_exactly_bound_and_strictly_bounded(self):
        binding = FakeAuthorization.binding_bytes
        marker = capacity_rejection_metadata(binding)
        self.assertEqual(len(marker), 1)
        key, value = marker[0]
        self.assertEqual(key, "steamboat-capacity-rejection-bin")
        self.assertEqual(key, CAPACITY_REJECTION_METADATA_KEY)
        self.assertEqual(value, b"SNCR\x01" + hashlib.sha256(binding).digest())
        self.assertTrue(has_capacity_rejection_metadata(marker, binding))

        other_binding = b'{"account_id":"acct_other","binding_version":1}'
        other_marker = capacity_rejection_metadata(other_binding)
        self.assertTrue(has_capacity_rejection_metadata(other_marker, other_binding))
        self.assertFalse(has_capacity_rejection_metadata(other_marker, binding))
        self.assertFalse(has_capacity_rejection_metadata((), binding))
        self.assertFalse(has_capacity_rejection_metadata(
            ((key, b"SNCR\x02" + value[5:]),), binding))
        self.assertFalse(has_capacity_rejection_metadata(
            ((key, value[:-1] + bytes((value[-1] ^ 1,))),), binding))
        self.assertFalse(has_capacity_rejection_metadata((marker[0], marker[0]), binding))
        self.assertFalse(has_capacity_rejection_metadata(
            (marker[0], ("x-unrecognized", b"value")), binding))
        self.assertFalse(has_capacity_rejection_metadata(
            ((key, value + b"x" * MAX_METADATA_BYTES),), binding))
        self.assertFalse(has_capacity_rejection_metadata(
            ((key, value.decode("latin1")),), binding))
        self.assertFalse(has_capacity_rejection_metadata(((key,),), binding))
        self.assertFalse(has_capacity_rejection_metadata(((key, object()),), binding))

        with self.assertRaises(AuthorizationRejected):
            capacity_rejection_metadata(b'{"account_id": "acct_test","binding_version":1}')
        with self.assertRaises(AuthorizationRejected):
            capacity_rejection_metadata(b"x" * 4097)

    def test_peer_identity_is_read_only_from_real_tls_auth_context(self):
        class Context:
            def __init__(self, auth_context):
                self._auth_context = auth_context

            def auth_context(self):
                return self._auth_context

        certificate = b"-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----"
        self.assertEqual(_peer_certificate_from_auth_context(Context({
            "transport_security_type": (b"ssl",), "x509_pem_cert": (certificate,)})),
            certificate)
        for auth_context in (
                {"transport_security_type": (b"ssl",)},
                {"transport_security_type": (b"insecure",), "x509_pem_cert": (certificate,)},
                {"transport_security_type": (b"ssl",),
                 "x509_pem_cert": (certificate, certificate)}):
            with self.subTest(auth_context=auth_context), self.assertRaises(AuthorizationRejected):
                _peer_certificate_from_auth_context(Context(auth_context))


class ConnectionBudgetTests(unittest.TestCase):
    def test_four_one_slot_listeners_fit_and_fifth_is_rejected_by_global_pending_budget(self):
        budget = NodeConnectionBudget()
        reservations = [budget.reserve_listener(f"listener-{index}",
            connection_slots=1, pending_slots=1) for index in range(4)]
        self.assertEqual(budget.reserved_connections, 4)
        self.assertEqual(budget.reserved_pending, 0)
        self.assertEqual(budget.reserved_listener_pending_capacity, 4)
        with self.assertRaises(SecureTransportError):
            budget.reserve_listener("listener-5", connection_slots=1, pending_slots=1)
        pending = [budget.reserve_pending(f"outbound-{index}") for index in range(4)]
        self.assertEqual(budget.reserved_pending, 4)
        with self.assertRaises(SecureTransportError):
            budget.reserve_pending("fifth-live-handshake")
        for reservation in pending:
            reservation.release()
        for reservation in reservations:
            reservation.release()
        self.assertEqual((budget.reserved_connections, budget.reserved_pending,
                          budget.reserved_listener_pending_capacity), (0, 0, 0))

    def test_two_slot_profile_fits_two_listeners_and_rejects_a_third(self):
        budget = NodeConnectionBudget()
        first = budget.reserve_listener("listener-1", connection_slots=2, pending_slots=2)
        second = budget.reserve_listener("listener-2", connection_slots=2, pending_slots=2)
        self.assertEqual((budget.reserved_connections, budget.reserved_pending,
                          budget.reserved_listener_pending_capacity), (4, 0, 4))
        with self.assertRaises(SecureTransportError):
            budget.reserve_listener("listener-3", connection_slots=2, pending_slots=2)
        first.release()
        second.release()

    def test_listener_must_reserve_its_exact_supported_full_bound(self):
        budget = NodeConnectionBudget()
        for connection_slots, pending_slots in ((1, 2), (2, 1), (3, 3), (True, True)):
            with self.subTest(connection_slots=connection_slots, pending_slots=pending_slots), \
                    self.assertRaises(ValueError):
                budget.reserve_listener("listener", connection_slots=connection_slots,
                                        pending_slots=pending_slots)

    def test_node_and_per_peer_outbound_static_reservations_are_bounded(self):
        budget = NodeConnectionBudget()
        listeners = [budget.reserve_listener(f"listener-{index}",
            connection_slots=1, pending_slots=1) for index in range(4)]
        channels = [budget.reserve_outbound(f"peer-{index}") for index in range(4)]
        self.assertEqual(budget.reserved_connections, 16)
        with self.assertRaises(SecureTransportError):
            budget.reserve_outbound("peer-extra")
        peer_budget = NodeConnectionBudget()
        peer_channels = [peer_budget.reserve_outbound("same-peer") for _ in range(2)]
        with self.assertRaises(SecureTransportError):
            peer_budget.reserve_outbound("same-peer")
        for reservation in channels + listeners + peer_channels:
            reservation.release()
        self.assertEqual(budget.reserved_connections, 0)
        self.assertEqual(peer_budget.reserved_connections, 0)

    def test_outbound_pending_is_bounded_at_two_and_shared_with_inbound(self):
        budget = NodeConnectionBudget()
        first = budget.reserve_outbound_pending("peer-a")
        second = budget.reserve_outbound_pending("peer-b")
        self.assertEqual((budget.reserved_pending, budget.reserved_outbound_pending), (2, 2))
        with self.assertRaises(SecureTransportError):
            budget.reserve_outbound_pending("peer-c")
        first.release()
        second.release()
        inbound = [budget.reserve_pending(f"inbound-{index}") for index in range(4)]
        with self.assertRaises(SecureTransportError):
            budget.reserve_outbound_pending("peer-a")
        for reservation in inbound:
            reservation.release()
        self.assertEqual((budget.reserved_pending, budget.reserved_outbound_pending), (0, 0))


class OptionsAndAdapterTests(unittest.TestCase):
    def test_listener_c_core_cap_matches_selected_profile_and_limits_remain_separate(self):
        defaults = dict(_secure_options(1024 * 1024))
        self.assertEqual(defaults["grpc.max_send_message_length"], 1024 * 1024)
        self.assertEqual(defaults["grpc.max_receive_message_length"], 1024 * 1024)
        self.assertEqual(defaults["grpc.max_metadata_size"], 8192)
        self.assertEqual(defaults["grpc.absolute_max_metadata_size"], 8192)
        self.assertNotIn("grpc.enable_retries", defaults)
        for key in ("grpc.initial_reconnect_backoff_ms", "grpc.min_reconnect_backoff_ms",
                    "grpc.max_reconnect_backoff_ms"):
            self.assertNotIn(key, defaults)
        self.assertNotIn("grpc.max_allowed_incoming_connections", defaults)
        for slots in (1, 2):
            options = dict(_secure_options(1024 * 1024, listener_slots=slots))
            self.assertEqual(options["grpc.max_allowed_incoming_connections"], slots)
            self.assertEqual(options["grpc.server_handshake_timeout_ms"], 5000)
        with self.assertRaises(ValueError):
            _secure_options(1024 * 1024, listener_slots=3)

    def test_coordinator_listener_requires_explicit_profile(self):
        from steamboat_runtime.secure_coordinator_service import create_secure_coordinator_server

        parameter = inspect.signature(create_secure_coordinator_server).parameters["listener_slots"]
        self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_secure_coordinator_fails_closed_without_explicit_submit_context_seam(self):
        from types import SimpleNamespace
        from steamboat_runtime.secure_coordinator_service import SecureCoordinatorService

        class CoordinatorWithoutContext:
            def submit(self, input_ids, new_tokens, *, forced_tokens=None):
                raise AssertionError("the secure adapter must reject this legacy seam")

        class Authorizer:
            def authorize(self, **_kwargs):
                raise AssertionError("authorization must not be attempted here")

        service = SimpleNamespace(max_streams=8,
            coordinator=CoordinatorWithoutContext())
        with self.assertRaises(SecureTransportError):
            SecureCoordinatorService(service, authorizer=Authorizer(),
                authorization_watcher=lambda _authorization: None,
                request_context_factory=lambda _authorization, _payload: object(),
                max_generate_streams=4)

    def test_authorizer_receives_the_parsed_worker_request_not_a_mapping(self):
        request = Request(timeout_ms=5000)
        authorization = FakeAuthorization()
        captured = {}

        class Authorizer:
            def authorize(self, **kwargs):
                captured.update(kwargs)
                return authorization

        actual = asyncio.run(_call_authorize(Authorizer(), WORKER_SERVICE, "Describe",
            request, ((BINDING_METADATA_KEY, authorization.binding_bytes),), b"peer TLS leaf"))
        self.assertIs(actual, authorization)
        self.assertIs(captured["payload"], request)
        self.assertEqual(captured["peer_certificate_pem"], b"peer TLS leaf")
        self.assertEqual(captured["service"], WORKER_SERVICE)

    def test_authorization_failure_uses_keyword_only_lifecycle_callback(self):
        authorization = FakeAuthorization()
        asyncio.run(_fail_authorization(authorization, cache_may_exist=False))
        self.assertEqual(authorization.failed, [False])


class GuardedAuthorizationTests(unittest.IsolatedAsyncioTestCase):
    async def test_assert_live_accepts_only_exact_none_or_true(self):
        class ResultAuthorization(FakeAuthorization):
            def __init__(self, result):
                super().__init__()
                self.result = result

            def assert_live(self):
                return self.result

        await _assert_live(ResultAuthorization(None))
        await _assert_live(ResultAuthorization(True))
        for result in (False, 1, "true", object()):
            with self.subTest(result=result), self.assertRaises(AuthorizationRevoked):
                await _assert_live(ResultAuthorization(result))

    async def test_assert_live_applies_same_predicate_to_awaited_results(self):
        class AsyncResultAuthorization(FakeAuthorization):
            def __init__(self, result):
                super().__init__()
                self.result = result

            async def assert_live(self):
                return self.result

        await _assert_live(AsyncResultAuthorization(None))
        await _assert_live(AsyncResultAuthorization(True))
        for result in (False, 1, "true", object()):
            with self.subTest(result=result), self.assertRaises(AuthorizationRevoked):
                await _assert_live(AsyncResultAuthorization(result))

    async def test_time_of_check_expiry_does_not_schedule_work_and_cancels_call(self):
        class ExpiresAfterAssertion(FakeAuthorization):
            def remaining_seconds(self):
                return 0

        dispatched = False
        cancelled = []

        async def operation():
            nonlocal dispatched
            dispatched = True

        async def watcher(_authorization):
            await asyncio.Future()

        with self.assertRaises(AuthorizationRevoked):
            await _run_guarded(operation(), ExpiresAfterAssertion(), watcher,
                timeout=1, cancel_callback=lambda: cancelled.append(True))
        self.assertFalse(dispatched)
        self.assertEqual(cancelled, [True])

    async def test_absolute_auth_deadline_clips_work_and_cancels_it(self):
        authorization = FakeAuthorization(remaining=0.03)
        cancelled = asyncio.Event()

        async def operation():
            try:
                await asyncio.sleep(1)
            finally:
                cancelled.set()

        async def watcher(_authorization):
            await asyncio.Future()

        with self.assertRaises(AuthorizationRevoked):
            await _run_guarded(operation(), authorization, watcher, timeout=2)
        self.assertTrue(cancelled.is_set())

    async def test_revocation_watcher_cancels_active_work(self):
        authorization = FakeAuthorization(remaining=2)
        cancelled = asyncio.Event()

        async def operation():
            try:
                await asyncio.sleep(1)
            finally:
                cancelled.set()

        async def watcher(_authorization):
            await asyncio.sleep(0.01)

        with self.assertRaises(AuthorizationRevoked):
            await _run_guarded(operation(), authorization, watcher, timeout=1)
        self.assertTrue(cancelled.is_set())

    async def test_request_timeout_remains_an_explicit_timeout(self):
        authorization = FakeAuthorization(remaining=5)

        async def watcher(_authorization):
            await asyncio.Future()

        with self.assertRaises(TimeoutError):
            await _run_guarded(asyncio.sleep(1), authorization, watcher, timeout=0.01)

    async def test_cancellation_swallowing_watcher_is_bounded_and_does_not_cancel_completed_call(self):
        authorization = FakeAuthorization(remaining=2)
        release = asyncio.Event()
        call_cancellations = []

        async def watcher(_authorization):
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                await release.wait()

        with self.assertRaises(SecureTaskPending):
            await _run_guarded(asyncio.sleep(0), authorization, watcher,
                timeout=1, cancel_callback=lambda: call_cancellations.append(True),
                cancel_grace_seconds=0.01)
        self.assertEqual(call_cancellations, [])
        release.set()
        for _ in range(20):
            if authorization.closed:
                break
            await asyncio.sleep(0.01)
        self.assertTrue(authorization.closed)

    async def test_nested_pending_watcher_child_retains_authorization_until_child_exits(self):
        authorization = FakeAuthorization(remaining=2)
        release_child = asyncio.Event()
        child_started = asyncio.Event()
        pending_children = []

        async def cancellation_resistant_child():
            child_started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                await release_child.wait()

        async def watcher(_authorization):
            child = asyncio.create_task(cancellation_resistant_child())
            pending_children.append(child)
            try:
                await asyncio.Future()
            finally:
                await _cancel_tasks_bounded((child,), grace=0.01,
                    message="nested watcher child did not stop")

        async def operation():
            await child_started.wait()

        with self.assertRaises(SecureTaskPending) as raised:
            await _run_guarded(operation(), authorization, watcher,
                timeout=1, cancel_grace_seconds=0.1,
                on_pending=lambda tasks: pending_children.extend(
                    task for task in tasks if task not in pending_children))
        await asyncio.wait_for(child_started.wait(), 0.2)
        child = pending_children[0]
        self.assertIn(child, raised.exception.tasks)
        self.assertFalse(authorization.closed)

        release_child.set()
        await asyncio.wait_for(child, 0.5)
        for _ in range(50):
            if authorization.closed:
                break
            await asyncio.sleep(0.01)
        self.assertTrue(authorization.closed)

    async def test_second_cancellation_transfers_authorization_until_work_exits(self):
        authorization = FakeAuthorization(remaining=2)
        started = asyncio.Event()
        cancellation_seen = asyncio.Event()
        release = asyncio.Event()
        retained = []

        async def operation():
            started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancellation_seen.set()
                await release.wait()
                raise

        async def watcher(_authorization):
            await asyncio.Future()

        task = asyncio.create_task(_run_guarded(
            operation(), authorization, watcher, timeout=10,
            cancel_grace_seconds=0.5, on_pending=lambda pending: retained.extend(pending)))
        await asyncio.wait_for(started.wait(), 0.5)
        task.cancel()
        await asyncio.wait_for(cancellation_seen.wait(), 0.5)
        task.cancel()
        with self.assertRaises(SecureTaskPending):
            await asyncio.wait_for(task, 0.5)
        self.assertTrue(retained)
        self.assertFalse(authorization.closed)
        release.set()
        for _ in range(50):
            if authorization.closed:
                break
            await asyncio.sleep(0.01)
        self.assertTrue(authorization.closed)


class GuardMonitorRetirementTests(unittest.IsolatedAsyncioTestCase):
    class Authorization(FakeAuthorization):
        def __init__(self):
            super().__init__()
            self.close_calls = 0
            self.closed_event = asyncio.Event()

        def close(self):
            self.close_calls += 1
            self.closed_event.set()
            super().close()

    async def _exercise_completed_monitor_graph(self, *, release_order,
                                                close_authorization=True,
                                                monitor_pending_type=SecureConnectorPending):
        authorization = self.Authorization()
        retained_before = set(_RETAINED_TASKS)
        references = {}
        reported = []
        operation_started = asyncio.Event()
        operation_cancel_seen = asyncio.Event()
        release_operation_root = asyncio.Event()
        operation_child_started = asyncio.Event()
        release_operation_child = asyncio.Event()
        monitor_child_started = asyncio.Event()
        release_monitor_child = asyncio.Event()
        trigger_monitor = asyncio.Event()
        watcher_ready = asyncio.Event()
        caller = None
        grace = 0.04

        async def operation_child_work():
            operation_child_started.set()
            await release_operation_child.wait()

        async def monitor_child_work():
            monitor_child_started.set()
            await release_monitor_child.wait()

        async def operation():
            references["operation"] = asyncio.current_task()
            operation_started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                operation_cancel_seen.set()
                await release_operation_root.wait()
                child = asyncio.create_task(operation_child_work())
                references["operation_child"] = child
                await operation_child_started.wait()
                raise SecureTaskPending((child,), "operation child remains live")

        async def watcher(_authorization):
            references["monitor"] = asyncio.current_task()
            child = asyncio.create_task(monitor_child_work())
            references["monitor_child"] = child
            await monitor_child_started.wait()
            watcher_ready.set()
            await trigger_monitor.wait()
            raise monitor_pending_type((child,), "watcher child remains live")

        def retain(tasks):
            reported.append(set(tasks))

        async def cleanup():
            trigger_monitor.set()
            release_operation_root.set()
            release_operation_child.set()
            release_monitor_child.set()
            if caller is not None and not caller.done():
                caller.cancel()
            if caller is not None:
                done, pending = await asyncio.wait((caller,), timeout=1)
                if pending:
                    caller.cancel()
                    done, pending = await asyncio.wait(pending, timeout=1)
                if pending:
                    raise AssertionError("guard caller did not finish during cleanup")
                result = (await asyncio.gather(*done, return_exceptions=True))[0]
                if result is not None and not isinstance(
                        result, (SecureTaskPending, asyncio.CancelledError)):
                    raise AssertionError("guard caller failed unexpectedly") from result
            tasks = tuple(task for task in references.values()
                          if isinstance(task, asyncio.Task))
            if tasks:
                done, pending = await asyncio.wait(tasks, timeout=1)
                if pending:
                    for task in pending:
                        task.cancel()
                    done, pending = await asyncio.wait(pending, timeout=1)
                if pending:
                    raise AssertionError("guard task graph did not drain")
                results = await asyncio.gather(*done, return_exceptions=True)
                unexpected = [result for result in results
                              if isinstance(result, BaseException)
                              and not isinstance(result, (asyncio.CancelledError,
                                                          SecureTaskPending,
                                                          SecureConnectorPending))]
                if unexpected:
                    raise AssertionError("guard task graph failed unexpectedly") from unexpected[0]
            owner_tasks = tuple(_RETAINED_TASKS - retained_before)
            if owner_tasks:
                await asyncio.wait_for(_wait_owned_tasks(owner_tasks), 1)

        self.addAsyncCleanup(cleanup)
        caller = asyncio.create_task(_run_guarded(
            operation(), authorization, watcher, timeout=3,
            cancel_grace_seconds=grace, on_pending=retain,
            close_authorization_on_pending=close_authorization))
        await asyncio.wait_for(asyncio.gather(
            operation_started.wait(), watcher_ready.wait()), 0.5)
        started = time.monotonic()
        trigger_monitor.set()
        done, pending = await asyncio.wait((caller,), timeout=0.3)
        elapsed = time.monotonic() - started
        self.assertFalse(pending, "completed-monitor handoff must stay bounded")
        self.assertLess(elapsed, 0.25,
                        "finding the completed monitor graph must not add a second grace")
        with self.assertRaises(SecureTaskPending) as handoff:
            await caller

        operation_task = references["operation"]
        monitor_child = references["monitor_child"]
        self.assertIn(operation_task, handoff.exception.tasks)
        self.assertIn(monitor_child, handoff.exception.tasks)
        self.assertTrue(any(operation_task in tasks for tasks in reported))
        self.assertTrue(any(monitor_child in tasks for tasks in reported))
        self.assertIn(operation_task, _RETAINED_TASKS - retained_before)
        self.assertIn(monitor_child, _RETAINED_TASKS - retained_before)
        self.assertFalse(authorization.closed)
        self.assertEqual(authorization.close_calls, 0)
        self.assertEqual(authorization.failed, [])

        async def retire_operation_graph():
            release_operation_root.set()
            await asyncio.wait_for(operation_child_started.wait(), 0.3)
            operation_result = (await asyncio.wait_for(asyncio.gather(
                operation_task, return_exceptions=True), 0.3))[0]
            self.assertIsInstance(operation_result, SecureTaskPending)
            release_operation_child.set()
            await asyncio.wait_for(references["operation_child"], 0.3)

        if release_order == "operation-first":
            await retire_operation_graph()
            await asyncio.sleep(0)
            self.assertFalse(authorization.closed,
                             "the monitor graph still owns the authorization")
            release_monitor_child.set()
            await asyncio.wait_for(monitor_child, 0.3)
        else:
            release_monitor_child.set()
            await asyncio.wait_for(monitor_child, 0.3)
            await asyncio.sleep(0)
            self.assertFalse(authorization.closed,
                             "the operation graph still owns the authorization")
            await retire_operation_graph()

        if close_authorization:
            await asyncio.wait_for(authorization.closed_event.wait(), 0.5)
            self.assertEqual(authorization.failed, [True])
            self.assertEqual(authorization.close_calls, 1)
            self.assertTrue(authorization.closed)
        else:
            await asyncio.sleep(0)
            self.assertEqual(authorization.failed, [])
            self.assertEqual(authorization.close_calls, 0)
            self.assertFalse(authorization.closed,
                             "caller-owned mode leaves closure to its runtime owner")

    async def test_completed_monitor_graph_is_merged_before_single_close_owner_op_first(self):
        await self._exercise_completed_monitor_graph(release_order="operation-first")

    async def test_completed_monitor_graph_is_merged_before_single_close_owner_monitor_first(self):
        await self._exercise_completed_monitor_graph(release_order="monitor-first")

    async def test_caller_owned_mode_retains_both_roots_without_guard_closure(self):
        await self._exercise_completed_monitor_graph(
            release_order="operation-first", close_authorization=False,
            monitor_pending_type=SecureTaskPending)

    async def _exercise_successful_operation_monitor_error(
            self, monitor_error_type, expected_type):
        authorization = self.Authorization()
        watcher_ready = asyncio.Event()
        monitor_cancel_seen = asyncio.Event()
        release_operation = asyncio.Event()
        release_monitor_error = asyncio.Event()
        caller = None
        monitor_error = None

        async def operation():
            await release_operation.wait()
            return "operation-result-must-not-escape"

        async def watcher(_authorization):
            nonlocal monitor_error
            watcher_ready.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                monitor_cancel_seen.set()
                await release_monitor_error.wait()
                if monitor_error_type in (SecureTaskPending,
                                          SecureConnectorPending):
                    completed = asyncio.create_task(asyncio.sleep(0))
                    await completed
                    monitor_error = monitor_error_type(
                        (completed,), "exhausted monitor pending report")
                else:
                    monitor_error = monitor_error_type(
                        "monitor terminal failure")
                raise monitor_error

        async def cleanup():
            release_operation.set()
            release_monitor_error.set()
            if caller is not None and not caller.done():
                caller.cancel()
            if caller is not None:
                done, pending = await asyncio.wait((caller,), timeout=1)
                if pending:
                    caller.cancel()
                    done, pending = await asyncio.wait(pending, timeout=1)
                if pending:
                    raise AssertionError("monitor failure caller did not drain")
                result = (await asyncio.gather(
                    *done, return_exceptions=True))[0]
                if result is not None and not isinstance(
                        result, (expected_type, asyncio.CancelledError)):
                    raise AssertionError(
                        "monitor failure caller failed unexpectedly") from result

        self.addAsyncCleanup(cleanup)
        caller = asyncio.create_task(_run_guarded(
            operation(), authorization, watcher, timeout=3,
            cancel_grace_seconds=0.1))
        await asyncio.wait_for(watcher_ready.wait(), 0.5)
        release_operation.set()
        await asyncio.wait_for(monitor_cancel_seen.wait(), 0.5)
        release_monitor_error.set()
        with self.assertRaises(expected_type) as raised:
            await asyncio.wait_for(caller, 0.5)
        self.assertIsNotNone(monitor_error)
        self.assertNotEqual(raised.exception, "operation-result-must-not-escape")
        if monitor_error_type in (SecureTaskPending, SecureConnectorPending):
            self.assertIsInstance(raised.exception, AuthorizationRevoked)
            self.assertIs(raised.exception.__cause__, monitor_error)
        else:
            self.assertIs(raised.exception, monitor_error)

    async def test_successful_operation_never_succeeds_after_monitor_terminal_error(self):
        cases = (
            ("authorization_revoked", AuthorizationRevoked,
             AuthorizationRevoked),
            ("ordinary_error", RuntimeError, RuntimeError),
            ("exhausted_secure_pending", SecureTaskPending,
             AuthorizationRevoked),
            ("exhausted_connector_pending", SecureConnectorPending,
             AuthorizationRevoked),
        )
        for label, monitor_error_type, expected_type in cases:
            with self.subTest(monitor_error=label):
                await self._exercise_successful_operation_monitor_error(
                    monitor_error_type, expected_type)

    async def test_operation_pending_remains_primary_with_monitor_error_as_cause(self):
        authorization = self.Authorization()
        retained_before = set(_RETAINED_TASKS)
        references = {}
        reported = []
        child_started = asyncio.Event()
        release_child = asyncio.Event()
        watcher_ready = asyncio.Event()
        monitor_cancel_seen = asyncio.Event()
        release_monitor_error = asyncio.Event()
        caller = None
        monitor_error = RuntimeError("monitor failed while retiring")

        async def child_work():
            child_started.set()
            await release_child.wait()

        async def operation():
            child = asyncio.create_task(child_work())
            references["child"] = child
            await child_started.wait()
            pending = SecureTaskPending((child,), "primary operation handoff")
            references["primary"] = pending
            raise pending

        async def watcher(_authorization):
            references["monitor"] = asyncio.current_task()
            watcher_ready.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                monitor_cancel_seen.set()
                await release_monitor_error.wait()
                raise monitor_error

        def retain(tasks):
            reported.append(set(tasks))

        async def cleanup():
            release_child.set()
            release_monitor_error.set()
            if caller is not None and not caller.done():
                caller.cancel()
            if caller is not None:
                done, pending = await asyncio.wait((caller,), timeout=1)
                if pending:
                    caller.cancel()
                    done, pending = await asyncio.wait(pending, timeout=1)
                if pending:
                    raise AssertionError("primary handoff caller did not drain")
                result = (await asyncio.gather(
                    *done, return_exceptions=True))[0]
                if result is not None and not isinstance(
                        result, (SecureTaskPending, asyncio.CancelledError)):
                    raise AssertionError("primary handoff failed unexpectedly") from result
            tasks = tuple(task for task in references.values()
                          if isinstance(task, asyncio.Task))
            if tasks:
                done, pending = await asyncio.wait(tasks, timeout=1)
                if pending:
                    raise AssertionError("primary handoff task graph did not drain")
                await asyncio.gather(*done, return_exceptions=True)
            owner_tasks = tuple(_RETAINED_TASKS - retained_before)
            if owner_tasks:
                await asyncio.wait_for(_wait_owned_tasks(owner_tasks), 1)

        self.addAsyncCleanup(cleanup)
        caller = asyncio.create_task(_run_guarded(
            operation(), authorization, watcher, timeout=3,
            cancel_grace_seconds=0.1, on_pending=retain))
        await asyncio.wait_for(watcher_ready.wait(), 0.5)
        await asyncio.wait_for(monitor_cancel_seen.wait(), 0.5)
        release_monitor_error.set()
        with self.assertRaises(SecureTaskPending) as raised:
            await asyncio.wait_for(caller, 0.5)

        child = references["child"]
        self.assertIs(raised.exception, references["primary"])
        self.assertIs(raised.exception.__cause__, monitor_error)
        self.assertIn(child, raised.exception.tasks)
        self.assertTrue(any(child in tasks for tasks in reported))
        self.assertIn(child, _RETAINED_TASKS - retained_before)
        self.assertEqual(authorization.close_calls, 0)
        self.assertFalse(authorization.closed)

        release_child.set()
        await asyncio.wait_for(child, 0.5)
        await asyncio.wait_for(authorization.closed_event.wait(), 0.5)
        self.assertEqual(authorization.failed, [True])
        self.assertEqual(authorization.close_calls, 1)

    def _assert_exception_chain_acyclic(self, root):
        visiting = set()
        visited = set()

        def visit(error):
            if not isinstance(error, BaseException):
                return
            identity = id(error)
            if identity in visiting:
                self.fail("exception __cause__/__context__ graph contains a cycle")
            if identity in visited:
                return
            visiting.add(identity)
            visit(error.__cause__)
            visit(error.__context__)
            visiting.remove(identity)
            visited.add(identity)

        visit(root)

    async def _exercise_finalizer_cancellation_preserves_pending(
            self, *, guard_owns_close, with_explicit_cause, monitor_pending):
        authorization = self.Authorization()
        retained_before = set(_RETAINED_TASKS)
        references = {}
        reported = []
        child_started = asyncio.Event()
        release_child = asyncio.Event()
        watcher_started = asyncio.Event()
        monitor_cancel_seen = asyncio.Event()
        release_monitor = asyncio.Event()
        monitor_child_started = asyncio.Event()
        release_monitor_child = asyncio.Event()
        caller = None
        primary_cause = RuntimeError("operation's original pending cause")

        async def child_work():
            child_started.set()
            await release_child.wait()

        async def monitor_child_work():
            monitor_child_started.set()
            await release_monitor_child.wait()

        async def operation():
            child = asyncio.create_task(child_work())
            references["child"] = child
            await child_started.wait()
            pending = SecureTaskPending((child,), "original pending handoff")
            references["primary"] = pending
            if with_explicit_cause:
                raise pending from primary_cause
            raise pending

        async def watcher(_authorization):
            references["monitor"] = asyncio.current_task()
            watcher_started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                monitor_cancel_seen.set()
                await release_monitor.wait()
                if monitor_pending:
                    monitor_child = asyncio.create_task(monitor_child_work())
                    references["monitor_child"] = monitor_child
                    await monitor_child_started.wait()
                # Schedule caller cancellation immediately before this monitor
                # retires, making the finalizer's interrupted-wait edge stable.
                caller.cancel()
                if monitor_pending:
                    raise SecureTaskPending(
                        (references["monitor_child"],),
                        "monitor reports a live descendant")
                raise

        def retain(tasks):
            reported.append(set(tasks))

        async def cleanup():
            release_child.set()
            release_monitor.set()
            release_monitor_child.set()
            if caller is not None and not caller.done():
                caller.cancel()
            if caller is not None:
                done, pending = await asyncio.wait((caller,), timeout=1)
                if pending:
                    caller.cancel()
                    done, pending = await asyncio.wait(pending, timeout=1)
                if pending:
                    raise AssertionError("interrupted pending handoff caller did not drain")
                await asyncio.gather(*done, return_exceptions=True)
            tasks = tuple(task for task in references.values()
                          if isinstance(task, asyncio.Task))
            if tasks:
                done, pending = await asyncio.wait(tasks, timeout=1)
                if pending:
                    raise AssertionError("interrupted pending handoff roots did not drain")
                await asyncio.gather(*done, return_exceptions=True)
            owner_tasks = tuple(_RETAINED_TASKS - retained_before)
            if owner_tasks:
                await asyncio.wait_for(_wait_owned_tasks(owner_tasks), 1)

        self.addAsyncCleanup(cleanup)
        caller = asyncio.create_task(_run_guarded(
            operation(), authorization, watcher, timeout=3,
            cancel_grace_seconds=0.1, on_pending=retain,
            close_authorization_on_pending=guard_owns_close))
        await asyncio.wait_for(watcher_started.wait(), 0.5)
        await asyncio.wait_for(child_started.wait(), 0.5)
        await asyncio.wait_for(monitor_cancel_seen.wait(), 0.5)
        release_monitor.set()
        with self.assertRaises(SecureTaskPending) as raised:
            await asyncio.wait_for(caller, 0.5)

        primary = references["primary"]
        child = references["child"]
        self.assertIs(raised.exception, primary)
        self.assertTrue(primary.authorization_transferred)
        self.assertIn(child, primary.tasks)
        if monitor_pending:
            self.assertIn(references["monitor_child"], primary.tasks,
                          "the monitor-pending roots must merge into the primary handoff")
        else:
            self.assertIsInstance(primary.__cause__ if not with_explicit_cause
                                  else primary.__context__,
                                  asyncio.CancelledError)
        if with_explicit_cause:
            self.assertIs(primary.__cause__, primary_cause,
                          "the operation's original explicit cause must remain intact")
        else:
            self.assertIsNotNone(primary.__cause__)
        self._assert_exception_chain_acyclic(primary)
        self.assertTrue(references["monitor"].done())
        self.assertTrue(any(child in tasks for tasks in reported))
        self.assertIn(child, _RETAINED_TASKS - retained_before)
        if monitor_pending:
            monitor_child = references["monitor_child"]
            self.assertIn(monitor_child, _RETAINED_TASKS - retained_before)
            self.assertTrue(any(monitor_child in tasks for tasks in reported))
        self.assertFalse(authorization.closed)
        self.assertEqual(authorization.failed, [])
        self.assertEqual(authorization.close_calls, 0)

        release_child.set()
        release_monitor_child.set()
        await asyncio.wait_for(child, 0.5)
        if monitor_pending:
            await asyncio.wait_for(references["monitor_child"], 0.5)
        if guard_owns_close:
            await asyncio.wait_for(authorization.closed_event.wait(), 0.5)
            self.assertEqual(authorization.failed, [True])
            self.assertEqual(authorization.close_calls, 1)
        else:
            await asyncio.sleep(0)
            self.assertEqual(authorization.failed, [])
            self.assertEqual(authorization.close_calls, 0)
            self.assertFalse(authorization.closed,
                             "caller-owned mode must leave authorization closure outside the guard")

    async def test_finalizer_cancellation_preserves_pending_handoff_and_single_close(self):
        for with_explicit_cause in (False, True):
            for monitor_pending in (False, True):
                with self.subTest(with_explicit_cause=with_explicit_cause,
                                  monitor_pending=monitor_pending):
                    await self._exercise_finalizer_cancellation_preserves_pending(
                        guard_owns_close=True,
                        with_explicit_cause=with_explicit_cause,
                        monitor_pending=monitor_pending)

    async def test_finalizer_cancellation_preserves_pending_in_caller_owned_mode(self):
        for with_explicit_cause in (False, True):
            for monitor_pending in (False, True):
                with self.subTest(with_explicit_cause=with_explicit_cause,
                                  monitor_pending=monitor_pending):
                    await self._exercise_finalizer_cancellation_preserves_pending(
                        guard_owns_close=False,
                        with_explicit_cause=with_explicit_cause,
                        monitor_pending=monitor_pending)

    async def test_ordinary_caller_cancellation_stays_cancelled_without_pending_handoff(self):
        authorization = self.Authorization()
        operation_started = asyncio.Event()
        watcher_started = asyncio.Event()
        caller = None

        async def operation():
            operation_started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                return

        async def watcher(_authorization):
            watcher_started.set()
            await asyncio.Future()

        caller = asyncio.create_task(_run_guarded(
            operation(), authorization, watcher, timeout=3,
            cancel_grace_seconds=0.1))
        await asyncio.wait_for(asyncio.gather(
            operation_started.wait(), watcher_started.wait()), 0.5)
        caller.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(caller, 0.5)
        self.assertEqual(authorization.failed, [])
        self.assertEqual(authorization.close_calls, 0)
        self.assertFalse(authorization.closed)

    async def test_operation_pending_cancels_live_monitor_with_one_grace(self):
        authorization = self.Authorization()
        retained_before = set(_RETAINED_TASKS)
        references = {}
        reported = []
        operation_child_started = asyncio.Event()
        release_operation_child = asyncio.Event()
        watcher_started = asyncio.Event()
        watcher_cancel_seen = asyncio.Event()
        release_watcher = asyncio.Event()
        caller = None
        grace = 0.04

        async def operation_child_work():
            operation_child_started.set()
            await release_operation_child.wait()

        async def operation():
            child = asyncio.create_task(operation_child_work())
            references["operation_child"] = child
            await operation_child_started.wait()
            raise SecureTaskPending((child,), "operation child remains live")

        async def watcher(_authorization):
            references["monitor"] = asyncio.current_task()
            watcher_started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                watcher_cancel_seen.set()
                await release_watcher.wait()
                raise

        def retain(tasks):
            reported.append(set(tasks))

        async def cleanup():
            release_operation_child.set()
            release_watcher.set()
            if caller is not None and not caller.done():
                caller.cancel()
            if caller is not None:
                done, pending = await asyncio.wait((caller,), timeout=1)
                if pending:
                    caller.cancel()
                    done, pending = await asyncio.wait(pending, timeout=1)
                if pending:
                    raise AssertionError("operation-pending guard did not drain")
                result = (await asyncio.gather(*done, return_exceptions=True))[0]
                if result is not None and not isinstance(
                        result, (SecureTaskPending, asyncio.CancelledError)):
                    raise AssertionError("operation-pending guard failed unexpectedly") from result
            tasks = tuple(task for task in references.values()
                          if isinstance(task, asyncio.Task))
            if tasks:
                done, pending = await asyncio.wait(tasks, timeout=1)
                if pending:
                    raise AssertionError("operation-pending roots did not drain")
                await asyncio.gather(*done, return_exceptions=True)
            owner_tasks = tuple(_RETAINED_TASKS - retained_before)
            if owner_tasks:
                await asyncio.wait_for(_wait_owned_tasks(owner_tasks), 1)

        self.addAsyncCleanup(cleanup)
        caller = asyncio.create_task(_run_guarded(
            operation(), authorization, watcher, timeout=3,
            cancel_grace_seconds=grace, on_pending=retain))
        await asyncio.wait_for(watcher_started.wait(), 0.5)
        started = time.monotonic()
        done, pending = await asyncio.wait((caller,), timeout=0.3)
        elapsed = time.monotonic() - started
        self.assertFalse(pending, "live-monitor retirement must stay bounded")
        self.assertLess(elapsed, 0.25,
                        "operation pending plus monitor retirement gets one grace")
        self.assertTrue(watcher_cancel_seen.is_set())
        with self.assertRaises(SecureTaskPending) as handoff:
            await caller

        operation_child = references["operation_child"]
        monitor = references["monitor"]
        self.assertIn(operation_child, handoff.exception.tasks)
        self.assertIn(monitor, handoff.exception.tasks)
        self.assertTrue(any(operation_child in tasks for tasks in reported))
        self.assertTrue(any(monitor in tasks for tasks in reported))
        self.assertFalse(authorization.closed)
        self.assertEqual(authorization.close_calls, 0)

        release_operation_child.set()
        await asyncio.wait_for(operation_child, 0.3)
        await asyncio.sleep(0)
        self.assertFalse(authorization.closed,
                         "the still-running monitor remains an owned root")
        release_watcher.set()
        monitor_result = (await asyncio.wait_for(asyncio.gather(
            monitor, return_exceptions=True), 0.3))[0]
        self.assertIsInstance(monitor_result, asyncio.CancelledError)
        await asyncio.wait_for(authorization.closed_event.wait(), 0.5)
        self.assertEqual(authorization.failed, [True])
        self.assertEqual(authorization.close_calls, 1)

    async def test_repeated_caller_cancellation_does_not_restart_joint_grace(self):
        authorization = self.Authorization()
        retained_before = set(_RETAINED_TASKS)
        references = {}
        reported = []
        operation_started = asyncio.Event()
        operation_cancel_seen = asyncio.Event()
        release_operation = asyncio.Event()
        watcher_started = asyncio.Event()
        watcher_cancel_seen = asyncio.Event()
        release_watcher = asyncio.Event()
        monitor_child_started = asyncio.Event()
        release_monitor_child = asyncio.Event()
        caller = None
        grace = 0.06

        async def monitor_child_work():
            monitor_child_started.set()
            await release_monitor_child.wait()

        async def operation():
            references["operation"] = asyncio.current_task()
            operation_started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                operation_cancel_seen.set()
                await release_operation.wait()

        async def watcher(_authorization):
            references["monitor"] = asyncio.current_task()
            watcher_started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                watcher_cancel_seen.set()
                await release_watcher.wait()
                child = asyncio.create_task(monitor_child_work())
                references["monitor_child"] = child
                await monitor_child_started.wait()
                raise SecureConnectorPending((child,), "late watcher child")

        def retain(tasks):
            reported.append(set(tasks))

        async def cleanup():
            release_operation.set()
            release_watcher.set()
            release_monitor_child.set()
            if caller is not None and not caller.done():
                caller.cancel()
            if caller is not None:
                done, pending = await asyncio.wait((caller,), timeout=1)
                if pending:
                    caller.cancel()
                    done, pending = await asyncio.wait(pending, timeout=1)
                if pending:
                    raise AssertionError("repeated-cancel guard did not drain")
                result = (await asyncio.gather(*done, return_exceptions=True))[0]
                if result is not None and not isinstance(
                        result, (SecureTaskPending, asyncio.CancelledError)):
                    raise AssertionError("repeated-cancel guard failed unexpectedly") from result
            tasks = tuple(task for task in references.values()
                          if isinstance(task, asyncio.Task))
            if tasks:
                done, pending = await asyncio.wait(tasks, timeout=1)
                if pending:
                    raise AssertionError("repeated-cancel roots did not drain")
                await asyncio.gather(*done, return_exceptions=True)
            owner_tasks = tuple(_RETAINED_TASKS - retained_before)
            if owner_tasks:
                await asyncio.wait_for(_wait_owned_tasks(owner_tasks), 1)

        self.addAsyncCleanup(cleanup)
        caller = asyncio.create_task(_run_guarded(
            operation(), authorization, watcher, timeout=3,
            cancel_grace_seconds=grace, on_pending=retain))
        await asyncio.wait_for(asyncio.gather(
            operation_started.wait(), watcher_started.wait()), 0.5)
        started = time.monotonic()
        caller.cancel()
        await asyncio.wait_for(asyncio.gather(
            operation_cancel_seen.wait(), watcher_cancel_seen.wait()), 0.5)
        caller.cancel()
        done, pending = await asyncio.wait((caller,), timeout=0.3)
        elapsed = time.monotonic() - started
        self.assertFalse(pending, "repeated caller cancellation must hand off promptly")
        self.assertLess(elapsed, 0.25,
                        "joint root cancellation must not restart its retirement grace")
        with self.assertRaises(SecureTaskPending) as handoff:
            await caller

        operation_task = references["operation"]
        monitor = references["monitor"]
        self.assertIn(operation_task, handoff.exception.tasks)
        self.assertIn(monitor, handoff.exception.tasks)
        self.assertIn(operation_task, _RETAINED_TASKS - retained_before)
        self.assertIn(monitor, _RETAINED_TASKS - retained_before)
        self.assertTrue(any(operation_task in tasks for tasks in reported))
        self.assertTrue(any(monitor in tasks for tasks in reported))
        self.assertFalse(authorization.closed)

        release_operation.set()
        await asyncio.wait_for(operation_task, 0.3)
        await asyncio.sleep(0)
        self.assertFalse(authorization.closed,
                         "the monitor root remains owned after operation retirement")
        release_watcher.set()
        await asyncio.wait_for(monitor_child_started.wait(), 0.3)
        monitor_child = references["monitor_child"]
        monitor_result = (await asyncio.wait_for(asyncio.gather(
            monitor, return_exceptions=True), 0.3))[0]
        self.assertIsInstance(monitor_result, SecureConnectorPending)
        await asyncio.sleep(0)
        self.assertFalse(authorization.closed,
                         "late monitor child remains owned after its root retires")
        release_monitor_child.set()
        await asyncio.wait_for(monitor_child, 0.3)
        await asyncio.wait_for(authorization.closed_event.wait(), 0.5)
        self.assertEqual(authorization.failed, [True])
        self.assertEqual(authorization.close_calls, 1)


class PendingExceptionOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_pending_descendants_survive_await_and_gather_until_deferred_auth_close(self):
        self.assertFalse(issubclass(SecureTaskPending, asyncio.CancelledError))
        self.assertFalse(issubclass(SecureConnectorPending, asyncio.CancelledError))
        for pending_type in (SecureTaskPending, SecureConnectorPending):
            for observation in ("await", "exception", "gather"):
                with self.subTest(pending_type=pending_type.__name__,
                                  observation=observation):
                    release_child = asyncio.Event()
                    child_started = asyncio.Event()
                    descendants = []
                    authorization = FakeAuthorization()
                    deferred_close = None
                    owner = None

                    async def child_work():
                        child_started.set()
                        await release_child.wait()

                    async def report_pending_child():
                        child = asyncio.create_task(child_work())
                        descendants.append(child)
                        await child_started.wait()
                        raise pending_type((child,), "nested cleanup is still pending")

                    owner = asyncio.create_task(report_pending_child())
                    try:
                        await asyncio.wait_for(child_started.wait(), 0.5)
                        if observation == "await":
                            with self.assertRaises(pending_type):
                                await owner
                            self.assertIsInstance(owner.exception(), pending_type)
                        elif observation == "exception":
                            await asyncio.sleep(0)
                            self.assertTrue(owner.done())
                            self.assertIsInstance(owner.exception(), pending_type)
                        else:
                            observed = await asyncio.gather(owner, return_exceptions=True)
                            self.assertIsInstance(observed[0], pending_type)

                        child = descendants[0]
                        self.assertFalse(child.done())
                        deferred_close = _retain_authorization_close_until_done(
                            authorization, (owner,))
                        waiter = asyncio.create_task(_wait_owned_tasks((owner,)))
                        await asyncio.sleep(0)
                        self.assertFalse(waiter.done(),
                            "wait_owned_tasks lost a pending descendant after observing its owner")
                        self.assertFalse(authorization.closed,
                            "authorization closed before the pending descendant finished")

                        release_child.set()
                        await asyncio.wait_for(child, 0.5)
                        await asyncio.wait_for(waiter, 0.5)
                        await asyncio.wait_for(deferred_close, 0.5)
                        self.assertTrue(authorization.closed)
                    finally:
                        release_child.set()
                        if descendants:
                            await asyncio.gather(*descendants, return_exceptions=True)
                        if deferred_close is not None:
                            await asyncio.gather(deferred_close, return_exceptions=True)
                        if owner is not None:
                            if not owner.done():
                                owner.cancel()
                            await asyncio.gather(owner, return_exceptions=True)


class OutboundPendingHandshakeTests(unittest.IsolatedAsyncioTestCase):
    class Connector:
        def __init__(self, *_args, **kwargs):
            self.failed = False
            self.failure = asyncio.Event()
            self.closed = False
            self.pending_reservation = kwargs["pending_reservation"]

        async def start(self):
            return self

        def channel_options(self):
            return (("test.connector", True),)

        def stop_accepting(self):
            return None

        async def confirm_ready(self):
            self.pending_reservation.release()
            self.pending_reservation = None

        async def wait_failure(self):
            await self.failure.wait()

        async def close(self, *, grace=5):
            if self.pending_reservation is not None:
                self.pending_reservation.release()
                self.pending_reservation = None
            self.closed = True

    class Channel:
        def __init__(self, *, ready=True):
            self.state = type("State", (), {"name": "CONNECTING"})()
            self.ready = ready
            self.closed = asyncio.Event()

        async def channel_ready(self):
            if not self.ready:
                await asyncio.Future()
            self.state = type("State", (), {"name": "READY"})()

        def get_state(self, try_to_connect=False):
            return self.state

        async def wait_for_state_change(self, state):
            await self.closed.wait()

        async def close(self):
            self.state = type("State", (), {"name": "SHUTDOWN"})()
            self.closed.set()

    async def test_outbound_pending_is_shared_and_reserved_before_channel_construction(self):
        budget = NodeConnectionBudget()
        inbound = [budget.reserve_pending(f"inbound-{index}") for index in range(3)]
        created = []
        channel_value = self.Channel()

        def create_channel(_connector):
            self.assertEqual(budget.reserved_pending, 4)
            created.append(True)
            return channel_value

        subchannel = _SecureSubchannel(endpoint="127.0.0.1:50051",
            create_channel=create_channel, controller=budget, peer_id="worker",
            allowed_addresses=("127.0.0.1",), on_unavailable=lambda: None,
            connector_factory=self.Connector)
        try:
            channel = await subchannel.get_ready(0.5)
            self.assertIs(channel, channel_value)
            self.assertEqual(created, [True])
            self.assertEqual(budget.reserved_pending, 3)
        finally:
            await subchannel.close()
            for reservation in inbound:
                reservation.release()
        self.assertEqual(budget.reserved_pending, 0)

    async def test_fifth_live_pending_rejects_before_outbound_channel_creation(self):
        budget = NodeConnectionBudget()
        reservations = [budget.reserve_pending(f"inbound-{index}") for index in range(4)]
        created = []
        subchannel = _SecureSubchannel(endpoint="127.0.0.1:50051",
            create_channel=lambda _connector: created.append(True), controller=budget,
            peer_id="worker", allowed_addresses=("127.0.0.1",),
            on_unavailable=lambda: None, connector_factory=self.Connector)
        try:
            with self.assertRaises(SecureTransportError):
                await subchannel.get_ready(0.5)
            self.assertEqual(created, [])
            self.assertEqual(budget.reserved_pending, 4)
        finally:
            for reservation in reservations:
                reservation.release()

    async def test_channel_factory_time_is_inside_five_second_handshake_budget(self):
        import time

        budget = NodeConnectionBudget()

        class NotReadyChannel(self.Channel):
            def __init__(self):
                super().__init__(ready=False)
                self.ready_calls = 0

            async def channel_ready(self):
                self.ready_calls += 1
                await super().channel_ready()

        channel = NotReadyChannel()

        def slow_channel_factory(_connector):
            time.sleep(0.02)
            return channel

        subchannel = _SecureSubchannel(endpoint="127.0.0.1:50051",
            create_channel=slow_channel_factory, controller=budget, peer_id="peer",
            allowed_addresses=("127.0.0.1",), on_unavailable=lambda: None,
            connector_factory=self.Connector)
        try:
            absolute_deadline = time.monotonic() + 0.01
            with patch("steamboat_runtime.protocol.secure_transport.HANDSHAKE_TIMEOUT_SECONDS",
                       0.01), self.assertRaises(SecureTransportError):
                await subchannel.get_ready(0.5, absolute_deadline)
            self.assertEqual(channel.ready_calls, 0)
            self.assertEqual(budget.reserved_pending, 0)
            self.assertIsNone(subchannel.channel)
        finally:
            await subchannel.close()

    async def test_channel_factory_failure_closes_started_gate_and_releases_pending(self):
        budget = NodeConnectionBudget()
        connectors = []

        class TrackedConnector(self.Connector):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                connectors.append(self)

        def fail_channel_factory(_connector):
            raise RuntimeError("synthetic channel construction failure")

        subchannel = _SecureSubchannel(endpoint="127.0.0.1:50051",
            create_channel=fail_channel_factory, controller=budget, peer_id="peer",
            allowed_addresses=("127.0.0.1",), on_unavailable=lambda: None,
            connector_factory=TrackedConnector)
        with self.assertRaises(SecureTransportError):
            await subchannel.get_ready(0.5)
        self.assertEqual(len(connectors), 1)
        self.assertTrue(connectors[0].closed)
        self.assertTrue(connectors[0].pending_reservation is None)
        self.assertEqual(budget.reserved_pending, 0)
        self.assertIsNone(subchannel.connector)
        self.assertIsNone(subchannel.channel)
        await subchannel.close()

    async def test_connectivity_loss_closes_channel_before_a_fresh_attempt(self):
        budget = NodeConnectionBudget()
        channels = []

        class ChangeableChannel(self.Channel):
            def __init__(self):
                super().__init__(ready=True)
                self.changed = asyncio.Event()

            async def channel_ready(self):
                self.state = type("State", (), {"name": "READY"})()

            async def wait_for_state_change(self, _state):
                await self.changed.wait()

            async def close(self):
                await super().close()
                self.changed.set()

        def create_channel(_connector):
            channel = ChangeableChannel()
            channels.append(channel)
            return channel

        subchannel = _SecureSubchannel(endpoint="127.0.0.1:50051",
            create_channel=create_channel, controller=budget, peer_id="peer",
            allowed_addresses=("127.0.0.1",), on_unavailable=lambda: None,
            connector_factory=self.Connector)
        try:
            first = await subchannel.get_ready(0.5)
            first.state = type("State", (), {"name": "TRANSIENT_FAILURE"})()
            first.changed.set()
            for _ in range(50):
                if subchannel.channel is None:
                    break
                await asyncio.sleep(0.01)
            self.assertIsNone(subchannel.channel)
            self.assertEqual(budget.reserved_pending, 0)
            second = await subchannel.get_ready(0.5)
            self.assertIsNot(second, first)
            self.assertEqual(len(channels), 2)
        finally:
            await subchannel.close()


    async def test_first_monitor_sample_nonready_closes_channel_and_connector(self):
        budget = NodeConnectionBudget()

        class FirstSampleFailureChannel(self.Channel):
            def __init__(self):
                super().__init__(ready=True)
                self.state_reads = 0

            async def channel_ready(self):
                self.state = type("State", (), {"name": "READY"})()

            def get_state(self, try_to_connect=False):
                self.state_reads += 1
                name = "READY" if self.state_reads == 1 else "TRANSIENT_FAILURE"
                self.state = type("State", (), {"name": name})()
                return self.state

        channel = FirstSampleFailureChannel()
        connectors = []

        class TrackedConnector(self.Connector):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                connectors.append(self)

        subchannel = _SecureSubchannel(endpoint="127.0.0.1:50051",
            create_channel=lambda _connector: channel, controller=budget,
            peer_id="peer", allowed_addresses=("127.0.0.1",),
            on_unavailable=lambda: None, connector_factory=TrackedConnector)
        try:
            self.assertIs(await subchannel.get_ready(0.5), channel)
            for _ in range(50):
                if subchannel.channel is None:
                    break
                await asyncio.sleep(0.01)
            self.assertGreaterEqual(channel.state_reads, 2)
            self.assertIsNone(subchannel.channel,
                "the first non-READY monitor sample must retire the channel")
            self.assertTrue(connectors[0].closed,
                "the one-shot gate must close with its channel")
            self.assertEqual(budget.reserved_pending, 0)
        finally:
            await subchannel.close()

    async def test_monitor_cancellation_retains_resistant_children_and_fences_channel(self):
        release_state_child = asyncio.Event()
        state_child_started = asyncio.Event()
        state_child_cleanup_started = asyncio.Event()
        state_child_cleanup_finished = asyncio.Event()
        gate_child_started = asyncio.Event()
        children = []
        state_child = []
        unavailable = []

        class MonitoringChannel(self.Channel):
            def __init__(self):
                super().__init__(ready=True)
                self.state = type("State", (), {"name": "READY"})()

            async def wait_for_state_change(self, _state):
                child = asyncio.current_task()
                children.append(child)
                state_child.append(child)
                try:
                    # Signal only after the owned child has entered its
                    # cancellation-resistant read/finally scope.
                    state_child_started.set()
                    await asyncio.Future()
                finally:
                    state_child_cleanup_started.set()
                    await release_state_child.wait()
                    state_child_cleanup_finished.set()

        class MonitoringConnector:
            failed = False
            closed = False

            def __init__(self):
                self.accepting_stopped = False

            async def wait_failure(self):
                child = asyncio.current_task()
                children.append(child)
                gate_child_started.set()
                await asyncio.Future()

            def stop_accepting(self):
                self.accepting_stopped = True

            async def close(self, *, grace=5):
                self.closed = True

        channel = MonitoringChannel()
        connector = MonitoringConnector()
        subchannel = _SecureSubchannel(endpoint="127.0.0.1:50051",
            create_channel=lambda _connector: channel,
            controller=NodeConnectionBudget(), peer_id="peer",
            allowed_addresses=("127.0.0.1",),
            on_unavailable=lambda: unavailable.append(True),
            connector_factory=self.Connector)
        subchannel.channel = channel
        subchannel.connector = connector
        subchannel._monitor_task = asyncio.create_task(subchannel._monitor(channel))
        try:
            await asyncio.wait_for(state_child_started.wait(), 0.5)
            await asyncio.wait_for(gate_child_started.wait(), 0.5)
            # Let both child coroutines reach their suspended waits before the
            # parent monitor is cancelled; this makes the ownership assertion
            # independent of event-loop task scheduling order.
            await asyncio.sleep(0)
            with patch("steamboat_runtime.protocol.secure_transport.MAX_CANCELLATION_GRACE_SECONDS",
                       0.01):
                subchannel._monitor_task.cancel()
                with self.assertRaises(SecureTaskPending) as raised:
                    await subchannel._monitor_task
                await asyncio.wait_for(state_child_cleanup_started.wait(), 0.2)
                self.assertFalse(state_child_cleanup_finished.is_set(),
                    "a cancellation-resistant child finalizer must remain owned")
                self.assertEqual(len(raised.exception.tasks), 1)
                self.assertIn(state_child[0], raised.exception.tasks)
                self.assertTrue(subchannel._unavailable)
                self.assertTrue(unavailable)

                with self.assertRaises(SecureTaskPending):
                    await subchannel.fence()
                self.assertFalse(connector.closed,
                    "fencing must retain connector ownership while a watcher child is live")

            release_state_child.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(state_child[0], 0.5)
            self.assertTrue(state_child_cleanup_finished.is_set())
            await subchannel.fence()
            self.assertTrue(connector.closed)
        finally:
            release_state_child.set()
            for child in children:
                if not child.done():
                    child.cancel()
            await asyncio.gather(*children, return_exceptions=True)

    async def test_expiry_does_not_swallow_secure_task_pending_as_cancellation(self):
        unavailable = []
        child_release = asyncio.Event()
        child_started = asyncio.Event()

        async def resistant_child():
            child_started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                await child_release.wait()

        child = asyncio.create_task(resistant_child())
        await asyncio.wait_for(child_started.wait(), 0.5)
        channel = self.Channel()
        subchannel = _SecureSubchannel(endpoint="127.0.0.1:50051",
            create_channel=lambda _connector: channel,
            controller=NodeConnectionBudget(), peer_id="peer",
            allowed_addresses=("127.0.0.1",),
            on_unavailable=lambda: unavailable.append(True),
            connector_factory=self.Connector)
        subchannel.channel = channel

        async def pending_close():
            raise SecureTaskPending((child,), "synthetic retained child")

        subchannel._close_channel_locked = pending_close
        try:
            with patch("steamboat_runtime.protocol.secure_transport.MAX_OUTBOUND_CHANNEL_LIFETIME_SECONDS",
                       0):
                with self.assertRaises(SecureTaskPending) as raised:
                    await subchannel._expire(channel, time.monotonic())
            self.assertIn(child, raised.exception.tasks)
            self.assertTrue(subchannel._unavailable)
            self.assertTrue(unavailable)
        finally:
            child.cancel()
            child_release.set()
            await asyncio.wait_for(child, 0.5)


class OutboundPreflightDispatchTests(unittest.IsolatedAsyncioTestCase):
    class ExpiringAuthorization(FakeAuthorization):
        def __init__(self, remaining_values=(2, 0)):
            super().__init__(remaining=2)
            self._remaining_values = iter(remaining_values)

        def remaining_seconds(self):
            return next(self._remaining_values, 0)

    class Authorizer:
        def __init__(self, authorization):
            self.authorization = authorization

        def authorize_outbound(self, **_kwargs):
            return self.authorization

    class Channel:
        def __init__(self):
            self.dispatched = 0

        def unary_unary(self, _method):
            def dispatch(*_args, **_kwargs):
                self.dispatched += 1
                raise AssertionError("expired authorization must stop before RPC dispatch")
            return dispatch

        def unary_stream(self, _method):
            def dispatch(*_args, **_kwargs):
                self.dispatched += 1
                raise AssertionError("expired authorization must stop before RPC dispatch")
            return dispatch

    class Subchannel:
        def __init__(self, channel):
            self.channel = channel

        async def get_ready(self, _timeout, _absolute_deadline=None):
            return self.channel

        async def fence(self):
            return None

    async def test_worker_expiry_after_channel_ready_prevents_rpc_construction(self):
        import types

        auth = self.ExpiringAuthorization()
        channel = self.Channel()
        client = object.__new__(SecureWorkerClient)
        client.max_timeout_ms = 300_000
        client.max_message_bytes = 1024 * 1024
        client.outbound_authorizer = self.Authorizer(auth)
        client.authorization_watcher = lambda _auth: asyncio.Future()
        client.approved_server_leaf_pem = b"approved leaf"
        client._closed = False
        client._unavailable = False
        client._runtime_owner = SimpleNamespace(unavailable=False,
                                                 retain_pending=lambda _tasks: None)
        client._active_calls = set()
        client._subchannel = self.Subchannel(channel)
        grpc_stub = types.SimpleNamespace(aio=types.SimpleNamespace(
            AioRpcError=type("AioRpcError", (Exception,), {})))
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(AuthorizationRevoked):
                await client.execute("Describe", Request(timeout_ms=5000),
                                     trusted_request_context=object())
        self.assertEqual(channel.dispatched, 0)
        self.assertTrue(auth.closed)

    async def test_worker_expiry_after_encoding_prevents_rpc_construction(self):
        import types

        auth = self.ExpiringAuthorization((2, 2, 0))
        channel = self.Channel()
        client = object.__new__(SecureWorkerClient)
        client.max_timeout_ms = 300_000
        client.max_message_bytes = 1024 * 1024
        client.outbound_authorizer = self.Authorizer(auth)
        client.authorization_watcher = lambda _auth: asyncio.Future()
        client.approved_server_leaf_pem = b"approved leaf"
        client._closed = False
        client._unavailable = False
        client._runtime_owner = SimpleNamespace(unavailable=False,
                                                 retain_pending=lambda _tasks: None)
        client._active_calls = set()
        client._subchannel = self.Subchannel(channel)
        grpc_stub = types.SimpleNamespace(aio=types.SimpleNamespace(
            AioRpcError=type("AioRpcError", (Exception,), {})))
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(AuthorizationRevoked):
                await client.execute("Describe", Request(timeout_ms=5000),
                                     trusted_request_context=object())
        self.assertEqual(channel.dispatched, 0)
        self.assertTrue(auth.closed)

    async def test_worker_expiry_after_clipped_reencoding_prevents_rpc_construction(self):
        import types

        # The first post-encode check clips and reserializes the protobuf.
        # The final check must still run after that second encoding.
        auth = self.ExpiringAuthorization((2, 2, 1, 0))
        channel = self.Channel()
        client = object.__new__(SecureWorkerClient)
        client.max_timeout_ms = 300_000
        client.max_message_bytes = 1024 * 1024
        client.outbound_authorizer = self.Authorizer(auth)
        client.authorization_watcher = lambda _auth: asyncio.Future()
        client.approved_server_leaf_pem = b"approved leaf"
        client._closed = False
        client._unavailable = False
        client._runtime_owner = SimpleNamespace(unavailable=False,
                                                 retain_pending=lambda _tasks: None)
        client._active_calls = set()
        client._subchannel = self.Subchannel(channel)
        grpc_stub = types.SimpleNamespace(aio=types.SimpleNamespace(
            AioRpcError=type("AioRpcError", (Exception,), {})))
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(AuthorizationRevoked):
                await client.execute("Describe", Request(timeout_ms=5000),
                                     trusted_request_context=object())
        self.assertEqual(channel.dispatched, 0)
        self.assertTrue(auth.closed)

    async def test_slow_final_async_liveness_check_cannot_outlive_absolute_request_deadline(self):
        import types

        class SlowFinalAuthorization(FakeAuthorization):
            def __init__(self):
                super().__init__(remaining=10)
                self.assertions = 0

            async def assert_live(self):
                self.assertions += 1
                if self.assertions == 4:
                    await asyncio.sleep(0.06)
                return None

            def remaining_seconds(self):
                return 10

        auth = SlowFinalAuthorization()
        channel = self.Channel()
        client = object.__new__(SecureWorkerClient)
        client.max_timeout_ms = 300_000
        client.max_message_bytes = 1024 * 1024
        client.outbound_authorizer = self.Authorizer(auth)
        client.authorization_watcher = lambda _auth: asyncio.Future()
        client.approved_server_leaf_pem = b"approved leaf"
        client._closed = False
        client._unavailable = False
        client._runtime_owner = SimpleNamespace(unavailable=False,
                                                 retain_pending=lambda _tasks: None)
        client._active_calls = set()
        client._subchannel = self.Subchannel(channel)
        grpc_stub = types.SimpleNamespace(aio=types.SimpleNamespace(
            AioRpcError=type("AioRpcError", (Exception,), {})))
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(TimeoutError):
                await client.execute("Describe", Request(timeout_ms=25),
                                     trusted_request_context=object())
        self.assertEqual(auth.assertions, 4)
        self.assertEqual(channel.dispatched, 0)
        self.assertTrue(auth.closed)

    async def test_coordinator_expiry_after_encoding_prevents_rpc_construction(self):
        import types

        auth = self.ExpiringAuthorization((2, 2, 0))
        channel = self.Channel()
        client = object.__new__(SecureCoordinatorClient)
        client.outbound_authorizer = self.Authorizer(auth)
        client.authorization_watcher = lambda _auth: asyncio.Future()
        client.approved_server_leaf_pem = b"approved leaf"
        client._closed = False
        client._unavailable = False
        client._runtime_owner = SimpleNamespace(unavailable=False,
                                                 retain_pending=lambda _tasks: None)
        client._active_calls = set()

        async def ensure_channel(_timeout, _absolute_deadline=None):
            return channel

        client._ensure_channel = ensure_channel
        grpc_stub = types.SimpleNamespace(aio=types.SimpleNamespace(
            AioRpcError=type("AioRpcError", (Exception,), {})))
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            stream = client.generate([1, 2], 1, trusted_request_context=object(),
                                     timeout_seconds=5)
            try:
                with self.assertRaises(AuthorizationRevoked):
                    await anext(stream)
            finally:
                await stream.aclose()
        self.assertEqual(channel.dispatched, 0)
        self.assertTrue(auth.closed)

    async def test_generate_expiry_after_clipped_reencoding_prevents_rpc_construction(self):
        import types

        # The post-metadata check clips the payload and triggers another JSON
        # encode; preflight again after that encode before stream dispatch.
        auth = self.ExpiringAuthorization((2, 2, 2, 1, 0))
        channel = self.Channel()
        client = object.__new__(SecureCoordinatorClient)
        client.outbound_authorizer = self.Authorizer(auth)
        client.authorization_watcher = lambda _auth: asyncio.Future()
        client.approved_server_leaf_pem = b"approved leaf"
        client._closed = False
        client._unavailable = False
        client._runtime_owner = SimpleNamespace(unavailable=False,
                                                 retain_pending=lambda _tasks: None)
        client._active_calls = set()

        async def ensure_channel(_timeout, _absolute_deadline=None):
            return channel

        client._ensure_channel = ensure_channel
        grpc_stub = types.SimpleNamespace(aio=types.SimpleNamespace(
            AioRpcError=type("AioRpcError", (Exception,), {})))
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            stream = client.generate([1, 2], 1, trusted_request_context=object(),
                                     timeout_seconds=5)
            try:
                with self.assertRaises(AuthorizationRevoked):
                    await anext(stream)
            finally:
                await stream.aclose()
        self.assertEqual(channel.dispatched, 0)
        self.assertTrue(auth.closed)


class ShutdownRetryTests(unittest.IsolatedAsyncioTestCase):
    class Reservation:
        def __init__(self, *, fail_once=False):
            self.fail_once = fail_once
            self.releases = 0

        def release(self):
            self.releases += 1
            if self.fail_once and self.releases == 1:
                raise OSError("synthetic release failure")

    async def test_server_shutdown_failure_keeps_reservation_and_can_retry(self):
        class Server:
            def __init__(self):
                self.stops = 0

            async def stop(self, _grace):
                self.stops += 1
                if self.stops == 1:
                    raise OSError("synthetic stop failure")

        reservation = self.Reservation()
        server = Server()
        handle = SecureServerHandle(server, 1, reservation)
        with self.assertRaises(OSError):
            await handle.stop()
        self.assertFalse(handle._stopped)
        self.assertEqual(reservation.releases, 0)
        await handle.stop()
        self.assertTrue(handle._stopped)
        self.assertEqual(server.stops, 2)
        self.assertEqual(reservation.releases, 1)

    async def test_server_stops_backend_even_when_gate_cleanup_fails_and_retries(self):
        class Server:
            def __init__(self):
                self.stops = 0

            async def stop(self, _grace):
                self.stops += 1

        class Acceptor:
            def __init__(self):
                self.stops = 0

            async def stop(self):
                self.stops += 1
                if self.stops == 1:
                    raise OSError("synthetic gate cleanup failure")

        reservation, server, acceptor = self.Reservation(), Server(), Acceptor()
        handle = SecureServerHandle(server, 1, reservation, acceptor=acceptor)
        with self.assertRaises(OSError):
            await handle.stop()
        self.assertEqual(server.stops, 1)
        self.assertEqual(reservation.releases, 0)
        await handle.stop()
        self.assertTrue(handle._stopped)
        self.assertEqual(acceptor.stops, 2)
        self.assertEqual(reservation.releases, 1)

    async def test_client_close_keeps_static_reservation_until_channel_close_succeeds(self):
        class FailOnceChannel(OutboundPendingHandshakeTests.Channel):
            def __init__(self):
                super().__init__()
                self.close_calls = 0

            async def close(self):
                self.close_calls += 1
                if self.close_calls == 1:
                    raise OSError("synthetic channel close failure")
                await super().close()

        budget = NodeConnectionBudget()
        reservation = budget.reserve_outbound("peer")
        channel_value = FailOnceChannel()
        subchannel = _SecureSubchannel(endpoint="127.0.0.1:50051",
            create_channel=lambda _connector: channel_value, controller=budget, peer_id="peer",
            allowed_addresses=("127.0.0.1",), on_unavailable=lambda: None,
            connector_factory=OutboundPendingHandshakeTests.Connector)
        await subchannel.get_ready(0.5)
        client = object.__new__(SecureWorkerClient)
        client._closed = False
        client._unavailable = False
        client._active_calls = set()
        client._runtime_owner = SimpleNamespace(unavailable=False, pending_tasks=set())
        client._subchannel = subchannel
        client._reservation = reservation
        with self.assertRaises(OSError):
            await client.close()
        self.assertFalse(client._closed)
        self.assertEqual(budget.reserved_connections, 3)
        await client.close()
        self.assertTrue(client._closed)
        self.assertEqual(budget.reserved_connections, 0)


class SecureServerPendingDescendantShutdownTests(unittest.IsolatedAsyncioTestCase):
    class Owner:
        def __init__(self):
            self.unavailable = False
            self.pending_tasks = set()

        def retain_pending(self, tasks):
            for task in tasks:
                if task in self.pending_tasks:
                    continue
                self.pending_tasks.add(task)
                task.add_done_callback(self._completed)

        def _completed(self, task):
            self.pending_tasks.discard(task)
            try:
                error = task.exception()
            except asyncio.CancelledError:
                return
            if isinstance(error, SecureTaskPending):
                self.retain_pending(error.tasks)

    class Server:
        def __init__(self):
            self.stopped = asyncio.Event()
            self.stop_calls = 0

        async def stop(self, _grace):
            self.stop_calls += 1
            self.stopped.set()

    async def _pending_child(self):
        owner = self.Owner()
        reservation = ShutdownRetryTests.Reservation()
        server = self.Server()
        handle = SecureServerHandle(server, 1, reservation, runtime_owner=owner)
        make_child = asyncio.Event()
        child_started = asyncio.Event()
        release_child = asyncio.Event()
        child_finished = asyncio.Event()
        children = []

        async def child():
            child_started.set()
            try:
                await release_child.wait()
            finally:
                child_finished.set()

        async def operation():
            await make_child.wait()
            descendant = asyncio.create_task(child())
            children.append(descendant)
            await child_started.wait()
            raise SecureTaskPending((descendant,))

        root = asyncio.create_task(operation())
        owner.retain_pending((root,))
        return (owner, reservation, server, handle, make_child,
                child_started, release_child, child_finished, children, root)

    async def test_stop_rechecks_late_descendant_with_one_bounded_drain(self):
        (owner, reservation, server, handle, make_child, child_started,
         release_child, child_finished, children, root) = await self._pending_child()
        with patch("steamboat_runtime.protocol.secure_transport.MAX_CANCELLATION_GRACE_SECONDS",
                   0.05):
            stop_task = asyncio.create_task(handle.stop())
            await asyncio.wait_for(server.stopped.wait(), 1)
            make_child.set()
            await asyncio.wait_for(child_started.wait(), 1)
            with self.assertRaises(SecureTaskPending) as raised:
                await asyncio.wait_for(stop_task, 1)
            self.assertTrue(root.done())
            self.assertEqual(len(children), 1)
            child = children[0]
            self.assertFalse(child.done())
            self.assertIn(child, owner.pending_tasks)
            self.assertIn(child, raised.exception.tasks)
            self.assertFalse(handle._stopped)
            self.assertEqual(reservation.releases, 0)

            release_child.set()
            await asyncio.wait_for(child_finished.wait(), 1)
            await handle.stop()
            await handle.stop()

        self.assertTrue(child.done())
        self.assertTrue(handle._stopped)
        self.assertEqual(server.stop_calls, 1)
        self.assertEqual(reservation.releases, 1)

    async def test_caller_cancellation_hands_off_descendant_and_keeps_reservation(self):
        (owner, reservation, server, handle, make_child, child_started,
         release_child, child_finished, children, root) = await self._pending_child()
        stop_task = asyncio.create_task(handle.stop())
        await asyncio.wait_for(server.stopped.wait(), 1)
        make_child.set()
        await asyncio.wait_for(child_started.wait(), 1)
        stop_task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(stop_task, 1)
        with self.assertRaises(SecureTaskPending):
            await asyncio.wait_for(root, 1)

        child = children[0]
        self.assertTrue(root.done())
        self.assertFalse(child.done())
        self.assertIn(child, owner.pending_tasks)
        self.assertFalse(handle._stopped)
        self.assertEqual(reservation.releases, 0)

        release_child.set()
        await asyncio.wait_for(child_finished.wait(), 1)
        await handle.stop()
        await handle.stop()
        self.assertTrue(handle._stopped)
        self.assertEqual(server.stop_calls, 1)
        self.assertEqual(reservation.releases, 1)


class CoordinatorGenerateGuardTests(unittest.IsolatedAsyncioTestCase):
    class Authorization(FakeAuthorization):
        binding_bytes = b'{"account_id":"acct_test","binding_version":1}'

    class Authorizer:
        def __init__(self):
            self.authorizations = []

        def authorize(self, **_kwargs):
            authorization = CoordinatorGenerateGuardTests.Authorization(10)
            self.authorizations.append(authorization)
            return authorization

    class Gate:
        def __init__(self):
            self.paused = False

        async def mark_authenticated_peer(self, _peer):
            return True

        async def reject_unestablished_peer(self, _peer):
            return True

        def pause(self):
            self.paused = True

    class Context:
        def __init__(self, *, time_remaining=None, stall_metadata=False,
                     stall_write=False, abort_raises=False):
            self.remaining = time_remaining
            self.stall_metadata = stall_metadata
            self.stall_write = stall_write
            self.abort_raises = abort_raises
            self.abort_calls = []
            self.metadata_started = asyncio.Event()
            self.metadata_cancelled = asyncio.Event()
            self.write_started = asyncio.Event()
            self.write_cancelled = asyncio.Event()
            self.metadata = None
            self.trailing_metadata = None

        def auth_context(self):
            return {"transport_security_type": (b"ssl",),
                    "x509_pem_cert": (b"-----BEGIN CERTIFICATE-----\npeer\n-----END CERTIFICATE-----",)}

        def invocation_metadata(self):
            return ((BINDING_METADATA_KEY,
                     CoordinatorGenerateGuardTests.Authorization.binding_bytes),)

        def peer(self):
            return "unix:/tmp/test-gate-client.sock"

        def time_remaining(self):
            return self.remaining

        async def send_initial_metadata(self, metadata):
            self.metadata = metadata
            self.metadata_started.set()
            if self.stall_metadata:
                try:
                    await asyncio.Future()
                finally:
                    self.metadata_cancelled.set()

        def set_trailing_metadata(self, metadata):
            self.trailing_metadata = tuple(metadata)

        async def write(self, _message):
            self.write_started.set()
            if self.stall_write:
                try:
                    await asyncio.Future()
                finally:
                    self.write_cancelled.set()

        async def abort(self, _code, _details):
            self.abort_calls.append((_code, _details))
            if self.abort_raises:
                raise RuntimeError("synthetic gRPC abort")
            return None

    class ModelCoordinator:
        def __init__(self):
            self.submissions = []
            self.handles = []

        def submit(self, input_ids, new_tokens, *, forced_tokens=None,
                   capture_logits=False, timeout_seconds=None,
                   trusted_request_context=None):
            self.submissions.append((trusted_request_context, timeout_seconds))
            handle = CoordinatorGenerateGuardTests.Handle()
            self.handles.append(handle)
            return handle

    class Handle:
        session_id = "a" * 32

        def __init__(self):
            self.cancelled = False
            self.cleanup_complete = False
            self.cleanup_status = None
            self.cleanup_finished = asyncio.Event()

        class Result:
            def __init__(self, status, cleanup_complete):
                self.status = status
                self.cleanup_complete = cleanup_complete

        async def __aiter__(self):
            yield SimpleNamespace(session_id=self.session_id, index=0,
                token_id=5, position=1, sequence=0, logits=None)

        async def result(self):
            await self.cleanup_finished.wait()
            return self.Result(self.cleanup_status, self.cleanup_complete)

    class Service:
        max_streams = 40

        def __init__(self):
            self.active_streams = 0
            self.counters = {"rejected_requests": 0, "transport_stalls": 0,
                             "disconnected_streams": 0}
            self.coordinator = CoordinatorGenerateGuardTests.ModelCoordinator()
            self.cleanups = set()
            self.fail_cleanup = False
            self.stall_cleanup = False
            self.incomplete_cleanup = False
            self.cleanup_release = asyncio.Event()

        async def _write(self, context, message, _deadline):
            await context.write(message)

        async def _finish(self, handle, *, cancel, release_active_stream=True):
            try:
                if self.fail_cleanup:
                    raise RuntimeError("synthetic session cleanup failure")
                if self.stall_cleanup:
                    await self.cleanup_release.wait()
                handle.cancelled = cancel
                handle.cleanup_status = "cancelled" if cancel else "completed"
                handle.cleanup_complete = not self.incomplete_cleanup
                handle.cleanup_finished.set()
            finally:
                if release_active_stream:
                    self.active_streams -= 1

    async def _make_adapter(self, factory, *, max_generate_streams=1):
        from steamboat_runtime.secure_coordinator_service import SecureCoordinatorService

        self.fake_authorizer = self.Authorizer()
        self.fake_service = self.Service()

        async def never_revoked(_authorization):
            await asyncio.Future()

        adapter = SecureCoordinatorService(self.fake_service,
            authorizer=self.fake_authorizer,
            authorization_watcher=never_revoked,
            request_context_factory=factory,
            max_generate_streams=max_generate_streams)
        adapter.acceptor = self.Gate()
        return adapter

    @staticmethod
    def _request(timeout=0.2):
        from steamboat_runtime.remote_client import encode_json

        return encode_json({"input_ids": [1], "new_tokens": 1,
            "timeout_seconds": timeout, "capture_logits": False})

    @staticmethod
    def _context(authorization, *, lifetime=1.0):
        from steamboat_runtime.participant_context import TrustedRequestContext

        return TrustedRequestContext(
            tenant_account_id="acct_" + "1" * 32,
            request_id="req_" + "2" * 32,
            session_id="ses_" + "3" * 32,
            route_id="route_" + "4" * 32,
            coordinator_boot_id="5" * 32,
            route_epoch=1, attempt=1, authorization=authorization,
            hard_monotonic_deadline=__import__("time").monotonic() + lifetime)

    async def test_payload_deadline_bounds_stalled_context_factory_and_owns_slot_early(self):
        factory_started, factory_cancelled = asyncio.Event(), asyncio.Event()

        async def factory(_authorization, _payload):
            factory_started.set()
            try:
                await asyncio.Future()
            finally:
                factory_cancelled.set()

        adapter = await self._make_adapter(factory)
        context = self.Context()
        task = asyncio.create_task(adapter.generate_rpc(self._request(0.08), context))
        await asyncio.wait_for(factory_started.wait(), 1)
        self.assertEqual(adapter.active_generate_streams, 1)
        self.assertEqual(self.fake_service.active_streams, 1)
        with self.assertRaises(TimeoutError):
            await asyncio.wait_for(task, 1)
        self.assertTrue(factory_cancelled.is_set())
        self.assertEqual(adapter.active_generate_streams, 0)
        self.assertEqual(self.fake_service.active_streams, 0)

    async def test_capacity_abort_exception_still_closes_authorization(self):
        async def factory(_authorization, _payload):
            raise AssertionError("capacity rejection must precede context construction")

        adapter = await self._make_adapter(factory)
        adapter.active_generate_streams = 1
        context = self.Context(abort_raises=True)
        with self.assertRaisesRegex(RuntimeError, "synthetic gRPC abort"):
            await adapter.generate_rpc(self._request(), context)

        authorization = self.fake_authorizer.authorizations[0]
        self.assertTrue(context.abort_calls)
        self.assertEqual(context.trailing_metadata,
                         capacity_rejection_metadata(authorization.binding_bytes))
        self.assertEqual(authorization.failed, [False])
        self.assertTrue(authorization.closed)
        self.assertEqual(self.fake_service.coordinator.submissions, [])
        self.assertEqual(self.fake_service.active_streams, 0)

    async def test_context_deadline_bounds_stalled_initial_metadata(self):
        async def factory(authorization, _payload):
            return self._context(authorization, lifetime=0.06)

        adapter = await self._make_adapter(factory)
        context = self.Context(stall_metadata=True)
        with self.assertRaises(TimeoutError):
            await adapter.generate_rpc(self._request(0.5), context)
        self.assertTrue(context.metadata_started.is_set())
        self.assertTrue(context.metadata_cancelled.is_set())
        self.assertEqual(self.fake_service.coordinator.submissions, [])
        self.assertEqual(adapter.active_generate_streams, 0)
        self.assertEqual(self.fake_service.active_streams, 0)

    async def test_invalid_context_factory_values_are_rejected_before_metadata_or_submit(self):
        for invalid in (None, False, {}, object()):
            async def factory(_authorization, _payload, value=invalid):
                return value

            adapter = await self._make_adapter(factory)
            context = self.Context()
            with self.subTest(invalid=type(invalid).__name__), \
                    self.assertRaises(SecureTransportError):
                await adapter.generate_rpc(self._request(), context)
            self.assertIsNone(context.metadata)
            self.assertEqual(self.fake_service.coordinator.submissions, [])
            self.assertEqual(adapter.active_generate_streams, 0)
            self.assertEqual(self.fake_service.active_streams, 0)

    async def test_cancelled_paused_stream_keeps_context_and_cleans_session(self):
        import types
        import time

        async def factory(authorization, _payload):
            return self._context(authorization, lifetime=1)

        adapter = await self._make_adapter(factory)
        context = self.Context(stall_write=True)
        torch_stub = types.SimpleNamespace(long=object(),
            tensor=lambda _values, dtype=None: ("tensor", dtype))
        with patch.dict(sys.modules, {"torch": torch_stub}):
            task = asyncio.create_task(adapter.generate_rpc(self._request(2), context))
            await asyncio.wait_for(context.write_started.wait(), 1)
            self.assertEqual(len(self.fake_service.coordinator.submissions), 1)
            trusted_context, _deadline = self.fake_service.coordinator.submissions[0]
            self.assertEqual(trusted_context.session_id, "ses_" + "3" * 32)
            self.assertIs(trusted_context.authorization,
                          self.fake_authorizer.authorizations[0])
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 1)
        self.assertTrue(context.write_cancelled.is_set())
        for _ in range(100):
            if not self.fake_service.cleanups and self.fake_service.active_streams == 0:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(adapter.active_generate_streams, 0)
        self.assertEqual(self.fake_service.active_streams, 0)

    async def test_failed_session_cleanup_retains_generate_slot_and_stops_service(self):
        import types

        async def factory(authorization, _payload):
            return self._context(authorization, lifetime=1)

        adapter = await self._make_adapter(factory)
        adapter.acceptor = self.Gate()
        self.fake_service.fail_cleanup = True
        context = self.Context(stall_write=True)
        torch_stub = types.SimpleNamespace(long=object(),
            tensor=lambda _values, dtype=None: ("tensor", dtype))
        with patch.dict(sys.modules, {"torch": torch_stub}):
            task = asyncio.create_task(adapter.generate_rpc(self._request(2), context))
            await asyncio.wait_for(context.write_started.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 1)
        for _ in range(50):
            if adapter.unavailable:
                break
            await asyncio.sleep(0.01)
        self.assertTrue(adapter.unavailable)
        self.assertTrue(adapter.acceptor.paused)
        self.assertEqual(adapter.active_generate_streams, 1)
        self.assertEqual(self.fake_service.active_streams, 1)

    async def test_stalled_session_cleanup_is_bounded_and_retains_slot_until_exit(self):
        import types

        async def factory(authorization, _payload):
            return self._context(authorization, lifetime=1)

        adapter = await self._make_adapter(factory)
        self.fake_service.stall_cleanup = True
        context = self.Context(stall_write=True)
        torch_stub = types.SimpleNamespace(long=object(),
            tensor=lambda _values, dtype=None: ("tensor", dtype))
        slots = []
        retain_owner = adapter._retain_generate_authorization_owner

        def track_owner(authorization, slot):
            slots.append(slot)
            return retain_owner(authorization, slot)

        adapter._retain_generate_authorization_owner = track_owner
        with patch("steamboat_runtime.protocol.secure_transport.MAX_CANCELLATION_GRACE_SECONDS",
                   0.02), patch.dict(sys.modules, {"torch": torch_stub}):
            task = asyncio.create_task(adapter.generate_rpc(self._request(2), context))
            await asyncio.wait_for(context.write_started.wait(), 1)
            task.cancel()
            with self.assertRaises(SecureTaskPending):
                await asyncio.wait_for(task, 1)
            for _ in range(50):
                if adapter.unavailable:
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(adapter.unavailable)
            self.assertEqual(adapter.active_generate_streams, 1)
            self.assertEqual(self.fake_service.active_streams, 1)
            slot = slots[0]
            handle = self.fake_service.coordinator.handles[0]
            self.assertFalse(handle.cleanup_finished.is_set())
            self.assertIs(slot["session_cleanup_confirmed"], False)
            self.assertFalse(self.fake_authorizer.authorizations[0].closed)
            self.fake_service.cleanup_release.set()
            await asyncio.wait_for(handle.cleanup_finished.wait(), 1)
            await asyncio.wait_for(slot["authorization_owner_task"], 1)
        self.assertTrue(handle.cleanup_complete)
        self.assertIs(slot["session_cleanup_confirmed"], True)
        self.assertIs(slot["resource_cleanup_confirmed"], True)
        self.assertTrue(self.fake_authorizer.authorizations[0].closed)
        self.assertEqual(adapter.active_generate_streams, 0)
        self.assertEqual(self.fake_service.active_streams, 0)

    async def test_cleanup_complete_false_keeps_generate_slot_and_authorization(self):
        import types

        async def factory(authorization, _payload):
            return self._context(authorization, lifetime=1)

        adapter = await self._make_adapter(factory)
        adapter.acceptor = self.Gate()
        self.fake_service.incomplete_cleanup = True
        context = self.Context(stall_write=True)
        torch_stub = types.SimpleNamespace(long=object(),
            tensor=lambda _values, dtype=None: ("tensor", dtype))
        slots = []
        retain_owner = adapter._retain_generate_authorization_owner

        def track_owner(authorization, slot):
            slots.append(slot)
            return retain_owner(authorization, slot)

        adapter._retain_generate_authorization_owner = track_owner
        with patch.dict(sys.modules, {"torch": torch_stub}):
            task = asyncio.create_task(adapter.generate_rpc(self._request(2), context))
            await asyncio.wait_for(context.write_started.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 1)

        slot = slots[0]
        handle = self.fake_service.coordinator.handles[0]
        await asyncio.wait_for(handle.cleanup_finished.wait(), 1)
        await asyncio.wait_for(slot["authorization_owner_task"], 1)
        self.assertFalse(handle.cleanup_complete)
        self.assertIs(slot["session_cleanup_confirmed"], False)
        self.assertIs(slot["resource_cleanup_confirmed"], False)
        self.assertFalse(self.fake_authorizer.authorizations[0].closed)
        self.assertTrue(adapter.unavailable)
        self.assertTrue(adapter.acceptor.paused)
        self.assertIn(slot, adapter._unreclaimed_generate_slots)
        self.assertEqual(adapter.active_generate_streams, 1)
        self.assertEqual(self.fake_service.active_streams, 1)

    async def test_coordinator_expiry_after_channel_ready_prevents_rpc_construction(self):
        import types

        auth = OutboundPreflightDispatchTests.ExpiringAuthorization()
        channel = OutboundPreflightDispatchTests.Channel()
        client = object.__new__(SecureCoordinatorClient)
        client.outbound_authorizer = OutboundPreflightDispatchTests.Authorizer(auth)
        client.authorization_watcher = lambda _auth: asyncio.Future()
        client.approved_server_leaf_pem = b"approved leaf"
        client._closed = False
        client._unavailable = False
        client._runtime_owner = SimpleNamespace(unavailable=False,
                                                 retain_pending=lambda _tasks: None)
        client._active_calls = set()
        client._subchannel = OutboundPreflightDispatchTests.Subchannel(channel)

        async def ensure_channel(_timeout, _absolute_deadline=None):
            return channel

        client._ensure_channel = ensure_channel
        grpc_stub = types.SimpleNamespace(aio=types.SimpleNamespace(
            AioRpcError=type("AioRpcError", (Exception,), {})))
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(AuthorizationRevoked):
                await client._unary("Describe", {}, 5, object(), 64)
        self.assertEqual(channel.dispatched, 0)
        self.assertTrue(auth.closed)


class SecureGenerateTypedSessionIdTests(unittest.IsolatedAsyncioTestCase):
    class Authorizer:
        def __init__(self, authorization):
            self.authorization = authorization

        def authorize_outbound(self, **_kwargs):
            return self.authorization

    class Call:
        def __init__(self, events):
            self.events = events
            self.cancelled = False
            self.finished = False

        async def initial_metadata(self):
            return ((BINDING_METADATA_KEY, FakeAuthorization.binding_bytes),)

        def __aiter__(self):
            async def iterate():
                for event in self.events:
                    await asyncio.sleep(0)
                    yield json.dumps(event, separators=(",", ":")).encode("utf-8")
                self.finished = True
            return iterate()

        def cancel(self):
            self.cancelled = True
            self.finished = True

        def done(self):
            return self.finished

    class Channel:
        def __init__(self, call):
            self.call = call
            self.dispatched = 0

        def unary_stream(self, _method):
            def dispatch(*_args, **_kwargs):
                self.dispatched += 1
                return self.call
            return dispatch

    class Subchannel:
        def __init__(self, channel):
            self.channel = channel
            self.fenced = False

        async def get_ready(self, _timeout, _absolute_deadline=None):
            return self.channel

        async def fence(self):
            self.fenced = True

    async def _collect(self, events):
        import types

        authorization = FakeAuthorization(remaining=10)
        call = self.Call(events)
        channel = self.Channel(call)
        subchannel = self.Subchannel(channel)
        client = object.__new__(SecureCoordinatorClient)
        client.outbound_authorizer = self.Authorizer(authorization)
        client.authorization_watcher = lambda _auth: asyncio.Future()
        client.approved_server_leaf_pem = b"approved server leaf"
        client._closed = False
        client._unavailable = False
        client._runtime_owner = SimpleNamespace(unavailable=False,
                                                 retain_pending=lambda _tasks: None)
        client._active_calls = set()
        client._subchannel = subchannel
        grpc_stub = types.SimpleNamespace(aio=types.SimpleNamespace(
            AioRpcError=type("AioRpcError", (Exception,), {})))
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            result = [event async for event in client.generate(
                [1, 2], 1, trusted_request_context=object(), timeout_seconds=5)]
        return result, authorization, channel, subchannel

    def _events(self, first_id, second_id=None):
        second_id = first_id if second_id is None else second_id
        return [
            {"type": "token", "session_id": first_id, "index": 0,
             "sequence": 0, "token_id": 3, "position": 2},
            {"type": "result", "session_id": second_id, "status": "completed",
             "cleanup_complete": True, "token_ids": [3], "metrics": {}},
        ]

    async def test_generate_accepts_typed_coordinator_session_id(self):
        session_id = "ses_" + "a" * 32
        events, authorization, channel, subchannel = await self._collect(
            self._events(session_id))
        self.assertEqual([event["session_id"] for event in events],
                         [session_id, session_id])
        self.assertEqual(channel.dispatched, 1)
        self.assertTrue(authorization.completed)
        self.assertFalse(subchannel.fenced)

    async def test_generate_rejects_raw_session_id(self):
        authorization, channel, subchannel = await self._reject(
            self._events("a" * 32))
        self.assertEqual(channel.dispatched, 1)
        self.assertTrue(subchannel.fenced)
        self.assertTrue(authorization.failed)

    async def test_generate_rejects_wrong_typed_session_prefix(self):
        authorization, _channel, subchannel = await self._reject(
            self._events("req_" + "b" * 32))
        self.assertTrue(subchannel.fenced)
        self.assertTrue(authorization.failed)

    async def test_generate_rejects_session_id_change_inside_stream(self):
        authorization, _channel, subchannel = await self._reject(
            self._events("ses_" + "c" * 32, "ses_" + "d" * 32))
        self.assertTrue(subchannel.fenced)
        self.assertTrue(authorization.failed)

    async def _reject(self, events):
        from steamboat_runtime.remote_client import RemoteError

        authorization = FakeAuthorization(remaining=10)
        call = self.Call(events)
        channel = self.Channel(call)
        subchannel = self.Subchannel(channel)
        client = object.__new__(SecureCoordinatorClient)
        client.outbound_authorizer = self.Authorizer(authorization)
        client.authorization_watcher = lambda _auth: asyncio.Future()
        client.approved_server_leaf_pem = b"approved server leaf"
        client._closed = False
        client._unavailable = False
        client._runtime_owner = SimpleNamespace(unavailable=False,
                                                 retain_pending=lambda _tasks: None)
        client._active_calls = set()
        client._subchannel = subchannel
        grpc_stub = SimpleNamespace(aio=SimpleNamespace(
            AioRpcError=type("AioRpcError", (Exception,), {})))
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(RemoteError):
                _ = [event async for event in client.generate(
                    [1, 2], 1, trusted_request_context=object(), timeout_seconds=5)]
        self.assertTrue(call.cancelled)
        self.assertTrue(authorization.closed)
        return authorization, channel, subchannel


class SecureGenerateCapacityRejectionTests(unittest.IsolatedAsyncioTestCase):
    class StatusCode:
        DEADLINE_EXCEEDED = object()
        RESOURCE_EXHAUSTED = object()
        CANCELLED = object()
        INVALID_ARGUMENT = object()
        UNAVAILABLE = object()

    class AioRpcError(Exception):
        def __init__(self, status):
            self._status = status

        def code(self):
            return self._status

    class Authorization(FakeAuthorization):
        def __init__(self, *, revoke_on_status=False):
            super().__init__(remaining=10)
            self.revoked = False
            self.revoke_on_status = revoke_on_status

        def assert_live(self):
            if self.revoked:
                raise AuthorizationRevoked("synthetic authorization expiry")

    class Call:
        def __init__(self, metadata, status, events, authorization, trailers):
            self.metadata = metadata
            self.status = status
            self.events = events
            self.authorization = authorization
            self.trailers = trailers
            self.cancelled = False
            self.finished = False
            self.trailing_started = False
            self.trailing_started_event = None

        async def initial_metadata(self):
            return self.metadata

        async def trailing_metadata(self):
            self.trailing_started = True
            if self.trailing_started_event is not None:
                self.trailing_started_event.set()
            if inspect.isawaitable(self.trailers):
                return await self.trailers
            return self.trailers

        def __aiter__(self):
            async def read():
                for event in self.events:
                    yield json.dumps(event, separators=(",", ":")).encode("utf-8")
                if self.authorization.revoke_on_status:
                    self.authorization.revoked = True
                self.finished = True
                raise SecureGenerateCapacityRejectionTests.AioRpcError(self.status)
            return read()

        def cancel(self):
            self.cancelled = True
            self.finished = True

        def done(self):
            return self.finished

    class Channel:
        def __init__(self, call):
            self.call = call
            self.dispatched = 0

        def unary_stream(self, _method):
            def dispatch(*_args, **_kwargs):
                self.dispatched += 1
                return self.call
            return dispatch

    class Subchannel:
        def __init__(self, channel):
            self.channel = channel
            self.fence_calls = 0

        async def get_ready(self, _timeout, _absolute_deadline=None):
            return self.channel

        async def fence(self):
            self.fence_calls += 1

    def _make_client(self, *, metadata=None, status=None, events=(), authorization=None,
                     trailers=None):
        authorization = authorization or self.Authorization()
        if status is None:
            status = self.StatusCode.RESOURCE_EXHAUSTED
        if metadata is None:
            metadata = ((BINDING_METADATA_KEY, authorization.binding_bytes),)
        if trailers is None:
            trailers = capacity_rejection_metadata(authorization.binding_bytes)
        call = self.Call(metadata, status, events, authorization, trailers)
        channel = self.Channel(call)
        subchannel = self.Subchannel(channel)
        client = object.__new__(SecureCoordinatorClient)

        class Authorizer:
            def authorize_outbound(self, **_kwargs):
                return authorization

        client.outbound_authorizer = Authorizer()
        client.authorization_watcher = lambda _auth: asyncio.Future()
        client.approved_server_leaf_pem = b"approved server leaf"
        client._closed = False
        client._unavailable = False
        client._runtime_owner = SimpleNamespace(unavailable=False,
                                                 retain_pending=lambda _tasks: None)
        client._active_calls = set()
        client._subchannel = subchannel
        grpc_stub = SimpleNamespace(
            aio=SimpleNamespace(AioRpcError=self.AioRpcError),
            StatusCode=self.StatusCode,
        )
        return client, call, channel, subchannel, authorization, grpc_stub

    async def _collect(self, client, *, timeout_seconds=5):
        return [event async for event in client.generate(
            [1, 2], 1, trusted_request_context=object(),
            timeout_seconds=timeout_seconds)]

    async def test_bound_zero_event_capacity_marker_preserves_shared_channel(self):
        from steamboat_runtime.remote_client import RemoteError

        client, call, channel, subchannel, authorization, grpc_stub = self._make_client()
        self.assertTrue(has_capacity_rejection_metadata(
            call.trailers, authorization.binding_bytes))
        other_call = self.Call((), self.StatusCode.UNAVAILABLE, (), authorization, ())
        client._active_calls.add((asyncio.current_task(), other_call))
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(RemoteError) as raised:
                await self._collect(client)

        self.assertEqual(raised.exception.code, "CAPACITY_EXHAUSTED")
        self.assertEqual(channel.dispatched, 1)
        self.assertTrue(call.done())
        self.assertTrue(call.cancelled)
        self.assertEqual(subchannel.fence_calls, 0)
        self.assertFalse(other_call.cancelled)
        self.assertIn((asyncio.current_task(), other_call), client._active_calls)
        self.assertEqual(authorization.failed, [False])
        self.assertTrue(authorization.closed)
        self.assertEqual(authorization.completed, [])

    async def test_missing_or_wrong_binding_capacity_denial_still_fences(self):
        from steamboat_runtime.remote_client import RemoteError

        for metadata in ((), ((BINDING_METADATA_KEY, b"wrong binding"),)):
            with self.subTest(metadata=metadata):
                (client, call, channel, subchannel, authorization,
                 grpc_stub) = self._make_client(metadata=metadata)
                with patch.dict(sys.modules, {"grpc": grpc_stub}):
                    with self.assertRaises((AuthorizationRejected, RemoteError)):
                        await self._collect(client)
                self.assertEqual(channel.dispatched, 1)
                self.assertTrue(call.cancelled)
                self.assertTrue(call.done())
                self.assertEqual(subchannel.fence_calls, 1)
                self.assertEqual(authorization.failed, [True])
                self.assertTrue(authorization.closed)

    async def test_resource_exhausted_with_valid_binding_but_no_marker_fences(self):
        from steamboat_runtime.remote_client import RemoteError

        (client, call, channel, subchannel, authorization,
         grpc_stub) = self._make_client(trailers=())
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(RemoteError):
                await self._collect(client)

        self.assertEqual(channel.dispatched, 1)
        self.assertTrue(call.cancelled)
        self.assertEqual(subchannel.fence_calls, 1)
        self.assertEqual(authorization.failed, [True])
        self.assertTrue(authorization.closed)

    async def test_stalled_trailer_lookup_stops_when_authorization_is_revoked(self):
        authorization = self.Authorization()
        trailer_future = asyncio.get_running_loop().create_future()
        (client, call, channel, subchannel, _authorization,
         grpc_stub) = self._make_client(authorization=authorization,
                                        trailers=trailer_future)
        watcher_signal = asyncio.Event()
        call.trailing_started_event = watcher_signal

        async def watcher(_authorization):
            await watcher_signal.wait()

        client.authorization_watcher = watcher
        started = time.monotonic()
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(AuthorizationRevoked):
                await self._collect(client)

        self.assertLess(time.monotonic() - started, 1.0)
        self.assertTrue(call.trailing_started)
        self.assertTrue(trailer_future.cancelled())
        self.assertTrue(call.cancelled)
        self.assertEqual(channel.dispatched, 1)
        self.assertEqual(subchannel.fence_calls, 1)
        self.assertEqual(authorization.failed, [True])
        self.assertTrue(authorization.closed)

    async def test_stalled_trailer_lookup_is_clipped_to_absolute_request_deadline(self):
        from steamboat_runtime.remote_client import RemoteError

        authorization = self.Authorization()
        trailer_future = asyncio.get_running_loop().create_future()
        (client, call, channel, subchannel, _authorization,
         grpc_stub) = self._make_client(authorization=authorization,
                                        trailers=trailer_future)
        started = time.monotonic()
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(RemoteError):
                await self._collect(client, timeout_seconds=0.5)

        self.assertLess(time.monotonic() - started, 1.5)
        self.assertTrue(call.trailing_started)
        self.assertTrue(trailer_future.cancelled())
        self.assertTrue(call.cancelled)
        self.assertEqual(channel.dispatched, 1)
        self.assertEqual(subchannel.fence_calls, 1)
        self.assertEqual(authorization.failed, [True])
        self.assertTrue(authorization.closed)

    async def test_resource_exhausted_requires_exact_marker_for_exact_binding(self):
        from steamboat_runtime.remote_client import RemoteError

        authorization = self.Authorization()
        valid = capacity_rejection_metadata(authorization.binding_bytes)
        other_binding = b'{"account_id":"acct_other","binding_version":1}'
        other_marker = capacity_rejection_metadata(other_binding)
        bad_digest = ((valid[0][0], valid[0][1][:-1] +
                       bytes((valid[0][1][-1] ^ 1,))),)
        malformed = (
            other_marker,
            ((valid[0][0], b"SNCR\x02" + valid[0][1][5:]),),
            bad_digest,
            (valid[0], valid[0]),
            (valid[0], ("x-unrecognized", b"extra")),
            ((valid[0][0], valid[0][1] + b"x" * MAX_METADATA_BYTES),),
            ((valid[0][0], valid[0][1].decode("latin1")),),
            ((valid[0][0], object()),),
        )
        for trailers in malformed:
            with self.subTest(trailers=trailers):
                (client, call, channel, subchannel, auth,
                 grpc_stub) = self._make_client(trailers=trailers)
                with patch.dict(sys.modules, {"grpc": grpc_stub}):
                    with self.assertRaises(RemoteError):
                        await self._collect(client)
                self.assertEqual(channel.dispatched, 1)
                self.assertTrue(call.cancelled)
                self.assertEqual(subchannel.fence_calls, 1)
                self.assertEqual(auth.failed, [True])
                self.assertTrue(auth.closed)

    async def test_canonical_but_different_initial_binding_fences(self):
        from steamboat_runtime.remote_client import RemoteError

        (client, call, channel, subchannel, authorization,
         grpc_stub) = self._make_client(metadata=((BINDING_METADATA_KEY,
            b'{"account_id":"acct_other","binding_version":1}'),))
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(RemoteError):
                await self._collect(client)

        self.assertEqual(channel.dispatched, 1)
        self.assertTrue(call.cancelled)
        self.assertEqual(subchannel.fence_calls, 1)
        self.assertEqual(authorization.failed, [True])
        self.assertTrue(authorization.closed)

    async def test_capacity_status_after_response_event_still_fences(self):
        from steamboat_runtime.remote_client import RemoteError

        event = {"type": "token", "session_id": "ses_" + "a" * 32,
                 "index": 0, "sequence": 0, "token_id": 3, "position": 2}
        client, call, channel, subchannel, authorization, grpc_stub = self._make_client(
            events=(event,))
        observed = []
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(RemoteError):
                async for item in client.generate(
                        [1, 2], 1, trusted_request_context=object(), timeout_seconds=5):
                    observed.append(item)

        self.assertEqual(len(observed), 1)
        self.assertEqual(channel.dispatched, 1)
        self.assertTrue(call.cancelled)
        self.assertEqual(subchannel.fence_calls, 1)
        self.assertEqual(authorization.failed, [True])
        self.assertTrue(authorization.closed)

    async def test_expired_authorization_on_capacity_error_fences_and_fails_closed(self):
        client, call, channel, subchannel, authorization, grpc_stub = self._make_client(
            authorization=self.Authorization(revoke_on_status=True))
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(AuthorizationRevoked):
                await self._collect(client)

        self.assertEqual(channel.dispatched, 1)
        self.assertTrue(call.cancelled)
        self.assertEqual(subchannel.fence_calls, 1)
        self.assertEqual(authorization.failed, [True])
        self.assertTrue(authorization.closed)

    async def test_other_rpc_errors_still_fence_and_report_unknown_failure(self):
        from steamboat_runtime.remote_client import RemoteError

        client, call, channel, subchannel, authorization, grpc_stub = self._make_client(
            status=self.StatusCode.UNAVAILABLE)
        with patch.dict(sys.modules, {"grpc": grpc_stub}):
            with self.assertRaises(RemoteError) as raised:
                await self._collect(client)

        self.assertEqual(raised.exception.code, "NOT_READY")
        self.assertEqual(channel.dispatched, 1)
        self.assertTrue(call.cancelled)
        self.assertEqual(subchannel.fence_calls, 1)
        self.assertEqual(authorization.failed, [True])
        self.assertTrue(authorization.closed)


class SecureGeneratePendingTrailerOwnershipTests(unittest.IsolatedAsyncioTestCase):
    StatusCode = SecureGenerateCapacityRejectionTests.StatusCode
    AioRpcError = SecureGenerateCapacityRejectionTests.AioRpcError
    Call = SecureGenerateCapacityRejectionTests.Call
    Channel = SecureGenerateCapacityRejectionTests.Channel
    Subchannel = SecureGenerateCapacityRejectionTests.Subchannel

    class Authorization(SecureGenerateCapacityRejectionTests.Authorization):
        def __init__(self):
            super().__init__()
            self.close_calls = 0
            self.closed_event = asyncio.Event()

        def close(self):
            self.close_calls += 1
            self.closed_event.set()
            super().close()

    class Reservation:
        def __init__(self):
            self.releases = 0

        async def release(self):
            self.releases += 1

    _make_client = SecureGenerateCapacityRejectionTests._make_client
    _collect = SecureGenerateCapacityRejectionTests._collect

    def _make_owned_client(self, trailers):
        authorization = self.Authorization()
        (client, call, channel, subchannel, _authorization,
         grpc_stub) = self._make_client(authorization=authorization,
                                        trailers=trailers)
        owner = _SecureRuntimeOwner()
        client._runtime_owner = owner
        reservation = self.Reservation()
        client._reservation = reservation
        subchannel.closed = False

        async def close_subchannel():
            subchannel.closed = True

        subchannel.close = close_subchannel
        call.trailing_started_event = asyncio.Event()
        retained_before = set(_RETAINED_TASKS)
        case = {
            "authorization": authorization,
            "call": call,
            "channel": channel,
            "client": client,
            "grpc_stub": grpc_stub,
            "owner": owner,
            "reservation": reservation,
            "retained_before": retained_before,
            "subchannel": subchannel,
            "caller": None,
            "release_operation": asyncio.Event(),
            "release_child": asyncio.Event(),
        }

        async def cleanup():
            case["release_operation"].set()
            case["release_child"].set()
            caller = case["caller"]
            if caller is not None and not caller.done():
                caller.cancel()
            if caller is not None:
                done, pending = await asyncio.wait((caller,), timeout=2)
                if pending:
                    caller.cancel()
                    done, pending = await asyncio.wait(pending, timeout=2)
                if pending:
                    raise AssertionError("public Generate caller did not drain")
                await asyncio.gather(*done, return_exceptions=True)
            tracked = set(owner.pending_tasks)
            if tracked:
                await asyncio.wait_for(_wait_owned_tasks(tracked), 2)
            if not authorization.closed_event.is_set():
                await asyncio.wait_for(authorization.closed_event.wait(), 2)
            deadline = time.monotonic() + 2
            while (owner.pending_tasks
                   or (_RETAINED_TASKS - retained_before)):
                if time.monotonic() >= deadline:
                    raise AssertionError("secure transport task registries did not drain")
                await asyncio.sleep(0)
            trailers = call.trailers
            if (inspect.iscoroutine(trailers)
                    and inspect.getcoroutinestate(trailers) == inspect.CORO_CREATED):
                trailers.close()
            if not client._closed:
                await client.close()

        case["cleanup"] = cleanup
        return case

    def _start_generate(self, case):
        async def collect():
            with patch.dict(sys.modules, {"grpc": case["grpc_stub"]}):
                return await self._collect(case["client"])

        caller = asyncio.create_task(collect())
        case["caller"] = caller
        self.addAsyncCleanup(case["cleanup"])
        return caller

    async def _assert_retired_and_closed(self, case, caller):
        authorization = case["authorization"]
        owner = case["owner"]
        await asyncio.wait_for(authorization.closed_event.wait(), 2)
        tracked = tuple(owner.pending_tasks)
        if tracked:
            await asyncio.wait_for(_wait_owned_tasks(tracked), 2)
        deadline = time.monotonic() + 2
        while (owner.pending_tasks
               or (_RETAINED_TASKS - case["retained_before"])):
            if time.monotonic() >= deadline:
                self.fail("secure transport task registries did not drain")
            await asyncio.sleep(0)
        self.assertEqual(authorization.failed, [True])
        self.assertEqual(authorization.close_calls, 1)
        self.assertTrue(authorization.closed)
        self.assertFalse(owner.pending_tasks)
        self.assertFalse(_RETAINED_TASKS - case["retained_before"])
        self.assertFalse(case["client"]._active_calls)
        self.assertEqual(case["reservation"].releases, 0)
        await case["client"].close()
        self.assertTrue(case["client"]._closed)
        self.assertTrue(case["subchannel"].closed)
        self.assertEqual(case["reservation"].releases, 1)
        self.assertTrue(caller.done())

    async def test_public_generate_bounds_cancellation_resistant_trailer_and_retains_owner(self):
        cancellation_seen = asyncio.Event()
        case_holder = {}

        async def resistant_trailers():
            case_holder["operation"] = asyncio.current_task()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancellation_seen.set()
                await case_holder["case"]["release_operation"].wait()
                return capacity_rejection_metadata(
                    case_holder["case"]["authorization"].binding_bytes)

        case = self._make_owned_client(resistant_trailers())
        case_holder["case"] = case
        caller = self._start_generate(case)
        await asyncio.wait_for(case["call"].trailing_started_event.wait(), 1)
        started = time.monotonic()
        caller.cancel()
        await asyncio.wait_for(cancellation_seen.wait(), 1)
        done, _ = await asyncio.wait((caller,), timeout=6)
        self.assertTrue(done, "cancellation must return within the guarded grace")
        self.assertLess(time.monotonic() - started, 6)
        with self.assertRaises(SecureTaskPending) as pending:
            await caller

        operation = case_holder["operation"]
        self.assertIn(operation, pending.exception.tasks)
        self.assertFalse(operation.done())
        self.assertIn(operation, case["owner"].pending_tasks)
        self.assertTrue(case["owner"].unavailable)
        self.assertTrue(case["client"]._unavailable)
        self.assertTrue(case["call"].cancelled)
        self.assertEqual(case["subchannel"].fence_calls, 1)
        self.assertEqual(case["channel"].dispatched, 1)
        self.assertFalse(case["client"]._active_calls)
        self.assertEqual(case["authorization"].failed, [])
        self.assertEqual(case["authorization"].close_calls, 0)
        self.assertEqual(case["reservation"].releases, 0)

        case["release_operation"].set()
        await self._assert_retired_and_closed(case, caller)

    async def test_public_generate_repeated_cancellation_does_not_cancel_retained_owner(self):
        cancellation_seen = asyncio.Event()
        case_holder = {}

        async def resistant_trailers():
            case_holder["operation"] = asyncio.current_task()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancellation_seen.set()
                await case_holder["case"]["release_operation"].wait()
                return capacity_rejection_metadata(
                    case_holder["case"]["authorization"].binding_bytes)

        case = self._make_owned_client(resistant_trailers())
        case_holder["case"] = case
        caller = self._start_generate(case)
        await asyncio.wait_for(case["call"].trailing_started_event.wait(), 1)
        caller.cancel()
        await asyncio.wait_for(cancellation_seen.wait(), 1)
        caller.cancel()
        done, _ = await asyncio.wait((caller,), timeout=1)
        self.assertTrue(done, "a repeated caller cancellation must remain bounded")
        with self.assertRaises(SecureTaskPending) as pending:
            await caller

        operation = case_holder["operation"]
        self.assertIn(operation, pending.exception.tasks)
        self.assertFalse(operation.done(), "caller cancellation must not cancel the retained owner")
        self.assertIn(operation, case["owner"].pending_tasks)
        self.assertTrue(case["owner"].unavailable)
        self.assertTrue(case["client"]._unavailable)
        self.assertTrue(case["call"].cancelled)
        self.assertEqual(case["subchannel"].fence_calls, 1)
        self.assertEqual(case["channel"].dispatched, 1)
        self.assertFalse(case["client"]._active_calls)
        self.assertEqual(case["authorization"].close_calls, 0)
        self.assertEqual(case["reservation"].releases, 0)

        case["release_operation"].set()
        await self._assert_retired_and_closed(case, caller)

    async def test_public_generate_tracks_late_pending_descendant_until_actual_retirement(self):
        cancellation_seen = asyncio.Event()
        child_started = asyncio.Event()
        child_tasks = []
        case_holder = {}

        async def descendant():
            child_started.set()
            await case_holder["case"]["release_child"].wait()

        async def resistant_trailers():
            case_holder["operation"] = asyncio.current_task()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancellation_seen.set()
                await case_holder["case"]["release_operation"].wait()
                child = asyncio.create_task(descendant())
                child_tasks.append(child)
                await child_started.wait()
                raise SecureTaskPending((child,), "late trailer descendant")

        case = self._make_owned_client(resistant_trailers())
        case_holder["case"] = case
        caller = self._start_generate(case)
        await asyncio.wait_for(case["call"].trailing_started_event.wait(), 1)
        caller.cancel()
        await asyncio.wait_for(cancellation_seen.wait(), 1)
        done, _ = await asyncio.wait((caller,), timeout=6)
        self.assertTrue(done, "late descendant ownership transfer must be bounded")
        with self.assertRaises(SecureTaskPending) as pending:
            await caller

        operation = case_holder["operation"]
        self.assertIn(operation, pending.exception.tasks)
        self.assertFalse(operation.done())
        self.assertEqual(child_tasks, [], "the descendant is created only after release")
        self.assertEqual(case["authorization"].close_calls, 0)
        self.assertFalse(case["authorization"].closed)
        self.assertIn(operation, case["owner"].pending_tasks)
        self.assertTrue(case["owner"].unavailable)
        self.assertTrue(case["client"]._unavailable)
        self.assertTrue(case["call"].cancelled)
        self.assertEqual(case["subchannel"].fence_calls, 1)
        self.assertEqual(case["channel"].dispatched, 1)
        self.assertFalse(case["client"]._active_calls)
        self.assertEqual(case["reservation"].releases, 0)

        case["release_operation"].set()
        await asyncio.wait_for(asyncio.gather(operation, return_exceptions=True), 1)
        self.assertEqual(len(child_tasks), 1)
        child = child_tasks[0]
        self.assertTrue(child_started.is_set())
        self.assertFalse(child.done())
        self.assertTrue(case["owner"].pending_tasks,
                        "the real runtime owner must retain its late-descendant observer")
        self.assertTrue(case["owner"].pending_tasks
                        & (_RETAINED_TASKS - case["retained_before"]))
        self.assertEqual(case["authorization"].close_calls, 0)
        self.assertFalse(case["authorization"].closed)

        case["release_child"].set()
        await asyncio.wait_for(child, 1)
        await self._assert_retired_and_closed(case, caller)

    async def test_guarded_timeout_uses_one_auth_owner_and_tracks_late_descendant(self):
        cancellation_seen = asyncio.Event()
        root_release = asyncio.Event()
        child_started = asyncio.Event()
        child_release = asyncio.Event()
        authorization = self.Authorization()
        owner = _SecureRuntimeOwner()
        reported = []
        operation_tasks = []
        child_tasks = []
        caller = None
        retained_before = set(_RETAINED_TASKS)

        async def watcher(_authorization):
            await asyncio.Future()

        async def child_operation():
            child_started.set()
            await child_release.wait()

        async def resistant_operation():
            operation_tasks.append(asyncio.current_task())
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancellation_seen.set()
                await root_release.wait()
                child = asyncio.create_task(child_operation())
                child_tasks.append(child)
                await child_started.wait()
                raise SecureTaskPending((child,), "late operation descendant")

        def retain(tasks):
            reported.append(tuple(tasks))
            owner.retain_pending(tasks)

        async def cleanup():
            root_release.set()
            child_release.set()
            if caller is not None and not caller.done():
                caller.cancel()
            if caller is not None:
                done, pending = await asyncio.wait((caller,), timeout=2)
                if pending:
                    caller.cancel()
                    done, pending = await asyncio.wait(pending, timeout=2)
                if pending:
                    raise AssertionError("guarded timeout caller did not drain")
                await asyncio.gather(*done, return_exceptions=True)
            tracked = tuple(owner.pending_tasks)
            if tracked:
                await asyncio.wait_for(_wait_owned_tasks(tracked), 2)
            if not authorization.closed_event.is_set():
                await asyncio.wait_for(authorization.closed_event.wait(), 2)
            deadline = time.monotonic() + 2
            while owner.pending_tasks or (_RETAINED_TASKS - retained_before):
                if time.monotonic() >= deadline:
                    raise AssertionError("guarded timeout ownership tasks did not drain")
                await asyncio.sleep(0)

        self.addAsyncCleanup(cleanup)
        started = time.monotonic()
        caller = asyncio.create_task(_run_guarded(
            resistant_operation(), authorization, watcher, timeout=0.04,
            cancel_grace_seconds=0.01, on_pending=retain))
        await asyncio.wait_for(cancellation_seen.wait(), 1)
        done, _ = await asyncio.wait((caller,), timeout=1)
        self.assertTrue(done, "the timeout handoff must stay bounded")
        self.assertLess(time.monotonic() - started, 1)
        with self.assertRaises(SecureTaskPending) as pending:
            await caller

        operation = operation_tasks[0]
        self.assertIn(operation, pending.exception.tasks)
        self.assertFalse(operation.done())
        self.assertGreaterEqual(len(reported), 2,
                                "each pending handoff must reach the runtime owner")
        self.assertTrue(all(operation in tasks for tasks in reported))
        self.assertIn(operation, owner.pending_tasks)
        self.assertTrue(owner.unavailable)
        self.assertEqual(authorization.failed, [])
        self.assertEqual(authorization.close_calls, 0)

        root_release.set()
        await asyncio.wait_for(asyncio.gather(operation, return_exceptions=True), 1)
        self.assertEqual(len(child_tasks), 1)
        child = child_tasks[0]
        self.assertTrue(child_started.is_set())
        self.assertFalse(child.done())
        self.assertTrue(owner.pending_tasks,
                        "runtime owner must retain descendant observation after the root exits")
        self.assertEqual(authorization.failed, [])
        self.assertEqual(authorization.close_calls, 0)

        child_release.set()
        await asyncio.wait_for(child, 1)
        await asyncio.wait_for(authorization.closed_event.wait(), 1)
        tracked = tuple(owner.pending_tasks)
        if tracked:
            await asyncio.wait_for(_wait_owned_tasks(tracked), 1)
        deadline = time.monotonic() + 1
        while owner.pending_tasks or (_RETAINED_TASKS - retained_before):
            if time.monotonic() >= deadline:
                self.fail("guarded timeout task registries did not clear")
            await asyncio.sleep(0)
        self.assertEqual(authorization.failed, [True])
        self.assertEqual(authorization.close_calls, 1)
        self.assertTrue(authorization.closed)


if __name__ == "__main__":
    unittest.main()
