"""Tests for trusted consumer contexts and Describe-only client bootstrap."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "security"))

from test_identity_core import (
    ACCOUNT_A,
    ASSIGNMENT,
    BOOT_COORDINATOR,
    BOOT_HOST,
    BOOT_ALT_COORDINATOR,
    DEVICE_COORDINATOR,
    DEVICE_HOST,
    DEVICE_ALT_COORDINATOR,
    MODEL,
    NOW,
    FakeTime,
    IdentityFixture,
    ParsedWorkerRequest,
)
from steamboat_security import (
    Authorization,
    Clock,
    LocalIdentity,
    OutboundAuthorizer,
    OutboundTarget,
    ScopeError,
    SessionError,
    new_id,
    sign_snapshot,
)
from steamboat_security.codec import COORDINATOR_SERVICE, WORKER_SERVICE
from steamboat_runtime.participant_context import (
    TrustedRequestContext,
    TrustedRequestContextExpired,
)
import steamboat_runtime.secure_context as secure_context_module
from steamboat_runtime.secure_context import (
    BootstrapWorkerClient,
    ConsumerContextAdmissionError,
    ConsumerContextCapacityError,
    ConsumerContextFactory,
)


class SharedRealMonotonicTime(FakeTime):
    """Fixed wall clock with the same monotonic source as runtime contexts."""

    def monotonic_now(self):
        return time.monotonic()

    def clock(self):
        return Clock(
            wall=lambda: self.wall,
            monotonic=self.monotonic_now,
            uncertainty_seconds=lambda: self.uncertainty,
            resume_token=lambda: self.resume,
        )


class ParsedWorkerResponse:
    DESCRIPTOR = SimpleNamespace(full_name="steamboat.v1.Response")

    def ByteSize(self):
        return 0


class RecordingSecureClient:
    def __init__(self):
        self.calls = []
        self.closed = False
        self.entered = False
        self.exited = False

    async def execute(self, method, request, *, trusted_request_context=None):
        self.calls.append((method, request, trusted_request_context))
        return ParsedWorkerResponse()

    async def close(self):
        self.closed = True

    async def __aenter__(self):
        self.entered = True
        return self

    async def __aexit__(self, *_):
        self.exited = True
        self.closed = True
        return False


class PolicyBackedSecureClient(RecordingSecureClient):
    def __init__(self, adapter, peer_certificate_pem):
        super().__init__()
        self.adapter = adapter
        self.peer_certificate_pem = peer_certificate_pem

    async def execute(self, method, request, *, trusted_request_context=None):
        self.calls.append((method, request, trusted_request_context))
        authorization = self.adapter.authorize_outbound(
            service=WORKER_SERVICE,
            method=method,
            payload=request,
            trusted_request_context=trusted_request_context,
            peer_certificate_pem=self.peer_certificate_pem,
        )
        authorization.close()
        return ParsedWorkerResponse()


class SecureContextTests(IdentityFixture):
    def setUp(self):
        self.time_source = FakeTime()
        self.snapshot_store, self.clock = self.store(self.time_source)

    @staticmethod
    def generate_payload(*, timeout_seconds=30.0):
        return {
            "input_ids": [1, 2],
            "new_tokens": 2,
            "forced_tokens": [3],
            "timeout_seconds": timeout_seconds,
            "capture_logits": False,
        }

    def authorize_generate(self, payload=None, *, store=None, method="Generate"):
        payload = self.generate_payload() if payload is None else payload
        store = self.snapshot_store if store is None else store
        authorizer, _time_source = self.coordinator_authorizer(
            time_source=self.time_source, store=store)
        actor = self.records["consumer"]
        fields = {
            "binding_version": 1,
            "operation_id": new_id("op"),
            "account_id": actor["account_id"],
            "device_id": actor["device_id"],
            "role": actor["role"],
            "credential_epoch": actor["credential_epoch"],
            "target_device_id": DEVICE_COORDINATOR,
        }
        if method == "Generate":
            fields["request_id"] = new_id("req")
        method_payload = payload if method == "Generate" else {}
        authorization = authorizer.authorize(
            COORDINATOR_SERVICE,
            method,
            method_payload,
            self.metadata(COORDINATOR_SERVICE, method, fields),
            self.credentials["consumer"]["certificate"],
        )
        self.assertIs(type(authorization), Authorization)
        return authorization, method_payload

    def authorize_with_runtime_monotonic(self, payload=None, *, store=None):
        time_source = SharedRealMonotonicTime()
        if store is None:
            store, _clock = self.store(time_source)
        previous_time_source = self.time_source
        self.time_source = time_source
        try:
            authorization, admitted = self.authorize_generate(payload, store=store)
        finally:
            self.time_source = previous_time_source
        return authorization, admitted

    def factory(self, **overrides):
        values = {
            "account_id": ACCOUNT_A,
            "device_id": DEVICE_COORDINATOR,
            "coordinator_boot_id": BOOT_COORDINATOR,
            "model_id": MODEL,
        }
        values.update(overrides)
        return ConsumerContextFactory(**values)

    def worker_adapter(self, *, max_describes=2, lifetime=30.0):
        local = LocalIdentity(
            self.credentials["coordinator"]["certificate"],
            BOOT_COORDINATOR,
            MODEL,
        )
        target = OutboundTarget.from_record(
            service=WORKER_SERVICE,
            record=self.records["host"],
            boot_id=BOOT_HOST,
            model_id=MODEL,
            assignment_id=ASSIGNMENT,
        )
        adapter = OutboundAuthorizer(
            local_identity=local,
            snapshot_store=self.snapshot_store,
            clock=self.clock,
            target=target,
            worker_request_type=ParsedWorkerRequest,
            trusted_request_context_type=TrustedRequestContext,
            allow_bootstrap_describe=True,
        )
        bootstrap = adapter.create_bootstrap_context(
            lifetime_seconds=lifetime, max_describes=max_describes)
        return adapter, bootstrap

    def test_factory_builds_actual_context_from_live_core_generate(self):
        authorization, payload = self.authorize_generate()
        factory = self.factory()
        context = factory(authorization, payload)
        self.assertIs(type(context), TrustedRequestContext)
        self.assertIs(context.authorization, authorization)
        self.assertEqual(context.tenant_account_id, authorization.actor.account_id)
        self.assertEqual(context.tenant_account_id, ACCOUNT_A)
        self.assertEqual(context.request_id,
                         authorization.binding["request_id"])
        self.assertTrue(context.session_id.startswith("ses_"))
        self.assertTrue(context.route_id.startswith("route_"))
        self.assertEqual(context.coordinator_boot_id, BOOT_COORDINATOR)
        self.assertEqual(context.route_epoch, 1)
        self.assertEqual(context.attempt, 1)
        context.assert_data_live()

    def test_factory_rejects_fake_closed_wrong_method_role_target_boot_model_and_epoch(self):
        factory = self.factory()
        payload = self.generate_payload()
        fake = SimpleNamespace(assert_live=lambda: True,
                                remaining_seconds=lambda: 5.0,
                                payload=payload)
        with self.assertRaises(ConsumerContextAdmissionError):
            factory(fake, payload)

        authorization, _ = self.authorize_generate()
        authorization.close()
        with self.assertRaises(ConsumerContextAdmissionError):
            factory(authorization, payload)

        describe, _ = self.authorize_generate(method="Describe")
        with self.assertRaises(ConsumerContextAdmissionError):
            factory(describe, {})

        wrong_role, wrong_payload = self.authorize_generate()
        wrong_role.actor = wrong_role.local
        with self.assertRaises(ScopeError):
            factory(wrong_role, wrong_payload)

        wrong_epoch, wrong_payload = self.authorize_generate()
        wrong_epoch.actor = replace(
            wrong_epoch.actor,
            record=replace(wrong_epoch.actor.record, credential_epoch=2),
        )
        with self.assertRaises(ScopeError):
            factory(wrong_epoch, wrong_payload)

        wrong_target, wrong_payload = self.authorize_generate()
        with self.assertRaises(ScopeError):
            self.factory(device_id=DEVICE_ALT_COORDINATOR,
                         coordinator_boot_id=BOOT_ALT_COORDINATOR)(
                             wrong_target, wrong_payload)
        with self.assertRaises(ScopeError):
            self.factory(coordinator_boot_id=BOOT_ALT_COORDINATOR)(
                wrong_target, wrong_payload)
        with self.assertRaises(ScopeError):
            self.factory(model_id="b" * 64)(wrong_target, wrong_payload)

    def test_factory_rejects_payload_mismatch_and_remote_generate_invalid_fields(self):
        authorization, admitted = self.authorize_generate()
        supplied = dict(admitted)
        supplied["new_tokens"] = 1
        with self.assertRaises(ConsumerContextAdmissionError):
            self.factory()(authorization, supplied)

        authorization2, admitted2 = self.authorize_generate()
        invalid = dict(admitted2)
        invalid["capture_logits"] = 1
        authorization2.payload = invalid
        with self.assertRaises(ConsumerContextAdmissionError):
            self.factory()(authorization2, invalid)

        authorization3, admitted3 = self.authorize_generate()
        forwarded = dict(admitted3)
        forwarded["tenant_account_id"] = ACCOUNT_A
        with self.assertRaises(ConsumerContextAdmissionError):
            self.factory()(authorization3, forwarded)

    def test_factory_rechecks_revocation_and_exact_current_grant(self):
        authorization, payload = self.authorize_generate()
        consumer_serial = self.records["consumer"]["serial"]
        records = [record for name, record in self.records.items()
                   if name != "consumer"]
        grants = [grant for grant in self.grants()
                  if grant["actor_serial"] != consumer_serial]
        updated = self.payload(revision=2, records=records, grants=grants,
                               revoked_serials=(consumer_serial,))
        self.snapshot_store.install(sign_snapshot(updated, self.signing_key))
        with self.assertRaises(ConsumerContextAdmissionError):
            self.factory()(authorization, payload)

    def test_factory_clips_hard_deadline_to_request_and_authority(self):
        short_request, request_payload = self.authorize_generate(
            self.generate_payload(timeout_seconds=0.05))
        started = time.monotonic()
        # Pin the factory's sampling instant so the strict bound does not
        # compare the call's later sample with an earlier external stopwatch.
        factory = self.factory(monotonic=lambda: started)
        request_context = factory(short_request, request_payload)
        self.assertLessEqual(request_context.hard_monotonic_deadline,
                             started + 0.05)
        self.assertGreater(request_context.hard_monotonic_deadline, started)
        time.sleep(0.12)
        self.assertGreater(time.monotonic(), request_context.hard_monotonic_deadline)
        with self.assertRaises(TrustedRequestContextExpired):
            request_context.assert_data_live()

        grant_expiry = NOW + 5
        payload = self.payload(grants=self.grants(expires=grant_expiry))
        store, _clock = self.store(self.time_source, payload)
        authority_bound, request = self.authorize_generate(
            self.generate_payload(timeout_seconds=100), store=store)
        authority_context = self.factory()(authority_bound, request)
        self.assertLessEqual(authority_context.hard_monotonic_deadline,
                             time.monotonic() + 5.1)
        self.time_source.advance(6)
        with self.assertRaises(TrustedRequestContextExpired):
            authority_context.assert_data_live()

    def test_absolute_deadline_preserves_receive_time_cap_through_slow_validation(self):
        authorization, payload = self.authorize_with_runtime_monotonic(
            self.generate_payload(timeout_seconds=30.0))
        factory = self.factory(monotonic=time.monotonic)
        received = time.monotonic()
        request_deadline = received + 0.75
        time.sleep(0.02)
        admitted = time.monotonic()
        self.assertGreater(admitted, received)

        original_live = secure_context_module._call_live
        checks = []

        def slow_live(core_authorization):
            checks.append(core_authorization)
            time.sleep(0.01)
            return original_live(core_authorization)

        with patch("steamboat_runtime.secure_context._call_live", slow_live):
            context = factory.create_with_deadline(
                authorization, payload, absolute_deadline=request_deadline)

        # The same absolute value supplied at server receive time survives both
        # delayed validation and the commit-time liveness recheck unchanged.
        self.assertEqual(checks, [authorization, authorization])
        self.assertLessEqual(context.hard_monotonic_deadline, request_deadline)
        self.assertEqual(context.hard_monotonic_deadline, request_deadline)

    def test_expired_during_commit_deadline_does_not_consume_authorization(self):
        authorization, payload = self.authorize_with_runtime_monotonic(
            self.generate_payload(timeout_seconds=30.0))
        factory = self.factory(monotonic=time.monotonic)
        request_deadline = time.monotonic() + 1.0
        original_live = secure_context_module._call_live
        at_commit = threading.Event()
        release_commit = threading.Event()
        checks = []
        outcome = []

        def pause_commit(core_authorization):
            checks.append(core_authorization)
            if len(checks) == 2:
                at_commit.set()
                if not release_commit.wait(timeout=3):
                    raise RuntimeError("test did not release commit check")
            return original_live(core_authorization)

        def create():
            try:
                outcome.append(factory.create_with_deadline(
                    authorization, payload, absolute_deadline=request_deadline))
            except BaseException as error:
                outcome.append(error)

        thread = threading.Thread(target=create, daemon=True)
        with patch("steamboat_runtime.secure_context._call_live", pause_commit):
            thread.start()
            try:
                self.assertTrue(at_commit.wait(timeout=2))
                while time.monotonic() <= request_deadline:
                    time.sleep(0.005)
            finally:
                release_commit.set()
                thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(checks, [authorization, authorization])
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], ConsumerContextAdmissionError)
        self.assertEqual(factory._records, {})

        # A failed commit did not reserve the actual Authorization's one-use
        # slot; a later call with a live cap can create and then release it.
        context = factory.create_with_deadline(
            authorization, payload, absolute_deadline=time.monotonic() + 10.0)
        factory.release(context)

    def test_absolute_deadline_validation_and_authority_fail_without_registration(self):
        authorization, payload = self.authorize_with_runtime_monotonic()
        factory = self.factory(monotonic=time.monotonic)
        malformed = (True, float("nan"), float("inf"), "123", None,
                     time.monotonic() - 1.0)
        for deadline in malformed:
            with self.subTest(deadline=repr(deadline)):
                with self.assertRaises(ConsumerContextAdmissionError):
                    factory.create_with_deadline(
                        authorization, payload, absolute_deadline=deadline)
                self.assertEqual(factory._records, {})

        fake = SimpleNamespace(assert_live=lambda: True,
                               remaining_seconds=lambda: 5.0,
                               payload=payload)
        with self.assertRaises(ConsumerContextAdmissionError):
            factory.create_with_deadline(
                fake, payload, absolute_deadline=time.monotonic() + 10.0)
        self.assertEqual(factory._records, {})

        # Invalid attempts did not consume this actual core Authorization.
        context = factory.create_with_deadline(
            authorization, payload, absolute_deadline=time.monotonic() + 10.0)
        other_factory = self.factory(monotonic=time.monotonic)
        with self.assertRaises(ConsumerContextAdmissionError):
            other_factory.release(context)
        factory.release(context)
        with self.assertRaises(ConsumerContextAdmissionError):
            factory.create_with_deadline(
                authorization, payload, absolute_deadline=time.monotonic() + 10.0)

    def test_absolute_deadline_is_also_clipped_by_current_authorization(self):
        grant_expiry = NOW + 5
        payload = self.payload(grants=self.grants(expires=grant_expiry))
        time_source = SharedRealMonotonicTime()
        store, _clock = self.store(time_source, payload)
        authorization, request = self.authorize_with_runtime_monotonic(
            self.generate_payload(timeout_seconds=30.0), store=store)
        started = time.monotonic()
        request_deadline = started + 30.0
        context = self.factory(monotonic=time.monotonic).create_with_deadline(
            authorization, request, absolute_deadline=request_deadline)
        self.assertLess(context.hard_monotonic_deadline, request_deadline)
        self.assertLessEqual(context.hard_monotonic_deadline, started + 5.0)
        self.assertGreater(context.hard_monotonic_deadline, started)

    def test_factory_deadline_does_not_extend_while_authority_is_rechecked(self):
        time_source = SharedRealMonotonicTime()
        store, _clock = self.store(time_source)
        previous_time_source = self.time_source
        self.time_source = time_source
        try:
            authorization, payload = self.authorize_generate(
                self.generate_payload(timeout_seconds=300.0), store=store)
        finally:
            self.time_source = previous_time_source
        core_deadline = authorization.deadline_monotonic
        original_remaining = authorization.remaining_seconds
        delay_applied = False

        def delayed_remaining():
            nonlocal delay_applied
            if not delay_applied:
                delay_applied = True
                time.sleep(0.05)
            return original_remaining()

        authorization.remaining_seconds = delayed_remaining
        started = time_source.monotonic_now()
        context = self.factory(monotonic=time_source.monotonic_now)(
            authorization, payload)
        finished = time_source.monotonic_now()
        self.assertTrue(delay_applied)
        self.assertGreaterEqual(finished - started, 0.04)
        self.assertLess(context.hard_monotonic_deadline, core_deadline)
        self.assertLessEqual(context.hard_monotonic_deadline,
                             authorization.deadline_monotonic)

    def test_factory_is_one_use_and_capacity_requires_release_and_terminal_cleanup(self):
        factory = self.factory(max_contexts=1)
        first_auth, first_payload = self.authorize_generate()
        second_auth, second_payload = self.authorize_generate()
        first_context = factory(first_auth, first_payload)
        with self.assertRaises(ConsumerContextAdmissionError):
            factory(first_auth, first_payload)
        factory.release(first_context)
        factory.release(first_context)
        with self.assertRaises(ConsumerContextAdmissionError):
            factory(first_auth, first_payload)
        with self.assertRaises(ConsumerContextCapacityError):
            factory(second_auth, second_payload)

        first_auth.close()
        second_context = factory(second_auth, second_payload)
        self.assertIs(type(second_context), TrustedRequestContext)
        factory.release(second_context)
        second_auth.close()

    def test_snapshot_revocation_before_factory_creation_fails_closed(self):
        authorization, payload = self.authorize_generate()
        consumer_serial = self.records["consumer"]["serial"]
        records = [record for name, record in self.records.items()
                   if name != "consumer"]
        grants = [grant for grant in self.grants()
                  if grant["actor_serial"] != consumer_serial]
        revoked = self.payload(revision=2, records=records, grants=grants,
                               revoked_serials=(consumer_serial,))
        self.snapshot_store.install(sign_snapshot(revoked, self.signing_key))
        with self.assertRaises(ConsumerContextAdmissionError):
            self.factory()(authorization, payload)

    def test_bootstrap_wrapper_injects_only_describe_and_forwards_explicit_context(self):
        async def scenario():
            client = RecordingSecureClient()
            _adapter, bootstrap = self.worker_adapter()
            wrapper = BootstrapWorkerClient(client, bootstrap)
            request = ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000)
            await wrapper.execute("Describe", request)
            self.assertIs(client.calls[0][2], bootstrap)

            authorization, payload = self.authorize_generate()
            context = self.factory()(authorization, payload)
            session_request = ParsedWorkerRequest(
                protocol_version=1, manifest_fingerprint=MODEL,
                worker_boot_id=BOOT_HOST, session_id=context.session_id,
                lease_token="lease", timeout_ms=1_000)
            await wrapper.execute("Step", session_request,
                                  trusted_request_context=context)
            self.assertIs(client.calls[1][2], context)

            for method in ("OpenSession", "Step", "RenewSession", "CloseSession",
                           "CancelSession", "SessionStatus"):
                with self.subTest(method=method), self.assertRaises(ScopeError):
                    await wrapper.execute(method, request)
            with self.assertRaises(ScopeError):
                await wrapper.execute("Open", request)
            await wrapper.close()
            self.assertTrue(client.closed)
            with self.assertRaises(ScopeError):
                await wrapper.execute("Describe", request)
        asyncio.run(scenario())

    def test_bootstrap_wrapper_policy_enforces_max_uses_expiry_and_method_scope(self):
        async def scenario():
            adapter, bootstrap = self.worker_adapter(max_describes=1)
            client = PolicyBackedSecureClient(
                adapter, self.credentials["host"]["certificate"])
            wrapper = BootstrapWorkerClient(client, bootstrap)
            request = ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000)
            await wrapper.execute("Describe", request)
            with self.assertRaises(ScopeError):
                await wrapper.execute("Describe", request)
            with self.assertRaises(ScopeError):
                await wrapper.execute("Step", request,
                                      trusted_request_context=bootstrap)

            _expired_adapter, expired_bootstrap = self.worker_adapter(
                max_describes=1, lifetime=1.0)
            expired_client = PolicyBackedSecureClient(
                _expired_adapter, self.credentials["host"]["certificate"])
            expired_wrapper = BootstrapWorkerClient(expired_client, expired_bootstrap)
            self.time_source.advance(2)
            with self.assertRaises((SessionError, ScopeError)):
                await expired_wrapper.execute("Describe", request)
        asyncio.run(scenario())

    def test_wrapper_context_manager_delegates_entry_and_exit(self):
        async def scenario():
            client = RecordingSecureClient()
            _adapter, bootstrap = self.worker_adapter()
            wrapper = BootstrapWorkerClient(client, bootstrap)
            async with wrapper as opened:
                self.assertIs(opened, wrapper)
                self.assertTrue(client.entered)
            self.assertTrue(client.exited)
            self.assertTrue(client.closed)
        asyncio.run(scenario())

    def test_wrapper_close_failure_is_retryable_and_success_is_idempotent(self):
        class FailOnceClient(RecordingSecureClient):
            def __init__(self):
                super().__init__()
                self.close_calls = 0

            async def close(self):
                self.close_calls += 1
                if self.close_calls == 1:
                    raise RuntimeError("injected close failure")
                self.closed = True

        async def scenario():
            client = FailOnceClient()
            _adapter, bootstrap = self.worker_adapter()
            wrapper = BootstrapWorkerClient(client, bootstrap)
            request = ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000)
            with self.assertRaisesRegex(RuntimeError, "injected close failure"):
                await wrapper.close()
            self.assertEqual(client.close_calls, 1)
            self.assertFalse(client.closed)
            with self.assertRaises(ScopeError):
                await wrapper.execute("Describe", request)

            await wrapper.close()
            self.assertEqual(client.close_calls, 2)
            self.assertTrue(client.closed)
            await wrapper.close()
            self.assertEqual(client.close_calls, 2)

        asyncio.run(scenario())

    def test_wrapper_close_cancellation_preserves_retry_path_and_fences_execute(self):
        class CancelOnceClient(RecordingSecureClient):
            def __init__(self):
                super().__init__()
                self.close_calls = 0
                self.first_close_started = asyncio.Event()

            async def close(self):
                self.close_calls += 1
                if self.close_calls == 1:
                    self.first_close_started.set()
                    await asyncio.Future()
                self.closed = True

        async def scenario():
            client = CancelOnceClient()
            _adapter, bootstrap = self.worker_adapter()
            wrapper = BootstrapWorkerClient(client, bootstrap)
            request = ParsedWorkerRequest(protocol_version=1, timeout_ms=5_000)
            first_close = asyncio.create_task(wrapper.close())
            await asyncio.wait_for(client.first_close_started.wait(), timeout=1)
            first_close.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await first_close
            self.assertEqual(client.close_calls, 1)
            self.assertFalse(client.closed)
            with self.assertRaises(ScopeError):
                await wrapper.execute("Describe", request)

            await wrapper.close()
            self.assertEqual(client.close_calls, 2)
            self.assertTrue(client.closed)
            await wrapper.close()
            self.assertEqual(client.close_calls, 2)

        asyncio.run(scenario())

    def test_wrapper_context_exit_failure_retries_same_exit_with_original_args(self):
        class FailOnceExitClient(RecordingSecureClient):
            def __init__(self):
                super().__init__()
                self.exit_calls = []
                self.close_calls = 0

            async def __aexit__(self, *args):
                self.exit_calls.append(args)
                if len(self.exit_calls) == 1:
                    raise RuntimeError("injected exit failure")
                self.exited = True
                self.closed = True
                return False

            async def close(self):
                self.close_calls += 1
                self.closed = True

        async def scenario():
            client = FailOnceExitClient()
            _adapter, bootstrap = self.worker_adapter()
            wrapper = BootstrapWorkerClient(client, bootstrap)
            request = RuntimeError("original context error")
            args = (RuntimeError, request, None)
            with self.assertRaisesRegex(RuntimeError, "injected exit failure"):
                await wrapper.__aexit__(*args)
            with self.assertRaises(ScopeError):
                await wrapper.execute(
                    "Describe", ParsedWorkerRequest(protocol_version=1,
                                                    timeout_ms=5_000))

            await wrapper.close()
            self.assertEqual(client.exit_calls, [args, args])
            self.assertEqual(client.close_calls, 0)
            self.assertTrue(client.exited)
            await wrapper.close()
            self.assertEqual(client.exit_calls, [args, args])

        asyncio.run(scenario())

    def test_secure_context_import_does_not_import_torch_in_fresh_interpreter(self):
        child_env = os.environ.copy()
        inherited = child_env.get("PYTHONPATH")
        child_env["PYTHONPATH"] = os.pathsep.join(
            value for value in (str(ROOT / "src"), inherited) if value)
        result = subprocess.run(
            [sys.executable, "-c",
             "import sys\n"
             "import steamboat_runtime.secure_context\n"
             "if any(name == 'torch' or name.startswith('torch.') "
             "for name in sys.modules):\n"
             "    raise SystemExit('secure context imported Torch')\n"],
            cwd=ROOT,
            env=child_env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr.strip())


if __name__ == "__main__":
    unittest.main()
