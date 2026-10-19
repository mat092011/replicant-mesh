"""Native Linux cold root cutover through real protected processes and inference.

This opt-in integration covers one same-host cold transition only.  It is not
cross-host root rotation, online reload, a consumer daemon, or a recovery gate.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from tests.security.root_cutover_fixture import RootCutoverFixture

_UNKNOWN_PROCESS_OWNERS = []


class _ObservedOutboundAuthorizer:
    """Record the actual encoded outbound binding while delegating unchanged."""

    def __init__(self, delegate):
        self.delegate = delegate
        self.bindings = []

    def authorize_outbound(self, *, service, method, payload,
                           trusted_request_context, peer_certificate_pem):
        from steamboat_security.codec import METADATA_KEY, parse_metadata

        authorization = self.delegate.authorize_outbound(
            service=service, method=method, payload=payload,
            trusted_request_context=trusted_request_context,
            peer_certificate_pem=peer_certificate_pem)
        parsed = parse_metadata(
            service, method,
            ((METADATA_KEY, authorization.binding_bytes),))
        self.bindings.append((service, method, dict(parsed.fields)))
        return authorization


@unittest.skipUnless(os.environ.get("STEAMBOAT_SECURE_PIPELINE_TESTS") == "1",
                     "set STEAMBOAT_SECURE_PIPELINE_TESTS=1 for native root cutover")
class RootCutoverOwnedProcessIntegrationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != "posix" or sys.platform != "linux" or not Path("/proc").is_dir():
            raise RuntimeError("root cutover requires native Linux process ownership")
        artifacts = os.environ.get("STEAMBOAT_ARTIFACT_DIR")
        reference = os.environ.get("STEAMBOAT_REFERENCE_DIR")
        if not artifacts or not Path(artifacts).is_dir():
            raise RuntimeError("opted-in root cutover needs STEAMBOAT_ARTIFACT_DIR")
        if not reference or not Path(reference).is_dir():
            raise RuntimeError("opted-in root cutover needs STEAMBOAT_REFERENCE_DIR")
        if not (Path("/app/lab/root_worker.py").is_file()
                and Path("/app/lab/root_coordinator.py").is_file()):
            raise RuntimeError("opted-in root cutover needs the fixed read-only /app source mount")
        from steamboat_runtime.manifest import load_manifest
        from steamboat_runtime.prepare import verify_snapshot
        import grpc  # noqa: F401
        import google.protobuf  # noqa: F401
        import safetensors  # noqa: F401
        import torch
        import transformers  # noqa: F401
        cls.artifact_directory = Path(artifacts).resolve(strict=True)
        cls.reference_directory = Path(reference).resolve(strict=True)
        cls.manifest = load_manifest(cls.artifact_directory)
        if (cls.manifest.get("model_id") != "Maykeye/TinyLLama-v0"
                or cls.manifest.get("revision")
                    != "298338802ab94432b917bcce11382aa151aee50f"):
            raise RuntimeError("root cutover requires the pinned local C0 model revision")
        verify_snapshot(cls.reference_directory)
        torch.set_num_threads(2)
        try:
            torch.set_num_interop_threads(2)
        except RuntimeError:
            if torch.get_num_interop_threads() > 2:
                raise
        if torch.get_num_threads() > 2 or torch.get_num_interop_threads() > 2:
            raise RuntimeError("root cutover requires at most two Torch threads")
        cls.torch = torch

    async def test_approved_cold_cutover_claims_new_five_role_root_and_generates(self):
        from steamboat_security import SnapshotStore
        from steamboat_security.errors import CredentialError, ScopeError, SnapshotError, StorageError
        from steamboat_security.root_transition_activation import activate_root_transition
        from steamboat_security.root_transition_launch import canonical_role_launch_digest
        from steamboat_security.root_transition_launch_claim import LaunchClaimStore
        from steamboat_security.root_transition_retirement import RetirementSupervisor
        from steamboat_security.root_transition_startup import RootCohortStartup
        from steamboat_security.root_transition_storage import RootGenerationStore
        from steamboat_security.snapshot import sign_snapshot
        from tests.security.test_secure_pipeline import _reference_forced_last_positions
        from steamboat_security.root_runtime import load_root_runtime_binding

        def selected_head():
            # Reuse startup's validator for the pinned manifest and closed
            # selected launch plan. Runtime binding separately verifies the
            # active policy signature and freshness.
            return RootCohortStartup._capture_selected(store)

        temp = tempfile.TemporaryDirectory(prefix="root-cold-cutover-")
        fixture = None
        store = None
        claim_store = None
        client = None
        old_client = None
        watcher = None
        old_watcher = None
        old_budget = new_budget = None
        context = None
        first_context = None
        stream = None
        first_stream = None
        reference_model = None
        old_startup = new_startup = None
        old_supervisor = RetirementSupervisor()
        new_supervisor = RetirementSupervisor()
        old_started = new_started = None
        old_retired = new_retired = None
        old_context = None
        old_actual_context = None
        old_route_evidence = None
        primary = None
        cleanup_errors = []
        try:
            fixture = RootCutoverFixture(
                Path(temp.name) / "fixture", self.artifact_directory,
                self.reference_directory)
            store = RootGenerationStore(fixture.new_root, expected_uid=os.geteuid())
            claim_store = LaunchClaimStore(fixture.claim_root, expected_uid=os.geteuid())
            old_startup = RootCohortStartup(
                root_store=store, claim_store=claim_store,
                retirement_supervisor=old_supervisor, clock=fixture.clock,
                expected_uid=os.geteuid())

            old_started = await old_startup.start(
                fixture.launch_inputs("old"), startup_timeout_seconds=60,
                cleanup_timeout_seconds=15)
            self.assertTrue(old_startup.validate_started_binding(old_started))
            old_selected = selected_head()
            self.assertEqual(old_selected.selector.generation_sha256,
                             fixture.old_generation)
            self.assertEqual(len(old_supervisor._owned), 5)
            self.assertTrue(all(item.process.poll() is None
                                for item in old_supervisor._owned))
            self._assert_three_real_old_worker_listeners(fixture)

            # Exercise a genuine old-root mTLS consumer Generate before the
            # cutover, including its last-position output against the complete
            # same-revision local reference.
            reference_model = self._load_reference_model()
            old_context, old_authorizer, old_watcher, old_binding = self._make_consumer_context(
                fixture, store, generation="old")
            old_observer = _ObservedOutboundAuthorizer(old_authorizer)
            old_client, old_budget = await self._make_coordinator_client(
                fixture, fixture.role_by_name["coordinator"],
                next(spec for spec in fixture.old_specs if spec.role == "personal_coordinator"),
                fixture.role_by_name["consumer"], old_binding, old_observer,
                old_watcher, generation="old")
            old_actual_context = old_authorizer.create_consumer_request_context(
                lifetime_seconds=120)
            self._assert_fresh_consumer_request(old_actual_context)
            # The supervised consumer child loads the same protected old
            # binding and remains alive while this test-owned client uses its
            # certificate/key through the real TLS coordinator channel.
            self._assert_owned_role_live(old_supervisor, fixture.old_specs, "consumer")
            old_actual_request_id = old_actual_context.request_id
            self.assertNotEqual(old_actual_request_id, old_context.request_id)
            with self.torch.inference_mode():
                reference_logits = reference_model(
                    input_ids=self.torch.tensor([[7, 13, 31]], dtype=self.torch.long),
                    use_cache=False, return_dict=True).logits[0, -1]
                expected_old_token = int(reference_logits.argmax().item())
            old_events = []
            async for event in old_client.generate(
                    [7, 13, 31], 1, trusted_request_context=old_actual_context,
                    timeout_seconds=60):
                old_events.append(event)
            self.assertEqual([event["type"] for event in old_events], ["token", "result"])
            self.assertEqual(old_events[0]["token_id"], expected_old_token)
            self.assertEqual(old_events[1]["status"], "completed")
            self.assertIs(old_events[1]["cleanup_complete"], True)
            old_terminal_wall_ns = time.time_ns()
            self._assert_owned_role_live(old_supervisor, fixture.old_specs, "consumer")
            old_session_id = old_events[0]["session_id"]
            self.assertEqual(old_events[1]["session_id"], old_session_id)
            self.assertRegex(old_session_id, r"^ses_[0-9a-f]{32}$")
            old_route_evidence = self._assert_observed_worker_route(
                fixture, "old", old_actual_request_id)
            old_call_bindings = [binding for _service, method, binding
                                 in old_observer.bindings if method == "Generate"]
            self.assertEqual(len(old_call_bindings), 1)
            self.assertEqual(old_call_bindings[0]["request_id"], old_actual_context.request_id)
            self.assertRegex(old_call_bindings[0]["operation_id"], r"^op_[0-9a-f]{32}$")
            self.assertEqual(old_call_bindings[0]["credential_epoch"],
                             next(spec for spec in fixture.old_specs
                                  if spec.role == "consumer").credential_epoch)
            await old_client.close()
            old_client = None
            old_actual_context.close()
            old_actual_context = None
            self.assertTrue(all(value == 0 for value in (
                old_budget.reserved_connections, old_budget.reserved_pending,
                old_budget.reserved_listener_pending_capacity,
                old_budget.reserved_outbound_pending)))
            await self._wait_worker_caches_empty(
                fixture, "old", after_wall_ns=old_terminal_wall_ns)

            expected_old_digest = canonical_role_launch_digest(fixture.old_specs)
            old_tree_before_live_retirement = self._tree_digest(fixture.new_root)
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(old_supervisor.retire_cohort(
                    fixture.transition_id, expected_old_digest,
                    timeout_seconds=0.25), timeout=1)
            self.assertTrue(all(item.process.poll() is None
                                and not old_supervisor._group_absent(item.pgid)
                                for item in old_supervisor._owned))
            self.assertEqual(selected_head().selector_sha256,
                             old_selected.selector_sha256)
            self.assertEqual(self._tree_digest(fixture.new_root),
                             old_tree_before_live_retirement)
            with self.assertRaises(CredentialError):
                activate_root_transition(
                    root_store=store,
                    expected_old_selector_sha256=old_selected.selector_sha256,
                    preparation_path=fixture.preparation_path,
                    preparation_root=fixture.preparation,
                    approval_path=fixture.approval_path,
                    approval_root=fixture.approval_root,
                    expected_uid=os.geteuid(), clock=fixture.clock,
                    candidate=fixture.candidate,
                    new_ca_certificate_pem=fixture.new_ca,
                    new_snapshot_public_key_pem=fixture.new_snapshot_public,
                    new_csr_by_identity=fixture.new_csrs,
                    principal_inputs=fixture.final_inputs,
                    retirement_supervisor=old_supervisor,
                    retirement_capability=object())
            self.assertEqual(selected_head().selector_sha256,
                             old_selected.selector_sha256)
            self.assertNotIn("pending.json", os.listdir(fixture.new_root))
            self.assertEqual(self._tree_digest(fixture.new_root),
                             old_tree_before_live_retirement)

            await asyncio.to_thread(
                old_supervisor.terminate_owned_generation,
                fixture.old_generation, timeout_seconds=5)
            old_retired = await asyncio.wait_for(old_supervisor.retire_cohort(
                fixture.transition_id, expected_old_digest,
                timeout_seconds=15), timeout=16)
            self.assertTrue(old_supervisor.validate_retirement_capability(
                old_retired, transition_id=fixture.transition_id,
                expected_old_bindings_digest=expected_old_digest))
            self.assertTrue(all(item.process.poll() is not None
                                and old_supervisor._group_absent(item.pgid)
                                for item in old_supervisor._owned))
            self._assert_generation_cleanly_exited(fixture, old_supervisor, "old")

            result = activate_root_transition(
                root_store=store,
                expected_old_selector_sha256=old_selected.selector_sha256,
                preparation_path=fixture.preparation_path,
                preparation_root=fixture.preparation,
                approval_path=fixture.approval_path,
                approval_root=fixture.approval_root,
                expected_uid=os.geteuid(), clock=fixture.clock,
                candidate=fixture.candidate,
                new_ca_certificate_pem=fixture.new_ca,
                new_snapshot_public_key_pem=fixture.new_snapshot_public,
                new_csr_by_identity=fixture.new_csrs,
                principal_inputs=fixture.final_inputs,
                retirement_supervisor=old_supervisor,
                retirement_capability=old_retired)
            self.assertEqual(result.generation_sha256, fixture.new_generation)
            selected = selected_head()
            self.assertEqual(selected.selector.generation_sha256, fixture.new_generation)
            self.assertEqual(len(selected.artifacts), 13)
            self.assertEqual(selected.selector.policy_revision,
                             old_selected.selector.policy_revision + 1)
            self.assertEqual(len(fixture.new_specs), 5)
            self.assertTrue(all(
                new.credential_epoch == old.credential_epoch + 1
                and new.admission_epoch == old.admission_epoch + 1
                and new.boot_id != old.boot_id
                for old, new in zip(fixture.old_specs, fixture.new_specs)))

            # Reopen from disk independently and reject both a signed rollback
            # and same-revision policy equivocation under the new signer.
            store.close()
            store = RootGenerationStore(fixture.new_root, expected_uid=os.geteuid())
            selected = selected_head()
            persisted_store = SnapshotStore(
                verification_key_pem=fixture.new_snapshot_public,
                ca_certificate_pem=fixture.new_ca, clock=fixture.clock,
                minimum_revision=selected.selector.policy_revision,
                minimum_policy_digest=selected.selector.policy_digest)
            persisted_store.install(selected.active_policy_snapshot)
            rollback_payload = json.loads(fixture.candidate.policy_payload)
            rollback_payload["revision"] = selected.selector.policy_revision - 1
            new_signer_rollback = sign_snapshot(
                rollback_payload, fixture.new_snapshot_key)
            signature_verifier = SnapshotStore(
                verification_key_pem=fixture.new_snapshot_public,
                ca_certificate_pem=fixture.new_ca, clock=fixture.clock)
            verified_rollback = signature_verifier.install(new_signer_rollback)
            self.assertEqual(verified_rollback.revision,
                             selected.selector.policy_revision - 1)
            self.assertEqual(
                {record.identity for record in verified_rollback.credentials_by_serial.values()},
                {spec.identity for spec in fixture.new_specs})
            self.assertTrue(verified_rollback.grants)
            with self.assertRaises(SnapshotError):
                persisted_store.install(new_signer_rollback)
            equivocated_payload = json.loads(fixture.candidate.policy_payload)
            equivocated_payload["grants"][0]["not_after"] -= 1
            equivocated = sign_snapshot(equivocated_payload, fixture.new_snapshot_key)
            with self.assertRaises(SnapshotError):
                persisted_store.install(equivocated)

            # The exact five-role new plan consumes a second durable whole-plan
            # claim and every child emits real supervisor-observed READY.
            new_startup = RootCohortStartup(
                root_store=store, claim_store=claim_store,
                retirement_supervisor=new_supervisor, clock=fixture.clock,
                expected_uid=os.geteuid())
            new_started = await new_startup.start(
                fixture.launch_inputs("new"), startup_timeout_seconds=60,
                cleanup_timeout_seconds=15)
            self.assertTrue(new_startup.validate_started_binding(new_started))
            self.assertEqual(len(new_supervisor._owned), 5)
            self.assertTrue(all(item.process.poll() is None
                                for item in new_supervisor._owned))
            # As above, the consumer's supervised process proves protected
            # binding load/READY; the real client call below uses that loaded
            # new-root binding from this test process.
            self._assert_owned_role_live(new_supervisor, fixture.new_specs, "consumer")
            self.assertEqual(len(list(fixture.claim_root.glob("claim-*.json"))), 2)
            before_old_leaf_attempt = self._read_worker_binding_observations(
                fixture, "new")
            before_session_bindings = [item for item in before_old_leaf_attempt
                                       if item["method"] != "Describe"]
            self._assert_owned_role_live(
                new_supervisor, fixture.new_specs, "personal_coordinator")
            await self._assert_old_consumer_leaf_refused_by_new_listener(fixture)
            after_old_leaf_attempt = self._read_worker_binding_observations(
                fixture, "new")
            self.assertEqual(
                [item for item in after_old_leaf_attempt
                 if item["method"] != "Describe"], before_session_bindings,
                "old-root mTLS leaf reached new-root worker authorization")
            # This is paired with the valid new-root Generate below on the
            # same live listener; do not infer a TLS cause from gRPC wording.
            for old, new in zip(fixture.old_specs, fixture.new_specs):
                if old.identity == new.identity:
                    self.assertNotEqual(old.certificate_sha256, new.certificate_sha256)
                    self.assertNotEqual(old.boot_id, new.boot_id)
                    self.assertEqual(new.credential_epoch, old.credential_epoch + 1)
                    self.assertEqual(new.admission_epoch, old.admission_epoch + 1)

            # Root/leaf/boot/epoch stale bindings fail before any worker can
            # receive an OpenSession or allocate a KV cache.
            for stale in fixture.launch_inputs("old"):
                with self.subTest(stale_role=stale.launch_spec.role,
                                  stale_device=stale.launch_spec.device_id):
                    with self.assertRaises((CredentialError, StorageError)):
                        load_root_runtime_binding(
                            root_store=store, clock=fixture.clock,
                            expected_launch_spec=stale.launch_spec,
                            configuration_path=stale.configuration_path,
                            configuration_root=stale.configuration_root,
                            expected_uid=os.geteuid())
            new_specs_by_identity = {spec.identity: spec for spec in fixture.new_specs}
            old_by_identity = {spec.identity: spec for spec in fixture.old_specs}
            from dataclasses import replace
            for identity, spec in new_specs_by_identity.items():
                launch = next(x for x in fixture.launch_inputs("new")
                              if x.launch_spec.identity == identity)
                stale_bindings = (
                    replace(spec, boot_id=old_by_identity[identity].boot_id),
                    replace(spec, credential_epoch=old_by_identity[identity].credential_epoch),
                    replace(spec, admission_epoch=old_by_identity[identity].admission_epoch),
                )
                for stale in stale_bindings:
                    with self.assertRaises((CredentialError, StorageError)):
                        load_root_runtime_binding(
                            root_store=store, clock=fixture.clock,
                            expected_launch_spec=stale,
                            configuration_path=launch.configuration_path,
                            configuration_root=launch.configuration_root,
                            expected_uid=os.geteuid())

            # The current signer/CA cannot authenticate an old consumer leaf.
            with self.assertRaises(CredentialError):
                self._make_consumer_context(fixture, store, generation="new",
                                            use_old_credential=True)

            coordinator = fixture.role_by_name["coordinator"]
            consumer = fixture.role_by_name["consumer"]
            coordinator_spec = new_specs_by_identity[
                (coordinator.account_id, coordinator.device_id, coordinator.role)]
            consumer_spec = new_specs_by_identity[
                (consumer.account_id, consumer.device_id, consumer.role)]
            consumer_launch = next(
                launch for launch in fixture.launch_inputs("new")
                if launch.launch_spec.identity == consumer_spec.identity)
            consumer_binding = load_root_runtime_binding(
                root_store=store, clock=fixture.clock,
                expected_launch_spec=consumer_spec,
                configuration_path=consumer_launch.configuration_path,
                configuration_root=consumer_launch.configuration_root,
                expected_uid=os.geteuid())
            from steamboat_runtime.remote_client import SERVICE as COORDINATOR_SERVICE
            from steamboat_security.outbound import AuthorizationWatcher, OutboundAuthorizer, OutboundTarget
            issued_coordinator = fixture.issued_by_identity[
                (coordinator.account_id, coordinator.device_id, coordinator.role)]
            target = OutboundTarget.from_record(
                service=COORDINATOR_SERVICE, record=issued_coordinator.record,
                boot_id=coordinator_spec.boot_id, model_id=fixture.fingerprint)
            authorizer = OutboundAuthorizer(
                local_identity=consumer_binding.local_identity,
                snapshot_store=consumer_binding.snapshot_store,
                clock=fixture.clock, target=target)
            watcher = AuthorizationWatcher(poll_interval_seconds=0.5)
            new_observer = _ObservedOutboundAuthorizer(authorizer)
            client, new_budget = await self._make_coordinator_client(
                fixture, coordinator, coordinator_spec, consumer,
                consumer_binding, new_observer, watcher, generation="new")
            first_context = authorizer.create_consumer_request_context(lifetime_seconds=120)
            self.assertNotEqual(first_context.request_id, old_context.request_id)
            self._assert_fresh_consumer_request(first_context)
            first_request_id = first_context.request_id
            first_stream = client.generate(
                [7, 13, 31], 1, trusted_request_context=first_context,
                timeout_seconds=60)
            first_session_id = None
            first_events = []
            async for event in first_stream:
                first_events.append(event)
                if event.get("type") == "token":
                    first_session_id = event["session_id"]
            await first_stream.aclose()
            first_stream = None
            self.assertIsInstance(first_session_id, str)
            self.assertRegex(first_session_id, r"^ses_[0-9a-f]{32}$")
            self.assertNotEqual(first_session_id, old_session_id)
            self.assertEqual([event["type"] for event in first_events], ["token", "result"])
            with self.torch.inference_mode():
                expected_new_greedy = int(reference_model(
                    input_ids=self.torch.tensor([[7, 13, 31]], dtype=self.torch.long),
                    use_cache=False, return_dict=True).logits[0, -1].argmax().item())
            self.assertEqual(first_events[0]["token_id"], expected_new_greedy)
            self.assertEqual(first_events[1]["status"], "completed")
            self.assertIs(first_events[1]["cleanup_complete"], True)
            self.assertEqual(first_events[1]["session_id"], first_session_id)
            first_terminal_wall_ns = time.time_ns()
            first_route_evidence = self._assert_observed_worker_route(
                fixture, "new", first_request_id)
            self._assert_owned_role_live(new_supervisor, fixture.new_specs, "consumer")
            await self._wait_worker_caches_empty(
                fixture, "new", after_wall_ns=first_terminal_wall_ns)
            first_context.close()
            first_context = None

            context = authorizer.create_consumer_request_context(lifetime_seconds=120)
            self._assert_fresh_consumer_request(context)
            self.assertNotEqual(context.request_id, first_request_id)
            self.assertNotEqual(context.request_id, old_context.request_id)
            with self.assertRaises(ScopeError):
                async for _event in client.generate(
                        [7, 13, 31], 1,
                        trusted_request_context=old_context,
                        timeout_seconds=10):
                    pass
            stale_attempt_wall_ns = time.time_ns()
            new_observations = self._read_worker_binding_observations(fixture, "new")
            self.assertFalse(any(item.get("request_id") == old_context.request_id
                                 for item in new_observations))
            await self._wait_worker_caches_empty(
                fixture, "new", after_wall_ns=stale_attempt_wall_ns)

            forced_token, expected_rows = _reference_forced_last_positions(
                reference_model, self.torch, [7, 13, 31])
            comparisons = []
            terminal_events = []
            forced_event_types = []
            stream = client.generate(
                [7, 13, 31], 9, forced_tokens=[forced_token] * 8,
                trusted_request_context=context, capture_logits=True,
                timeout_seconds=120)
            async for event in stream:
                forced_event_types.append(event.get("type"))
                if event.get("type") == "token":
                    index = len(comparisons)
                    self.assertLess(index, 9)
                    logits = self.torch.tensor(event["logits"], dtype=self.torch.float32)
                    self.assertEqual(tuple(logits.shape), (32_000,))
                    self.assertTrue(bool(self.torch.isfinite(logits).all().item()))
                    self.assertTrue(self.torch.allclose(
                        logits, expected_rows[index], atol=1e-3, rtol=0.0))
                    self.assertEqual(event["token_id"],
                                     int(expected_rows[index].argmax().item()))
                    session_id = event.get("session_id")
                    self.assertIsInstance(session_id, str)
                    self.assertRegex(session_id, r"^ses_[0-9a-f]{32}$")
                    self.assertNotEqual(session_id, first_session_id)
                    if comparisons:
                        self.assertEqual(session_id, comparisons[0][1])
                    comparisons.append((int(event["token_id"]), session_id))
                elif event.get("type") == "result":
                    terminal_events.append(event)
                event.pop("logits", None)
            await stream.aclose()
            self.assertEqual(len(comparisons), 9)
            self.assertEqual(len(terminal_events), 1)
            self.assertEqual(forced_event_types, ["token"] * 9 + ["result"])
            self.assertEqual(terminal_events[0]["status"], "completed")
            self.assertIs(terminal_events[0]["cleanup_complete"], True)
            self.assertEqual(terminal_events[0]["session_id"], comparisons[0][1])
            forced_terminal_wall_ns = time.time_ns()
            self.assertEqual(len({item[1] for item in comparisons}), 1)
            self.assertTrue(all(item[0] == int(expected_rows[index].argmax().item())
                                for index, item in enumerate(comparisons)))
            second_route_evidence = self._assert_observed_worker_route(
                fixture, "new", context.request_id)
            self.assertTrue(set(old_route_evidence["route_ids"]).isdisjoint(
                first_route_evidence["route_ids"] | second_route_evidence["route_ids"]))
            self.assertTrue(set(old_route_evidence["session_ids"]).isdisjoint(
                first_route_evidence["session_ids"] | second_route_evidence["session_ids"]))
            self.assertTrue(first_route_evidence["route_ids"].isdisjoint(
                second_route_evidence["route_ids"]))
            self.assertTrue(first_route_evidence["session_ids"].isdisjoint(
                second_route_evidence["session_ids"]))
            self.assertTrue(set(old_route_evidence["operation_ids"]).isdisjoint(
                first_route_evidence["operation_ids"] | second_route_evidence["operation_ids"]))
            self.assertTrue(first_route_evidence["operation_ids"].isdisjoint(
                second_route_evidence["operation_ids"]))
            await self._wait_worker_caches_empty(
                fixture, "new", after_wall_ns=forced_terminal_wall_ns)
            new_call_bindings = [binding for _service, method, binding
                                 in new_observer.bindings if method == "Generate"]
            self.assertEqual(len(new_call_bindings), 2)
            new_operation_ids = [item["operation_id"] for item in new_call_bindings]
            self.assertEqual(len(set(new_operation_ids)), 2)
            self.assertTrue(all(re.fullmatch(r"op_[0-9a-f]{32}", value)
                                for value in new_operation_ids))
            new_request_ids = [item["request_id"] for item in new_call_bindings]
            self.assertEqual(len(set(new_request_ids)), 2)
            self.assertTrue(all(re.fullmatch(r"req_[0-9a-f]{32}", value)
                                for value in new_request_ids))
            self.assertTrue(set(new_request_ids).isdisjoint({
                old_actual_request_id, old_context.request_id}))
            self.assertTrue(set(new_operation_ids).isdisjoint(
                item["operation_id"] for _service, method, item in old_observer.bindings
                if method == "Generate"))
            self.assertEqual(new_request_ids[0], first_request_id)
            self.assertEqual(new_request_ids[1], context.request_id)
            self.assertTrue(all(item["role"] == "consumer"
                                and item["credential_epoch"]
                                    == consumer_spec.credential_epoch
                                for item in new_call_bindings))
            context.close()
            context = None
            await client.close()
            client = None
            self.assertTrue(all(value == 0 for value in (
                new_budget.reserved_connections, new_budget.reserved_pending,
                new_budget.reserved_listener_pending_capacity,
                new_budget.reserved_outbound_pending)))
            new_digest = canonical_role_launch_digest(fixture.new_specs)
            await asyncio.to_thread(
                new_supervisor.terminate_owned_generation,
                fixture.new_generation, timeout_seconds=5)
            new_retired = await asyncio.wait_for(new_supervisor.retire_cohort(
                fixture.transition_id, new_digest, timeout_seconds=15), timeout=16)
            self.assertTrue(new_supervisor.validate_retirement_capability(
                new_retired, transition_id=fixture.transition_id,
                expected_old_bindings_digest=new_digest))
            self._assert_generation_cleanly_exited(fixture, new_supervisor, "new")

        except BaseException as error:
            primary = error
            raise
        finally:
            async def cleanup(label, callback):
                try:
                    result = callback()
                    if asyncio.iscoroutine(result):
                        result = await result
                    if result is False:
                        raise RuntimeError(f"{label} did not confirm cleanup")
                except BaseException as error:
                    cleanup_errors.append(error)

            if stream is not None:
                await cleanup("consumer stream", stream.aclose)
            if first_stream is not None:
                await cleanup("first consumer stream", first_stream.aclose)
            if context is not None:
                await cleanup("new consumer request context", context.close)
            if first_context is not None:
                await cleanup("first new consumer request context", first_context.close)
            if old_context is not None:
                await cleanup("old consumer request context", old_context.close)
            if old_actual_context is not None:
                await cleanup("old Generate request context", old_actual_context.close)
            if old_client is not None:
                await cleanup("old coordinator client", old_client.close)
            if client is not None:
                await cleanup("new coordinator client", client.close)
            reference_model = None
            import gc
            gc.collect()
            for supervisor, generation in (
                    (new_supervisor, getattr(fixture, "new_generation", None)),
                    (old_supervisor, getattr(fixture, "old_generation", None))):
                if generation and any(
                        item.process.poll() is None
                        for item in supervisor._owned
                        if any(spec.generation_sha256 == generation for spec in item.specs)):
                    await cleanup(f"{generation[:8]} owned process groups", lambda s=supervisor, g=generation:
                                  asyncio.to_thread(s.terminate_owned_generation,
                                                    g, timeout_seconds=5))
                if generation and supervisor._owned and all(
                        item.process.poll() is not None
                        and supervisor._group_absent(item.pgid)
                        for item in supervisor._owned
                        if any(spec.generation_sha256 == generation for spec in item.specs)):
                    try:
                        owned_specs = tuple(sorted((
                            spec for item in supervisor._owned
                            for spec in item.specs
                            if spec.generation_sha256 == generation),
                            key=lambda spec: spec.identity))
                        if (not owned_specs or len({spec.identity for spec in owned_specs})
                                != len(owned_specs)):
                            raise RuntimeError("owned cleanup plans are missing or duplicated")
                        digest = canonical_role_launch_digest(owned_specs)
                        known = (old_retired if supervisor is old_supervisor
                                 else new_retired)
                        if not (known is not None and supervisor.validate_retirement_capability(
                                known, transition_id=fixture.transition_id,
                                expected_old_bindings_digest=digest)):
                            await asyncio.wait_for(supervisor.retire_cohort(
                                fixture.transition_id, digest,
                                timeout_seconds=15), timeout=16)
                    except BaseException as error:
                        cleanup_errors.append(error)
            owners_gone = all(item.process.poll() is not None
                              and supervisor._group_absent(item.pgid)
                              for supervisor in (old_supervisor, new_supervisor)
                              for item in supervisor._owned)
            if owners_gone:
                for supervisor in (old_supervisor, new_supervisor):
                    for owner in supervisor._owned:
                        for name in ("stdin", "stdout", "stderr"):
                            pipe = getattr(owner.process, name, None)
                            if pipe is not None and not pipe.closed:
                                await cleanup(f"owned process {name} pipe", pipe.close)
                if store is not None:
                    await cleanup("selected root store", store.close)
                if claim_store is not None:
                    await cleanup("launch claim store", claim_store.close)
                if fixture is not None:
                    await cleanup("private root cutover fixture", fixture.close)
                await cleanup("temporary directory", temp.cleanup)
            else:
                cleanup_errors.append(RuntimeError(
                    "owned process group is live or unknown; stores and private files retained"))
                _UNKNOWN_PROCESS_OWNERS.append((
                    temp, fixture, store, claim_store,
                    old_supervisor, new_supervisor, old_client, client,
                    old_context, old_actual_context, context, first_context))
            if cleanup_errors:
                if primary is not None:
                    raise BaseExceptionGroup(
                        "root cutover failed and cleanup also failed",
                        [primary, *cleanup_errors])
                raise BaseExceptionGroup("root cutover cleanup failed", cleanup_errors)

    @staticmethod
    def _make_consumer_context(fixture, root_store, *, generation: str,
                               use_old_credential: bool = False):
        from steamboat_security.authorization import LocalIdentity
        from steamboat_runtime.remote_client import SERVICE as COORDINATOR_SERVICE
        from steamboat_security.outbound import OutboundAuthorizer, OutboundTarget
        from steamboat_security.root_runtime import load_root_runtime_binding

        consumer = fixture.role_by_name["consumer"]
        coordinator = fixture.role_by_name["coordinator"]
        if generation == "old":
            spec = next(item for item in fixture.old_specs if item.role == "consumer")
            coordinator_record = coordinator.record
            launches = fixture.launch_inputs("old")
        else:
            spec = next(item for item in fixture.new_specs if item.role == "consumer")
            issued_coordinator = fixture.issued_by_identity[
                (coordinator.account_id, coordinator.device_id, coordinator.role)]
            coordinator_record = issued_coordinator.record
            launches = fixture.launch_inputs("new")
        launch = next(item for item in launches if item.launch_spec.identity == spec.identity)
        binding = load_root_runtime_binding(
            root_store=root_store, clock=fixture.clock,
            expected_launch_spec=spec, configuration_path=launch.configuration_path,
            configuration_root=launch.configuration_root,
            expected_uid=os.geteuid())
        if generation == "old":
            coordinator_spec = next(item for item in fixture.old_specs
                                    if item.role == "personal_coordinator")
            coordinator_boot = coordinator_spec.boot_id
        else:
            coordinator_spec = next(item for item in fixture.new_specs
                                    if item.role == "personal_coordinator")
            coordinator_boot = coordinator_spec.boot_id
        local = binding.local_identity
        if use_old_credential:
            local = LocalIdentity(
                consumer.certificate_pem, spec.boot_id, fixture.fingerprint, None,
                spec.admission_epoch, spec.generation_sha256)
        target = OutboundTarget.from_record(
            service=COORDINATOR_SERVICE, record=coordinator_record,
            boot_id=coordinator_boot, model_id=fixture.fingerprint)
        authorizer = OutboundAuthorizer(
            local_identity=local, snapshot_store=binding.snapshot_store,
            clock=fixture.clock, target=target)
        context = authorizer.create_consumer_request_context(lifetime_seconds=120)
        from steamboat_security.outbound import AuthorizationWatcher
        watcher = AuthorizationWatcher(poll_interval_seconds=0.5)
        return context, authorizer, watcher, binding

    @staticmethod
    async def _make_coordinator_client(fixture, coordinator, coordinator_spec,
                                       consumer, consumer_binding, authorizer, watcher,
                                       *, generation: str):
        from steamboat_runtime.protocol.secure_transport import (
            C0ExpectedServerLeafAdapter, ExpectedServerIdentity, FixedPeer,
            LocalTlsIdentity, NodeConnectionBudget, create_secure_coordinator_client,
        )
        from steamboat_security import verify_expected_server_leaf

        material = (fixture.old_generation_material if generation == "old"
                    else fixture.new_generation_material)
        if generation == "old":
            coordinator_certificate = coordinator.certificate_pem
            coordinator_record = coordinator.record
            coordinator_boot = coordinator.boot_id
            cohort_ca = fixture.identities.cohort_ca_pem
        else:
            issued_coordinator = fixture.issued_by_identity[
                (coordinator.account_id, coordinator.device_id, coordinator.role)]
            coordinator_certificate = issued_coordinator.certificate_pem
            coordinator_record = issued_coordinator.record
            coordinator_boot = coordinator_spec.boot_id
            cohort_ca = fixture.new_ca
        if type(coordinator_record) is dict:
            serial = int(coordinator_record["serial"], 16)
            public_key_hash = coordinator_record["public_key_sha256"]
            certificate_hash = coordinator_record["certificate_sha256"]
        else:
            serial = int(coordinator_record.serial, 16)
            public_key_hash = coordinator_record.public_key_sha256
            certificate_hash = coordinator_record.certificate_sha256
        peer = FixedPeer(
            endpoint=f"127.0.0.1:{material['entries']['coordinator']['endpoint']}",
            allowed_addresses=("127.0.0.1",), device_id=coordinator.device_id,
            server_leaf_pem=coordinator_certificate,
            cohort_ca_pem=cohort_ca,
            expected_server=ExpectedServerIdentity(
                coordinator.account_id, coordinator.device_id,
                "personal_coordinator", serial, public_key_hash,
                certificate_hash, "127.0.0.1"))
        budget = NodeConnectionBudget(max_connections=16, max_pending=4)
        client = await create_secure_coordinator_client(
            peer, local_identity=LocalTlsIdentity(
                consumer_binding.tls_materials.certificate_pem,
                consumer_binding.tls_materials.private_key_pem),
            outbound_authorizer=authorizer,
            authorization_watcher=watcher,
            verify_expected_server_leaf=C0ExpectedServerLeafAdapter(
                verify_expected_server_leaf), connection_controller=budget)
        return client, budget

    async def _assert_old_consumer_leaf_refused_by_new_listener(self, fixture):
        import grpc

        old_consumer = fixture.role_by_name["consumer"]
        endpoint = fixture.new_generation_material["entries"]["coordinator"]["endpoint"]
        credentials = grpc.ssl_channel_credentials(
            root_certificates=fixture.new_ca,
            private_key=old_consumer.private_key_pem,
            certificate_chain=old_consumer.certificate_pem)
        channel = grpc.aio.secure_channel(
            f"127.0.0.1:{endpoint}", credentials,
            options=(("grpc.enable_retries", 0),))
        try:
            describe = channel.unary_unary(
                "/steamboat.v1.Coordinator/Describe")
            with self.assertRaises(grpc.aio.AioRpcError) as rejected:
                await asyncio.wait_for(describe(
                    b"{}", timeout=5, wait_for_ready=False), timeout=6)
            self.assertEqual(rejected.exception.code(), grpc.StatusCode.UNAVAILABLE)
        finally:
            await channel.close()

    @staticmethod
    def _assert_fresh_consumer_request(context):
        value = context.request_id
        if (not isinstance(value, str) or not value.startswith("req_")
                or len(value) != 36
                or any(char not in "0123456789abcdef" for char in value[4:])):
            raise AssertionError("consumer request context does not contain a fresh typed request ID")

    def _load_reference_model(self):
        from transformers import AutoModelForCausalLM

        model = AutoModelForCausalLM.from_pretrained(
            str(self.reference_directory), dtype=self.torch.float32,
            attn_implementation="eager", local_files_only=True,
            use_safetensors=True)
        return model.to("cpu").eval().requires_grad_(False)

    @staticmethod
    def _assert_three_real_old_worker_listeners(fixture):
        for index in (1, 2, 3):
            endpoint = fixture.old_generation_material["entries"][f"worker-{index}"]["endpoint"]
            with socket.create_connection(("127.0.0.1", endpoint), timeout=2):
                pass

    @staticmethod
    def _worker_caches_empty(fixture, label, after_wall_ns):
        from steamboat_security.files import safe_read

        material = (fixture.old_generation_material if label == "old"
                    else fixture.new_generation_material)
        for index in (1, 2, 3):
            root = material["entries"][f"worker-{index}"]["root"]
            status_path = root / "status.json"
            info = os.stat(status_path, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_mtime_ns <= after_wall_ns):
                return False
            status = json.loads(safe_read(
                status_path, root=root, expected_uid=os.geteuid(),
                max_bytes=16 * 1024))
            handler = status.get("handler", {})
            bridge = status.get("bridge", {})
            principal = fixture.role_by_name[f"worker-{index}"]
            spec = next(item for item in material["specs"]
                        if item.role == "host" and item.identity == (
                            principal.account_id, principal.device_id, principal.role))
            if (spec.generation_sha256 != material["generation"]
                    or status.get("schema_version") != 1
                    or status.get("event") not in ("ready", "heartbeat")
                    or status.get("phase") != "ready"
                    or status.get("report_state") != "confirmed"
                    or status.get("resource_state") != "observed"
                    or status.get("worker_name") != f"worker-{index}"
                    or status.get("account_id") != principal.account_id
                    or status.get("device_id") != principal.device_id
                    or status.get("boot_id") != spec.boot_id
                    or status.get("assignment_id") != principal.assignment_id
                    or status.get("model_id") != fixture.manifest["model_id"]
                    or status.get("model_revision") != fixture.manifest["revision"]
                    or status.get("manifest_fingerprint") != fixture.fingerprint
                    or handler.get("state") != "observed"
                    or handler.get("active_sessions") != 0
                    or handler.get("active_session_ids") != []
                    or handler.get("tombstones") != 0
                    or handler.get("active_compute") is not False
                    or handler.get("queued_operations") != 0
                    or handler.get("committed_cache_bytes") != 0
                    or handler.get("allocated_cache_bytes") != 0
                    or handler.get("cache_bytes_exact") is not True
                    or handler.get("retained_entries") != 0
                    or handler.get("requires_restart") is not False
                    or handler.get("stopping") is not False
                    or status.get("transport", {}).get("server_state") != "running"
                    or status.get("transport", {}).get("reserved_connections")
                        != status.get("transport", {}).get("listener_slots")
                    or status.get("transport", {}).get("reserved_pending") != 0
                    or status.get("transport", {}).get("reserved_listener_pending_capacity")
                        != status.get("transport", {}).get("listener_slots")
                    or status.get("transport", {}).get("reserved_outbound_pending") != 0
                    or bridge.get("state") != "observed"
                    or bridge.get("ready") is not True
                    or bridge.get("unavailable") is not False
                    or bridge.get("requires_restart") is not False
                    or bridge.get("cleanup_confirmed") is not True
                    or bridge.get("active_authorizations") != 0
                    or bridge.get("owned_sessions") != 0
                    or bridge.get("pending_notices") != 0
                    or bridge.get("fault_present") is not False):
                return False
        return True

    @staticmethod
    def _read_worker_binding_observations(fixture, label):
        from steamboat_security.files import safe_read

        material = (fixture.old_generation_material if label == "old"
                    else fixture.new_generation_material)
        entry = material["entries"]["coordinator"]
        path = Path(entry["observer_path"])
        root = Path(entry["root"])
        protected_inputs = {
            root / "status.json", Path(entry["runtime_path"]),
            Path(entry["header_path"]), Path(entry["manifest_path"]),
        }
        if (path.parent != root or path.name != "worker-binding-observations.jsonl"
                or path in protected_inputs):
            raise AssertionError("test observer aliases protected runtime status/configuration")
        raw = safe_read(path, root=root, expected_uid=os.geteuid(),
                        max_bytes=256 * 1024)
        if len(raw) > 256 * 1024 or (raw and not raw.endswith(b"\n")):
            raise AssertionError("test observer output exceeds its fixed bound or framing")
        lines = raw.splitlines()
        if len(lines) > 256:
            raise AssertionError("test observer exceeded its 256 record cap")
        records = []
        for line in lines:
            value = json.loads(line.decode("ascii"))
            if (type(value) is not dict or value.get("service") != "steamboat.v1.Worker"
                    or value.get("method") not in {
                        "Describe", "OpenSession", "RenewSession", "Step",
                        "CloseSession", "CancelSession", "SessionStatus"}
                    or any(key in value for key in (
                        "payload", "prompt", "tensor", "private_key", "certificate"))):
                raise AssertionError("test observer recorded an invalid or sensitive field")
            records.append(value)
        return records

    def _assert_observed_worker_route(self, fixture, label, request_id):
        from steamboat_security.ids import validate_id

        material = (fixture.old_generation_material if label == "old"
                    else fixture.new_generation_material)
        specs = material["specs"]
        coordinator_spec = next(spec for spec in specs
                               if spec.role == "personal_coordinator")
        worker_specs = {spec.device_id: spec for spec in specs if spec.role == "host"}
        records = self._read_worker_binding_observations(fixture, label)
        route_records = [record for record in records
                         if record.get("request_id") == request_id]
        if not route_records:
            self.fail(f"{label} Generate produced no observed worker binding")
        sessions, routes, operations, targets = set(), set(), set(), set()
        methods_by_target = {}
        for record in route_records:
            self.assertEqual(record.get("role"), "personal_coordinator")
            self.assertEqual(record.get("account_id"), coordinator_spec.account_id)
            self.assertEqual(record.get("device_id"), coordinator_spec.device_id)
            self.assertEqual(record.get("credential_epoch"), coordinator_spec.credential_epoch)
            self.assertEqual(record.get("coordinator_boot_id"), coordinator_spec.boot_id)
            self.assertEqual(record.get("route_epoch"), 1)
            self.assertEqual(record.get("attempt"), 1)
            session_id = validate_id(record.get("session_id"), "ses")
            route_id = validate_id(record.get("route_id"), "route")
            operation_id = validate_id(record.get("operation_id"), "op")
            target = record.get("target_device_id")
            validate_id(target, "dev")
            target_spec = worker_specs.get(target)
            if target_spec is None:
                self.fail("observed route targeted a worker outside the exact launch plan")
            self.assertEqual(record.get("worker_boot_id"), target_spec.boot_id)
            sessions.add(session_id)
            routes.add(route_id)
            operations.add(operation_id)
            targets.add(target)
            methods_by_target.setdefault(target, set()).add(record["method"])
        self.assertEqual(len(sessions), 1)
        self.assertEqual(len(routes), 1)
        self.assertEqual(len(operations), len(route_records))
        self.assertEqual(targets, set(worker_specs))
        for target in worker_specs:
            self.assertTrue({"OpenSession", "Step", "CloseSession"}
                            <= methods_by_target[target])
        return {"session_ids": sessions, "route_ids": routes,
                "operation_ids": operations}

    async def _wait_worker_caches_empty(self, fixture, label, *, after_wall_ns):
        limits = fixture.manifest["limits"]
        # CloseSession intentionally retains a zeroed tombstone for one RPC
        # timeout. Wait for the real configured lease/reap path to remove it;
        # every accepted report must also be a same-host heartbeat written
        # after the terminal Generate/rejection marker.
        timeout = (limits["rpc_timeout_seconds"]
                   + 2 * limits["lease_check_interval_seconds"] + 3)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if self._worker_caches_empty(fixture, label, after_wall_ns):
                    return
            except (OSError, ValueError, KeyError):
                pass
            await asyncio.sleep(0.05)
        self.fail(f"{label} worker process reports did not confirm empty caches")

    @staticmethod
    def _assert_owned_role_live(supervisor, specs, role):
        identities = {spec.identity for spec in specs if spec.role == role}
        owners = [owner for owner in supervisor._owned
                  if any(spec.identity in identities for spec in owner.specs)]
        if len(owners) != 1 or owners[0].process.poll() is not None:
            raise AssertionError(f"supervised {role} process is not alive")

    @staticmethod
    def _tree_digest(root):
        digest = hashlib.sha256()
        for path in sorted(Path(root).rglob("*")):
            if path.is_file():
                relative = path.relative_to(root).as_posix().encode("utf-8")
                content = path.read_bytes()
                digest.update(len(relative).to_bytes(4, "big"))
                digest.update(relative)
                digest.update(hashlib.sha256(content).digest())
        return digest.hexdigest()

    @staticmethod
    def _assert_generation_cleanly_exited(fixture, supervisor, label):
        from steamboat_security.files import safe_read

        material = (fixture.old_generation_material if label == "old"
                    else fixture.new_generation_material)
        role_name_by_identity = {
            (role["old"].account_id, role["old"].device_id, role["old"].role): role["name"]
            for role in fixture.roles}
        for owner in supervisor._owned:
            if owner.process.poll() is None or not supervisor._group_absent(owner.pgid):
                raise AssertionError(f"{label} owned process group remains live")
            if owner.process.returncode != 0:
                raise AssertionError(
                    f"{label} owned process exited {owner.process.returncode}, expected clean exit 0")
            if len(owner.specs) != 1:
                raise AssertionError("root cutover process group unexpectedly owns multiple roles")
            spec = owner.specs[0]
            name = role_name_by_identity[spec.identity]
            root = material["entries"][name]["root"]
            if name.startswith("worker-"):
                status = json.loads(safe_read(
                    root / "status.json", root=root, expected_uid=os.geteuid(),
                    max_bytes=16 * 1024))
                shutdown = status.get("shutdown", {})
                handler = status.get("handler", {})
                bridge = status.get("bridge", {})
                transport = status.get("transport", {})
                # Normal bridge stop fences the worker and marks restart
                # required. This confirms cleanup, not service health/recovery.
                principal = fixture.role_by_name[name]
                expected_spec = next(item for item in material["specs"]
                                     if item.identity == spec.identity)
                if (status.get("event") != "final" or status.get("phase") != "stopped"
                        or status.get("report_state") != "confirmed"
                        or status.get("resource_state") != "observed"
                        or status.get("worker_name") != name
                        or status.get("account_id") != principal.account_id
                        or status.get("device_id") != principal.device_id
                        or status.get("boot_id") != expected_spec.boot_id
                        or status.get("assignment_id") != principal.assignment_id
                        or status.get("model_id") != fixture.manifest["model_id"]
                        or status.get("model_revision") != fixture.manifest["revision"]
                        or status.get("manifest_fingerprint") != fixture.fingerprint
                        or shutdown.get("overall") != "confirmed"
                        or shutdown.get("server") != "confirmed"
                        or shutdown.get("bridge") != "confirmed"
                        or shutdown.get("handler") != "confirmed"
                        or handler.get("active_sessions") != 0
                        or handler.get("active_session_ids") != []
                        or handler.get("tombstones") != 0
                        or handler.get("active_compute") is not False
                        or handler.get("queued_operations") != 0
                        or handler.get("committed_cache_bytes") != 0
                        or handler.get("allocated_cache_bytes") != 0
                        or handler.get("cache_bytes_exact") is not True
                        or handler.get("retained_entries") != 0
                        or type(handler.get("requires_restart")) is not bool
                        or handler.get("requires_restart") is not True
                        or handler.get("stopping") is not True
                        or bridge.get("state") != "observed"
                        or bridge.get("cleanup_confirmed") is not True
                        or bridge.get("active_authorizations") != 0
                        or bridge.get("owned_sessions") != 0
                        or bridge.get("pending_notices") != 0
                        or type(bridge.get("requires_restart")) is not bool
                        or bridge.get("requires_restart") is not handler.get("requires_restart")
                        or type(bridge.get("ready")) is not bool
                        or bridge.get("ready") is not False
                        or type(bridge.get("unavailable")) is not bool
                        or bridge.get("unavailable") is not True
                        or transport.get("server_state") != "stopped"
                        or transport.get("reserved_connections") != 0
                        or transport.get("reserved_pending") != 0
                        or transport.get("reserved_listener_pending_capacity") != 0
                        or transport.get("reserved_outbound_pending") != 0):
                    raise AssertionError(f"{label} {name} final resource status is incomplete")
            elif name == "coordinator":
                status = json.loads(safe_read(
                    root / "status.json", root=root, expected_uid=os.geteuid(),
                    max_bytes=16 * 1024))
                if (status.get("event") != "root_coordinator_status"
                        or status.get("phase") != "stopped"
                        or status.get("shutdown_confirmed") is not True
                        or status.get("active_requests") != 0):
                    raise AssertionError(f"{label} coordinator final shutdown status is incomplete")
            else:
                status = json.loads(safe_read(
                    root / "consumer-status.json", root=root,
                    expected_uid=os.geteuid(), max_bytes=4096))
                if (status.get("event") != "root_test_consumer_status"
                        or status.get("phase") != "stopped"
                        or status.get("shutdown_confirmed") is not True):
                    raise AssertionError(f"{label} test consumer final status is incomplete")


if __name__ == "__main__":
    unittest.main()
