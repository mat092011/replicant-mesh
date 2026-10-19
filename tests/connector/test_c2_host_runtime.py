"""C2 selected host assigned-stage composition and retained ownership tests."""
from __future__ import annotations

import asyncio
import base64
import json
import os
from contextlib import contextmanager
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_connector.c2_host_runtime import (
    C2HostRuntimeError, _validate_allocations, build_c2_host_runtime,
)
from steamboat_connector.runtime_pin_handoff import validate_child_pin
from steamboat_connector.policy import validate_policy
from steamboat_security.errors import CredentialError


class C2HostRuntimeContractTests(unittest.TestCase):
    def test_import_does_not_load_torch(self):
        code = ("import sys; sys.path.insert(0, " + repr(str(ROOT / "src")) + "); "
                "import steamboat_connector.c2_host_runtime; "
                "assert 'torch' not in sys.modules")
        subprocess.run([sys.executable, "-I", "-c", code], check=True,
                       capture_output=True, text=True, timeout=10)

_ARTIFACTS = Path(os.environ.get("STEAMBOAT_C2_STARTUP_ARTIFACTS", "/artifacts"))
_NATIVE_FIXTURE = os.name == "posix" and hasattr(os, "geteuid") and _ARTIFACTS.is_dir()


@unittest.skipUnless(_NATIVE_FIXTURE,
    "requires Linux POSIX and the approved offline /artifacts model fixture")
class C2HostRuntimeNativeTests(unittest.IsolatedAsyncioTestCase):
    @contextmanager
    def resources(self, scratch, *, pin_variant=None):
        from tests.connector.c2_startup_fixture import c2_startup_fixture
        from steamboat_connector.artifacts import ArtifactInstaller
        from steamboat_connector.c2_child_config import (
            build_c2_child_config, open_c2_child_binding, parse_c2_child_config,
        )

        with c2_startup_fixture(_ARTIFACTS, scratch,
                                pin_variant=pin_variant) as fx:
            document = build_c2_child_config(role="host",
                selected_root=str(fx.selected_store.root),
                protected_root=str(fx.protected_root),
                configuration_path=str(fx.selected_header_path),
                launch_spec=fx.selected_host,
                operator_verification_key_pem=fx.operator_verification_key_pem)
            child_owner = open_c2_child_binding(parse_c2_child_config(document),
                clock=fx.clock, expected_uid=os.geteuid())
            pin = fx.pin
            assignments = []
            for item in pin.record["assignments"]:
                authority = pin.child_launch_metadata(item["assignment_id"])
                assignments.append({"version": 1, "component": authority["component"],
                    "worker_boot_id": authority["worker_boot_id"],
                    "assignment_deadline": authority["assignment_deadline"],
                    "signed_assignment": base64.b64encode(
                        authority["signed_assignment"]).decode("ascii")})
            metadata = {"version": 1, "kind": "group", "role": "host",
                "root": str(pin.root), "uid": pin.uid,
                "record_path": str(pin.record_path), "record": dict(pin.record),
                "global_fd": os.dup(pin.global_fd), "role_fd": os.dup(pin.role_fd),
                "clock_domain": pin.clock_domain, "captured_mono": pin.captured_mono,
                "catalog_deadline": pin.catalog_deadline,
                "signed_catalog": base64.b64encode(pin.signed_catalog).decode("ascii"),
                "public_key": base64.b64encode(fx.verifier.public_key).decode("ascii"),
                "assignments": assignments}
            child_pins = validate_child_pin(metadata, clock=fx.clock, verifier=fx.verifier)
            installer = ArtifactInstaller(fx.pin_root, fx.verifier,
                disk_ceiling_bytes=256 * 1024 * 1024,
                disk_headroom_bytes=16 * 1024 * 1024, uid=os.geteuid(),
                read_only=True, wall_clock=fx.installer.wall_clock)
            try:
                yield fx, child_owner, child_pins, installer
            finally:
                if child_pins._state == "open":
                    child_pins.close()
                child_owner.close()

    @staticmethod
    def owner_policy(*, sessions=1, kv_bytes=32768, queued_calls=0):
        from steamboat_connector.policy import LIMIT_FIELDS, RESERVATION_FIELDS
        limits = {field: 1 for field in LIMIT_FIELDS}
        limits.update(memory_ceiling_bytes=1 << 30,
            memory_headroom_bytes=16 << 20, cpu_quota_millis=1000,
            disk_ceiling_bytes=1 << 30, send_bytes_per_second=1 << 20,
            receive_bytes_per_second=1 << 20, total_network_bytes=1 << 30,
            cleanup_send_bytes_per_second=1 << 20,
            cleanup_receive_bytes_per_second=1 << 20,
            cleanup_total_network_bytes=1 << 30, max_sessions=8,
            max_queued_calls=8, max_request_seconds=300)
        reservation = {field: 0 for field in RESERVATION_FIELDS}
        reservation.update(kv_bytes=kv_bytes, sessions=sessions,
                           queued_calls=queued_calls, max_request_seconds=300)
        return {"version": 1, "pool_id": "c2-host-test", "limits": limits,
            "reservations": {"host": reservation}, "required_telemetry": []}

    @staticmethod
    def allocations(component="worker-1", *, sessions=1, kv_bytes=32768,
                    cache_positions=32, queued_calls=0):
        return {component: {"sessions": sessions, "kv_bytes": kv_bytes,
            "cache_positions": cache_positions, "queued_calls": queued_calls}}

    async def test_real_signed_assigned_stage_forced_steps_and_confirmed_close(self):
        import torch
        from steamboat_runtime.model import LayerCache, PipelineModel
        from steamboat_runtime.protocol.codec import decode_tensor, encode_tensor
        from steamboat_runtime.protocol.worker_pb2 import Request

        with tempfile.TemporaryDirectory(prefix="c2-host-runtime-") as scratch:
            os.chmod(scratch, 0o700)
            with self.resources(scratch) as (fx, child_owner, child_pins, installer):
                runtime = await build_c2_host_runtime(child_owner, child_pins, installer,
                    owner_policy=self.owner_policy(),
                    component_allocations=self.allocations())
                self.assertEqual(runtime.components, ("worker-1",))
                handler = runtime._handlers["worker-1"]
                bridge = runtime._bridges["worker-1"]
                self.assertIs(bridge.authorizer_core, runtime._authorizers["worker-1"])
                self.assertIs(bridge._runtime_guard.__self__, runtime._binding)

                # Add a real, narrowly scoped C1 Describe grant to the signed
                # current snapshot. The fixture signing key and coordinator
                # principal are the same ones bound by the selected RootStore.
                from steamboat_runtime.secure_worker_runtime import WORKER_SERVICE
                from steamboat_security.codec import METADATA_KEY, encode_binding
                from steamboat_security.snapshot import sign_snapshot
                policy = json.loads(runtime._binding._snapshot_store.current().canonical_payload)
                grants = policy["grants"]
                worker_grant = next(grant for grant in grants
                    if grant["role"] == "personal_coordinator"
                    and grant["target_role"] == "host"
                    and grant["assignment_id"] == fx.assignment_id
                    and grant["method"] == f"{WORKER_SERVICE}/Step")
                describe_grant = dict(worker_grant,
                    method=f"{WORKER_SERVICE}/Describe")
                self.assertNotIn(describe_grant, grants)
                grants.append(describe_grant)
                policy["revision"] += 1
                policy["issued_at"] = int(fx.selected_store.wall)
                signed_policy = sign_snapshot(policy,
                    fx.cohort_fixture.fx.new_snapshot_key)
                runtime._binding.install_policy(signed_policy)

                coordinator = next(principal
                    for principal in fx.cohort_fixture.candidate.issuance_candidate.principals
                    if principal.serial == worker_grant["actor_serial"])
                coordinator_spec = next(spec
                    for spec in fx.cohort_fixture.candidate.new_launch_specs
                    if spec.identity == coordinator.identity)
                describe_request = Request(protocol_version=1)
                describe_binding = encode_binding(WORKER_SERVICE, "Describe", {
                    "binding_version": 1,
                    "operation_id": "op_" + "1" * 32,
                    "account_id": coordinator_spec.account_id,
                    "device_id": coordinator_spec.device_id,
                    "role": "personal_coordinator",
                    "credential_epoch": coordinator_spec.credential_epoch,
                    "target_device_id": runtime._authorizers[
                        "worker-1"].local_identity.device_id,
                })
                authorization = bridge.incoming_authorizer.authorize(
                    service=WORKER_SERVICE, method="Describe",
                    payload=describe_request,
                    metadata=((METADATA_KEY, describe_binding),),
                    peer_certificate_pem=coordinator.certificate_pem)
                try:
                    described = await bridge.handler.handle("Describe", describe_request)
                    self.assertTrue(described.ready)
                    authorization.complete(described)
                finally:
                    authorization.close()

                # Compare actual assigned-stage forced steps with the same
                # signed assigned shard run through the in-process reference.
                reference = PipelineModel(_ARTIFACTS)
                reference_stage = reference.stages[0]
                reference_cache = LayerCache(0, 3)
                request = Request(protocol_version=1,
                    manifest_fingerprint=fx.model_fingerprint,
                    worker_boot_id=fx.worker_boot_id, session_id="c2-runtime-session",
                    timeout_ms=10000, max_positions=16, lifetime_ms=30000,
                    idle_lease_ms=30000)
                opened = await handler.handle("OpenSession", request)
                self.assertEqual(opened.code, "OK", opened.message)
                for index, token in enumerate((7, 19, 31)):
                    input_ids = torch.tensor([[token]], dtype=torch.long)
                    hidden = reference.input_output.embed_tokens(input_ids)
                    with torch.inference_mode():
                        expected = reference_stage(hidden, reference_cache, index)
                    step = Request(protocol_version=1,
                        manifest_fingerprint=fx.model_fingerprint,
                        worker_boot_id=fx.worker_boot_id,
                        session_id="c2-runtime-session", lease_token=opened.lease_token,
                        timeout_ms=10000, start_position=index, sequence=index,
                        token_count=1, tensor=encode_tensor(hidden))
                    response = await handler.handle("Step", step)
                    self.assertEqual(response.code, "OK", response.message)
                    actual = decode_tensor(response.tensor, 1)
                    torch.testing.assert_close(actual, expected, atol=1e-6, rtol=0)
                closed = await handler.handle("CloseSession", Request(
                    protocol_version=1, manifest_fingerprint=fx.model_fingerprint,
                    worker_boot_id=fx.worker_boot_id, session_id="c2-runtime-session",
                    lease_token=opened.lease_token, timeout_ms=10000))
                self.assertEqual(closed.code, "OK", closed.message)
                description = await handler.handle("Describe", Request(
                    protocol_version=1, timeout_ms=1000))
                self.assertEqual(description.active_sessions, 0)
                self.assertEqual(description.allocated_cache_bytes, 0)
                events = []
                for bridge in runtime._bridges.values():
                    invalidate = bridge.request_runtime_invalidation
                    stop = bridge.stop
                    def record_invalidation(reason, original=invalidate):
                        events.append("fence")
                        return original(reason)
                    async def record_stop(*, grace_seconds, original=stop):
                        events.append("stop")
                        return await original(grace_seconds=grace_seconds)
                    bridge.request_runtime_invalidation = record_invalidation
                    bridge.stop = record_stop
                self.assertTrue(await runtime.close(5.0))
                self.assertEqual(events[0], "fence")
                self.assertIn("stop", events)
                self.assertLess(events.index("fence"), events.index("stop"))
                self.assertEqual(runtime._handlers, {})
                self.assertEqual(runtime._bridges, {})
                self.assertEqual(child_pins._state, "open")

    async def test_bad_component_allocation_rejected_before_any_weight_load(self):
        with tempfile.TemporaryDirectory(prefix="c2-host-runtime-preload-") as scratch:
            os.chmod(scratch, 0o700)
            with self.resources(scratch) as (_fx, child_owner, child_pins, installer):
                with mock.patch("steamboat_connector.c2_host_runtime.build_assigned_worker_handler",
                                       side_effect=AssertionError("weights loaded before validation")) as build:
                    with self.assertRaises(CredentialError):
                        await build_c2_host_runtime(child_owner, child_pins, installer,
                            owner_policy=self.owner_policy(sessions=1),
                            component_allocations=self.allocations(kv_bytes=65536))
                    build.assert_not_called()

    async def test_queue_and_global_policy_rejected_before_any_weight_load(self):
        with tempfile.TemporaryDirectory(prefix="c2-host-runtime-policy-preload-") as scratch:
            os.chmod(scratch, 0o700)
            with self.resources(scratch) as (_fx, child_owner, child_pins, installer):
                with mock.patch("steamboat_connector.c2_host_runtime.build_assigned_worker_handler",
                                side_effect=AssertionError("weights loaded before validation")) as build:
                    with self.assertRaises(CredentialError):
                        await build_c2_host_runtime(child_owner, child_pins, installer,
                            owner_policy=self.owner_policy(queued_calls=8),
                            component_allocations=self.allocations(queued_calls=9))
                    with self.assertRaises(CredentialError):
                        policy = self.owner_policy(kv_bytes=800_000)
                        policy["limits"]["memory_ceiling_bytes"] = 1_000_000
                        policy["limits"]["memory_headroom_bytes"] = 256_000
                        await build_c2_host_runtime(child_owner, child_pins, installer,
                            owner_policy=policy,
                            component_allocations=self.allocations())
                    build.assert_not_called()

    async def test_signed_pin_catalog_digest_key_assignment_and_group_mismatches_precede_load(self):
        cases = (
            ("catalog_digest", "inherited catalog bytes or key differ"),
            ("catalog_key", "inherited catalog bytes or key differ"),
            ("assignment_digest", "inherited group record differs from the complete selected set"),
            ("extra_component", "host runtime requires exact live child pins"),
        )
        for variant, expected in cases:
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory(prefix="c2-host-runtime-pins-preload-") as scratch:
                    os.chmod(scratch, 0o700)
                    with self.resources(scratch, pin_variant=variant) as (
                            fx, child_owner, child_pins, installer):
                        self.assertEqual(fx.selected_scope["components"][0]["assignment_id"],
                                         fx.assignment_id)
                        with child_owner.borrow() as binding:
                            with mock.patch(
                                "steamboat_connector.c2_host_runtime.build_assigned_worker_handler",
                                side_effect=AssertionError("weights loaded before pin matching")) as build:
                                with self.assertRaisesRegex(CredentialError, expected):
                                    _validate_allocations(binding, child_pins, installer,
                                        validate_policy(self.owner_policy()),
                                        self.allocations())
                                build.assert_not_called()
