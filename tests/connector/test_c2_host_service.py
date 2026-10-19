"""Closed-boundary tests for the fixed supervised C2 host service."""
from __future__ import annotations

import subprocess
import sys
import os
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
            service._runner.close()

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
                service._runtime = runtime
                try:
                    await service._probe_assigned_stages()
                    handler = runtime._handlers["worker-1"]
                    self.assertEqual(handler.sessions, {})
                    self.assertEqual(handler._active_operation, None)
                finally:
                    self.assertTrue(await runtime.close(grace_seconds=5.0))


if __name__ == "__main__":
    unittest.main()
