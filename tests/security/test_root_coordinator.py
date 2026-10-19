"""Fixed coordinator CLI framing and signal-lifecycle tests."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lab.root_coordinator import (
    MAX_ROLE_SPEC_INPUT_BYTES, RootCoordinatorError, _parse_arguments,
    _check_status_path, _ready_callback, _signal_stop_handlers,
    parse_coordinator_launch_spec_input,
    root_coordinator_ready_packet,
)
from steamboat_security.codec import canonical_json
from steamboat_security.root_transition_launch import (
    RoleLaunchSpec, role_launch_document,
)
from steamboat_security.root_runtime import load_root_runtime_binding
from steamboat_security.root_transition_storage import RootGenerationStore
from lab import root_coordinator_runtime
import lab.root_coordinator as coordinator_cli


def _coordinator_spec():
    return RoleLaunchSpec(
        "a" * 64, "acct_" + "1" * 32, "dev_" + "2" * 32,
        "personal_coordinator", "abc123", "b" * 64, "c" * 64,
        2, "d" * 32, 3, "e" * 64, "f" * 32)


class RootCoordinatorInputTests(unittest.TestCase):
    def test_one_canonical_coordinator_spec_requires_newline_and_eof(self):
        spec = _coordinator_spec()
        encoded = canonical_json([role_launch_document(spec)]) + b"\n"
        self.assertEqual(parse_coordinator_launch_spec_input(encoded), spec)
        for malformed in (encoded[:-1], encoded + b"\n", b" " + encoded,
                          encoded[:-1] + b" \n"):
            with self.subTest(malformed=malformed[:30]):
                with self.assertRaises(RootCoordinatorError):
                    parse_coordinator_launch_spec_input(malformed)

    def test_closed_types_duplicates_aliases_and_role_are_rejected(self):
        valid = canonical_json([role_launch_document(_coordinator_spec())])
        cases = (
            valid.replace(b'"role":"personal_coordinator"', b'"role":"consumer"'),
            valid.replace(b'"admission_epoch":3', b'"admission_epoch":true'),
            valid.replace(b'"admission_epoch":3', b'"admission_epoch":3.0'),
            valid.replace(b'"role":"personal_coordinator"',
                         b'"role":"personal_coordinator","role":"personal_coordinator"'),
            canonical_json([role_launch_document(_coordinator_spec()),
                            role_launch_document(_coordinator_spec())]),
        )
        for raw in cases:
            with self.subTest(raw=raw[:90]):
                with self.assertRaises(RootCoordinatorError):
                    parse_coordinator_launch_spec_input(raw + b"\n")

    def test_input_bound_and_exact_cli_arguments(self):
        with self.assertRaises(RootCoordinatorError):
            parse_coordinator_launch_spec_input(b"[" + b" " * MAX_ROLE_SPEC_INPUT_BYTES + b"]\n")
        path = str(Path.cwd() / "protected" / "coordinator.json")
        self.assertEqual(_parse_arguments(["--config", path]), path)
        for argv in ([], ["--config"], ["--config", "relative.json"],
                     ["--config", path, "--plugin"],
                     ["--config", path.replace("\\", "/") + "/../x"]):
            with self.subTest(argv=argv):
                with self.assertRaises(RootCoordinatorError):
                    _parse_arguments(argv)

    def test_ready_packet_is_canonical_single_coordinator_record(self):
        spec = _coordinator_spec()
        packet = root_coordinator_ready_packet(spec)
        self.assertLessEqual(len(packet), 16 * 1024)
        self.assertTrue(packet.endswith(b"\n"))
        value = json.loads(packet[:-1])
        self.assertEqual(set(value), {"schema_version", "event", "launch_nonce", "roles"})
        self.assertEqual(value["schema_version"], 1)
        self.assertEqual(value["event"], "root_role_ready")
        self.assertEqual(value["launch_nonce"], spec.launch_nonce)
        self.assertEqual(value["roles"], [role_launch_document(spec)])
        self.assertEqual(packet[:-1], canonical_json(value))

    def test_signal_handler_requests_stop_then_releases_fenced_hold(self):
        class Loop:
            def __init__(self): self.handlers = {}
            def add_signal_handler(self, signum, callback): self.handlers[signum] = callback
            def remove_signal_handler(self, signum): self.handlers.pop(signum, None)

        async def check():
            loop = Loop()
            stop, hold = asyncio.Event(), asyncio.Event()
            installed = _signal_stop_handlers(loop, stop, hold)
            self.assertEqual(set(installed), set(loop.handlers))
            handler = loop.handlers[installed[0]]
            handler()
            self.assertTrue(stop.is_set())
            self.assertFalse(hold.is_set())
            handler()
            self.assertTrue(hold.is_set())
        asyncio.run(check())

    def test_stop_during_startup_prevents_ready_frame(self):
        async def check():
            stop = asyncio.Event()
            state = {"emitted": False}
            callback = _ready_callback(_coordinator_spec(), stop, state)
            with patch("lab.root_coordinator._write_packet") as write_packet:
                # A signal arrives during startup, before the runtime invokes
                # its terminal readiness callback.
                stop.set()
                with self.assertRaisesRegex(RootCoordinatorError, "shutdown was requested"):
                    callback()
                write_packet.assert_not_called()
            self.assertFalse(state["emitted"])
        asyncio.run(check())

    def test_status_path_cannot_alias_outer_protected_header(self):
        with tempfile.TemporaryDirectory() as directory:
            header = Path(directory) / "role-header.json"
            header.write_bytes(b"protected header bytes")
            config = SimpleNamespace(status_report_path=str(header))
            with self.assertRaisesRegex(RootCoordinatorError, "conflicts"):
                _check_status_path(config, header)
            self.assertEqual(header.read_bytes(), b"protected header bytes")

    def test_isolated_profile_rejection_emits_only_fixed_failure_packet(self):
        script = Path(__file__).resolve().parents[2] / "lab" / "root_coordinator.py"
        completed = subprocess.run(
            [sys.executable, "-I", str(script), "--config",
             str(Path.cwd() / "missing-root-coordinator.json")],
            input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout,
            b'{"category":"startup_rejected","event":"root_coordinator_startup_failed",'
            b'"schema_version":1}\n')
        self.assertEqual(completed.stderr, b"")


@unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid"),
                     "composition test requires protected POSIX file reads")
class RootCoordinatorCompositionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from steamboat_security.codec import canonical_json
        self.temp = tempfile.TemporaryDirectory(prefix="root-coordinator-composition-")
        self.root = Path(self.temp.name).resolve()
        os.chmod(self.root, 0o700)
        self.header_path = self.root / "role.json"
        self.runtime_path = self.root / "runtime.json"
        self._write_fixture()
        self.stores = []
        self.loader_calls = []

    def tearDown(self):
        self.temp.cleanup()

    def _write_fixture(self, *, alias_status=False):
        from steamboat_security.codec import canonical_json

        runtime = {
            "schema_version": 1, "profile": "native_posix_root_coordinator_v1",
            "artifact_directory": str(self.root / "artifacts"),
            "reference_directory": str(self.root / "reference"),
            "listen_ip": "127.0.0.1", "listen_port": 43127,
            "clock_uncertainty_seconds": 2.0,
            "acceptor_directory": str(self.root / "acceptor"),
            "status_report_path": str(self.header_path if alias_status
                                       else self.root / "status.json"),
            "workers": [{
                "worker_name": f"worker-{index}",
                "account_id": f"acct_{index:032x}",
                "device_id": f"dev_{index + 10:032x}",
                "boot_id": f"{index:032x}",
                "assignment_id": f"asg_{index + 20:032x}",
                "certificate_path": str(self.root / f"worker-{index}.pem"),
                "ip": "127.0.0.1", "port": 44000 + index,
            } for index in (1, 2, 3)],
        }
        runtime_bytes = canonical_json(runtime)
        self.runtime_path.write_bytes(runtime_bytes)
        os.chmod(self.runtime_path, 0o600)
        header = {
            "schema_version": 1, "profile": "native_posix_root_role_v1",
            "protected_root": str(self.root), "selected_root": str(self.root / "selected"),
            "account_id": "acct_" + "1" * 32, "device_id": "dev_" + "2" * 32,
            "role": "personal_coordinator", "boot_id": "d" * 32,
            "credential_epoch": 2, "admission_epoch": 3,
            "generation_sha256": "a" * 64, "launch_nonce": "f" * 32,
            "certificate_path": str(self.root / "coordinator.pem"),
            "private_key_path": str(self.root / "coordinator-key.pem"),
            "model_id": "b" * 64, "assignment_id": None,
            "runtime_configuration_path": str(self.runtime_path),
            "runtime_configuration_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
        }
        header_bytes = canonical_json(header)
        self.header_path.write_bytes(header_bytes)
        os.chmod(self.header_path, 0o600)
        self.spec = RoleLaunchSpec(
            header["generation_sha256"], header["account_id"], header["device_id"],
            header["role"], "abc123", "c" * 64, "e" * 64,
            header["credential_epoch"], header["boot_id"], header["admission_epoch"],
            hashlib.sha256(header_bytes).hexdigest(), header["launch_nonce"])
        self.spec_bytes = canonical_json([role_launch_document(self.spec)]) + b"\n"
        self.header_bytes, self.runtime_bytes = header_bytes, runtime_bytes

    def _patch_dependencies(self, runtime_serve):
        class Store:
            def __init__(store_self, root, *, expected_uid):
                store_self.root, store_self.expected_uid = root, expected_uid
                store_self.closed = False
                self.stores.append(store_self)
            def close(store_self):
                store_self.closed = True

        def loader(**kwargs):
            self.loader_calls.append(kwargs)
            return SimpleNamespace(
                configuration_header=self.header_bytes,
                runtime_configuration=self.runtime_bytes,
                snapshot_store=SimpleNamespace(clock=kwargs["clock"]))

        async def invoke(config, *, root_binding, root_ready_callback, stop_event):
            return await runtime_serve(config, root_binding, root_ready_callback, stop_event)

        store_module = sys.modules["steamboat_security.root_transition_storage"]
        return (
            patch.object(store_module, "RootGenerationStore", Store),
            patch("steamboat_security.root_runtime.load_root_runtime_binding",
                  side_effect=loader),
            patch("lab.root_coordinator_runtime.serve", side_effect=invoke),
        )

    async def test_composition_keeps_same_store_clock_spec_and_binding_until_close(self):
        seen, emitted = {}, []
        async def runtime_serve(config, binding, callback, _stop_event):
            seen.update(config=config, binding=binding)
            callback()
        patches = self._patch_dependencies(runtime_serve)
        with patch.object(root_coordinator_runtime, "_RETAINED_UNKNOWN_OWNERS", []), \
             patch.object(root_coordinator_runtime, "_RETAINED_CLEANUP_TASKS", set()), \
             patches[0], patches[1], patches[2], \
             patch("lab.root_coordinator._write_packet", side_effect=emitted.append):
            result = await coordinator_cli._serve_bound_coordinator(
                str(self.header_path), self.spec_bytes)
        self.assertEqual(result, 0)
        self.assertEqual(len(self.stores), 1)
        self.assertTrue(self.stores[0].closed)
        self.assertEqual(len(self.loader_calls), 1)
        call = self.loader_calls[0]
        self.assertIs(call["root_store"], self.stores[0])
        self.assertEqual(call["expected_launch_spec"], self.spec)
        self.assertIs(type(call["clock"]), __import__(
            "steamboat_security", fromlist=["Clock"]).Clock)
        self.assertIs(seen["binding"].snapshot_store.clock, call["clock"])
        self.assertEqual(seen["binding"].configuration_header, self.header_bytes)
        self.assertEqual(seen["binding"].runtime_configuration, self.runtime_bytes)
        self.assertEqual(emitted, [root_coordinator_ready_packet(self.spec)])

    async def test_stop_during_startup_suppresses_ready_and_closes_store(self):
        invoked = []
        async def runtime_serve(_config, _binding, callback, stop_event):
            stop_event.set()
            with self.assertRaisesRegex(RootCoordinatorError, "shutdown was requested"):
                callback()
            invoked.append("cleanup")
            raise RootCoordinatorError("shutdown was requested before readiness")
        patches = self._patch_dependencies(runtime_serve)
        packets = []
        with patch.object(root_coordinator_runtime, "_RETAINED_UNKNOWN_OWNERS", []), \
             patch.object(root_coordinator_runtime, "_RETAINED_CLEANUP_TASKS", set()), \
             patches[0], patches[1], patches[2], \
             patch("lab.root_coordinator._write_packet", side_effect=packets.append):
            with self.assertRaisesRegex(RootCoordinatorError, "shutdown was requested"):
                await coordinator_cli._serve_bound_coordinator(
                    str(self.header_path), self.spec_bytes)
        self.assertEqual(invoked, ["cleanup"])
        self.assertEqual(packets, [])
        self.assertTrue(self.stores[0].closed)

    async def test_unknown_runtime_owner_holds_root_store_until_external_release(self):
        async def runtime_serve(*_args, **_kwargs):
            raise RuntimeError("runtime cleanup pending")
        patches = self._patch_dependencies(runtime_serve)
        retained = []
        unknown_owners = [object()]
        cleanup_tasks = set()
        hold_events = []
        def capture_hold(_loop, _stop, hold):
            hold_events.append(hold)
            return ()
        with patch.object(root_coordinator_runtime, "_RETAINED_UNKNOWN_OWNERS", unknown_owners), \
             patch.object(root_coordinator_runtime, "_RETAINED_CLEANUP_TASKS", cleanup_tasks), \
             patch.object(coordinator_cli, "_RETAINED_ROOT_STORES", retained), \
             patch.object(coordinator_cli, "_signal_stop_handlers", side_effect=capture_hold), \
             patches[0], patches[1], patches[2]:
            task = asyncio.create_task(coordinator_cli._serve_bound_coordinator(
                str(self.header_path), self.spec_bytes))
            for _ in range(100):
                if hold_events:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(len(hold_events), 1)
            self.assertFalse(self.stores[0].closed)
            self.assertFalse(task.done())
            hold_events[0].set()
            with self.assertRaisesRegex(RuntimeError, "runtime cleanup pending"):
                await task
        self.assertIn(self.stores[0], retained)
        self.assertFalse(self.stores[0].closed)

    async def test_header_status_collision_rejects_before_store_or_runtime(self):
        self._write_fixture(alias_status=True)
        async def should_not_run(*_args, **_kwargs):
            self.fail("runtime serve must not be called")
        patches = self._patch_dependencies(should_not_run)
        with patch.object(root_coordinator_runtime, "_RETAINED_UNKNOWN_OWNERS", []), \
             patch.object(root_coordinator_runtime, "_RETAINED_CLEANUP_TASKS", set()), \
             patches[0], patches[1], patches[2]:
            with self.assertRaisesRegex(RootCoordinatorError, "conflicts"):
                await coordinator_cli._serve_bound_coordinator(
                    str(self.header_path), self.spec_bytes)
        self.assertEqual(self.stores, [])
        self.assertEqual(self.loader_calls, [])


if __name__ == "__main__":
    unittest.main()
