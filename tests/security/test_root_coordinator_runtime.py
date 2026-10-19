"""Component-boundary tests for the fixed root coordinator runtime."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import time
import types
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import tests.security.test_root_transition_issuance as issuance_fixture
import tests.security.test_root_transition_policy as policy_fixture
from tests.security.secure_pipeline_fixture import SecurePipelineIdentityFixture, WORKER_METHODS
from steamboat_security.authorization import LocalIdentity
from steamboat_security.codec import canonical_json
from steamboat_security.errors import BindingError, CredentialError
from steamboat_security.root_runtime import RootRuntimeBinding, TLSMaterials
from steamboat_security.root_transition_launch import RoleLaunchSpec
from steamboat_security.snapshot import sign_snapshot
from lab.root_coordinator_config import parse_config_bytes
import lab.root_coordinator_runtime as runtime_module
from lab.root_coordinator_runtime import (
    _Owners, _active_request_count, _close_owners, _current_local_policy, _invoke_ready_callback,
    _validated_binding, _worker_records, _write_status, serve,
)


def _make_real_coordinator_binding(root, artifact_dir, reference_dir,
                                   *, clock=None):
    """Prepare real three-peer C0 materials for adapter integration tests."""
    import hashlib
    from steamboat_runtime.manifest import load_manifest
    from steamboat_security import Clock, SnapshotStore
    from steamboat_security.codec import canonical_json
    from steamboat_security.root_transition_launch import RoleLaunchSpec
    from tests.security.secure_pipeline_fixture import SecurePipelineIdentityFixture

    manifest = load_manifest(artifact_dir)
    fixture = SecurePipelineIdentityFixture(manifest["fingerprint"])
    root = Path(root).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    coordinator = fixture.principals["coordinator"]
    workers = tuple(fixture.principals[f"worker-{index}"] for index in (1, 2, 3))
    runtime_path = root / "coordinator-runtime.json"
    certificate_path = root / "coordinator-leaf.pem"
    key_path = root / "coordinator-key.pem"
    certificate_path.write_bytes(coordinator.certificate_pem)
    key_path.write_bytes(coordinator.private_key_pem)
    runtime = {
        "schema_version": 1, "profile": "native_posix_root_coordinator_v1",
        "artifact_directory": str(Path(artifact_dir).resolve()),
        "reference_directory": str(Path(reference_dir).resolve()),
        "listen_ip": "127.0.0.1", "listen_port": 43129,
        "clock_uncertainty_seconds": 5.0,
        "acceptor_directory": str(root / "acceptor"),
        "status_report_path": str(root / "status.json"),
        "workers": [{
            "worker_name": f"worker-{index}", "account_id": worker.account_id,
            "device_id": worker.device_id, "boot_id": worker.boot_id,
            "assignment_id": worker.assignment_id,
            "certificate_path": str(root / f"worker-{index}.pem"),
            "ip": "127.0.0.1", "port": 44100 + index,
        } for index, worker in enumerate(workers, 1)],
    }
    for index, worker in enumerate(workers, 1):
        (root / f"worker-{index}.pem").write_bytes(worker.certificate_pem)
    header = {
        "schema_version": 1, "profile": "native_posix_root_role_v1",
        "protected_root": str(root), "selected_root": str(root / "selected"),
        "account_id": coordinator.account_id, "device_id": coordinator.device_id,
        "role": coordinator.role, "boot_id": coordinator.boot_id,
        "credential_epoch": coordinator.record["credential_epoch"],
        "admission_epoch": 1, "generation_sha256": "c" * 64,
        "launch_nonce": "1" * 32, "certificate_path": str(certificate_path),
        "private_key_path": str(key_path), "model_id": manifest["fingerprint"],
        "assignment_id": None, "runtime_configuration_path": str(runtime_path),
        "runtime_configuration_sha256": hashlib.sha256(canonical_json(runtime)).hexdigest(),
    }
    header_bytes = canonical_json(header)
    runtime_bytes = canonical_json(runtime)
    runtime_path.write_bytes(runtime_bytes)
    for path in root.iterdir():
        if path.is_file():
            os.chmod(path, 0o600)
    spec = RoleLaunchSpec(
        header["generation_sha256"], coordinator.account_id, coordinator.device_id,
        coordinator.role, coordinator.record["serial"],
        coordinator.record["certificate_sha256"],
        coordinator.record["public_key_sha256"], coordinator.record["credential_epoch"],
        coordinator.boot_id, header["admission_epoch"],
        hashlib.sha256(header_bytes).hexdigest(), header["launch_nonce"])
    clock = clock or Clock.system(uncertainty_seconds=lambda: 0.0)
    store = SnapshotStore(verification_key_pem=fixture.snapshot_verification_key_pem,
                          ca_certificate_pem=fixture.cohort_ca_pem, clock=clock)
    store.install(fixture.signed_snapshot)
    binding = RootRuntimeBinding(
        LocalIdentity(coordinator.certificate_pem, spec.boot_id,
                      manifest["fingerprint"], None, spec.admission_epoch,
                      spec.generation_sha256), store,
        TLSMaterials(coordinator.certificate_pem, coordinator.private_key_pem),
        runtime_bytes, spec, header_bytes)
    config = parse_config_bytes(runtime_bytes, str(runtime_path), str(root))
    return fixture, config, binding, header, spec, manifest


class RootCoordinatorRuntimeBoundaryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rc-")
        self.root = os.path.abspath(self.temp.name)
        self.config_path = os.path.join(self.root, "coordinator.json")
        raw = {
            "schema_version": 1,
            "profile": "native_posix_root_coordinator_v1",
            "artifact_directory": os.path.join(self.root, "artifacts"),
            "reference_directory": os.path.join(self.root, "reference"),
            "listen_ip": "127.0.0.1", "listen_port": 43121,
            "clock_uncertainty_seconds": 2.5,
            "acceptor_directory": os.path.join(self.root, "sock"),
            "status_report_path": os.path.join(self.root, "status.json"),
            "workers": [
                {
                    "worker_name": f"worker-{index}",
                    "account_id": f"acct_{index:032x}",
                    "device_id": f"dev_{(index + 10):032x}",
                    "boot_id": f"{index:032x}",
                    "assignment_id": f"asg_{(index + 20):032x}",
                    "certificate_path": os.path.join(self.root, f"worker-{index}.pem"),
                    "ip": "127.0.0.1", "port": 44000 + index,
                }
                for index in (1, 2, 3)
            ],
        }
        self.config = parse_config_bytes(
            canonical_json(raw), self.config_path, self.root)

    def tearDown(self):
        self.temp.cleanup()

    async def test_runtime_rejects_untyped_binding_before_loading_optional_runtime(self):
        with self.assertRaises(BindingError):
            await serve(self.config, root_binding=object(),
                        stop_event=asyncio.Event())

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid"),
                         "serve wiring exercise targets the fixed POSIX adapter")
    async def test_serve_wires_same_root_authority_and_confirms_ordered_shutdown(self):
        import steamboat_security
        from steamboat_security.codec import WORKER_SERVICE

        model_data = {"fingerprint": "a" * 64, "model_id": "pinned-model",
                      "revision": "pinned-revision", "config": {"vocab_size": 32000}}
        calls = []
        mode = {"client_count": 0, "fail_client_at": None, "fail_server": False,
                "policy_count": 0, "fail_final_policy": False}
        class Budget:
            reserved_connections = 0
            reserved_pending = 0
            reserved_outbound_pending = 0
            reserved_listener_pending_capacity = 0

        class Watcher:
            def __init__(self, **kwargs):
                calls.append(("watcher", kwargs))

        class Outbound:
            def __init__(self, **kwargs):
                calls.append(("outbound", kwargs))
            def create_bootstrap_context(self, **kwargs):
                calls.append(("bootstrap", kwargs))
                return object()

        class Client:
            async def close(self):
                calls.append(("client-close", None))

        class Bootstrap:
            def __init__(self, client, _context):
                self.client = client
            async def close(self):
                return await self.client.close()

        class Model:
            manifest = model_data
            async def close(self):
                calls.append(("model-close", None))
                return True

        class ModelFactory:
            def from_artifacts(self, *_args):
                calls.append(("model-load", None))
                return Model()

        class Coordinator:
            def __init__(self, manifest, clients, model):
                self.clients, self.model = clients, model
                calls.append(("coordinator", (manifest, clients, model)))
            async def start(self):
                calls.append(("coordinator-start", None))
            async def close(self):
                calls.append(("coordinator-close", None))
                for client in reversed(self.clients):
                    await client.close()
                await self.model.close()
                return True

        class Service:
            def __init__(self, _coordinator):
                self.active_streams, self.cleanups = 0, ()

        class Capture:
            def __init__(self, _config):
                pass
            def status(self):
                return SimpleNamespace(active_captures=0,
                    cleanup_pending_captures=0, reserved_bytes=0)

        class Server:
            async def stop(self, _grace=0):
                calls.append(("server-stop", None))

        class ServerAuthorizer:
            def __init__(self, **kwargs):
                calls.append(("server-authorizer", kwargs))

        class ContextFactory:
            def __init__(self, **kwargs):
                calls.append(("context-factory", kwargs))

        class CaptureConfig:
            def __init__(self, **kwargs):
                calls.append(("capture-config", kwargs))

        class CaptureStub:
            def __init__(self, config):
                self.capture = Capture(config)
            def __getattr__(self, name):
                return getattr(self.capture, name)

        class Target:
            @classmethod
            def from_record(cls, **kwargs):
                calls.append(("target", kwargs))
                return SimpleNamespace(**kwargs)

        class LocalTls:
            def __init__(self, certificate, key):
                self.certificate_chain_pem, self.private_key_pem = certificate, key

        class Expected:
            def __init__(self, *args):
                self.args = args

        class Peer:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        class ConnectionBudget(Budget):
            def __init__(self, **kwargs):
                calls.append(("budget", kwargs))

        class FakeSecureService:
            active_generate_streams = 0

        def module(**values):
            result = types.ModuleType("fake")
            for name, value in values.items():
                setattr(result, name, value)
            return result

        async def create_worker_client(*args, **kwargs):
            calls.append(("create-worker-client", (args, kwargs)))
            mode["client_count"] += 1
            if mode["client_count"] == mode["fail_client_at"]:
                raise RuntimeError("second worker connection creation failed")
            return Client()

        async def create_server(*_args, **kwargs):
            calls.append(("create-server", (_args, kwargs)))
            if mode["fail_server"]:
                raise RuntimeError("coordinator listener startup failed")
            return Server(), FakeSecureService()

        def current_policy(*_args, **_kwargs):
            mode["policy_count"] += 1
            calls.append(("current-policy", None))
            if mode["fail_final_policy"] and mode["policy_count"] == 2:
                raise CredentialError("policy expired after status and certificate reads")
            return object(), object(), record

        def worker_preflight(*_args, **_kwargs):
            calls.append(("worker-preflight", None))
            return selected

        def worker_recheck(*_args, **_kwargs):
            calls.append(("worker-recheck", None))
            return selected

        def read_worker_materials(*_args, **_kwargs):
            calls.append(("worker-materials-read", None))
            return ()

        torch = module(set_num_threads=lambda value: calls.append(("torch-threads", value)),
                       get_num_threads=lambda: 2,
                       set_num_interop_threads=lambda _value: None,
                       get_num_interop_threads=lambda: 2)
        fake_modules = {
            "torch": torch,
            "steamboat_runtime.manifest": module(
                MODEL_ID=model_data["model_id"], MODEL_REVISION=model_data["revision"],
                load_manifest=lambda _path: model_data),
            "steamboat_runtime.prepare": module(verify_snapshot=lambda _path: None),
            "steamboat_runtime.coordinator": module(Coordinator=Coordinator),
            "steamboat_runtime.coordinator_service": module(
                CoordinatorService=Service, supervised_model_class=ModelFactory),
            "steamboat_runtime.capture_budget": module(
                CaptureBudget=CaptureStub, CaptureBudgetConfig=CaptureConfig),
            "steamboat_runtime.protocol.secure_transport": module(
                C0ExpectedServerLeafAdapter=lambda callback: callback,
                ExpectedServerIdentity=Expected, FixedPeer=Peer,
                LocalTlsIdentity=LocalTls, NodeConnectionBudget=ConnectionBudget,
                create_secure_worker_client=create_worker_client,
                create_secure_coordinator_client=lambda *_args, **_kwargs: None),
            "steamboat_runtime.secure_coordinator_service": module(
                create_secure_coordinator_server=create_server),
            "steamboat_runtime.secure_context": module(
                BootstrapWorkerClient=Bootstrap, ConsumerContextFactory=ContextFactory),
            "steamboat_runtime.participant_context": module(
                TrustedRequestContext=type("TrustedRequestContext", (), {})),
            "steamboat_runtime.protocol.worker_pb2": module(
                Request=type("Request", (), {})),
            "steamboat_runtime.remote_client": module(SERVICE="steamboat.v1.Coordinator"),
        }
        identity = SimpleNamespace(model_id=model_data["fingerprint"],
                                   certificate_pem=b"coordinator-leaf",
                                   boot_id="b" * 32, assignment_id=None,
                                   admission_epoch=1, root_generation_sha256="c" * 64)
        sample, view = object(), object()
        clock = SimpleNamespace(sample=lambda: sample)
        store = SimpleNamespace(clock=clock, ca_certificate_pem=b"cohort-ca",
                                current=lambda *, sample: view)
        spec = SimpleNamespace(account_id="acct_" + "1" * 32,
                               device_id="dev_" + "2" * 32, boot_id="b" * 32)
        binding = SimpleNamespace(local_identity=identity, snapshot_store=store,
            tls_materials=SimpleNamespace(certificate_pem=b"coordinator-leaf",
                                          private_key_pem=b"private-key"),
            launch_spec=spec)
        record = SimpleNamespace(serial="abc123", public_key_sha256="d" * 64,
                                  certificate_sha256="e" * 64, ekus=("client", "server"),
                                  dns_sans=(), ip_sans=("127.0.0.1",))
        selected = tuple((worker, record, b"worker-leaf") for worker in self.config.workers)
        release = asyncio.Event()
        release.set()

        with patch.dict("sys.modules", fake_modules), \
             patch.object(steamboat_security, "AuthorizationWatcher", Watcher), \
             patch.object(steamboat_security, "Authorizer", ServerAuthorizer), \
             patch.object(steamboat_security, "OutboundAuthorizer", Outbound), \
             patch.object(steamboat_security, "OutboundTarget", Target), \
             patch("lab.secure_worker_config.validate_readonly_artifacts"), \
             patch.object(runtime_module, "_validated_binding",
                          return_value=({"model_id": model_data["fingerprint"]}, spec)), \
             patch.object(runtime_module, "_current_local_policy",
                          side_effect=current_policy) as current_policy_mock, \
             patch.object(runtime_module, "_check_worker_records",
                          side_effect=worker_preflight), \
             patch.object(runtime_module, "_worker_records_from_materials",
                          side_effect=worker_recheck) as final_worker_check, \
             patch.object(runtime_module, "_check_binding_files"), \
             patch.object(runtime_module, "_read_worker_certificates",
                          side_effect=read_worker_materials), \
             patch.object(runtime_module, "_write_status") as status_write:
            result = await serve(self.config, root_binding=binding,
                                 root_ready_callback=lambda: calls.append(("ready", None)),
                                 stop_event=release)

            self.assertTrue(result["shutdown_confirmed"])
            self.assertEqual(result["worker_count"], 3)
            self.assertEqual(current_policy_mock.call_count, 2)
            self.assertIs(current_policy_mock.call_args.kwargs["sample"],
                          final_worker_check.call_args.kwargs["sample"])
            self.assertIs(current_policy_mock.call_args.kwargs["view"],
                          final_worker_check.call_args.kwargs["view"])
            server_authorizer = next(item[1] for item in calls if item[0] == "server-authorizer")
            self.assertIs(server_authorizer["snapshot_store"], store)
            self.assertIs(server_authorizer["clock"], clock)
            outbound_calls = [item[1] for item in calls if item[0] == "outbound"]
            self.assertEqual(len(outbound_calls), 3)
            self.assertTrue(all(item["local_identity"] is identity for item in outbound_calls))
            self.assertTrue(all(item["snapshot_store"] is store for item in outbound_calls))
            self.assertTrue(all(item["clock"] is clock for item in outbound_calls))
            self.assertTrue(all(item["allow_bootstrap_describe"] is True
                                for item in outbound_calls))
            client_calls = [item[1] for item in calls if item[0] == "create-worker-client"]
            self.assertEqual(len(client_calls), 3)
            server_call = next(item[1] for item in calls if item[0] == "create-server")
            self.assertTrue(all(call_args[1]["local_identity"] is
                                server_call[1]["server_identity"] for call_args in client_calls))
            self.assertTrue(all(call_args[1]["local_identity"].certificate_chain_pem
                                == binding.tls_materials.certificate_pem
                                for call_args in client_calls))
            self.assertTrue(all(call_args[1]["connection_controller"] is not None
                                for call_args in client_calls))
            context = next(item[1] for item in calls if item[0] == "context-factory")
            self.assertEqual(context["coordinator_boot_id"], spec.boot_id)
            ready_index = calls.index(("ready", None))
            server_index = next(index for index, item in enumerate(calls)
                                if item[0] == "create-server")
            preflight_index = next(index for index, item in enumerate(calls)
                                   if item[0] == "worker-preflight")
            final_check_index = next(index for index, item in enumerate(calls)
                                     if item[0] == "worker-recheck")
            self.assertLess(preflight_index, server_index)
            self.assertLess(server_index, final_check_index)
            self.assertLess(final_check_index, ready_index)
            self.assertLess(calls.index(("worker-materials-read", None)),
                            max(index for index, item in enumerate(calls)
                                if item[0] == "current-policy"))
            self.assertLess(ready_index, calls.index(("server-stop", None)))
            self.assertLess(calls.index(("coordinator-close", None)), calls.index(("model-close", None)))
            self.assertIn(("server-stop", None), calls)

            # A failure during the second client construction must close the one
            # already-owned client, without loading a model or signaling READY.
            calls.clear()
            mode.update(client_count=0, fail_client_at=2, fail_server=False)
            with self.assertRaisesRegex(RuntimeError, "second worker connection"):
                await serve(self.config, root_binding=binding,
                            root_ready_callback=lambda: calls.append(("ready", None)),
                            stop_event=release)
            self.assertEqual(sum(item[0] == "client-close" for item in calls), 1)
            self.assertFalse(any(item[0] == "model-load" for item in calls))
            self.assertFalse(any(item[0] == "ready" for item in calls))

            # Listener startup failure happens after coordinator/model ownership;
            # that owner performs reverse client/model cleanup and no READY signal.
            calls.clear()
            mode.update(client_count=0, fail_client_at=None, fail_server=True)
            with self.assertRaisesRegex(RuntimeError, "listener startup failed"):
                await serve(self.config, root_binding=binding,
                            root_ready_callback=lambda: calls.append(("ready", None)),
                            stop_event=release)
            self.assertIn(("coordinator-close", None), calls)
            self.assertIn(("model-close", None), calls)
            self.assertEqual(sum(item[0] == "client-close" for item in calls), 3)
            self.assertFalse(any(item[0] == "ready" for item in calls))

            # A current-policy denial at the final shared-sample gate must not
            # invoke READY, even though model preflight/listener startup passed.
            calls.clear()
            mode.update(client_count=0, fail_client_at=None, fail_server=False,
                        policy_count=0, fail_final_policy=True)
            with self.assertRaisesRegex(CredentialError, "policy expired"):
                await serve(self.config, root_binding=binding,
                            root_ready_callback=lambda: calls.append(("ready", None)),
                            stop_event=release)
            self.assertIn(("worker-materials-read", None), calls)
            self.assertFalse(any(item[0] == "ready" for item in calls))
            self.assertIn(("coordinator-close", None), calls)
            failed_statuses = [call.args[2] for call in status_write.call_args_list
                               if len(call.args) >= 3
                               and call.args[2].get("phase") == "failed"]
            self.assertTrue(failed_statuses)
            self.assertTrue(all(payload["ready"] is False for payload in failed_statuses))

    async def test_ready_hook_requires_exact_synchronous_none(self):
        called = []
        self.assertIsNone(_invoke_ready_callback(lambda: called.append("ready")))
        self.assertEqual(called, ["ready"])
        with self.assertRaises(BindingError):
            _invoke_ready_callback(lambda: False)

        async def wrong_async_hook():
            return None

        with self.assertRaises(BindingError):
            _invoke_ready_callback(wrong_async_hook)

    async def test_owner_cleanup_order_and_false_result_remain_unconfirmed(self):
        order = []

        class Server:
            async def stop(self, grace):
                order.append(("server", grace))

        class Coordinator:
            async def close(self):
                order.append(("coordinator", None))
                return False

        owners = _Owners()
        owners.server = Server()
        owners.coordinator = Coordinator()
        errors = await _close_owners(owners)
        self.assertEqual(order, [("server", 0), ("coordinator", None)])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(owners.server, Server)
        self.assertIsInstance(owners.coordinator, Coordinator)
        runtime_module._RETAINED_UNKNOWN_OWNERS[:] = [
            item for item in runtime_module._RETAINED_UNKNOWN_OWNERS
            if item is not owners]

    async def test_partial_startup_closes_owned_clients_then_model_and_checks_false(self):
        order = []

        class Client:
            def __init__(self, name, result):
                self.name, self.result = name, result

            async def close(self):
                order.append(self.name)
                return self.result

        class Model:
            async def close(self):
                order.append("model")
                return True

        owners = _Owners()
        first, second = Client("client-1", None), Client("client-2", False)
        owners.clients[:] = [first, second]
        owners.model = Model()
        errors = await _close_owners(owners)
        self.assertEqual(order, ["client-2", "client-1", "model"])
        self.assertEqual(len(errors), 1)
        self.assertIn("worker client close returned a non-confirming", str(errors[0]))
        self.assertIs(owners.clients[0], first)
        self.assertIs(owners.clients[1], second)
        self.assertIsNotNone(owners.model)
        runtime_module._RETAINED_UNKNOWN_OWNERS[:] = [
            item for item in runtime_module._RETAINED_UNKNOWN_OWNERS
            if item is not owners]

    async def test_cleanup_timeout_retains_task_and_owner_without_hanging(self):
        gate = asyncio.Event()

        class Server:
            async def stop(self, _grace):
                await gate.wait()

        owners = _Owners()
        owners.server = Server()
        old_bound = runtime_module.MAX_CLEANUP_SECONDS
        runtime_module.MAX_CLEANUP_SECONDS = 0.01
        try:
            errors = await _close_owners(owners)
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], TimeoutError)
            self.assertTrue(any(item is owners
                                for item in runtime_module._RETAINED_UNKNOWN_OWNERS))
            self.assertTrue(runtime_module._RETAINED_CLEANUP_TASKS)
        finally:
            runtime_module.MAX_CLEANUP_SECONDS = old_bound
            gate.set()
            tasks = tuple(runtime_module._RETAINED_CLEANUP_TASKS)
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            runtime_module._RETAINED_UNKNOWN_OWNERS[:] = [
                item for item in runtime_module._RETAINED_UNKNOWN_OWNERS
                if item is not owners]

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                         "requires protected POSIX status files")
    async def test_status_write_is_bounded_private_and_atomically_replaceable(self):
        os.chmod(self.root, 0o700)
        payload = {
            "schema_version": 1, "event": "root_coordinator_status",
            "phase": "ready", "ready": True, "worker_count": 3,
            "active_requests": 0,
        }
        _write_status(self.config, os.geteuid(), payload)
        path = Path(self.config.status_report_path)
        self.assertEqual(json.loads(path.read_bytes()), payload)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        changed = {**payload, "phase": "stopped", "ready": False}
        _write_status(self.config, os.geteuid(), changed)
        self.assertEqual(json.loads(path.read_bytes()), changed)
        with self.assertRaises(BindingError):
            _write_status(self.config, os.geteuid(), {"x": "y" * 5000})


class RootCoordinatorRealPolicyTests(unittest.TestCase):
    """Use real fixture certificates and signed policy, without loading a model."""

    @classmethod
    def setUpClass(cls):
        policy_fixture.RootTransitionPolicyTests.setUpClass()

    def setUp(self):
        self.fx = SecurePipelineIdentityFixture("a" * 64)
        self.temp = tempfile.TemporaryDirectory(prefix="rc-real-")
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.fx.close)

    def test_unobserved_active_request_count_is_not_reported_as_zero(self):
        owners = _Owners()
        self.assertIsNone(_active_request_count(owners))
        owners.service = SimpleNamespace(active_streams=0)
        owners.coordinator = SimpleNamespace(stats=lambda: {"active_requests": 1})
        self.assertEqual(_active_request_count(owners), 1)
        owners.coordinator = SimpleNamespace(stats=lambda: {"active_requests": 0})
        self.assertEqual(_active_request_count(owners), 0)
        owners.coordinator = SimpleNamespace(stats=lambda: {"active_requests": True})
        self.assertIsNone(_active_request_count(owners))
        owners.coordinator = SimpleNamespace(stats=lambda: {})
        self.assertIsNone(_active_request_count(owners))

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid"),
                         "requires protected POSIX binding files")
    def test_protected_coordinator_binding_and_real_policy_grants(self):
        import hashlib
        from dataclasses import replace
        from steamboat_security.certificates import certificate_sha256, _pem_certificate
        from steamboat_security.root_transition_launch import role_launch_document

        coordinator = self.fx.principals["coordinator"]
        workers = tuple(self.fx.principals[f"worker-{index}"] for index in (1, 2, 3))
        coordinator_cert = coordinator.certificate_pem
        runtime_path = self.root / "coordinator.json"
        coordinator_cert_path = self.root / "coordinator.pem"
        coordinator_key_path = self.root / "coordinator-key.pem"
        runtime = {
            "schema_version": 1,
            "profile": "native_posix_root_coordinator_v1",
            "artifact_directory": str(self.root / "artifacts"),
            "reference_directory": str(self.root / "reference"),
            "listen_ip": "127.0.0.1", "listen_port": 43121,
            "clock_uncertainty_seconds": 2.5,
            "acceptor_directory": str(self.root / "sock"),
            "status_report_path": str(self.root / "status.json"),
            "workers": [],
        }
        for index, worker in enumerate(workers, 1):
            runtime["workers"].append({
                "worker_name": f"worker-{index}",
                "account_id": worker.account_id,
                "device_id": worker.device_id,
                "boot_id": worker.boot_id,
                "assignment_id": worker.assignment_id,
                "certificate_path": str(self.root / f"worker-{index}.pem"),
                "ip": "127.0.0.1", "port": 44000 + index,
            })
        runtime_bytes = canonical_json(runtime)
        runtime_path.write_bytes(runtime_bytes)
        coordinator_cert_path.write_bytes(coordinator_cert)
        coordinator_key_path.write_bytes(coordinator.private_key_pem)
        for index, worker in enumerate(workers, 1):
            (self.root / f"worker-{index}.pem").write_bytes(worker.certificate_pem)
        for path in self.root.iterdir():
            if path.is_file():
                os.chmod(path, 0o600)

        generation = "c" * 64
        provisional = RoleLaunchSpec(
            generation, coordinator.account_id, coordinator.device_id,
            coordinator.role, coordinator.record["serial"],
            coordinator.record["certificate_sha256"],
            coordinator.record["public_key_sha256"],
            coordinator.record["credential_epoch"], coordinator.boot_id,
            1, "0" * 64, "1" * 32)

        header = {
            "schema_version": 1, "profile": "native_posix_root_role_v1",
            "protected_root": str(self.root),
            "selected_root": str(self.root / "selected"),
            "account_id": coordinator.account_id,
            "device_id": coordinator.device_id,
            "role": coordinator.role, "boot_id": coordinator.boot_id,
            "credential_epoch": coordinator.record["credential_epoch"],
            "admission_epoch": 1,
            "generation_sha256": generation,
            "launch_nonce": "1" * 32,
            "certificate_path": str(coordinator_cert_path),
            "private_key_path": str(coordinator_key_path),
            "model_id": self.fx.model_id, "assignment_id": None,
            "runtime_configuration_path": str(runtime_path),
            "runtime_configuration_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
        }
        header_bytes = canonical_json(header)
        spec = replace(provisional,
                       configuration_sha256=hashlib.sha256(header_bytes).hexdigest())
        binding = RootRuntimeBinding(
            LocalIdentity(coordinator_cert, spec.boot_id, self.fx.model_id,
                          None, spec.admission_epoch, spec.generation_sha256),
            self.fx.new_store()[0], TLSMaterials(coordinator_cert, coordinator.private_key_pem),
            runtime_bytes, spec, header_bytes)
        config = parse_config_bytes(runtime_bytes, str(runtime_path), str(self.root))
        validated_header, validated_spec = _validated_binding(config, binding)
        self.assertEqual(validated_header, header)
        self.assertEqual(validated_spec, spec)
        sample = binding.snapshot_store.clock.sample()
        view, _, local_record = _current_local_policy(
            binding, header, spec, "127.0.0.1", 30, sample=sample,
            view=binding.snapshot_store.current(sample=sample))
        self.assertEqual(local_record.identity,
                         (coordinator.account_id, coordinator.device_id, coordinator.role))
        selected_workers = _worker_records(config, binding, local_record)
        self.assertEqual(len(selected_workers), 3)
        self.assertEqual({item[1].identity for item in selected_workers},
                         {(worker.account_id, worker.device_id, "host") for worker in workers})
        self.assertEqual({certificate_sha256(_pem_certificate(item[2]))
                          for item in selected_workers},
                         {worker.record["certificate_sha256"] for worker in workers})

        # The signed grant revocation is installed into the same real verifier;
        # actual protected leaf files still parse, but serve admission must fail.
        payload = json.loads(self.fx.signed_snapshot)
        payload["payload"]["grants"] = [g for g in payload["payload"]["grants"]
                                           if not g["method"].endswith("/Step")]
        payload["payload"]["revision"] += 1
        snapshot_signing_key = (self.fx.root / "snapshot-signing-root.key.pem").read_bytes()
        binding.snapshot_store.install(sign_snapshot(payload["payload"],
                                                       snapshot_signing_key))
        with self.assertRaises(CredentialError):
            _worker_records(config, binding, local_record)


class RootCoordinatorServeRealAuthorityTests(unittest.IsolatedAsyncioTestCase):
    """Exercise serve's real C0 binding, files and policy gates with inert I/O factories."""

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid")
                         and os.environ.get("STEAMBOAT_ARTIFACT_DIR")
                         and os.environ.get("STEAMBOAT_REFERENCE_DIR"),
                         "requires Linux protected files and the read-only lab model mounts")
    async def test_real_three_peer_authority_reaches_ready_and_revocation_blocks_it(self):
        import steamboat_security
        from steamboat_security.codec import WORKER_SERVICE

        artifact = os.environ["STEAMBOAT_ARTIFACT_DIR"]
        reference = os.environ["STEAMBOAT_REFERENCE_DIR"]
        temp = tempfile.TemporaryDirectory(prefix="root-coordinator-real-serve-")
        self.addAsyncCleanup(asyncio.sleep, 0)
        self.addCleanup(temp.cleanup)
        fixture, config, binding, _header, _spec, manifest = _make_real_coordinator_binding(
            temp.name, artifact, reference)
        self.addCleanup(fixture.close)
        calls = []

        class Client:
            async def close(self):
                calls.append("client-close")

        class Bootstrap:
            def __init__(self, client, _context):
                self.client = client
            async def close(self):
                return await self.client.close()

        class Model:
            def __init__(self):
                self.manifest = manifest
            async def close(self):
                return True

        class ModelFactory:
            def from_artifacts(self, *_args):
                calls.append("model")
                return Model()

        class Coordinator:
            def __init__(self, _manifest, clients, model):
                self.clients, self.model = clients, model
            async def start(self):
                calls.append("worker-preflight")
            async def close(self):
                for client in reversed(self.clients):
                    await client.close()
                await self.model.close()
                return True

        class Server:
            async def stop(self, _grace=0):
                calls.append("listener-stop")

        class ContextFactory:
            def __init__(self, **_kwargs): pass

        class Authorizer:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        class Outbound:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
            def create_bootstrap_context(self, **kwargs):
                return kwargs

        class Target:
            @classmethod
            def from_record(cls, **kwargs):
                return SimpleNamespace(**kwargs)

        class LocalTls:
            def __init__(self, cert, key):
                self.certificate_chain_pem, self.private_key_pem = cert, key

        class Expected:
            def __init__(self, *_args): pass

        class Peer:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        class Budget:
            reserved_connections = 0
            reserved_pending = 0
            reserved_outbound_pending = 0
            reserved_listener_pending_capacity = 0
            def __init__(self, **_kwargs): pass

        class Watcher:
            def __init__(self, **_kwargs): pass

        class Service:
            def __init__(self, _coordinator):
                self.active_streams = 0
                self.cleanups = ()

        class Capture:
            def __init__(self, _config): pass
            def status(self):
                return SimpleNamespace(active_captures=0,
                    cleanup_pending_captures=0, reserved_bytes=0)

        class CaptureConfig:
            def __init__(self, **_kwargs): pass

        class CaptureBudget:
            def __init__(self, _config): pass
            def __getattr__(self, name):
                return getattr(Capture(self), name)

        def fake_module(**attrs):
            module = types.ModuleType("test_fake")
            for key, value in attrs.items():
                setattr(module, key, value)
            return module

        async def create_client(*_args, **_kwargs):
            calls.append("client-create")
            return Client()

        async def create_server(*_args, **_kwargs):
            calls.append("listener-start")
            return Server(), SimpleNamespace(active_generate_streams=0)

        fake_modules = {
            "steamboat_runtime.coordinator": fake_module(Coordinator=Coordinator),
            "steamboat_runtime.coordinator_service": fake_module(
                CoordinatorService=Service, supervised_model_class=ModelFactory),
            "steamboat_runtime.capture_budget": fake_module(
                CaptureBudget=CaptureBudget, CaptureBudgetConfig=CaptureConfig),
            "steamboat_runtime.protocol.secure_transport": fake_module(
                C0ExpectedServerLeafAdapter=lambda fn: fn,
                ExpectedServerIdentity=Expected, FixedPeer=Peer, LocalTlsIdentity=LocalTls,
                NodeConnectionBudget=Budget, create_secure_worker_client=create_client),
            "steamboat_runtime.secure_coordinator_service": fake_module(
                create_secure_coordinator_server=create_server),
            "steamboat_runtime.secure_context": fake_module(
                BootstrapWorkerClient=Bootstrap, ConsumerContextFactory=ContextFactory),
            "steamboat_runtime.participant_context": fake_module(
                TrustedRequestContext=type("TrustedRequestContext", (), {})),
            "steamboat_runtime.protocol.worker_pb2": fake_module(Request=type("Request", (), {})),
            "steamboat_runtime.remote_client": fake_module(SERVICE="steamboat.v1.Coordinator"),
            "lab.secure_worker_config": fake_module(
                validate_readonly_artifacts=__import__(
                    "lab.secure_worker_config", fromlist=["validate_readonly_artifacts"]
                ).validate_readonly_artifacts),
        }
        release = asyncio.Event()
        release.set()
        ready = []
        original_status = runtime_module._write_status

        with patch.dict("sys.modules", fake_modules), \
             patch.object(steamboat_security, "AuthorizationWatcher", Watcher), \
             patch.object(steamboat_security, "Authorizer", Authorizer), \
             patch.object(steamboat_security, "OutboundAuthorizer", Outbound), \
             patch.object(steamboat_security, "OutboundTarget", Target):
            result = await serve(config, root_binding=binding,
                                 root_ready_callback=lambda: ready.append("ready"),
                                 stop_event=release)
            self.assertEqual(result["worker_count"], 3)
            self.assertEqual(ready, ["ready"])
            self.assertEqual(calls.count("client-create"), 3)
            self.assertIn("worker-preflight", calls)
            self.assertLess(calls.index("worker-preflight"), calls.index("listener-start"))
            self.assertTrue(result["shutdown_confirmed"])

            # Real policy update during the actual final certificate-file sweep:
            # safe_read still reads each protected file before the same real
            # Clock observes the new monotonic/wall sample and rejects expiry.
            original_safe_read = runtime_module.safe_read
            from dataclasses import replace as dataclass_replace
            from steamboat_security import Clock, SnapshotStore
            trigger = {"reads": 0, "shift": 0.0, "ready_status": False,
                       "advanced": False}
            clock = Clock(
                wall=lambda: time.time() + trigger["shift"],
                monotonic=lambda: time.monotonic() + trigger["shift"],
                uncertainty_seconds=lambda: 0.0)
            payload = json.loads(fixture.signed_snapshot)["payload"]
            now = int(time.time())
            payload["issued_at"] = now - 1
            payload["expires_at"] = payload["issued_at"] + 300
            payload["grants"] = [{**grant, "not_before": now - 1, "not_after": now + 20}
                                 for grant in payload["grants"]]
            signer = (fixture.root / "snapshot-signing-root.key.pem").read_bytes()
            negative_store = SnapshotStore(
                verification_key_pem=fixture.snapshot_verification_key_pem,
                ca_certificate_pem=fixture.cohort_ca_pem, clock=clock)
            negative_store.install(sign_snapshot(payload, signer))
            negative_binding = dataclass_replace(binding, snapshot_store=negative_store)

            def advance_after_real_worker_read(path, **kwargs):
                value = original_safe_read(path, **kwargs)
                if (trigger["ready_status"]
                        and path in {worker.certificate_path for worker in config.workers}):
                    trigger["reads"] += 1
                    if trigger["reads"] == 3:
                        # The 29-second coherent wall+monotonic advance is
                        # injected only after listener/preflight success and
                        # after all three final protected certificate reads.
                        trigger["shift"] = 29.0
                        trigger["advanced"] = True
                return value

            def status_then_expire(cfg, uid, payload):
                original_status(cfg, uid, payload)
                calls.append(f"status:{payload['phase']}")
                if payload["phase"] == "ready":
                    trigger["ready_status"] = True

            calls.clear()
            ready.clear()
            with patch.object(runtime_module, "safe_read", side_effect=advance_after_real_worker_read), \
                 patch.object(runtime_module, "_write_status", side_effect=status_then_expire):
                with self.assertRaises(CredentialError):
                    await serve(config, root_binding=negative_binding,
                                root_ready_callback=lambda: ready.append("ready"),
                                stop_event=release)
            self.assertEqual(trigger["reads"], 3)
            self.assertTrue(trigger["advanced"])
            self.assertEqual(ready, [])
            self.assertIn("status:failed", calls)
            self.assertNotIn("ready", calls)


if __name__ == "__main__":
    unittest.main()
