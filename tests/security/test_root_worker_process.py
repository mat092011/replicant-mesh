"""Opt-in Linux integration for the fixed root worker process profile.

This is a component test only.  A protected one-line bootstrap invokes the
literal read-only ``/app/lab/root_worker.py`` under Python ``-I``; READY is
observed through the real process supervisor after the worker has loaded the
pinned tiny model and opened its native TLS listener.  It does not test cohort
claim consumption, cross-role startup, or root activation.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import time
import unittest
from types import SimpleNamespace
from unittest import mock


_BOOTSTRAP = b"import runpy; runpy.run_path('/app/lab/root_worker.py', run_name='__main__')\n"


class RootWorkerOwnedProcessIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Exercise the fixed worker through protected spawn, READY, and mTLS."""

    @classmethod
    def setUpClass(cls):
        if os.environ.get("STEAMBOAT_SECURE_PIPELINE_TESTS") != "1":
            raise unittest.SkipTest(
                "set STEAMBOAT_SECURE_PIPELINE_TESTS=1 for the offline Linux model process test")
        if os.name != "posix" or sys.platform != "linux":
            raise RuntimeError("required root worker process test needs native Linux")
        artifact_value = os.environ.get("STEAMBOAT_ARTIFACT_DIR")
        if not artifact_value or not Path(artifact_value).is_dir():
            raise RuntimeError("required root worker process test needs STEAMBOAT_ARTIFACT_DIR")
        cls.artifact_directory = Path(artifact_value).resolve(strict=True)
        if not (Path("/app/lab/root_worker.py").is_file()
                and Path("/app/lab/root_worker.py").read_bytes()):
            raise RuntimeError("required root worker process test needs the fixed /app source mount")

        # The transition test fixture normally uses historical public fixture
        # dates and a synthetic model fingerprint.  Build fresh public test
        # credentials at the real system time and pin the actual offline
        # artifact fingerprint; the production child uses Clock.system.
        from steamboat_runtime.manifest import load_manifest
        import tests.security.test_root_transition_issuance as issuance_fixture
        import tests.security.test_root_transition_policy as policy_fixture
        import tests.security.test_root_worker as worker_fixture

        cls.fingerprint = load_manifest(cls.artifact_directory)["fingerprint"]
        cls.fixture_now = int(time.time()) - 1
        cls.issuance_fixture = issuance_fixture
        cls.policy_fixture = policy_fixture
        cls.worker_fixture = worker_fixture
        base_issuance = issuance_fixture.RootTransitionIssuanceTests
        original_snapshot_payload = base_issuance.__dict__["snapshot_payload"].__func__

        def include_open_session(fixture_cls, **kwargs):
            payload = original_snapshot_payload(fixture_cls, **kwargs)
            open_session = dict(payload["grants"][0])
            open_session["method"] = "steamboat.v1.Worker/OpenSession"
            payload["grants"].append(open_session)
            describe = dict(payload["grants"][0])
            describe["method"] = "steamboat.v1.Worker/Describe"
            payload["grants"].append(describe)
            return payload

        fixture_type = type("WorkerProcessIssuanceFixture", (base_issuance,), {})
        fixture_type.snapshot_payload = classmethod(include_open_session)
        fixture_module = SimpleNamespace(
            NOW=cls.fixture_now, MODEL=cls.fingerprint,
            MutableClock=issuance_fixture.MutableClock,
            RootTransitionIssuanceTests=fixture_type)
        cls.fixture_module = fixture_module
        cls.policy_type = type(
            "WorkerProcessPolicyFixture",
            (policy_fixture.RootTransitionPolicyTests,), {})
        cls.runtime_type = type(
            "WorkerProcessRuntimeFixture",
            (worker_fixture.root_runtime_fixture.RootRuntimeProtectedBindingTests,), {})
        cls.worker_type = type(
            "WorkerProcessRootWorkerFixture",
            (worker_fixture.RootWorkerProtectedBindingTests,), {})
        with mock.patch.object(issuance_fixture, "MODEL", cls.fingerprint):
            with mock.patch.object(issuance_fixture, "NOW", cls.fixture_now):
                with mock.patch.object(issuance_fixture.MutableClock.__init__,
                                       "__defaults__", (cls.fixture_now,)):
                    with mock.patch.object(policy_fixture, "issuance_fixture", fixture_module):
                        with mock.patch.object(worker_fixture, "issuance_fixture", fixture_module):
                            with mock.patch.object(policy_fixture,
                                                   "RootTransitionPolicyTests", cls.policy_type):
                                with mock.patch.object(
                                        worker_fixture.root_runtime_fixture,
                                        "RootRuntimeProtectedBindingTests", cls.runtime_type):
                                    with mock.patch.object(
                                            worker_fixture,
                                            "RootWorkerProtectedBindingTests", cls.worker_type):
                                        cls.policy_type.setUpClass()
                                        cls.worker_type.setUpClass()

    def setUp(self):
        self.case = self.worker_type(
            "test_real_protected_crypto_binding_reuses_clock_store_and_config")
        with mock.patch.object(self.issuance_fixture, "MODEL", self.fingerprint):
            with mock.patch.object(self.worker_fixture, "issuance_fixture",
                                   self.fixture_module):
                with mock.patch.object(self.policy_fixture,
                                        "RootTransitionPolicyTests", self.policy_type):
                    with mock.patch.object(
                            self.worker_fixture.root_runtime_fixture,
                            "RootRuntimeProtectedBindingTests", self.runtime_type):
                        with mock.patch.object(
                                self.worker_fixture,
                                "RootWorkerProtectedBindingTests", self.worker_type):
                            self.case.setUp()

        # Rebuild the fixture's private candidate with the exact mounted model
        # path and a currently available loopback port.  No production parser,
        # signature, or runtime path is patched.
        case = self.case.case
        if case.store is not None:
            case.store.close()
            case.store = None
        shutil.rmtree(case.root)
        case.root.mkdir(mode=0o700)
        os.chmod(case.root, 0o700)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]

        values = json.loads(case.runtime)
        configured_ip = values["listen_ip"]
        self.assertEqual(configured_ip, "127.0.0.1",
                         "the real issued leaf/policy fixture must carry loopback SAN")
        acceptor_directory = Path(values["acceptor_directory"])
        self.assertEqual(acceptor_directory, case.base / "acceptor")
        self.assertFalse(acceptor_directory.exists())
        acceptor_directory.mkdir(mode=0o700)
        acceptor_info = acceptor_directory.lstat()
        self.assertTrue(acceptor_directory.is_dir())
        self.assertFalse(acceptor_directory.is_symlink())
        self.assertEqual(acceptor_info.st_uid, os.geteuid())
        self.assertEqual(acceptor_info.st_mode & 0o777, 0o700)
        self.assertEqual(acceptor_directory.resolve(strict=True), acceptor_directory)
        from lab.secure_worker_config import MAX_ACCEPTOR_DIRECTORY_BYTES
        from steamboat_runtime.protocol.secure_acceptor import validate_private_unix_directory
        self.assertLessEqual(len(os.fsencode(acceptor_directory)),
                             MAX_ACCEPTOR_DIRECTORY_BYTES)
        self.assertEqual(validate_private_unix_directory(acceptor_directory),
                         acceptor_directory)
        values["artifact_directory"] = str(self.artifact_directory)
        values["manifest_fingerprint"] = self.fingerprint
        values["listen_port"] = port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((configured_ip, 0))
        case.runtime = self.worker_fixture.canonical_json(values)
        self.runtime = case.runtime
        from lab.secure_worker_config import parse_config_bytes
        self.config = parse_config_bytes(
            case.runtime, config_path=case.config_root / "runtime.json")

        fixture_canonical = self.worker_fixture.root_runtime_fixture.canonical_json

        def preserve_runtime(value):
            if type(value) is dict and value == {"fixed_adapter": "host-v1"}:
                return case.runtime
            return fixture_canonical(value)

        with mock.patch.object(
                self.worker_fixture.root_runtime_fixture,
                "canonical_json", side_effect=preserve_runtime):
            with mock.patch.object(self.policy_fixture, "issuance_fixture",
                                   self.worker_type.fixture_module):
                with mock.patch.object(self.worker_fixture.root_runtime_fixture,
                                       "issuance_fixture",
                                       self.worker_type.fixture_module):
                    case._prepare_candidate_and_root()
        case.store = self._open_root_store(case.root)
        self.spec = case.spec
        grant_methods = {grant["method"] for grant in json.loads(
            case.fx.candidate.policy_payload)["grants"]}
        self.assertIn("steamboat.v1.Worker/OpenSession", grant_methods)
        self.assertIn("steamboat.v1.Worker/Step", grant_methods)
        self.assertEqual(self.spec.configuration_sha256,
                         hashlib.sha256(case.config_path.read_bytes()).hexdigest())
        self.assertEqual(hashlib.sha256(case.runtime_path.read_bytes()).hexdigest(),
                         hashlib.sha256(case.runtime).hexdigest())

        from steamboat_security.root_transition_retirement import RetirementSupervisor
        self.supervisor = RetirementSupervisor()
        self.pending = None

    @staticmethod
    def _open_root_store(root):
        from steamboat_security.root_transition_storage import RootGenerationStore
        return RootGenerationStore(root, expected_uid=os.geteuid())

    def tearDown(self):
        case = getattr(self, "case", None)
        if case is not None:
            root_case = case.case
            if root_case.store is not None:
                root_case.store.close()
                root_case.store = None
            case.tearDown()

    async def test_real_isolated_root_worker_ready_and_authenticated_describe(self):
        from steamboat_security.codec import canonical_json
        from steamboat_security.root_transition_launch import role_launch_document
        from steamboat_security.root_transition_retirement import (
            canonical_role_launch_digest,
        )
        from steamboat_security.files import safe_read

        uid = os.geteuid()
        case = self.case.case
        config_root = case.config_root
        script_path = config_root / "root-worker-bootstrap.py"
        manifest_path = config_root / "root-worker-launch.json"
        script_path.write_bytes(_BOOTSTRAP)
        os.chmod(script_path, 0o600)
        self.assertEqual(script_path.read_bytes(), _BOOTSTRAP)

        executable = str(Path(sys.executable).resolve(strict=True))
        config_path = str(case.config_path.resolve(strict=True))
        script = str(script_path.resolve(strict=True))
        manifest = {
            "schema_version": 1,
            "containment_profile": "trusted_no_escape_v1",
            "executable_path": executable,
            "executable_sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
            "script_path": script,
            "script_sha256": hashlib.sha256(_BOOTSTRAP).hexdigest(),
            "configuration_path": config_path,
            "configuration_sha256": hashlib.sha256(case.config_path.read_bytes()).hexdigest(),
            "argv": [executable, "-I", script, "--config", config_path],
        }
        manifest_path.write_bytes(canonical_json(manifest))
        os.chmod(manifest_path, 0o600)
        client = None
        budget = None
        watcher = None
        context = None
        observed = None
        owned_process = None
        try:
            self.pending = self.supervisor.spawn_owned_process(
                manifest_path, protected_root=config_root, expected_uid=uid,
                specs=(self.spec,))
            owned_process = self.supervisor._owned[0].process
            observed = await asyncio.wait_for(
                self.supervisor.observe_ready(self.pending, ready_timeout_seconds=10),
                timeout=12)
            self.assertTrue(self.supervisor.validate_observed_launch(observed))
            self.assertEqual(self.supervisor._owned[0].process.poll(), None)

            status_bytes = safe_read(case.config_root / "status.json", root=config_root,
                                     expected_uid=uid, max_bytes=4096)
            status = json.loads(status_bytes)
            self.assertIn(status["event"], {"ready", "heartbeat"})
            self.assertEqual(status["phase"], "ready")
            self.assertEqual(status["worker_name"], "worker-1")
            self.assertEqual(status["manifest_fingerprint"], self.fingerprint)
            self.assertEqual(status["layer_range"], [0, 3])
            self.assertEqual(status["handler"]["active_sessions"], 0)
            self.assertIs(status["handler"]["active_compute"], False)

            client, watcher, context, budget = await self._authenticated_describe()
            response = await asyncio.wait_for(
                client.execute("Describe", self._describe_request(),
                               trusted_request_context=context), timeout=10)
            self.assertTrue(response.ready)
            self.assertEqual(response.worker_boot_id, self.spec.boot_id)
            self.assertEqual(response.manifest_fingerprint, self.fingerprint)
            self.assertEqual((response.layer_start, response.layer_end), (0, 3))
            self.assertEqual(response.hidden_size, 64)
        finally:
            try:
                if client is not None:
                    await client.close()
                if budget is not None:
                    self.assertGreaterEqual(budget.max_connections, 3)
                    self.assertEqual(budget.reserved_connections, 0)
                    self.assertEqual(budget.reserved_pending, 0)
                    self.assertEqual(budget.reserved_outbound_pending, 0)
            finally:
                # The watcher has no background task; the supervisor is the
                # sole process owner and verifies leader/group disappearance.
                del watcher
                if self.supervisor._owned:
                    self.supervisor.terminate_owned_generation(
                        self.spec.generation_sha256, timeout_seconds=5)
                    digest = canonical_role_launch_digest((self.spec,))
                    capability = await asyncio.wait_for(
                        self.supervisor.retire_cohort(
                            "9" * 32, digest, timeout_seconds=10), timeout=12)
                    self.assertTrue(self.supervisor.validate_retirement_capability(
                        capability, transition_id="9" * 32,
                        expected_old_bindings_digest=digest))
                    if observed is not None:
                        final = json.loads(safe_read(
                            case.config_root / "status.json", root=config_root,
                            expected_uid=uid, max_bytes=4096))
                        self.assertEqual(final["event"], "final")
                        self.assertEqual(final["phase"], "stopped")
                        self.assertEqual(final["shutdown"]["overall"], "confirmed")
                        self.assertEqual(final["handler"]["active_sessions"], 0)
                        self.assertIs(final["handler"]["active_compute"], False)
                        self.assertEqual(final["handler"]["allocated_cache_bytes"], 0)
                        self.assertEqual(final["handler"]["retained_entries"], 0)
                        self.assertEqual(owned_process.poll(), 0)
                        for stream in (owned_process.stdin, owned_process.stdout,
                                       owned_process.stderr):
                            if stream is not None and not stream.closed:
                                stream.close()

    def _describe_request(self):
        from steamboat_runtime.protocol.worker_pb2 import Request
        return Request(protocol_version=1, manifest_fingerprint=self.fingerprint,
                       timeout_ms=5000)

    async def _authenticated_describe(self):
        """Create the real pinned mTLS worker client using the selected cohort."""
        from steamboat_runtime.protocol.secure_transport import (
            C0ExpectedServerLeafAdapter, ExpectedServerIdentity, FixedPeer,
            LocalTlsIdentity, NodeConnectionBudget, create_secure_worker_client,
        )
        from steamboat_runtime.secure_context import BootstrapWorkerClient
        from steamboat_security import AuthorizationWatcher, LocalIdentity
        from steamboat_security.clock import Clock
        from steamboat_security.codec import WORKER_SERVICE
        from steamboat_security.outbound import OutboundAuthorizer, OutboundTarget
        from steamboat_security.snapshot import SnapshotStore
        from steamboat_security import verify_expected_server_leaf
        from steamboat_runtime.participant_context import TrustedRequestContext

        case = self.case.case
        candidate = case.fx.candidate
        issued = {item.identity: item for item in candidate.issuance_candidate.principals}
        host = issued[self.spec.identity]
        coordinator = next(item for item in candidate.issuance_candidate.principals
                           if item.record.role == "personal_coordinator")
        coordinator_spec = next(item for item in candidate.new_launch_specs
                                if item.identity == coordinator.identity)
        key_by_identity = {entry["principal"].identity: entry["new_key"]
                           for entry in case.fx.roles}
        clock = Clock.system(uncertainty_seconds=lambda: self.config.clock_uncertainty_seconds)
        selected = case.store.read_selected(validate=lambda *_args: None)
        store = SnapshotStore(
            verification_key_pem=selected.artifacts["snapshot_signer_public.pem"],
            ca_certificate_pem=selected.artifacts["ca_certificate.pem"], clock=clock,
            minimum_revision=selected.selector.policy_revision,
            minimum_policy_digest=selected.selector.policy_digest)
        store.install(selected.active_policy_snapshot)
        from steamboat_runtime.protocol.worker_pb2 import Request
        local = LocalIdentity(coordinator.certificate_pem,
                              coordinator_spec.boot_id, self.fingerprint)
        target = OutboundTarget.from_record(
            service=WORKER_SERVICE, record=host.record, boot_id=self.spec.boot_id,
            model_id=self.fingerprint, assignment_id=self.config.assignment_id)
        outbound = OutboundAuthorizer(
            local_identity=local, snapshot_store=store, clock=clock,
            target=target, worker_request_type=Request,
            trusted_request_context_type=TrustedRequestContext,
            allow_bootstrap_describe=True)
        peer = FixedPeer(
            endpoint=self.config.endpoint, allowed_addresses=(self.config.listen_ip,),
            device_id=host.record.device_id, server_leaf_pem=host.certificate_pem,
            cohort_ca_pem=case.fx.new_ca,
            expected_server=ExpectedServerIdentity(
                host.record.account_id, host.record.device_id, "host",
                int(host.record.serial, 16), host.record.public_key_sha256,
                host.record.certificate_sha256, self.config.listen_ip))
        watcher = AuthorizationWatcher(poll_interval_seconds=0.5)
        client = None
        context = None
        budget = NodeConnectionBudget(max_connections=4, max_pending=1)
        try:
            client = await create_secure_worker_client(
                peer, local_identity=LocalTlsIdentity(
                    coordinator.certificate_pem, key_by_identity[coordinator.identity]),
                outbound_authorizer=outbound, authorization_watcher=watcher,
                verify_expected_server_leaf=C0ExpectedServerLeafAdapter(
                    verify_expected_server_leaf),
                connection_controller=budget)
            context = outbound.create_bootstrap_context(
                lifetime_seconds=20, max_describes=1)
            return BootstrapWorkerClient(client, context), watcher, context, budget
        except BaseException:
            if client is not None:
                await client.close()
            raise


if __name__ == "__main__":
    unittest.main()
