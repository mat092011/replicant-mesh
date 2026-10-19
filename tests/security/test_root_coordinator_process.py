"""Opt-in process/TLS/numerical exercise for the fixed root coordinator.

The selected root below is an explicitly test-provisioned trust fixture.  This
test exercises protected process binding and the real coordinator runtime; it
does not claim activation approval, launch-claim consumption, or full cutover.
"""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest


_BOOTSTRAP = b"import runpy; runpy.run_path('/app/lab/root_coordinator.py', run_name='__main__')\n"
_RETAINED_PROCESS_FAILURES = []


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _provision_selected(root: Path, artifacts: dict[str, bytes], policy,
                        generation: str):
    """Create a test-only initial selected root from actual signed materials."""
    from steamboat_security.root_transition_storage import (
        RootGenerationSelector, root_generation_selector_document,
    )
    from steamboat_security.snapshot import canonical_policy_digest
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    generations, policies = root / "generations", root / "policies"
    generations.mkdir(mode=0o700)
    policies.mkdir(mode=0o700)
    lock = root / "transition.lock"
    lock.touch(mode=0o600)
    os.chmod(lock, 0o600)
    policy_sha = _sha(artifacts["policy_snapshot.json"])
    selector = RootGenerationSelector(
        generation, _sha(artifacts["activation_manifest.json"]),
        policy["revision"], canonical_policy_digest(policy), policy_sha,
        {name: _sha(value) for name, value in artifacts.items()})
    policy_path = policies / f"{policy_sha}.json"
    policy_path.write_bytes(artifacts["policy_snapshot.json"])
    os.chmod(policy_path, 0o600)
    generation_path = generations / generation
    generation_path.mkdir(mode=0o700)
    descriptor = {
        "schema_version": 1, "purpose": "root_generation_descriptor",
        "generation_sha256": generation,
        "activation_manifest_sha256": selector.activation_manifest_sha256,
        "artifact_sha256": dict(selector.artifact_sha256),
    }
    from steamboat_security.codec import canonical_json
    descriptor["purpose"] = "root_generation_descriptor"
    for name, data in {"descriptor.json": canonical_json(descriptor), **artifacts}.items():
        target = generation_path / name
        target.write_bytes(data)
        os.chmod(target, 0o600)
    selector_bytes = canonical_json(root_generation_selector_document(selector))
    (root / "selector.json").write_bytes(selector_bytes)
    os.chmod(root / "selector.json", 0o600)


@unittest.skipUnless(os.environ.get("STEAMBOAT_SECURE_PIPELINE_TESTS") == "1",
                     "set STEAMBOAT_SECURE_PIPELINE_TESTS=1 for the offline model process test")
class RootCoordinatorOwnedProcessIntegrationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        if os.name != "posix" or sys.platform != "linux":
            raise RuntimeError("coordinator process integration requires native Linux")
        artifacts = os.environ.get("STEAMBOAT_ARTIFACT_DIR")
        reference = os.environ.get("STEAMBOAT_REFERENCE_DIR")
        if not artifacts or not Path(artifacts).is_dir():
            raise RuntimeError("required process test needs STEAMBOAT_ARTIFACT_DIR")
        if not reference or not Path(reference).is_dir():
            raise RuntimeError("required process test needs STEAMBOAT_REFERENCE_DIR")
        if not Path("/app/lab/root_coordinator.py").is_file():
            raise RuntimeError("required process test needs the fixed /app source mount")
        from steamboat_runtime.manifest import load_manifest
        from steamboat_runtime.prepare import verify_snapshot
        import torch
        cls.artifact_directory = Path(artifacts).resolve(strict=True)
        cls.reference_directory = Path(reference).resolve(strict=True)
        cls.manifest = load_manifest(cls.artifact_directory)
        verify_snapshot(cls.reference_directory)
        cls.fingerprint = cls.manifest["fingerprint"]
        torch.set_num_threads(2)
        try:
            torch.set_num_interop_threads(2)
        except RuntimeError:
            if torch.get_num_interop_threads() > 2:
                raise
        if torch.get_num_threads() > 2 or torch.get_num_interop_threads() > 2:
            raise RuntimeError("process test requires at most two Torch threads")
        cls.torch = torch

    async def test_isolated_coordinator_process_generates_against_three_real_tls_stages(self):
        import steamboat_security
        from steamboat_runtime.protocol.secure_transport import (
            C0ExpectedServerLeafAdapter, ExpectedServerIdentity, FixedPeer,
            LocalTlsIdentity, NodeConnectionBudget,
            create_secure_coordinator_client, create_secure_worker_server,
        )
        from steamboat_runtime.secure_worker_runtime import SecureWorkerRuntimeBridge
        from steamboat_runtime.worker_state import StageExecutor, WorkerHandler
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_runtime.remote_client import SERVICE as COORDINATOR_SERVICE
        from steamboat_security import (
            AuthorizationWatcher, Authorizer, LocalIdentity, OutboundAuthorizer,
            OutboundTarget, SessionBindings, verify_expected_server_leaf,
        )
        from steamboat_security.codec import WORKER_SERVICE, canonical_json
        from steamboat_security.root_transition_launch import (
            RoleLaunchSpec, canonical_role_launch_digest, role_launch_document,
        )
        from steamboat_security.root_transition_policy import ACTIVATION_MANIFEST_DOMAIN
        from steamboat_security.certificates import (
            certificate_sha256, public_key_sha256, _pem_certificate,
        )
        from steamboat_security.root_transition_retirement import RetirementSupervisor
        from steamboat_security.clock import Clock
        from steamboat_security.snapshot import canonical_policy_digest
        from steamboat_security.files import safe_read
        from steamboat_runtime.prepare import verify_snapshot
        from transformers import AutoModelForCausalLM

        from tests.security.test_root_coordinator_runtime import _make_real_coordinator_binding
        from tests.security.test_secure_pipeline import _reference_forced_last_positions

        temp = tempfile.TemporaryDirectory(prefix="root-coordinator-process-")
        base = Path(temp.name)
        config_root = base / "protected"
        config_root.mkdir(mode=0o700)
        os.chmod(config_root, 0o700)
        fixture, _old_config, _unused_binding, header, _unused_spec, manifest = (
            _make_real_coordinator_binding(
                config_root, self.artifact_directory, self.reference_directory))
        root_path = config_root / "selected"
        generation = "c" * 64
        acceptor = config_root / "acceptor"
        acceptor.mkdir(mode=0o700)
        os.chmod(acceptor, 0o700)

        # Start actual StageExecutor/WorkerHandler listeners, then pin their
        # resolved endpoints in the protected coordinator runtime.
        budget = NodeConnectionBudget(max_connections=16, max_pending=4)
        workers = []
        coordinator_client = None
        consumer_watcher = None
        consumer_context = None
        supervisor = RetirementSupervisor()
        child = None
        observed = None
        reference_model = None
        stream = None
        primary_error = None
        try:
            for index in (1, 2, 3):
                principal = fixture.principals[f"worker-{index}"]
                worker_clock = Clock.system(uncertainty_seconds=lambda: 0.0)
                worker_store = steamboat_security.SnapshotStore(
                    verification_key_pem=fixture.snapshot_verification_key_pem,
                    ca_certificate_pem=fixture.cohort_ca_pem, clock=worker_clock)
                worker_store.install(fixture.signed_snapshot)
                bindings = SessionBindings(clock=worker_clock)
                identity = LocalIdentity(
                    principal.certificate_pem, principal.boot_id, self.fingerprint,
                    principal.assignment_id)
                authorizer = Authorizer(
                    local_identity=identity, snapshot_store=worker_store,
                    clock=worker_clock, session_bindings=bindings,
                    worker_request_type=Request)
                executor = StageExecutor(self.artifact_directory, f"worker-{index}")
                handler = WorkerHandler(
                    manifest, f"worker-{index}", executor,
                    boot_id=principal.boot_id, enable_queue=True)
                node = {"principal": principal, "store": worker_store,
                        "clock": worker_clock, "executor": executor,
                        "handler": handler, "bridge": None, "server": None}
                workers.append(node)
                bridge = SecureWorkerRuntimeBridge(
                    authorizer, handler, sweep_interval_seconds=0.5)
                node["bridge"] = bridge
                await bridge.start()
                server = await create_secure_worker_server(
                    bridge.handler, listen_endpoint="127.0.0.1:0",
                    allowed_listen_addresses=("127.0.0.1",),
                    server_identity=LocalTlsIdentity(
                        principal.certificate_pem, principal.private_key_pem),
                    client_ca_pem=fixture.cohort_ca_pem,
                    authorizer=bridge.incoming_authorizer,
                    authorization_watcher=bridge.authorization_watcher,
                    connection_controller=budget,
                    listener_id=f"root-coordinator-process-worker-{index}",
                    listener_slots=1, acceptor_directory=str(acceptor))
                node["server"] = server

            workers_raw = []
            for index, node in enumerate(workers, 1):
                principal = node["principal"]
                cert_path = config_root / f"worker-{index}.pem"
                cert_path.write_bytes(principal.certificate_pem)
                os.chmod(cert_path, 0o600)
                workers_raw.append({
                    "worker_name": f"worker-{index}",
                    "account_id": principal.account_id,
                    "device_id": principal.device_id,
                    "boot_id": principal.boot_id,
                    "assignment_id": principal.assignment_id,
                    "certificate_path": str(cert_path), "ip": "127.0.0.1",
                    "port": node["server"].port,
                })
            runtime = {
                "schema_version": 1, "profile": "native_posix_root_coordinator_v1",
                "artifact_directory": str(self.artifact_directory),
                "reference_directory": str(self.reference_directory),
                "listen_ip": "127.0.0.1", "listen_port": _port(),
                "clock_uncertainty_seconds": 0.001,
                "acceptor_directory": str(acceptor),
                "status_report_path": str(config_root / "coordinator-status.json"),
                "workers": workers_raw,
            }
            runtime_bytes = canonical_json(runtime)
            runtime_path = config_root / "coordinator-runtime.json"
            runtime_path.write_bytes(runtime_bytes)
            os.chmod(runtime_path, 0o600)
            header.update({
                "selected_root": str(root_path), "generation_sha256": generation,
                "runtime_configuration_path": str(runtime_path),
                "runtime_configuration_sha256": _sha(runtime_bytes),
            })
            header["launch_nonce"] = "1" * 32
            header_bytes = canonical_json(header)
            header_path = config_root / "coordinator-role.json"
            header_path.write_bytes(header_bytes)
            os.chmod(header_path, 0o600)
            coordinator = fixture.principals["coordinator"]
            coordinator_spec = RoleLaunchSpec(
                generation, coordinator.account_id, coordinator.device_id,
                "personal_coordinator", coordinator.record["serial"],
                coordinator.record["certificate_sha256"],
                coordinator.record["public_key_sha256"],
                coordinator.record["credential_epoch"], coordinator.boot_id, 1,
                _sha(header_bytes), header["launch_nonce"])
            worker_specs = tuple(RoleLaunchSpec(
                generation, node["principal"].account_id,
                node["principal"].device_id, node["principal"].role,
                node["principal"].record["serial"],
                node["principal"].record["certificate_sha256"],
                node["principal"].record["public_key_sha256"],
                node["principal"].record["credential_epoch"],
                node["principal"].boot_id, 1, "e" * 64,
                f"{index + 2:032x}") for index, node in enumerate(workers, 1))
            new_specs = tuple(sorted((coordinator_spec, *worker_specs), key=lambda x: x.identity))
            old_specs = tuple(sorted((replace_spec(
                spec, generation_sha256="d" * 64, configuration_sha256="f" * 64,
                launch_nonce="f" * 32) for spec in new_specs), key=lambda x: x.identity))
            new_digest = canonical_role_launch_digest(new_specs)
            old_digest = canonical_role_launch_digest(old_specs)
            payload = json.loads(fixture.signed_snapshot)["payload"]
            policy_digest = canonical_policy_digest(payload)
            from cryptography.hazmat.primitives import serialization
            signer = serialization.load_pem_public_key(fixture.snapshot_verification_key_pem)
            new_certificates = [{
                "identity": list(spec.identity), "serial": spec.serial,
                "certificate_sha256": spec.certificate_sha256,
                "public_key_sha256": spec.public_key_sha256,
            } for spec in new_specs]
            activation = {
                "domain": ACTIVATION_MANIFEST_DOMAIN, "version": 1,
                "transition_id": "9" * 32,
                "preparation_intent_sha256": "a" * 64,
                "issuance_manifest_sha256": "b" * 64,
                "old_ca_sha256": "d" * 64,
                "new_ca_sha256": certificate_sha256(
                    _pem_certificate(fixture.cohort_ca_pem)),
                "old_snapshot_key_sha256": "e" * 64,
                "new_snapshot_key_sha256": public_key_sha256(signer),
                "old_launch_digest": old_digest, "new_launch_digest": new_digest,
                "old_launch_specs": [role_launch_document(item) for item in old_specs],
                "new_launch_specs": [role_launch_document(item) for item in new_specs],
                "policy_revision": payload["revision"], "policy_digest": policy_digest,
                "policy_payload_sha256": _sha(canonical_json(payload)),
                "new_certificates": new_certificates,
            }
            artifacts = {
                "activation_manifest.json": canonical_json(activation),
                "policy_snapshot.json": fixture.signed_snapshot,
                "ca_certificate.pem": fixture.cohort_ca_pem,
                "snapshot_signer_public.pem": fixture.snapshot_verification_key_pem,
                "new_launch_specs.json": canonical_json(
                    [role_launch_document(item) for item in new_specs]),
                "old_launch_specs.json": canonical_json(
                    [role_launch_document(item) for item in old_specs]),
            }
            _provision_selected(root_path, artifacts, payload, generation)

            # The selected root and role header above are protected fixture
            # inputs; now launch the unmodified fixed CLI and wait for its real
            # model/preflight/listener READY frame.
            bootstrap_path = config_root / "coordinator-bootstrap.py"
            bootstrap_path.write_bytes(_BOOTSTRAP)
            os.chmod(bootstrap_path, 0o600)
            executable = str(Path(sys.executable).resolve(strict=True))
            argv = [executable, "-I", str(bootstrap_path), "--config", str(header_path)]
            launch_manifest = {
                "schema_version": 1, "containment_profile": "trusted_no_escape_v1",
                "executable_path": executable,
                "executable_sha256": _sha(Path(executable).read_bytes()),
                "script_path": str(bootstrap_path), "script_sha256": _sha(_BOOTSTRAP),
                "configuration_path": str(header_path),
                "configuration_sha256": _sha(header_path.read_bytes()), "argv": argv,
            }
            launch_manifest_path = config_root / "coordinator-launch.json"
            launch_manifest_path.write_bytes(canonical_json(launch_manifest))
            os.chmod(launch_manifest_path, 0o600)
            pending = supervisor.spawn_owned_process(
                launch_manifest_path, protected_root=config_root,
                expected_uid=os.geteuid(), specs=(coordinator_spec,))
            child = pending._record.process
            observed = await asyncio.wait_for(
                supervisor.observe_ready(pending, ready_timeout_seconds=10), timeout=12)
            self.assertTrue(supervisor.validate_observed_launch(observed))
            self.assertIsNone(child.poll())
            ready_status = json.loads(safe_read(
                runtime["status_report_path"], root=config_root,
                expected_uid=os.geteuid(), max_bytes=4096))
            self.assertEqual(ready_status.get("phase"), "ready")
            self.assertIs(ready_status.get("ready"), True)
            self.assertEqual(ready_status.get("worker_count"), 3)

            # Reuse actual consumer mTLS identity/context and compare every
            # captured forced-feedback vector against a same-stack reference.
            consumer = fixture.principals["consumer"]
            consumer_store = fixture.new_store()[0]
            consumer_target = OutboundTarget.from_record(
                service=COORDINATOR_SERVICE, record=coordinator.record,
                boot_id=coordinator.boot_id, model_id=self.fingerprint)
            outbound = OutboundAuthorizer(
                local_identity=LocalIdentity(consumer.certificate_pem,
                    consumer.boot_id, self.fingerprint, consumer.assignment_id),
                snapshot_store=consumer_store, clock=consumer_store.clock,
                target=consumer_target)
            watcher = AuthorizationWatcher(poll_interval_seconds=0.5)
            consumer_watcher = watcher
            peer = FixedPeer(
                endpoint=f"127.0.0.1:{runtime['listen_port']}",
                allowed_addresses=("127.0.0.1",), device_id=coordinator.device_id,
                server_leaf_pem=coordinator.certificate_pem,
                cohort_ca_pem=fixture.cohort_ca_pem,
                expected_server=ExpectedServerIdentity(
                    coordinator.account_id, coordinator.device_id,
                    "personal_coordinator", int(coordinator.record["serial"], 16),
                    coordinator.record["public_key_sha256"],
                    coordinator.record["certificate_sha256"], "127.0.0.1"))
            coordinator_client = await create_secure_coordinator_client(
                peer, local_identity=LocalTlsIdentity(
                    consumer.certificate_pem, consumer.private_key_pem),
                outbound_authorizer=outbound, authorization_watcher=watcher,
                verify_expected_server_leaf=C0ExpectedServerLeafAdapter(
                    verify_expected_server_leaf), connection_controller=budget)

            from transformers import AutoModelForCausalLM
            verify_snapshot(self.reference_directory)
            reference_model = AutoModelForCausalLM.from_pretrained(
                str(self.reference_directory), dtype=self.torch.float32,
                attn_implementation="eager", local_files_only=True,
                use_safetensors=True).to("cpu").eval().requires_grad_(False)
            prompt = [7, 13, 31]
            forced_token, expected_rows = _reference_forced_last_positions(
                reference_model, self.torch, prompt)
            request_context = outbound.create_consumer_request_context(lifetime_seconds=120)
            consumer_context = request_context
            comparisons = []
            events = []
            stream = coordinator_client.generate(
                prompt, 9, forced_tokens=[forced_token] * 8,
                trusted_request_context=request_context, capture_logits=True,
                timeout_seconds=120)
            async for event in stream:
                if event.get("type") == "token":
                    index = len(comparisons)
                    self.assertLess(index, 9)
                    actual = self.torch.tensor(event["logits"], dtype=self.torch.float32)
                    self.assertEqual(tuple(actual.shape), (32_000,))
                    self.assertTrue(bool(self.torch.isfinite(actual).all().item()))
                    self.assertTrue(self.torch.allclose(
                        actual, expected_rows[index], atol=1e-3, rtol=0.0))
                    token = int(expected_rows[index].argmax().item())
                    self.assertEqual(event["token_id"], token)
                    comparisons.append(token)
                event.pop("logits", None)
                events.append(event)
            await stream.aclose()
            self.assertEqual(len(comparisons), 9)
            self.assertEqual([x["type"] for x in events], ["token"] * 9 + ["result"])
            terminal = events[-1]
            self.assertEqual(terminal.get("status"), "completed")
            self.assertIs(terminal.get("cleanup_complete"), True)
            self.assertEqual(terminal.get("token_ids"), comparisons)
            self.assertNotEqual(comparisons[0], forced_token)
            deadline = asyncio.get_running_loop().time() + 10.0
            while any(node["bridge"].status()["owned_sessions"] != 0
                      or node["handler"].supervision_status()["active_compute"]
                      for node in workers):
                if asyncio.get_running_loop().time() >= deadline:
                    self.fail("worker session/cache/compute ownership did not retire")
                await asyncio.sleep(0.02)
            self.assertTrue(all(not node["handler"].sessions for node in workers))
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_errors = []

            async def cleanup(label, callback, *, false_is_failure=False):
                try:
                    result = callback()
                    if inspect.isawaitable(result):
                        result = await result
                    if false_is_failure and result is False:
                        raise RuntimeError(f"{label} did not confirm cleanup")
                except BaseException as error:
                    try:
                        error.add_note(f"coordinator process teardown: {label}")
                    except (AttributeError, TypeError):
                        pass
                    cleanup_errors.append(error)

            if stream is not None:
                await cleanup("consumer stream", stream.aclose)
            if consumer_context is not None:
                await cleanup("consumer request context", consumer_context.close)
            if coordinator_client is not None:
                await cleanup("coordinator client", coordinator_client.close)
            reference_model = None
            import gc
            gc.collect()
            owned_records = tuple(getattr(supervisor, "_owned", ()))
            process_exit_confirmed = not owned_records

            def process_groups_gone():
                try:
                    return all(
                        record.process.poll() is not None
                        and supervisor._group_absent(record.pgid)
                        for record in owned_records)
                except BaseException:
                    # An OS/procfs inspection failure is unknown ownership,
                    # never evidence that the child and its group are gone.
                    return False

            if owned_records:
                try:
                    if any(record.process.poll() is None for record in owned_records):
                        await asyncio.to_thread(
                            supervisor.terminate_owned_generation,
                            generation, timeout_seconds=5)
                    process_exit_confirmed = process_groups_gone()
                    if not process_exit_confirmed:
                        raise RuntimeError("owned coordinator process group remains live")
                    digest = canonical_role_launch_digest((coordinator_spec,))
                    capability = await asyncio.wait_for(
                        supervisor.retire_cohort(
                            "9" * 32, digest, timeout_seconds=10), timeout=12)
                    if not supervisor.validate_retirement_capability(
                            capability, transition_id="9" * 32,
                            expected_old_bindings_digest=digest):
                        raise RuntimeError("coordinator retirement was not confirmed")
                    for record in owned_records:
                        if record.process.returncode != 0:
                            raise RuntimeError("coordinator child exited unsuccessfully")
                    if observed is not None:
                        final_status = json.loads(safe_read(
                            config_root / "coordinator-status.json", root=config_root,
                            expected_uid=os.geteuid(), max_bytes=4096))
                        if (final_status.get("event") != "root_coordinator_status"
                                or final_status.get("phase") != "stopped"
                                or final_status.get("shutdown_confirmed") is not True):
                            raise RuntimeError("coordinator final status was not confirmed")
                except BaseException as error:
                    cleanup_errors.append(error)
                    process_exit_confirmed = process_groups_gone()
                if process_exit_confirmed:
                    for record in owned_records:
                        for pipe in (record.process.stdin, record.process.stdout,
                                     record.process.stderr):
                            if pipe is not None and not pipe.closed:
                                await cleanup("owned process pipe", pipe.close)
                else:
                    # Keep the protected launch files and process owner until
                    # actual process/group retirement is established.
                    _RETAINED_PROCESS_FAILURES.append(
                        (temp, supervisor, owned_records, workers, fixture))
            for node in reversed(workers):
                if node["server"] is not None:
                    await cleanup(f"{node['principal'].role} listener",
                                  lambda node=node: node["server"].stop(0))
                if (node["bridge"] is not None and node["bridge"]._started
                        and not node["bridge"]._closed):
                    await cleanup(f"{node['principal'].role} bridge",
                                  lambda node=node: node["bridge"].stop(grace_seconds=5),
                                  false_is_failure=True)
                if node["handler"] is not None:
                    await cleanup(f"{node['principal'].role} handler",
                                  lambda node=node: node["handler"].shutdown(grace_seconds=5),
                                  false_is_failure=True)
                if node["bridge"] is not None:
                    await cleanup(f"{node['principal'].role} bridge status",
                                  lambda node=node: self.assertIs(
                                      node["bridge"].status()["cleanup_confirmed"], True))
            await cleanup("connection budget", lambda: self.assertEqual(
                (budget.reserved_connections, budget.reserved_pending,
                 budget.reserved_outbound_pending), (0, 0, 0)))
            if process_exit_confirmed:
                await cleanup("fixture", fixture.close)
                await cleanup("temporary protected root", temp.cleanup)
            elif owned_records:
                # Preserve the fixture and protected paths with the live or
                # uncertain process; their release is not inferred from a
                # failed/unknown group inspection.
                if not any(entry[1] is supervisor
                           for entry in _RETAINED_PROCESS_FAILURES):
                    _RETAINED_PROCESS_FAILURES.append(
                        (temp, supervisor, owned_records, workers, fixture))
            else:
                await cleanup("fixture", fixture.close)
                await cleanup("temporary protected root", temp.cleanup)

            if cleanup_errors:
                errors = ([primary_error] if primary_error is not None else []) + cleanup_errors
                raise BaseExceptionGroup(
                    "coordinator process test and teardown failures", errors)


def replace_spec(spec, **changes):
    from dataclasses import replace
    return replace(spec, **changes)


if __name__ == "__main__":
    unittest.main()
