"""Controlled execution of the actual owner producer coroutine.

These tests use genuine local C0 contexts and authorization bindings, a real tiny
CPU tensor, and the shared owner parsers. Only the remote worker transport and
operator handoff are simulated; no model weights or inference are involved.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from lab import secure_cohort as cohort


_HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                   for name in ("torch", "grpc", "google.protobuf"))


@unittest.skipUnless(os.name == "posix" and _HAS_RUNTIME,
                     "owner producer flow requires Linux, torch, protobuf and grpc")
class SecureOwnerProducerFlowTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from steamboat_runtime.manifest import MODEL_REVISION
        from tests.security.secure_pipeline_fixture import SecurePipelineIdentityFixture
        from lab.secure_cohort_boot import build_trusted_probe_context
        from lab.secure_cohort_owner import (
            PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE,
            build_owner_action_request, validate_owner_action_request,
        )
        import steamboat_runtime.protocol.secure_transport as transport
        from steamboat_runtime.protocol.worker_pb2 import Response

        self.fingerprint = "a" * 64
        self.authority = SecurePipelineIdentityFixture(
            self.fingerprint,
            ip_sans_by_principal={"worker-3": ("10.1.2.3",)},
            clock_uncertainty_seconds=1.0)
        self.addCleanup(self.authority.close)
        self.build_probe = build_trusted_probe_context
        self.transport = transport
        self.Response = Response
        store, _clock = self.authority.new_store()
        initial = store.current()
        worker = self.authority.principals["worker-3"]
        self.remote_expected = cohort.RemoteExpectation(
            run_id="1" * 32, nonce="2" * 32, worker_name="worker-3",
            account_id=worker.account_id, device_id=worker.device_id,
            boot_id=worker.boot_id, assignment_id=worker.assignment_id,
            model_id=self.authority.model_id, model_revision=MODEL_REVISION,
            manifest_fingerprint=self.fingerprint,
            snapshot_sha256=hashlib.sha256(self.authority.signed_snapshot).hexdigest(),
            endpoint="10.1.2.3:50061", clock_uncertainty_seconds=1.0,
            layer_range=(6, 8))
        self.worker_config = {
            "schema_version": 1, "protected_root": "/run/steamboat",
            "account_id": worker.account_id, "device_id": worker.device_id,
            "boot_id": worker.boot_id, "assignment_id": worker.assignment_id,
            "worker_name": "worker-3", "model_id": self.authority.model_id,
            "model_revision": MODEL_REVISION, "manifest_fingerprint": self.fingerprint,
            "listen_ip": "10.1.2.3", "listen_port": 50061,
            "clock_uncertainty_seconds": 1.0,
            "certificate_path": "/run/steamboat/worker.pem",
            "private_key_path": "/run/steamboat/worker-key.pem",
            "cohort_ca_path": "/run/steamboat/ca.pem",
            "snapshot_verification_key_path": "/run/steamboat/snapshot.pub",
            "signed_snapshot_path": "/run/steamboat/snapshot.json",
            "artifact_directory": "/model", "acceptor_directory": "/run/steamboat/s",
            "status_report_path": "/run/steamboat/status.json",
        }
        self.expectations = {}
        self.PROFILES = (PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE)
        self.build_owner_action_request = build_owner_action_request
        self.validate_owner_action_request = validate_owner_action_request
        self.initial = initial
        self.host_key = "c" * 64
        self.writes = []
        self.action_requests = {}
        self.cutoff = False
        self.commands = []
        self.materials = None
        self.rpc_methods = []

    def tearDown(self):
        for key, expected in list(self.expectations.items()):
            self.assertRegex(expected.run_id, r"[0-9a-f]{32}\Z")

    def _new_expectation(self, profile):
        return cohort._owner_expectation(
            profile, remote_expected=self.remote_expected,
            authority=self.authority, worker_config=self.worker_config)

    def _status(self, owner_expected, *, event="heartbeat", phase="ready",
                active=False, ack=None, deadline_reached=False):
        expected = self.remote_expected
        status = {
            "schema_version": 1, "event": event, "phase": phase,
            "worker_name": "worker-3", "account_id": expected.account_id,
            "device_id": expected.device_id, "boot_id": expected.boot_id,
            "assignment_id": expected.assignment_id, "model_id": expected.model_id,
            "model_revision": expected.model_revision,
            "manifest_fingerprint": expected.manifest_fingerprint,
            "listen_endpoint": expected.endpoint, "layer_range": [6, 8],
            "clock_uncertainty_seconds": 1.0, "torch_threads": 2,
            "handler": {
                "state": "observed", "active_sessions": int(active),
                "active_session_ids": [], "tombstones": 0,
                "retained_entries": int(active),
                "queued_operations": 0, "active_compute": False,
                "cache_bytes_exact": True, "requires_restart": False,
                "stopping": False,
                "limits": {"max_sessions": 8, "max_tombstones": 4096,
                           "max_stage_queue": 8, "max_positions": 1152,
                           "max_cache_positions": 12288,
                           "max_cache_bytes": 16777216,
                           "max_message_bytes": 1048576},
                "committed_cache_bytes": 768 if active else 0,
                "committed_cache_bytes_lower_bound": None,
                "allocated_cache_bytes": 768 if active else 0,
            },
            "bridge": {
                "state": "observed", "ready": phase == "ready",
                "unavailable": False, "requires_restart": False,
                "cleanup_confirmed": True, "active_authorizations": 0,
                "owned_sessions": int(active), "pending_notices": 0,
                "fault_present": False,
            },
            "transport": {
                "listener_slots": 1, "max_connections": 16, "max_pending": 4,
                "reserved_connections": 1, "reserved_pending": 0,
                "reserved_listener_pending_capacity": 1,
                "reserved_outbound_pending": 0, "server_state": "running",
            },
            "external_supervision": {
                "startup_watchdog_seconds": 60, "termination_watchdog_seconds": 15,
                "resource_caps": "configured_by_external_supervisor",
                "verified_by_worker": False,
            },
            "shutdown": {"state": "not_started"},
            "report_state": "confirmed", "resource_state": "observed",
            "owner_lifecycle": {
                "phase": phase,
                "drain_started_monotonic": None if phase == "ready" else 1.0,
                "drain_deadline_monotonic": None if phase == "ready" else 31.0,
                "deadline_reached": deadline_reached,
            },
            "owner_control": {
                "run_id": owner_expected.run_id,
                "last_sequence": 0 if ack is None else ack["sequence"],
                "last_command_sha256": "" if ack is None else ack["command_sha256"],
                "last_action": "" if ack is None else ack["action"],
                "received_monotonic_ns": 0 if ack is None else ack["received_monotonic_ns"],
                "applied_monotonic_ns": 0 if ack is None else ack["completed_monotonic_ns"],
                "applied_snapshot_sha256": "" if ack is None else ack["applied_snapshot_sha256"],
                "applied_revision": 0 if ack is None else ack["applied_revision"],
                "removal_intent_verified": (
                    owner_expected.profile == cohort.PROFILE_C1B_OWNER_REMOVE
                    and ack is not None),
                "revocation_notice_monotonic_ns": (
                    1200 if ack is not None
                    and owner_expected.profile == cohort.PROFILE_C1B_OWNER_REMOVE
                    and ack["sequence"] == 1 else 0),
            },
        }
        if active:
            status["handler"]["active_session_ids"] = [self.active_session]
        return status

    def _receipt(self, kind, digest, size):
        return {
            "schema_version": 1, "event": "owner_file_publication", "kind": kind,
            "sha256": digest, "size": size, "uid": 1000, "gid": 1000,
            "mode": 0o600, "file_fsync_confirmed": True,
            "directory_fsync_confirmed": True, "readback_confirmed": True,
        }

    def _action_response(self, owner_expected, request):
        from lab.secure_cohort_owner import (
            validate_owner_command_ack, build_owner_action_request,
            validate_owner_action_request,
        )
        number = request["command_number"]
        command = validate_owner_action_request(request, owner_expected)
        self.cutoff = True
        received = 1000 if number == 1 else 1600
        completed = 1500 if number == 1 else 2000
        digest = (owner_expected.initial_snapshot_sha256 if command.action == "drain"
                  else command.snapshot_sha256)
        revision = (owner_expected.initial_revision if command.action == "drain"
                    else command.snapshot_revision)
        ack = {
            "schema_version": 1, "event": "owner_control_ack",
            "run_id": command.run_id, "worker_boot_id": command.worker_boot_id,
            "sequence": command.sequence, "command_id": command.command_id,
            "command_sha256": command.command_sha256, "action": command.action,
            "accepted": True, "failure_code": None,
            "received_monotonic_ns": received,
            "completed_monotonic_ns": completed,
            "phase": ("draining" if command.action == "drain"
                      or number == 1 else "removing"),
            "applied_snapshot_sha256": digest, "applied_revision": revision,
        }
        validate_owner_command_ack(ack, command, owner_expected)
        self.commands.append(ack)
        if command.action == "drain":
            publication = {
                "install_intent": None, "removal_intent": None, "policy": None,
                "command": self._receipt(
                    f"command{number}", command.command_sha256,
                    len(__import__("lab.secure_cohort_owner", fromlist=["_canonical_bytes"])
                        ._canonical_bytes(request["command"]))),
            }
        else:
            ready = self.materials["ready"]
            files = self.materials["files"]
            install = self._receipt(
                "install_intent", ready["files"]["install-intent.json"]["sha256"],
                ready["files"]["install-intent.json"]["size"])
            remove = self._receipt(
                "removal_intent", ready["files"]["removal-intent.json"]["sha256"],
                ready["files"]["removal-intent.json"]["size"])
            policy_name = ("install-snapshot.json" if number == 1
                           else "remove-snapshot.json")
            publication = {
                "install_intent": install, "removal_intent": remove,
                "policy": self._receipt(
                    f"policy{number}", command.snapshot_sha256,
                    len(files[policy_name])),
                "command": self._receipt(
                    f"command{number}", command.command_sha256,
                    len(__import__("lab.secure_cohort_owner", fromlist=["_canonical_bytes"])
                        ._canonical_bytes(request["command"]))),
            }
        status = self._status(
            owner_expected,
            event=("status" if command.action != "drain" and number == 2
                   else "heartbeat"),
            phase="draining", active=(command.action == "drain"), ack=ack)
        protected = {
            "measurement_label": "ssh_protected_owner_status_v1",
            "ssh_host_key_sha256": self.host_key,
            "remote_mark_ns": 10000 + number * 100,
            "heartbeat_mtime_ns": 10001 + number * 100,
            "remote_status_uid": 1000, "remote_status_mode": 0o600,
            "remote_status": status,
        }
        response = {
            "schema_version": 1, "event": "owner_action_response",
            "profile": owner_expected.profile, "run_id": owner_expected.run_id,
            "nonce": owner_expected.nonce,
            "worker_boot_id": owner_expected.worker_boot_id,
            "command_number": number, "command_sha256": request["command_sha256"],
            "publication": publication, "worker_ack": ack,
            "protected_status": protected,
        }
        from lab.secure_cohort_owner import validate_owner_action_response
        validate_owner_action_response(
            response, request, owner_expected,
            expected_ssh_host_key_sha256=self.host_key,
            expected_worker_config=self.worker_config)
        return response

    def _observation_response(self, owner_expected, request):
        seq = request["sequence"]
        if seq == 5:
            phase, ack, active, deadline = "ready", None, True, False
        elif seq == 6:
            phase, ack = "draining", self.commands[1 if owner_expected.profile ==
                                                    cohort.PROFILE_C1B_OWNER_DRAIN else 0]
            active = owner_expected.profile == cohort.PROFILE_C1B_OWNER_DRAIN
            deadline = False
        else:
            ack = self.commands[1]
            active = False
            phase, deadline = (("paused", True)
                               if owner_expected.profile == cohort.PROFILE_C1B_OWNER_DRAIN
                               else ("paused", False))
        event = "status" if seq == 7 and owner_expected.profile == cohort.PROFILE_C1B_OWNER_REMOVE else "heartbeat"
        status = self._status(owner_expected, event=event, phase=phase, active=active,
                              ack=ack, deadline_reached=deadline)
        if seq == 7 and owner_expected.profile == cohort.PROFILE_C1B_OWNER_REMOVE:
            # A post-removal status may expose paused ownership with the fixed
            # draining outer phase until the independently supervised stop.
            status["phase"] = "draining"
        mark = 20000 + seq * 100
        heartbeat = mark + 1
        if seq == 7 and owner_expected.profile == cohort.PROFILE_C1B_OWNER_REMOVE:
            frame = self.last_action_response["protected_status"]
            status = frame["remote_status"]
            mark = frame["remote_mark_ns"]
            heartbeat = frame["heartbeat_mtime_ns"]
        return {
            "schema_version": 1, "event": "observation_ack",
            "run_id": request["run_id"], "nonce": request["nonce"],
            "sequence": seq, "case_id": request["case_id"],
            "request_id": request["request_id"], "session_id": request["session_id"],
            "boot_id": request["expected_boot_id"],
            "manifest_fingerprint": owner_expected.manifest_fingerprint,
            "endpoint": owner_expected.endpoint, "ssh_host_key_sha256": self.host_key,
            "remote_status_uid": 1000, "remote_status_mode": 0o600,
            "supervisor_monotonic_ns": 30000 + seq,
            "remote_mark_ns": mark, "heartbeat_mtime_ns": heartbeat,
            "measurement_label": "ssh_protected_owner_status_v1",
            "remote_status": status,
        }

    async def _run_profile(self, profile, *, fail_first_close=False,
                           command_state=None, expected=None, owner_expected=None,
                           commands=None, serials=None, post_close_fault=None,
                           producer=None):
        from lab.secure_cohort_owner import PROFILE_C1B_OWNER_REMOVE

        expected = expected or self.remote_expected
        owner_expected = owner_expected or self._new_expectation(profile)
        self.remote_expected = expected
        self.expectations[profile] = owner_expected
        self.active_session = None
        if commands is not None:
            pass
        elif profile == PROFILE_C1B_OWNER_REMOVE:
            self.materials = cohort._prepare_owner_materials(
                self.authority, owner_expected, command_ids=("3" * 32, "4" * 32))
            commands = self.materials["commands"]
            serials = self.materials["initial_local_serials"]
        else:
            commands = cohort._prepare_owner_drain_commands(
                owner_expected, command_ids=("5" * 32, "6" * 32))
            serials = cohort._owner_initial_local_serials(
                self.authority, self.worker_config, owner_expected)
        self.commands = []
        self.writes = []
        self.rpc_methods = []
        self.cutoff = False
        self.last_action_response = None
        self.action_requests = {}
        created_clients = []
        self.last_probes = []
        self.last_contexts = []
        self.last_clients = created_clients
        old_local_shutdown = {"confirmed": True, "failure_types": []}
        previous_factory = self.transport.create_secure_worker_client
        producer = producer or cohort._run_owner_direct_probe

        async def make_client(*args, **kwargs):
            client = await previous_factory(*args, **kwargs)
            created_clients.append(client)
            real_close = client.close
            close_state = {"calls": 0}
            async def close():
                close_state["calls"] += 1
                if fail_first_close and len(created_clients) == 1 and close_state["calls"] == 1:
                    raise RuntimeError("injected first direct client close failure")
                result = real_close()
                if hasattr(result, "__await__"):
                    return await result
                return result
            client.close = close
            original_authorizer = client.outbound_authorizer

            async def execute(method, request, *, trusted_request_context=None):
                from steamboat_security.codec import WORKER_SERVICE
                self.rpc_methods.append(method)
                auth = original_authorizer.authorize_outbound(
                    service=WORKER_SERVICE, method=method, payload=request,
                    trusted_request_context=trusted_request_context,
                    peer_certificate_pem=client.peer.server_leaf_pem)
                if method in ("OpenSession", "SessionStatus") and self.cutoff:
                    auth.fail(cache_may_exist=False)
                    import grpc
                    raise grpc.aio.AioRpcError(
                        grpc.StatusCode.UNAUTHENTICATED, (), (), "revoked by test operator")
                response = self.Response(
                    protocol_version=1,
                    manifest_fingerprint=owner_expected.manifest_fingerprint,
                    worker_boot_id=owner_expected.worker_boot_id, code="OK")
                if method == "Describe":
                    response.ready = not self.cutoff
                    response.active_sessions = int(self.active_session is not None)
                    response.reserved_positions = 12 if self.active_session is not None else 0
                    response.allocated_cache_bytes = 768 if self.active_session is not None else 0
                    response.active_operations = response.queued_operations = 0
                    response.tombstones = 0
                    response.cache_bytes_exact = True
                    response.requires_restart = False
                elif method == "OpenSession":
                    self.active_session = request.session_id
                    response.session_id = request.session_id
                    response.lease_token = "test-only-lease-never-recorded"
                    response.remaining_lifetime_ms = 120000
                    response.remaining_idle_ms = 120000
                elif method == "Step":
                    response.session_id = request.session_id
                    response.sequence = request.sequence
                    response.start_position = request.start_position
                    response.token_count = request.token_count
                    response.end_position = request.start_position + request.token_count
                    response.next_sequence = request.sequence + 1
                    response.tensor.CopyFrom(request.tensor)
                elif method in ("RenewSession", "SessionStatus"):
                    response.session_id = request.session_id
                auth.complete(response)
                return response

            client.execute = execute
            return client

        def write(_fd, name, value):
            self.writes.append(name)
            if name.startswith("owner-action-request-"):
                self.action_requests[name] = value

        async def wait_control(_fd, name, *, timeout):
            if name.startswith("owner-action-response-"):
                number = int(name.rsplit("-", 1)[1].split(".")[0])
                response = self._action_response(
                    owner_expected, self.action_requests[
                        f"owner-action-request-{number}.json"])
                self.last_action_response = response
                return response
            if name.startswith("observation-response-"):
                seq = int(name.rsplit("-", 1)[1].split(".")[0])
                request = next(value for key, value in reversed(self.observation_requests.items())
                               if key == f"observation-request-{seq}.json")
                return self._observation_response(owner_expected, request)
            raise AssertionError(f"unexpected handoff read {name}")

        original_write = cohort._safe_write_handoff
        self.observation_requests = {}
        def record_write(fd, name, value):
            if name.startswith("observation-request-"):
                self.observation_requests[name] = value
            write(fd, name, value)

        try:
            with (mock.patch.object(self.transport, "create_secure_worker_client",
                                    new=make_client),
                  mock.patch.object(cohort, "_safe_write_handoff", new=record_write),
                  mock.patch.object(cohort, "_wait_for_control", new=wait_control),
                  mock.patch.object(cohort.asyncio, "sleep", new=mock.AsyncMock())):
                original_probe_builder = self.build_probe
                def record_probe(*args, **kwargs):
                    probe = original_probe_builder(*args, **kwargs)
                    self.last_probes.append(probe)
                    self.last_contexts.append(probe.context)
                    return probe
                from lab.secure_cohort_boot import TrustedProbe
                original_probe_close = TrustedProbe.close
                def close_probe(probe):
                    original_probe_close(probe)
                    if post_close_fault == "false":
                        probe.context_factory._context_index[id(probe.context)] = -1
                    elif post_close_fault == "exception":
                        class RaisingContains(dict):
                            def __contains__(self, _key):
                                raise RuntimeError("post-close context predicate fault")
                        probe.context_factory._context_index = RaisingContains()
                with (mock.patch("lab.secure_cohort_boot.build_trusted_probe_context",
                                 side_effect=record_probe),
                      mock.patch.object(TrustedProbe, "close", new=close_probe)):
                    result = await producer(
                        7, authority=self.authority, expected=expected,
                        owner_expected=owner_expected, worker_config=self.worker_config,
                        host_key=self.host_key, commands=commands,
                        initial_local_serials=serials,
                        old_local_shutdown=old_local_shutdown,
                        command_state=(command_state if command_state is not None
                                       else {"last_response": None}))
        finally:
            cohort._safe_write_handoff = original_write
        return result

    async def test_actual_drain_and_remove_owner_producer_bodies(self):
        from lab.secure_cohort_owner import (
            PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE,
        )
        for profile in (PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE):
            with self.subTest(profile=profile):
                result = await self._run_profile(profile)
                self.assertEqual(result["status"], "passed")
                self.assertEqual(len(result["observations"]), 3)
                self.assertEqual([row["sequence"] for row in result["observations"]], [5, 6, 7])
                self.assertEqual([row["worker_ack"]["sequence"]
                                  for row in result["commands"]], [1, 2])
                self.assertTrue(result["probe_cleanup"]["confirmed"])
                self.assertEqual(
                    self.rpc_methods,
                    (["Describe", "OpenSession", "Step", "Step", "RenewSession",
                      "Describe", "OpenSession"]
                     if profile == PROFILE_C1B_OWNER_DRAIN else
                     ["Describe", "OpenSession", "Step", "SessionStatus", "OpenSession"]))
                self.assertEqual(
                    [name for name in self.writes if name.startswith("observation-request-")
                     or name.startswith("owner-action-request-")],
                    (["observation-request-5.json", "owner-action-request-1.json",
                      "owner-action-request-2.json", "observation-request-6.json",
                      "observation-request-7.json"]
                     if profile == PROFILE_C1B_OWNER_DRAIN else
                     ["observation-request-5.json", "owner-action-request-1.json",
                      "observation-request-6.json", "owner-action-request-2.json",
                      "observation-request-7.json"]))

    async def test_actual_owner_probe_retains_complete_graph_after_first_close_failure(self):
        from lab.secure_cohort_owner import PROFILE_C1B_OWNER_DRAIN

        previous = list(cohort._RETAINED_OWNER_OWNERS)
        cohort._RETAINED_OWNER_OWNERS.clear()
        command_state = {"last_response": None}
        try:
            with self.assertRaises(BaseExceptionGroup):
                await self._run_profile(
                    PROFILE_C1B_OWNER_DRAIN, fail_first_close=True,
                    command_state=command_state)
            self.assertIs(command_state.get("direct_cleanup_unconfirmed"), True)
            self.assertEqual(len(cohort._RETAINED_OWNER_OWNERS), 1)
            graph = cohort._RETAINED_OWNER_OWNERS[0]
            self.assertIs(graph[0], self.authority)
            self.assertGreaterEqual(len(graph), 7)
        finally:
            cohort._RETAINED_OWNER_OWNERS[:] = previous

    async def test_actual_owner_probe_retains_graph_when_post_close_check_is_false_or_throws(self):
        from lab.secure_cohort_owner import PROFILE_C1B_OWNER_DRAIN

        previous = list(cohort._RETAINED_OWNER_OWNERS)
        cohort._RETAINED_OWNER_OWNERS.clear()
        try:
            for fault in ("false", "exception"):
                with self.subTest(fault=fault):
                    cohort._RETAINED_OWNER_OWNERS.clear()
                    command_state = {"last_response": None}
                    with self.assertRaises((cohort.CohortError, RuntimeError)):
                        await self._run_profile(
                            PROFILE_C1B_OWNER_DRAIN, command_state=command_state,
                            post_close_fault=fault)
                    self.assertIs(command_state.get("direct_cleanup_unconfirmed"), True)
                    self.assertEqual(len(cohort._RETAINED_OWNER_OWNERS), 1)
                    graph = cohort._RETAINED_OWNER_OWNERS[0]
                    self.assertIs(graph[0], self.authority)
                    self.assertTrue(any(
                        item is self.last_probes[0]
                        for resource in graph
                        for item in (resource if type(resource) in (tuple, list)
                                     else (resource,))))
        finally:
            cohort._RETAINED_OWNER_OWNERS[:] = previous

    async def _run_outer_owner_flow(self, *, fail_first_close=False,
                                   post_close_fault=None):
        from steamboat_runtime.manifest import MODEL_ID, MODEL_REVISION
        from lab.secure_cohort_owner import PROFILE_C1B_OWNER_DRAIN

        with tempfile.TemporaryDirectory(prefix="owner-outer-cleanup-") as temporary:
            root = Path(temporary)
            artifacts, reference, handoff = root / "artifacts", root / "reference", root / "handoff"
            artifacts.mkdir()
            reference.mkdir()
            handoff.mkdir(mode=0o700)
            os.chmod(handoff, 0o700)
            args = cohort.build_parser().parse_args([
                "--artifacts", str(artifacts), "--reference", str(reference),
                "--external-ip", "10.1.2.3", "--external-port", "50061",
                "--clock-uncertainty-seconds", "1.0",
                "--handoff-directory", str(handoff), "--profile", PROFILE_C1B_OWNER_DRAIN,
            ])
            manifest = {"model_id": MODEL_ID, "revision": MODEL_REVISION,
                        "fingerprint": self.fingerprint}
            run_id, nonce = "8" * 32, "9" * 32
            worker = self.authority.principals["worker-3"]
            expected = cohort.RemoteExpectation(
                run_id=run_id, nonce=nonce, worker_name="worker-3",
                account_id=worker.account_id, device_id=worker.device_id,
                boot_id=worker.boot_id, assignment_id=worker.assignment_id,
                model_id=self.authority.model_id, model_revision=MODEL_REVISION,
                manifest_fingerprint=self.fingerprint,
                snapshot_sha256=hashlib.sha256(self.authority.signed_snapshot).hexdigest(),
                endpoint="10.1.2.3:50061", clock_uncertainty_seconds=1.0,
                layer_range=(6, 8))
            owner_expected = cohort._owner_expectation(
                PROFILE_C1B_OWNER_DRAIN, remote_expected=expected,
                authority=self.authority, worker_config=self.worker_config)
            bundle_ready = {
                "schema_version": 1, "event": "bundle_ready",
                "run_id": expected.run_id,
                "nonce": expected.nonce,
                "bundle_path": str(root / "bundle"),
                "expected_boot_id": expected.boot_id,
                "manifest_fingerprint": expected.manifest_fingerprint,
                "snapshot_sha256": expected.snapshot_sha256,
                "endpoint": expected.endpoint, "worker_name": "worker-3",
            }

            async def pipeline(_args, *, result, **_kwargs):
                result["baseline"].update(
                    status="passed", completed_requests=4, captured_vectors=27)

            def provision(*, worker_config_out, run_id, nonce, **_kwargs):
                worker_config_out["worker_config"] = self.worker_config
                self.assertEqual((run_id, nonce), (expected.run_id, expected.nonce))
                return str(root / "bundle"), expected, bundle_ready

            async def direct_probe(directory_fd, *, expected, owner_expected,
                                   worker_config, host_key, commands,
                                   initial_local_serials, command_state, **_kwargs):
                direct_command_state["state"] = command_state
                return await self._run_profile(
                    PROFILE_C1B_OWNER_DRAIN, fail_first_close=fail_first_close,
                    command_state=command_state, expected=expected,
                    owner_expected=owner_expected, commands=commands,
                    serials=initial_local_serials, post_close_fault=post_close_fault,
                    producer=original_direct)

            async def wait_outer_control(_fd, name, *, timeout):
                if name == cohort.HANDOFF_READY_ACK_FILE:
                    status = self._status(owner_expected)
                    return {
                        "schema_version": 1, "event": "ready_ack",
                        "run_id": expected.run_id, "nonce": expected.nonce,
                        "boot_id": expected.boot_id,
                        "manifest_fingerprint": expected.manifest_fingerprint,
                        "snapshot_sha256": expected.snapshot_sha256,
                        "endpoint": expected.endpoint,
                        "ssh_host_key_sha256": self.host_key,
                        "remote_status_uid": 1000, "remote_status_mode": 0o600,
                        "remote_status_mtime_ns": 10001,
                        "measurement_label": cohort.READY_LABEL,
                        "remote_status": status,
                    }
                if name == cohort.HANDOFF_STOP_ACK_FILE:
                    command = direct_command_state["state"]["last_response"]["worker_ack"]
                    status = self._status(
                        owner_expected, event="final", phase="paused", ack=command)
                    status.update({
                        "phase": "stopped",
                        "shutdown": {"server": "confirmed", "bridge": "confirmed",
                                     "handler": "confirmed", "overall": "confirmed"},
                    })
                    status["handler"].update(
                        active_sessions=0, active_session_ids=[], queued_operations=0,
                        active_compute=False, committed_cache_bytes=0,
                        allocated_cache_bytes=0, retained_entries=0)
                    status["bridge"].update(
                        ready=False, active_authorizations=0, owned_sessions=0,
                        pending_notices=0)
                    status["transport"].update(
                        listener_slots=1, reserved_connections=0, reserved_pending=0,
                        reserved_listener_pending_capacity=0,
                        reserved_outbound_pending=0, server_state="stopped")
                    return {
                        "schema_version": 1, "event": "stop_ack",
                        "run_id": expected.run_id, "nonce": expected.nonce,
                        "boot_id": expected.boot_id, "process_state": "exited",
                        "exit_code": 0, "shutdown_confirmed": True,
                        "ssh_host_key_sha256": self.host_key,
                        "remote_status_uid": 1000, "remote_status_mode": 0o600,
                        "measurement_label": cohort.STOP_LABEL,
                        "remote_status": status,
                    }
                raise AssertionError(f"unexpected outer control read {name}")

            direct_command_state = {"last_response": None}
            original_direct = cohort._run_owner_direct_probe
            async def direct_with_actual_body(directory_fd, **kwargs):
                return await direct_probe(directory_fd, **kwargs)

            secrets_module = cohort.secrets
            fixed_random_values = {1: run_id, 2: nonce,
                                   4: "a" * 32, 5: "b" * 32}
            class CohortSecretsProxy:
                def __init__(self):
                    self.calls = 0

                def token_hex(self, nbytes=None):
                    self.calls += 1
                    if self.calls in fixed_random_values:
                        if nbytes != 16:
                            raise AssertionError("expected fixed 128-bit run/command ID")
                        return fixed_random_values[self.calls]
                    return secrets_module.token_hex(nbytes)

                def __getattr__(self, name):
                    return getattr(secrets_module, name)

            cohort_secrets_proxy = CohortSecretsProxy()
            retain_impl = cohort._retain_owner_graph

            with (mock.patch("steamboat_runtime.manifest.load_manifest",
                             return_value=manifest),
                  mock.patch("steamboat_runtime.prepare.verify_snapshot"),
                  mock.patch.object(cohort, "_load_identity_fixture",
                                    return_value=type(self.authority)),
                  mock.patch.object(cohort, "_create_authority_fixture",
                                    return_value=self.authority),
                  mock.patch.object(cohort, "provision_worker3_bundle",
                                    side_effect=provision),
                  mock.patch.object(cohort, "_run_real_pipeline", new=pipeline),
                  mock.patch.object(cohort, "_close_local_pipeline",
                                    new=mock.AsyncMock(return_value=[])),
                  mock.patch.object(cohort, "_run_owner_direct_probe",
                                    new=direct_with_actual_body),
                  mock.patch.object(cohort, "_wait_for_control", new=wait_outer_control),
                  mock.patch.object(cohort, "secrets", cohort_secrets_proxy),
                  mock.patch.object(cohort, "_retain_owner_graph",
                                    wraps=retain_impl) as retain_spy,
                  mock.patch.object(self.authority, "close", wraps=self.authority.close) as close):
                if fail_first_close or post_close_fault is not None:
                    previous = list(cohort._RETAINED_OWNER_OWNERS)
                    cohort._RETAINED_OWNER_OWNERS.clear()
                    try:
                        if fail_first_close:
                            with self.assertRaises(BaseExceptionGroup):
                                await cohort.run_cohort(args)
                        elif post_close_fault == "false":
                            with self.assertRaisesRegex(
                                    cohort.CohortError,
                                    "owner Generate authorization/context was not truly released"):
                                await cohort.run_cohort(args)
                        else:
                            with self.assertRaisesRegex(
                                    RuntimeError, "post-close context predicate fault"):
                                await cohort.run_cohort(args)
                        def contains_identity(value, target):
                            if value is target:
                                return True
                            if type(value) in (tuple, list):
                                return any(contains_identity(item, target)
                                           for item in value)
                            if type(value) is dict:
                                return any(contains_identity(item, target)
                                           for item in value.values())
                            if type(value).__name__ == "TrustedProbe":
                                return contains_identity(value.context, target)
                            return False
                        outer_call = next(
                            call.args for call in retain_spy.call_args_list
                            if type(call.args[5]) is dict
                            and type(call.args[6]) is dict
                            and type(call.args[7]) is dict)
                        outer_owner, pipeline_state, result, remote_shutdown = outer_call[4:8]
                        local_shutdown = result["local_shutdown"]
                        self.assertEqual(len(cohort._RETAINED_OWNER_OWNERS), 1)
                        retained_graph = cohort._RETAINED_OWNER_OWNERS[0]
                        retained_identities = (
                            self.authority, outer_owner, pipeline_state, result,
                            local_shutdown, remote_shutdown,
                            *self.last_clients, *self.last_probes, *self.last_contexts)
                        self.assertTrue(self.last_clients)
                        self.assertTrue(self.last_probes)
                        self.assertEqual(len(self.last_contexts), len(self.last_probes))
                        for retained in retained_identities:
                            self.assertTrue(contains_identity(retained_graph, retained),
                                            f"retained graph dropped {type(retained).__name__}")
                        self.assertFalse(cohort._owner_authority_retention_required(
                            active=True, cleanup_errors=[], direct_cleanup_unconfirmed=False,
                            may_have_started=True,
                            remote_shutdown={"confirmed": True, "process_state": "exited",
                                             "exit_code": 0}))
                        close.assert_not_called()
                    finally:
                        cohort._RETAINED_OWNER_OWNERS[:] = previous
                else:
                    result = await cohort.run_cohort(args)
                    self.assertEqual(result["remote_shutdown"]["process_state"], "exited")
                    self.assertTrue(result["local_shutdown"]["confirmed"])
                    close.assert_called_once()

    async def test_run_cohort_retains_authority_when_direct_close_is_unknown(self):
        await self._run_outer_owner_flow(fail_first_close=True)

    async def test_run_cohort_retains_authority_when_post_close_check_is_false_or_throws(self):
        for fault in ("false", "exception"):
            with self.subTest(fault=fault):
                await self._run_outer_owner_flow(post_close_fault=fault)

    async def test_run_cohort_disposes_authority_after_confirmed_outer_cleanup(self):
        await self._run_outer_owner_flow(fail_first_close=False)
