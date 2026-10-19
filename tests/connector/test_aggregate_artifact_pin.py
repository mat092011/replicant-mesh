"""Shared-store host assignment pin tests; model-backed case is a parent gate."""
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace

from steamboat_connector.aggregate_artifact_pin import (
    AggregateArtifactPinError, _validate_group_record, _AssignmentSlice)


def _record():
    return {"version": 2, "pin_id": "a" * 64,
            "account_id": "acct_" + "1" * 32,
            "device_id": "dev_" + "2" * 32, "role": "host",
            "model_id": "tiny-llama", "catalog_sha256": "b" * 64,
            "runtime_boot_id": "c" * 32,
            "assignments": [
                {"component": f"worker-{index}",
                 "assignment_id": f"asg_{index:032x}",
                 "assignment_sha256": str(index) * 64,
                 "worker_boot_id": f"{index:032x}"}
                for index in range(1, 4)]}


class AggregateArtifactPinRecordTests(unittest.TestCase):
    def test_module_import_is_torch_free(self):
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(
            ("src", environment.get("PYTHONPATH", "")))
        result = subprocess.run(
            [sys.executable, "-B", "-c",
             "import sys; import steamboat_connector.aggregate_artifact_pin; "
             "assert not any(n == 'torch' or n.startswith('torch.') for n in sys.modules)"],
            capture_output=True, text=True, timeout=10, check=False, env=environment)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_accepts_closed_sorted_three_component_record(self):
        value = _record()
        self.assertIs(_validate_group_record(value), value)

    def test_rejects_unknown_fields_duplicate_or_unsorted_entries(self):
        for mutate in (
                lambda value: value.update(extra=True),
                lambda value: value["assignments"].reverse(),
                lambda value: value["assignments"].__setitem__(1, value["assignments"][0])):
            value = _record()
            mutate(value)
            with self.subTest(value=value), self.assertRaises(AggregateArtifactPinError):
                _validate_group_record(value)

    def test_assignment_guard_slice_cannot_release_group_owner(self):
        class Owner:
            record = _record()
            _authorities = {"asg_" + f"{1:032x}": object()}

            def assert_open_descriptors(self):
                return True

        authority = SimpleNamespace(assignment_id="asg_" + f"{1:032x}",
                                    assignment_sha256="d" * 64,
                                    worker_boot_id="1" * 32)
        pin = _AssignmentSlice(Owner(), authority)
        self.assertTrue(pin.assert_open_descriptors())
        with self.assertRaises(AggregateArtifactPinError):
            pin.close()


@unittest.skipUnless(os.name == "posix" and __import__("sys").platform.startswith("linux")
                     and os.environ.get("STEAMBOAT_ASSIGNED_TEST_SOURCE")
                     and os.environ.get("STEAMBOAT_ASSIGNED_TEST_SCRATCH"),
                     "parent Linux model gate supplies readonly artifacts and bounded scratch")
class AggregateHostWorkerNumericalFixture(unittest.TestCase):
    def test_three_workers_share_one_installer_pin_and_interleave_sessions(self):
        import torch
        from steamboat_connector.aggregate_artifact_pin import RuntimeArtifactGroupPin
        from steamboat_connector.artifacts import ArtifactInstaller, ArtifactInstallBusy
        from steamboat_connector.catalog import (ARTIFACT_FILENAMES, RUNTIME_LOCK_SHA256,
                                                  CatalogVerifier)
        from steamboat_runtime.assigned_executor import build_assigned_worker_handler
        from steamboat_runtime.manifest import MODEL_ID, MODEL_REVISION, SOURCE_HASHES, load_manifest
        from steamboat_runtime.model import PipelineModel
        from steamboat_runtime.protocol.codec import decode_tensor, encode_tensor
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_security.clock import Clock
        from tests.connector.test_artifacts import (
            _ACCOUNT, _PUBLIC, _assignment_bundle, _sign_document)

        source = Path(os.environ["STEAMBOAT_ASSIGNED_TEST_SOURCE"])
        scratch = Path(os.environ["STEAMBOAT_ASSIGNED_TEST_SCRATCH"])
        manifest = load_manifest(source)
        now = int(time.time())
        file_entries = {}
        for filename, digest in manifest["files"].items():
            info = (source / filename).lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            file_entries[filename] = {"sha256": digest, "size_bytes": info.st_size}
        manifest_bytes = (source / "modelmanifest.json").read_bytes()
        file_entries["modelmanifest.json"] = {
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "size_bytes": len(manifest_bytes)}
        components = {
            name: {"file": item["file"], "layer_range": item["layer_range"],
                   "sha256": item["sha256"],
                   "size_bytes": file_entries[item["file"]]["size_bytes"]}
            for name, item in manifest["components"].items()}
        catalog_payload = {
            "schema_version": 1, "catalog_revision": 1,
            "issued_at": now - 10, "expires_at": now + 3600,
            "model": {"model_id": MODEL_ID, "model_revision": MODEL_REVISION,
                      "tokenizer_revision": MODEL_REVISION, "source_hashes": SOURCE_HASHES,
                      "device": "cpu", "dtype": "float32", "attention": "eager",
                      "compression": "none", "layout": "batch_sequence_hidden",
                      "batch_size": 1, "hidden_size": 64, "vocabulary_size": 32000,
                      "layers": 8, "model_context": 2048, "runtime_context": 1152,
                      "tied_input_output_weights": False},
            "runtime": {"os": "linux", "architecture": "amd64", "python": "3.12.15",
                        "torch": "2.14.1+cpu", "transformers": "5.19.0",
                        "grpcio": "1.84.0", "protobuf": "7.36.2",
                        "lock_sha256": RUNTIME_LOCK_SHA256},
            "manifest": {"filename": "modelmanifest.json",
                         "fingerprint": manifest["fingerprint"],
                         **file_entries["modelmanifest.json"]},
            "components": components, "files": file_entries}
        catalog_bytes = _sign_document(catalog_payload, "catalog")
        clock = Clock(uncertainty_seconds=lambda: 0.0)
        verifier = CatalogVerifier(_PUBLIC, clock=clock)

        class SourceRetriever:
            def iter_chunks(self, filename, *, deadline, max_chunk_bytes):
                if filename not in ARTIFACT_FILENAMES:
                    raise ValueError("unapproved source artifact")
                path = source / filename
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise ValueError("source artifact is not regular")
                with path.open("rb") as stream:
                    while True:
                        chunk = stream.read(max_chunk_bytes)
                        if not chunk:
                            return
                        yield chunk

        device_id = "dev_" + "2" * 32
        worker_boots = {f"worker-{index}": f"{index:032x}" for index in range(1, 4)}
        handlers, sessions = [], {}
        group = None
        handlers_stopped = False
        reference = None
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            installer = ArtifactInstaller(Path(temporary) / "one-store", verifier,
                disk_ceiling_bytes=256 * 1024 * 1024,
                disk_headroom_bytes=16 * 1024 * 1024, wall_clock=lambda: now)
            views = []
            for index, component in enumerate(("worker-1", "worker-2", "worker-3"), 1):
                assignment_id = f"asg_{index:032x}"
                signed_catalog = verifier.verify_catalog(catalog_bytes, now=now)
                assignment_bytes, _ = _assignment_bundle(
                    verifier, signed_catalog, role="host", component=component, now=now,
                    assignment_id=assignment_id, device_id=device_id)
                installer.install(catalog_bytes, assignment_bytes, SourceRetriever(),
                    account_id=_ACCOUNT, device_id=device_id, role="host")
                views.append(installer.open_view(assignment_id, account_id=_ACCOUNT,
                    device_id=device_id, role="host", now=now))
            state = installer._load_state()
            self.assertEqual(set(state["host_slots"].values()),
                             {view.assignment_id for view in views})
            self.assertEqual(len({id(view.installer) for view in views}), 1)
            self.assertEqual(installer._used_bytes(state),
                sum(record["accounted_bytes"] for record in state["installations"].values()))
            group = RuntimeArtifactGroupPin.acquire(
                views, clock=clock, runtime_boot_id="d" * 32,
                worker_boot_ids=worker_boots)
            from steamboat_connector.artifact_pin import ArtifactPinBusy, ArtifactPinError
            first_guard = group.make_guard(views[0].assignment_id, clock, verifier)
            with self.assertRaises(ArtifactPinError):
                first_guard.close()
            group.assert_open_descriptors()
            launch = group.child_launch_metadata(views[0].assignment_id)
            inherited_fds = (os.dup(launch["global_fd"]), os.dup(launch["role_fd"]))
            for fd in inherited_fds:
                os.set_inheritable(fd, True)
            child_payload = {
                "root": launch["root"], "uid": launch["uid"],
                "record_path": launch["record_path"], "record": launch["record"],
                "component": launch["component"], "worker_boot_id": launch["worker_boot_id"],
                "clock_domain": launch["clock_domain"],
                "captured_mono": launch["captured_mono"],
                "catalog_deadline": launch["catalog_deadline"],
                "assignment_deadline": launch["assignment_deadline"],
                "signed_catalog": base64.b64encode(launch["signed_catalog"]).decode("ascii"),
                "signed_assignment": base64.b64encode(launch["signed_assignment"]).decode("ascii"),
                "public_key": _PUBLIC.hex()}
            child_script = "\n".join((
                "import base64, json, os, sys",
                "from steamboat_connector.aggregate_artifact_pin import validate_inherited_group_pin",
                "from steamboat_connector.catalog import CatalogVerifier",
                "from steamboat_security.clock import Clock",
                "p = json.loads(sys.argv[1]); c = Clock(uncertainty_seconds=lambda: 0.0)",
                "v = CatalogVerifier(bytes.fromhex(p['public_key']), clock=c)",
                "owner, guard = validate_inherited_group_pin(int(sys.argv[2]), int(sys.argv[3]),",
                "root=p['root'], uid=p['uid'], record_path=p['record_path'],",
                "expected_record=p['record'], component=p['component'],",
                "worker_boot_id=p['worker_boot_id'], clock_domain=p['clock_domain'],",
                "captured_mono=p['captured_mono'], catalog_deadline=p['catalog_deadline'],",
                "assignment_deadline=p['assignment_deadline'], clock=c,",
                "signed_catalog=base64.b64decode(p['signed_catalog']),",
                "signed_assignment=base64.b64decode(p['signed_assignment']), verifier=v)",
                "assert not os.get_inheritable(int(sys.argv[2]))",
                "assert not os.get_inheritable(int(sys.argv[3]))",
                "guard.check(); owner.close()"))
            try:
                child = subprocess.run(
                    [sys.executable, "-B", "-c", child_script, json.dumps(child_payload),
                     str(inherited_fds[0]), str(inherited_fds[1])],
                    pass_fds=inherited_fds, capture_output=True, text=True, timeout=30)
                self.assertEqual(child.returncode, 0, msg=child.stderr)
                group.assert_open_descriptors()
            finally:
                for fd in inherited_fds:
                    os.close(fd)
            with self.assertRaises(ArtifactPinBusy):
                RuntimeArtifactGroupPin.acquire(
                    views, clock=clock, runtime_boot_id="e" * 32,
                    worker_boot_ids=worker_boots)
            with self.assertRaises(ArtifactInstallBusy):
                installer.deactivate("host", compute_stopped=True)

            reference = PipelineModel(source)
            sessions.update({"session-A": reference.open_session(16),
                             "session-B": reference.open_session(16)})
            with asyncio.Runner() as runner:
                try:
                    for view in views:
                        entry = next(item for item in group.record["assignments"]
                                     if item["assignment_id"] == view.assignment_id)
                        guard = group.make_guard(view.assignment_id, clock, verifier)
                        handlers.append(build_assigned_worker_handler(
                            view, boot_id=entry["worker_boot_id"], clock=clock, guard=guard))
                    leases = {}
                    sequences = {(handler.worker_name, session): 0 for handler in handlers
                                 for session in sessions}
                    positions = {session: 0 for session in sessions}

                    async def call(method, handler, session_id, **fields):
                        values = {"protocol_version": 1,
                                  "manifest_fingerprint": handler.manifest["fingerprint"],
                                  "worker_boot_id": handler.boot_id,
                                  "session_id": session_id,
                                  "lease_token": leases.get((handler.worker_name, session_id), ""),
                                  "timeout_ms": handler.limits["rpc_timeout_seconds"] * 1000}
                        values.update(fields)
                        return await handler.handle(method, Request(**values))

                    async def exercise():
                        for handler in handlers:
                            for session_id in sessions:
                                opened = await call("OpenSession", handler, session_id,
                                    lease_token="", max_positions=16, lifetime_ms=300000,
                                    idle_lease_ms=120000)
                                self.assertEqual(opened.code, "OK", opened.message)
                                leases[(handler.worker_name, session_id)] = opened.lease_token
                        events = (("session-A", (1, 17, 19)), ("session-B", (5, 7)),
                                  ("session-A", (23,)), ("session-B", (29,)),
                                  ("session-A", (31,)), ("session-B", (37,)))
                        for session_id, token_values in events:
                            ids = torch.tensor([token_values], dtype=torch.long)
                            expected = sessions[session_id].step(ids)
                            with torch.inference_mode():
                                hidden = reference.input_output.embed_tokens(ids)
                            for handler in handlers:
                                count = len(token_values)
                                encoded = encode_tensor(hidden, hidden_size=64,
                                    max_tokens=handler.limits["max_positions"],
                                    max_bytes=handler.limits["max_message_bytes"])
                                response = await call("Step", handler, session_id,
                                    sequence=sequences[(handler.worker_name, session_id)],
                                    start_position=positions[session_id], token_count=count,
                                    tensor=encoded)
                                self.assertEqual(response.code, "OK", response.message)
                                hidden = decode_tensor(response.tensor, count, hidden_size=64,
                                    max_tokens=handler.limits["max_positions"],
                                    max_bytes=handler.limits["max_message_bytes"])
                                sequences[(handler.worker_name, session_id)] += 1
                            with torch.inference_mode():
                                actual = reference.input_output.lm_head(
                                    reference.input_output.norm(hidden[:, -1:, :]))
                            torch.testing.assert_close(actual, expected, atol=1e-3, rtol=0)
                            positions[session_id] += len(token_values)
                        for handler in handlers:
                            for session_id in sessions:
                                result = await call("CloseSession", handler, session_id)
                                self.assertEqual(result.code, "OK", result.message)
                                self.assertTrue(result.reclaimed)
                    runner.run(exercise())
                finally:
                    if handlers:
                        async def stop_handlers():
                            return await asyncio.gather(*(handler.shutdown() for handler in handlers))
                        handlers_stopped = all(value is True for value in runner.run(stop_handlers()))
                    for session in sessions.values():
                        session.close()
                    if reference is not None:
                        reference.close()
                    if handlers_stopped and group is not None:
                        group.release()
                    elif group is not None:
                        self.fail("worker cleanup was not proven; aggregate pin remains held")


if __name__ == "__main__":
    unittest.main()
