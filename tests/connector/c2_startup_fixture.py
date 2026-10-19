"""Coherent signed C2 selected-root and artifact-pin fixture for startup tests.

This helper uses the real selected-cohort, RootGenerationStore, channel
certificate, catalog, assignment, installer, and aggregate-pin validators.
It does not load model weights or start a worker process.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import time
from pathlib import Path

from steamboat_security.codec import canonical_json
from steamboat_security.root_transition_storage import (
    RootGenerationStore, RootGenerationSelector, root_generation_selector_document,
)
from steamboat_security.snapshot import canonical_policy_digest, sign_snapshot
from steamboat_connector.aggregate_artifact_pin import RuntimeArtifactGroupPin
from steamboat_connector.artifacts import ArtifactInstaller
from steamboat_connector.catalog import (ARTIFACT_FILENAMES, RUNTIME_LOCK_SHA256,
                                         CatalogVerifier)
from steamboat_runtime.manifest import (MODEL_ID, MODEL_REVISION, SOURCE_HASHES,
                                        load_manifest)

from tests.connector.test_artifacts import (_ACCOUNT, _PUBLIC, _PRIVATE,
    _OTHER_PUBLIC, _OTHER_PRIVATE, _assignment_bundle, _sign_document)
from tests.security.test_root_c2_runtime import C2RuntimeStoreIntegrationTests


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _SourceRetriever:
    def __init__(self, root: Path):
        self.root = root

    def iter_chunks(self, filename, *, deadline, max_chunk_bytes):
        if filename not in ARTIFACT_FILENAMES:
            raise ValueError("unapproved artifact filename")
        path = self.root / filename
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("artifact source must be a regular file")
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(max_chunk_bytes)
                if not chunk:
                    return
                yield chunk


class C2StartupFixture:
    """Owns a signed selected C2 binding and one exact signed worker pin."""

    def __init__(self, artifacts_dir, scratch_dir, *, pin_variant=None):
        if os.name != "posix" or not sys_platform_linux():
            raise RuntimeError("native C2 startup fixture requires Linux POSIX storage")
        self.artifacts_dir = Path(artifacts_dir).resolve(strict=True)
        self.scratch_dir = Path(scratch_dir).resolve(strict=True)
        self._closed = False
        if pin_variant not in (None, "catalog_digest", "assignment_digest",
                               "catalog_key", "extra_component"):
            raise ValueError("unknown C2 startup pin variant")
        self.pin_variant = pin_variant
        self.pin = None
        self.root_store = None
        self.installer = None
        self.selected_store = None
        self.binding = None
        self._temp = tempfile.TemporaryDirectory(prefix="c2-startup-fixture-",
                                                  dir=self.scratch_dir)
        self.work = Path(self._temp.name)
        self.selected_root = self.work / "selected"
        self.pin_root = self.work / "artifact-store"
        try:
            self._build_selected_root()
            self._build_artifact_pin()
        except BaseException:
            self.close()
            raise

    def _build_selected_root(self):
        fixture_type = C2RuntimeStoreIntegrationTests
        fixture_type.setUpClass()
        self.selected_store = object.__new__(fixture_type)
        self.selected_store._testMethodName = "startup_fixture"
        self.selected_store.setUp()
        self.fixture = self.selected_store
        self.cohort_fixture = self.selected_store.fixture
        self.clock = self.selected_store.clock
        manifest = load_manifest(self.artifacts_dir)
        fingerprint = manifest["fingerprint"]
        selected = self.selected_store
        # The runtime model identifier is the fingerprint authenticated by the
        # signed catalog, not the operator-facing model name in the pin record.
        group = json.loads(selected.artifacts["activation_manifest.json"])
        group_scope = group["new_host_group_scopes"][0]
        group_scope["model_id"] = fingerprint
        self.available_components = list(group_scope["components"])
        group_scope["components"] = [group_scope["components"][0]]
        chosen = group_scope["components"][0]
        self._prepare_selected_artifacts(fingerprint, group_scope, selected)
        active = json.loads(selected.active)["payload"]
        active["grants"] = [grant for grant in active["grants"]
            if grant["target_boot_id"] == chosen["worker_boot_id"]
            and grant["assignment_id"] == chosen["assignment_id"]]
        if not active["grants"]:
            raise RuntimeError("selected worker has no matching signed current grant")
        # Issue a new real operator signature over the narrowed selected scope.
        from steamboat_security.certificates import generate_private_key_pem, public_key_sha256
        from cryptography.hazmat.primitives import serialization
        group_key = generate_private_key_pem()
        operator_private = serialization.load_pem_private_key(group_key, password=None)
        selected.operator_public = operator_private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        group_scope["operator_public_key_sha256"] = public_key_sha256(operator_private.public_key())
        from steamboat_security.root_c2_group_scope import sign_c2_host_group_policy
        signed_group_bytes = sign_c2_host_group_policy({"version": 1,
            "issued_at": int(selected.wall), "expires_at": int(selected.wall) + 60,
            "scope": group_scope}, group_key)
        selected._private(selected.protected / "group-policy.json", signed_group_bytes)
        header = json.loads(selected.header_path.read_bytes())
        header["model_id"] = fingerprint
        header["group_policy_sha256"] = _sha(signed_group_bytes)
        header["component_paths"] = {"worker-1": header["component_paths"]["worker-1"]}
        header_bytes = canonical_json(header)
        selected._private(selected.header_path, header_bytes)
        host_doc = next(x for x in group["new_launch_specs"] if x["role"] == "host")
        host_doc["configuration_sha256"] = _sha(header_bytes)
        group["new_host_group_scopes"] = [group_scope]
        new_specs = tuple(__import__("steamboat_security.root_transition_launch",
            fromlist=["parse_role_launch_spec"]).parse_role_launch_spec(x)
            for x in group["new_launch_specs"])
        from steamboat_security.root_transition_launch import canonical_role_launch_digest
        group["new_launch_digest"] = canonical_role_launch_digest(new_specs)
        selected.artifacts["new_launch_specs.json"] = canonical_json(group["new_launch_specs"])

        # Rebuild both signed policy snapshots and their selected-root bindings
        # so all current grants and the immutable baseline agree with the model.
        baseline = json.loads(selected.artifacts["policy_snapshot.json"])["payload"]
        for grant in baseline["grants"]:
            grant["model_id"] = fingerprint
        for grant in active["grants"]:
            grant["model_id"] = fingerprint
        baseline_bytes = sign_snapshot(baseline, selected.fixture.fx.new_snapshot_key)
        active_bytes = sign_snapshot(active, selected.fixture.fx.new_snapshot_key)
        selected.artifacts["policy_snapshot.json"] = baseline_bytes
        group["policy_revision"] = baseline["revision"]
        group["policy_digest"] = canonical_policy_digest(baseline)
        group["policy_payload_sha256"] = _sha(canonical_json(baseline))
        manifest_bytes = canonical_json(group)
        selected.artifacts["activation_manifest.json"] = manifest_bytes
        selected.active = active_bytes
        selected.components = group_scope["components"]
        selected.host_spec = __import__("steamboat_security.root_transition_launch",
            fromlist=["parse_role_launch_spec"]).parse_role_launch_spec(host_doc)
        artifact_hashes = {name: _sha(data) for name, data in selected.artifacts.items()}
        selected.selector = RootGenerationSelector(
            selected.selector.generation_sha256, _sha(manifest_bytes), active["revision"],
            canonical_policy_digest(active), _sha(active_bytes), artifact_hashes)
        generation = selected.root / "generations" / selected.selector.generation_sha256
        descriptor = {"schema_version": 1, "purpose": "root_generation_descriptor",
            "generation_sha256": selected.selector.generation_sha256,
            "activation_manifest_sha256": selected.selector.activation_manifest_sha256,
            "artifact_sha256": dict(selected.selector.artifact_sha256)}
        selected._private(generation / "descriptor.json", canonical_json(descriptor))
        for name, data in selected.artifacts.items():
            selected._private(generation / name, data)
        for path in (selected.root / "policies").iterdir():
            path.unlink()
        selected._private(selected.root / "policies" / f"{_sha(active_bytes)}.json", active_bytes)
        selected._private(selected.root / "selector.json",
                           canonical_json(root_generation_selector_document(selected.selector)))
        self.model_fingerprint = fingerprint
        self.selected_host = selected.host_spec
        self.selected_header_path = selected.header_path
        self.protected_root = selected.protected
        self.operator_verification_key_pem = selected.operator_public
        self.operator_public_key_pem = selected.operator_public
        self.selected_scope = group_scope
        self.root_store = RootGenerationStore(selected.root, expected_uid=os.geteuid())
        from steamboat_security.root_c2_runtime import load_c2_host_runtime_binding
        self.binding = load_c2_host_runtime_binding(root_store=self.root_store,
            clock=self.clock, expected_launch_spec=selected.host_spec,
            configuration_path=selected.header_path,
            configuration_root=selected.protected, expected_uid=os.geteuid(),
            operator_verification_key_pem=selected.operator_public)

    def _prepare_selected_artifacts(self, fingerprint, scope, selected):
        """Create the exact signed catalog and assignment before signing C2 scope."""
        manifest = load_manifest(self.artifacts_dir)
        now = int(selected.wall)
        file_entries = {}
        for filename in ARTIFACT_FILENAMES:
            path = self.artifacts_dir / filename
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"artifact is not a regular file: {filename}")
            data = path.read_bytes()
            file_entries[filename] = {"sha256": _sha(data), "size_bytes": len(data)}
        components = {name: {"file": item["file"], "layer_range": item["layer_range"],
            "sha256": item["sha256"], "size_bytes": file_entries[item["file"]]["size_bytes"]}
            for name, item in manifest["components"].items()}
        catalog_payload = {"schema_version": 1, "catalog_revision": 1,
            "issued_at": now - 10, "expires_at": now + 3600,
            "model": {"model_id": MODEL_ID, "model_revision": MODEL_REVISION,
                "tokenizer_revision": MODEL_REVISION, "source_hashes": SOURCE_HASHES,
                "device": "cpu", "dtype": "float32", "attention": "eager",
                "compression": "none", "layout": "batch_sequence_hidden", "batch_size": 1,
                "hidden_size": 64, "vocabulary_size": 32000, "layers": 8,
                "model_context": 2048, "runtime_context": 1152,
                "tied_input_output_weights": False},
            "runtime": {"os": "linux", "architecture": "amd64", "python": "3.12.15",
                "torch": "2.14.1+cpu", "transformers": "5.19.0", "grpcio": "1.84.0",
                "protobuf": "7.36.2", "lock_sha256": RUNTIME_LOCK_SHA256},
            "manifest": {"filename": "modelmanifest.json", "fingerprint": fingerprint,
                **file_entries["modelmanifest.json"]}, "components": components,
            "files": file_entries}
        catalog_bytes = _sign_document(catalog_payload, "catalog")
        verifier = CatalogVerifier(_PUBLIC, clock=self.clock)
        catalog = verifier.verify_catalog(catalog_bytes, now=now)
        chosen = scope["components"][0]
        self.assignment_id = chosen["assignment_id"]
        self.worker_boot_id = chosen["worker_boot_id"]
        self.component = chosen["component"]
        assignment_bytes, assignment = _assignment_bundle(verifier, catalog,
            role="host", component=chosen["component"], now=now,
            assignment_id=chosen["assignment_id"],
            account_id=scope["account_id"], device_id=scope["device_id"])
        scope["catalog_sha256"] = catalog.document_sha256
        scope["catalog_public_key_sha256"] = hashlib.sha256(verifier.public_key).hexdigest()
        chosen["assignment_sha256"] = assignment.document_sha256
        self.selected_verifier = verifier
        self.selected_catalog = catalog
        self.selected_catalog_bytes = catalog_bytes
        self.selected_assignment = assignment
        self.selected_assignment_bytes = assignment_bytes
        self.selected_catalog_key_hash = hashlib.sha256(verifier.public_key).hexdigest()
        self.selected_assignment_sha256 = assignment.document_sha256

    def _build_artifact_pin(self):
        manifest = load_manifest(self.artifacts_dir)
        now = int(self.selected_store.wall)
        catalog_bytes = self.selected_catalog_bytes
        assignment_bytes = self.selected_assignment_bytes
        self.verifier = self.selected_verifier
        catalog = self.selected_catalog
        assignment = self.selected_assignment
        if self.pin_variant == "catalog_digest":
            catalog_bytes = _sign_document(catalog.payload, "catalog", _PRIVATE)
            catalog = self.verifier.verify_catalog(catalog_bytes, now=now)
            assignment_bytes, assignment = _assignment_bundle(self.verifier, catalog,
                role="host", component="worker-1", now=now,
                assignment_id=self.assignment_id,
                account_id=self.selected_host.account_id,
                device_id=self.selected_host.device_id)
        elif self.pin_variant == "assignment_digest":
            assignment_bytes = _sign_document(self.selected_assignment.payload,
                                               "assignment", _PRIVATE)
            assignment = self.verifier.verify_assignment(assignment_bytes, catalog,
                account_id=self.selected_host.account_id,
                device_id=self.selected_host.device_id, role="host", now=now)
        elif self.pin_variant == "catalog_key":
            self.verifier = CatalogVerifier(_OTHER_PUBLIC, clock=self.clock)
            catalog_bytes = _sign_document(self.selected_catalog.payload,
                                           "catalog", _OTHER_PRIVATE)
            catalog = self.verifier.verify_catalog(catalog_bytes, now=now)
            assignment_bytes, assignment = _assignment_bundle(self.verifier, catalog,
                role="host", component="worker-1", now=now,
                assignment_id=self.assignment_id,
                account_id=self.selected_host.account_id,
                device_id=self.selected_host.device_id, private_key=_OTHER_PRIVATE)
        component = "worker-1"
        selected_component = next(item for item in self.binding.components
                                  if item.component == component)
        self.assignment_id = selected_component.assignment_id
        self.worker_boot_id = selected_component.identity.boot_id
        self.component = component
        self.assignment = assignment
        self.host_policy = next(grant for grant in json.loads(self.selected_store.active)["payload"]["grants"]
                                if grant["assignment_id"] == self.assignment_id)
        self.signed_catalog = catalog_bytes
        self.signed_assignment = assignment_bytes
        self.pin_root.mkdir(mode=0o700)
        self.installer = ArtifactInstaller(self.pin_root, self.verifier,
            disk_ceiling_bytes=256 * 1024 * 1024, disk_headroom_bytes=16 * 1024 * 1024,
            wall_clock=lambda: now)
        self.installer.install(catalog_bytes, assignment_bytes,
            _SourceRetriever(self.artifacts_dir), account_id=self.selected_host.account_id,
            device_id=self.selected_host.device_id, role="host")
        view = self.installer.open_view(self.assignment_id,
            account_id=self.selected_host.account_id, device_id=self.selected_host.device_id,
            role="host", now=now)
        views = [view]
        self.worker_boot_ids = {component: self.worker_boot_id}
        if self.pin_variant == "extra_component":
            extra = next(item for item in self.available_components
                         if item["component"] == "worker-2")
            extra_bytes, self.extra_assignment = _assignment_bundle(self.verifier, catalog,
                role="host", component=extra["component"], now=now,
                assignment_id=extra["assignment_id"],
                account_id=self.selected_host.account_id,
                device_id=self.selected_host.device_id,
                private_key=_PRIVATE)
            self.installer.install(catalog_bytes, extra_bytes,
                _SourceRetriever(self.artifacts_dir), account_id=self.selected_host.account_id,
                device_id=self.selected_host.device_id, role="host")
            views.append(self.installer.open_view(extra["assignment_id"],
                account_id=self.selected_host.account_id, device_id=self.selected_host.device_id,
                role="host", now=now))
            self.worker_boot_ids[extra["component"]] = extra["worker_boot_id"]
        self.pin = RuntimeArtifactGroupPin.acquire(views, clock=self.clock,
            runtime_boot_id=self.selected_host.boot_id,
            worker_boot_ids=self.worker_boot_ids)
        pin_entry = next(entry for entry in self.pin.record["assignments"]
                         if entry["component"] == component)
        if (pin_entry["assignment_id"] != self.assignment_id
                or pin_entry["worker_boot_id"] != self.worker_boot_id
                or self.pin.record["model_id"] != MODEL_ID
                or self.selected_scope["model_id"] != self.model_fingerprint):
            raise RuntimeError("artifact pin differs from selected signed C2 tuple")

    def close(self):
        if self._closed:
            return
        self._closed = True
        failure = None
        for owner, method in ((self.pin, "release"), (self.root_store, "close")):
            if owner is not None:
                try:
                    getattr(owner, method)()
                except BaseException as error:
                    failure = failure or error
        if self.selected_store is not None:
            try:
                self.selected_store.tearDown()
            except BaseException as error:
                failure = failure or error
        # Preserve the private root if ownership release is uncertain so the
        # lock records and descriptors can still be diagnosed/recovered.
        if failure is None:
            try:
                self._temp.cleanup()
            except BaseException as error:
                failure = error
        if failure is not None:
            raise failure

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def sys_platform_linux():
    import sys
    return sys.platform.startswith("linux")


def c2_startup_fixture(artifacts_dir="/artifacts", scratch_dir=None, *, pin_variant=None):
    """Construct a C2 startup fixture; caller owns it with a `with` block."""
    if scratch_dir is None:
        scratch_dir = os.environ.get("STEAMBOAT_ASSIGNED_TEST_SCRATCH")
    if not scratch_dir:
        raise ValueError("scratch_dir or STEAMBOAT_ASSIGNED_TEST_SCRATCH is required")
    return C2StartupFixture(artifacts_dir, scratch_dir, pin_variant=pin_variant)
