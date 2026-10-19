import asyncio
import builtins
import copy
from contextlib import contextmanager, nullcontext
import errno
import hashlib
import os
from pathlib import Path
import select
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from steamboat_connector import catalog as catalog_module
from steamboat_connector import artifacts as artifacts_module
from steamboat_connector import storage as storage_module
from steamboat_connector.artifacts import (INSTALL_METADATA_RESERVE_BYTES,
                                           ArtifactInstallBusy, ArtifactInstallError, ArtifactInstaller,
                                           ArtifactQuotaError, LocalArtifactStoreRetriever)
from steamboat_connector.catalog import (ARTIFACT_FILENAMES, ASSIGNABLE_COMPONENTS,
                                        CHUNK_BYTES, CatalogError, CatalogVerifier,
                                        RUNTIME_LOCK_SHA256, required_artifact_names)
from steamboat_connector.validation import json_bytes
from steamboat_runtime.manifest import (MODEL_ID, MODEL_REVISION, SOURCE_HASHES)
from steamboat_runtime import assigned_artifacts as assigned_artifacts_module
from steamboat_runtime.assigned_artifacts import (AssignedArtifactError,
                                                  AssignedArtifactView)


_PRIVATE = ec.derive_private_key(
    0x123456789ABCDEF0123456789ABCDEF123456789ABCDEF0123456789ABCDEF,
    ec.SECP256R1())
_OTHER_PRIVATE = ec.derive_private_key(
    0x123456789ABCDEF0123456789ABCDEF123456789ABCDEF0123456789ABCDF6,
    ec.SECP256R1())
_PUBLIC = catalog_module.public_key_bytes(_PRIVATE.public_key())
_OTHER_PUBLIC = catalog_module.public_key_bytes(_OTHER_PRIVATE.public_key())
_ACCOUNT = "acct_0123456789abcdef0123456789abcdef"
_DEVICE = "dev_0123456789abcdef0123456789abcdef"
_NOW = 1_800_000_000


def _sign_document(payload, kind, private_key=_PRIVATE):
    message = catalog_module._signature_message(kind, payload)
    der_signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_signature)
    if s > catalog_module._N // 2:
        s = catalog_module._N - s
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    public_key = catalog_module.public_key_bytes(private_key.public_key())
    envelope = {
        "schema_version": 1,
        "signature_scheme": catalog_module.SIGNATURE_SCHEME,
        "key_id": catalog_module.key_id_for(public_key),
        "payload": payload,
        "signature": signature.hex(),
    }
    maximum = (catalog_module.MAX_CATALOG_BYTES if kind == "catalog"
               else catalog_module.MAX_ASSIGNMENT_BYTES)
    return json_bytes(envelope, maximum_bytes=maximum)


def _fixture_file_bytes(source_hashes=None):
    source_hashes = SOURCE_HASHES if source_hashes is None else source_hashes
    result = {name: ("artifact-fixture:" + name).encode("ascii")
              for name in ARTIFACT_FILENAMES if name != "modelmanifest.json"}
    result["modelmanifest.json"] = b'{"fixture_manifest":true}'
    return result


def _catalog_payload(now=_NOW, revision=1, file_bytes=None, source_hashes=None, **changes):
    source_hashes = dict(SOURCE_HASHES if source_hashes is None else source_hashes)
    file_bytes = _fixture_file_bytes(source_hashes) if file_bytes is None else file_bytes
    files = {}
    for filename in ARTIFACT_FILENAMES:
        content = file_bytes.get(filename)
        if filename in source_hashes and filename != "model.safetensors":
            digest = source_hashes[filename]
            size = len(content) if content is not None else 1
        elif content is not None:
            digest = hashlib.sha256(content).hexdigest()
            size = len(content)
        else:
            digest = hashlib.sha256(filename.encode("ascii")).hexdigest()
            size = 1
        files[filename] = {"sha256": digest, "size_bytes": size}
    components = {}
    for component, layer_range in ASSIGNABLE_COMPONENTS.items():
        filename = f"{component}.safetensors"
        components[component] = {
            "file": filename,
            "layer_range": layer_range,
            **files[filename],
        }
    payload = {
        "schema_version": 1,
        "catalog_revision": revision,
        "issued_at": now - 10,
        "expires_at": now + 3600,
        "model": {
            "model_id": MODEL_ID,
            "model_revision": MODEL_REVISION,
            "tokenizer_revision": MODEL_REVISION,
            "source_hashes": source_hashes,
            "device": "cpu",
            "dtype": "float32",
            "attention": "eager",
            "compression": "none",
            "layout": "batch_sequence_hidden",
            "batch_size": 1,
            "hidden_size": 64,
            "vocabulary_size": 32000,
            "layers": 8,
            "model_context": 2048,
            "runtime_context": 1152,
            "tied_input_output_weights": False,
        },
        "runtime": {
            "os": "linux",
            "architecture": "amd64",
            "python": "3.12.15",
            "torch": "2.14.1+cpu",
            "transformers": "5.19.0",
            "grpcio": "1.84.0",
            "protobuf": "7.36.2",
            "lock_sha256": RUNTIME_LOCK_SHA256,
        },
        "manifest": {
            "filename": "modelmanifest.json",
            "fingerprint": "f" * 64,
            **files["modelmanifest.json"],
        },
        "components": components,
        "files": files,
    }
    for key, value in changes.items():
        payload[key] = value
    return payload


def _catalog_bundle(payload=None, *, now=_NOW, private_key=_PRIVATE):
    payload = _catalog_payload(now=now) if payload is None else payload
    catalog_bytes = _sign_document(payload, "catalog", private_key)
    verifier = CatalogVerifier(catalog_module.public_key_bytes(private_key.public_key()))
    catalog = verifier.verify_catalog(catalog_bytes, now=now)
    return verifier, catalog_bytes, catalog


def _assignment_payload(catalog, *, role="host", component="worker-1", now=_NOW,
                        account_id=_ACCOUNT, device_id=_DEVICE, assignment_id=None,
                        **changes):
    assignment = {
        "schema_version": 1,
        "assignment_id": assignment_id or f"asg_{'1' * 32}",
        "catalog_revision": catalog.payload["catalog_revision"],
        "catalog_sha256": catalog.document_sha256,
        "account_id": account_id,
        "device_id": device_id,
        "role": role,
        "component": component,
        "manifest_fingerprint": catalog.payload["manifest"]["fingerprint"],
        "issued_at": now - 5,
        "expires_at": min(catalog.payload["expires_at"], now + 1800),
    }
    assignment.update(changes)
    return assignment


def _assignment_bundle(verifier, catalog, *, role="host", component="worker-1", now=_NOW,
                       private_key=_PRIVATE, **changes):
    payload = _assignment_payload(catalog, role=role, component=component,
                                  now=now, **changes)
    raw = _sign_document(payload, "assignment", private_key)
    verified = verifier.verify_assignment(raw, catalog, account_id=payload["account_id"],
                                          device_id=payload["device_id"], role=role, now=now)
    return raw, verified


def _fd_count():
    return len(os.listdir("/proc/self/fd"))


def _safetensors_bytes(tensors, variant):
    specifications = {
        name: {"shape": list(specification["shape"]),
               "dtype": specification["dtype"]}
        for name, specification in tensors.items()
    }
    first_name = sorted(specifications)[0]
    if variant == "keys":
        specification = specifications.pop(first_name)
        specifications["model.layers.0.unexpected.weight"] = specification
    elif variant == "shape":
        vector_name = next(name for name in sorted(specifications)
                           if len(specifications[name]["shape"]) == 1)
        specifications[vector_name]["shape"].insert(0, 1)
    elif variant == "dtype":
        specifications[first_name]["dtype"] = "F64"
    else:
        raise ValueError("unsupported safetensors test variant")
    item_sizes = {"F32": 4, "F64": 8}
    header = {"__metadata__": {"format": "pt"}}
    offset = 0
    for name, specification in sorted(specifications.items()):
        elements = 1
        for dimension in specification["shape"]:
            elements *= dimension
        size = elements * item_sizes[specification["dtype"]]
        header[name] = {
            "dtype": specification["dtype"],
            "shape": specification["shape"],
            "data_offsets": [offset, offset + size],
        }
        offset += size
    encoded_header = json_bytes(header)
    encoded_header += b" " * (-len(encoded_header) % 8)
    return struct.pack("<Q", len(encoded_header)) + encoded_header + bytes(offset)


class _DescriptorRetriever:
    def __init__(self, source_path, chunk):
        self.source_path = source_path
        self.chunk = chunk
        self.closed = False

    def iter_chunks(self, filename, *, deadline, max_chunk_bytes):
        descriptor = os.open(self.source_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            yield self.chunk
            yield b"unreachable"
        finally:
            os.close(descriptor)
            self.closed = True


class CatalogSignatureTests(unittest.TestCase):
    def setUp(self):
        self.verifier, self.catalog_bytes, self.catalog = _catalog_bundle()

    def test_signed_catalog_and_role_scopes_are_closed(self):
        self.assertEqual(self.catalog.payload["catalog_revision"], 1)
        self.assertEqual(required_artifact_names("host", "worker-2"),
                         ("modelmanifest.json", "config.json", "worker-2.safetensors"))
        self.assertEqual(required_artifact_names("coordinator", "coordinator"),
                         ("modelmanifest.json", "config.json", "coordinator.safetensors",
                          *catalog_module.TOKENIZER_FILES))
        self.assertEqual(required_artifact_names("consumer", None), ())

    def test_wrong_signer_and_tampered_signature_rejected(self):
        other = CatalogVerifier(_OTHER_PUBLIC)
        with self.assertRaises(CatalogError):
            other.verify_catalog(self.catalog_bytes, now=_NOW)
        envelope = catalog_module.strict_json_loads(self.catalog_bytes)
        envelope["signature"] = "0" * 128
        with self.assertRaises(CatalogError):
            self.verifier.verify_catalog(json_bytes(envelope), now=_NOW)

    def test_cryptography_signatures_verify_and_invalid_points_or_curves_reject(self):
        message = catalog_module._signature_message("catalog", self.catalog.payload)
        der = _PRIVATE.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        if s > catalog_module._N // 2:
            s = catalog_module._N - s
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        self.assertTrue(catalog_module.verify_p256_sha256(_PUBLIC, message, signature))
        altered = bytes([signature[0] ^ 1]) + signature[1:]
        self.assertFalse(catalog_module.verify_p256_sha256(_PUBLIC, message, altered))
        high_s = (catalog_module._N - int.from_bytes(signature[32:], "big")).to_bytes(32, "big")
        self.assertFalse(catalog_module.verify_p256_sha256(
            _PUBLIC, message, signature[:32] + high_s))
        with self.assertRaises(CatalogError):
            catalog_module.validate_public_key(b"\x04" + bytes(64))
        with self.assertRaises(CatalogError):
            catalog_module.public_key_bytes(
                ec.derive_private_key(1, ec.SECP384R1()).public_key())
        wrong_curve = ec.derive_private_key(1, ec.SECP384R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        with self.assertRaises(CatalogError):
            CatalogVerifier(wrong_curve)

    def test_catalog_and_assignment_signatures_are_domain_separated(self):
        with self.assertRaises(CatalogError):
            self.verifier.verify_assignment(
                self.catalog_bytes, self.catalog, account_id=_ACCOUNT,
                device_id=_DEVICE, role="host", now=_NOW)
        assignment_bytes, _ = _assignment_bundle(self.verifier, self.catalog)
        with self.assertRaises(CatalogError):
            self.verifier.verify_catalog(assignment_bytes, now=_NOW)

        valid_assignment = _assignment_payload(self.catalog)
        correctly_signed = _sign_document(valid_assignment, "assignment")
        self.verifier.verify_assignment(
            correctly_signed, self.catalog, account_id=_ACCOUNT,
            device_id=_DEVICE, role="host", now=_NOW)
        wrong_domain = _sign_document(valid_assignment, "catalog")
        with self.assertRaisesRegex(CatalogError, "signature verification"):
            self.verifier.verify_assignment(
                wrong_domain, self.catalog, account_id=_ACCOUNT,
                device_id=_DEVICE, role="host", now=_NOW)

    def test_unknown_fields_duplicate_keys_nonfinite_and_noncanonical_json_rejected(self):
        payload = copy.deepcopy(self.catalog.payload)
        payload["unrecognized"] = True
        with self.assertRaises(CatalogError):
            self.verifier.verify_catalog(_sign_document(payload, "catalog"), now=_NOW)
        for raw in (b'{"schema_version":1,"schema_version":1}',
                    b'{"value":NaN}', b'{ "not": "canonical" }'):
            with self.subTest(raw=raw), self.assertRaises(CatalogError):
                self.verifier.verify_catalog(raw, now=_NOW)

    def test_revision_expiry_model_runtime_hash_size_and_layer_range_rejected(self):
        cases = []
        payload = copy.deepcopy(self.catalog.payload)
        payload["catalog_revision"] = True
        cases.append(("boolean revision", payload))
        payload = copy.deepcopy(self.catalog.payload)
        payload["expires_at"] = _NOW
        cases.append(("expiry", payload))
        payload = copy.deepcopy(self.catalog.payload)
        payload["model"]["model_revision"] = "latest"
        cases.append(("model revision", payload))
        payload = copy.deepcopy(self.catalog.payload)
        payload["runtime"]["lock_sha256"] = "0" * 64
        cases.append(("runtime lock", payload))
        payload = copy.deepcopy(self.catalog.payload)
        payload["files"]["worker-1.safetensors"]["sha256"] = "0" * 64
        cases.append(("file hash", payload))
        payload = copy.deepcopy(self.catalog.payload)
        payload["files"]["worker-1.safetensors"]["size_bytes"] = 33 * 1024 * 1024
        cases.append(("file size", payload))
        payload = copy.deepcopy(self.catalog.payload)
        payload["components"]["worker-1"]["layer_range"] = [0, 4]
        cases.append(("component range", payload))
        for name, invalid in cases:
            raw = _sign_document(invalid, "catalog")
            with self.subTest(name=name), self.assertRaises(CatalogError):
                self.verifier.verify_catalog(raw, now=_NOW)

    def test_assignment_binds_account_device_catalog_role_component_and_expiry(self):
        raw, verified = _assignment_bundle(self.verifier, self.catalog, component="worker-3")
        self.assertEqual(verified.payload["component"], "worker-3")
        failures = (
            {"account_id": "acct_" + "2" * 32},
            {"device_id": "dev_" + "2" * 32},
            {"catalog_revision": 0},
            {"component": "coordinator"},
            {"expires_at": _NOW},
            {"manifest_fingerprint": "0" * 64},
        )
        for changes in failures:
            payload = _assignment_payload(self.catalog, **changes)
            bad = _sign_document(payload, "assignment")
            with self.subTest(changes=changes), self.assertRaises(CatalogError):
                self.verifier.verify_assignment(bad, self.catalog, account_id=_ACCOUNT,
                                                device_id=_DEVICE, role="host", now=_NOW)
        consumer, _ = _assignment_bundle(self.verifier, self.catalog, role="consumer", component=None)
        self.verifier.verify_assignment(consumer, self.catalog, account_id=_ACCOUNT,
                                        device_id=_DEVICE, role="consumer", now=_NOW)
        coordinator, _ = _assignment_bundle(self.verifier, self.catalog, role="coordinator",
                                            component="coordinator")
        self.verifier.verify_assignment(coordinator, self.catalog, account_id=_ACCOUNT,
                                        device_id=_DEVICE, role="coordinator", now=_NOW)
        self.assertEqual(raw, verified.document_bytes)

    def test_assignment_unknown_version_type_and_signature_rejected(self):
        payload = _assignment_payload(self.catalog)
        payload["schema_version"] = 2
        raw = _sign_document(payload, "assignment")
        with self.assertRaises(CatalogError):
            self.verifier.verify_assignment(raw, self.catalog, account_id=_ACCOUNT,
                                            device_id=_DEVICE, role="host", now=_NOW)
        payload = _assignment_payload(self.catalog)
        payload["unrecognized"] = "field"
        raw = _sign_document(payload, "assignment")
        with self.assertRaises(CatalogError):
            self.verifier.verify_assignment(raw, self.catalog, account_id=_ACCOUNT,
                                            device_id=_DEVICE, role="host", now=_NOW)
        payload = _assignment_payload(self.catalog, component=["worker-1"])
        raw = _sign_document(payload, "assignment")
        with self.assertRaises(CatalogError):
            self.verifier.verify_assignment(raw, self.catalog, account_id=_ACCOUNT,
                                            device_id=_DEVICE, role="host", now=_NOW)
        raw, _ = _assignment_bundle(self.verifier, self.catalog)
        with self.assertRaises(CatalogError):
            self.verifier.verify_assignment(raw, self.catalog, account_id=_ACCOUNT,
                                            device_id=_DEVICE, role="coordinator", now=_NOW)


class ArtifactConfigurationTests(unittest.TestCase):
    def test_installer_timeout_configuration_is_finite_and_bounded(self):
        root = Path.cwd() / ".invalid-installer-test-root"
        for lock_timeout, install_timeout in (
                (5.01, 300), (float("nan"), 300), (5, 301)):
            with self.subTest(lock_timeout=lock_timeout,
                              install_timeout=install_timeout):
                with self.assertRaises(ValueError):
                    ArtifactInstaller(
                        root, CatalogVerifier(_PUBLIC),
                        disk_ceiling_bytes=64 * 1024 * 1024,
                        disk_headroom_bytes=16 * 1024 * 1024,
                        lock_timeout_seconds=lock_timeout,
                        install_timeout_seconds=install_timeout)
        self.assertFalse(root.exists())


class _MemoryRetriever:
    def __init__(self, files, *, interrupt_after=None, interrupt_name=None,
                 corrupt_name=None, chunk_bytes=CHUNK_BYTES):
        self.files = files
        self.interrupt_after = interrupt_after
        self.interrupt_name = interrupt_name
        self.corrupt_name = corrupt_name
        if type(chunk_bytes) is not int or not 1 <= chunk_bytes <= CHUNK_BYTES:
            raise ValueError("fixture chunk size is outside the retriever bound")
        self.chunk_bytes = chunk_bytes
        self.yielded_bytes = {}
        self.interrupted_at = None

    def iter_chunks(self, filename, *, deadline, max_chunk_bytes):
        if filename not in self.files:
            raise OSError("missing fixture")
        content = self.files[filename]
        if filename == self.corrupt_name:
            content = content + b"corrupt"
        chunk_bytes = min(max_chunk_bytes, self.chunk_bytes)
        for offset in range(0, len(content), chunk_bytes):
            should_interrupt = (self.interrupt_after is not None
                                and (self.interrupt_name is None
                                     or filename == self.interrupt_name))
            if should_interrupt and offset >= self.interrupt_after:
                self.interrupted_at = (filename, self.yielded_bytes.get(filename, 0))
                raise OSError("fixture interruption")
            chunk = content[offset:offset + chunk_bytes]
            self.yielded_bytes[filename] = self.yielded_bytes.get(filename, 0) + len(chunk)
            yield chunk


class AssignedRuntimeIdentityTests(unittest.TestCase):
    @staticmethod
    def _view():
        assignment_id = f"asg_{'f' * 32}"
        view = object.__new__(AssignedArtifactView)
        view.role = "host"
        view.assignment_id = assignment_id
        view.installer = SimpleNamespace(
            _locked=lambda: nullcontext(),
            _load_state=lambda: {"installations": {assignment_id: {}}},
        )
        view._verify_unlocked = mock.Mock(return_value={})
        return view

    @staticmethod
    def _versions(changes=None):
        values = {
            "torch": "2.14.1+cpu",
            "transformers": "5.19.0",
            "safetensors": "0.8.0",
            "grpcio": "1.84.0",
            "protobuf": "7.36.2",
        }
        values.update(changes or {})
        return values

    def test_runtime_platform_and_distribution_mismatches_fail_before_torch_import(self):
        cases = (
            {"machine": "aarch64", "versions": self._versions()},
            {"machine": "x86_64", "versions": self._versions({"grpcio": "1.83.0"})},
        )
        for case in cases:
            with self.subTest(machine=case["machine"], versions=case["versions"]):
                view = self._view()
                torch_imports = []
                original_import = builtins.__import__

                def reject_torch_import(name, *args, **kwargs):
                    if name == "torch" or name.startswith("torch."):
                        torch_imports.append(name)
                        raise AssertionError("Torch imported before runtime identity passed")
                    return original_import(name, *args, **kwargs)

                with (mock.patch.object(assigned_artifacts_module.sys,
                                        "platform", "linux"),
                      mock.patch.object(assigned_artifacts_module.platform,
                                        "system", return_value="Linux"),
                      mock.patch.object(assigned_artifacts_module.platform,
                                        "machine", return_value=case["machine"]),
                      mock.patch.object(assigned_artifacts_module.platform,
                                        "python_implementation", return_value="CPython"),
                      mock.patch.object(assigned_artifacts_module.platform,
                                        "python_version", return_value="3.12.15"),
                      mock.patch.object(assigned_artifacts_module.importlib.metadata,
                                        "version",
                                        side_effect=lambda name: case["versions"][name]),
                      mock.patch.object(builtins, "__import__",
                                        side_effect=reject_torch_import)):
                    with self.assertRaises(AssignedArtifactError):
                        view.load_stage()
                self.assertEqual(torch_imports, [])

    def test_loaded_torch_rejects_accelerator_builds(self):
        cpu_build = SimpleNamespace(
            __version__="2.14.1+cpu",
            version=SimpleNamespace(cuda=None, hip=None),
            cuda=SimpleNamespace(is_available=lambda: False),
        )
        assigned_artifacts_module._verify_loaded_torch_cpu(cpu_build)
        cuda_build = SimpleNamespace(
            __version__="2.14.1+cpu",
            version=SimpleNamespace(cuda="12.8", hip=None),
            cuda=SimpleNamespace(is_available=lambda: True),
        )
        with self.assertRaisesRegex(AssignedArtifactError, "CPU-only"):
            assigned_artifacts_module._verify_loaded_torch_cpu(cuda_build)

    def test_new_layer_cache_rejects_wrong_stack_before_torch_import(self):
        view = self._view()
        view.assignment = SimpleNamespace(payload={"component": "worker-1"})
        view._verify_unlocked = mock.Mock(return_value={
            "components": {"worker-1": {"layer_range": [0, 3]}}})
        torch_imports = []
        original_import = builtins.__import__

        def reject_torch_import(name, *args, **kwargs):
            if name == "torch" or name.startswith("torch."):
                torch_imports.append(name)
                raise AssertionError("cache creation imported Torch on a rejected stack")
            return original_import(name, *args, **kwargs)

        with (mock.patch.object(assigned_artifacts_module.sys, "platform", "win32"),
              mock.patch.object(builtins, "__import__", side_effect=reject_torch_import)):
            with self.assertRaises(AssignedArtifactError):
                view.new_layer_cache()
        self.assertEqual(torch_imports, [])

    def test_open_view_now_is_only_the_initial_validation_snapshot(self):
        assignment_id = f"asg_{'7' * 32}"
        record = {"role": "host", "component": "worker-1"}
        state = {"installations": {assignment_id: record},
                 "active": {"host": assignment_id, "coordinator": None},
                 "host_slots": {"worker-1": assignment_id,
                                "worker-2": None, "worker-3": None}}
        clock = {"now": _NOW}
        installer = SimpleNamespace(
            _locked=lambda: nullcontext(),
            _load_state=lambda: state,
            wall_clock=lambda: clock["now"],
            runtime_lock_path=None,
        )
        validated_at = []

        def verify_open_snapshot(view, _state, _record):
            validated_at.append(view._clock_now())
            return {}

        with (mock.patch.object(assigned_artifacts_module, "verify_runtime_lock"),
              mock.patch.object(AssignedArtifactView, "_verify_unlocked",
                                new=verify_open_snapshot)):
            view = ArtifactInstaller.open_view(
                installer, assignment_id, account_id=_ACCOUNT,
                device_id=_DEVICE, role="host", now=_NOW)
        self.assertEqual(validated_at, [_NOW])
        clock["now"] = _NOW + 1800
        self.assertEqual(view._clock_now(), _NOW + 1800)

    def test_expiry_after_open_hash_and_runtime_import_blocks_stage_and_head(self):
        verifier, catalog_bytes, catalog = _catalog_bundle()
        clock = {"now": _NOW}
        manifest = {
            "config": {},
            "components": {
                "worker-1": {"layer_range": [0, 3]},
                "coordinator": {"layer_range": None},
            },
        }

        class FakeLlamaConfig:
            @staticmethod
            def from_dict(config):
                return SimpleNamespace()

        torch_module = ModuleType("torch")
        safetensors_module = ModuleType("safetensors")
        safetensors_module.__path__ = []
        safetensors_module.safe_open = mock.Mock()
        safetensors_torch_module = ModuleType("safetensors.torch")
        load_file = mock.Mock(name="load_file")
        safetensors_torch_module.load_file = load_file
        transformers_module = ModuleType("transformers")
        transformers_module.LlamaConfig = FakeLlamaConfig
        transformers_module.AutoTokenizer = mock.Mock()
        model_module = ModuleType("steamboat_runtime.model")
        layer_stage = mock.Mock(name="LayerStage")
        input_output = mock.Mock(name="InputOutput")
        model_module.LayerStage = layer_stage
        model_module.InputOutput = input_output
        coordinator_module = ModuleType("steamboat_runtime.coordinator_model")
        coordinator_model = mock.Mock(name="CoordinatorModel")
        coordinator_module.CoordinatorModel = coordinator_model
        imported_modules = {
            "torch": torch_module,
            "safetensors": safetensors_module,
            "safetensors.torch": safetensors_torch_module,
            "transformers": transformers_module,
            "steamboat_runtime.model": model_module,
            "steamboat_runtime.coordinator_model": coordinator_module,
        }

        for role, component, assignment_id, loader in (
                ("host", "worker-1", f"asg_{'1' * 32}", "load_stage"),
                ("coordinator", "coordinator", f"asg_{'2' * 32}",
                 "load_coordinator_model")):
            with self.subTest(role=role):
                clock["now"] = _NOW
                assignment_bytes, _ = _assignment_bundle(
                    verifier, catalog, role=role, component=component,
                    assignment_id=assignment_id)
                assignment = verifier.verify_assignment(
                    assignment_bytes, catalog, account_id=_ACCOUNT,
                    device_id=_DEVICE, role=role, now=_NOW)
                record = {"role": role, "component": component}
                state = {"installations": {assignment_id: record},
                         "active": {"host": None, "coordinator": None},
                         "host_slots": {"worker-1": None, "worker-2": None,
                                        "worker-3": None}}
                if role == "host":
                    state["host_slots"][component] = assignment_id
                    state["active"][role] = assignment_id
                else:
                    state["active"][role] = assignment_id
                installer = SimpleNamespace(
                    _locked=lambda: nullcontext(),
                    _load_state=lambda: state,
                    wall_clock=lambda: clock["now"],
                    verifier=verifier,
                    runtime_lock_path=None,
                )
                with mock.patch.object(assigned_artifacts_module,
                                       "verify_runtime_lock"):
                    view = AssignedArtifactView(
                        installer, assignment_id, account_id=_ACCOUNT,
                        device_id=_DEVICE, role=role, now=_NOW)
                self.assertEqual(view._clock_now(), _NOW)

                def verify_during_slow_hash(_state, _record):
                    now = view._clock_now()
                    view.catalog = verifier.verify_catalog(catalog_bytes, now=now)
                    view.assignment = verifier.verify_assignment(
                        assignment_bytes, view.catalog, account_id=_ACCOUNT,
                        device_id=_DEVICE, role=role, now=now)
                    view.directory = Path("/unused-assigned-test-path")
                    clock["now"] = _NOW + 1799
                    return manifest

                view._verify_unlocked = verify_during_slow_hash

                def expire_during_runtime_import():
                    clock["now"] = _NOW + 1800

                load_file.reset_mock()
                layer_stage.reset_mock()
                input_output.reset_mock()
                coordinator_model.reset_mock()
                with (mock.patch.dict(sys.modules, imported_modules),
                      mock.patch.object(assigned_artifacts_module,
                                        "_verify_execution_runtime_metadata",
                                        side_effect=expire_during_runtime_import),
                      mock.patch.object(assigned_artifacts_module,
                                        "_verify_loaded_torch_cpu"),
                      mock.patch.object(assigned_artifacts_module,
                                        "_verify_safetensors_header")):
                    with self.assertRaisesRegex(
                            AssignedArtifactError, "expired or became invalid"):
                        getattr(view, loader)()
                load_file.assert_not_called()
                layer_stage.assert_not_called()
                input_output.assert_not_called()
                coordinator_model.assert_not_called()


class ArtifactImportsRemainTorchFreeTests(unittest.TestCase):
    def test_crypto_backed_artifact_imports_do_not_load_torch(self):
        project_root = Path(__file__).resolve().parents[2]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(project_root / "src")
        script = """
import sys
import cryptography
from steamboat_connector import artifacts, catalog
from steamboat_runtime import assigned_artifacts

assert cryptography.__name__ == "cryptography"
assert artifacts.ArtifactInstaller
assert catalog.CatalogVerifier
assert assigned_artifacts.AssignedArtifactView
assert not any(name == "torch" or name.startswith("torch.")
               for name in sys.modules)
assert not any(name == "transformers" or name.startswith("transformers.")
               or name == "huggingface_hub" or name.startswith("huggingface_hub.")
               for name in sys.modules)
"""
        result = subprocess.run(
            [sys.executable, "-B", "-c", script], cwd=project_root,
            env=environment, capture_output=True, text=True, timeout=20,
            check=False)
        self.assertEqual(result.returncode, 0, msg=f"{result.stdout}\n{result.stderr}")


@unittest.skipUnless(sys.platform.startswith("linux"),
                     "installer storage primitives require Linux openat/O_NOFOLLOW and flock")
class ArtifactInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "installed"
        self.file_bytes = _fixture_file_bytes()
        self.source_hashes = {
            name: hashlib.sha256(self.file_bytes.get(name, b"fixture-source-model")).hexdigest()
            for name in SOURCE_HASHES
        }
        self.source_patch = mock.patch.object(catalog_module, "SOURCE_HASHES", self.source_hashes)
        self.source_patch.start()
        self.addCleanup(self.source_patch.stop)
        self.verifier, self.catalog_bytes, self.catalog = _catalog_bundle(
            _catalog_payload(file_bytes=self.file_bytes, source_hashes=self.source_hashes))
        self.installer = ArtifactInstaller(
            self.root, self.verifier, disk_ceiling_bytes=64 * 1024 * 1024,
            disk_headroom_bytes=16 * 1024 * 1024, wall_clock=lambda: _NOW)

    def _install_input(self, *, component="worker-1", assignment_id=None, revision=1,
                       files=None, retriever=None):
        if revision == self.catalog.payload["catalog_revision"]:
            catalog_bytes = self.catalog_bytes
            catalog = self.catalog
        else:
            payload = _catalog_payload(now=_NOW, revision=revision,
                                       file_bytes=self.file_bytes,
                                       source_hashes=self.source_hashes)
            catalog_bytes = _sign_document(payload, "catalog")
            catalog = self.verifier.verify_catalog(catalog_bytes, now=_NOW)
        assignment_bytes, _ = _assignment_bundle(
            self.verifier, catalog, component=component, assignment_id=assignment_id or
            f"asg_{'1' * 31}{revision}")
        source = files or self.file_bytes
        return catalog_bytes, assignment_bytes, retriever or _MemoryRetriever(source)

    def test_install_scope_modes_and_persisted_restart_state(self):
        catalog_bytes, assignment_bytes, retriever = self._install_input()
        result = self.installer.install(catalog_bytes, assignment_bytes, retriever,
                                        account_id=_ACCOUNT, device_id=_DEVICE, role="host")
        self.assertTrue(result.created)
        self.assertTrue(result.path.is_dir())
        self.assertEqual(set(path.name for path in result.path.iterdir()), {
            "modelmanifest.json", "config.json", "worker-1.safetensors",
            "signed-catalog.json", "signed-assignment.json"})
        for path in result.path.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        reopened = ArtifactInstaller(
            self.root, self.verifier, disk_ceiling_bytes=64 * 1024 * 1024,
            disk_headroom_bytes=16 * 1024 * 1024, wall_clock=lambda: _NOW)
        state = reopened._load_state()
        self.assertEqual(state["highest_catalog_revision"], 1)
        self.assertEqual(state["active"]["host"], result.assignment_id)

    def test_three_host_components_share_one_store_and_activate_exact_slots(self):
        installed = {}
        for index, component in enumerate(("worker-1", "worker-2", "worker-3"), 1):
            catalog_bytes, assignment_bytes, retriever = self._install_input(
                component=component, assignment_id=f"asg_{index:032x}")
            installed[component] = self.installer.install(
                catalog_bytes, assignment_bytes, retriever, account_id=_ACCOUNT,
                device_id=_DEVICE, role="host")
        state = self.installer._load_state()
        self.assertEqual(state["host_slots"], {
            name: installed[name].assignment_id for name in installed})
        self.assertEqual(len(state["installations"]), 3)
        self.assertEqual(self.installer._used_bytes(state),
                         sum(item["accounted_bytes"] for item in state["installations"].values()))

        replacement_inputs = self._install_input(
            component="worker-2", assignment_id=f"asg_{'f' * 32}")
        replacement = self.installer.install(
            *replacement_inputs[:2], replacement_inputs[2], account_id=_ACCOUNT,
            device_id=_DEVICE, role="host")
        state = self.installer._load_state()
        self.assertEqual(state["host_slots"]["worker-1"], installed["worker-1"].assignment_id)
        self.assertEqual(state["host_slots"]["worker-2"], replacement.assignment_id)
        self.assertEqual(state["host_slots"]["worker-3"], installed["worker-3"].assignment_id)
        with self.assertRaises(ArtifactInstallError):
            self.installer.remove_installation(installed["worker-1"].assignment_id,
                                               compute_stopped=True)
        with self.assertRaises(ArtifactInstallError):
            self.installer.remove_installation(installed["worker-3"].assignment_id,
                                               compute_stopped=True)
        self.installer.deactivate("host", compute_stopped=True)
        self.assertEqual(set(self.installer._load_state()["host_slots"].values()), {None})

    def test_v1_state_requires_explicit_guarded_migration(self):
        catalog_bytes, assignment_bytes, retriever = self._install_input(
            assignment_id=f"asg_{'a' * 32}")
        result = self.installer.install(catalog_bytes, assignment_bytes, retriever,
                                        account_id=_ACCOUNT, device_id=_DEVICE, role="host")
        state = self.installer._load_state()
        legacy = copy.deepcopy(state)
        legacy["version"] = 1
        legacy.pop("host_slots")
        from steamboat_connector.storage import atomic_write_json
        atomic_write_json(self.root / artifacts_module.INSTALL_STATE_FILENAME, legacy)
        with self.assertRaisesRegex(ArtifactInstallError, "explicit migration"):
            ArtifactInstaller(
                self.root, self.verifier, disk_ceiling_bytes=64 * 1024 * 1024,
                disk_headroom_bytes=16 * 1024 * 1024, wall_clock=lambda: _NOW,
                read_only=True)
        migration_owner = ArtifactInstaller(
            self.root, self.verifier, disk_ceiling_bytes=64 * 1024 * 1024,
            disk_headroom_bytes=16 * 1024 * 1024, wall_clock=lambda: _NOW)
        with self.assertRaisesRegex(ArtifactInstallError, "explicit migration"):
            migration_owner._load_state()
        migrated = migration_owner.migrate_state_v1()
        self.assertEqual(migrated["version"], 2)
        self.assertEqual(migrated["host_slots"]["worker-1"], result.assignment_id)
        self.assertEqual(migrated["highest_catalog_revision"], legacy["highest_catalog_revision"])
        self.assertEqual(migrated["installations"], legacy["installations"])
        self.assertEqual(migrated["reservations"], legacy["reservations"])

    def test_existing_install_revalidates_after_cross_process_lock_wait(self):
        inputs = self._install_input(assignment_id=f"asg_{'1' * 32}")
        installed = self.installer.install(
            *inputs[:2], inputs[2], account_id=_ACCOUNT,
            device_id=_DEVICE, role="host")
        clock = {"now": _NOW + 1799}
        fresh = ArtifactInstaller(
            self.root, self.verifier, disk_ceiling_bytes=64 * 1024 * 1024,
            disk_headroom_bytes=16 * 1024 * 1024, lock_timeout_seconds=3,
            wall_clock=lambda: clock["now"])

        project_root = Path(__file__).resolve().parents[2]
        holder_script = "\n".join((
            "import sys",
            "from pathlib import Path",
            "from steamboat_connector.storage import FileLock",
            "lock = FileLock(Path(sys.argv[1]) / '.artifact-install.lock', timeout=2)",
            "lock.acquire()",
            "print('LOCKED', flush=True)",
            "try:",
            "    sys.stdin.readline()",
            "finally:",
            "    lock.release()",
        ))
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(project_root / "src")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        holder = subprocess.Popen(
            [sys.executable, "-B", "-c", holder_script, str(self.root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=environment)
        install_thread = None
        try:
            ready, _, _ = select.select([holder.stdout], [], [], 2)
            self.assertTrue(ready, "lock-holder subprocess did not acquire its lock")
            self.assertEqual(holder.stdout.readline().strip(), "LOCKED")

            lock_attempted = threading.Event()
            original_locked = fresh._locked

            def observed_lock():
                lock_attempted.set()
                return original_locked()

            fresh._locked = observed_lock
            outcome = {}

            def retry_existing_install():
                try:
                    outcome["result"] = fresh.install(
                        *inputs[:2], inputs[2], account_id=_ACCOUNT,
                        device_id=_DEVICE, role="host")
                except Exception as error:
                    outcome["error"] = error

            install_thread = threading.Thread(target=retry_existing_install)
            install_thread.start()
            self.assertTrue(lock_attempted.wait(timeout=2),
                            "install did not reach the cross-process lock")
            time.sleep(0.05)
            self.assertTrue(install_thread.is_alive(),
                            "install did not remain behind the held process lock")

            clock["now"] = _NOW + 1800
            holder.stdin.write("release\n")
            holder.stdin.flush()
            install_thread.join(timeout=2)
            self.assertFalse(install_thread.is_alive(), "install did not leave the held lock")
            self.assertNotIn("result", outcome)
            self.assertIsInstance(outcome.get("error"), CatalogError)
            self.assertIn("not currently valid", str(outcome["error"]))
            state = self.installer._load_state()
            self.assertEqual(state["active"]["host"], installed.assignment_id)
            self.assertFalse(state["reservations"])
        finally:
            if holder.poll() is None:
                try:
                    holder.stdin.write("release\n")
                    holder.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass
                try:
                    holder.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    holder.terminate()
                    holder.wait(timeout=2)
            if install_thread is not None:
                install_thread.join(timeout=2)

    def test_signed_installed_component_tampering_is_rejected_by_open_view(self):
        inputs = self._install_input(assignment_id=f"asg_{'2' * 32}")
        result = self.installer.install(
            *inputs[:2], inputs[2], account_id=_ACCOUNT,
            device_id=_DEVICE, role="host")
        component = result.path / "worker-1.safetensors"
        with component.open("r+b") as stream:
            original = stream.read(1)
            stream.seek(0)
            stream.write(bytes((original[0] ^ 1,)))
            stream.flush()
            os.fsync(stream.fileno())

        with self.assertRaisesRegex(AssignedArtifactError, "SHA-256 mismatch"):
            self.installer.open_view(
                result.assignment_id, account_id=_ACCOUNT,
                device_id=_DEVICE, role="host", now=_NOW)
        state = self.installer._load_state()
        self.assertEqual(state["active"]["host"], result.assignment_id)
        self.assertTrue(component.is_file())

    def test_interrupted_or_corrupt_replacement_preserves_previous_install(self):
        first_catalog, first_assignment, first_source = self._install_input()
        first = self.installer.install(first_catalog, first_assignment, first_source,
                                       account_id=_ACCOUNT, device_id=_DEVICE, role="host")
        second_catalog, second_assignment, interrupted = self._install_input(
            component="worker-2", assignment_id=f"asg_{'2' * 32}",
            retriever=_MemoryRetriever(
                self.file_bytes, interrupt_after=1,
                interrupt_name="worker-2.safetensors", chunk_bytes=8))
        with self.assertRaises(ArtifactInstallError):
            self.installer.install(second_catalog, second_assignment, interrupted,
                                   account_id=_ACCOUNT, device_id=_DEVICE, role="host")
        self.assertEqual(interrupted.interrupted_at, ("worker-2.safetensors", 8))
        self.assertEqual(interrupted.yielded_bytes["worker-2.safetensors"], 8)
        self.assertLess(interrupted.yielded_bytes["worker-2.safetensors"],
                        len(self.file_bytes["worker-2.safetensors"]))
        state = self.installer._load_state()
        self.assertEqual(state["active"]["host"], first.assignment_id)
        self.assertTrue(first.path.is_dir())
        self.assertFalse(state["reservations"])
        self.assertEqual(list(self.root.glob(".artifact-stage-*")), [])
        self.assertFalse((self.root / f"install-asg_{'2' * 32}").exists())
        corrupt_catalog, corrupt_assignment, corrupt = self._install_input(
            component="worker-3", assignment_id=f"asg_{'3' * 32}",
            retriever=_MemoryRetriever(self.file_bytes, corrupt_name="worker-3.safetensors"))
        with self.assertRaises(ArtifactInstallError):
            self.installer.install(corrupt_catalog, corrupt_assignment, corrupt,
                                   account_id=_ACCOUNT, device_id=_DEVICE, role="host")
        state = self.installer._load_state()
        self.assertEqual(state["active"]["host"], first.assignment_id)
        self.assertTrue(first.path.is_dir())
        self.assertFalse(state["reservations"])
        self.assertEqual(list(self.root.glob(".artifact-stage-*")), [])
        self.assertFalse((self.root / f"install-asg_{'3' * 32}").exists())

    def test_revision_rollback_and_same_revision_equivocation_are_rejected(self):
        high = self._install_input(revision=2, assignment_id=f"asg_{'4' * 32}")
        self.installer.install(*high[:2], high[2], account_id=_ACCOUNT,
                               device_id=_DEVICE, role="host")
        old = self._install_input(revision=1, assignment_id=f"asg_{'5' * 32}")
        with self.assertRaises(ArtifactInstallError):
            self.installer.install(*old[:2], old[2], account_id=_ACCOUNT,
                                   device_id=_DEVICE, role="host")
        changed_payload = _catalog_payload(now=_NOW, revision=2,
                                           file_bytes=self.file_bytes,
                                           source_hashes=self.source_hashes)
        changed_payload["issued_at"] -= 1
        equivocal_catalog = _sign_document(changed_payload, "catalog")
        verified = self.verifier.verify_catalog(equivocal_catalog, now=_NOW)
        equivocal_assignment, _ = _assignment_bundle(
            self.verifier, verified, component="worker-2", assignment_id=f"asg_{'6' * 32}")
        with self.assertRaises(ArtifactInstallError):
            self.installer.install(equivocal_catalog, equivocal_assignment,
                                   _MemoryRetriever(self.file_bytes), account_id=_ACCOUNT,
                                   device_id=_DEVICE, role="host")

    def test_disk_full_consumer_scope_and_unsafe_paths_fail_closed(self):
        inputs = self._install_input()
        with mock.patch("steamboat_connector.artifacts.shutil.disk_usage",
                        return_value=type("Usage", (), {"free": 0})()):
            with self.assertRaises(ArtifactQuotaError):
                self.installer.install(*inputs[:2], inputs[2], account_id=_ACCOUNT,
                                       device_id=_DEVICE, role="host")
        consumer_bytes, _ = _assignment_bundle(
            self.verifier, self.catalog, role="consumer", component=None,
            assignment_id=f"asg_{'7' * 32}")
        with self.assertRaises(ArtifactInstallError):
            self.installer.install(self.catalog_bytes, consumer_bytes, _MemoryRetriever({}),
                                   account_id=_ACCOUNT, device_id=_DEVICE, role="consumer")
        store = Path(self.temp.name) / "store"
        store.mkdir(mode=0o700)
        local = LocalArtifactStoreRetriever(store)
        with self.assertRaises(ArtifactInstallError):
            list(local.iter_chunks("../outside", deadline=10,
                                   max_chunk_bytes=CHUNK_BYTES))

    def test_removal_requires_stopped_inactive_role_and_only_removes_managed_files(self):
        inputs = self._install_input()
        result = self.installer.install(*inputs[:2], inputs[2], account_id=_ACCOUNT,
                                        device_id=_DEVICE, role="host")
        with self.assertRaises(ArtifactInstallError):
            self.installer.remove_installation(result.assignment_id, compute_stopped=True)
        self.installer.deactivate("host", compute_stopped=True)
        self.assertTrue(self.installer.remove_installation(result.assignment_id,
                                                           compute_stopped=True))
        self.assertFalse(result.path.exists())
        state = self.installer._load_state()
        self.assertNotIn(result.assignment_id, state["installations"])

    def test_local_store_refuses_symlink_sources(self):
        store = Path(self.temp.name) / "store"
        store.mkdir(mode=0o700)
        target = Path(self.temp.name) / "outside"
        target.write_bytes(b"outside")
        os.symlink(target, store / "worker-1.safetensors")
        retriever = LocalArtifactStoreRetriever(store)
        with self.assertRaisesRegex(ArtifactInstallError, "source is unavailable"):
            list(retriever.iter_chunks(
                "worker-1.safetensors", deadline=time.monotonic() + 10))

    def test_regular_file_readers_reject_fifo_without_blocking(self):
        project_root = Path(__file__).resolve().parents[2]
        store = Path(self.temp.name) / "fifo-store"
        store.mkdir(mode=0o700)
        fifo = store / "worker-1.safetensors"
        os.mkfifo(fifo, 0o600)
        script = r"""
import os
import sys
import time
from pathlib import Path
from steamboat_connector.artifacts import ArtifactInstallError, LocalArtifactStoreRetriever
from steamboat_connector.storage import StorageError, read_private_file, open_private_directory
from steamboat_runtime.assigned_artifacts import (
    AssignedArtifactError, _read_file, _verify_file, verify_runtime_lock)

root = Path(sys.argv[1])
fifo = root / "worker-1.safetensors"
uid = os.getuid()
directory_fd = open_private_directory(root, uid=uid)
checks = (
    ("local retriever", lambda: list(LocalArtifactStoreRetriever(root, uid=uid).iter_chunks(
        fifo.name, deadline=time.monotonic() + 1)), ArtifactInstallError, "safe regular file"),
    ("private reader", lambda: read_private_file(fifo, uid=uid), StorageError, "regular file"),
    ("assigned reader", lambda: _read_file(directory_fd, fifo.name, 1024, uid),
     AssignedArtifactError, "owner, mode or size"),
    ("assigned verifier", lambda: _verify_file(directory_fd, fifo.name, 0,
     "0" * 64, uid), AssignedArtifactError, "owner, mode or size"),
    ("runtime lock", lambda: verify_runtime_lock(fifo), AssignedArtifactError,
     "bounded regular file"),
)
try:
    for label, operation, error_type, expected in checks:
        started = time.monotonic()
        try:
            operation()
        except error_type as error:
            assert expected in str(error), (label, str(error))
        else:
            raise AssertionError(label + " accepted a FIFO")
        assert time.monotonic() - started < 1, label + " blocked opening a FIFO"
finally:
    os.close(directory_fd)
assert not any(name == "torch" or name.startswith("torch.") for name in sys.modules)
"""
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(project_root / "src")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [sys.executable, "-B", "-c", script, str(store)],
            capture_output=True, text=True, timeout=5, env=environment)
        self.assertEqual(result.returncode, 0,
                         f"FIFO reader subprocess failed: {result.stdout}\n{result.stderr}")

    def test_invalid_chunk_closes_retriever_fd_with_traceback_retained(self):
        source_path = Path(self.temp.name) / "retriever-source"
        source_path.write_bytes(b"source")
        retriever = _DescriptorRetriever(source_path, bytearray(b"invalid"))
        inputs = self._install_input(retriever=retriever)
        open_before = _fd_count()
        retained = []
        try:
            self.installer.install(*inputs[:2], inputs[2], account_id=_ACCOUNT,
                                   device_id=_DEVICE, role="host")
        except ArtifactInstallError as error:
            retained.append(error)
        else:
            self.fail("invalid retriever chunk was accepted")
        self.assertIsNotNone(retained[0].__traceback__)
        self.assertTrue(retriever.closed)
        self.assertEqual(_fd_count(), open_before)

    def test_enospc_after_positive_partial_write_closes_local_source_fd(self):
        store = Path(self.temp.name) / "store"
        store.mkdir(mode=0o700)
        for name in required_artifact_names("host", "worker-1"):
            path = store / name
            path.write_bytes(self.file_bytes[name])
            os.chmod(path, 0o600)
        retriever = LocalArtifactStoreRetriever(store)
        inputs = self._install_input(retriever=retriever)
        original_write = os.write
        partial_write_bytes = 0
        target_write_calls = 0

        def fail_after_partial_write(descriptor, data):
            nonlocal partial_write_bytes, target_write_calls
            target = os.readlink(f"/proc/self/fd/{descriptor}")
            if "/.artifact-stage-" not in target or not target.endswith("/modelmanifest.json"):
                return original_write(descriptor, data)
            target_write_calls += 1
            if target_write_calls == 1:
                written = original_write(descriptor, data[:8])
                partial_write_bytes += written
                return written
            raise OSError(errno.ENOSPC, "injected full disk after partial write")

        open_before = _fd_count()
        retained = []
        with mock.patch.object(artifacts_module.os, "write",
                               side_effect=fail_after_partial_write):
            try:
                self.installer.install(*inputs[:2], inputs[2], account_id=_ACCOUNT,
                                       device_id=_DEVICE, role="host")
            except ArtifactInstallError as error:
                retained.append(error)
            else:
                self.fail("injected ENOSPC did not fail installation")
        self.assertEqual(partial_write_bytes, 8)
        self.assertGreaterEqual(target_write_calls, 2)
        self.assertIsNotNone(retained[0].__traceback__)
        self.assertEqual(_fd_count(), open_before)
        state = self.installer._load_state()
        self.assertFalse(state["reservations"])
        self.assertEqual(list(self.root.glob(".artifact-stage-*")), [])

    def test_open_private_directory_closes_next_fd_when_child_stat_fails(self):
        directory = Path(self.temp.name) / "private-stat-race"
        directory.mkdir(mode=0o700)
        original_stat = os.stat

        def fail_child_stat(path, *args, **kwargs):
            if kwargs.get("dir_fd") is not None:
                raise OSError(errno.ENOENT, "injected child rename race")
            return original_stat(path, *args, **kwargs)

        open_before = _fd_count()
        with mock.patch.object(storage_module.os, "stat", side_effect=fail_child_stat):
            with self.assertRaises(OSError):
                storage_module.open_private_directory(directory)
        self.assertEqual(_fd_count(), open_before)

    def test_atomic_write_closes_directory_fd_when_cleanup_unlink_fails(self):
        target = self.root / "atomic-cleanup-target"
        original_unlink = os.unlink
        writes = []
        unlinks = []
        retained = []
        open_before = _fd_count()

        def fail_write(_descriptor, _data):
            writes.append(True)
            raise OSError(errno.EIO, "injected temporary-file write failure")

        def fail_cleanup_unlink(_path, **_kwargs):
            unlinks.append(True)
            raise OSError(errno.EIO, "injected temporary-file cleanup failure")

        with (mock.patch.object(storage_module.os, "write", side_effect=fail_write),
              mock.patch.object(storage_module.os, "unlink", side_effect=fail_cleanup_unlink)):
            try:
                storage_module.atomic_write_private(target, b"synthetic", uid=os.getuid())
            except OSError as error:
                retained.append(error)
            else:
                self.fail("injected write and cleanup failures did not propagate")

        self.assertEqual(writes, [True])
        self.assertEqual(unlinks, [True])
        self.assertIsNotNone(retained[0].__traceback__)
        frame_names = []
        traceback = retained[0].__traceback__
        while traceback is not None:
            frame_names.append(traceback.tb_frame.f_code.co_name)
            traceback = traceback.tb_next
        self.assertIn("atomic_write_private", frame_names)
        self.assertEqual(_fd_count(), open_before)

        for temporary in self.root.glob(f".{target.name}.*.tmp"):
            original_unlink(temporary)

    def test_concurrent_installs_serialize_and_do_not_oversubscribe(self):
        first = self._install_input(component="worker-1", assignment_id=f"asg_{'8' * 32}")
        second = self._install_input(component="worker-2", assignment_id=f"asg_{'9' * 32}")
        results = []
        errors = []

        def run(inputs):
            try:
                results.append(self.installer.install(
                    inputs[0], inputs[1], inputs[2], account_id=_ACCOUNT,
                    device_id=_DEVICE, role="host"))
            except Exception as error:
                errors.append(error)

        threads = [threading.Thread(target=run, args=(item,)) for item in (first, second)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(len(self.installer._load_state()["installations"]), 2)

    def test_runtime_shared_pin_waiting_on_installer_gate_cannot_deadlock_mutation(self):
        from steamboat_connector import artifact_pin
        gate_held = threading.Event()
        runtime_pinned = threading.Event()
        permit_probe = threading.Event()
        results = []
        failures = []
        original_gate = self.installer._locked

        @contextmanager
        def gate():
            with original_gate():
                if threading.current_thread().name == "fixture-mutator":
                    gate_held.set()
                    if not permit_probe.wait(2):
                        raise RuntimeError("runtime pin barrier timed out")
                yield

        def mutate():
            try:
                with self.installer._mutating():
                    failures.append(AssertionError("mutation crossed a runtime pin"))
            except ArtifactInstallBusy:
                results.append("busy")
            except BaseException as error:
                failures.append(error)

        def runtime():
            descriptor = None
            try:
                descriptor = artifact_pin._lock(
                    self.root, artifact_pin.GLOBAL_LOCK, os.getuid(),
                    artifact_pin.fcntl.LOCK_SH)
                runtime_pinned.set()
                with self.installer._locked():
                    results.append("runtime-verified")
            except BaseException as error:
                failures.append(error)
            finally:
                if descriptor is not None:
                    os.close(descriptor)

        mutator = threading.Thread(target=mutate, name="fixture-mutator")
        reader = threading.Thread(target=runtime, name="fixture-runtime")
        with mock.patch.object(self.installer, "_locked", gate):
            try:
                mutator.start()
                self.assertTrue(gate_held.wait(2))
                reader.start()
                self.assertTrue(runtime_pinned.wait(2))
                permit_probe.set()
                mutator.join(1)
                reader.join(1)
                self.assertFalse(mutator.is_alive())
                self.assertFalse(reader.is_alive())
                self.assertEqual(failures, [])
                self.assertCountEqual(results, ["busy", "runtime-verified"])
            finally:
                permit_probe.set()
                mutator.join(6)
                if reader.ident is not None:
                    reader.join(6)

    def test_failed_commit_preserves_previous_active_install(self):
        first_inputs = self._install_input(assignment_id=f"asg_{'a' * 32}")
        first = self.installer.install(
            *first_inputs[:2], first_inputs[2], account_id=_ACCOUNT,
            device_id=_DEVICE, role="host")
        second_inputs = self._install_input(
            component="worker-2", assignment_id=f"asg_{'b' * 32}")
        original_write = self.installer._write_state
        calls = 0

        def fail_commit_once(state):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ArtifactInstallError("simulated atomic metadata failure")
            return original_write(state)

        with mock.patch.object(self.installer, "_write_state", side_effect=fail_commit_once):
            with self.assertRaises(ArtifactInstallError):
                self.installer.install(
                    *second_inputs[:2], second_inputs[2], account_id=_ACCOUNT,
                    device_id=_DEVICE, role="host")
        state = self.installer._load_state()
        self.assertEqual(state["active"]["host"], first.assignment_id)
        self.assertIn(first.assignment_id, state["installations"])
        self.assertNotIn(f"asg_{'b' * 32}", state["installations"])
        self.assertTrue(first.path.is_dir())
        self.assertFalse((self.root / f"install-asg_{'b' * 32}").exists())
        self.assertFalse(state["reservations"])

    def test_postreplace_commit_failure_preserves_files_and_accounting(self):
        first_inputs = self._install_input(assignment_id=f"asg_{'c' * 32}")
        first = self.installer.install(
            *first_inputs[:2], first_inputs[2], account_id=_ACCOUNT,
            device_id=_DEVICE, role="host")
        second_inputs = self._install_input(
            component="worker-2", assignment_id=f"asg_{'d' * 32}")
        original_write = self.installer._write_state
        calls = 0

        def replace_then_fail_and_arm_second_failure(state):
            nonlocal calls
            calls += 1
            if calls == 2:
                original_write(state)
                raise ArtifactInstallError("injected failure after state replacement and fsync")
            if calls == 3:
                raise ArtifactInstallError("injected second persistence failure")
            return original_write(state)

        with mock.patch.object(self.installer, "_write_state",
                               side_effect=replace_then_fail_and_arm_second_failure):
            with self.assertRaisesRegex(
                    ArtifactInstallError, "after state replacement and fsync"):
                self.installer.install(
                    *second_inputs[:2], second_inputs[2], account_id=_ACCOUNT,
                    device_id=_DEVICE, role="host")
        self.assertEqual(calls, 2)
        reopened = ArtifactInstaller(
            self.root, self.verifier, disk_ceiling_bytes=64 * 1024 * 1024,
            disk_headroom_bytes=16 * 1024 * 1024, wall_clock=lambda: _NOW)
        state = reopened._load_state()
        second_id = f"asg_{'d' * 32}"
        self.assertEqual(state["active"]["host"], second_id)
        self.assertTrue(first.path.is_dir())
        self.assertTrue((self.root / f"install-{second_id}").is_dir())
        self.assertEqual(set(state["installations"]), {first.assignment_id, second_id})
        self.assertFalse(state["reservations"])
        for active_id in state["active"].values():
            if active_id is not None:
                record = state["installations"][active_id]
                self.assertTrue((self.root / record["directory"]).is_dir())

    def test_directory_fsync_failure_after_replace_preserves_uncertain_install(self):
        inputs = self._install_input(assignment_id=f"asg_{'d' * 32}")
        root_directory_fsyncs = 0
        injected_failures = []
        retained = []
        original_fsync = os.fsync
        open_before = _fd_count()

        def fail_commit_directory_fsync(descriptor):
            nonlocal root_directory_fsyncs
            info = os.fstat(descriptor)
            if stat.S_ISDIR(info.st_mode):
                try:
                    opened_path = os.readlink(f"/proc/self/fd/{descriptor}")
                except OSError:
                    opened_path = ""
                if opened_path == str(self.root):
                    root_directory_fsyncs += 1
                    if root_directory_fsyncs == 4:
                        injected_failures.append(True)
                        raise OSError(errno.EIO, "injected post-replace directory fsync failure")
            return original_fsync(descriptor)

        with mock.patch.object(storage_module.os, "fsync",
                               side_effect=fail_commit_directory_fsync):
            try:
                self.installer.install(
                    *inputs[:2], inputs[2], account_id=_ACCOUNT,
                    device_id=_DEVICE, role="host")
            except OSError as error:
                retained.append(error)
            else:
                self.fail("actual post-replace directory fsync failure was not surfaced")

        self.assertEqual(root_directory_fsyncs, 4)
        self.assertEqual(injected_failures, [True])
        self.assertIsNotNone(retained[0].__traceback__)
        self.assertEqual(_fd_count(), open_before)
        assignment_id = f"asg_{'d' * 32}"
        state = self.installer._load_state()
        self.assertEqual(state["active"]["host"], assignment_id)
        self.assertIn(assignment_id, state["installations"])
        self.assertFalse(state["reservations"])
        self.assertTrue((self.root / f"install-{assignment_id}").is_dir())

    def test_atomic_publication_race_preserves_unknown_final_and_reservation(self):
        first_inputs = self._install_input(assignment_id=f"asg_{'c' * 32}")
        first = self.installer.install(
            *first_inputs[:2], first_inputs[2], account_id=_ACCOUNT,
            device_id=_DEVICE, role="host")
        second_inputs = self._install_input(
            component="worker-2", assignment_id=f"asg_{'e' * 32}")
        final_name = f"install-asg_{'e' * 32}"
        original_publish = artifacts_module.publish_directory_noreplace
        raced = {}

        def create_final_then_publish(parent_fd, source_name, destination_name):
            os.mkdir(destination_name, 0o700, dir_fd=parent_fd)
            destination_fd = os.open(
                destination_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd)
            try:
                marker_fd = os.open(
                    "racer-marker", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=destination_fd)
                try:
                    os.write(marker_fd, b"preserve")
                finally:
                    os.close(marker_fd)
                info = os.fstat(destination_fd)
                raced["identity"] = (info.st_dev, info.st_ino)
            finally:
                os.close(destination_fd)
            original_publish(parent_fd, source_name, destination_name)

        with mock.patch.object(artifacts_module, "publish_directory_noreplace",
                               side_effect=create_final_then_publish):
            with self.assertRaisesRegex(ArtifactInstallError, "preserving it and its reservation"):
                self.installer.install(
                    *second_inputs[:2], second_inputs[2], account_id=_ACCOUNT,
                    device_id=_DEVICE, role="host")

        final_path = self.root / final_name
        final_info = final_path.stat()
        self.assertEqual((final_info.st_dev, final_info.st_ino), raced["identity"])
        self.assertEqual((final_path / "racer-marker").read_bytes(), b"preserve")
        state = self.installer._load_state()
        self.assertEqual(state["active"]["host"], first.assignment_id)
        self.assertIn(first.assignment_id, state["installations"])
        self.assertNotIn(f"asg_{'e' * 32}", state["installations"])
        self.assertEqual(len(state["reservations"]), 1)
        reservation = next(iter(state["reservations"].values()))
        self.assertEqual(reservation["final_directory"], final_name)
        expected_bytes = sum(
            self.catalog.payload["files"][name]["size_bytes"]
            for name in required_artifact_names("host", "worker-2"))
        expected_bytes += (len(second_inputs[0]) + len(second_inputs[1])
                           + INSTALL_METADATA_RESERVE_BYTES)
        self.assertEqual(reservation["accounted_bytes"], expected_bytes)
        self.assertFalse((self.root / reservation["stage_directory"]).exists())
        self.assertEqual(list(self.root.glob(".artifact-stage-*")), [])

    def test_recovery_never_removes_an_interrupted_final_directory(self):
        token = "c" * 32
        assignment_id = f"asg_{'d' * 32}"
        final_path = self.root / f"install-{assignment_id}"
        final_path.mkdir(mode=0o700)
        marker = final_path / "unknown"
        marker.write_text("leave untouched", encoding="utf-8")
        state = self.installer._load_state()
        state["reservations"][token] = {
            "stage_directory": ".artifact-stage-" + token,
            "final_directory": f"install-{assignment_id}",
            "accounted_bytes": 1,
        }
        self.installer._write_state(state)
        with self.assertRaises(ArtifactInstallError):
            ArtifactInstaller(
                self.root, self.verifier, disk_ceiling_bytes=64 * 1024 * 1024,
                disk_headroom_bytes=16 * 1024 * 1024, wall_clock=lambda: _NOW)
        self.assertEqual(marker.read_text(encoding="utf-8"), "leave untouched")


class AssignedModelIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux")
                         and os.environ.get("STEAMBOAT_ASSIGNED_TEST_SOURCE")
                         and os.environ.get("STEAMBOAT_ASSIGNED_TEST_SCRATCH"),
                         "parent Linux model gate must provide readonly artifacts and bounded scratch")
    def test_role_scoped_loaders_match_same_stack_forced_logits(self):
        from steamboat_connector.catalog import (MAX_ASSIGNMENT_BYTES_TOTAL,
                                                 RUNTIME_LOCK_SHA256)
        from steamboat_runtime.manifest import load_manifest

        source = Path(os.environ["STEAMBOAT_ASSIGNED_TEST_SOURCE"])
        scratch = Path(os.environ["STEAMBOAT_ASSIGNED_TEST_SCRATCH"])
        manifest = load_manifest(source)
        manifest_path = source / "modelmanifest.json"
        manifest_bytes = manifest_path.read_bytes()
        file_entries = {}
        for filename, digest in manifest["files"].items():
            info = (source / filename).lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            file_entries[filename] = {"sha256": digest, "size_bytes": info.st_size}
        file_entries["modelmanifest.json"] = {
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "size_bytes": len(manifest_bytes),
        }
        components = {
            name: {"file": item["file"], "layer_range": item["layer_range"],
                   "sha256": item["sha256"], "size_bytes": file_entries[item["file"]]["size_bytes"]}
            for name, item in manifest["components"].items()
        }
        now = int(__import__("time").time())
        payload = {
            "schema_version": 1, "catalog_revision": 1, "issued_at": now - 10,
            "expires_at": now + 3600,
            "model": {
                "model_id": MODEL_ID, "model_revision": MODEL_REVISION,
                "tokenizer_revision": MODEL_REVISION, "source_hashes": SOURCE_HASHES,
                "device": "cpu", "dtype": "float32", "attention": "eager",
                "compression": "none", "layout": "batch_sequence_hidden",
                "batch_size": 1, "hidden_size": 64, "vocabulary_size": 32000,
                "layers": 8, "model_context": 2048, "runtime_context": 1152,
                "tied_input_output_weights": False,
            },
            "runtime": {
                "os": "linux", "architecture": "amd64", "python": "3.12.15",
                "torch": "2.14.1+cpu", "transformers": "5.19.0", "grpcio": "1.84.0",
                "protobuf": "7.36.2", "lock_sha256": RUNTIME_LOCK_SHA256,
            },
            "manifest": {"filename": "modelmanifest.json",
                         "fingerprint": manifest["fingerprint"],
                         **file_entries["modelmanifest.json"]},
            "components": components, "files": file_entries,
        }
        catalog_bytes = _sign_document(payload, "catalog")
        verifier = CatalogVerifier(_PUBLIC)
        catalog = verifier.verify_catalog(catalog_bytes, now=now)

        class SourceRetriever:
            def __init__(self):
                self.opened_names = []

            def iter_chunks(self, filename, *, deadline, max_chunk_bytes):
                if filename not in ARTIFACT_FILENAMES:
                    raise ValueError("unapproved source name")
                self.opened_names.append(filename)
                path = source / filename
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("nonregular source file")
                with path.open("rb") as stream:
                    while True:
                        block = stream.read(max_chunk_bytes)
                        if not block:
                            return
                        yield block

        account_id = _ACCOUNT
        device_id = _DEVICE
        assigned_stages = []
        assigned_caches = []
        coordinator = None
        retriever = SourceRetriever()
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            installer = ArtifactInstaller(
                Path(temporary) / "installations", verifier,
                disk_ceiling_bytes=128 * 1024 * 1024,
                disk_headroom_bytes=16 * 1024 * 1024,
                wall_clock=lambda: now)
            for index, component in enumerate(("worker-1", "worker-2", "worker-3"), start=1):
                assignment_id = f"asg_{index:032x}"
                assignment_bytes, _ = _assignment_bundle(
                    verifier, catalog, role="host", component=component, now=now,
                    assignment_id=assignment_id)
                opened_before = len(retriever.opened_names)
                result = installer.install(catalog_bytes, assignment_bytes, retriever,
                                           account_id=account_id, device_id=device_id, role="host")
                required_names = required_artifact_names("host", component)
                self.assertEqual(retriever.opened_names[opened_before:], list(required_names))
                view = installer.open_view(result.assignment_id, account_id=account_id,
                                           device_id=device_id, role="host", now=now)
                expected_names = set(required_names) | {
                    "signed-catalog.json", "signed-assignment.json"}
                self.assertEqual({path.name for path in result.path.iterdir()}, expected_names)
                with self.assertRaises(ValueError):
                    load_manifest(result.path)

                component_path = result.path / f"{component}.safetensors"
                with component_path.open("r+b") as stream:
                    original_byte = stream.read(1)
                    stream.seek(0)
                    stream.write(bytes((original_byte[0] ^ 1,)))
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    with mock.patch("safetensors.torch.load_file",
                                    side_effect=AssertionError(
                                        "corrupt assigned file reached tensor materialization")) as loader:
                        with self.assertRaises(AssignedArtifactError):
                            view.load_stage()
                        loader.assert_not_called()
                finally:
                    with component_path.open("r+b") as stream:
                        stream.seek(0)
                        stream.write(original_byte)
                        stream.flush()
                        os.fsync(stream.fileno())

                from safetensors.torch import load_file as real_load_file

                loaded_names = []

                def record_loaded_file(path, *args, **kwargs):
                    loaded_names.append(Path(path).name)
                    return real_load_file(path, *args, **kwargs)

                with mock.patch("safetensors.torch.load_file",
                                side_effect=record_loaded_file):
                    assigned_stages.append(view.load_stage())
                self.assertEqual(loaded_names, [f"{component}.safetensors"])
                assigned_caches.append(view.new_layer_cache())
            assignment_bytes, _ = _assignment_bundle(
                verifier, catalog, role="coordinator", component="coordinator", now=now,
                assignment_id=f"asg_{'a' * 32}")
            opened_before = len(retriever.opened_names)
            coordinator_result = installer.install(
                catalog_bytes, assignment_bytes, retriever, account_id=account_id,
                device_id=device_id, role="coordinator")
            coordinator_names = required_artifact_names("coordinator", "coordinator")
            self.assertEqual(retriever.opened_names[opened_before:], list(coordinator_names))
            self.assertEqual({path.name for path in coordinator_result.path.iterdir()},
                             set(coordinator_names) | {
                                 "signed-catalog.json", "signed-assignment.json"})
            with self.assertRaises(ValueError):
                load_manifest(coordinator_result.path)
            coordinator_view = installer.open_view(
                coordinator_result.assignment_id, account_id=account_id,
                device_id=device_id, role="coordinator", now=now)
            self.assertFalse(any(name.startswith("worker-") and name.endswith(".safetensors")
                                 for name in (path.name for path in coordinator_result.path.iterdir())))
            from safetensors.torch import load_file as real_load_file

            loaded_coordinator_names = []

            def record_coordinator_file(path, *args, **kwargs):
                loaded_coordinator_names.append(Path(path).name)
                return real_load_file(path, *args, **kwargs)

            with mock.patch("safetensors.torch.load_file",
                            side_effect=record_coordinator_file):
                coordinator = coordinator_view.load_coordinator_model()
            self.assertEqual(loaded_coordinator_names, ["coordinator.safetensors"])
            from steamboat_runtime.model import PipelineModel
            import torch

            reference = PipelineModel(source)
            reference_session = reference.open_session(16)
            position = 0
            sequence = (torch.tensor([[1, 17, 19]], dtype=torch.long),
                        torch.tensor([[23]], dtype=torch.long),
                        torch.tensor([[31]], dtype=torch.long))
            try:
                for input_ids in sequence:
                    expected = reference_session.step(input_ids)
                    with torch.inference_mode():
                        hidden = coordinator.input_output.embed_tokens(input_ids)
                        for stage, cache in zip(assigned_stages, assigned_caches):
                            hidden = stage(hidden, cache, position)
                        actual = coordinator.input_output.lm_head(
                            coordinator.input_output.norm(hidden[:, -1:, :]))
                    torch.testing.assert_close(actual, expected, atol=1e-3, rtol=0)
                    position += input_ids.shape[1]
            finally:
                reference_session.close()
                asyncio.run(coordinator.close(timeout_seconds=1))
        self._assert_signed_header_rejections(source, scratch, manifest, now)

    @unittest.skipUnless(sys.platform.startswith("linux")
                         and os.environ.get("STEAMBOAT_ASSIGNED_TEST_SOURCE")
                         and os.environ.get("STEAMBOAT_ASSIGNED_TEST_SCRATCH"),
                         "parent Linux model gate must provide readonly artifacts and bounded scratch")
    def test_assigned_executor_worker_handlers_preserve_interleaved_session_logits(self):
        """Drive the real adapter, WorkerHandler and tensor wire codec on pinned weights."""
        from steamboat_connector.catalog import RUNTIME_LOCK_SHA256
        from steamboat_connector.artifact_pin import RuntimeArtifactPin
        from steamboat_runtime.assigned_executor import build_assigned_worker_handler
        from steamboat_runtime.manifest import load_manifest
        from steamboat_runtime.model import PipelineModel
        from steamboat_runtime.protocol.codec import decode_tensor, encode_tensor
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_security.clock import Clock
        import torch

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
            "size_bytes": len(manifest_bytes),
        }
        components = {
            name: {"file": item["file"], "layer_range": item["layer_range"],
                   "sha256": item["sha256"],
                   "size_bytes": file_entries[item["file"]]["size_bytes"]}
            for name, item in manifest["components"].items()
        }
        catalog_payload = {
            "schema_version": 1, "catalog_revision": 1,
            "issued_at": now - 10, "expires_at": now + 3600,
            "model": {
                "model_id": MODEL_ID, "model_revision": MODEL_REVISION,
                "tokenizer_revision": MODEL_REVISION, "source_hashes": SOURCE_HASHES,
                "device": "cpu", "dtype": "float32", "attention": "eager",
                "compression": "none", "layout": "batch_sequence_hidden",
                "batch_size": 1, "hidden_size": 64, "vocabulary_size": 32000,
                "layers": 8, "model_context": 2048, "runtime_context": 1152,
                "tied_input_output_weights": False,
            },
            "runtime": {
                "os": "linux", "architecture": "amd64", "python": "3.12.15",
                "torch": "2.14.1+cpu", "transformers": "5.19.0",
                "grpcio": "1.84.0", "protobuf": "7.36.2",
                "lock_sha256": RUNTIME_LOCK_SHA256,
            },
            "manifest": {"filename": "modelmanifest.json",
                         "fingerprint": manifest["fingerprint"],
                         **file_entries["modelmanifest.json"]},
            "components": components, "files": file_entries,
        }
        catalog_bytes = _sign_document(catalog_payload, "catalog")
        # This isolated numerical fixture assumes an accurate test clock. It
        # does not establish an operator clock source for participant readiness.
        verifier = CatalogVerifier(_PUBLIC,
            clock=Clock(uncertainty_seconds=lambda: 0.0))

        class SourceRetriever:
            def iter_chunks(self, filename, *, deadline, max_chunk_bytes):
                if filename not in ARTIFACT_FILENAMES:
                    raise ValueError("unapproved source artifact")
                path = source / filename
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise ValueError("source artifact is not a regular file")
                with path.open("rb") as stream:
                    while True:
                        block = stream.read(max_chunk_bytes)
                        if not block:
                            return
                        yield block

        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            handlers = []
            pins = []
            exercise_started = False
            handlers_stopped = False
            reference = PipelineModel(source)
            reference_sessions = {
                "session-A": reference.open_session(16),
                "session-B": reference.open_session(16),
            }
            try:
                for index, component in enumerate(
                        ("worker-1", "worker-2", "worker-3"), start=1):
                    device_id = f"dev_{index:032x}"
                    assignment_id = f"asg_{index:032x}"
                    current_catalog = verifier.verify_catalog(catalog_bytes, now=now)
                    assignment_bytes, _ = _assignment_bundle(
                        verifier, current_catalog, role="host", component=component,
                        now=now, assignment_id=assignment_id, device_id=device_id)
                    installer = ArtifactInstaller(
                        Path(temporary) / component, verifier,
                        disk_ceiling_bytes=128 * 1024 * 1024,
                        disk_headroom_bytes=16 * 1024 * 1024,
                        wall_clock=lambda: now)
                    installer.install(catalog_bytes, assignment_bytes, SourceRetriever(),
                        account_id=_ACCOUNT, device_id=device_id, role="host")
                    view = installer.open_view(assignment_id, account_id=_ACCOUNT,
                        device_id=device_id, role="host", now=now)
                    pin = RuntimeArtifactPin.acquire(
                        view, clock=verifier.clock, boot_id=f"{index:032x}")
                    try:
                        handler = build_assigned_worker_handler(
                            view, boot_id=f"{index:032x}", clock=verifier.clock,
                            pin=pin)
                    except BaseException:
                        pin.release()
                        raise
                    pins.append(pin)
                    handlers.append(handler)

                leases = {}
                sequences = {(component, session): 0
                    for component in ("worker-1", "worker-2", "worker-3")
                    for session in reference_sessions}
                positions = {session: 0 for session in reference_sessions}

                async def call(method, handler, session_id, **fields):
                    request_fields = {
                        "protocol_version": 1,
                        "manifest_fingerprint": handler.manifest["fingerprint"],
                        "worker_boot_id": handler.boot_id,
                        "session_id": session_id,
                        "lease_token": leases.get((handler.worker_name, session_id), ""),
                        "timeout_ms": handler.limits["rpc_timeout_seconds"] * 1000,
                    }
                    request_fields.update(fields)
                    request = Request(**request_fields)
                    return await handler.handle(method, request)

                async def exercise():
                    nonlocal handlers_stopped
                    try:
                        for handler in handlers:
                            for session_id in reference_sessions:
                                opened = await call("OpenSession", handler, session_id,
                                    lease_token="", max_positions=16,
                                    lifetime_ms=300000, idle_lease_ms=120000)
                                self.assertEqual(opened.code, "OK", opened.message)
                                leases[(handler.worker_name, session_id)] = opened.lease_token

                        events = (("session-A", (1, 17, 19)),
                                  ("session-B", (5, 7)),
                                  ("session-A", (23,)),
                                  ("session-B", (29,)),
                                  ("session-A", (31,)),
                                  ("session-B", (37,)))
                        for session_id, token_values in events:
                            input_ids = torch.tensor([token_values], dtype=torch.long)
                            expected = reference_sessions[session_id].step(input_ids)
                            with torch.inference_mode():
                                hidden = reference.input_output.embed_tokens(input_ids)
                            for handler in handlers:
                                component = handler.worker_name
                                count = len(token_values)
                                encoded = encode_tensor(hidden, hidden_size=64,
                                    max_tokens=handler.limits["max_positions"],
                                    max_bytes=handler.limits["max_message_bytes"])
                                response = await call("Step", handler, session_id,
                                    sequence=sequences[(component, session_id)],
                                    start_position=positions[session_id],
                                    token_count=count, tensor=encoded)
                                self.assertEqual(response.code, "OK", response.message)
                                hidden = decode_tensor(response.tensor, count,
                                    hidden_size=64,
                                    max_tokens=handler.limits["max_positions"],
                                    max_bytes=handler.limits["max_message_bytes"])
                                sequences[(component, session_id)] += 1
                            with torch.inference_mode():
                                actual = reference.input_output.lm_head(
                                    reference.input_output.norm(hidden[:, -1:, :]))
                            torch.testing.assert_close(actual, expected, atol=1e-3, rtol=0)
                            positions[session_id] += len(token_values)

                        for handler in handlers:
                            for closed_count, session_id in enumerate(reference_sessions, start=1):
                                closed = await call("CloseSession", handler, session_id)
                                self.assertEqual(closed.code, "OK", closed.message)
                                self.assertTrue(closed.reclaimed)
                                described = await call("Describe", handler, "")
                                remaining = len(reference_sessions) - closed_count
                                self.assertEqual(described.active_sessions, remaining)
                                if remaining:
                                    self.assertGreater(described.allocated_cache_bytes, 0)
                                else:
                                    self.assertEqual(described.allocated_cache_bytes, 0)
                    finally:
                        shutdowns = await asyncio.gather(
                            *(handler.shutdown() for handler in handlers),
                            return_exceptions=False)
                        self.assertTrue(all(result is True for result in shutdowns))
                        handlers_stopped = True

                exercise_started = True
                asyncio.run(exercise())
            finally:
                if handlers and not exercise_started:
                    async def shutdown_unstarted_handlers():
                        nonlocal handlers_stopped
                        shutdowns = await asyncio.gather(
                            *(handler.shutdown() for handler in handlers),
                            return_exceptions=True)
                        self.assertTrue(all(result is True for result in shutdowns))
                        handlers_stopped = True
                    asyncio.run(shutdown_unstarted_handlers())
                if handlers_stopped:
                    for pin in pins:
                        pin.release()
                for session in reference_sessions.values():
                    session.close()

    def _assert_signed_header_rejections(self, source, scratch, manifest, now):
        from steamboat_runtime.manifest import fingerprint, validate_manifest

        component = "worker-1"
        filename = f"{component}.safetensors"
        for variant in ("keys", "shape", "dtype"):
            with self.subTest(header_variant=variant):
                malformed_bytes = _safetensors_bytes(
                    manifest["components"][component]["tensors"], variant)
                malformed_manifest = copy.deepcopy(manifest)
                digest = hashlib.sha256(malformed_bytes).hexdigest()
                malformed_manifest["files"][filename] = digest
                malformed_manifest["components"][component]["sha256"] = digest
                malformed_manifest["fingerprint"] = fingerprint(malformed_manifest)
                validate_manifest(malformed_manifest)
                manifest_bytes = json_bytes(malformed_manifest)
                file_bytes = {
                    "modelmanifest.json": manifest_bytes,
                    "config.json": (source / "config.json").read_bytes(),
                    filename: malformed_bytes,
                }
                payload = _catalog_payload(now=now, file_bytes=file_bytes)
                payload["manifest"]["fingerprint"] = malformed_manifest["fingerprint"]
                catalog_bytes = _sign_document(payload, "catalog")
                verifier = CatalogVerifier(_PUBLIC)
                catalog = verifier.verify_catalog(catalog_bytes, now=now)
                assignment_id = f"asg_{'f' * 31}{('1' if variant == 'keys' else '2' if variant == 'shape' else '3')}"
                assignment_bytes, _ = _assignment_bundle(
                    verifier, catalog, role="host", component=component, now=now,
                    assignment_id=assignment_id)
                directory = Path(tempfile.mkdtemp(dir=scratch))
                try:
                    os.chmod(directory, 0o700)
                    for name, data in (
                            ("modelmanifest.json", manifest_bytes),
                            ("config.json", file_bytes["config.json"]),
                            (filename, malformed_bytes),
                            ("signed-catalog.json", catalog_bytes),
                            ("signed-assignment.json", assignment_bytes)):
                        path = directory / name
                        path.write_bytes(data)
                        os.chmod(path, 0o600)
                    record = {"role": "host", "component": component}
                    state = {"installations": {assignment_id: record},
                             "active": {"host": assignment_id, "coordinator": None},
                             "host_slots": {name: assignment_id if name == component else None
                                            for name in ("worker-1", "worker-2", "worker-3")}}
                    installer = SimpleNamespace(
                        _locked=lambda: nullcontext(),
                        _load_state=lambda: state,
                        wall_clock=lambda: now,
                        verifier=verifier,
                        uid=os.getuid(),
                        runtime_lock_path=assigned_artifacts_module.default_runtime_lock_path(),
                    )
                    view = AssignedArtifactView(
                        installer, assignment_id, account_id=_ACCOUNT,
                        device_id=_DEVICE, role="host", now=now)
                    verified_hashes = []

                    def verify_signed_scope(_state, _record):
                        current_catalog = verifier.verify_catalog(catalog_bytes, now=now)
                        current_assignment = verifier.verify_assignment(
                            assignment_bytes, current_catalog, account_id=_ACCOUNT,
                            device_id=_DEVICE, role="host", now=now)
                        directory_fd = os.open(
                            directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                        try:
                            entry = current_catalog.payload["files"][filename]
                            assigned_artifacts_module._verify_file(
                                directory_fd, filename, entry["size_bytes"],
                                entry["sha256"], os.getuid())
                        finally:
                            os.close(directory_fd)
                        verified_hashes.append(filename)
                        view.catalog = current_catalog
                        view.assignment = current_assignment
                        view.directory = directory
                        return malformed_manifest

                    view._verify_unlocked = verify_signed_scope
                    with (mock.patch("safetensors.torch.load_file",
                                     side_effect=AssertionError(
                                         "malformed signed tensor header reached load_file")) as loader,
                          mock.patch("steamboat_runtime.model.LayerStage") as stage_constructor):
                        with self.assertRaisesRegex(
                                AssignedArtifactError,
                                "tensor inventory|shape or dtype"):
                            view.load_stage()
                    self.assertEqual(verified_hashes, [filename])
                    loader.assert_not_called()
                    stage_constructor.assert_not_called()
                finally:
                    shutil.rmtree(directory)


if __name__ == "__main__":
    unittest.main()
