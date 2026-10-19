"""Selective loaders for a signed, role-scoped v1 artifact installation.

This module deliberately imports no model framework at import time. It does not
change the full-inventory guarantees of ``manifest.load_manifest``.
"""

import importlib.metadata
import hashlib
import os
from pathlib import Path
import platform
import stat
import sys

from steamboat_connector.catalog import (CONFIG_MAX_BYTES, MANIFEST_MAX_BYTES,
                                         RUNTIME_LOCK_SHA256, CatalogError,
                                         required_artifact_names)
from steamboat_connector.storage import open_private_directory
from steamboat_connector.validation import json_bytes, strict_json_loads

from .manifest import (MODEL_ID, MODEL_REVISION, SOURCE_HASHES, expected_tensors,
                       validate_config, validate_manifest)


MAX_LOCK_FILE_BYTES = 1024 * 1024
_EXECUTION_DISTRIBUTIONS = {
    "torch": "2.14.1+cpu",
    "transformers": "5.19.0",
    "safetensors": "0.8.0",
    "grpcio": "1.84.0",
    "protobuf": "7.36.2",
}
_MANIFEST_FIELDS = {
    "schema_version", "model_id", "revision", "architecture", "dtype", "device",
    "attention", "layout", "config", "limits", "source_files", "components", "files",
    "fingerprint",
}


class AssignedArtifactError(ValueError):
    pass


def _verify_execution_runtime_metadata():
    if (sys.platform != "linux" or platform.system() != "Linux"
            or platform.machine().lower() not in {"x86_64", "amd64"}
            or platform.python_implementation() != "CPython"
            or platform.python_version() != "3.12.15"):
        raise AssignedArtifactError("assigned model loading requires the pinned CPython Linux/amd64 runtime")
    try:
        actual = {name: importlib.metadata.version(name)
                  for name in _EXECUTION_DISTRIBUTIONS}
    except (importlib.metadata.PackageNotFoundError, ValueError) as error:
        raise AssignedArtifactError("a pinned assigned-model runtime distribution is unavailable") from error
    if actual != _EXECUTION_DISTRIBUTIONS:
        raise AssignedArtifactError("installed assigned-model runtime versions differ from the C0 CPU stack")
    return actual


def _verify_loaded_torch_cpu(torch):
    version = getattr(torch, "version", None)
    if (getattr(torch, "__version__", None) != _EXECUTION_DISTRIBUTIONS["torch"]
            or getattr(version, "cuda", None) is not None
            or getattr(version, "hip", None) is not None):
        raise AssignedArtifactError("assigned model loading requires the pinned CPU-only PyTorch build")
    cuda = getattr(torch, "cuda", None)
    if cuda is not None and cuda.is_available():
        raise AssignedArtifactError("CUDA is unsupported by assigned CPU model loading")


def default_runtime_lock_path():
    return Path(__file__).resolve().parents[2] / "docker" / "pytorch" / "requirements.lock"


def verify_runtime_lock(path=None):
    target = Path(path) if path is not None else default_runtime_lock_path()
    descriptor = None
    try:
        descriptor = os.open(
            target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0))
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_LOCK_FILE_BYTES:
            raise AssignedArtifactError("runtime lock is not a bounded regular file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    except OSError as error:
        raise AssignedArtifactError("pinned CPU runtime lock is unavailable") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if digest.hexdigest() != RUNTIME_LOCK_SHA256:
        raise AssignedArtifactError("runtime lock differs from the accepted C0 GitLF identity")
    return digest.hexdigest()


class AssignedArtifactView:
    def __init__(self, installer, assignment_id, *, account_id, device_id, role, now=None):
        self.installer = installer
        self.assignment_id = assignment_id
        self.account_id = account_id
        self.device_id = device_id
        self.role = role
        self._initial_now = now
        self.catalog = None
        self.assignment = None
        self.manifest = None
        self.directory = None
        self._verify_runtime_identity()

    def _verify_runtime_identity(self):
        verify_runtime_lock(self.installer.runtime_lock_path)

    def _clock_now(self):
        if self._initial_now is not None:
            now = self._initial_now
            self._initial_now = None
            return now
        return self.installer.wall_clock()

    def _verify_current_expiry(self):
        now = self.installer.wall_clock()
        try:
            catalog = self.installer.verifier.verify_catalog(
                self.catalog.document_bytes, now=now)
            assignment = self.installer.verifier.verify_assignment(
                self.assignment.document_bytes, catalog,
                account_id=self.account_id, device_id=self.device_id,
                role=self.role, now=now)
        except CatalogError as error:
            raise AssignedArtifactError(
                "installed catalog or assignment expired or became invalid before model loading") from error
        self.catalog = catalog
        self.assignment = assignment

    def _verify_unlocked(self, state, record):
        if self.role not in {"host", "coordinator"}:
            raise AssignedArtifactError("consumer roles do not load model artifacts")
        active_id = (state["host_slots"].get(record.get("component"))
                     if self.role == "host" and type(state.get("host_slots")) is dict
                     else state["active"].get(self.role))
        if (record["role"] != self.role
                or active_id != self.assignment_id
                or state["installations"].get(self.assignment_id) != record):
            raise AssignedArtifactError("assignment is not the active role installation")
        directory = self.installer.root / record["directory"]
        directory_fd = open_private_directory(directory, uid=self.installer.uid)
        try:
            expected_names = set(record["files"])
            if set(os.listdir(directory_fd)) != expected_names:
                raise AssignedArtifactError("installed artifact file scope is incomplete or contains extras")
            catalog_bytes = _read_file(directory_fd, "signed-catalog.json", 128 * 1024,
                                       self.installer.uid)
            assignment_bytes = _read_file(directory_fd, "signed-assignment.json", 16 * 1024,
                                          self.installer.uid)
            now = self._clock_now()
            catalog = self.installer.verifier.verify_catalog(catalog_bytes, now=now)
            assignment = self.installer.verifier.verify_assignment(
                assignment_bytes, catalog, account_id=self.account_id,
                device_id=self.device_id, role=self.role, now=now)
            if assignment.payload["assignment_id"] != self.assignment_id:
                raise AssignedArtifactError("installed assignment identity mismatch")
            if (catalog.payload["catalog_revision"] != state["highest_catalog_revision"]
                    or catalog.document_sha256 != state["highest_catalog_sha256"]
                    or catalog.document_sha256 != record["catalog_sha256"]
                    or assignment.document_sha256 != record["assignment_sha256"]
                    or assignment.payload["manifest_fingerprint"] != record["manifest_fingerprint"]):
                raise AssignedArtifactError("installed catalog does not match persistent anti-rollback state")
            component = assignment.payload["component"]
            if record["component"] != component:
                raise AssignedArtifactError("installed component differs from signed assignment")
            if self.role == "host" and state["host_slots"].get(component) != self.assignment_id:
                raise AssignedArtifactError("host assignment is not active in its signed component slot")
            names = required_artifact_names(self.role, component)
            if record["files"] != sorted(set(names) | {
                    "signed-catalog.json", "signed-assignment.json"}):
                raise AssignedArtifactError("installed files exceed the signed role scope")
            catalog_files = catalog.payload["files"]
            for name in names:
                expected = catalog_files[name]
                _verify_file(directory_fd, name, expected["size_bytes"],
                             expected["sha256"], self.installer.uid)
            manifest_entry = catalog.payload["manifest"]
            manifest_bytes = _read_file(directory_fd, "modelmanifest.json",
                                        MANIFEST_MAX_BYTES, self.installer.uid)
            if (len(manifest_bytes) != manifest_entry["size_bytes"]
                    or hashlib.sha256(manifest_bytes).hexdigest() != manifest_entry["sha256"]):
                raise AssignedArtifactError("global runtime manifest hash or size mismatch")
            try:
                manifest = strict_json_loads(manifest_bytes, maximum_bytes=MANIFEST_MAX_BYTES)
                if type(manifest) is not dict or set(manifest) != _MANIFEST_FIELDS:
                    raise AssignedArtifactError("global runtime manifest fields are unsupported")
                validate_manifest(manifest)
            except (TypeError, ValueError, UnicodeError) as error:
                if isinstance(error, AssignedArtifactError):
                    raise
                raise AssignedArtifactError("global v1 runtime manifest is invalid") from error
            if (manifest["model_id"] != MODEL_ID or manifest["revision"] != MODEL_REVISION
                    or manifest["fingerprint"] != manifest_entry["fingerprint"]
                    or manifest["fingerprint"] != assignment.payload["manifest_fingerprint"]):
                raise AssignedArtifactError("global model or manifest fingerprint mismatch")
            for component_name, catalog_component in catalog.payload["components"].items():
                runtime_component = manifest["components"][component_name]
                if (runtime_component["file"] != catalog_component["file"]
                        or runtime_component["layer_range"] != catalog_component["layer_range"]
                        or runtime_component["sha256"] != catalog_component["sha256"]):
                    raise AssignedArtifactError("signed catalog component identity/range mismatch")
            for filename, expected_hash in manifest["files"].items():
                catalog_entry = catalog_files[filename]
                if catalog_entry["sha256"] != expected_hash:
                    raise AssignedArtifactError("catalog inventory differs from the global manifest")
            config_bytes = _read_file(directory_fd, "config.json", CONFIG_MAX_BYTES,
                                      self.installer.uid)
            config = strict_json_loads(config_bytes, maximum_bytes=CONFIG_MAX_BYTES)
            validate_config(config)
            if (hashlib.sha256(config_bytes).hexdigest() != SOURCE_HASHES["config.json"]
                    or json_bytes(config) != json_bytes(manifest["config"])):
                raise AssignedArtifactError("pinned model config differs from the global manifest")
        except CatalogError as error:
            raise AssignedArtifactError("installed catalog or assignment is not currently trusted") from error
        finally:
            os.close(directory_fd)
        self.catalog = catalog
        self.assignment = assignment
        self.manifest = manifest
        self.directory = directory
        return manifest

    def _locked_manifest(self):
        with self.installer._locked():
            state = self.installer._load_state()
            record = state["installations"].get(self.assignment_id)
            if record is None:
                raise AssignedArtifactError("approved assignment installation is missing")
            return self._verify_unlocked(state, record)

    def load_stage(self):
        if self.role != "host":
            raise AssignedArtifactError("only a host assignment can load a worker stage")
        with self.installer._locked():
            state = self.installer._load_state()
            record = state["installations"].get(self.assignment_id)
            if record is None:
                raise AssignedArtifactError("approved assignment installation is missing")
            manifest = self._verify_unlocked(state, record)
            _verify_execution_runtime_metadata()
            import torch
            _verify_loaded_torch_cpu(torch)
            from safetensors import safe_open
            from safetensors.torch import load_file
            from transformers import LlamaConfig
            from .model import LayerStage

            component = self.assignment.payload["component"]
            start, end = manifest["components"][component]["layer_range"]
            config = LlamaConfig.from_dict(manifest["config"])
            config._attn_implementation = "eager"
            path = self.directory / f"{component}.safetensors"
            _verify_safetensors_header(path, component)
            self._verify_current_expiry()
            weights = load_file(str(path), device="cpu")
            if any(tensor.device.type != "cpu" or tensor.dtype != torch.float32
                   or not bool(torch.isfinite(tensor).all()) for tensor in weights.values()):
                raise AssignedArtifactError("assigned safetensors are not finite CPU float32")
            return LayerStage(config, start, end, weights)

    def new_layer_cache(self):
        if self.role != "host":
            raise AssignedArtifactError("only a host assignment owns a worker cache")
        with self.installer._locked():
            state = self.installer._load_state()
            record = state["installations"].get(self.assignment_id)
            if record is None:
                raise AssignedArtifactError("approved assignment installation is missing")
            manifest = self._verify_unlocked(state, record)
            _verify_execution_runtime_metadata()
            import torch
            _verify_loaded_torch_cpu(torch)
            from .model import LayerCache

            start, end = manifest["components"][self.assignment.payload["component"]]["layer_range"]
            self._verify_current_expiry()
            return LayerCache(start, end)

    def load_coordinator_model(self):
        if self.role != "coordinator":
            raise AssignedArtifactError("only a coordinator assignment can load the model head")
        with self.installer._locked():
            state = self.installer._load_state()
            record = state["installations"].get(self.assignment_id)
            if record is None:
                raise AssignedArtifactError("approved assignment installation is missing")
            manifest = self._verify_unlocked(state, record)
            _verify_execution_runtime_metadata()
            import torch
            _verify_loaded_torch_cpu(torch)
            from safetensors.torch import load_file
            from safetensors import safe_open
            from transformers import AutoTokenizer, LlamaConfig
            from .coordinator_model import CoordinatorModel
            from .model import InputOutput

            config = LlamaConfig.from_dict(manifest["config"])
            config._attn_implementation = "eager"
            path = self.directory / "coordinator.safetensors"
            _verify_safetensors_header(path, "coordinator")
            self._verify_current_expiry()
            weights = load_file(str(path), device="cpu")
            if any(tensor.device.type != "cpu" or tensor.dtype != torch.float32
                   or not bool(torch.isfinite(tensor).all()) for tensor in weights.values()):
                raise AssignedArtifactError("assigned coordinator weights are not finite CPU float32")
            input_output = InputOutput(config, weights)
            tokenizer = AutoTokenizer.from_pretrained(
                str(self.directory), local_files_only=True, trust_remote_code=False)
            if len(tokenizer) != config.vocab_size:
                raise AssignedArtifactError("tokenizer vocabulary differs from the pinned model")
            return CoordinatorModel(manifest, input_output, tokenizer)


def _read_file(directory_fd, filename, maximum_bytes, uid):
    try:
        descriptor = os.open(
            filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd)
    except OSError as error:
        raise AssignedArtifactError("assigned file is unavailable or a symlink") from error
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > maximum_bytes):
            raise AssignedArtifactError("assigned file owner, mode or size is invalid")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise AssignedArtifactError("assigned file exceeds its read bound")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _verify_file(directory_fd, filename, expected_size, expected_hash, uid):
    try:
        descriptor = os.open(
            filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd)
    except OSError as error:
        raise AssignedArtifactError("assigned artifact is unavailable or a symlink") from error
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != expected_size):
            raise AssignedArtifactError("assigned artifact owner, mode or size mismatch")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > expected_size:
                raise AssignedArtifactError("assigned artifact grew during verification")
            digest.update(chunk)
        if total != expected_size or digest.hexdigest() != expected_hash:
            raise AssignedArtifactError("assigned artifact SHA-256 mismatch")
    finally:
        os.close(descriptor)


def _verify_safetensors_header(path, component):
    from safetensors import safe_open

    expected = expected_tensors(component)
    try:
        with safe_open(str(path), framework="pt", device="cpu") as artifact:
            if set(artifact.keys()) != set(expected):
                raise AssignedArtifactError("safetensors tensor inventory differs from the assigned component")
            for name, specification in expected.items():
                tensor_slice = artifact.get_slice(name)
                if (tensor_slice.get_shape() != specification["shape"]
                        or tensor_slice.get_dtype() != specification["dtype"]):
                    raise AssignedArtifactError("safetensors header shape or dtype is incompatible")
    except AssignedArtifactError:
        raise
    except Exception as error:
        raise AssignedArtifactError("assigned safetensors header is invalid") from error
