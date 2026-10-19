"""Closed C2.3 catalog and assignment verification for the pinned CPU runtime."""

from dataclasses import dataclass
import hashlib
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from steamboat_runtime.manifest import LAYER_RANGES, MODEL_ID, MODEL_REVISION, SOURCE_HASHES

from .validation import json_bytes, strict_json_loads, valid_typed_id


CATALOG_SCHEMA_VERSION = 1
ASSIGNMENT_SCHEMA_VERSION = 1
SIGNATURE_SCHEME = "ecdsa-p256-sha256-raw-low-s-v1"
RUNTIME_LOCK_SHA256 = "0d893300099241375c9ef032268e162ff6ef46fe93cce1bbe6457bfd01545434"
MAX_CATALOG_BYTES = 128 * 1024
MAX_ASSIGNMENT_BYTES = 16 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_ASSIGNMENT_BYTES_TOTAL = 64 * 1024 * 1024
MAX_CATALOG_LIFETIME_SECONDS = 30 * 24 * 60 * 60
MANIFEST_MAX_BYTES = 256 * 1024
CONFIG_MAX_BYTES = 64 * 1024
CHUNK_BYTES = 64 * 1024
MAX_FILE_CHUNKS = (MAX_FILE_BYTES + CHUNK_BYTES - 1) // CHUNK_BYTES
TOKENIZER_FILES = tuple(name for name in SOURCE_HASHES
                        if name not in {"model.safetensors", "config.json"})
ASSIGNABLE_COMPONENTS = {
    "coordinator": None,
    "worker-1": list(LAYER_RANGES[0]),
    "worker-2": list(LAYER_RANGES[1]),
    "worker-3": list(LAYER_RANGES[2]),
}
ARTIFACT_FILENAMES = frozenset(
    {"modelmanifest.json", "coordinator.safetensors", "worker-1.safetensors",
     "worker-2.safetensors", "worker-3.safetensors"}
    | {name for name in SOURCE_HASHES if name != "model.safetensors"}
)

_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_HEX = re.compile(r"^[0-9a-f]{128}$")


class CatalogError(ValueError):
    pass


def validate_public_key(public_key):
    if type(public_key) is not bytes or len(public_key) != 65 or public_key[0] != 4:
        raise CatalogError("catalog public key must be an uncompressed P-256 point")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
    except ValueError as error:
        raise CatalogError("catalog public key is not a valid P-256 point") from error


def public_key_bytes(public_key):
    if (not isinstance(public_key, ec.EllipticCurvePublicKey)
            or not isinstance(public_key.curve, ec.SECP256R1)):
        raise CatalogError("catalog signing key must use P-256")
    encoded = public_key.public_bytes(serialization.Encoding.X962,
                                     serialization.PublicFormat.UncompressedPoint)
    validate_public_key(encoded)
    return encoded


def key_id_for(public_key):
    validate_public_key(public_key)
    return hashlib.sha256(public_key).hexdigest()


def _signature_message(kind, payload):
    if kind not in {"catalog", "assignment"}:
        raise CatalogError("unsupported signed-document kind")
    return f"steamboat-participant-{kind}-v1\0".encode("ascii") + json_bytes(
        payload, maximum_bytes=MAX_CATALOG_BYTES if kind == "catalog" else MAX_ASSIGNMENT_BYTES)


def verify_p256_sha256(public_key, message, signature):
    key = validate_public_key(public_key)
    if type(message) is not bytes or type(signature) is not bytes or len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not 1 <= r < _N or not 1 <= s <= _N // 2:
        return False
    try:
        key.verify(utils.encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


@dataclass(frozen=True)
class VerifiedDocument:
    payload: dict
    document_bytes: bytes
    document_sha256: str
    key_id: str


class CatalogVerifier:
    def __init__(self, pinned_public_key):
        self.public_key = bytes(pinned_public_key)
        self.key_id = key_id_for(self.public_key)

    def _verify_document(self, data, kind):
        maximum = MAX_CATALOG_BYTES if kind == "catalog" else MAX_ASSIGNMENT_BYTES
        try:
            raw = data.encode("utf-8") if isinstance(data, str) else data
            envelope = strict_json_loads(raw, maximum_bytes=maximum)
            if type(envelope) is not dict or set(envelope) != {
                    "schema_version", "signature_scheme", "key_id", "payload", "signature"}:
                raise CatalogError("signed envelope fields are invalid")
            if (type(envelope["schema_version"]) is not int
                    or envelope["schema_version"] != 1
                    or envelope["signature_scheme"] != SIGNATURE_SCHEME
                    or envelope["key_id"] != self.key_id
                    or type(envelope["payload"]) is not dict
                    or type(envelope["signature"]) is not str
                    or not _SIGNATURE_HEX.fullmatch(envelope["signature"])):
                raise CatalogError("signed envelope identity or types are invalid")
            if json_bytes(envelope, maximum_bytes=maximum) != raw:
                raise CatalogError("signed envelope is not canonical JSON")
            signature = bytes.fromhex(envelope["signature"])
            if not verify_p256_sha256(self.public_key,
                                      _signature_message(kind, envelope["payload"]), signature):
                raise CatalogError("catalog signature verification failed")
            return VerifiedDocument(envelope["payload"], raw, hashlib.sha256(raw).hexdigest(),
                                    self.key_id)
        except (UnicodeError, TypeError, ValueError) as error:
            if isinstance(error, CatalogError):
                raise
            raise CatalogError("signed document is malformed") from error

    def verify_catalog(self, data, *, now=None):
        verified = self._verify_document(data, "catalog")
        validate_catalog_payload(verified.payload, now=now)
        return verified

    def verify_assignment(self, data, catalog, *, account_id, device_id, role, now=None):
        verified = self._verify_document(data, "assignment")
        validate_assignment_payload(verified.payload, catalog, account_id=account_id,
                                    device_id=device_id, role=role, now=now)
        return verified


def _exact_object(value, keys, label):
    if type(value) is not dict or set(value) != set(keys):
        raise CatalogError(f"{label} fields do not match schema version 1")


def _exact_equal(value, expected, label):
    if json_bytes(value) != json_bytes(expected):
        raise CatalogError(f"unsupported {label}")


def _bounded_timestamp(value, name):
    if type(value) is not int or not 0 <= value <= 4_102_444_800:
        raise CatalogError(f"{name} must be a bounded integer Unix timestamp")


def _check_file_entry(value, name):
    _exact_object(value, {"sha256", "size_bytes"}, f"file {name}")
    if type(value["sha256"]) is not str or not _HEX_64.fullmatch(value["sha256"]):
        raise CatalogError(f"file {name} has an invalid SHA-256")
    if type(value["size_bytes"]) is not int or not 1 <= value["size_bytes"] <= MAX_FILE_BYTES:
        raise CatalogError(f"file {name} exceeds its size bound")
    if name == "modelmanifest.json" and value["size_bytes"] > MANIFEST_MAX_BYTES:
        raise CatalogError("global runtime manifest exceeds its size bound")
    if name == "config.json" and value["size_bytes"] > CONFIG_MAX_BYTES:
        raise CatalogError("pinned model config exceeds its size bound")


def validate_catalog_payload(payload, *, now=None):
    _exact_object(payload, {"schema_version", "catalog_revision", "issued_at", "expires_at",
                            "model", "runtime", "manifest", "components", "files"}, "catalog")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != CATALOG_SCHEMA_VERSION:
        raise CatalogError("unsupported catalog schema version")
    if type(payload["catalog_revision"]) is not int or payload["catalog_revision"] < 1:
        raise CatalogError("catalog revision must be a positive integer")
    _bounded_timestamp(payload["issued_at"], "catalog issued_at")
    _bounded_timestamp(payload["expires_at"], "catalog expires_at")
    current = int(time.time()) if now is None else now
    if type(current) is not int:
        raise CatalogError("catalog clock must be an integer Unix timestamp")
    if (payload["expires_at"] <= payload["issued_at"]
            or payload["expires_at"] - payload["issued_at"] > MAX_CATALOG_LIFETIME_SECONDS
            or payload["issued_at"] > current or payload["expires_at"] <= current):
        raise CatalogError("catalog is not currently valid or exceeds its lifetime")

    model = payload["model"]
    _exact_object(model, {"model_id", "model_revision", "tokenizer_revision", "source_hashes",
                          "device", "dtype", "attention", "compression", "layout", "batch_size",
                          "hidden_size", "vocabulary_size", "layers", "model_context",
                          "runtime_context", "tied_input_output_weights"}, "model")
    expected_model = {
        "model_id": MODEL_ID, "model_revision": MODEL_REVISION,
        "tokenizer_revision": MODEL_REVISION, "source_hashes": SOURCE_HASHES,
        "device": "cpu", "dtype": "float32", "attention": "eager", "compression": "none",
        "layout": "batch_sequence_hidden", "batch_size": 1, "hidden_size": 64,
        "vocabulary_size": 32000, "layers": 8, "model_context": 2048,
        "runtime_context": 1152, "tied_input_output_weights": False,
    }
    _exact_equal(model, expected_model, "pinned model identity")

    runtime = payload["runtime"]
    _exact_object(runtime, {"os", "architecture", "python", "torch", "transformers",
                            "grpcio", "protobuf", "lock_sha256"}, "runtime")
    expected_runtime = {
        "os": "linux", "architecture": "amd64", "python": "3.12.15",
        "torch": "2.14.1+cpu", "transformers": "5.19.0", "grpcio": "1.84.0",
        "protobuf": "7.36.2", "lock_sha256": RUNTIME_LOCK_SHA256,
    }
    _exact_equal(runtime, expected_runtime, "pinned runtime identity")

    manifest = payload["manifest"]
    _exact_object(manifest, {"filename", "fingerprint", "sha256", "size_bytes"}, "manifest")
    if manifest["filename"] != "modelmanifest.json":
        raise CatalogError("catalog manifest filename is not supported")
    if (type(manifest["fingerprint"]) is not str or not _HEX_64.fullmatch(manifest["fingerprint"])
            or type(manifest["sha256"]) is not str or not _HEX_64.fullmatch(manifest["sha256"])):
        raise CatalogError("catalog manifest identity is malformed")
    _check_file_entry({"sha256": manifest["sha256"], "size_bytes": manifest["size_bytes"]},
                      "modelmanifest.json")

    components = payload["components"]
    _exact_object(components, set(ASSIGNABLE_COMPONENTS), "component inventory")
    files = payload["files"]
    _exact_object(files, ARTIFACT_FILENAMES, "artifact file inventory")
    for name, entry in files.items():
        _check_file_entry(entry, name)
    if (files["modelmanifest.json"]["sha256"] != manifest["sha256"]
            or files["modelmanifest.json"]["size_bytes"] != manifest["size_bytes"]):
        raise CatalogError("catalog manifest entry disagrees with file inventory")
    for source_name, expected_hash in SOURCE_HASHES.items():
        if source_name == "model.safetensors":
            continue
        if files[source_name]["sha256"] != expected_hash:
            raise CatalogError(f"pinned source hash mismatch for {source_name}")
    for component, layer_range in ASSIGNABLE_COMPONENTS.items():
        entry = components[component]
        _exact_object(entry, {"file", "layer_range", "sha256", "size_bytes"},
                      f"component {component}")
        filename = f"{component}.safetensors"
        if entry["file"] != filename:
            raise CatalogError(f"unsupported artifact path for {component}")
        _exact_equal(entry["layer_range"], layer_range, f"layer range for {component}")
        _check_file_entry({"sha256": entry["sha256"], "size_bytes": entry["size_bytes"]}, filename)
        if (files[filename]["sha256"] != entry["sha256"]
                or files[filename]["size_bytes"] != entry["size_bytes"]):
            raise CatalogError(f"component {component} disagrees with file inventory")
    return payload


def validate_assignment_payload(payload, catalog, *, account_id, device_id, role, now=None):
    _exact_object(payload, {"schema_version", "assignment_id", "catalog_revision", "catalog_sha256",
                            "account_id", "device_id", "role", "component",
                            "manifest_fingerprint", "issued_at", "expires_at"}, "assignment")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != ASSIGNMENT_SCHEMA_VERSION:
        raise CatalogError("unsupported assignment schema version")
    if not valid_typed_id(payload["assignment_id"], "asg"):
        raise CatalogError("assignment identity is malformed")
    if not valid_typed_id(payload["account_id"], "acct") or payload["account_id"] != account_id:
        raise CatalogError("assignment account binding mismatch")
    if not valid_typed_id(payload["device_id"], "dev") or payload["device_id"] != device_id:
        raise CatalogError("assignment device binding mismatch")
    if type(role) is not str or role not in {"consumer", "host", "coordinator"} or payload["role"] != role:
        raise CatalogError("assignment role binding mismatch")
    if (type(payload["catalog_revision"]) is not int
            or payload["catalog_revision"] != catalog.payload["catalog_revision"]
            or payload["catalog_sha256"] != catalog.document_sha256
            or payload["manifest_fingerprint"] != catalog.payload["manifest"]["fingerprint"]):
        raise CatalogError("assignment does not bind the verified catalog and manifest")
    component = payload["component"]
    if role == "consumer":
        if component is not None:
            raise CatalogError("consumer assignments cannot include model components")
    elif role == "host":
        if type(component) is not str or component not in {"worker-1", "worker-2", "worker-3"}:
            raise CatalogError("host assignment must name exactly one supported worker shard")
    elif component != "coordinator":
        raise CatalogError("coordinator assignment must name only the coordinator component")
    for name in ("issued_at", "expires_at"):
        _bounded_timestamp(payload[name], f"assignment {name}")
    current = int(time.time()) if now is None else now
    if type(current) is not int:
        raise CatalogError("assignment clock must be an integer Unix timestamp")
    catalog_payload = catalog.payload
    if (payload["issued_at"] > current or payload["issued_at"] < catalog_payload["issued_at"]
            or payload["expires_at"] <= current
            or payload["expires_at"] <= payload["issued_at"]
            or payload["expires_at"] > catalog_payload["expires_at"]):
        raise CatalogError("assignment is not currently valid within catalog lifetime")
    return payload


def required_artifact_names(role, component):
    if role == "consumer":
        if component is not None:
            raise CatalogError("consumer assignments cannot include artifacts")
        return ()
    if role == "host" and component in {"worker-1", "worker-2", "worker-3"}:
        return ("modelmanifest.json", "config.json", f"{component}.safetensors")
    if role == "coordinator" and component == "coordinator":
        return ("modelmanifest.json", "config.json", "coordinator.safetensors", *TOKENIZER_FILES)
    raise CatalogError("assignment has no supported role-specific artifact scope")
