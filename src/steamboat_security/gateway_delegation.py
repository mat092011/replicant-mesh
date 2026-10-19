"""Operator-authorized assertions from a terminating gateway to a worker.

The gateway signs a bounded assertion about the authenticated upstream actor
and exact downstream request. This is a trusted gateway assertion, not
end-to-end proof that the coordinator signed the request. C1 grants, revocation,
readiness, replay admission, and native TLS ownership remain separate checks.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .certificates import (MAX_CERTIFICATE_BYTES, certificate_sha256,
                           public_key_sha256, serial_hex, verify_leaf)
from .channel_certificates import verify_channel_certificate
from .channel_policy import ChannelPolicyStore
from .clock import Clock
from .codec import WORKER_METHODS, WORKER_SERVICE, canonical_json, parse_metadata
from .errors import SecurityError
from .ids import validate_boot, validate_id
from .authorization import LocalIdentity

DOMAIN = b"steamboat-gateway-delegation-v1\0"
MAX_DELEGATION_BYTES = 32 * 1024
MAX_REQUEST_BYTES = 1024 * 1024
MAX_DELEGATION_SECONDS = 300
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_GENERATION = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
_FIELDS = frozenset({
    "version", "policy_revision", "policy_digest", "gateway_id",
    "gateway_certificate_sha256", "actor_certificate_base64",
    "coordinator_boot_id", "tenant_account_id", "target_device_id",
    "worker_boot_id", "assignment_id", "model_id", "stream_generation",
    "frame_sequence", "service", "method", "binding_sha256",
    "request_sha256", "issued_at", "expires_at",
})
_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class DelegationError(SecurityError):
    """A gateway delegation was malformed, unauthorized, or no longer live."""


def _validate_payload(payload):
    if type(payload) is not dict or set(payload) != _FIELDS:
        raise DelegationError("delegation payload has unknown or missing fields")
    if type(payload["version"]) is not int or payload["version"] != 1:
        raise DelegationError("unsupported delegation version")
    if type(payload["policy_revision"]) is not int or payload["policy_revision"] < 1:
        raise DelegationError("invalid policy revision")
    if type(payload["frame_sequence"]) is not int or not 1 <= payload["frame_sequence"] <= 2**63 - 1:
        raise DelegationError("invalid frame sequence")
    for name in ("issued_at", "expires_at"):
        if type(payload[name]) is not int or payload[name] < 0:
            raise DelegationError("invalid delegation time")
    if (payload["expires_at"] <= payload["issued_at"]
            or payload["expires_at"] - payload["issued_at"] > MAX_DELEGATION_SECONDS):
        raise DelegationError("delegation lifetime exceeds 300 seconds")
    for name in ("policy_digest", "gateway_certificate_sha256", "model_id",
                 "binding_sha256", "request_sha256"):
        if type(payload[name]) is not str or not _HEX64.fullmatch(payload[name]):
            raise DelegationError(f"invalid {name}")
    if type(payload["stream_generation"]) is not str or not _GENERATION.fullmatch(payload["stream_generation"]):
        raise DelegationError("invalid stream generation")
    if type(payload["gateway_id"]) is not str or not re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?", payload["gateway_id"], re.ASCII):
        raise DelegationError("invalid gateway ID")
    for name, prefix in (("tenant_account_id", "acct"), ("target_device_id", "dev"),
                         ("assignment_id", "asg")):
        try:
            validate_id(payload[name], prefix)
        except Exception as error:
            raise DelegationError(f"invalid {name}") from error
    for name in ("coordinator_boot_id", "worker_boot_id"):
        try:
            validate_boot(payload[name])
        except Exception as error:
            raise DelegationError(f"invalid {name}") from error
    if (type(payload["service"]) is not str or payload["service"] != WORKER_SERVICE
            or type(payload["method"]) is not str
            or payload["method"] not in WORKER_METHODS):
        raise DelegationError("delegation does not name a supported worker method")
    actor_text = payload["actor_certificate_base64"]
    if type(actor_text) is not str or len(actor_text) > ((MAX_CERTIFICATE_BYTES + 2) // 3) * 4:
        raise DelegationError("actor certificate encoding exceeds its bound")
    try:
        actor = base64.b64decode(actor_text, validate=True)
    except (ValueError, TypeError) as error:
        raise DelegationError("actor certificate encoding is invalid") from error
    if not 1 <= len(actor) <= MAX_CERTIFICATE_BYTES or base64.b64encode(actor).decode("ascii") != actor_text:
        raise DelegationError("actor certificate encoding is not canonical")
    return actor


def _load_private_key(key_pem):
    if type(key_pem) is not bytes or not 1 <= len(key_pem) <= MAX_CERTIFICATE_BYTES:
        raise DelegationError("gateway signing key input exceeds its bound")
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError) as error:
        raise DelegationError("gateway signing key is malformed") from error
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise DelegationError("gateway signing key must be P-256")
    return key


def sign_gateway_delegation(payload, gateway_private_key_pem, gateway_certificate_pem):
    """Create a canonical low-S attestation using the actual gateway leaf key."""
    _validate_payload(payload)
    key = _load_private_key(gateway_private_key_pem)
    if type(gateway_certificate_pem) is not bytes or not 1 <= len(gateway_certificate_pem) <= MAX_CERTIFICATE_BYTES:
        raise DelegationError("gateway certificate exceeds its bound")
    try:
        cert = x509.load_pem_x509_certificate(gateway_certificate_pem)
    except ValueError as error:
        raise DelegationError("gateway certificate is malformed") from error
    if (not isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
            or cert.public_key().public_numbers() != key.public_key().public_numbers()):
        raise DelegationError("gateway signing key does not match its leaf certificate")
    signature = key.sign(DOMAIN + canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)
    if s > _ORDER // 2:
        signature = encode_dss_signature(r, _ORDER - s)
    envelope = canonical_json({"payload": payload,
                               "signature": base64.b64encode(signature).decode("ascii")})
    if len(envelope) > MAX_DELEGATION_BYTES:
        raise DelegationError("delegation exceeds its 32 KiB bound")
    return envelope


@dataclass
class _LiveFence:
    deadline: float
    lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass(frozen=True)
class VerifiedDelegation:
    payload: object
    actor_certificate_pem: bytes
    gateway_certificate_pem: bytes
    actor_identity: tuple
    ingress_identity: tuple
    deadline_monotonic: float
    _fence: _LiveFence = field(repr=False, compare=False)

    def assert_live(self, verifier):
        return verifier.assert_live(self)


class GatewayDelegationVerifier:
    """Verify signed gateway assertions against concrete C2 policy and clocks."""

    def __init__(self, policy_store, *, clock: Clock, gateway_ca_pem: bytes,
                 participant_ca_pem: bytes, local_identity, endpoint_host: str,
                 endpoint_port: int):
        if (type(clock) is not Clock or type(policy_store) is not ChannelPolicyStore
                or policy_store.clock is not clock):
            raise TypeError("verifier requires the exact Clock owned by policy store")
        if not isinstance(gateway_ca_pem, bytes) or not gateway_ca_pem:
            raise TypeError("pinned gateway CA PEM is required")
        if not isinstance(participant_ca_pem, bytes) or not participant_ca_pem:
            raise TypeError("pinned participant CA PEM is required")
        if type(endpoint_host) is not str or not endpoint_host:
            raise TypeError("fixed gateway endpoint host is required")
        if type(endpoint_port) is not int or not 1 <= endpoint_port <= 65535:
            raise TypeError("fixed gateway endpoint port is invalid")
        if type(local_identity) is not LocalIdentity:
            raise TypeError("verifier requires the exact core LocalIdentity")
        self.policy_store, self.clock = policy_store, clock
        self.gateway_ca_pem, self.participant_ca_pem = gateway_ca_pem, participant_ca_pem
        self.local_identity = local_identity
        self.endpoint_host, self.endpoint_port = endpoint_host, endpoint_port

    def _verify(self, envelope, *, gateway_peer_certificate_pem, metadata,
                request_bytes, expected_stream_generation, expected_frame_sequence):
        if type(envelope) is not bytes or not 1 <= len(envelope) <= MAX_DELEGATION_BYTES:
            raise DelegationError("delegation envelope exceeds its byte bound")
        if type(request_bytes) is not bytes or len(request_bytes) > MAX_REQUEST_BYTES:
            raise DelegationError("raw request exceeds its byte bound")
        try:
            outer = json.loads(envelope.decode("utf-8", "strict"), object_pairs_hook=self._pairs,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except Exception as error:
            raise DelegationError("delegation envelope is malformed") from error
        if type(outer) is not dict or set(outer) != {"payload", "signature"} or canonical_json(outer) != envelope:
            raise DelegationError("delegation envelope is noncanonical or has unknown fields")
        payload = outer["payload"]
        actor_pem = _validate_payload(payload)
        signature_text = outer["signature"]
        if type(signature_text) is not str or len(signature_text) > 128:
            raise DelegationError("delegation signature is malformed")
        try:
            signature = base64.b64decode(signature_text, validate=True)
            if base64.b64encode(signature).decode("ascii") != signature_text:
                raise ValueError("noncanonical base64")
            r, s = decode_dss_signature(signature)
            if not (1 <= r < _ORDER and 1 <= s <= _ORDER // 2) or encode_dss_signature(r, s) != signature:
                raise ValueError("noncanonical or high-S signature")
        except (ValueError, TypeError) as error:
            raise DelegationError("delegation signature is noncanonical") from error

        sample = self.clock.sample()
        view = self.policy_store.current()
        gateway = view.gateway(payload["gateway_id"])
        if gateway is None:
            raise DelegationError("gateway is not in the current operator policy")
        if (view.revision != payload["policy_revision"]
                or view.policy_digest != payload["policy_digest"]):
            raise DelegationError("delegation does not name the exact current policy")
        expected_dns = None
        expected_ip = None
        try:
            ipaddress.ip_address(self.endpoint_host)
            expected_ip = self.endpoint_host
        except ValueError:
            expected_dns = self.endpoint_host
        channel = verify_channel_certificate(
            gateway_peer_certificate_pem, self.gateway_ca_pem, kind="gateway",
            expected_identity=payload["gateway_id"], now=sample.wall,
            uncertainty_seconds=sample.uncertainty, required_eku={"client", "server"},
            expected_dns=expected_dns, expected_ip=expected_ip)
        if (channel.certificate_sha256 != gateway["certificate_sha256"]
                or channel.serial != gateway["serial"]
                or channel.public_key_sha256 != gateway["public_key_sha256"]
                or gateway["endpoint_host"] != self.endpoint_host
                or gateway["endpoint_port"] != self.endpoint_port
                or payload["gateway_certificate_sha256"] != channel.certificate_sha256):
            raise DelegationError("actual TLS gateway certificate or endpoint is not policy-pinned")
        try:
            channel_cert = x509.load_pem_x509_certificate(gateway_peer_certificate_pem)
            channel_cert.public_key().verify(signature, DOMAIN + canonical_json(payload),
                                              ec.ECDSA(hashes.SHA256()))
        except (ValueError, InvalidSignature, AttributeError) as error:
            raise DelegationError("gateway signature does not verify under authenticated TLS leaf") from error

        binding = parse_metadata(WORKER_SERVICE, payload["method"], metadata)
        if (payload["service"] != WORKER_SERVICE
                or payload["binding_sha256"] != hashlib.sha256(binding.encoded).hexdigest()
                or payload["request_sha256"] != hashlib.sha256(request_bytes).hexdigest()):
            raise DelegationError("delegation differs from exact binding or raw request")
        if (type(expected_stream_generation) is not str
                or not _GENERATION.fullmatch(expected_stream_generation)
                or payload["stream_generation"] != expected_stream_generation
                or type(expected_frame_sequence) is not int
                or not 1 <= expected_frame_sequence <= 2**63 - 1
                or payload["frame_sequence"] != expected_frame_sequence):
            raise DelegationError("delegation is outside the active stream generation/sequence")
        fields = binding.fields
        for key, val in (("coordinator_boot_id", payload["coordinator_boot_id"]),
                         ("tenant_account_id", payload["tenant_account_id"]),
                         ("target_device_id", payload["target_device_id"]),
                         ("worker_boot_id", payload["worker_boot_id"]),
                         ("assignment_id", payload["assignment_id"])):
            if fields.get(key) != val:
                raise DelegationError("delegation does not match exact C1 binding")
        if fields.get("role") != "personal_coordinator":
            raise DelegationError("delegated actor must be a personal coordinator")
        actor_cert = verify_leaf(
            self.participant_ca_pem, actor_pem, now=sample.wall,
            uncertainty_seconds=sample.uncertainty, account_id=fields["account_id"],
            device_id=fields["device_id"], role="personal_coordinator")
        actor_hash = certificate_sha256(actor_cert)
        actor_serial = serial_hex(actor_cert.serial_number)
        if (actor_hash != payload.get("_unused", actor_hash)
                or actor_serial == ""):
            raise DelegationError("actor certificate is invalid")
        route = view.route(
            gateway_id=payload["gateway_id"], account_id=fields["account_id"],
            device_id=fields["device_id"], actor_serial=actor_serial,
            actor_credential_epoch=fields["credential_epoch"],
            actor_certificate_sha256=actor_hash,
            coordinator_boot_id=payload["coordinator_boot_id"],
            tenant_account_id=payload["tenant_account_id"],
            target_device_id=payload["target_device_id"], worker_boot_id=payload["worker_boot_id"],
            assignment_id=payload["assignment_id"], model_id=payload["model_id"],
            method=payload["method"])
        if route is None:
            raise DelegationError("actor route is not authorized by current operator policy")
        worker = view.worker(payload["target_device_id"], payload["worker_boot_id"])
        if worker is None or self.local_identity is None:
            raise DelegationError("local worker identity is unavailable")
        local_cert = verify_leaf(
            self.participant_ca_pem, self.local_identity.certificate_pem,
            now=sample.wall, uncertainty_seconds=sample.uncertainty,
            account_id=worker["account_id"], device_id=payload["target_device_id"], role="host",
            serial=worker["host_serial"], certificate_hash=worker["host_certificate_sha256"])
        if (payload["worker_boot_id"] != self.local_identity.boot_id
                or payload["model_id"] != self.local_identity.model_id
                or payload["assignment_id"] != self.local_identity.assignment_id
                or certificate_sha256(local_cert) != worker["host_certificate_sha256"]):
            raise DelegationError("delegation target differs from this pinned worker identity")

        now_earliest, now_latest = sample.earliest_wall, sample.latest_wall
        if (payload["issued_at"] > now_earliest or payload["expires_at"] <= now_latest):
            raise DelegationError("delegation is not currently valid")
        deadline = min(view.deadline_monotonic,
                       sample.monotonic + payload["expires_at"] - now_latest,
                       sample.monotonic + channel.not_after.timestamp() - now_latest,
                       sample.monotonic + actor_cert.not_valid_after_utc.timestamp() - now_latest,
                       sample.monotonic + local_cert.not_valid_after_utc.timestamp() - now_latest)
        if not math.isfinite(deadline) or deadline <= sample.monotonic:
            raise DelegationError("delegation has no conservative live interval")
        ingress = ("gateway-v1", channel.certificate_sha256, payload["stream_generation"])
        frozen = dict(payload)
        from types import MappingProxyType
        return VerifiedDelegation(
            MappingProxyType(frozen), actor_pem, gateway_peer_certificate_pem,
            (fields["account_id"], fields["device_id"], fields["credential_epoch"]),
            ingress, deadline, _LiveFence(deadline))

    @staticmethod
    def _pairs(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate JSON member")
            out[key] = value
        return out

    def verify(self, envelope, *, gateway_peer_certificate_pem, metadata,
               request_bytes, expected_stream_generation, expected_frame_sequence):
        try:
            return self._verify(
                envelope, gateway_peer_certificate_pem=gateway_peer_certificate_pem,
                metadata=metadata, request_bytes=request_bytes,
                expected_stream_generation=expected_stream_generation,
                expected_frame_sequence=expected_frame_sequence)
        except DelegationError:
            raise
        except Exception as error:
            raise DelegationError("gateway delegation verification failed") from error

    def assert_live(self, verified):
        if type(verified) is not VerifiedDelegation:
            raise DelegationError("verified delegation object is required")
        sample = None
        try:
            sample = self.clock.sample()
            view = self.policy_store.current()
            if (view.revision != verified.payload["policy_revision"]
                    or view.policy_digest != verified.payload["policy_digest"]):
                raise DelegationError("delegation policy identity was replaced")
            with verified._fence.lock:
                verified._fence.deadline = min(
                    verified._fence.deadline, view.deadline_monotonic,
                    sample.monotonic + verified.payload["expires_at"] - sample.latest_wall)
                if verified.payload["issued_at"] > sample.earliest_wall:
                    verified._fence.deadline = min(verified._fence.deadline,
                                                  sample.monotonic)
                    raise DelegationError(
                        "delegation is not yet valid under current clock uncertainty")
            actor = verify_leaf(
                self.participant_ca_pem, verified.actor_certificate_pem,
                now=sample.wall, uncertainty_seconds=sample.uncertainty,
                account_id=verified.actor_identity[0],
                device_id=verified.actor_identity[1],
                role="personal_coordinator")
            gateway = view.gateway(verified.payload["gateway_id"])
            if gateway is None:
                raise DelegationError("gateway was removed from current policy")
            try:
                ipaddress.ip_address(self.endpoint_host)
                dns, ip = None, self.endpoint_host
            except ValueError:
                dns, ip = self.endpoint_host, None
            channel = verify_channel_certificate(
                verified.gateway_certificate_pem, self.gateway_ca_pem,
                kind="gateway", expected_identity=verified.payload["gateway_id"],
                now=sample.wall, uncertainty_seconds=sample.uncertainty,
                required_eku={"client", "server"}, expected_dns=dns, expected_ip=ip)
            if (channel.certificate_sha256 != verified.payload["gateway_certificate_sha256"]
                    or channel.serial != gateway["serial"]
                    or channel.public_key_sha256 != gateway["public_key_sha256"]
                    or gateway["endpoint_host"] != self.endpoint_host
                    or gateway["endpoint_port"] != self.endpoint_port):
                raise DelegationError("gateway certificate is no longer policy-pinned")
            actor_hash = certificate_sha256(actor)
            if view.route(
                    gateway_id=verified.payload["gateway_id"],
                    account_id=verified.actor_identity[0],
                    device_id=verified.actor_identity[1],
                    actor_serial=serial_hex(actor.serial_number),
                    actor_credential_epoch=verified.actor_identity[2],
                    actor_certificate_sha256=actor_hash,
                    coordinator_boot_id=verified.payload["coordinator_boot_id"],
                    tenant_account_id=verified.payload["tenant_account_id"],
                    target_device_id=verified.payload["target_device_id"],
                    worker_boot_id=verified.payload["worker_boot_id"],
                    assignment_id=verified.payload["assignment_id"],
                    model_id=verified.payload["model_id"],
                    method=verified.payload["method"]) is None:
                raise DelegationError("actor route is no longer authorized")
            worker = view.worker(verified.payload["target_device_id"],
                                 verified.payload["worker_boot_id"])
            if worker is None:
                raise DelegationError("worker was removed from current policy")
            local = verify_leaf(
                self.participant_ca_pem, self.local_identity.certificate_pem,
                now=sample.wall, uncertainty_seconds=sample.uncertainty,
                account_id=worker["account_id"],
                device_id=verified.payload["target_device_id"], role="host",
                serial=worker["host_serial"],
                certificate_hash=worker["host_certificate_sha256"])
            if (self.local_identity.boot_id != verified.payload["worker_boot_id"]
                    or self.local_identity.model_id != verified.payload["model_id"]
                    or self.local_identity.assignment_id != verified.payload["assignment_id"]):
                raise DelegationError("local worker identity changed")
            end = min(view.deadline_monotonic,
                      sample.monotonic + verified.payload["expires_at"] - sample.latest_wall,
                      sample.monotonic + channel.not_after.timestamp() - sample.latest_wall,
                      sample.monotonic + actor.not_valid_after_utc.timestamp() - sample.latest_wall,
                      sample.monotonic + local.not_valid_after_utc.timestamp() - sample.latest_wall)
            if not math.isfinite(end) or end <= sample.monotonic:
                raise DelegationError("delegation no longer has a conservative live interval")
            with verified._fence.lock:
                verified._fence.deadline = min(verified._fence.deadline, end)
                if sample.monotonic >= verified._fence.deadline:
                    raise DelegationError("delegation has expired")
            return True
        except DelegationError:
            if sample is not None:
                with verified._fence.lock:
                    verified._fence.deadline = min(verified._fence.deadline,
                                                   sample.monotonic)
            raise
        except Exception as error:
            if sample is not None:
                with verified._fence.lock:
                    verified._fence.deadline = min(verified._fence.deadline,
                                                   sample.monotonic)
            raise DelegationError("delegation liveness check failed closed") from error
