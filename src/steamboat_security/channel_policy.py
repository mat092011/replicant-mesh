"""Operator-signed, bounded authorization for terminating C2 gateways.

This is a policy primitive. It does not authenticate TLS peers, check C1
grants/revocation or readiness, or issue a per-operation delegation. The
verification key is a public key distributed to verifiers. Its private signing
counterpart is a dedicated operator policy key, separate from gateway, worker,
or CA keys, and is never distributed to participants.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import inspect
import json
import re
import threading
from dataclasses import dataclass
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .certificates import public_key_sha256
from .clock import Clock, ClockSample
from .codec import canonical_json, WORKER_METHODS
from .errors import SnapshotError
from .ids import validate_boot, validate_id

MAX_CHANNEL_POLICY_BYTES = 64 * 1024
MAX_CHANNEL_POLICY_LIFETIME_SECONDS = 300
MAX_CHANNEL_LIFETIME_SECONDS = 900
DOMAIN = b"steamboat-channel-policy-v1\0"
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SERIAL = re.compile(r"^[1-9a-f][0-9a-f]{0,39}$", re.ASCII)
_GATEWAY = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$", re.ASCII)
_DNS = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$",
    re.ASCII,
)
_POLICY_FIELDS = {
    "version",
    "revision",
    "issued_at",
    "expires_at",
    "gateways",
    "workers",
    "routes",
}
_GATEWAY_FIELDS = {
    "gateway_id",
    "serial",
    "certificate_sha256",
    "public_key_sha256",
    "not_before",
    "not_after",
    "endpoint_host",
    "endpoint_port",
}
_WORKER_FIELDS = {
    "account_id",
    "device_id",
    "host_serial",
    "host_credential_epoch",
    "host_certificate_sha256",
    "worker_boot_id",
    "assignment_id",
    "model_id",
    "channel_serial",
    "channel_certificate_sha256",
    "channel_public_key_sha256",
    "not_before",
    "not_after",
    "gateway_id",
}
_ROUTE_FIELDS = {
    "gateway_id",
    "account_id",
    "device_id",
    "actor_serial",
    "actor_credential_epoch",
    "actor_certificate_sha256",
    "coordinator_boot_id",
    "tenant_account_id",
    "target_device_id",
    "worker_boot_id",
    "assignment_id",
    "model_id",
    "methods",
}
_MAX_INTEGER = 2**63 - 1
_MAX_EPOCH = 2**31 - 1


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise SnapshotError("channel policy contains a duplicate key")
        out[key] = value
    return out


def _constant(_value):
    raise SnapshotError("channel policy contains a non-finite number")


def _integer(value, name, minimum=0):
    if type(value) is not int or not minimum <= value <= _MAX_INTEGER:
        raise SnapshotError(f"channel policy {name} is invalid")
    return value


def _hex(value, name):
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise SnapshotError(f"channel policy {name} is invalid")
    return value


def _serial(value, name):
    if type(value) is not str or not _SERIAL.fullmatch(value):
        raise SnapshotError(f"channel policy {name} is invalid")
    return value


def _sorted_strings(value, name, maximum, allowed=None):
    if (
        type(value) is not list
        or len(value) > maximum
        or any(type(x) is not str for x in value)
    ):
        raise SnapshotError(f"channel policy {name} exceeds its bound")
    if value != sorted(value) or len(set(value)) != len(value):
        raise SnapshotError(f"channel policy {name} must be sorted and unique")
    if allowed is not None and any(x not in allowed for x in value):
        raise SnapshotError(f"channel policy {name} contains an unknown method")
    return tuple(value)


def _gateway_id(value):
    if type(value) is not str or not _GATEWAY.fullmatch(value):
        raise SnapshotError("channel policy gateway ID is invalid")
    return value


def _endpoint(value):
    if (
        type(value) is not str
        or value != value.lower()
        or "*" in value
        or "://" in value
        or "%" in value
    ):
        raise SnapshotError("channel policy endpoint host is invalid")
    try:
        parsed = ipaddress.ip_address(value)
        if str(parsed) != value:
            raise SnapshotError("channel policy endpoint IP is not canonical")
    except ValueError:
        if not _DNS.fullmatch(value):
            raise SnapshotError("channel policy endpoint DNS name is invalid")


def _validate_payload(payload, signer_hash):
    if type(payload) is not dict or set(payload) != _POLICY_FIELDS:
        raise SnapshotError("channel policy has unknown or missing fields")
    if _integer(payload["version"], "version", 1) != 1:
        raise SnapshotError("unsupported channel policy version")
    revision = _integer(payload["revision"], "revision", 1)
    issued = _integer(payload["issued_at"], "issued_at")
    expires = _integer(payload["expires_at"], "expires_at", 1)
    if expires <= issued or expires - issued > MAX_CHANNEL_POLICY_LIFETIME_SECONDS:
        raise SnapshotError("channel policy lifetime exceeds 300 seconds")
    if type(payload["gateways"]) is not list or len(payload["gateways"]) > 4:
        raise SnapshotError("channel policy gateway list exceeds its bound")
    if type(payload["workers"]) is not list or len(payload["workers"]) > 8:
        raise SnapshotError("channel policy worker list exceeds its bound")
    if type(payload["routes"]) is not list or len(payload["routes"]) > 32:
        raise SnapshotError("channel policy route list exceeds its bound")
    gateways = {}
    prior = None
    gateway_serials, gateway_certs, gateway_keys = set(), set(), set()
    for item in payload["gateways"]:
        if type(item) is not dict or set(item) != _GATEWAY_FIELDS:
            raise SnapshotError("gateway record has unknown or missing fields")
        gid = _gateway_id(item["gateway_id"])
        if prior is not None and gid <= prior:
            raise SnapshotError("gateway records must be sorted and unique")
        prior = gid
        serial = _serial(item["serial"], "gateway serial")
        cert = _hex(item["certificate_sha256"], "gateway certificate hash")
        key = _hex(item["public_key_sha256"], "gateway public key hash")
        if key == signer_hash:
            raise SnapshotError("gateway key cannot reuse the policy signing key")
        if serial in gateway_serials or cert in gateway_certs or key in gateway_keys:
            raise SnapshotError(
                "gateway serial, certificate, and key identities must be unique"
            )
        gateway_serials.add(serial)
        gateway_certs.add(cert)
        gateway_keys.add(key)
        start = _integer(item["not_before"], "gateway not_before")
        stop = _integer(item["not_after"], "gateway not_after", 1)
        if (
            stop <= start
            or stop - start > MAX_CHANNEL_LIFETIME_SECONDS
            or start > issued
            or stop < expires
        ):
            raise SnapshotError(
                "gateway validity must cover policy lifetime and fit 900 seconds"
            )
        _endpoint(item["endpoint_host"])
        port = _integer(item["endpoint_port"], "endpoint_port", 1)
        if port > 65535:
            raise SnapshotError("channel policy endpoint port is invalid")
        gateways[gid] = (serial, cert, key, start, stop)
    workers = {}
    prior = None
    channel_serials, channel_certs, channel_keys = set(), set(), set()
    host_serials, host_certs = set(), set()
    account_by_device = {}
    for item in payload["workers"]:
        if type(item) is not dict or set(item) != _WORKER_FIELDS:
            raise SnapshotError("worker record has unknown or missing fields")
        account = validate_id(item["account_id"], "acct")
        device = validate_id(item["device_id"], "dev")
        if device in account_by_device and account_by_device[device] != account:
            raise SnapshotError(
                "one stable worker device cannot belong to multiple accounts"
            )
        account_by_device[device] = account
        identity = (device, validate_boot(item["worker_boot_id"]))
        if prior is not None and identity <= prior:
            raise SnapshotError("worker records must be sorted and unique")
        prior = identity
        host_serial = _serial(item["host_serial"], "host serial")
        epoch = _integer(item["host_credential_epoch"], "host credential epoch", 1)
        if epoch > _MAX_EPOCH:
            raise SnapshotError("channel policy host credential epoch is invalid")
        host_cert = _hex(item["host_certificate_sha256"], "host certificate hash")
        if host_serial in gateway_serials or host_cert in gateway_certs:
            raise SnapshotError(
                "gateway and participant certificate identities must be distinct"
            )
        if host_serial in channel_serials or host_cert in channel_certs:
            raise SnapshotError(
                "host and worker channel certificate identities must be distinct"
            )
        host_serials.add(host_serial)
        host_certs.add(host_cert)
        assignment = validate_id(item["assignment_id"], "asg")
        model = _hex(item["model_id"], "model ID")
        channel_serial = _serial(item["channel_serial"], "channel serial")
        channel_cert = _hex(
            item["channel_certificate_sha256"], "channel certificate hash"
        )
        channel_key = _hex(item["channel_public_key_sha256"], "channel public key hash")
        if channel_key == signer_hash:
            raise SnapshotError("worker channel key cannot reuse policy signing key")
        if (
            channel_serial in channel_serials
            or channel_cert in channel_certs
            or channel_key in channel_keys
            or channel_serial in gateway_serials
            or channel_cert in gateway_certs
            or channel_key in gateway_keys
            or channel_serial in host_serials
            or channel_cert in host_certs
        ):
            raise SnapshotError(
                "worker channel serial, certificate, and key identities must be unique"
            )
        channel_serials.add(channel_serial)
        channel_certs.add(channel_cert)
        channel_keys.add(channel_key)
        start = _integer(item["not_before"], "worker not_before")
        stop = _integer(item["not_after"], "worker not_after", 1)
        if (
            stop <= start
            or stop - start > MAX_CHANNEL_LIFETIME_SECONDS
            or start > issued
            or stop < expires
        ):
            raise SnapshotError(
                "worker channel validity must cover policy lifetime and fit 900 seconds"
            )
        gid = _gateway_id(item["gateway_id"])
        if gid not in gateways:
            raise SnapshotError("worker references an unknown gateway")
        workers[identity] = (
            account,
            host_serial,
            epoch,
            host_cert,
            assignment,
            model,
            channel_serial,
            channel_cert,
            channel_key,
            start,
            stop,
            gid,
        )
    routes = []
    prior_route = None
    for item in payload["routes"]:
        if type(item) is not dict or set(item) != _ROUTE_FIELDS:
            raise SnapshotError("route record has unknown or missing fields")
        gid = _gateway_id(item["gateway_id"])
        account = validate_id(item["account_id"], "acct")
        device = validate_id(item["device_id"], "dev")
        actor_serial = _serial(item["actor_serial"], "actor serial")
        actor_epoch = _integer(
            item["actor_credential_epoch"], "actor credential epoch", 1
        )
        if actor_epoch > _MAX_EPOCH:
            raise SnapshotError("channel policy actor credential epoch is invalid")
        actor_cert = _hex(item["actor_certificate_sha256"], "actor certificate hash")
        coord_boot = validate_boot(item["coordinator_boot_id"])
        tenant = validate_id(item["tenant_account_id"], "acct")
        target = validate_id(item["target_device_id"], "dev")
        worker_boot = validate_boot(item["worker_boot_id"])
        assignment = validate_id(item["assignment_id"], "asg")
        model = _hex(item["model_id"], "model ID")
        methods = _sorted_strings(
            item["methods"], "route methods", len(WORKER_METHODS), WORKER_METHODS
        )
        if not methods:
            raise SnapshotError("route must authorize at least one worker method")
        route_key = (
            gid,
            account,
            device,
            actor_serial,
            actor_epoch,
            actor_cert,
            coord_boot,
            target,
            worker_boot,
            assignment,
            model,
        )
        if prior_route is not None and route_key <= prior_route:
            raise SnapshotError("routes must be sorted and unique")
        prior_route = route_key
        if tenant != account:
            raise SnapshotError("gateway route tenant must match actor account")
        worker = workers.get((target, worker_boot))
        if worker is None or worker[-1] != gid:
            raise SnapshotError(
                "route does not reference the exact policy worker and gateway"
            )
        if worker[4] != assignment or worker[5] != model:
            raise SnapshotError(
                "route target assignment/model does not match policy worker"
            )
        routes.append(
            (
                gid,
                account,
                device,
                actor_serial,
                actor_epoch,
                actor_cert,
                coord_boot,
                tenant,
                target,
                worker_boot,
                assignment,
                model,
                methods,
            )
        )
    return revision, issued, expires, gateways, workers, tuple(routes)


def _signing_key(pem):
    if type(pem) is not bytes or not 1 <= len(pem) <= MAX_CHANNEL_POLICY_BYTES:
        raise SnapshotError("channel policy signing key input exceeds its bound")
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as error:
        raise SnapshotError("channel policy signing key is malformed") from error
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise SnapshotError("channel policy key must be ECDSA P-256")
    return key


def _verification_key(pem):
    if type(pem) is not bytes or not 1 <= len(pem) <= MAX_CHANNEL_POLICY_BYTES:
        raise SnapshotError("channel policy verification key input exceeds its bound")
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as error:
        raise SnapshotError("channel policy verification key is malformed") from error
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise SnapshotError("channel policy key must be ECDSA P-256")
    return key


def sign_channel_policy(payload: dict, private_key_pem: bytes) -> bytes:
    """Validate and sign a v1 payload using a dedicated operator policy key."""
    key = _signing_key(private_key_pem)
    _validate_payload(payload, public_key_sha256(key.public_key()))
    signed = DOMAIN + canonical_json(payload)
    signature = key.sign(signed, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    if s > order // 2:
        signature = encode_dss_signature(r, order - s)
    encoded = canonical_json(
        {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}
    )
    if len(encoded) > MAX_CHANNEL_POLICY_BYTES:
        raise SnapshotError("signed channel policy exceeds 64 KiB")
    return encoded


@dataclass(frozen=True)
class ChannelPolicyView:
    revision: int
    issued_at: int
    expires_at: int
    policy_digest: str
    deadline_monotonic: float
    published_monotonic: float
    gateways: object
    workers: object
    routes: tuple
    canonical_payload: bytes

    def gateway(self, gateway_id):
        return self.gateways.get(gateway_id)

    def worker(self, device_id, worker_boot_id):
        return self.workers.get((device_id, worker_boot_id))

    def route(
        self,
        *,
        gateway_id,
        account_id,
        device_id,
        actor_serial,
        actor_credential_epoch,
        actor_certificate_sha256,
        coordinator_boot_id,
        tenant_account_id,
        target_device_id,
        worker_boot_id,
        assignment_id,
        model_id,
        method,
    ):
        for route in self.routes:
            if (
                route[:12]
                == (
                    gateway_id,
                    account_id,
                    device_id,
                    actor_serial,
                    actor_credential_epoch,
                    actor_certificate_sha256,
                    coordinator_boot_id,
                    tenant_account_id,
                    target_device_id,
                    worker_boot_id,
                    assignment_id,
                    model_id,
                )
                and method in route[12]
            ):
                return route
        return None


class ChannelPolicyStore:
    """Pinned operator-key policy store with monotonic deadlines and a durable fence."""

    def __init__(
        self,
        verification_key_pem,
        *,
        clock: Clock,
        minimum_revision=None,
        minimum_policy_digest=None,
        durable_commit=None,
        require_durable=True,
    ):
        if type(clock) is not Clock:
            raise TypeError("clock must be the exact core Clock")
        if (minimum_revision is None) != (minimum_policy_digest is None) or (
            minimum_revision is not None
            and (
                type(minimum_revision) is not int
                or minimum_revision < 1
                or type(minimum_policy_digest) is not str
                or not _HEX64.fullmatch(minimum_policy_digest)
            )
        ):
            raise ValueError("minimum revision and digest must be a valid pair")
        if type(require_durable) is not bool:
            raise TypeError("require_durable must be bool")
        if durable_commit is not None and not callable(durable_commit):
            raise TypeError("durable_commit must be synchronous callable")
        if require_durable and durable_commit is None:
            raise ValueError("production channel policy store requires durable_commit")
        self.clock = clock
        self._key = _verification_key(verification_key_pem)
        self._signer_hash = public_key_sha256(self._key)
        self._minimum_revision = minimum_revision
        self._minimum_digest = minimum_policy_digest
        self._commit = durable_commit
        self._require_durable = require_durable
        self._view = None
        self._faulted = False
        self._installing = False
        self._lock = threading.RLock()

    def install(self, encoded: bytes) -> ChannelPolicyView:
        with self._lock:
            if self._installing:
                raise SnapshotError(
                    "reentrant channel policy installation is forbidden"
                )
            if self._faulted:
                raise SnapshotError("durable channel policy state is faulted")
            self._installing = True
            try:
                return self._install_locked(encoded)
            finally:
                self._installing = False

    def _install_locked(self, encoded):
        if (
            type(encoded) is not bytes
            or not 1 <= len(encoded) <= MAX_CHANNEL_POLICY_BYTES
        ):
            raise SnapshotError("channel policy exceeds its byte bound")
        try:
            envelope = json.loads(
                encoded.decode("utf-8", "strict"),
                object_pairs_hook=_pairs,
                parse_constant=_constant,
            )
        except SnapshotError:
            raise
        except (UnicodeError, ValueError, TypeError, RecursionError) as error:
            raise SnapshotError("channel policy envelope is malformed") from error
        if (
            type(envelope) is not dict
            or set(envelope) != {"payload", "signature"}
            or canonical_json(envelope) != encoded
        ):
            raise SnapshotError(
                "channel policy envelope is noncanonical or has unknown fields"
            )
        payload = envelope["payload"]
        if type(payload) is not dict:
            raise SnapshotError("channel policy payload must be an object")
        revision, issued, expires, gateways, workers, routes = _validate_payload(
            payload, self._signer_hash
        )
        canonical = canonical_json(payload)
        signature_text = envelope["signature"]
        if type(signature_text) is not str or len(signature_text) > 128:
            raise SnapshotError("channel policy signature is malformed")
        try:
            signature = base64.b64decode(signature_text, validate=True)
            if base64.b64encode(signature).decode("ascii") != signature_text:
                raise ValueError("noncanonical base64")
            r, s = decode_dss_signature(signature)
            order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
            if (
                not (1 <= r < order and 1 <= s <= order // 2)
                or encode_dss_signature(r, s) != signature
            ):
                raise ValueError("noncanonical ECDSA signature")
            self._key.verify(signature, DOMAIN + canonical, ec.ECDSA(hashes.SHA256()))
        except (ValueError, InvalidSignature) as error:
            raise SnapshotError(
                "channel policy signature is invalid or noncanonical"
            ) from error
        digest = hashlib.sha256(canonical).hexdigest()
        if self._minimum_revision is not None and (
            revision < self._minimum_revision
            or (revision == self._minimum_revision and digest != self._minimum_digest)
        ):
            raise SnapshotError(
                "channel policy is below or conflicts with configured minimum"
            )
        previous = self._view
        if previous is not None and (
            revision < previous.revision or issued < previous.issued_at
        ):
            raise SnapshotError("channel policy rollback detected")
        if (
            previous is not None
            and revision == previous.revision
            and canonical != previous.canonical_payload
        ):
            raise SnapshotError("channel policy revision equivocation")
        sample = self.clock.sample()
        if previous is not None:
            previous = self._clip_live_view(previous, sample)
        if issued > sample.earliest_wall or expires <= sample.latest_wall:
            raise SnapshotError("channel policy is not currently valid")
        deadline = sample.monotonic + (expires - sample.latest_wall)
        if previous is not None and previous.expires_at == expires:
            deadline = min(deadline, previous.deadline_monotonic)
        if previous is not None and revision == previous.revision:
            if deadline <= sample.monotonic:
                raise SnapshotError("channel policy expired")
            # Same signed payload is idempotent; it cannot recommit or extend its lease.
            return previous
        if self._commit is None and self._require_durable:
            raise SnapshotError("durable channel policy hook is unavailable")
        frozen_gateways = MappingProxyType(
            {
                k: MappingProxyType(
                    {
                        "serial": v[0],
                        "certificate_sha256": v[1],
                        "public_key_sha256": v[2],
                        "not_before": v[3],
                        "not_after": v[4],
                        "endpoint_host": next(
                            x["endpoint_host"]
                            for x in payload["gateways"]
                            if x["gateway_id"] == k
                        ),
                        "endpoint_port": next(
                            x["endpoint_port"]
                            for x in payload["gateways"]
                            if x["gateway_id"] == k
                        ),
                    }
                )
                for k, v in gateways.items()
            }
        )
        frozen_workers = MappingProxyType(
            {
                k: MappingProxyType(
                    {
                        "account_id": v[0],
                        "host_serial": v[1],
                        "host_credential_epoch": v[2],
                        "host_certificate_sha256": v[3],
                        "assignment_id": v[4],
                        "model_id": v[5],
                        "channel_serial": v[6],
                        "channel_certificate_sha256": v[7],
                        "channel_public_key_sha256": v[8],
                        "not_before": v[9],
                        "not_after": v[10],
                        "gateway_id": v[11],
                    }
                )
                for k, v in workers.items()
            }
        )
        prepared_view = ChannelPolicyView(
            revision,
            issued,
            expires,
            digest,
            deadline,
            sample.monotonic,
            frozen_gateways,
            frozen_workers,
            routes,
            canonical,
        )
        durable_started = self._commit is not None
        if durable_started:
            self._faulted = True
        try:
            if self._commit is not None:
                result = self._commit(encoded, revision, digest)
                if inspect.isawaitable(result) or result is not None:
                    raise SnapshotError(
                        "durable channel policy hook must synchronously return None"
                    )
            sample = self.clock.sample()
            final_deadline = sample.monotonic + (expires - sample.latest_wall)
            final_deadline = min(deadline, final_deadline)
            if previous is not None and previous.expires_at == expires:
                final_deadline = min(final_deadline, previous.deadline_monotonic)
            if (
                issued > sample.earliest_wall
                or expires <= sample.latest_wall
                or sample.monotonic >= final_deadline
            ):
                raise SnapshotError("channel policy expired during commit")
            if previous is not None and revision <= previous.revision:
                raise SnapshotError("channel policy changed during durable commit")
            view = ChannelPolicyView(
                prepared_view.revision,
                prepared_view.issued_at,
                prepared_view.expires_at,
                prepared_view.policy_digest,
                final_deadline,
                sample.monotonic,
                prepared_view.gateways,
                prepared_view.workers,
                prepared_view.routes,
                prepared_view.canonical_payload,
            )
            self._publish_view(view)
            self._faulted = False
            return view
        except BaseException as error:
            if durable_started:
                self._faulted = True
            if isinstance(error, SnapshotError):
                raise
            raise SnapshotError(
                "channel policy commit or publication failed"
            ) from error

    def _publish_view(self, view: ChannelPolicyView) -> None:
        self._view = view

    def current(self) -> ChannelPolicyView:
        view, _sample = self.current_with_sample()
        return view

    def current_with_sample(self) -> tuple[ChannelPolicyView, ClockSample]:
        """Return the live view and the exact clock sample that accepted it."""
        with self._lock:
            if self._installing:
                raise SnapshotError("channel policy is unavailable during installation")
            if self._faulted or self._view is None:
                raise SnapshotError("no live channel policy is installed")
            sample = self.clock.sample()
            view = self._clip_live_view(self._view, sample)
            if (
                sample.latest_wall >= view.expires_at
                or sample.monotonic >= view.deadline_monotonic
            ):
                raise SnapshotError("channel policy has expired")
            return view, sample

    def _clip_live_view(self, view: ChannelPolicyView, sample) -> ChannelPolicyView:
        if sample.monotonic < view.published_monotonic:
            raise SnapshotError("clock sample predates channel policy publication")
        candidate = sample.monotonic + (view.expires_at - sample.latest_wall)
        clipped = min(view.deadline_monotonic, candidate)
        if clipped != view.deadline_monotonic:
            try:
                view = ChannelPolicyView(
                    view.revision,
                    view.issued_at,
                    view.expires_at,
                    view.policy_digest,
                    clipped,
                    view.published_monotonic,
                    view.gateways,
                    view.workers,
                    view.routes,
                    view.canonical_payload,
                )
            except BaseException as error:
                self._faulted = True
                raise SnapshotError(
                    "channel policy deadline clipping failed closed"
                ) from error
            self._view = view
        return view
