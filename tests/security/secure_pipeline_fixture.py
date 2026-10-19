"""Ephemeral operator fixture for the opt-in secure pipeline integration test.

This module deliberately uses the actual C0 invitation, certificate and signed
snapshot APIs. It is test-only: the CA and signing keys are kept under a private
temporary directory and are never passed to a running participant component.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import math
import os
from pathlib import Path
import stat
import tempfile
import time
from collections.abc import Mapping
from types import MappingProxyType

from steamboat_security import (
    Clock,
    InvitationRegistry,
    SnapshotStore,
    create_invitation,
    enroll_invited,
    generate_authorization_signing_key_pem,
    generate_ca,
    generate_private_key_pem,
    make_csr,
    new_boot_id,
    new_id,
    sign_snapshot,
    snapshot_public_key_pem,
)
from steamboat_security.codec import WORKER_SERVICE
from steamboat_runtime.remote_client import SERVICE as COORDINATOR_SERVICE


LOOPBACK_IP = "127.0.0.1"
_PRINCIPAL_NAMES = frozenset({
    "coordinator", "consumer", "worker-1", "worker-2", "worker-3",
})
WORKER_METHODS = (
    "Describe", "OpenSession", "RenewSession", "Step",
    "CloseSession", "CancelSession", "SessionStatus",
)
COORDINATOR_METHODS = ("Describe", "Tokenize", "Generate")


@dataclass(frozen=True)
class Principal:
    name: str
    account_id: str
    device_id: str
    role: str
    boot_id: str
    assignment_id: str | None
    private_key_pem: bytes
    certificate_pem: bytes
    record: dict


class SecurePipelineIdentityFixture:
    """Create one short-lived actual signed authority view for a local harness."""

    def __init__(self, model_id: str, *,
                 ip_sans_by_principal: Mapping[str, tuple[str, ...] | list[str]] | None = None,
                 clock_uncertainty_seconds: int | float = 0.0,
                 leaf_lifetime_seconds: int = 900):
        if (type(leaf_lifetime_seconds) is not int
                or not 60 <= leaf_lifetime_seconds <= 900):
            raise ValueError("leaf lifetime must be an exact integer from 60 to 900 seconds")
        self.ip_sans_by_principal = self._validate_ip_sans(ip_sans_by_principal)
        self._clock_uncertainty_seconds = self._validate_clock_uncertainty(
            clock_uncertainty_seconds)
        self._leaf_lifetime_seconds = leaf_lifetime_seconds
        self._issuance_backdate_seconds = (
            self._clock_uncertainty_seconds + 1.0
            if self._clock_uncertainty_seconds > 0 else 0.0)
        self._temporary = tempfile.TemporaryDirectory(
            prefix="steamboat-secure-pipeline-")
        self.root = Path(self._temporary.name)
        try:
            self._initialize(model_id)
        except BaseException as primary:
            # The temporary directory is a resource even when a later key,
            # certificate, invitation or snapshot step fails.  Do not rely on
            # TemporaryDirectory finalization for partial fixture creation.
            try:
                self.close()
            except BaseException as cleanup:
                raise BaseExceptionGroup(
                    "identity fixture initialization and cleanup failed",
                    [primary, cleanup])
            raise

    @staticmethod
    def _validate_ip_sans(value: Mapping | None):
        normalized = {name: (LOOPBACK_IP,) for name in _PRINCIPAL_NAMES}
        if value is None:
            return MappingProxyType(normalized)
        if not isinstance(value, Mapping):
            raise TypeError("IP SAN overrides must be a mapping")
        try:
            entries = tuple(value.items())
        except Exception as error:
            raise TypeError("IP SAN overrides could not be read") from error
        for principal, addresses in entries:
            if type(principal) is not str:
                raise TypeError("IP SAN override principal names must be strings")
            if principal not in _PRINCIPAL_NAMES:
                raise ValueError("IP SAN override names an unknown principal")
            if type(addresses) not in (tuple, list):
                raise TypeError("each IP SAN override must be a tuple or list")
            if not 1 <= len(addresses) <= 4:
                raise ValueError("each principal requires one to four IP SANs")
            canonical = []
            for address in addresses:
                if type(address) is not str:
                    raise TypeError("IP SAN values must be strings")
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError as error:
                    raise ValueError("IP SAN values must be canonical numeric IPv4") from error
                if (not isinstance(parsed, ipaddress.IPv4Address)
                        or str(parsed) != address):
                    raise ValueError("IP SAN values must be canonical numeric IPv4")
                if parsed.is_unspecified or parsed.is_multicast:
                    raise ValueError("unspecified and multicast IP SANs are forbidden")
                canonical.append(address)
            if len(set(canonical)) != len(canonical):
                raise ValueError("duplicate IP SANs are forbidden")
            normalized[principal] = tuple(canonical)
        return MappingProxyType(normalized)

    @staticmethod
    def _validate_clock_uncertainty(value: int | float) -> float:
        if type(value) not in (int, float):
            raise TypeError("clock uncertainty must be a finite number, not bool")
        try:
            uncertainty = float(value)
        except OverflowError as error:
            raise ValueError("clock uncertainty is outside the finite numeric range") from error
        if not math.isfinite(uncertainty) or not 0 <= uncertainty <= 30:
            raise ValueError("clock uncertainty must be finite and between zero and 30")
        return uncertainty

    @property
    def clock_uncertainty_seconds(self) -> float:
        return self._clock_uncertainty_seconds

    def _issuance_time(self) -> int:
        return int(time.time() - self._issuance_backdate_seconds)

    def _initialize(self, model_id: str) -> None:
        if os.name == "posix":
            os.chmod(self.root, 0o700)
            if stat.S_IMODE(self.root.stat().st_mode) != 0o700:
                raise RuntimeError("temporary identity directory is not mode 0700")

        self.model_id = model_id
        ca_start_backdate = max(30.0, self._issuance_backdate_seconds + 1.0)
        self.cohort_ca_pem, ca_private_key = generate_ca(
            common_name="nonproduction secure pipeline cohort",
            now=datetime.now(timezone.utc) - timedelta(seconds=ca_start_backdate),
            lifetime_days=2)
        self._write_private("cohort-ca.key.pem", ca_private_key)

        enrollment_key = generate_authorization_signing_key_pem()
        self._write_private("enrollment-authority.key.pem", enrollment_key)
        snapshot_key = generate_authorization_signing_key_pem()
        self._write_private("snapshot-signing-root.key.pem", snapshot_key)
        self.snapshot_verification_key_pem = snapshot_public_key_pem(snapshot_key)

        coordinator_account = new_id("acct")
        definitions = [
            ("coordinator", coordinator_account, new_id("dev"),
             "personal_coordinator", new_boot_id(), None),
            ("consumer", coordinator_account, new_id("dev"),
             "consumer", new_boot_id(), None),
        ]
        for index in (1, 2, 3):
            definitions.append((
                f"worker-{index}", new_id("acct"), new_id("dev"),
                "host", new_boot_id(), new_id("asg")))

        uncertainty = self._clock_uncertainty_seconds
        enrollment_clock = Clock.system(
            uncertainty_seconds=lambda captured=uncertainty: captured)
        registry = InvitationRegistry(
            verification_key_pem=snapshot_public_key_pem(enrollment_key),
            clock=enrollment_clock)
        self.principals: dict[str, Principal] = {}
        credentials = []
        for name, account_id, device_id, role, boot_id, assignment_id in definitions:
            private_key = generate_private_key_pem()
            self._write_private(f"{name}.role.key.pem", private_key)
            csr = make_csr(private_key, account_id=account_id,
                           device_id=device_id, role=role,
                           ip_sans=self.ip_sans_by_principal[name])
            invited_at = self._issuance_time()
            invitation = create_invitation(
                enrollment_key, account_id=account_id, device_id=device_id,
                roles=(role,), now=invited_at, lifetime_seconds=120)
            leaves, records = enroll_invited(
                invitation_registry=registry,
                invitation=invitation,
                csr_by_role={role: csr},
                ca_certificate_pem=self.cohort_ca_pem,
                ca_private_key_pem=ca_private_key,
                now=self._issuance_time(),
                leaf_lifetime_seconds=self._leaf_lifetime_seconds)
            certificate_pem = leaves[role]
            record = records[0]
            self.principals[name] = Principal(
                name=name, account_id=account_id, device_id=device_id,
                role=role, boot_id=boot_id, assignment_id=assignment_id,
                private_key_pem=private_key, certificate_pem=certificate_pem,
                record=record)
            credentials.append(record)
            self._write_public(f"{name}.role.crt.pem", certificate_pem)

        # The participant-side test objects receive only their role key and
        # certificate. Keep the CA key operator-only and drop its in-memory copy.
        ca_private_key = None
        self._build_signed_snapshot(credentials, snapshot_key)
        enrollment_key = None
        snapshot_key = None
        registry = None

    def _write_private(self, name: str, value: bytes) -> None:
        path = self.root / name
        if os.name == "posix":
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            stream_context = os.fdopen(descriptor, "wb")
        else:
            # Windows protects this file through the private TemporaryDirectory
            # ACL; POSIX mode bits are applied and checked only on Linux.
            stream_context = path.open("xb")
        with stream_context as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            info = path.stat(follow_symlinks=False)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise RuntimeError("temporary private key did not retain mode 0600")

    def _write_public(self, name: str, value: bytes) -> None:
        path = self.root / name
        with path.open("xb") as stream:
            stream.write(value)

    def _build_signed_snapshot(self, credentials: list[dict], snapshot_key: bytes) -> None:
        issued_at = self._issuance_time()
        expires_at = issued_at + 300
        grant_before = issued_at
        grant_after = expires_at
        coordinator = self.principals["coordinator"]
        consumer = self.principals["consumer"]
        grants = []

        for index in (1, 2, 3):
            host = self.principals[f"worker-{index}"]
            for method in WORKER_METHODS:
                grants.append(self._grant(
                    actor=coordinator, target=host,
                    tenant_account_id=coordinator.account_id,
                    target_boot_id=host.boot_id,
                    actor_boot_id=coordinator.boot_id,
                    assignment_id=host.assignment_id,
                    method=f"{WORKER_SERVICE}/{method}",
                    not_before=grant_before, not_after=grant_after))
        for method in COORDINATOR_METHODS:
            grants.append(self._grant(
                actor=consumer, target=coordinator,
                tenant_account_id=consumer.account_id,
                target_boot_id=coordinator.boot_id,
                actor_boot_id=None, assignment_id=None,
                method=f"{COORDINATOR_SERVICE}/{method}",
                not_before=grant_before, not_after=grant_after))

        payload = {
            "version": 1,
            "revision": 1,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "revoked_serials": [],
            "revoked_devices": [],
            "credentials": credentials,
            "grants": grants,
        }
        self.signed_snapshot = sign_snapshot(payload, snapshot_key)

    def _grant(self, *, actor: Principal, target: Principal,
               tenant_account_id: str, target_boot_id: str,
               actor_boot_id: str | None, assignment_id: str | None,
               method: str, not_before: int, not_after: int) -> dict:
        actor_record = actor.record
        target_record = target.record
        return {
            "account_id": actor.account_id,
            "device_id": actor.device_id,
            "role": actor.role,
            "actor_serial": actor_record["serial"],
            "actor_public_key_sha256": actor_record["public_key_sha256"],
            "actor_credential_epoch": actor_record["credential_epoch"],
            "tenant_account_id": tenant_account_id,
            "target_account_id": target.account_id,
            "target_device_id": target.device_id,
            "target_role": target.role,
            "target_serial": target_record["serial"],
            "target_public_key_sha256": target_record["public_key_sha256"],
            "target_credential_epoch": target_record["credential_epoch"],
            "target_boot_id": target_boot_id,
            "actor_boot_id": actor_boot_id,
            "assignment_id": assignment_id,
            "model_id": self.model_id,
            "method": method,
            "not_before": not_before,
            "not_after": not_after,
        }

    def new_store(self) -> tuple[SnapshotStore, Clock]:
        """Build an independent verifier and fresh real host clock for one role."""
        uncertainty = self._clock_uncertainty_seconds
        clock = Clock.system(
            uncertainty_seconds=lambda captured=uncertainty: captured)
        store = SnapshotStore(
            verification_key_pem=self.snapshot_verification_key_pem,
            ca_certificate_pem=self.cohort_ca_pem,
            clock=clock)
        store.install(self.signed_snapshot)
        return store, clock

    def close(self) -> None:
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            temporary.cleanup()
            self._temporary = None
