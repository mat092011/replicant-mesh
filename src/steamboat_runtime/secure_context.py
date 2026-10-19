"""Secure client context construction and bounded worker bootstrap delegation.

The consumer factory only accepts a live core Authorization returned by the
incoming coordinator authorizer.  The worker wrapper only forwards an explicit
trusted context, except for a finite Describe-only BootstrapContext minted by
the outbound identity adapter.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import math
import threading
import time
import weakref
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Protocol

from steamboat_security.authorization import (
    Authorization,
    Authorizer,
    LocalIdentity,
    VerifiedCredential,
)
from steamboat_security.codec import Binding, COORDINATOR_SERVICE, WORKER_METHODS
from steamboat_security.errors import ScopeError
from steamboat_security.ids import new_id, validate_boot, validate_id
from steamboat_security.outbound import BootstrapContext
from steamboat_security.snapshot import Grant

from .participant_context import (
    TrustedRequestContext,
    TrustedRequestContextError,
)
from .remote_client import RemoteError, validate_generate


MAX_CONSUMER_CONTEXTS = 4096
DEFAULT_CONSUMER_CONTEXTS = 256


class ConsumerContextAdmissionError(TrustedRequestContextError):
    """The consumer Authorization cannot create trusted coordinator context."""


class ConsumerContextCapacityError(ConsumerContextAdmissionError):
    """The bounded live consumer-context table is full."""


class SecureWorkerClientProtocol(Protocol):
    """Narrow async delegation contract implemented by SecureWorkerClient."""

    async def execute(self, method: str, request: Any, *,
                      trusted_request_context: object | None = None) -> Any: ...

    async def close(self) -> None: ...


@dataclass
class _FactoryRecord:
    authorization_ref: weakref.ReferenceType
    context: TrustedRequestContext | None


def _finite_positive_seconds(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConsumerContextAdmissionError(f"{name} is not a finite positive number")
    try:
        result = float(value)
    except (OverflowError, ValueError):
        raise ConsumerContextAdmissionError(
            f"{name} is not a finite positive number") from None
    if not math.isfinite(result) or result <= 0:
        raise ConsumerContextAdmissionError(f"{name} is expired or invalid")
    return result


def _absolute_monotonic_deadline(value: object) -> float:
    """Validate an externally supplied deadline in this process clock domain."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConsumerContextAdmissionError(
            "absolute deadline is not a finite monotonic timestamp")
    try:
        result = float(value)
    except (OverflowError, ValueError):
        raise ConsumerContextAdmissionError(
            "absolute deadline is not a finite monotonic timestamp") from None
    if not math.isfinite(result):
        raise ConsumerContextAdmissionError(
            "absolute deadline is not a finite monotonic timestamp")
    return result


def _call_live(authorization: Authorization) -> float:
    try:
        asserted = authorization.assert_live()
        if asserted is not None and asserted is not True:
            raise ConsumerContextAdmissionError(
                "core Authorization assert_live() returned an invalid result")
        remaining = authorization.remaining_seconds()
    except ConsumerContextAdmissionError:
        raise
    except Exception as error:
        raise ConsumerContextAdmissionError(
            "core consumer Authorization is no longer live") from error
    return _finite_positive_seconds(remaining, "consumer Authorization lifetime")


def _canonical_generate_payload(payload: object, name: str) -> bytes:
    if type(payload) is not dict:
        raise ConsumerContextAdmissionError(f"{name} must be the admitted JSON object")
    try:
        validate_generate(payload)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (RemoteError, TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise ConsumerContextAdmissionError(
            f"{name} does not satisfy remote Generate validation") from error


class ConsumerContextFactory:
    """Create one real TrustedRequestContext per live admitted Generate.

    Call ``release(context)`` in the secure handler's ``finally`` block after
    the coordinator has completed request cleanup.  Release drops the retained
    context but keeps a weak one-use marker while the core Authorization is
    still live.  Terminal/deallocated authorizations are pruned; live entries
    are never evicted to make room for new work.
    """

    def __init__(self, *, account_id: str, device_id: str,
                 coordinator_boot_id: str, model_id: str,
                 max_contexts: int = DEFAULT_CONSUMER_CONTEXTS,
                 monotonic=time.monotonic):
        validate_id(account_id, "acct")
        validate_id(device_id, "dev")
        validate_boot(coordinator_boot_id)
        if (type(model_id) is not str or len(model_id) != 64
                or any(character not in "0123456789abcdef" for character in model_id)):
            raise ValueError("model_id must be a lowercase SHA-256 fingerprint")
        if (type(max_contexts) is not int
                or not 1 <= max_contexts <= MAX_CONSUMER_CONTEXTS):
            raise ValueError("consumer context bound is invalid")
        if not callable(monotonic):
            raise ValueError("monotonic must be a callable in the process monotonic domain")
        self.account_id = account_id
        self.device_id = device_id
        self.coordinator_boot_id = coordinator_boot_id
        self.model_id = model_id
        self.max_contexts = max_contexts
        self._monotonic = monotonic
        self._lock = threading.RLock()
        self._last_monotonic: float | None = None
        self._clock_faulted = False
        self._records: OrderedDict[int, _FactoryRecord] = OrderedDict()
        self._context_index: dict[int, int] = {}

    def _sample_monotonic(self) -> float:
        try:
            value = self._monotonic()
        except Exception as error:
            with self._lock:
                self._clock_faulted = True
            raise ConsumerContextAdmissionError(
                "factory monotonic clock is unavailable") from error
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or value < 0):
            with self._lock:
                self._clock_faulted = True
            raise ConsumerContextAdmissionError(
                "factory monotonic clock sample is invalid")
        sample = float(value)
        with self._lock:
            if self._clock_faulted:
                raise ConsumerContextAdmissionError(
                    "factory monotonic clock requires trusted reinitialization")
            if self._last_monotonic is not None and sample < self._last_monotonic:
                self._clock_faulted = True
                raise ConsumerContextAdmissionError(
                    "factory monotonic clock moved backwards")
            self._last_monotonic = sample
        return sample

    @staticmethod
    def _terminal(authorization: Authorization) -> bool:
        return (getattr(authorization, "_finished", None) is True
                or getattr(authorization, "_failed", None) is True)

    def _prune_locked(self) -> None:
        remove = []
        for auth_id, record in self._records.items():
            authorization = record.authorization_ref()
            if authorization is None or self._terminal(authorization):
                remove.append(auth_id)
        for auth_id in remove:
            record = self._records.pop(auth_id)
            if record.context is not None:
                self._context_index.pop(id(record.context), None)

    def _validate_authorization(self, authorization: object,
                                payload: object) -> tuple[str, float, float]:
        if type(authorization) is not Authorization:
            raise ConsumerContextAdmissionError(
                "factory requires the actual core Authorization type")
        if type(getattr(authorization, "_finished", None)) is not bool or type(
                getattr(authorization, "_failed", None)) is not bool:
            raise ConsumerContextAdmissionError("core Authorization state is invalid")
        if authorization._finished or authorization._failed:
            raise ConsumerContextAdmissionError("core Authorization is closed or failed")
        if type(authorization.binding) is not Binding:
            raise ConsumerContextAdmissionError("core Authorization binding is invalid")
        if (authorization.binding.service != COORDINATOR_SERVICE
                or authorization.binding.method != "Generate"):
            raise ConsumerContextAdmissionError(
                "only an admitted Coordinator Generate can create consumer context")
        if (type(authorization.actor) is not VerifiedCredential
                or type(authorization.local) is not VerifiedCredential
                or type(authorization.grant) is not Grant):
            raise ConsumerContextAdmissionError(
                "Authorization lacks verified endpoint and grant records")
        actor, local, grant = (authorization.actor, authorization.local,
                               authorization.grant)
        if (actor.role != "consumer" or actor.account_id != self.account_id
                or local.role != "personal_coordinator"
                or local.account_id != self.account_id
                or local.device_id != self.device_id):
            raise ScopeError("Authorization roles or configured local coordinator differ")

        core_authorizer = getattr(authorization, "_authorizer", None)
        if type(core_authorizer) is not Authorizer:
            raise ConsumerContextAdmissionError(
                "Authorization was not issued by the core Authorizer")
        local_identity = getattr(core_authorizer, "local_identity", None)
        if type(local_identity) is not LocalIdentity:
            raise ConsumerContextAdmissionError("local core identity is invalid")
        if (local_identity.boot_id != self.coordinator_boot_id
                or local_identity.model_id != self.model_id
                or local_identity.assignment_id is not None
                or authorization.model_id != self.model_id
                or local_identity.certificate_pem != local.certificate_pem):
            raise ScopeError("Authorization target boot, model, or local leaf differs")

        fields = authorization.binding
        expected_binding = {
            "account_id": actor.account_id,
            "device_id": actor.device_id,
            "role": actor.role,
            "credential_epoch": actor.credential_epoch,
            "target_device_id": local.device_id,
        }
        if any(fields.get(name) != value for name, value in expected_binding.items()):
            raise ScopeError("Generate binding does not match its verified actor and target")
        request_id = fields.get("request_id")
        try:
            validate_id(request_id, "req")
        except (TypeError, ValueError) as error:
            raise ConsumerContextAdmissionError(
                "authenticated Generate binding has no valid request ID") from error

        exact_grant = (
            grant.account_id == actor.account_id
            and grant.device_id == actor.device_id
            and grant.role == "consumer"
            and grant.actor_serial == actor.serial
            and grant.actor_public_key_sha256 == actor.public_key_sha256
            and grant.actor_credential_epoch == actor.credential_epoch
            and grant.tenant_account_id == actor.account_id
            and grant.target_account_id == local.account_id
            and grant.target_device_id == local.device_id
            and grant.target_role == "personal_coordinator"
            and grant.target_serial == local.serial
            and grant.target_public_key_sha256 == local.public_key_sha256
            and grant.target_credential_epoch == local.credential_epoch
            and grant.target_boot_id == self.coordinator_boot_id
            and grant.actor_boot_id is None
            and grant.assignment_id is None
            and grant.model_id == self.model_id
            and grant.method == f"{COORDINATOR_SERVICE}/Generate"
        )
        if not exact_grant:
            raise ScopeError("Generate authorization lacks the exact current personal grant")

        admitted = _canonical_generate_payload(
            authorization.payload, "Authorization payload")
        supplied = _canonical_generate_payload(payload, "supplied payload")
        if admitted != supplied:
            raise ConsumerContextAdmissionError(
                "supplied Generate payload differs from the admitted Authorization payload")
        remaining = _call_live(authorization)
        timeout = float(payload["timeout_seconds"])
        return request_id, timeout, remaining

    def __call__(self, authorization: object,
                 payload: object) -> TrustedRequestContext:
        """Keep the direct-call API, deriving its deadline at admission time."""
        return self._create_context(authorization, payload)

    def create_with_deadline(self, authorization: object, payload: object, *,
                             absolute_deadline: object) -> TrustedRequestContext:
        """Create context bounded by a server deadline measured at receive time.

        The absolute deadline must use this process's monotonic clock domain.
        It is checked before authority validation and again immediately before
        the one-use record is committed.  No deadline is rebased after receipt.
        """
        deadline_cap = _absolute_monotonic_deadline(absolute_deadline)
        started = self._sample_monotonic()
        if deadline_cap <= started:
            raise ConsumerContextAdmissionError(
                "server request deadline has expired")
        return self._create_context(
            authorization, payload, absolute_deadline=deadline_cap,
            started=started)

    def _create_context(self, authorization: object, payload: object, *,
                        absolute_deadline: float | None = None,
                        started: float | None = None) -> TrustedRequestContext:
        # Start before rechecking core liveness. Mapping the returned duration
        # from this earlier sample is conservative and cannot extend the core
        # Authorization deadline by the validation work itself.
        if started is None:
            started = self._sample_monotonic()
        request_id, timeout, remaining = self._validate_authorization(
            authorization, payload)
        deadlines = [started + timeout, started + remaining]
        if absolute_deadline is not None:
            deadlines.append(absolute_deadline)
        deadline = min(deadlines)
        if not math.isfinite(deadline) or deadline <= self._sample_monotonic():
            raise ConsumerContextAdmissionError("Generate authorization deadline expired")

        # Construct without reserving a table slot so malformed/expired context
        # creation cannot consume capacity. The lock below makes the one-use
        # check and successful insertion atomic across concurrent callers.
        context = TrustedRequestContext(
            tenant_account_id=authorization.actor.account_id,
            request_id=request_id,
            session_id=new_id("ses"),
            route_id=new_id("route"),
            coordinator_boot_id=self.coordinator_boot_id,
            route_epoch=1,
            attempt=1,
            authorization=authorization,
            hard_monotonic_deadline=deadline,
        )
        try:
            context.assert_data_live()
        except Exception as error:
            raise ConsumerContextAdmissionError(
                "consumer context expired during construction") from error

        with self._lock:
            self._prune_locked()
            auth_id = id(authorization)
            existing = self._records.get(auth_id)
            if existing is not None and existing.authorization_ref() is authorization:
                raise ConsumerContextAdmissionError(
                    "core Authorization has already created a trusted context")
            if len(self._records) >= self.max_contexts:
                raise ConsumerContextCapacityError(
                    "bounded live consumer context table is full")
            if self._terminal(authorization):
                raise ConsumerContextAdmissionError(
                    "core Authorization closed during context construction")
            try:
                # Check the authorities after any construction delay, then make
                # the final deadline sample immediately before committing.
                _call_live(authorization)
                context.assert_data_live()
                if self._sample_monotonic() >= context.hard_monotonic_deadline:
                    raise ConsumerContextAdmissionError(
                        "Generate request deadline expired during construction")
                # No context is retained when current grant, revocation,
                # credentials, or deadline validation fails at commit.
            except ConsumerContextAdmissionError:
                raise
            except Exception as error:
                raise ConsumerContextAdmissionError(
                    "core Authorization expired before context admission") from error
            record = _FactoryRecord(weakref.ref(authorization), context)
            self._records[auth_id] = record
            self._context_index[id(context)] = auth_id
        return context

    def release(self, context: TrustedRequestContext) -> None:
        """Drop the retained context after coordinator cleanup, keeping one-use fencing."""
        if type(context) is not TrustedRequestContext:
            raise ConsumerContextAdmissionError(
                "release requires a context issued by this factory")
        with self._lock:
            auth_id = self._context_index.get(id(context))
            record = self._records.get(auth_id) if auth_id is not None else None
            if record is None or record.context is not context:
                authorization = getattr(context, "authorization", None)
                prior = (self._records.get(id(authorization))
                         if type(authorization) is Authorization else None)
                if (prior is not None
                        and prior.authorization_ref() is authorization
                        and prior.context is None):
                    return
                if (type(authorization) is Authorization
                        and self._terminal(authorization)):
                    return
                raise ConsumerContextAdmissionError(
                    "context is not retained by this factory or was already released")
            record.context = None
            self._context_index.pop(id(context), None)
            self._prune_locked()


class BootstrapWorkerClient:
    """Add finite Describe-only bootstrap context to a secure worker client.

    The delegated client must implement ``SecureWorkerClientProtocol`` and
    enforce ``trusted_request_context`` through ``OutboundAuthorizer``. This
    wrapper does not implement transport security, identity verification, or
    retry behavior.
    """

    def __init__(self, client: SecureWorkerClientProtocol,
                 bootstrap_context: BootstrapContext):
        if not callable(getattr(client, "execute", None)) or not callable(
                getattr(client, "close", None)):
            raise TypeError("client must implement the secure worker client protocol")
        if type(bootstrap_context) is not BootstrapContext:
            raise TypeError("bootstrap_context must be an adapter-issued BootstrapContext")
        self._client = client
        self._bootstrap_context = bootstrap_context
        # Closing and closed are separate states.  Once closing starts, calls
        # are fenced immediately; if delegated cleanup fails or is cancelled,
        # another close() can retry the same delegated operation.
        self._closing = False
        self._closed = False
        self._close_lock = asyncio.Lock()
        self._close_kind: str | None = None
        self._close_args: tuple[Any, ...] = ()

    async def execute(self, method: str, request: Any, *,
                      trusted_request_context: object | None = None) -> Any:
        if self._closing or self._closed:
            raise ScopeError("secure worker client wrapper is closing or closed")
        if type(method) is not str or method not in WORKER_METHODS:
            raise ScopeError("Worker method is not an exact v1 wire name")
        context = trusted_request_context
        if context is None:
            if method != "Describe":
                raise ScopeError(
                    "context-free worker calls are limited to bootstrap Describe")
            context = self._bootstrap_context
        return await self._client.execute(
            method, request, trusted_request_context=context)

    async def close(self) -> None:
        await self._finish_close("close", ())

    async def _finish_close(self, kind: str, args: tuple[Any, ...]):
        if self._closed:
            return False
        if not self._closing:
            self._closing = True
            self._close_kind = kind
            self._close_args = args

        # Keep the original operation and arguments after failure/cancellation.
        # A later close() therefore retries the same delegate cleanup.
        async with self._close_lock:
            if self._closed:
                return False
            if self._close_kind == "exit":
                exit_method = getattr(self._client, "__aexit__", None)
                if callable(exit_method):
                    result = exit_method(*self._close_args)
                    if inspect.isawaitable(result):
                        result = await result
                else:
                    result = self._client.close()
                    if inspect.isawaitable(result):
                        await result
                    result = False
            else:
                result = self._client.close()
                if inspect.isawaitable(result):
                    await result
                result = False
            self._closing = False
            self._closed = True
            return result

    async def __aenter__(self):
        if self._closing or self._closed:
            raise ScopeError("secure worker client wrapper is closing or closed")
        enter = getattr(self._client, "__aenter__", None)
        if callable(enter):
            result = enter()
            if inspect.isawaitable(result):
                await result
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        if self._closed:
            return False
        return await self._finish_close("exit", (exc_type, exc, traceback))


__all__ = [
    "BootstrapWorkerClient",
    "ConsumerContextAdmissionError",
    "ConsumerContextCapacityError",
    "ConsumerContextFactory",
    "SecureWorkerClientProtocol",
]
