"""Validated, in-process consumer context for one coordinator request.

This is a capability object for trusted adapters. It is not a network payload,
and its identifiers do not authenticate a caller. The parent integration must
construct it only after consumer authorization has succeeded.
"""

from dataclasses import dataclass, field
import inspect
import math
import re
import threading
import time


_TYPED_ID = re.compile(r"(?P<prefix>acct|req|ses|route)_[0-9a-f]{32}\Z")
_BOOT_ID = re.compile(r"[0-9a-f]{32}\Z")


class TrustedRequestContextError(ValueError):
    """A trusted request context is malformed, expired, or already consumed."""


class TrustedRequestContextExpired(TrustedRequestContextError):
    """The consumer authorization or its hard monotonic deadline has expired."""


@dataclass
class _Admission:
    lock: object = field(default_factory=threading.Lock)
    claimed: bool = False
    completed: bool = False


def _typed_id(value, prefix, name):
    if type(value) is not str or not _TYPED_ID.fullmatch(value):
        raise ValueError(f"{name} must be a typed 128-bit lowercase-hex ID")
    if not value.startswith(prefix + "_"):
        raise ValueError(f"{name} must use the {prefix}_ ID prefix")


def _positive_finite(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite positive number")
    try:
        result = float(value)
    except (OverflowError, ValueError):
        raise ValueError(f"{name} must be a finite positive number") from None
    if not math.isfinite(result) or result <= 0:
        raise ValueError(f"{name} must be a finite positive number")
    return result


@dataclass(frozen=True, slots=True)
class TrustedRequestContext:
    """Immutable trusted context for one admission and its bounded cleanup.

    ``authorization`` must be the actual consumer Authorization from the
    trusted adapter and expose synchronous ``assert_live()`` and
    ``remaining_seconds()`` methods. There is intentionally no parser or
    factory here: validating IDs is not consumer authentication.
    """

    tenant_account_id: str
    request_id: str
    session_id: str
    route_id: str
    coordinator_boot_id: str
    route_epoch: int
    attempt: int
    authorization: object = field(repr=False, compare=False)
    hard_monotonic_deadline: float
    _admission: _Admission = field(default_factory=_Admission, init=False,
                                   repr=False, compare=False)

    def __post_init__(self):
        _typed_id(self.tenant_account_id, "acct", "tenant_account_id")
        _typed_id(self.request_id, "req", "request_id")
        _typed_id(self.session_id, "ses", "session_id")
        _typed_id(self.route_id, "route", "route_id")
        if type(self.coordinator_boot_id) is not str or not _BOOT_ID.fullmatch(
                self.coordinator_boot_id):
            raise ValueError("coordinator_boot_id must be 32 lowercase hex characters")
        if type(self.route_epoch) is not int or self.route_epoch != 1:
            raise ValueError("route_epoch must be exactly 1")
        if type(self.attempt) is not int or self.attempt != 1:
            raise ValueError("attempt must be exactly 1")
        if not callable(getattr(self.authorization, "assert_live", None)):
            raise ValueError("authorization must expose assert_live()")
        if not callable(getattr(self.authorization, "remaining_seconds", None)):
            raise ValueError("authorization must expose remaining_seconds()")
        deadline = _positive_finite(self.hard_monotonic_deadline,
                                    "hard_monotonic_deadline")
        object.__setattr__(self, "hard_monotonic_deadline", deadline)
        if deadline <= time.monotonic():
            raise TrustedRequestContextExpired("hard monotonic deadline has expired")
        self._authorization_remaining()

    def _authorization_remaining(self):
        value = self.authorization.remaining_seconds()
        if inspect.isawaitable(value):
            close = getattr(value, "close", None)
            if callable(close):
                close()
            raise TrustedRequestContextExpired(
                "authorization remaining_seconds() must be synchronous")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TrustedRequestContextExpired("consumer authorization has expired")
        try:
            result = float(value)
        except (OverflowError, ValueError):
            raise TrustedRequestContextExpired(
                "consumer authorization has an invalid lifetime") from None
        if not math.isfinite(result) or result <= 0:
            raise TrustedRequestContextExpired("consumer authorization has expired")
        return result

    def remaining_seconds(self):
        """Return the smaller authorization/deadline lifetime or fail closed."""
        remaining = min(self.hard_monotonic_deadline - time.monotonic(),
                        self._authorization_remaining())
        if remaining <= 0 or not math.isfinite(remaining):
            raise TrustedRequestContextExpired("trusted request context has expired")
        return remaining

    def assert_data_live(self):
        """Check consumer authorization before Describe/Open/Step/Renew work."""
        try:
            result = self.authorization.assert_live()
        except Exception as error:
            raise TrustedRequestContextExpired(
                "consumer authorization is no longer live") from error
        if inspect.isawaitable(result):
            close = getattr(result, "close", None)
            if callable(close):
                close()
            raise TypeError("authorization assert_live() must be synchronous")
        if result is not None and result is not True:
            raise TypeError("authorization assert_live() must return exactly None or True")
        self.remaining_seconds()

    def claim_admission(self):
        """Claim this capability exactly once before enqueueing coordinator work."""
        with self._admission.lock:
            if self._admission.claimed or self._admission.completed:
                raise TrustedRequestContextError(
                    "trusted request context has already been submitted")
            self._admission.claimed = True

    def complete_admission(self):
        """Mark the one admitted request complete after its cleanup attempt."""
        with self._admission.lock:
            if not self._admission.claimed:
                raise TrustedRequestContextError(
                    "trusted request context was not claimed for admission")
            self._admission.completed = True
