"""Torch-free logical reservations for last-position logit capture.

This module accounts for bounded capture representations. It does not allocate,
inspect, serialize, or reclaim tensors, and it is not a physical memory limit.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Final


PINNED_VOCABULARY_SIZE: Final = 32_000
MAX_CAPTURE_MESSAGE_BYTES: Final = 1_048_576
MAX_OUTPUT_QUEUE_SLOTS: Final = 16
MAX_ACTIVE_CAPTURES: Final = 8
MAX_OWNER_POOL_BYTES: Final = 1 << 30
MIN_TRANSPORT_ALLOCATOR_HEADROOM_BYTES: Final = 64 << 20
MAX_REQUEST_ID_BYTES: Final = 128
MAX_RETAINED_REQUEST_IDS: Final = 65_536


class CaptureBudgetError(Exception):
    """Base class for bounded-capture ledger errors."""


class CaptureConfigurationError(CaptureBudgetError, ValueError):
    """A local capture budget configuration is outside the supported bounds."""


class UnsupportedVocabularyError(CaptureConfigurationError):
    """Capture is supported only for the pinned vocabulary size."""


class CaptureAdmissionError(CaptureBudgetError):
    """A capture reservation could not be admitted."""


class ActiveCaptureLimitError(CaptureAdmissionError):
    """The configured active-capture limit is already reached."""


class CaptureCapacityError(CaptureAdmissionError):
    """The owner-approved logical byte capacity is insufficient."""


class RequestIdCapacityError(CaptureAdmissionError):
    """The bounded request-ID replay history is full."""


class InvalidCaptureRequestIdError(CaptureBudgetError, ValueError):
    """A request ID is not a bounded local identifier."""


class DuplicateCaptureRequestIdError(CaptureAdmissionError):
    """A request ID has already been admitted by this ledger."""


class InvalidCaptureLeaseError(CaptureBudgetError):
    """A lease is unknown to this ledger or belongs to another ledger."""


class InvalidCleanupConfirmationError(CaptureBudgetError, ValueError):
    """Cleanup confirmation must be an explicit boolean."""


@dataclass(frozen=True, slots=True)
class CaptureReservationBreakdown:
    """Per-capture logical reservation, using the frozen C0 representation."""

    vocabulary_size: int
    output_queue_slots: int
    event_limit_bytes: int
    serialized_event_slot_bytes: int
    raw_float32_tensor_slot_bytes: int
    python_float_list_slot_bytes: int
    encoding_copy_bytes: int
    transport_allocator_headroom_bytes: int
    total_bytes: int


@dataclass(frozen=True, slots=True)
class CaptureReservedBreakdown:
    """Aggregate bytes currently retained by active and cleanup-pending leases."""

    serialized_event_slot_bytes: int = 0
    raw_float32_tensor_slot_bytes: int = 0
    python_float_list_slot_bytes: int = 0
    encoding_copy_bytes: int = 0
    transport_allocator_headroom_bytes: int = 0
    total_bytes: int = 0


@dataclass(frozen=True, slots=True)
class CaptureBudgetConfig:
    """Immutable owner-selected bounds for one process-local capture ledger.

    ``capacity_bytes`` is an owner-approved logical pool allocation. This class
    does not prove that the allocation is physically exclusive or enforced.
    """

    vocabulary_size: int = PINNED_VOCABULARY_SIZE
    output_queue_slots: int = MAX_OUTPUT_QUEUE_SLOTS
    max_active_captures: int = MAX_ACTIVE_CAPTURES
    capacity_bytes: int = MAX_OWNER_POOL_BYTES
    transport_allocator_headroom_bytes: int = MIN_TRANSPORT_ALLOCATOR_HEADROOM_BYTES
    max_retained_request_ids: int = 4096

    def __post_init__(self) -> None:
        for name in (
            "vocabulary_size",
            "output_queue_slots",
            "max_active_captures",
            "capacity_bytes",
            "transport_allocator_headroom_bytes",
            "max_retained_request_ids",
        ):
            value = getattr(self, name)
            if type(value) is not int:
                raise CaptureConfigurationError(f"{name} must be an integer")

        if self.vocabulary_size != PINNED_VOCABULARY_SIZE:
            raise UnsupportedVocabularyError("unsupported capture vocabulary")
        if not 0 <= self.output_queue_slots <= MAX_OUTPUT_QUEUE_SLOTS:
            raise CaptureConfigurationError("output queue slots exceed the supported range")
        if not 0 <= self.max_active_captures <= MAX_ACTIVE_CAPTURES:
            raise CaptureConfigurationError("active captures exceed the supported range")
        if not 0 <= self.capacity_bytes <= MAX_OWNER_POOL_BYTES:
            raise CaptureConfigurationError("capacity is outside the supported range")
        if not MIN_TRANSPORT_ALLOCATOR_HEADROOM_BYTES <= self.transport_allocator_headroom_bytes <= MAX_OWNER_POOL_BYTES:
            raise CaptureConfigurationError("transport headroom is below the required minimum or oversized")
        if not 1 <= self.max_retained_request_ids <= MAX_RETAINED_REQUEST_IDS:
            raise CaptureConfigurationError("request-ID history is outside the supported range")


def calculate_capture_reservation(
    config: CaptureBudgetConfig,
) -> CaptureReservationBreakdown:
    """Return the exact per-capture logical reservation without allocating data."""

    if type(config) is not CaptureBudgetConfig:
        raise CaptureConfigurationError("config must be a CaptureBudgetConfig")

    vocabulary = config.vocabulary_size
    queue_slots = config.output_queue_slots
    event_limit = vocabulary * 32 + 4096
    if event_limit > MAX_CAPTURE_MESSAGE_BYTES:
        raise CaptureConfigurationError("last-position event exceeds the unchanged 1 MiB limit")

    serialized = (queue_slots + 2) * event_limit
    raw_float32 = (queue_slots + 2) * (vocabulary * 4 + 512)
    python_objects = 2 * (vocabulary * 32 + 128)
    encoding_copies = 2 * event_limit
    headroom = config.transport_allocator_headroom_bytes
    total = serialized + raw_float32 + python_objects + encoding_copies + headroom
    return CaptureReservationBreakdown(
        vocabulary_size=vocabulary,
        output_queue_slots=queue_slots,
        event_limit_bytes=event_limit,
        serialized_event_slot_bytes=serialized,
        raw_float32_tensor_slot_bytes=raw_float32,
        python_float_list_slot_bytes=python_objects,
        encoding_copy_bytes=encoding_copies,
        transport_allocator_headroom_bytes=headroom,
        total_bytes=total,
    )


class CaptureLease:
    """Opaque, identity-based release capability minted by one ledger."""

    __slots__ = ("__owner",)

    def __init__(self, owner: object, *, _mint: object = None) -> None:
        if _mint is not _LEASE_MINT:
            raise TypeError("CaptureLease values are minted by CaptureBudget.reserve")
        object.__setattr__(self, "_CaptureLease__owner", owner)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("CaptureLease is immutable")

    def __repr__(self) -> str:
        return "<CaptureLease opaque>"

    def __reduce__(self) -> object:
        raise TypeError("CaptureLease cannot be serialized")


_LEASE_MINT = object()


@dataclass(slots=True)
class _Reservation:
    breakdown: CaptureReservationBreakdown
    state: str = "active"


@dataclass(frozen=True, slots=True)
class CaptureBudgetStatus:
    """Payload-free ledger status; no request IDs or lease capabilities are exposed."""

    capacity_bytes: int
    active_captures: int
    cleanup_pending_captures: int
    released_captures: int
    used_request_ids: int
    request_id_capacity: int
    reserved_bytes: int
    available_bytes: int
    per_capture: CaptureReservationBreakdown
    reserved_breakdown: CaptureReservedBreakdown


class CaptureBudget:
    """Thread-safe logical capture ledger; release requires trusted reclamation."""

    __slots__ = (
        "_config",
        "_per_capture",
        "_owner",
        "_lock",
        "_reservations",
        "_used_request_ids",
        "_reserved_bytes",
    )

    def __init__(self, config: CaptureBudgetConfig = CaptureBudgetConfig()) -> None:
        if type(config) is not CaptureBudgetConfig:
            raise CaptureConfigurationError("config must be a CaptureBudgetConfig")
        self._config = config
        self._per_capture = calculate_capture_reservation(config)
        self._owner = object()
        self._lock = Lock()
        self._reservations: dict[CaptureLease, _Reservation] = {}
        self._used_request_ids: set[str] = set()
        self._reserved_bytes = 0

    @property
    def config(self) -> CaptureBudgetConfig:
        return self._config

    @property
    def per_capture(self) -> CaptureReservationBreakdown:
        return self._per_capture

    def reserve(self, request_id: str) -> CaptureLease:
        """Atomically reserve one capture; failed admission retains no ID or bytes."""

        _validate_request_id(request_id)
        with self._lock:
            if request_id in self._used_request_ids:
                raise DuplicateCaptureRequestIdError("capture request ID was already admitted")
            if len(self._used_request_ids) >= self._config.max_retained_request_ids:
                raise RequestIdCapacityError("capture request-ID history is full")
            active = sum(entry.state != "released" for entry in self._reservations.values())
            if active >= self._config.max_active_captures:
                raise ActiveCaptureLimitError("active capture limit reached")
            new_total = self._reserved_bytes + self._per_capture.total_bytes
            if new_total > self._config.capacity_bytes:
                raise CaptureCapacityError("capture reservation exceeds available logical capacity")

            lease = CaptureLease(self._owner, _mint=_LEASE_MINT)
            self._reservations[lease] = _Reservation(self._per_capture)
            self._used_request_ids.add(request_id)
            self._reserved_bytes = new_total
            return lease

    def release(self, lease: CaptureLease, *, buffers_reclaimed: bool) -> bool:
        """Mark cleanup pending or release after explicit trusted reclamation.

        Returns ``True`` when the lease is released (including repeated confirmed
        release), and ``False`` while buffers/compute may still be referenced.
        ``buffers_reclaimed=True`` is a trusted local assertion, never a peer claim.
        """

        if type(buffers_reclaimed) is not bool:
            raise InvalidCleanupConfirmationError("buffers_reclaimed must be an explicit boolean")
        if type(lease) is not CaptureLease or getattr(lease, "_CaptureLease__owner", None) is not self._owner:
            raise InvalidCaptureLeaseError("lease does not belong to this capture ledger")

        with self._lock:
            entry = self._reservations.get(lease)
            if entry is None:
                raise InvalidCaptureLeaseError("lease is unknown to this capture ledger")
            if entry.state == "released":
                return True
            if not buffers_reclaimed:
                entry.state = "cleanup_pending"
                return False
            entry.state = "released"
            self._reserved_bytes -= entry.breakdown.total_bytes
            return True

    def status(self) -> CaptureBudgetStatus:
        """Return bounded aggregate counts and a logical byte breakdown."""

        with self._lock:
            active = 0
            pending = 0
            released = 0
            serialized = 0
            raw_float32 = 0
            python_objects = 0
            encoding = 0
            headroom = 0
            for entry in self._reservations.values():
                if entry.state == "released":
                    released += 1
                    continue
                if entry.state == "cleanup_pending":
                    pending += 1
                else:
                    active += 1
                part = entry.breakdown
                serialized += part.serialized_event_slot_bytes
                raw_float32 += part.raw_float32_tensor_slot_bytes
                python_objects += part.python_float_list_slot_bytes
                encoding += part.encoding_copy_bytes
                headroom += part.transport_allocator_headroom_bytes
            total = serialized + raw_float32 + python_objects + encoding + headroom
            reserved = CaptureReservedBreakdown(
                serialized_event_slot_bytes=serialized,
                raw_float32_tensor_slot_bytes=raw_float32,
                python_float_list_slot_bytes=python_objects,
                encoding_copy_bytes=encoding,
                transport_allocator_headroom_bytes=headroom,
                total_bytes=total,
            )
            return CaptureBudgetStatus(
                capacity_bytes=self._config.capacity_bytes,
                active_captures=active,
                cleanup_pending_captures=pending,
                released_captures=released,
                used_request_ids=len(self._used_request_ids),
                request_id_capacity=self._config.max_retained_request_ids,
                reserved_bytes=self._reserved_bytes,
                available_bytes=self._config.capacity_bytes - self._reserved_bytes,
                per_capture=self._per_capture,
                reserved_breakdown=reserved,
            )

    def __repr__(self) -> str:
        return "<CaptureBudget redacted>"


def _validate_request_id(request_id: str) -> None:
    if type(request_id) is not str:
        raise InvalidCaptureRequestIdError("capture request ID must be text")
    try:
        encoded = request_id.encode("ascii")
    except UnicodeEncodeError as exc:
        raise InvalidCaptureRequestIdError("capture request ID must be bounded ASCII") from exc
    if not 1 <= len(encoded) <= MAX_REQUEST_ID_BYTES:
        raise InvalidCaptureRequestIdError("capture request ID length is outside the supported range")
    if not encoded[0:1].isalnum() or any(
        byte not in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
        for byte in encoded
    ):
        raise InvalidCaptureRequestIdError("capture request ID contains unsupported characters")
