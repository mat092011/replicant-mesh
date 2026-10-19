"""Injectable wall/monotonic clock checks for signed-policy validity."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from threading import Lock
from typing import Callable

from .errors import ClockError


MAX_CLOCK_UNCERTAINTY_SECONDS = 30.0
MAX_CLOCK_DISCONTINUITY_SECONDS = 30.0


@dataclass(frozen=True)
class ClockSample:
    wall: float
    monotonic: float
    uncertainty: float
    resume_token: object

    @property
    def earliest_wall(self) -> float:
        """Earliest plausible wall time; use for not-before checks."""
        return self.wall - self.uncertainty

    @property
    def latest_wall(self) -> float:
        """Latest plausible wall time; use for expiry checks."""
        return self.wall + self.uncertainty


class Clock:
    """Clock wrapper which rejects rollback, discontinuity, and unknown accuracy.

    Production callers must provide an uncertainty callback backed by an
    operator-approved clock source. The default uncertainty is infinite so an
    unconfigured host clock cannot silently become trusted.
    """

    def __init__(self, *, wall: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 uncertainty_seconds: Callable[[], float] | None = None,
                 resume_token: Callable[[], object] | None = None):
        self._wall = wall
        self._monotonic = monotonic
        self._uncertainty = uncertainty_seconds or (lambda: math.inf)
        self._resume_token = resume_token or (lambda: 0)
        # Provider reads and the state transition which accepts/rejects them
        # are one transaction. The model threadpool and event loop can share a
        # Clock, so protecting only _last would still let an older wall read
        # be compared after a newer sample had committed.
        self._lock = Lock()
        self._last: ClockSample | None = None
        self._faulted = False
        # A monotonic rollback invalidates all absolute monotonic deadlines for
        # this process.  Catching up the counter cannot make those deadlines
        # comparable again; only process restart can clear this latch.
        self._restart_required = False

    def _read(self) -> ClockSample:
        try:
            wall = float(self._wall())
            mono = float(self._monotonic())
            uncertainty = float(self._uncertainty())
            token = self._resume_token()
        except Exception as error:
            self._faulted = True
            raise ClockError("clock provider failed") from error
        if not math.isfinite(wall) or not math.isfinite(mono) or mono < 0:
            if self._last is not None and (not math.isfinite(mono) or mono < self._last.monotonic):
                self._restart_required = True
            self._faulted = True
            raise ClockError("clock returned a non-finite or invalid value")
        if not math.isfinite(uncertainty) or uncertainty < 0 or uncertainty > MAX_CLOCK_UNCERTAINTY_SECONDS:
            self._faulted = True
            raise ClockError("clock uncertainty exceeds 30 seconds or is unknown")
        return ClockSample(wall, mono, uncertainty, token)

    @classmethod
    def system(cls, *, uncertainty_seconds: Callable[[], float],
               resume_token: Callable[[], object] | None = None) -> "Clock":
        return cls(uncertainty_seconds=uncertainty_seconds, resume_token=resume_token)

    def sample(self) -> ClockSample:
        # Keep the provider read inside the same critical section as anomaly
        # checks and state/latch commit. Provider callbacks are synchronous and
        # must not wait on another operation using this Clock.
        with self._lock:
            if self._faulted:
                raise ClockError("clock anomaly is latched; trusted revalidation is required")
            current = self._read()
            previous = self._last
            if previous is not None:
                wall_delta = current.wall - previous.wall
                mono_delta = current.monotonic - previous.monotonic
                if mono_delta < 0:
                    self._restart_required = True
                    self._faulted = True
                    raise ClockError("monotonic rollback requires process restart")
                if wall_delta < 0:
                    self._faulted = True
                    raise ClockError("clock moved backwards")
                if abs(wall_delta - mono_delta) > MAX_CLOCK_DISCONTINUITY_SECONDS:
                    self._faulted = True
                    raise ClockError("wall and monotonic clocks diverged; revalidation is required")
                if current.resume_token != previous.resume_token:
                    self._faulted = True
                    raise ClockError("system resume was detected; revalidation is required")
            self._last = current
            return current

    def revalidate_after_resume(self, *, trusted_clock: bool) -> ClockSample:
        """Clear a latched anomaly after explicit trusted-clock/policy review.

        Monotonic rollback cannot be repaired in a live process because prior
        monotonic deadlines would no longer be comparable. It requires process
        restart and fresh policy installation.
        """
        if trusted_clock is not True:
            raise ClockError("explicit trusted-clock revalidation is required")
        # Revalidation participates in the same transaction as ordinary
        # samples. It cannot clear a fault committed by a concurrent sample
        # after that sample's provider values have been observed.
        with self._lock:
            if self._restart_required:
                raise ClockError("monotonic rollback requires process restart")
            current = self._read()
            if self._last is not None and current.monotonic < self._last.monotonic:
                self._restart_required = True
                self._faulted = True
                raise ClockError("monotonic rollback requires process restart")
            self._last = current
            self._faulted = False
            return current
