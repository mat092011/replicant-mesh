import math
import threading
import time

from .policy import TELEMETRY_NAMES


class TelemetryRegistry:
    def __init__(self, *, clock=time.monotonic, maximum_age=5.0):
        self.clock = clock
        self.maximum_age = maximum_age
        self._lock = threading.RLock()
        self._samples = {}

    def record(self, name, value, *, observed_at=None):
        if name not in TELEMETRY_NAMES:
            raise ValueError("unknown telemetry policy")
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value)):
            raise ValueError("telemetry value must be finite numeric data")
        timestamp = self.clock() if observed_at is None else observed_at
        if (isinstance(timestamp, bool) or not isinstance(timestamp, (int, float))
                or not math.isfinite(timestamp)):
            raise ValueError("telemetry timestamp must be finite monotonic time")
        with self._lock:
            self._samples[name] = (float(value), float(timestamp))

    def invalidate(self, name):
        if name not in TELEMETRY_NAMES:
            raise ValueError("unknown telemetry policy")
        with self._lock:
            self._samples.pop(name, None)

    def status(self, required=(), *, now=None):
        current = self.clock() if now is None else now
        with self._lock:
            samples = dict(self._samples)
        result = {}
        for name in sorted(set(required)):
            sample = samples.get(name)
            if sample is None:
                result[name] = {"fresh": False, "reason": "unsupported_or_missing"}
                continue
            value, timestamp = sample
            age = current - timestamp
            if age < 0:
                result[name] = {"fresh": False, "reason": "future_timestamp"}
            elif age > self.maximum_age:
                result[name] = {"fresh": False, "reason": "stale"}
            else:
                result[name] = {"fresh": True, "age_seconds": round(age, 3)}
        return result

    def diagnostics(self, required=(), *, now=None):
        return self.status(required, now=now)
