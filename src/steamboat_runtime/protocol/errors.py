"""Stable protocol errors; messages are bounded and must not contain prompts."""

ERROR_CODES = frozenset({"INVALID_INPUT", "INCOMPATIBLE_MODEL", "CAPACITY_EXHAUSTED",
                         "EXPIRED_SESSION", "STALE_WORKER", "OUT_OF_ORDER", "TIMEOUT",
                         "EXECUTION_FAILED", "CANCELLED", "CLOSED_SESSION",
                         "UNKNOWN_SESSION"})
MAX_ERROR_CHARS = 256


class ProtocolError(Exception):
    def __init__(self, code, message):
        if code not in ERROR_CODES:
            raise ValueError("unknown protocol error code")
        self.code = code
        self.message = str(message)[:MAX_ERROR_CHARS]
        super().__init__(f"{code}: {self.message}")


def raise_for_error(response):
    """Optional exception interface; transport clients otherwise return responses."""
    if response.code != "OK":
        if response.code not in ERROR_CODES:
            raise ProtocolError("INVALID_INPUT", "unrecognized response status")
        raise ProtocolError(response.code, response.message)
    return response
