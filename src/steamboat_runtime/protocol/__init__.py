"""Versioned, bounded messages for the private experimental worker protocol."""

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 1048576
MAX_TIMEOUT_MS = 30000
METHODS = ("Describe", "OpenSession", "RenewSession", "Step", "CloseSession",
           "CancelSession", "SessionStatus")
