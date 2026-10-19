"""Bounded, transport-neutral identity and authorization error categories."""


class SecurityError(Exception):
    """Base error with a stable category and bounded, non-sensitive message."""

    code = "SECURITY_ERROR"
    max_message_chars = 192

    def __init__(self, message="request rejected"):
        self.message = str(message)[:self.max_message_chars]
        super().__init__(f"{self.code}: {self.message}")


class CredentialError(SecurityError):
    code = "UNAUTHENTICATED"


class SnapshotError(SecurityError):
    code = "AUTHORITY_UNAVAILABLE"


class BindingError(SecurityError):
    code = "INVALID_ARGUMENT"


class ScopeError(SecurityError):
    code = "PERMISSION_DENIED"


class SessionError(SecurityError):
    code = "PERMISSION_DENIED"


class ClockError(SecurityError):
    code = "CLOCK_UNSAFE"


class StorageError(SecurityError):
    code = "LOCAL_CREDENTIALS_UNSAFE"
