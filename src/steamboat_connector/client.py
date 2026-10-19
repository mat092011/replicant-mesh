from dataclasses import asdict, dataclass
import hmac
import os
import socket
import struct
import sys
import time
from typing import Protocol

from .errors import ConnectorError, FeatureUnavailable
from .paths import default_runtime_directory, socket_path, token_path
from .storage import StorageError, read_private_file
from .validation import MAX_JSON_BYTES, json_bytes, new_id, strict_json_loads, valid_typed_id


MAX_OPERATION_SECONDS = 5.0
_READ_ONLY_ACTIONS = {"status", "diagnostics", "policy.get", "operation.status"}


def _peer_uid(connection):
    if not hasattr(socket, "SO_PEERCRED"):
        raise FeatureUnavailable("UNSUPPORTED_PLATFORM", "Linux AF_UNIX peer credentials are required")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _, uid, _ = struct.unpack("3i", raw)
    return uid


def _recv_exact(connection, size, deadline):
    result = bytearray()
    while len(result) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("management operation deadline exceeded")
        connection.settimeout(remaining)
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise ConnectionError("management daemon closed a partial response")
        result.extend(chunk)
    return bytes(result)


@dataclass(frozen=True)
class ConsumerSubmission:
    request_id: str
    prompt: str
    max_new_tokens: int
    deadline_seconds: int
    attempt: int = 1

    def as_payload(self):
        return asdict(self)


class ConsumerTransport(Protocol):
    def submit(self, submission):
        ...

    def cancel(self, request_id):
        ...


class ConsumerClient:
    """Thin standard-library request builder; C2a supplies no network transport."""

    def __init__(self, transport=None):
        self._transport = transport

    @staticmethod
    def build_submission(prompt, *, max_new_tokens, deadline_seconds=300):
        if not isinstance(prompt, str):
            raise ValueError("prompt must be text")
        try:
            prompt_bytes = prompt.encode("utf-8", errors="strict")
        except UnicodeError as error:
            raise ValueError("prompt must be valid UTF-8 text") from error
        if len(prompt_bytes) > 65_536:
            raise ValueError("prompt exceeds the 64 KiB text limit")
        if type(max_new_tokens) is not int or not 1 <= max_new_tokens <= 1_152:
            raise ValueError("max_new_tokens must be in 1..1152")
        if type(deadline_seconds) is not int or not 1 <= deadline_seconds <= 300:
            raise ValueError("deadline_seconds must be in 1..300")
        return ConsumerSubmission(new_id("req"), prompt, max_new_tokens, deadline_seconds)

    def submit(self, prompt, *, max_new_tokens, deadline_seconds=300):
        submission = self.build_submission(prompt, max_new_tokens=max_new_tokens,
                                           deadline_seconds=deadline_seconds)
        if self._transport is None or not callable(getattr(self._transport, "submit", None)):
            raise FeatureUnavailable("TRANSPORT_UNAVAILABLE",
                                     "secure C1a/C2b consumer transport is not part of C2a")
        return self._transport.submit(submission)

    def cancel(self, request_id):
        if not valid_typed_id(request_id, "req"):
            raise ValueError("request_id must be a typed v1 request identity")
        if self._transport is None or not callable(getattr(self._transport, "cancel", None)):
            raise FeatureUnavailable("TRANSPORT_UNAVAILABLE",
                                     "secure C1a/C2b consumer transport is not part of C2a")
        return self._transport.cancel(request_id)


class LocalManagementClient:
    def __init__(self, runtime_directory=None, *, timeout=MAX_OPERATION_SECONDS):
        if not sys.platform.startswith("linux") or not hasattr(socket, "AF_UNIX"):
            raise FeatureUnavailable("UNSUPPORTED_PLATFORM",
                                     "local management requires Linux AF_UNIX")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) \
                or not 0 < timeout <= MAX_OPERATION_SECONDS:
            raise ValueError("management timeout must be in 0..5 seconds")
        self.runtime_directory = runtime_directory or default_runtime_directory()
        self.address = socket_path(self.runtime_directory)
        self.timeout = float(timeout)
        try:
            token_data = read_private_file(token_path(self.runtime_directory), maximum_size=65,
                                           exact_mode=0o600)
        except (StorageError, OSError) as error:
            raise ConnectorError("UNAVAILABLE", "private daemon token is unavailable") from error
        if (len(token_data) != 65 or token_data[-1:] != b"\n"
                or any(value not in b"0123456789abcdef" for value in token_data[:-1])):
            raise ConnectorError("UNAVAILABLE", "private daemon token is malformed")
        self._token = token_data[:-1].decode("ascii")

    def call(self, action, payload=None):
        if not isinstance(action, str) or not 1 <= len(action) <= 40:
            raise ValueError("management action is invalid")
        payload = {} if payload is None else payload
        if type(payload) is not dict:
            raise ValueError("management payload must be an object")
        operation_id = new_id("op")
        request = {"version": 1, "operation_id": operation_id, "token": self._token,
                   "action": action, "payload": payload}
        encoded = json_bytes(request, maximum_bytes=MAX_JSON_BYTES)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sent = False
        deadline = time.monotonic() + self.timeout
        try:
            connection.settimeout(self.timeout)
            connection.connect(os.fspath(self.address))
            if _peer_uid(connection) != os.getuid():
                raise ConnectorError("UNAUTHENTICATED", "management daemon UID mismatch")
            frame = struct.pack("!I", len(encoded)) + encoded
            while frame:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("management operation deadline exceeded")
                connection.settimeout(remaining)
                written = connection.send(frame)
                if written <= 0:
                    raise ConnectionError("management request could not be sent")
                frame = frame[written:]
                sent = True
            header = _recv_exact(connection, 4, deadline)
            length = struct.unpack("!I", header)[0]
            if not 1 <= length <= MAX_JSON_BYTES:
                raise ConnectorError("PROTOCOL_ERROR", "management response length is invalid")
            try:
                response = strict_json_loads(_recv_exact(connection, length, deadline))
            except (TypeError, ValueError, UnicodeError) as error:
                raise ConnectorError("PROTOCOL_ERROR", "management response is malformed") from error
        except (TimeoutError, socket.timeout, ConnectionError, OSError) as error:
            mutating = action not in _READ_ONLY_ACTIONS
            code = "AMBIGUOUS" if sent and mutating else "UNAVAILABLE"
            raise ConnectorError(code, "management call ended without a complete response") from error
        finally:
            connection.close()
        if (type(response) is not dict or type(response.get("version")) is not int
                or response.get("version") != 1
                or response.get("operation_id") != operation_id
                or type(response.get("ok")) is not bool):
            raise ConnectorError("PROTOCOL_ERROR", "management response identity is invalid")
        if not response["ok"]:
            error = response.get("error")
            if (type(error) is not dict or set(error) != {"code", "message"}
                    or not isinstance(error["code"], str)
                    or not isinstance(error["message"], str)
                    or len(error["code"]) > 64 or len(error["message"]) > 256):
                raise ConnectorError("PROTOCOL_ERROR", "management error response is invalid")
            raise ConnectorError(error["code"], error["message"])
        if set(response) != {"version", "operation_id", "ok", "result"} \
                or type(response["result"]) is not dict:
            raise ConnectorError("PROTOCOL_ERROR", "management result response is invalid")
        return response["result"]

    def status(self):
        return self.call("status")

    def diagnostics(self):
        return self.call("diagnostics")

    def get_policy(self):
        return self.call("policy.get")

    def set_policy(self, policy):
        return self.call("policy.set", {"policy": policy})

    def enable_role(self, role):
        return self.call("role.enable", {"role": role})

    def disable_role(self, role):
        return self.call("role.disable", {"role": role})

    def start(self, roles=None):
        return self.call("start", {} if roles is None else {"roles": roles})

    def drain(self, roles=None, *, deadline_seconds=30):
        payload = {"deadline_seconds": deadline_seconds}
        if roles is not None:
            payload["roles"] = roles
        return self.call("drain", payload)

    def stop(self, roles=None):
        return self.call("stop", {} if roles is None else {"roles": roles})

    def remove(self, *, delete_owned_data=False):
        return self.call("remove", {"delete_owned_data": delete_owned_data})

    def operation(self, operation_id):
        return self.call("operation.status", {"operation_id": operation_id})
