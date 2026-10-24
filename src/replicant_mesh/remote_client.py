"""Bounded JSON/gRPC client for the private coordinator service; no Torch import.

The transport supplies no authentication or encryption. Non-loopback use requires
an explicit private-network opt-in and an externally isolated network.
"""

import json
import math


SERVICE = "replicant.mesh.v1.Coordinator"
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_GENERATE_BYTES = 32 * 1024
MAX_TEXT_BYTES = 64 * 1024
MAX_TOKENIZE_BYTES = 512 * 1024
MAX_POSITIONS = 1152
VOCAB_SIZE = 32000
MAX_TIMEOUT_SECONDS = 300


class RemoteError(Exception):
    def __init__(self, code, message):
        self.code = str(code)[:64]
        self.message = str(message)[:256]
        super().__init__(f"{self.code}: {self.message}")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _constant(_):
    raise ValueError("Non-finite JSON number")


def encode_json(value, limit=MAX_MESSAGE_BYTES):
    try:
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False,
                             allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise RemoteError("INVALID_INPUT", "Invalid JSON message") from None
    if len(payload) > limit:
        raise RemoteError("INVALID_INPUT", "Message exceeds its byte bound")
    return payload


def decode_json(payload, limit=MAX_MESSAGE_BYTES):
    if not isinstance(payload, bytes) or len(payload) > limit:
        raise RemoteError("INVALID_INPUT", "Message exceeds its byte bound")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise RemoteError("INVALID_INPUT", "Invalid JSON message") from None
    if not isinstance(value, dict):
        raise RemoteError("INVALID_INPUT", "Expected a JSON object")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 12:
            raise RemoteError("INVALID_INPUT", "JSON nesting exceeds its bound")
        if isinstance(item, float) and not math.isfinite(item):
            # JSON exponent overflow (1e400) bypasses json.loads parse_constant.
            raise RemoteError("INVALID_INPUT", "Non-finite JSON number")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def _tokens(value, *, minimum=1, maximum=MAX_POSITIONS):
    return (isinstance(value, list) and minimum <= len(value) <= maximum
            and all(type(token) is int and 0 <= token < VOCAB_SIZE for token in value))


def validate_generate(value):
    required = {"input_ids", "new_tokens", "timeout_seconds", "capture_logits"}
    if (not isinstance(value, dict) or not required <= value.keys()
            or value.keys() - required - {"forced_tokens"}):
        raise RemoteError("INVALID_INPUT", "Unknown or missing generation fields")
    count = value["new_tokens"]
    if (not _tokens(value["input_ids"]) or type(count) is not int or count < 1
            or len(value["input_ids"]) + count > MAX_POSITIONS):
        raise RemoteError("INVALID_INPUT", "Token IDs or context budget are invalid")
    forced = value.get("forced_tokens")
    if forced is not None and (not _tokens(forced, minimum=0) or len(forced) != count - 1):
        raise RemoteError("INVALID_INPUT", "Expected new_tokens-1 forced feedback IDs")
    timeout = value["timeout_seconds"]
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not 0 < timeout <= MAX_TIMEOUT_SECONDS or not math.isfinite(timeout)
            or type(value["capture_logits"]) is not bool):
        raise RemoteError("INVALID_INPUT", "Invalid timeout or logit capture option")
    return value


def validate_text(value):
    if (not isinstance(value, dict) or "text" not in value
            or set(value) - {"text", "add_special_tokens"}
            or type(value.get("add_special_tokens", True)) is not bool):
        raise RemoteError("INVALID_INPUT", "Expected text and optional add_special_tokens boolean")
    text = value["text"]
    if not isinstance(text, str) or not text or len(text) > MAX_TEXT_BYTES:
        raise RemoteError("INVALID_INPUT", "Text must be nonempty and at most 64 KiB UTF-8")
    try:
        length = len(text.encode("utf-8"))
    except UnicodeError:
        raise RemoteError("INVALID_INPUT", "Text is not valid UTF-8") from None
    if length > MAX_TEXT_BYTES:
        raise RemoteError("INVALID_INPUT", "Text exceeds 64 KiB UTF-8")
    return text


def _rpc_error(error):
    import grpc
    code = {grpc.StatusCode.DEADLINE_EXCEEDED: "TIMEOUT",
            grpc.StatusCode.RESOURCE_EXHAUSTED: "CAPACITY_EXHAUSTED",
            grpc.StatusCode.CANCELLED: "CANCELLED",
            grpc.StatusCode.INVALID_ARGUMENT: "INVALID_INPUT",
            grpc.StatusCode.UNAVAILABLE: "NOT_READY"}.get(error.code(), "EXECUTION_FAILED")
    # Never expose grpc details, which may contain server or peer input.
    return RemoteError(code, "Coordinator RPC failed; requests are never retried")


class RemoteClient:
    def __init__(self, target="coordinator:50052", *, private_network=False):
        import grpc
        from .protocol.transport import validate_endpoint
        validate_endpoint(target, private_network=private_network)
        self.channel = grpc.aio.insecure_channel(target, options=(
            ("grpc.max_send_message_length", MAX_MESSAGE_BYTES),
            ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
            ("grpc.enable_retries", 0)), compression=grpc.Compression.NoCompression)

    async def _unary(self, method, value, timeout):
        import grpc
        try:
            response = await self.channel.unary_unary(f"/{SERVICE}/{method}")(
                encode_json(value), timeout=timeout, wait_for_ready=False)
        except grpc.aio.AioRpcError as error:
            raise _rpc_error(error) from None
        return decode_json(response)

    async def describe(self, timeout_seconds=5):
        return await self._unary("Describe", {}, timeout_seconds)

    async def tokenize(self, text, *, add_special_tokens=True):
        request = {"text": text, "add_special_tokens": add_special_tokens}
        validate_text(request)
        response = await self._unary("Tokenize", request, 30)
        if set(response) != {"input_ids"} or not _tokens(response["input_ids"]):
            raise RemoteError("EXECUTION_FAILED", "Invalid tokenizer reply")
        return response["input_ids"]

    async def generate(self, input_ids, new_tokens, *, forced_tokens=None,
                       capture_logits=False, timeout_seconds=300):
        """Stream checked token dictionaries and one terminal result.

        The deadline covers the whole RPC, including admission. Call ``aclose``
        on an abandoned generator (or cancel its consumer task) to cancel the RPC;
        remote cleanup continues independently and is observable through Describe.
        A failed terminal result is yielded before a bounded RemoteError is raised.
        Client timing must use the consumer's local monotonic clock.
        """
        import grpc
        request = validate_generate({"input_ids": input_ids, "new_tokens": new_tokens,
                                     "forced_tokens": forced_tokens,
                                     "capture_logits": capture_logits,
                                     "timeout_seconds": timeout_seconds})
        call = self.channel.unary_stream(f"/{SERVICE}/Generate")(
            encode_json(request, MAX_GENERATE_BYTES), timeout=timeout_seconds,
            wait_for_ready=False)
        received, session_id, terminal = [], None, False
        try:
            async for payload in call:
                event = decode_json(payload)
                kind = event.get("type")
                sid = event.get("session_id")
                if (not isinstance(sid, str) or len(sid) != 32
                        or any(c not in "0123456789abcdef" for c in sid)
                        or (session_id is not None and sid != session_id) or terminal):
                    raise RemoteError("EXECUTION_FAILED", "Invalid stream identity or ordering")
                session_id = sid
                if kind == "token":
                    index = len(received)
                    if (type(event.get("index")) is not int or event["index"] != index
                            or event.get("sequence") != index or index >= new_tokens
                            or type(event.get("token_id")) is not int
                            or not 0 <= event["token_id"] < VOCAB_SIZE
                            or event.get("position") != len(input_ids) + index):
                        raise RemoteError("EXECUTION_FAILED", "Invalid token order or value")
                    if capture_logits:
                        logits = event.get("logits")
                        if (not isinstance(logits, list) or len(logits) != VOCAB_SIZE
                                or any(isinstance(x, bool) or not isinstance(x, (float, int))
                                       or not math.isfinite(x) for x in logits)):
                            raise RemoteError("EXECUTION_FAILED", "Invalid logit vector")
                    elif "logits" in event:
                        raise RemoteError("EXECUTION_FAILED", "Unexpected logits")
                    received.append(event["token_id"])
                elif kind == "result":
                    terminal = True
                    if (event.get("status") not in {"completed", "cancelled", "failed"}
                            or type(event.get("cleanup_complete")) is not bool
                            or not _tokens(event.get("token_ids"), minimum=0)
                            or not isinstance(event.get("metrics"), dict)):
                        raise RemoteError("EXECUTION_FAILED", "Invalid terminal result")
                    if event["status"] == "completed" and (
                            len(received) != new_tokens or event["token_ids"] != received):
                        raise RemoteError("EXECUTION_FAILED", "Incomplete successful stream")
                else:
                    raise RemoteError("EXECUTION_FAILED", "Unknown stream event")
                yield event
                if terminal and event["status"] != "completed":
                    raise RemoteError(event.get("error_code") or "EXECUTION_FAILED",
                                      event.get("error") or "Generation failed")
            if not terminal:
                raise RemoteError("EXECUTION_FAILED", "Stream ended without a terminal result")
        except grpc.aio.AioRpcError as error:
            raise _rpc_error(error) from None
        finally:
            if not call.done():
                call.cancel()

    async def close(self):
        await self.channel.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()
