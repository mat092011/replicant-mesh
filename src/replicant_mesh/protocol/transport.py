"""Bounded transports for loopback and explicitly selected private Docker labs.

No authentication, service discovery or automatic retries are supplied here.
"""

import asyncio
import ipaddress
import re

from . import MAX_MESSAGE_BYTES, MAX_TIMEOUT_MS, METHODS, PROTOCOL_VERSION
from .errors import ProtocolError
from .wire import parse_message, serialize_message, validate_response
from .worker_pb2 import Request, Response

SERVICE = "replicant.mesh.v1.Worker"


def _method(method):
    if method not in METHODS:
        raise ProtocolError("INVALID_INPUT", "unknown protocol operation")


def _timeout(request, maximum):
    if type(maximum) is not int or not 1 <= maximum <= MAX_TIMEOUT_MS:
        raise ValueError("timeout ceiling must be within the protocol limit")
    if not 1 <= request.timeout_ms <= maximum:
        raise ProtocolError("INVALID_INPUT", "request timeout is outside the transport limit")
    return request.timeout_ms / 1000


def error_response(error, request=None):
    response = Response(protocol_version=PROTOCOL_VERSION, code=error.code, message=error.message)
    if request is not None:
        for name in ("manifest_fingerprint", "worker_boot_id", "session_id", "lease_token"):
            setattr(response, name, getattr(request, name)[:256])
        for name in ("sequence", "start_position", "token_count"):
            setattr(response, name, getattr(request, name))
    return response


class InMemoryTransport:
    """The same binary request/reply boundary without a network socket."""

    def __init__(self, handler, max_message_bytes=MAX_MESSAGE_BYTES,
                 max_timeout_ms=MAX_TIMEOUT_MS):
        self.handler = handler
        self.max_message_bytes = max_message_bytes
        self.max_timeout_ms = max_timeout_ms

    async def execute(self, method, request):
        _method(method)
        timeout = _timeout(request, self.max_timeout_ms)
        received = parse_message(serialize_message(request, self.max_message_bytes),
                                 Request, self.max_message_bytes)
        try:
            response = await asyncio.wait_for(self.handler.handle(method, received), timeout)
        except TimeoutError:
            response = error_response(ProtocolError("TIMEOUT", "transport deadline exceeded"), request)
        result = parse_message(serialize_message(response, self.max_message_bytes),
                               Response, self.max_message_bytes)
        return validate_response(method, request, result)

    async def close(self):
        """No channel is owned; the fixture remains responsible for its handler."""


def _options(max_message_bytes):
    if type(max_message_bytes) is not int or not 1 <= max_message_bytes <= MAX_MESSAGE_BYTES:
        raise ValueError("message limit must be within the protocol ceiling")
    return (("grpc.max_send_message_length", max_message_bytes),
            ("grpc.max_receive_message_length", max_message_bytes),
            ("grpc.enable_retries", 0))


def validate_endpoint(endpoint, *, private_network=False, listen=False):
    """Constrain endpoints to numeric IPv4 or Docker's simple service names.

    Non-loopback use requires the explicit private-lab opt-in. Compose provides
    network isolation; this flag is not authentication or transport encryption.
    """
    if not isinstance(endpoint, str) or endpoint.count(":") != 1:
        raise ValueError("Expected an IPv4 host or service name followed by a port")
    host, port = endpoint.split(":")
    if not port.isascii() or not port.isdecimal() or not (0 if listen else 1) <= int(port) <= 65535:
        raise ValueError("Invalid endpoint port")
    if host == "127.0.0.1":
        return endpoint
    if not private_network:
        raise ValueError("Non-loopback endpoints require the private-network option")
    if listen and host == "0.0.0.0":
        return endpoint
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        if listen or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,62}", host):
            raise ValueError("Only private IPv4 addresses and simple Docker service names are supported") from None
    else:
        networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        if not any(address in ipaddress.IPv4Network(network) for network in networks):
            raise ValueError("Only RFC1918 addresses are supported outside loopback")
    return endpoint


async def create_server(handler, host="127.0.0.1:0", max_message_bytes=MAX_MESSAGE_BYTES,
                        *, private_network=False):
    """Start an insecure server in loopback or an explicitly isolated private lab."""
    import grpc

    validate_endpoint(host, private_network=private_network, listen=True)
    server = grpc.aio.server(options=_options(max_message_bytes), maximum_concurrent_rpcs=32)

    def make_handler(method):
        async def invoke(data, context):
            request = None
            try:
                request = parse_message(data, Request, max_message_bytes)
                timeout = _timeout(request, MAX_TIMEOUT_MS)
                remaining = context.time_remaining()
                if remaining is not None:
                    timeout = min(timeout, remaining)
                response = await asyncio.wait_for(handler.handle(method, request), timeout)
            except ProtocolError as error:
                response = error_response(error, request)
            except TimeoutError:
                response = error_response(ProtocolError("TIMEOUT", "transport deadline exceeded"), request)
            return serialize_message(response, max_message_bytes)
        return grpc.unary_unary_rpc_method_handler(invoke)

    methods = {name: make_handler(name) for name in METHODS}
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(SERVICE, methods),))
    port = server.add_insecure_port(host)
    if not port:
        raise RuntimeError("could not bind the gRPC listener")
    await server.start()
    return server, port


class GrpcClient:
    """One attempt per request; an ambiguous failure must terminate the session."""

    def __init__(self, target, max_message_bytes=MAX_MESSAGE_BYTES, max_timeout_ms=MAX_TIMEOUT_MS,
                 *, private_network=False):
        import grpc

        validate_endpoint(target, private_network=private_network)
        self.max_message_bytes = max_message_bytes
        self.max_timeout_ms = max_timeout_ms
        self.channel = grpc.aio.insecure_channel(target, options=_options(max_message_bytes),
                                                 compression=grpc.Compression.NoCompression)

    async def execute(self, method, request):
        import grpc

        _method(method)
        timeout = _timeout(request, self.max_timeout_ms)
        data = serialize_message(request, self.max_message_bytes)
        call = self.channel.unary_unary(f"/{SERVICE}/{method}")
        try:
            payload = await call(data, timeout=timeout, wait_for_ready=False)
        except grpc.aio.AioRpcError as error:
            codes = {grpc.StatusCode.DEADLINE_EXCEEDED: "TIMEOUT",
                     grpc.StatusCode.RESOURCE_EXHAUSTED: "CAPACITY_EXHAUSTED",
                     grpc.StatusCode.CANCELLED: "CANCELLED"}
            code = codes.get(error.code(), "EXECUTION_FAILED")
            return error_response(ProtocolError(code, "RPC failed; step outcome may be unknown"), request)
        response = parse_message(payload, Response, self.max_message_bytes)
        return validate_response(method, request, response)

    async def close(self):
        await self.channel.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()
