"""One-shot, fixed-peer CONNECT gates for native gRPC address proxies.

The gate only forwards opaque TCP bytes. gRPC keeps its configured channel
target, TLS hostname verification and pinned leaf trust material.
"""

import asyncio
import hmac
import ipaddress
import inspect
import math
import secrets
import socket
import time


CONNECT_HEADER_LIMIT_BYTES = 4096
CONNECT_MAX_FIELDS = 16
CONNECT_MAX_LINE_BYTES = 1024
PUMP_CHUNK_BYTES = 64 * 1024
MAX_CONNECT_SETUP_SECONDS = 5.0
MAX_OUTBOUND_LIFETIME_SECONDS = 300.0


class SecureConnectorError(RuntimeError):
    """A rejected or failed outbound CONNECT gate."""


class SecureConnectorPending(SecureConnectorError):
    """Gate teardown is still pending; referenced tasks remain caller-owned."""

    def __init__(self, tasks, message="outbound CONNECT tunnel is still closing"):
        self.tasks = tuple(task for task in tasks if task is not None)
        super().__init__(message)


class SecureConnector:
    """Own one local proxy endpoint and at most one fixed-peer TCP tunnel.

    ``pending_reservation`` is the caller's existing shared node reservation.
    The connector never allocates another pending token. It releases the
    supplied token after :meth:`confirm_ready` or confirmed pre-ready teardown.
    """

    def __init__(self, endpoint, allowed_addresses, *, pending_reservation,
                 handshake_deadline, lifetime_seconds, on_lifetime_expired,
                 cleanup_grace=5.0):
        if not isinstance(endpoint, str) or endpoint.count(":") != 1:
            raise ValueError("outbound gate requires a fixed numeric IPv4 endpoint")
        host, port_text = endpoint.split(":", 1)
        try:
            parsed = ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError:
            raise ValueError("outbound gate does not support DNS or IPv6") from None
        if (str(parsed) != host or parsed.is_unspecified or parsed.is_multicast
                or parsed.is_reserved):
            raise ValueError("outbound gate target must be canonical unicast IPv4")
        if not isinstance(allowed_addresses, (tuple, list, set, frozenset)):
            raise ValueError("outbound gate requires the peer address allowlist")
        if host not in allowed_addresses:
            raise ValueError("outbound gate target is outside the peer allowlist")
        if not port_text.isascii() or not port_text.isdecimal():
            raise ValueError("outbound gate target port is invalid")
        port = int(port_text)
        if not 1 <= port <= 65535 or str(port) != port_text:
            raise ValueError("outbound gate target port is invalid")
        if (pending_reservation is None
                or not callable(getattr(pending_reservation, "release", None))):
            raise ValueError("outbound gate requires its shared pending reservation")
        if (isinstance(handshake_deadline, bool)
                or not isinstance(handshake_deadline, (int, float))
                or not math.isfinite(handshake_deadline)
                or not handshake_deadline > time.monotonic()):
            raise ValueError("outbound gate requires a future monotonic handshake deadline")
        if handshake_deadline - time.monotonic() > MAX_CONNECT_SETUP_SECONDS:
            raise ValueError("outbound gate setup deadline exceeds five seconds")
        if (isinstance(lifetime_seconds, bool)
                or not isinstance(lifetime_seconds, (int, float))
                or not math.isfinite(lifetime_seconds)
                or not 0 < lifetime_seconds <= MAX_OUTBOUND_LIFETIME_SECONDS):
            raise ValueError("outbound channel lifetime must be within 300 seconds")
        if (isinstance(cleanup_grace, bool)
                or not isinstance(cleanup_grace, (int, float))
                or not math.isfinite(cleanup_grace) or not 0 < cleanup_grace <= 5.0):
            raise ValueError("outbound cleanup grace must be within five seconds")
        if not callable(on_lifetime_expired):
            raise ValueError("outbound gate requires a lifetime-expiry channel closer")

        self.target_ip = host
        self.target_port = port
        self.target = endpoint
        self.pending_reservation = pending_reservation
        self.handshake_deadline = float(handshake_deadline)
        self.lifetime_seconds = float(lifetime_seconds)
        self.cleanup_grace = float(cleanup_grace)
        self.on_lifetime_expired = on_lifetime_expired
        self._token = secrets.token_hex(32)
        self._listener = None
        self._listener_ref = None
        self._accepted = None
        self._upstream = None
        self._owned_sockets = []
        self._accept_task = None
        self._pump_tasks = ()
        self._pump_results = {}
        self._deadline_task = None
        self._lifetime_task = None
        self._tunnel_ready = False
        self._ready_confirmed = False
        self._setup_expired = False
        self._upstream_connected = False
        self._failure_event = asyncio.Event()
        self._closed_event = asyncio.Event()
        self._closed_confirmed = False
        self._owner_close_requested = False
        self._closure_evidence = None
        self._started = False
        self._closed = False
        self.accepted_count = 0
        self.upstream_dial_count = 0
        self.local_port = None

    @property
    def failed(self):
        return self._failure_event.is_set() or self._closed_event.is_set()

    @property
    def closed_confirmed(self):
        return self._closed_confirmed

    @property
    def closure_evidence(self):
        """How the gate established that no owned tunnel descriptor remains."""
        return self._closure_evidence

    @property
    def owned_sockets_closed(self):
        return all(sock.fileno() == -1 for sock in self._owned_sockets)

    @property
    def listener_closed_confirmed(self):
        return self._listener is None and (
            self._listener_ref is None or self._listener_ref.fileno() == -1)

    @property
    def pump_tasks_done(self):
        return all(task.done() for task in self._pump_tasks)

    async def start(self):
        if self._started or self._closed:
            raise SecureConnectorError("outbound gate cannot be restarted")
        if time.monotonic() >= self.handshake_deadline:
            raise TimeoutError("outbound gate setup deadline expired")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setblocking(False)
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
        except BaseException:
            listener.close()
            raise
        self._listener = listener
        self._listener_ref = listener
        self.local_port = listener.getsockname()[1]
        self._started = True
        self._accept_task = asyncio.create_task(self._accept_once())
        self._deadline_task = asyncio.create_task(self._enforce_handshake_deadline())
        return self

    def channel_options(self):
        if not self._started or self.local_port is None or self._closed:
            raise SecureConnectorError("outbound proxy options require a live one-shot gate")
        return (
            ("grpc.enable_retries", 0),
            ("grpc.use_local_subchannel_pool", 1),
            ("grpc.http_proxy", ""),
            ("grpc.enable_http_proxy", 1),
            ("grpc.address_http_proxy", f"127.0.0.1:{self.local_port}"),
            ("grpc.address_http_proxy_enabled_addresses", f"{self.target_ip}/32"),
            ("grpc.http_connect_headers", "steamboat-proxy-token:" + self._token),
            ("grpc.max_connections_per_subchannel_cap", 1),
        )

    def stop_accepting(self):
        """Retire the one-shot listener before channel teardown begins."""
        self._close_listener()

    async def confirm_ready(self):
        if (self._closed or self._setup_expired or not self._tunnel_ready
                or self._closed_event.is_set() or self._accept_task is None
                or self._accept_task.done()
                or time.monotonic() >= self.handshake_deadline):
            if time.monotonic() >= self.handshake_deadline:
                self._setup_expired = True
            raise SecureConnectorError(
                "gRPC TLS readiness did not retain the original CONNECT tunnel")
        await self._stop_timer("_deadline_task")
        if (self._closed or self._setup_expired or not self._tunnel_ready
                or self._closed_event.is_set() or self._accept_task is None
                or self._accept_task.done()
                or time.monotonic() >= self.handshake_deadline):
            if time.monotonic() >= self.handshake_deadline:
                self._setup_expired = True
            raise SecureConnectorError(
                "original CONNECT tunnel or absolute setup deadline expired while readiness was being confirmed")
        await self._release_pending()
        self._ready_confirmed = True
        self._lifetime_deadline = time.monotonic() + self.lifetime_seconds
        self._lifetime_task = asyncio.create_task(
            self._enforce_lifetime(self._lifetime_deadline))
        self._lifetime_task.add_done_callback(self._observe_background_task)

    @staticmethod
    def _observe_background_task(task):
        try:
            task.exception()
        except asyncio.CancelledError:
            pass

    async def _release_pending(self):
        reservation = self.pending_reservation
        if reservation is None:
            return
        result = reservation.release()
        if inspect.isawaitable(result):
            close = getattr(result, "close", None)
            cancel = getattr(result, "cancel", None)
            if callable(close):
                close()
            elif callable(cancel):
                cancel()
            raise SecureConnectorError(
                "shared pending reservation release must be synchronous")
        self.pending_reservation = None

    async def wait_failure(self):
        await self._failure_event.wait()

    async def _stop_timer(self, name, *, grace=None):
        task = getattr(self, name)
        if task is None or task is asyncio.current_task():
            return
        if not task.done():
            task.cancel()
        done, pending = await asyncio.wait((task,),
            timeout=self.cleanup_grace if grace is None else grace)
        if pending:
            raise SecureConnectorPending((task,), "outbound gate timer did not stop")
        await asyncio.gather(task, return_exceptions=True)
        setattr(self, name, None)

    def _close_listener(self):
        listener = self._listener
        if listener is None:
            return
        try:
            listener.close()
        except OSError:
            pass
        if listener.fileno() != -1:
            raise SecureConnectorError(
                "one-shot CONNECT listener descriptor did not close")
        self._listener = None

    async def _enforce_handshake_deadline(self):
        try:
            await asyncio.sleep(max(0.0, self.handshake_deadline - time.monotonic()))
            if self._ready_confirmed or self._closed:
                return
            self._setup_expired = True
            self._close_listener()
        except asyncio.CancelledError:
            raise

    async def _enforce_lifetime(self, lifetime_deadline):
        try:
            # The channel lifetime starts at successful readiness, not at
            # listener bind. Keep its own absolute deadline independent of the
            # gRPC channel's Python-side monitor.
            await asyncio.sleep(max(0.0, lifetime_deadline - time.monotonic()))
            if not self._closed:
                self._failure_event.set()
                result = self.on_lifetime_expired(self)
                if inspect.isawaitable(result):
                    await result
        except asyncio.CancelledError:
            raise

    async def _accept_once(self):
        accepted = None
        try:
            listener = self._listener
            if listener is None:
                return
            loop = asyncio.get_running_loop()
            remaining = self.handshake_deadline - time.monotonic()
            if remaining <= 0:
                self._setup_expired = True
                return
            accepted, _address = await asyncio.wait_for(
                loop.sock_accept(listener), timeout=remaining)
            accepted.setblocking(False)
            self.accepted_count += 1
            self._accepted = accepted
            self._owned_sockets.append(accepted)
            # Closing the acceptor immediately prevents C-core from creating
            # another physical upstream attempt through this channel's gate.
            self._close_listener()
            await self._serve_tunnel(accepted)
        except asyncio.CancelledError:
            raise
        except SecureConnectorPending:
            self._failure_event.set()
            raise
        except asyncio.TimeoutError:
            self._setup_expired = True
        except Exception:
            self._failure_event.set()
        finally:
            self._close_listener()
            if not self._upstream_connected:
                self._shutdown_owned_sockets()
                self._close_owned_sockets()
                self._closure_evidence = "no-established-upstream; owned descriptors closed"
            self._closed_event.set()
            if self._ready_confirmed or self.accepted_count:
                self._failure_event.set()

    async def _read_connect_header(self, sock):
        loop = asyncio.get_running_loop()
        data = bytearray()
        marker = b"\r\n\r\n"
        while marker not in data:
            if len(data) >= CONNECT_HEADER_LIMIT_BYTES:
                raise SecureConnectorError("CONNECT headers exceed the configured bound")
            remaining = self.handshake_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("outbound CONNECT header exceeded the handshake deadline")
            chunk = await asyncio.wait_for(loop.sock_recv(
                sock, min(1024, CONNECT_HEADER_LIMIT_BYTES + 1 - len(data))),
                timeout=remaining)
            if not chunk:
                raise SecureConnectorError("CONNECT request ended before its headers")
            data.extend(chunk)
            if len(data) > CONNECT_HEADER_LIMIT_BYTES:
                raise SecureConnectorError("CONNECT headers exceed the configured bound")
        end = data.index(marker) + len(marker)
        if end != len(data):
            raise SecureConnectorError("CONNECT request contains a body or pipelined bytes")
        return bytes(data[:end])

    def _validate_connect_header(self, raw):
        try:
            text = raw.decode("ascii", errors="strict")
        except UnicodeDecodeError:
            raise SecureConnectorError("CONNECT request is not ASCII") from None
        if not text.endswith("\r\n\r\n"):
            raise SecureConnectorError("CONNECT request is malformed")
        lines = text[:-4].split("\r\n")
        if not lines or len(lines) - 1 > CONNECT_MAX_FIELDS:
            raise SecureConnectorError("CONNECT request has too many fields")
        request_parts = lines[0].split(" ")
        if (len(request_parts) != 3 or request_parts[0] != "CONNECT"
                or request_parts[1] != self.target
                or request_parts[2] not in ("HTTP/1.0", "HTTP/1.1")):
            raise SecureConnectorError("CONNECT method, target or version is invalid")
        headers = {}
        allowed = {"host", "user-agent", "proxy-connection",
                   "steamboat-proxy-token"}
        for line in lines[1:]:
            if not line or len(line.encode("ascii")) > CONNECT_MAX_LINE_BYTES:
                raise SecureConnectorError("CONNECT header field is malformed or oversized")
            if ":" not in line:
                raise SecureConnectorError("CONNECT header field is malformed")
            name, value = line.split(":", 1)
            if (not name or name != name.strip() or not name.isascii()
                    or any(not (char.isalnum() or char == "-") for char in name)):
                raise SecureConnectorError("CONNECT header name is malformed")
            key = name.lower()
            if key in headers:
                raise SecureConnectorError("duplicate CONNECT header")
            if key in ("content-length", "transfer-encoding") or key not in allowed:
                raise SecureConnectorError("CONNECT request contains a forbidden header")
            value = value.strip(" \t")
            if any((ord(char) < 0x20 and char != "\t") or ord(char) == 0x7f
                   for char in value):
                raise SecureConnectorError("CONNECT header value is malformed")
            if len(value) > 512:
                raise SecureConnectorError("CONNECT header value exceeds its bound")
            headers[key] = value
        if headers.get("host", self.target) != self.target:
            raise SecureConnectorError("CONNECT Host differs from its fixed target")
        proxy_connection = headers.get("proxy-connection", "").lower()
        if proxy_connection not in ("", "keep-alive", "close"):
            raise SecureConnectorError("CONNECT proxy-connection value is invalid")
        token = headers.get("steamboat-proxy-token", "")
        if not hmac.compare_digest(token, self._token):
            raise SecureConnectorError("CONNECT token is invalid")
        return True

    async def _send_response(self, sock, status):
        loop = asyncio.get_running_loop()
        remaining = self.handshake_deadline - time.monotonic()
        if remaining <= 0:
            return False
        response = (b"HTTP/1.0 200 Connection established\r\n\r\n"
                    if status == 200 else b"HTTP/1.0 400 Bad Request\r\nConnection: close\r\n\r\n")
        try:
            await asyncio.wait_for(loop.sock_sendall(sock, response),
                                   timeout=min(0.5, remaining))
            return True
        except asyncio.CancelledError:
            raise
        except Exception:
            return False

    async def _serve_tunnel(self, client):
        loop = asyncio.get_running_loop()
        try:
            header = await self._read_connect_header(client)
            self._validate_connect_header(header)
            await asyncio.sleep(0)
            try:
                early = client.recv(1, socket.MSG_PEEK)
            except BlockingIOError:
                early = None
            if early is not None:
                if not early:
                    raise SecureConnectorError("CONNECT peer closed before the response")
                raise SecureConnectorError("CONNECT request contains a body or early tunnel bytes")
            if time.monotonic() >= self.handshake_deadline:
                raise TimeoutError("outbound CONNECT exceeded the handshake deadline")
        except (SecureConnectorError, TimeoutError, asyncio.TimeoutError):
            await self._send_response(client, 400)
            return

        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.setblocking(False)
        self._upstream = upstream
        self._owned_sockets.append(upstream)
        try:
            remaining = self.handshake_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("outbound TCP setup exceeded the handshake deadline")
            self.upstream_dial_count += 1
            try:
                await asyncio.wait_for(loop.sock_connect(
                    upstream, (self.target_ip, self.target_port)), timeout=remaining)
            except BaseException:
                # No relay readers exist until after connect succeeds, so this
                # descriptor can be retired synchronously once sock_connect
                # has unwound.
                self._shutdown_socket(upstream)
                self._close_socket(upstream)
                raise
            self._upstream_connected = True
            if time.monotonic() >= self.handshake_deadline:
                raise TimeoutError("outbound TCP setup exceeded the handshake deadline")
            if not await self._send_response(client, 200):
                raise SecureConnectorError("CONNECT acceptance could not reach gRPC Core")
            self._tunnel_ready = True
            pumps = (asyncio.create_task(self._pump(client, upstream)),
                     asyncio.create_task(self._pump(upstream, client)))
            self._pump_tasks = pumps
            await self._wait_for_pumps(pumps)
        except asyncio.CancelledError:
            self._failure_event.set()
            raise
        except SecureConnectorPending:
            self._failure_event.set()
            raise
        except Exception:
            self._failure_event.set()
        finally:
            if self._pump_tasks and not self._all_pumps_terminal():
                # On selector loops, shutdown wakes sock_recv with EOF while
                # the descriptor is still registered. Keep the owned FDs open
                # until every read owner has observed that EOF.
                self._shutdown_owned_sockets()
            else:
                # No pump can still be registered on these descriptors.
                if self._owned_sockets:
                    self._shutdown_owned_sockets()
                self._close_owned_sockets()
            self._confirm_owned_closure()

    async def _pump(self, source, destination):
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = await loop.sock_recv(source, PUMP_CHUNK_BYTES)
            except ConnectionResetError:
                return "reset"
            except OSError:
                if (self._owner_close_requested
                        and source.fileno() == -1):
                    return "owned-descriptor-closed"
                raise
            if not data:
                if self._owner_close_requested and source.fileno() == -1:
                    return "owned-descriptor-closed"
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return "eof"
            try:
                await loop.sock_sendall(destination, data)
            except ConnectionResetError:
                return "reset"
            except OSError:
                if (self._owner_close_requested
                        and destination.fileno() == -1):
                    return "owned-descriptor-closed"
                raise

    async def _wait_for_pumps(self, pumps):
        waiting = set(pumps)
        errors = []
        while waiting:
            done, waiting = await asyncio.wait(
                waiting, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    result = task.result()
                except asyncio.CancelledError as error:
                    errors.append(error)
                    self._pump_results[task] = "pump-cancelled"
                    self._failure_event.set()
                    self._shutdown_owned_sockets()
                    continue
                except SecureConnectorPending:
                    self._pump_results[task] = "pump-pending"
                    self._failure_event.set()
                    self._shutdown_owned_sockets()
                    raise
                except Exception as error:
                    errors.append(error)
                    self._pump_results[task] = "pump-error"
                    self._failure_event.set()
                    self._shutdown_owned_sockets()
                    continue
                self._pump_results[task] = result
                if result == "reset":
                    self._failure_event.set()
                    self._shutdown_owned_sockets()
                elif result not in ("eof", "owned-descriptor-closed"):
                    errors.append(SecureConnectorError(
                        "opaque CONNECT pump did not observe EOF, reset or owned closure"))
                    self._failure_event.set()
                    self._shutdown_owned_sockets()
        self._confirm_owned_closure()
        if errors:
            raise SecureConnectorError(
                "opaque CONNECT pump failed; owned tunnel teardown was requested") from errors[0]

    def _all_pumps_terminal(self):
        return bool(self._pump_tasks) and all(task.done() for task in self._pump_tasks)

    def _close_owned_sockets(self):
        pending = tuple(task for task in self._pump_tasks if not task.done())
        if pending:
            raise SecureConnectorPending(
                pending, "owned socket descriptors still have registered pump readers")
        for sock in tuple(self._owned_sockets):
            self._close_socket(sock)

    def _shutdown_owned_sockets(self):
        self._owner_close_requested = True
        for sock in tuple(self._owned_sockets):
            self._shutdown_socket(sock)

    def _confirm_owned_closure(self):
        task = self._accept_task
        task_done = task is None or task.done()
        pumps_done = all(pump.done() for pump in self._pump_tasks)
        if (task_done and pumps_done and self.listener_closed_confirmed
                and self.owned_sockets_closed):
            if self._pump_tasks:
                statuses = set(self._pump_results.values())
                if "reset" in statuses:
                    self._closure_evidence = "peer reset and owned descriptors closed"
                elif statuses and statuses == {"eof"}:
                    self._closure_evidence = "bidirectional peer EOF and owned descriptors closed"
                elif "pump-error" in statuses or "pump-cancelled" in statuses:
                    self._closure_evidence = "pump failure and owned descriptors closed"
                elif self._owner_close_requested or "owned-descriptor-closed" in statuses:
                    self._closure_evidence = (
                        "both pumps exited after coordinated shutdown; owned descriptors closed")
                else:
                    self._closure_evidence = "pump exit and owned descriptors closed"
            elif self._closure_evidence is None:
                self._closure_evidence = "no tunnel pumps; owned descriptors closed"
            self._closed_confirmed = True

    @staticmethod
    def _shutdown_socket(sock):
        """Request bidirectional shutdown without invalidating selector readers."""
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    @staticmethod
    def _close_socket(sock):
        try:
            sock.close()
        except OSError:
            pass

    async def close(self, *, grace=None):
        if grace is None:
            grace = self.cleanup_grace
        if (isinstance(grace, bool) or not isinstance(grace, (int, float))
                or not math.isfinite(grace) or not 0 <= grace <= MAX_CONNECT_SETUP_SECONDS):
            raise ValueError("outbound gate cleanup grace must be within five seconds")
        if self._closed:
            return
        deadline = time.monotonic() + float(grace)
        self._close_listener()
        if not self._started:
            self._closure_evidence = "gate never started; listener absent"
        task = self._accept_task
        if (task is not None and not task.done() and not self._tunnel_ready
                and not self._upstream_connected):
            task.cancel()
        elif self._owned_sockets:
            # The caller closes the gRPC channel before asking the connector to
            # close. Shutdown wakes the opposite-direction reader while keeping
            # its descriptor valid until the pump finishes. Pump readers are
            # not cancelled: they must observe EOF/reset before descriptor close.
            self._shutdown_owned_sockets()
        if task is not None and task is not asyncio.current_task():
            done, pending = await asyncio.wait((task,),
                timeout=max(0.0, deadline - time.monotonic()))
            if pending:
                raise SecureConnectorPending((task, *self._pump_tasks))
            if not task.cancelled():
                try:
                    task.result()
                except SecureConnectorPending as error:
                    pending_children = tuple(child for child in error.tasks
                                             if not child.done())
                    self._failure_event.set()
                    if pending_children:
                        self._shutdown_owned_sockets()
                        raise SecureConnectorPending(pending_children,
                            "outbound CONNECT accept task still owns child tasks") from error
                except BaseException:
                    # A failed accept/relay task can still be safely retired
                    # once the listener, owned sockets and pumps are closed.
                    # Keep the failure signal, but don't let its exception
                    # bypass physical resource accounting.
                    self._failure_event.set()
                    self._shutdown_owned_sockets()
        if (task is None or task.done()) and self.accepted_count == 0:
            # A task cancelled before its first coroutine step cannot execute
            # its finally block. The listener was closed synchronously above,
            # and no connected socket was ever accepted, so this is a confirmed
            # empty-gate teardown rather than an unobserved tunnel close.
            self._closure_evidence = "empty one-shot gate; listener closed"
        pumps = tuple(self._pump_tasks)
        if pumps:
            done, pending = await asyncio.wait(pumps,
                timeout=max(0.0, deadline - time.monotonic()))
            if pending:
                raise SecureConnectorPending(pending,
                    "outbound CONNECT pumps did not exit after socket shutdown")
            for pump in done:
                try:
                    pump.result()
                except BaseException:
                    pass
        # The accept coroutine may have been cancelled after a successful
        # upstream connect. In that case its finally block can request
        # shutdown but cannot wait for its sibling pumps. The close owner does
        # that bounded wait here and closes only after all readers are done.
        self._close_owned_sockets()
        self._confirm_owned_closure()
        if not self._closed_confirmed:
            for name in ("_deadline_task", "_lifetime_task"):
                await self._stop_timer(name,
                    grace=max(0.0, deadline - time.monotonic()))
            raise SecureConnectorError(
                "outbound tunnel closure lacks completed pumps and closed owned descriptors")
        for name in ("_deadline_task", "_lifetime_task"):
            await self._stop_timer(name,
                grace=max(0.0, deadline - time.monotonic()))
        await self._release_pending()
        self._closed = True
