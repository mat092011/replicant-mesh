"""Bounded worker state and owned-layer execution, independent of RPC hosting.

All state transitions run on one asyncio loop. Compute uses one dedicated thread;
control operations never wait for that thread. A timeout invalidates the session
but cannot interrupt a Torch kernel. The service supervisor enforces the final
termination deadline from outside the inference process.
"""

import asyncio
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import math
import re
import secrets
import time
import uuid

from .manifest import artifact_path, cache_bytes, load_manifest, validate_manifest
from .protocol.codec import decode_tensor, encode_tensor, validate_envelope
from .protocol.clock import clock_identity
from .protocol.errors import ProtocolError
from .protocol.worker_pb2 import Request, Response


METHODS = {"Describe", "OpenSession", "RenewSession", "Step", "CloseSession",
           "CancelSession", "SessionStatus"}
TERMINAL = {"CLOSED_SESSION": "CLOSED", "CANCELLED": "CANCELLED",
            "EXPIRED_SESSION": "EXPIRED", "TIMEOUT": "TIMED_OUT", "EXECUTION_FAILED": "FAILED"}


class StageExecutor:
    """Loads one verified partition, never the complete model or coordinator head."""

    def __init__(self, directory, worker_name):
        from safetensors.torch import load_file
        from transformers import LlamaConfig
        from .model import LayerStage

        self.manifest = load_manifest(directory)
        if worker_name not in ("worker-1", "worker-2", "worker-3"):
            raise ValueError("A fixed worker assignment is required")
        self.worker_name = worker_name
        config = LlamaConfig.from_dict(self.manifest["config"])
        config._attn_implementation = "eager"
        self.start, self.end = self.manifest["components"][worker_name]["layer_range"]
        self.stage = LayerStage(config, self.start, self.end, load_file(
            str(artifact_path(directory, self.manifest, worker_name)), device="cpu"))

    def new_cache(self):
        from .model import LayerCache
        return LayerCache(self.start, self.end)

    def execute(self, hidden, cache, position):
        import torch
        # Inference mode is thread local: it must be enabled in the compute thread.
        with torch.inference_mode():
            return self.stage(hidden, cache, position)


@dataclass
class Session:
    session_id: str
    lease: str
    max_positions: int
    lifetime_ms: int
    idle_lease_ms: int
    deadline: float
    idle_deadline: float
    cache: object
    position: int = 0
    sequence: int = 0
    in_flight: bool = False
    queued: bool = False
    committed_bytes: int = 0
    terminal_code: str = ""
    terminated_at: float = 0.0
    expires_at: float = 0.0
    monotonic_terminated_at: float = 0.0


@dataclass
class Operation:
    request: object
    entry: Session
    hidden: object
    options: dict
    deadline: float
    monotonic_deadline: float
    submitted: float
    completion: object
    identity: str
    compute_started_at: float = 0.0


class WorkerHandler:
    def __init__(self, manifest, worker_name, executor, *, clock=time.monotonic,
                 boot_id=None, max_tombstones=4096, enable_queue=False, queue_capacity=None,
                 on_supervision=None):
        validate_manifest(manifest)
        if worker_name not in ("worker-1", "worker-2", "worker-3"):
            raise ValueError("Unknown worker assignment")
        if type(max_tombstones) is not int or max_tombstones < 1:
            raise ValueError("Tombstone capacity must be positive")
        self.manifest, self.worker_name, self.executor = manifest, worker_name, executor
        self.limits = manifest["limits"]
        if type(enable_queue) is not bool:
            raise ValueError("Queue selection must be boolean")
        if queue_capacity is None:
            queue_capacity = self.limits["max_stage_queue"]
        if (type(queue_capacity) is not int or queue_capacity < 1
                or queue_capacity > self.limits["max_stage_queue"]):
            raise ValueError("Queue capacity must fit the manifest limit")
        self.queue_capacity = queue_capacity if enable_queue else 0
        if on_supervision is not None and not callable(on_supervision):
            raise ValueError("Supervision observer must be callable")
        self.on_supervision = on_supervision
        self.start, self.end = manifest["components"][worker_name]["layer_range"]
        self.clock = clock
        self.boot_id = boot_id or uuid.uuid4().hex
        self.max_tombstones = max_tombstones
        self.sessions, self.tombstones = {}, {}
        self.requires_restart = False
        self.stopping = False
        self._loop = None
        self._sweeper = None
        self._compute_task = None
        self._active_operation = None
        self._queue = deque()
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix=worker_name)
        self._notify_supervisor()

    def _bind_loop(self):
        loop = asyncio.get_running_loop()
        if self._loop is not None and self._loop is not loop:
            raise RuntimeError("WorkerHandler is confined to its original asyncio loop")
        if self._loop is None:
            self._loop = loop
            self._sweeper = loop.create_task(self._sweep_loop())

    async def _sweep_loop(self):
        try:
            while not self.stopping:
                await asyncio.sleep(self.limits["lease_check_interval_seconds"])
                self._reap()
        except asyncio.CancelledError:
            return

    def _reap(self):
        now = self.clock()
        for key, entry in list(self.tombstones.items()):
            if now >= entry.expires_at:
                del self.tombstones[key]
        for entry in list(self.sessions.values()):
            if not entry.terminal_code and now >= min(entry.deadline, entry.idle_deadline):
                self._terminate(entry, "EXPIRED_SESSION")
            if (entry.terminal_code and entry.in_flight
                    and now - entry.terminated_at >= self.limits["compute_cancel_grace_seconds"]):
                self.requires_restart = True
                self._notify_supervisor()
        for operation in list(self._queue):
            if now >= operation.deadline:
                self._terminate(operation.entry, "TIMEOUT")
        if self._active_operation and now >= self._active_operation.deadline:
            self._terminate(self._active_operation.entry, "TIMEOUT")

    def supervision_status(self):
        """Deadline snapshot for a supervisor in a separate OS process.

        Monotonic timestamps are from this host, never received over the network.
        The parent retains a deadline even if this event loop stops reporting.
        """
        operation = self._active_operation
        deadline = terminate_deadline = started = identity = None
        if operation is not None:
            entry = operation.entry
            # Accepted renewals can extend idle time, never the RPC or lifetime.
            deadline = min(operation.monotonic_deadline, time.monotonic() + max(
                0.0, min(entry.deadline, entry.idle_deadline) - self.clock()))
            if entry.terminal_code:
                terminate_deadline = (entry.monotonic_terminated_at
                                      + self.limits["compute_cancel_grace_seconds"])
            started, identity = operation.compute_started_at, operation.identity
        return {"ready": not self.stopping and not self.requires_restart,
                "requires_restart": self.requires_restart,
                "active_compute": operation is not None,
                "compute_deadline": deadline, "terminate_deadline": terminate_deadline,
                "compute_id": identity, "compute_started_at": started}

    def _notify_supervisor(self):
        if self.on_supervision is not None:
            self.on_supervision(self.supervision_status())

    async def reap(self):
        self._bind_loop()
        self._reap()

    def _terminate(self, entry, code):
        if not entry.terminal_code:
            entry.terminal_code = code
            entry.terminated_at = self.clock()
            entry.monotonic_terminated_at = time.monotonic()
        queued_operation = None
        if entry.queued:
            queued_operation = next(op for op in self._queue if op.entry is entry)
            self._queue.remove(queued_operation)
            entry.queued = False
        if not entry.in_flight and entry.session_id in self.sessions:
            entry.cache.clear()
            entry.committed_bytes = 0
            del self.sessions[entry.session_id]
            entry.expires_at = self.clock() + self.limits["rpc_timeout_seconds"]
            self.tombstones[entry.session_id] = entry
        if queued_operation and not queued_operation.completion.done():
            response = self._response(queued_operation.request, entry,
                                      code=entry.terminal_code, message="Queued session cannot continue")
            response.queue_ms = (time.perf_counter() - queued_operation.submitted) * 1000
            queued_operation.completion.set_result(response)
        self._notify_supervisor()

    def _remaining_ms(self, deadline):
        return max(0, int((deadline - self.clock()) * 1000))

    def _response(self, request=None, entry=None, *, code="OK", message=""):
        # Error echoes are bounded too: malformed input must not inflate a reply.
        response = Response(
            protocol_version=1, manifest_fingerprint=self.manifest["fingerprint"],
            worker_boot_id=self.boot_id, code=code, message=message[:256],
            clock_id=clock_identity(), monotonic_ns=time.monotonic_ns(),
            ready=not self.stopping and not self.requires_restart,
            layer_start=self.start, layer_end=self.end,
            hidden_size=self.manifest["config"]["hidden_size"],
            active_sessions=len(self.sessions),
            reserved_positions=sum(s.max_positions for s in self.sessions.values()),
            allocated_cache_bytes=sum(s.committed_bytes for s in self.sessions.values()),
            cache_bytes_exact=not any(s.in_flight for s in self.sessions.values()),
            active_operations=sum(s.in_flight for s in self.sessions.values()),
            queued_operations=len(self._queue), max_stage_queue=self.queue_capacity,
            tombstones=len(self.tombstones), requires_restart=self.requires_restart,
            max_sessions=self.limits["max_sessions"], max_positions_limit=self.limits["max_positions"],
            max_message_bytes=self.limits["max_message_bytes"],
            max_cache_positions=self.limits["worker_cache_positions"],
            max_cache_bytes=self.limits["worker_cache_bytes"],
            lease_check_interval_ms=1000 * self.limits["lease_check_interval_seconds"],
            rpc_timeout_ms=1000 * self.limits["rpc_timeout_seconds"],
        )
        if isinstance(request, Request):
            response.session_id = request.session_id[:64]
            response.lease_token = request.lease_token[:64]
            response.sequence = request.sequence
            response.start_position = request.start_position
            response.token_count = request.token_count
        if entry is not None:
            response.session_id, response.lease_token = entry.session_id, entry.lease
            response.end_position, response.next_sequence = entry.position, entry.sequence
            response.max_positions = entry.max_positions
            response.remaining_lifetime_ms = self._remaining_ms(entry.deadline)
            response.remaining_idle_ms = self._remaining_ms(min(entry.idle_deadline, entry.deadline))
            state = "RUNNING" if entry.in_flight else "QUEUED" if entry.queued else "OPEN"
            response.state = TERMINAL.get(entry.terminal_code, state)
            response.reclaimed = bool(entry.terminal_code and not entry.in_flight)
            response.allocated_cache_bytes = entry.committed_bytes
            response.cache_bytes_exact = not entry.in_flight
        return response

    def _check_request(self, method, request):
        if method not in METHODS or not isinstance(request, Request):
            raise ProtocolError("INVALID_INPUT", "Unknown operation or request type")
        if request.ByteSize() > self.limits["max_message_bytes"]:
            raise ProtocolError("INVALID_INPUT", "Request exceeds message ceiling")
        clean = Request()
        clean.CopyFrom(request)
        clean.DiscardUnknownFields()
        if clean.SerializeToString() != request.SerializeToString():
            raise ProtocolError("INVALID_INPUT", "Unknown protocol fields")
        fields = {field.name for field, _ in request.ListFields()}
        allowed = {"protocol_version", "manifest_fingerprint", "worker_boot_id", "timeout_ms"}
        if method != "Describe":
            allowed.add("session_id")
        if method == "OpenSession":
            allowed.update(("max_positions", "lifetime_ms", "idle_lease_ms"))
        elif method != "Describe":
            allowed.add("lease_token")
        if method == "Step":
            allowed.update(("sequence", "start_position", "token_count", "tensor"))
        if fields - allowed or request.protocol_version != 1:
            raise ProtocolError("INVALID_INPUT", "Unsupported fields or protocol version")
        if not 1 <= request.timeout_ms <= self.limits["rpc_timeout_seconds"] * 1000:
            raise ProtocolError("INVALID_INPUT", "RPC timeout must fit the configured budget")
        if method != "Describe" or request.manifest_fingerprint:
            if request.manifest_fingerprint != self.manifest["fingerprint"]:
                raise ProtocolError("INCOMPATIBLE_MODEL", "Model manifest does not match")
        if method != "Describe" or request.worker_boot_id:
            if request.worker_boot_id != self.boot_id:
                raise ProtocolError("STALE_WORKER", "Worker boot identity does not match")
        if method != "Describe" and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", request.session_id):
            raise ProtocolError("INVALID_INPUT", "Invalid opaque session ID")

    def _lookup(self, request, allow_terminal=False):
        entry = self.sessions.get(request.session_id) or self.tombstones.get(request.session_id)
        if entry is None:
            raise ProtocolError("UNKNOWN_SESSION", "Session is unknown")
        if (not re.fullmatch(r"[0-9a-f]{32}", request.lease_token)
                or not secrets.compare_digest(request.lease_token, entry.lease)):
            raise ProtocolError("INVALID_INPUT", "Session lease does not match")
        if entry.terminal_code and not allow_terminal:
            raise ProtocolError(entry.terminal_code, "Session cannot continue")
        return entry

    def _renew(self, entry):
        entry.idle_deadline = min(entry.deadline, self.clock() + entry.idle_lease_ms / 1000)
        if entry.in_flight:
            self._notify_supervisor()

    def _open(self, request):
        if not 1 <= request.max_positions <= self.limits["max_positions"]:
            raise ProtocolError("INVALID_INPUT", "Invalid context reservation")
        if not 1 <= request.lifetime_ms <= self.limits["request_timeout_seconds"] * 1000:
            raise ProtocolError("INVALID_INPUT", "Invalid session lifetime")
        if not 1 <= request.idle_lease_ms <= self.limits["idle_lease_seconds"] * 1000:
            raise ProtocolError("INVALID_INPUT", "Invalid idle lease")
        existing = self.sessions.get(request.session_id) or self.tombstones.get(request.session_id)
        if existing is not None:
            if existing.terminal_code:
                raise ProtocolError(existing.terminal_code, "Session ID is retired")
            if (existing.max_positions, existing.lifetime_ms, existing.idle_lease_ms) != (
                    request.max_positions, request.lifetime_ms, request.idle_lease_ms):
                raise ProtocolError("INVALID_INPUT", "Conflicting duplicate open")
            self._renew(existing)
            return self._response(request, existing)
        if self.stopping or self.requires_restart:
            raise ProtocolError("CAPACITY_EXHAUSTED", "Worker is not accepting sessions")
        if (len(self.sessions) >= self.limits["max_sessions"]
                or len(self.sessions) + len(self.tombstones) >= self.max_tombstones):
            raise ProtocolError("CAPACITY_EXHAUSTED", "Session or tombstone capacity exhausted")
        positions = sum(s.max_positions for s in self.sessions.values()) + request.max_positions
        reserved_bytes = sum(cache_bytes(self.manifest["config"], self.end - self.start, s.max_positions)
                             for s in self.sessions.values())
        reserved_bytes += cache_bytes(self.manifest["config"], self.end - self.start, request.max_positions)
        if (positions > self.limits["worker_cache_positions"]
                or reserved_bytes > self.limits["worker_cache_bytes"]):
            raise ProtocolError("CAPACITY_EXHAUSTED", "Cache reservation capacity exhausted")
        now = self.clock()
        entry = Session(request.session_id, secrets.token_hex(16), request.max_positions,
                        request.lifetime_ms, request.idle_lease_ms,
                        now + request.lifetime_ms / 1000,
                        now + min(request.lifetime_ms, request.idle_lease_ms) / 1000,
                        self.executor.new_cache())
        self.sessions[entry.session_id] = entry
        return self._response(request, entry)

    async def handle(self, method, request):
        self._bind_loop()
        received_at = self.clock()
        received_perf = time.perf_counter()
        self._reap()
        try:
            self._check_request(method, request)
            if method == "Describe":
                return self._response(request)
            if method == "OpenSession":
                return self._open(request)
            entry = self._lookup(request, allow_terminal=method in (
                "CloseSession", "CancelSession", "SessionStatus"))
            if method == "RenewSession":
                self._renew(entry)
            elif method in ("CloseSession", "CancelSession"):
                self._terminate(entry, "CLOSED_SESSION" if method == "CloseSession" else "CANCELLED")
            elif method == "Step":
                return await self._step(request, entry, received_at, received_perf)
            return self._response(request, entry)
        except ProtocolError as error:
            return self._response(request, code=error.code, message=str(error))

    async def _step(self, request, entry, received_at, received_perf):
        if (entry.in_flight or entry.queued or request.sequence != entry.sequence
                or request.start_position != entry.position):
            raise ProtocolError("OUT_OF_ORDER", "Step does not match the next committed operation")
        if not 1 <= request.token_count <= self.limits["max_positions"]:
            raise ProtocolError("INVALID_INPUT", "Invalid token count")
        if entry.position + request.token_count > entry.max_positions:
            raise ProtocolError("INVALID_INPUT", "Step exceeds the session context reservation")
        options = dict(hidden_size=self.manifest["config"]["hidden_size"],
                       max_tokens=self.limits["max_positions"], max_bytes=self.limits["max_message_bytes"])
        validate_envelope(request.tensor, request.token_count, **options)
        # Includes the finite-value check before changing a reservation or queue.
        hidden = decode_tensor(request.tensor, request.token_count, **options)
        busy = self._active_operation is not None
        if (self.stopping or self.requires_restart
                or (busy and len(self._queue) >= self.queue_capacity)):
            raise ProtocolError("CAPACITY_EXHAUSTED", "Worker compute capacity exhausted")
        if any(length != entry.position for length in entry.cache.lengths()):
            self._terminate(entry, "EXECUTION_FAILED")
            raise ProtocolError("EXECUTION_FAILED", "Committed cache state is inconsistent")
        self._renew(entry)
        deadline = min(received_at + request.timeout_ms / 1000, entry.deadline)
        budget = deadline - self.clock()
        if budget <= 0:
            code = "EXPIRED_SESSION" if self.clock() >= entry.deadline else "TIMEOUT"
            self._terminate(entry, code)
            raise ProtocolError(code, "Step lifetime or timeout budget has expired")
        # Copy metadata before scheduling: a local caller may mutate its protobuf.
        copied = Request()
        copied.CopyFrom(request)
        operation = Operation(copied, entry, hidden, options, deadline,
                              time.monotonic() + budget, received_perf,
                              self._loop.create_future(), uuid.uuid4().hex)
        if busy:
            entry.queued = True
            self._queue.append(operation)
        else:
            self._start(operation)
        try:
            return await asyncio.wait_for(asyncio.shield(operation.completion), timeout=budget)
        except asyncio.TimeoutError:
            was_queued = entry.queued
            self._terminate(entry, "TIMEOUT")
            if was_queued:
                # _terminate resolves a discarded queued operation with its
                # measured wait; retain it instead of returning zero queue time.
                return operation.completion.result()
            return self._response(copied, entry, code="TIMEOUT", message="Step budget expired; session invalidated")
        except asyncio.CancelledError:
            self._terminate(entry, "CANCELLED")
            raise

    def _start(self, operation):
        operation.entry.queued = False
        operation.entry.in_flight = True
        operation.compute_started_at = time.monotonic()
        self._active_operation = operation
        # Synchronous publication must precede thread dispatch: a wedged native
        # call may prevent this event loop from sending another heartbeat.
        self._notify_supervisor()
        self._compute_task = self._loop.create_task(self._run_operation(operation))

    async def _run_operation(self, operation):
        try:
            response = await self._compute(operation.request, operation.entry, operation.hidden,
                                           operation.options, operation.deadline, operation.submitted)
            if not operation.completion.done():
                operation.completion.set_result(response)
        finally:
            if operation.entry.in_flight:
                # A second cancellation may detach us from a still-live thread.
                # Keep its deadline armed and ownership visible until process exit.
                self.requires_restart = True
                self._notify_supervisor()
            else:
                self._active_operation = None
                self._notify_supervisor()
                self._reap()
                if not self.stopping and not self.requires_restart and self._queue:
                    self._start(self._queue.popleft())

    async def _compute(self, request, entry, hidden, options, deadline, submitted):
        queue_ms = compute_ms = 0.0
        compute_start_ns = compute_end_ns = 0
        # Dispatch itself yields to the event loop. A queued operation may have
        # been cancelled or expired after selection but before its task runs.
        # Reclaim it now without sending a stale activation into the thread.
        self._reap()
        if entry.terminal_code:
            entry.in_flight = False
            self._terminate(entry, entry.terminal_code)
            response = self._response(request, entry, code=entry.terminal_code,
                                      message="Session terminated before execution")
            response.queue_ms = (time.perf_counter() - submitted) * 1000
            return response
        future = self._loop.run_in_executor(self._pool, self._execute_timed,
                                            hidden, entry.cache, entry.position, submitted)
        try:
            # The compute future cannot be cancelled by an RPC task losing its caller.
            result, failed, queue_ms, compute_ms, compute_start_ns, compute_end_ns = await asyncio.shield(future)
            if failed:
                raise RuntimeError("Layer execution failed")
            self._reap()
            if not entry.terminal_code and self.clock() >= deadline:
                self._terminate(entry, "TIMEOUT")
            if not entry.terminal_code:
                encoded = encode_tensor(result, **options)
                validate_envelope(encoded, request.token_count, **options)
                self._reap()
                if not entry.terminal_code and self.clock() >= deadline:
                    self._terminate(entry, "TIMEOUT")
                if entry.terminal_code:
                    raise ProtocolError(entry.terminal_code, "Result arrived after termination")
                if any(length != entry.position + request.token_count for length in entry.cache.lengths()):
                    raise RuntimeError("Executor failed to advance every owned cache")
                entry.position += request.token_count
                entry.sequence += 1
                entry.committed_bytes = entry.cache.allocated_bytes()
                entry.in_flight = False
                response = self._response(request, entry)
                response.tensor.CopyFrom(encoded)
                response.queue_ms, response.compute_ms = queue_ms, compute_ms
                response.compute_start_ns, response.compute_end_ns = compute_start_ns, compute_end_ns
                return response
        except asyncio.CancelledError:
            # Shutdown must not release a buffer while a thread is using it. If
            # the loop itself is cancelled, retain ownership until completion.
            self._terminate(entry, "CANCELLED")
            try:
                await asyncio.shield(future)
            except asyncio.CancelledError:
                self.requires_restart = True
                raise
            except Exception:
                pass
        except Exception:
            self._terminate(entry, "EXECUTION_FAILED")
        entry.in_flight = False
        self._terminate(entry, entry.terminal_code or "EXECUTION_FAILED")
        response = self._response(request, entry, code=entry.terminal_code, message="Session cannot continue")
        response.queue_ms, response.compute_ms = queue_ms, compute_ms
        response.compute_start_ns, response.compute_end_ns = compute_start_ns, compute_end_ns
        return response

    def _execute_timed(self, hidden, cache, position, submitted):
        started = time.perf_counter()
        compute_start_ns = time.monotonic_ns()
        try:
            result, failed = self.executor.execute(hidden, cache, position), False
        except Exception:
            result, failed = None, True
        compute_end_ns = time.monotonic_ns()
        return (result, failed, (started - submitted) * 1000,
                (time.perf_counter() - started) * 1000, compute_start_ns, compute_end_ns)

    async def shutdown(self, grace_seconds=None):
        self._bind_loop()
        if grace_seconds is None:
            grace_seconds = self.limits["compute_cancel_grace_seconds"]
        if not isinstance(grace_seconds, (int, float)) or not math.isfinite(grace_seconds) or grace_seconds <= 0:
            raise ValueError("Shutdown grace must be finite and positive")
        self.stopping = True
        self._notify_supervisor()
        if self._sweeper:
            self._sweeper.cancel()
            await asyncio.gather(self._sweeper, return_exceptions=True)
        for entry in list(self.sessions.values()):
            self._terminate(entry, "CANCELLED")
        task = self._compute_task
        if task and not task.done():
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=grace_seconds)
            except asyncio.TimeoutError:
                self.requires_restart = True
                self._notify_supervisor()
                self._pool.shutdown(wait=False, cancel_futures=True)
                return False
        self._pool.shutdown(wait=False, cancel_futures=True)
        return True
