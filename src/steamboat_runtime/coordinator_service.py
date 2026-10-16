"""Private, supervised coordinator listener with bounded streaming and diagnostics."""

import argparse
import asyncio
from collections import deque
import importlib.metadata
import os
import signal
import sys
import time
import uuid

from .remote_client import (SERVICE, MAX_MESSAGE_BYTES, MAX_GENERATE_BYTES,
                            MAX_TOKENIZE_BYTES, RemoteError, decode_json,
                            encode_json, validate_generate, validate_text)


def process_resources():
    import psutil
    import resource
    return {"pid": os.getpid(), "rss_bytes": psutil.Process().memory_info().rss,
            "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024}


def runtime_versions():
    return {"python": sys.version.split()[0], **{
        name: importlib.metadata.version(name)
        for name in ("torch", "transformers", "grpcio", "protobuf", "safetensors")}}


def supervised_model_class():
    """Build the model class lazily so protocol/client imports stay Torch-free."""
    import torch
    from .coordinator_model import CoordinatorModel

    class SupervisedModel(CoordinatorModel):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.operations = {}
            self.on_supervision = None

        def supervision_status(self):
            operations = [item for item in self.operations.values()
                          if item["future"] is None or not item["future"].done()]
            # One execution thread, FIFO submission. Track the oldest accepted
            # operation, including any operation abandoned by its asyncio waiter.
            current = min(operations, key=lambda item: item["submitted"], default=None)
            return {"ready": not self._closed, "requires_restart": self.requires_restart,
                    "active_compute": current is not None,
                    "compute_id": current["identity"] if current else None,
                    "compute_deadline": current["deadline"] if current else None,
                    "terminate_deadline": current["terminate"] if current else None}

        def publish(self):
            if self.on_supervision:
                self.on_supervision(self.supervision_status())

        async def _call(self, operation, *args):
            if self._closed:
                raise RuntimeError("Coordinator model is closed")
            loop = asyncio.get_running_loop()
            if self._loop is not None and loop is not self._loop:
                raise RuntimeError("Coordinator model must stay on one event loop")
            self._loop = loop
            self._pending.difference_update(f for f in tuple(self._pending) if f.done())
            if len(self._pending) >= self._capacity:
                raise RuntimeError("Coordinator CPU operation capacity exhausted")
            identity, now = uuid.uuid4().hex, time.monotonic()
            record = {"identity": identity, "submitted": now, "future": None,
                      "deadline": now + self.limits["rpc_timeout_seconds"], "terminate": None}
            self.operations[identity] = record
            # The independent parent receives the deadline before a CPU callable
            # can hold the GIL or stop the child's asyncio heartbeat.
            self.publish()

            def execute():
                with torch.inference_mode():
                    return operation(*args)

            try:
                future = self._executor.submit(execute)
            except BaseException:
                self.operations.pop(identity, None)
                self.publish()
                raise
            record["future"] = future
            self._pending.add(future)

            def completed(_):
                def release():
                    self._pending.discard(future)
                    self.operations.pop(identity, None)
                    self.publish()
                try:
                    loop.call_soon_threadsafe(release)
                except RuntimeError:
                    pass

            future.add_done_callback(completed)
            wrapped = asyncio.wrap_future(future)
            wrapped.add_done_callback(self._observe_completion)
            try:
                return await asyncio.shield(wrapped)
            except asyncio.CancelledError:
                # Cancelling a pending Future is safe. An executing thread keeps
                # its reservation and gets a parent-enforced termination deadline.
                if not future.cancel() and not future.done():
                    record["terminate"] = time.monotonic() + self.limits["compute_cancel_grace_seconds"]
                self.publish()
                raise

    return SupervisedModel


class RequestMetrics:
    """Fixed-size counters, never prompt/token payloads or unbounded trace lists."""

    def __init__(self):
        self.admission_ms = None
        self.trace_first = []
        self.trace_tail = deque(maxlen=6)
        self.stages = [{"worker": worker, "phase": phase, "dispatches": 0,
                        "responses": 0, "scheduler_queue_ms": 0.0,
                        "worker_queue_ms": 0.0, "worker_compute_ms": 0.0,
                        "rpc_ms": 0.0, "request_bytes": 0, "response_bytes": 0}
                       for worker in (1, 2, 3) for phase in ("prefill", "decode")]

    def record(self, event):
        kind = event["event"]
        if kind == "admitted":
            self.admission_ms = event["admission_ms"]
        if kind not in {"stage_dispatch", "stage_response"}:
            return
        # Deliberate partial trace: fixed memory even for the maximum context.
        # Events contain identities/timing/byte counts, never activation payloads.
        if len(self.trace_first) < 6:
            self.trace_first.append(dict(event))
        else:
            self.trace_tail.append(dict(event))
        cell = self.stages[2 * (event["worker"] - 1) + int(event["sequence"] != 0)]
        if kind == "stage_dispatch":
            cell["dispatches"] += 1
            cell["scheduler_queue_ms"] += (event["dispatch_ns"] - event["queued_ns"]) / 1e6
            cell["request_bytes"] += event["request_bytes"]
        else:
            cell["responses"] += 1
            cell["worker_queue_ms"] += event["queue_ms"]
            cell["worker_compute_ms"] += event["compute_ms"]
            cell["rpc_ms"] += (event["coordinator_ns"] - event["dispatch_ns"]) / 1e6
            cell["response_bytes"] += event["response_bytes"]

    def result(self, result):
        return {"admission_ms": self.admission_ms, "stages": self.stages,
                "trace_sample": self.trace_first + list(self.trace_tail),
                "trace_scope": "partial: first six and last six stage events; counters cover every event",
                "server_elapsed_ms": 1000 * (result.finished_at - result.submitted_at),
                "bytes_scope": "serialized worker Step protobuf messages only",
                "timing_scope": "local durations; rpc includes worker queue and compute"}


class CoordinatorService:
    def __init__(self, coordinator, *, loading_seconds=0, max_streams=None):
        self.coordinator = coordinator
        self.manifest = coordinator.manifest
        bound = coordinator.limits.max_sessions + coordinator.limits.max_waiting_admissions
        self.max_streams = bound if max_streams is None else max_streams
        if type(self.max_streams) is not int or not 1 <= self.max_streams <= bound:
            raise ValueError("Service stream bound must not exceed the scheduler bound")
        self.loading_seconds = loading_seconds
        self.active_streams = self.tokenizing = self.describing = 0
        self.counters = {name: 0 for name in ("completed_requests", "failed_requests",
                         "cancelled_requests", "cleanup_incomplete_requests", "rejected_requests",
                         "disconnected_streams", "transport_stalls")}
        self.metrics = {}
        self.cleanups = set()
        self._previous_trace = coordinator.trace
        coordinator.trace = self._trace
        self._runtime = runtime_versions()

    def _trace(self, event):
        sid = event.get("session_id")
        if event["event"] == "submitted":
            self.metrics[sid] = RequestMetrics()
        if sid in self.metrics:
            self.metrics[sid].record(event)
        if self._previous_trace:
            self._previous_trace(event)

    async def describe(self, timeout=1.2):
        from .coordinator import CoordinatorError
        from .protocol.errors import ProtocolError
        from .worker import validate_ready

        async def worker(index):
            name = f"worker-{index + 1}"
            try:
                response = await self.coordinator._execute(index, "Describe",
                    self.coordinator._envelope(index, timeout=timeout))
                validate_ready(response, self.manifest, name)
                if response.worker_boot_id != self.coordinator.boot_ids[index]:
                    self.coordinator._fail_workers(CoordinatorError("STALE_WORKER", "Worker boot changed"))
                    raise RuntimeError("Worker boot changed")
                names = ("worker_boot_id", "ready", "layer_start", "layer_end",
                         "active_sessions", "reserved_positions", "allocated_cache_bytes",
                         "cache_bytes_exact", "active_operations", "queued_operations",
                         "tombstones", "requires_restart", "max_cache_bytes", "max_cache_positions")
                return {"name": name, **{key: getattr(response, key) for key in names}}
            except ProtocolError as error:
                # The real binary transport rejects an old boot/model identity
                # before a response reaches the readiness validation above.
                if error.code in {"STALE_WORKER", "INCOMPATIBLE_MODEL"}:
                    self.coordinator._fail_workers(CoordinatorError(error.code, "Worker identity changed"))
                return {"name": name, "ready": False, "error": "Worker diagnostics unavailable or incompatible"}
            except Exception:
                return {"name": name, "ready": False, "error": "Worker diagnostics unavailable or incompatible"}

        workers = await asyncio.gather(*(worker(index) for index in range(3)))
        scheduler = self.coordinator.stats()
        diagnostics = getattr(self.coordinator.model, "diagnostics", lambda: {})()
        return {"protocol_version": 1, "ready": scheduler["ready"] and all(w["ready"] for w in workers),
                "fingerprint": self.manifest["fingerprint"],
                "model": {key: self.manifest[key] for key in ("model_id", "revision", "dtype", "device", "attention")},
                "config": self.manifest["config"], "limits": self.manifest["limits"],
                "runtime": self._runtime, "resources": process_resources(),
                "model_diagnostics": diagnostics, "scheduler": scheduler, "workers": workers,
                "service": {"active_streams": self.active_streams, "max_streams": self.max_streams,
                            "tokenizing": self.tokenizing, "loading_seconds": self.loading_seconds,
                            "metrics_sessions": len(self.metrics), **self.counters}}

    async def _abort(self, context, error):
        import grpc
        codes = {"INVALID_INPUT": grpc.StatusCode.INVALID_ARGUMENT,
                 "CAPACITY_EXHAUSTED": grpc.StatusCode.RESOURCE_EXHAUSTED,
                 "TIMEOUT": grpc.StatusCode.DEADLINE_EXCEEDED,
                 "NOT_READY": grpc.StatusCode.UNAVAILABLE}
        await context.abort(codes.get(error.code, grpc.StatusCode.INTERNAL), error.message)

    async def describe_rpc(self, data, context):
        try:
            if decode_json(data, 64):
                raise RemoteError("INVALID_INPUT", "Describe accepts an empty object")
            if self.describing >= 4:
                raise RemoteError("CAPACITY_EXHAUSTED", "Diagnostics capacity exhausted")
        except RemoteError as error:
            return await self._abort(context, error)
        self.describing += 1
        try:
            remaining = context.time_remaining()
            return encode_json(await self.describe(min(1.2, max(0.001, remaining or 1.2))))
        finally:
            self.describing -= 1

    async def tokenize_rpc(self, data, context):
        try:
            request = decode_json(data, MAX_TOKENIZE_BYTES)
            text = validate_text(request)
            if not self.coordinator.stats()["ready"]:
                raise RemoteError("NOT_READY", "Coordinator is not ready")
            if self.tokenizing >= self.coordinator.limits.max_sessions:
                raise RemoteError("CAPACITY_EXHAUSTED", "Tokenizer capacity exhausted")
        except RemoteError as error:
            return await self._abort(context, error)
        self.tokenizing += 1
        try:
            async with asyncio.timeout(min(30, context.time_remaining() or 30)):
                if request.get("add_special_tokens", True):
                    ids = await self.coordinator.model.tokenize(text)
                else:
                    model = self.coordinator.model

                    def encode_fixture():
                        ids = model.tokenizer(text, return_tensors="pt", truncation=False,
                                              add_special_tokens=False)["input_ids"]
                        model.validate_tokens(ids)
                        return ids

                    ids = await model._call(encode_fixture)
            return encode_json({"input_ids": ids.reshape(-1).tolist()})
        except ValueError:
            await self._abort(context, RemoteError("INVALID_INPUT", "Tokenized text exceeds the model bounds"))
        except TimeoutError:
            await self._abort(context, RemoteError("TIMEOUT", "Tokenization deadline expired"))
        except RuntimeError:
            await self._abort(context, RemoteError("CAPACITY_EXHAUSTED", "Tokenizer operation unavailable"))
        finally:
            self.tokenizing -= 1

    async def _write(self, context, value, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Stream deadline expired")
        payload = encode_json(value)
        await asyncio.wait_for(context.write(payload), min(
            remaining, self.coordinator.limits.output_stall_timeout_seconds))

    async def _finish(self, handle, *, cancel):
        try:
            result = await (handle.cancel() if cancel else handle.result())
            self.counters[{"completed": "completed_requests", "cancelled": "cancelled_requests",
                           "failed": "failed_requests"}[result.status]] += 1
            if not result.cleanup_complete:
                self.counters["cleanup_incomplete_requests"] += 1
        finally:
            self.metrics.pop(handle.session_id, None)
            self.active_streams -= 1

    async def generate_rpc(self, data, context):
        from .coordinator import CoordinatorError
        import torch

        received = time.monotonic()
        handle = None
        finished = False
        if self.active_streams >= self.max_streams:
            self.counters["rejected_requests"] += 1
            await self._abort(context, RemoteError("CAPACITY_EXHAUSTED", "Stream capacity exhausted"))
            return
        # Counts parsing/submission and streaming, including streams draining a
        # completed scheduler request and disconnected requests still cleaning up.
        self.active_streams += 1
        try:
            request = validate_generate(decode_json(data, MAX_GENERATE_BYTES))
            duration = min(request["timeout_seconds"], context.time_remaining() or request["timeout_seconds"])
            deadline = received + duration
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RemoteError("TIMEOUT", "Request deadline expired before admission")
            handle = self.coordinator.submit(torch.tensor([request["input_ids"]], dtype=torch.long),
                request["new_tokens"], forced_tokens=request.get("forced_tokens"),
                capture_logits=request["capture_logits"], timeout_seconds=remaining)
            try:
                async for event in handle:
                    message = {"type": "token", "session_id": event.session_id,
                               "index": event.index, "token_id": event.token_id,
                               "position": event.position, "sequence": event.sequence}
                    if event.logits is not None:
                        message["logits"] = event.logits.reshape(-1).tolist()
                    await self._write(context, message, deadline)
            except CoordinatorError:
                # The terminal result carries the scheduler's sanitized error.
                pass
            result = await handle.result()
            metrics = self.metrics[handle.session_id].result(result)
            metrics["service_elapsed_ms"] = 1000 * (time.monotonic() - received)
            await self._write(context, {"type": "result", "session_id": result.session_id,
                "status": result.status, "token_ids": list(result.token_ids),
                "cleanup_complete": result.cleanup_complete, "error": result.error,
                "error_code": result.error_code, "metrics": metrics}, deadline)
            finished = True
        except (RemoteError, CoordinatorError) as error:
            self.counters["rejected_requests"] += int(handle is None)
            await self._abort(context, RemoteError(error.code, error.message))
        except TimeoutError:
            self.counters["transport_stalls"] += 1
            await self._abort(context, RemoteError("TIMEOUT", "Output transport or request deadline expired"))
        except asyncio.CancelledError:
            self.counters["disconnected_streams"] += 1
            raise
        finally:
            if handle is None:
                self.active_streams -= 1
            else:
                cleanup = asyncio.create_task(self._finish(handle, cancel=not finished))
                self.cleanups.add(cleanup)
                cleanup.add_done_callback(self.cleanups.discard)
                # The task owns its stream slot until actual reclamation, even
                # when grpc cancels this handler again during shutdown.
                await asyncio.shield(cleanup)

    async def close(self):
        clean = await self.coordinator.close()
        if self.cleanups:
            await asyncio.gather(*tuple(self.cleanups), return_exceptions=True)
        return clean


async def create_server(service, host="127.0.0.1:0", *, private_network=False):
    import grpc
    from .protocol.transport import validate_endpoint
    validate_endpoint(host, private_network=private_network, listen=True)
    server = grpc.aio.server(options=(("grpc.max_send_message_length", MAX_MESSAGE_BYTES),
        ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES), ("grpc.enable_retries", 0)),
        maximum_concurrent_rpcs=service.max_streams + 12)
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(SERVICE, {
        "Describe": grpc.unary_unary_rpc_method_handler(service.describe_rpc),
        "Tokenize": grpc.unary_unary_rpc_method_handler(service.tokenize_rpc),
        "Generate": grpc.unary_stream_rpc_method_handler(service.generate_rpc)}),))
    port = server.add_insecure_port(host)
    if not port:
        raise RuntimeError("Could not bind coordinator listener")
    await server.start()
    return server, port


async def serve_child(artifacts, workers, host, *, private_network=False):
    import torch
    from .coordinator import Coordinator
    from .protocol.transport import GrpcClient
    from .worker import _frame

    threads = int(os.environ.get("OMP_NUM_THREADS", "2"))
    if not 1 <= threads <= 24:
        raise ValueError("OMP_NUM_THREADS must be between 1 and 24")
    torch.set_num_threads(threads)
    started = time.monotonic()
    model = supervised_model_class().from_artifacts(artifacts)
    clients = [GrpcClient(target, private_network=private_network) for target in workers]
    coordinator = Coordinator(model.manifest, clients, model)
    try:
        await coordinator.start()
    except BaseException:
        await coordinator.close()
        raise
    service = CoordinatorService(coordinator, loading_seconds=time.monotonic() - started)
    try:
        server, _ = await create_server(service, host, private_network=private_network)
    except BaseException:
        await service.close()
        raise
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)

    fatal_since = None

    def status():
        nonlocal fatal_since
        value = model.supervision_status()
        value["ready"] = coordinator.stats()["ready"]
        if coordinator._fatal_error is not None:
            fatal_since = time.monotonic() if fatal_since is None else fatal_since
            # Give request tasks their normal bounded lease cleanup before the
            # parent replaces this process. An unresponsive event loop or model
            # thread remains covered by the independent watchdog deadlines.
            drained = not coordinator._requests and not service.cleanups
            value["requires_restart"] |= drained or time.monotonic() - fatal_since >= 21
        return value

    model.on_supervision = lambda _: _frame("heartbeat", status())
    diagnostics = model.diagnostics()
    resources = process_resources()
    _frame("ready", status(), worker="coordinator", loading_seconds=service.loading_seconds,
           rss_bytes=resources["rss_bytes"], startup_peak_rss_bytes=resources["peak_rss_bytes"],
           parameter_count=diagnostics["parameter_count"], parameter_bytes=diagnostics["parameter_bytes"])

    async def heartbeat():
        while True:
            _frame("heartbeat", status())
            await asyncio.sleep(0.1)

    pulse = asyncio.create_task(heartbeat())
    try:
        await stop.wait()
        await server.stop(0)
        return 0 if await service.close() else 70
    finally:
        pulse.cancel()
        await asyncio.gather(pulse, return_exceptions=True)
        await server.stop(0)


async def health(artifacts, target, *, private_network=False):
    from .manifest import load_manifest
    from .remote_client import RemoteClient
    manifest = load_manifest(artifacts)
    async with RemoteClient(target, private_network=private_network) as client:
        value = await client.describe(timeout_seconds=1.5)
    if (value.get("ready") is not True or value.get("fingerprint") != manifest["fingerprint"]
            or value.get("protocol_version") != 1):
        raise RuntimeError("Coordinator readiness failed")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("serve", "_serve-child", "health"):
        command = commands.add_parser(name)
        command.add_argument("--artifacts", required=True)
        command.add_argument("--private-network", action="store_true")
        if name == "health":
            command.add_argument("--target", default="127.0.0.1:50052")
        else:
            command.add_argument("--workers", nargs=3, required=True)
            command.add_argument("--host", default="127.0.0.1:50052")
    args = parser.parse_args(argv)
    if args.command == "serve":
        from .supervisor import run_supervised
        child = [sys.executable, "-u", "-m", "steamboat_runtime.coordinator_service", "_serve-child",
                 "--artifacts", args.artifacts, "--workers", *args.workers, "--host", args.host]
        if args.private_network:
            child.append("--private-network")
        return run_supervised(child, child_shutdown_grace=40)
    try:
        if args.command == "health":
            asyncio.run(health(args.artifacts, args.target, private_network=args.private_network))
            return 0
        return asyncio.run(serve_child(args.artifacts, args.workers, args.host,
                                      private_network=args.private_network))
    except Exception as error:
        import json
        print(json.dumps({"event": "coordinator_failed", "error_type": type(error).__name__}),
              file=sys.stderr, flush=True)
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
