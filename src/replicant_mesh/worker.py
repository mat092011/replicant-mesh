"""Serve one fixed resident partition under an independent process supervisor."""

import argparse
import asyncio
import json
import os
import signal
import sys
import time


def _frame(event, status, **fields):
    payload = (json.dumps({"event": event, "status": status, **fields},
                          sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    if len(payload) > 4096:
        raise RuntimeError("Supervision frame exceeds its fixed bound")
    # This local control pipe is written before compute is submitted. The parent
    # is a separate Python process and can kill this process if its GIL wedges.
    os.write(sys.stdout.fileno(), payload)


async def serve_child(artifacts, worker_name, host, *, private_network=False,
                      executor_factory=None):
    """Child implementation; executor injection is local to process tests only."""
    import torch
    from .protocol.transport import create_server
    from .worker_state import StageExecutor, WorkerHandler

    threads = int(os.environ.get("OMP_NUM_THREADS", "2"))
    if not 1 <= threads <= 24:
        raise ValueError("OMP_NUM_THREADS must be between 1 and 24")
    torch.set_num_threads(threads)
    started = time.monotonic()
    executor = (executor_factory or StageExecutor)(artifacts, worker_name)
    listening = False

    def publish(status):
        if listening:
            _frame("heartbeat", status)

    handler = WorkerHandler(executor.manifest, worker_name, executor,
                            enable_queue=True, on_supervision=publish)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    server, port = await create_server(handler, host, private_network=private_network)
    listening = True
    await handler.reap()
    stage = getattr(executor, "stage", None)
    parameters = list(stage.parameters()) if stage is not None else []
    import psutil
    import resource
    _frame("ready", handler.supervision_status(), boot_id=handler.boot_id,
           worker=worker_name, layer_start=handler.start, layer_end=handler.end,
           loading_seconds=time.monotonic() - started,
           rss_bytes=psutil.Process().memory_info().rss,
           startup_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
           parameter_count=sum(p.numel() for p in parameters),
           parameter_bytes=sum(p.numel() * p.element_size() for p in parameters))

    async def heartbeat():
        while True:
            _frame("heartbeat", handler.supervision_status())
            await asyncio.sleep(0.1)

    pulse = asyncio.create_task(heartbeat())
    try:
        await stop.wait()
        # shutdown marks all live/queued requests terminal before yielding.
        closing = asyncio.create_task(handler.shutdown())
        await asyncio.sleep(0)
        await server.stop(0)
        clean = await closing
        if not clean:
            # The parent enforces/reaps the child deadline even if asyncio's
            # subsequent teardown cannot join a wedged inference thread.
            return 70
        return 0
    finally:
        pulse.cancel()
        await asyncio.gather(pulse, return_exceptions=True)
        await server.stop(0)


def validate_ready(response, manifest, worker_name):
    """Validate assignment and immutable limits, not merely an open TCP port."""
    from .protocol import PROTOCOL_VERSION
    component = manifest["components"][worker_name]
    limits = manifest["limits"]
    expected = {
        "protocol_version": PROTOCOL_VERSION,
        "manifest_fingerprint": manifest["fingerprint"],
        "layer_start": component["layer_range"][0],
        "layer_end": component["layer_range"][1],
        "hidden_size": manifest["config"]["hidden_size"],
        "max_sessions": limits["max_sessions"],
        "max_positions_limit": limits["max_positions"],
        "max_message_bytes": limits["max_message_bytes"],
        "max_cache_positions": limits["worker_cache_positions"],
        "max_cache_bytes": limits["worker_cache_bytes"],
        "rpc_timeout_ms": 1000 * limits["rpc_timeout_seconds"],
        "lease_check_interval_ms": 1000 * limits["lease_check_interval_seconds"],
        "max_stage_queue": limits["max_stage_queue"],
    }
    if response.code != "OK" or not response.ready or response.requires_restart:
        raise RuntimeError("Worker is not ready")
    if len(response.worker_boot_id) != 32 or any(c not in "0123456789abcdef" for c in response.worker_boot_id):
        raise RuntimeError("Worker boot identity is invalid")
    for name, value in expected.items():
        if getattr(response, name) != value:
            raise RuntimeError(f"Worker readiness mismatch: {name}")
    return response


async def health(artifacts, worker_name, target, *, private_network=False):
    from .manifest import load_manifest
    from .protocol.transport import GrpcClient
    from .protocol.worker_pb2 import Request
    manifest = load_manifest(artifacts)
    async with GrpcClient(target, private_network=private_network, max_timeout_ms=1500) as client:
        response = await client.execute("Describe", Request(protocol_version=1, timeout_ms=1500,
                                       manifest_fingerprint=manifest["fingerprint"]))
    return validate_ready(response, manifest, worker_name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("serve", "_serve-child", "health"):
        command = commands.add_parser(name)
        command.add_argument("--artifacts", required=True)
        command.add_argument("--worker", required=True, choices=("worker-1", "worker-2", "worker-3"))
        command.add_argument("--private-network", action="store_true",
                             help="Opt into the trusted private Docker network; no authentication")
        if name == "health":
            command.add_argument("--target", default="127.0.0.1:50051")
        else:
            command.add_argument("--host", default="127.0.0.1:50051")
    args = parser.parse_args(argv)
    if args.command == "serve":
        from .supervisor import run_supervised
        child = [sys.executable, "-u", "-m", "replicant_mesh.worker", "_serve-child",
                 "--artifacts", args.artifacts, "--worker", args.worker, "--host", args.host]
        if args.private_network:
            child.append("--private-network")
        return run_supervised(child)
    if args.command == "health":
        try:
            asyncio.run(health(args.artifacts, args.worker, args.target,
                               private_network=args.private_network))
        except Exception:
            print("Worker readiness failed", file=sys.stderr)
            return 1
        return 0
    try:
        result = asyncio.run(serve_child(args.artifacts, args.worker, args.host,
                                        private_network=args.private_network))
    except Exception as error:
        # Exception type is enough for deployment diagnostics. Do not expose
        # request payloads or unexpected values from third-party exceptions.
        print(json.dumps({"event": "worker_start_failed", "error_type": type(error).__name__}),
              file=sys.stderr, flush=True)
        result = 70
    return result


if __name__ == "__main__":
    raise SystemExit(main())
