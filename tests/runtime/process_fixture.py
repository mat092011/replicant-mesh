"""Local subprocess fixtures. No production RPC can select these executors."""

import argparse
import asyncio
import sys
import threading
import time


class Cache:
    def __init__(self, layers):
        self.position, self.layers = 0, layers

    def lengths(self):
        return [self.position] * self.layers

    def allocated_bytes(self):
        return self.position * self.layers * 2 * 64 * 4

    def clear(self):
        self.position = 0


class Executor:
    def __init__(self, artifacts, worker, block=False, delay_ms=0):
        from steamboat_runtime.manifest import load_manifest
        self.manifest = load_manifest(artifacts)
        start, end = self.manifest["components"][worker]["layer_range"]
        self.layers, self.block, self.delay_ms = end - start, block, delay_ms

    def new_cache(self):
        return Cache(self.layers)

    def execute(self, hidden, cache, position):
        cache.position += hidden.shape[1]
        if self.block:
            # No release path: the supervisor must really terminate this child.
            threading.Event().wait()
        if self.delay_ms:
            time.sleep(self.delay_ms / 1000)
        return hidden + 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("supervise", "child"))
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--block", action="store_true")
    parser.add_argument("--delay-ms", type=int, default=0)
    args = parser.parse_args()
    if args.command == "supervise":
        from steamboat_runtime.supervisor import run_supervised
        command = [sys.executable, "-u", __file__, "child", "--artifacts", args.artifacts,
                   "--host", args.host]
        if args.block:
            command.append("--block")
        command += ["--delay-ms", str(args.delay_ms)]
        return run_supervised(command)
    from steamboat_runtime.worker import serve_child
    return asyncio.run(serve_child(args.artifacts, "worker-1", args.host,
        executor_factory=lambda artifacts, worker: Executor(artifacts, worker, args.block, args.delay_ms)))


if __name__ == "__main__":
    raise SystemExit(main())
