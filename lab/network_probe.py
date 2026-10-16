"""Bounded synthetic TCP exchange/bulk probe inside the private Docker lab.

Times use the measuring process's monotonic clock. RTT is a persistent TCP echo
exchange, not ICMP. Bulk rates include application/ACK overhead, not a link cap.
"""

import argparse
import asyncio
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import secrets
import time

PORT = 50053
MAX_BYTES = 16 * 1024 * 1024
CHUNK = b"p" * 65536


async def send_bulk(writer, count):
    while count:
        size = min(count, len(CHUNK))
        writer.write(CHUNK[:size])
        await writer.drain()
        count -= size


async def receive_bulk(reader, count):
    while count:
        size = min(count, len(CHUNK))
        data = await reader.readexactly(size)
        if data != CHUNK[:size]:
            raise ValueError("Probe payload mismatch")
        count -= size


class ProbeServer:
    def __init__(self, token):
        if len(token) != 32 or any(c not in "0123456789abcdef" for c in token):
            raise ValueError("Probe ownership token must be 32 hex characters")
        self.token, self.stop, self.active = token, asyncio.Event(), 0

    async def handle(self, reader, writer):
        if self.active >= 4:
            writer.close()
            return
        self.active += 1
        try:
            async with asyncio.timeout(45):
                line = await reader.readline()
                if len(line) > 256:
                    raise ValueError("Probe header too long")
                parts = line.decode("ascii").strip().split()
                if len(parts) != 3 or not secrets.compare_digest(parts[0], self.token):
                    raise ValueError("Probe ownership mismatch")
                command, count = parts[1], int(parts[2])
                if not 1 <= count <= MAX_BYTES:
                    raise ValueError("Probe count exceeds bound")
                if command == "stop":
                    self.stop.set()
                    writer.write(b"OK\n")
                elif command == "ping" and count <= 20:
                    writer.write(b"OK\n")
                    await writer.drain()
                    for _ in range(count):
                        if await reader.readexactly(1) != b"p":
                            raise ValueError("Invalid echo byte")
                        writer.write(b"p")
                        await writer.drain()
                elif command == "download":
                    writer.write(b"OK\n")
                    await writer.drain()
                    # The measuring peer starts its clock before releasing bulk
                    # data, so already buffered payload cannot inflate goodput.
                    if await reader.readexactly(1) != b"g":
                        raise ValueError("Invalid bulk start acknowledgement")
                    await send_bulk(writer, count)
                elif command == "upload":
                    writer.write(b"OK\n")
                    await writer.drain()
                    await receive_bulk(reader, count)
                    writer.write(b"OK\n")
                else:
                    raise ValueError("Unsupported probe operation")
                await writer.drain()
        except (ValueError, UnicodeError, OSError, TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            self.active -= 1
            writer.close()
            await writer.wait_closed()


async def connect(host, token, command, count, port=PORT):
    reader, writer = await asyncio.open_connection(host, port, limit=1024)
    writer.write(f"{token} {command} {count}\n".encode("ascii"))
    await writer.drain()
    if await reader.readline() != b"OK\n":
        writer.close()
        await writer.wait_closed()
        raise ValueError("Probe rejected operation or ownership token")
    return reader, writer


async def measure(host, token, count=8 * 1024 * 1024, *, port=PORT):
    if type(count) is not int or not 1 <= count <= MAX_BYTES:
        raise ValueError("Probe byte count exceeds bound")
    evidence = {"host": host, "bulk_bytes": count, "rtt_seconds": [],
                "rtt_method": "persistent TCP one-byte echo after handshake",
                "rate_method": "payload bytes / monotonic transfer time; excludes connection setup; includes upload completion ACK or download GO"}
    async with asyncio.timeout(150):
        reader, writer = await connect(host, token, "ping", 5, port)
        try:
            for _ in range(5):
                started = time.monotonic()
                writer.write(b"p")
                await writer.drain()
                if await reader.readexactly(1) != b"p":
                    raise ValueError("Invalid echo")
                evidence["rtt_seconds"].append(time.monotonic() - started)
        finally:
            writer.close()
            await writer.wait_closed()
        for command in ("upload", "download"):
            reader, writer = await connect(host, token, command, count, port)
            try:
                started = time.monotonic()
                if command == "upload":
                    await send_bulk(writer, count)
                    if await reader.readline() != b"OK\n":
                        raise ValueError("Upload not acknowledged")
                else:
                    writer.write(b"g")
                    await writer.drain()
                    await receive_bulk(reader, count)
                duration = time.monotonic() - started
                evidence[command + "_seconds"] = duration
                evidence[command + "_mbit_per_second"] = count * 8 / duration / 1e6
            finally:
                writer.close()
                await writer.wait_closed()
    return evidence


async def run(args):
    if args.command == "serve":
        from steamboat_runtime.protocol.transport import validate_endpoint
        validate_endpoint(f"{args.host}:{args.port}", listen=True, private_network=args.private_network)
        handler = ProbeServer(args.token)
        server = await asyncio.start_server(handler.handle, args.host, args.port, limit=1024)
        async with server:
            # Expiry bounds forgotten probes even if the controlling shell dies.
            try:
                await asyncio.wait_for(handler.stop.wait(), 3600)
            except TimeoutError:
                pass
        return {"stopped": True}
    if args.command == "stop":
        async with asyncio.timeout(5):
            _, writer = await connect(args.host, args.token, "stop", 1, args.port)
            writer.close()
            await writer.wait_closed()
        return {"stopped": True}
    return await measure(args.host, args.token, args.bytes, port=args.port)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["serve", "measure", "stop"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--token", required=True)
    parser.add_argument("--private-network", action="store_true")
    parser.add_argument("--bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--output")
    args = parser.parse_args()
    result = {"created_utc": datetime.now(timezone.utc).isoformat(), "success": False}
    try:
        if not 1 <= args.port <= 65535:
            raise ValueError("Invalid port")
        result.update(asyncio.run(run(args)))
        result["success"] = True
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    if args.output:
        with Path(args.output).open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, allow_nan=False)
    print(json.dumps(result, allow_nan=False))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
