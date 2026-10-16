"""Actual bounded TCP exchange checks; no inference dependencies required."""
import asyncio
import sys
import unittest
from lab.network_probe import ProbeServer, connect, measure, MAX_BYTES


@unittest.skipUnless(sys.version_info >= (3, 11), "M5 TCP probe uses the pinned Python 3.12 runtime")
class ProbeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.handler = ProbeServer("a" * 32)
        self.server = await asyncio.start_server(self.handler.handle, "127.0.0.1", 0, limit=1024)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        for _ in range(100):
            if not self.handler.active:
                return
            await asyncio.sleep(0.01)
        self.fail("Probe connections did not drain")

    async def test_echo_and_bidirectional_payload_are_measured(self):
        value = await measure("127.0.0.1", "a" * 32, 131072, port=self.port)
        self.assertEqual(len(value["rtt_seconds"]), 5)
        self.assertTrue(all(t > 0 for t in value["rtt_seconds"]))
        self.assertGreater(value["upload_mbit_per_second"], 0)
        self.assertGreater(value["download_mbit_per_second"], 0)

    async def test_wrong_owner_cannot_stop_probe(self):
        with self.assertRaises(ValueError):
            await connect("127.0.0.1", "b" * 32, "stop", 1, self.port)
        self.assertFalse(self.handler.stop.is_set())
        _, writer = await connect("127.0.0.1", "a" * 32, "stop", 1, self.port)
        writer.close()
        await writer.wait_closed()
        self.assertTrue(self.handler.stop.is_set())

    async def test_wire_bound_rejected_without_bulk_allocation(self):
        with self.assertRaises(ValueError):
            await connect("127.0.0.1", "a" * 32, "download", MAX_BYTES + 1, self.port)
        with self.assertRaises(ValueError):
            await measure("127.0.0.1", "a" * 32, 0, port=self.port)

    async def test_download_waits_for_measuring_peer_before_sending_payload(self):
        reader, writer = await connect("127.0.0.1", "a" * 32, "download", 131072, self.port)
        try:
            # The handshake must not put unmeasured payload in the receive buffer.
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(reader.read(1), 0.03)
            writer.write(b"g")
            await writer.drain()
            self.assertEqual(await reader.readexactly(131072), b"p" * 131072)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_four_connection_capacity_is_enforced(self):
        connections = [await asyncio.open_connection("127.0.0.1", self.port) for _ in range(4)]
        try:
            await asyncio.sleep(0.02)
            reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
            self.assertEqual(await asyncio.wait_for(reader.read(1), 1), b"")
            writer.close()
            await writer.wait_closed()
        finally:
            for _, writer in connections:
                writer.close()
                await writer.wait_closed()


if __name__ == "__main__":
    unittest.main()
