"""One real selected C2 host process, gateway HELLO and bounded Stop."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sys
import unittest

from tests.connector.c2_host_service_fixture import C2HostProcessFixture


_ARTIFACTS = Path(os.environ.get("STEAMBOAT_C2_STARTUP_ARTIFACTS", "/artifacts"))
_NATIVE = (os.name == "posix" and sys.platform.startswith("linux")
           and sys.version_info[:2] == (3, 12) and _ARTIFACTS.is_dir())


@unittest.skipUnless(_NATIVE,
    "requires pinned Linux CPython 3.12 and approved offline C2 model artifacts")
class C2HostProcessIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_selected_host_process_reaches_tls_hello_ready_and_stops(self):
        fixture = C2HostProcessFixture(_ARTIFACTS)
        self.addCleanup(fixture.close)
        owner_policy = fixture.configure_backend()
        stop_pump = asyncio.Event()

        async def pump_gateway():
            while not stop_pump.is_set():
                fixture.gateway.pump_once()
                await asyncio.sleep(0.001)

        pump = asyncio.create_task(pump_gateway())
        try:
            handle = await asyncio.to_thread(
                fixture.backend.spawn_owned_start, "host", owner_policy,
                expected_artifact_pin=fixture.pin)
            self.assertIsNotNone(handle, "the real supervisor must publish a process owner")
            process = handle._owned.process
            process_group = handle._owned.group
            self.assertIsNotNone(process)
            self.assertTrue(Path("/proc", str(process.pid)).exists())

            ready = await asyncio.to_thread(
                fixture.backend.observe_owned_ready, handle, timeout_seconds=30.0)
            self.assertTrue(ready, "parent READY follows actual child health and gateway HELLO")
            component = fixture.scope["components"][0]
            expected = (fixture.selected_spec.device_id,
                        component["worker_boot_id"])
            self.assertEqual(tuple(fixture.gateway._workers), (expected,))
            self.assertIsNone(fixture.gateway.failure)
            # The coordinator endpoint is purpose-separated but no
            # coordinator process is part of this one-role test.
            self.assertFalse(fixture.gateway.route_connected)

            stop_pump.set()
            pump.cancel()
            try:
                await pump
            except asyncio.CancelledError:
                pass
            fixture.gateway.stop()
            self.assertTrue(fixture.gateway_reclamation_confirmed(),
                "gateway sockets, TLS credentials and retained owners must be confirmed closed before pin release")
            stopped = await asyncio.to_thread(
                fixture.backend.stop, ("host",), 15.0)
            self.assertIs(stopped.get("host"), True)
            self.assertNotIn("host", fixture.backend._owned)
            self.assertFalse(process_group.exists(),
                "supervisor must reap the child before removing its lifecycle group")
            self.assertEqual(fixture.pin._state, "closed",
                "the artifact pin is released only after actual process reclamation")
        finally:
            stop_pump.set()
            if not pump.done():
                pump.cancel()
            try:
                await pump
            except asyncio.CancelledError:
                pass
            # Idempotent proof/cleanup on failure paths; successful paths stop
            # the gateway before backend pin release above.
            fixture.gateway.stop()


if __name__ == "__main__":
    unittest.main()
