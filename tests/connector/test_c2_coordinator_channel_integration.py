"""WIP native integration entry point for selected C2 coordinator channels.

The genuine selected-root/gateway fixture is still being composed. Keep this
entry point explicit and skipped until the fixture proves the complete
three-worker TLS/HELLO route and confirmed cleanup on the pinned Linux image.
"""
from __future__ import annotations

import os
import unittest
from pathlib import Path

_ARTIFACTS = Path(os.environ.get("STEAMBOAT_C2_STARTUP_ARTIFACTS", "/artifacts"))
_NATIVE = os.name == "posix" and hasattr(os, "geteuid") and _ARTIFACTS.is_dir()


@unittest.skip("WIP: composed selected coordinator + three-worker service fixture is not complete")
class C2CoordinatorChannelIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_selected_channel_mints_three_targets_and_releases_confirmed_owners(self):
        if not _NATIVE:
            self.skipTest("requires the approved Linux offline artifact fixture")
        from tests.connector.c2_coordinator_channel_fixture import C2CoordinatorChannelFixture

        fixture = C2CoordinatorChannelFixture(_ARTIFACTS)
        try:
            await fixture.build_channel()
            self.assertEqual(len(fixture.channel.targets), 3)
        finally:
            await fixture.async_close()
        self.assertTrue(fixture._reclaimed)
        self.assertEqual(fixture.runtime_case.child_owner._state, "closed")


if __name__ == "__main__":
    unittest.main()
