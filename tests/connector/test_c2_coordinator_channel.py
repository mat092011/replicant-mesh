"""Portable contract checks for the outbound coordinator channel owner."""
from __future__ import annotations

import asyncio
from pathlib import Path
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_connector.c2_coordinator_channel import (
    _read_pin, _stream_reservation,
    build_c2_coordinator_channel,
)
from steamboat_security.errors import CredentialError


class C2CoordinatorChannelContractTests(unittest.TestCase):
    def test_import_does_not_load_torch(self):
        code = ("import sys; sys.path.insert(0, " + repr(str(ROOT / "src")) + "); "
                "import steamboat_connector.c2_coordinator_channel; "
                "assert 'torch' not in sys.modules")
        subprocess.run([sys.executable, "-I", "-c", code], check=True,
                       capture_output=True, text=True, timeout=10)

    def test_stream_reservation_is_positive_and_includes_three_wire_bounds(self):
        self.assertGreaterEqual(_stream_reservation(), 4 * 1024 * 1024)

    def test_builder_rejects_nonowners_before_settings_or_network(self):
        with self.assertRaises(TypeError):
            asyncio.run(build_c2_coordinator_channel(
                object(), owner_policy=object(), policy_owner=object(), traffic=object()))

    def test_pinned_material_rejects_changed_bytes_before_network(self):
        pin = SimpleNamespace(path="/protected/ca.pem", sha256="0" * 64)
        with mock.patch("steamboat_connector.c2_coordinator_channel.safe_read",
                        return_value=b"different protected bytes"):
            with self.assertRaises(CredentialError):
                _read_pin(pin, root="/protected", uid=1, maximum=1024,
                          label="gateway CA")


if __name__ == "__main__":
    unittest.main()
