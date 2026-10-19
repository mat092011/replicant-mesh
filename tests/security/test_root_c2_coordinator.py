"""Focused portable contract checks for the C2 coordinator profile."""
import unittest
from unittest.mock import patch

from steamboat_security.codec import canonical_json
from steamboat_security.errors import CredentialError
from steamboat_security.root_c2_coordinator import (
    C2CoordinatorRuntimeBinding, _FIELDS, _read_header,
)


class C2CoordinatorHeaderTests(unittest.TestCase):
    def _header(self):
        return {
            "schema_version": 1,
            "profile": "native_posix_root_c2_personal_coordinator_v1",
            "protected_root": "/protected", "selected_root": "/selected",
            "account_id": "acct_" + "1" * 32,
            "device_id": "dev_" + "2" * 32,
            "role": "personal_coordinator", "boot_id": "boot_" + "3" * 32,
            "credential_epoch": 1, "admission_epoch": 1,
            "generation_sha256": "4" * 64, "launch_nonce": "5" * 32,
            "certificate_path": "/protected/role.pem",
            "private_key_path": "/protected/role.key",
            "model_id": "7" * 64,
            "runtime_configuration_path": "/protected/runtime.bin",
            "runtime_configuration_sha256": "6" * 64,
        }

    def test_accepts_only_closed_coordinator_profile(self):
        header = self._header()
        encoded = canonical_json(header)
        with patch("steamboat_security.root_c2_coordinator.safe_read", return_value=encoded):
            raw, parsed = _read_header("/protected/header.json", "/protected", 1)
        self.assertEqual(raw, encoded)
        self.assertEqual(set(parsed), _FIELDS)

    def test_rejects_host_header_and_extra_command_fields(self):
        for change in (
            {"profile": "native_posix_root_c2_host_group_v1"},
            {"role": "host"}, {"peer_command": ["sh", "-c", "true"]},
        ):
            header = self._header() | change
            with patch("steamboat_security.root_c2_coordinator.safe_read",
                       return_value=canonical_json(header)):
                with self.assertRaises(CredentialError):
                    _read_header("/protected/header.json", "/protected", 1)

    def test_invalidation_notifies_once_and_outside_lock(self):
        binding = object.__new__(C2CoordinatorRuntimeBinding)
        import threading
        binding._lock = threading.RLock()
        binding._invalid = False
        binding._reason = None
        binding._subscribers = []
        binding._notification_faulted = False
        binding._notify = C2CoordinatorRuntimeBinding._notify.__get__(binding)
        calls = []
        binding._subscribers.append(lambda reason: calls.append(reason))
        binding.invalidate("test")
        binding.invalidate("again")
        self.assertEqual(calls, ["test"])
        self.assertTrue(binding._invalid)

    def test_awaitable_teardown_is_rejected(self):
        binding = object.__new__(C2CoordinatorRuntimeBinding)
        import threading
        binding._lock = threading.RLock()
        binding._invalid = False
        binding._subscribers = []
        async def callback(_reason):
            return None
        with self.assertRaisesRegex(TypeError, "synchronous"):
            binding.subscribe_teardown(callback)


if __name__ == "__main__":
    unittest.main()
