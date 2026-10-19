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
    C2CoordinatorChannel, C2CoordinatorChannelError,
    _check_runtime_guard, _open_selected_socket, _read_pin,
    _retain_egress_constructor_failure, _stream_reservation,
    build_c2_coordinator_channel,
)
from steamboat_security.errors import CredentialError
from steamboat_security.gateway_egress import GatewayEgressError


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

    def test_runtime_guard_requires_exact_none_success(self):
        with self.assertRaises(C2CoordinatorChannelError):
            _check_runtime_guard(SimpleNamespace(_runtime_guard=lambda: True))


class C2CoordinatorChannelLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def _partial_owner(self, *, startup_done=True, lease=None):
        owner = C2CoordinatorChannel.__new__(C2CoordinatorChannel)
        owner._loop = asyncio.get_running_loop()
        owner._state = "starting"
        owner._invalidated = __import__("threading").Event()
        owner._close_lock = asyncio.Lock()
        owner._cleanup_task = None
        owner._lease_exit_task = None
        owner._lease = lease
        owner._startup_done = asyncio.Event()
        if startup_done:
            owner._startup_done.set()
        owner._startup_tasks = []
        owner._startup_cleanup_error = None
        owner._startup_cleanup_metadata = None
        owner._startup_cleanup_owner = None
        owner._attempts = []
        owner.client = owner.stream = owner.driver = owner.egress = None
        owner.socket = None
        owner.targets = ()
        return owner

    async def test_invalidation_after_late_dns_result_opens_no_socket(self):
        release_dns = asyncio.Event()
        invalidated = False
        loop = asyncio.get_running_loop()

        class DelayedLoop:
            @staticmethod
            def time():
                return loop.time()

            async def getaddrinfo(self, *_args, **_kwargs):
                await release_dns.wait()
                return [(2, 1, 6, "", ("127.0.0.1", 12345))]

            async def sock_connect(self, *_args):
                raise AssertionError("runtime guard must fence before TCP connect")

        owner = self._partial_owner()
        owner._loop = DelayedLoop()

        def runtime_guard():
            if invalidated:
                raise C2CoordinatorChannelError("late DNS result after invalidation")
            return None

        owner._runtime_guard = runtime_guard
        with mock.patch("steamboat_connector.c2_coordinator_channel.socket.socket") as make_socket:
            task = asyncio.create_task(_open_selected_socket(
                owner, owner._loop, "gateway.example", 443, loop.time() + 1))
            await asyncio.sleep(0)
            invalidated = True
            release_dns.set()
            with self.assertRaises(C2CoordinatorChannelError):
                await task
            make_socket.assert_not_called()
        self.assertEqual(len(owner._startup_tasks), 1)
        self.assertEqual(owner._attempts, [])

    async def test_guard_consuming_startup_budget_prevents_dns_task_creation(self):
        loop = asyncio.get_running_loop()

        class DelayedLoop:
            now = loop.time()

            def time(self):
                return self.now

        fake_loop = DelayedLoop()
        owner = self._partial_owner()
        owner._loop = fake_loop

        def slow_guard():
            fake_loop.now += 2
            return None

        owner._runtime_guard = slow_guard
        with mock.patch("steamboat_connector.c2_coordinator_channel.socket.socket") as make_socket:
            with self.assertRaisesRegex(C2CoordinatorChannelError, "deadline"):
                await _open_selected_socket(
                    owner, fake_loop, "gateway.example", 443, fake_loop.time() + 1)
            make_socket.assert_not_called()
        self.assertEqual(owner._startup_tasks, [])

    async def test_policy_refresh_precedes_final_binding_authority_check(self):
        owner = self._partial_owner()
        order = []
        changed = False

        class PolicyOwner:
            def current(self):
                nonlocal changed
                order.append("policy")
                changed = True
                return object()

        class Binding:
            def assert_live(self):
                order.append("binding")
                if changed:
                    raise C2CoordinatorChannelError("binding expired during policy refresh")
                return None

        owner._policy_owner = PolicyOwner()
        owner._binding = Binding()
        with self.assertRaisesRegex(C2CoordinatorChannelError, "expired"):
            owner._guard_runtime()
        self.assertEqual(order, ["policy", "binding"])

    async def test_pending_connect_retains_one_socket_and_blocks_cleanup(self):
        release_connect = asyncio.Event()
        loop = asyncio.get_running_loop()

        class DelayedLoop:
            @staticmethod
            def time():
                return loop.time()

            async def getaddrinfo(self, *_args, **_kwargs):
                return [(2, 1, 6, "", ("127.0.0.1", 12345))]

            async def sock_connect(self, *_args):
                await release_connect.wait()

        class RetainedSocket:
            close_calls = 0

            def setblocking(self, _value):
                return None

            def close(self):
                self.close_calls += 1

        owner = self._partial_owner()
        owner._loop = DelayedLoop()
        owner._runtime_guard = lambda: None
        sock = RetainedSocket()
        with mock.patch("steamboat_connector.c2_coordinator_channel.socket.socket",
                        return_value=sock):
            with self.assertRaises(C2CoordinatorChannelError):
                await _open_selected_socket(
                    owner, owner._loop, "gateway.example", 443, loop.time() + 0.01)
        self.assertEqual(len(owner._attempts), 1)
        self.assertIs(owner._attempts[0]["socket"], sock)
        self.assertEqual(len(owner._startup_tasks), 2)
        with self.assertRaises(C2CoordinatorChannelError):
            await owner._cleanup_owned()
        self.assertEqual(sock.close_calls, 0)
        release_connect.set()
        await owner._startup_tasks[-1]

    async def test_unknown_socket_close_is_one_attempt_and_never_releases_lease(self):
        class AmbiguousSocket:
            calls = 0

            def close(self):
                self.calls += 1
                raise OSError("ambiguous close")

        class Lease:
            exits = 0

            def __exit__(self, *_args):
                self.exits += 1

        sock, lease = AmbiguousSocket(), Lease()
        owner = self._partial_owner(lease=lease)
        owner._attempts.append({"socket": sock, "close_status": "open", "driver": None})
        for _ in range(2):
            with self.assertRaises(C2CoordinatorChannelError):
                await owner.close(grace_seconds=0.2)
        self.assertIs(owner._attempts[0]["socket"], sock)
        self.assertEqual(owner._attempts[0]["close_status"], "uncertain")
        self.assertEqual(sock.calls, 1)
        self.assertEqual(lease.exits, 0)
        self.assertIs(owner._lease, lease)
        self.assertIsNotNone(owner._cleanup_task)

    async def test_bounded_close_retains_one_cleanup_task_and_retires_lease_once(self):
        class Lease:
            exits = 0

            def __exit__(self, *_args):
                self.exits += 1

        lease = Lease()
        owner = self._partial_owner(startup_done=False, lease=lease)
        with self.assertRaises(C2CoordinatorChannelError):
            await owner.close(grace_seconds=0.01)
        cleanup = owner._cleanup_task
        self.assertIsNotNone(cleanup)
        self.assertFalse(cleanup.done())
        self.assertEqual(owner._state, "closing")
        owner._startup_done.set()
        self.assertTrue(await owner.close(grace_seconds=0.2))
        self.assertIs(owner._cleanup_task, cleanup)
        self.assertEqual(lease.exits, 1)
        self.assertEqual(owner._state, "closed")

    async def test_uncertain_egress_constructor_error_stays_sticky_and_keeps_lease(self):
        class Lease:
            exits = 0

            def __exit__(self, *_args):
                self.exits += 1

        lease = Lease()
        owner = self._partial_owner(lease=lease)
        error = GatewayEgressError(
            "TLS credential removal is uncertain", cleanup_status="uncertain",
            credential_directory="/protected/private-tls")
        retained = object()
        error.retained_owner = retained
        _retain_egress_constructor_failure(owner, error)
        self.assertIs(owner._startup_cleanup_error, error)
        owner._state = "faulted"
        with self.assertRaises(C2CoordinatorChannelError) as raised:
            await owner.close(grace_seconds=0.2)
        self.assertIs(raised.exception.__cause__, error)
        self.assertEqual(lease.exits, 0)
        self.assertIs(owner._lease, lease)
        self.assertEqual(owner._startup_cleanup_metadata["cleanup_status"], "uncertain")
        self.assertEqual(owner._startup_cleanup_metadata["credential_directory"],
                         "/protected/private-tls")
        self.assertIs(owner._startup_cleanup_owner, retained)


if __name__ == "__main__":
    unittest.main()
