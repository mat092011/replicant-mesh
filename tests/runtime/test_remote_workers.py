"""M3 client preflight and partial-admission cleanup without model allocations."""

import importlib
import os
import unittest
import uuid


@unittest.skipUnless(os.environ.get("REPLICANT_MESH_PROTOCOL_TESTS") == "1",
                     "Set REPLICANT_MESH_PROTOCOL_TESTS=1 for remote worker contracts")
class RemoteWorkerContractTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from replicant_mesh.protocol.worker_pb2 import Response
        from replicant_mesh.protocol.errors import ProtocolError
        from replicant_mesh.remote_check import RemoteWorkers
        fixture = importlib.import_module(f"{__package__}.test_manifest" if __package__ else "test_manifest")
        cls.sample_manifest = staticmethod(fixture.sample_manifest)
        cls.Response, cls.ProtocolError, cls.RemoteWorkers = Response, ProtocolError, RemoteWorkers

    async def asyncSetUp(self):
        self.manifest = self.sample_manifest()
        self.calls = []
        case = self

        class FakeClient:
            def __init__(self, index):
                self.index = index
                self.boot_id = uuid.uuid4().hex
                self.describe_changes = {}
                self.failures = {}
                self.closed = False

            async def execute(self, method, request):
                case.calls.append((self.index, method, request.timeout_ms))
                values = {
                    "protocol_version": 1, "manifest_fingerprint": case.manifest["fingerprint"],
                    "worker_boot_id": self.boot_id, "code": self.failures.get(method, "OK"),
                    "ready": True, "layer_start": ((0, 3), (3, 6), (6, 8))[self.index][0],
                    "layer_end": ((0, 3), (3, 6), (6, 8))[self.index][1], "hidden_size": 64,
                    "max_sessions": 8, "max_positions_limit": 1152,
                    "max_message_bytes": 1048576, "max_cache_positions": 12288,
                    "max_cache_bytes": 16777216, "rpc_timeout_ms": 30000,
                    "lease_check_interval_ms": 5000, "max_stage_queue": 8,
                    "cache_bytes_exact": True,
                }
                if method == "Describe":
                    values.update(self.describe_changes)
                else:
                    values.update(session_id=request.session_id,
                                  lease_token=request.lease_token or uuid.uuid4().hex,
                                  max_positions=request.max_positions,
                                  reclaimed=method == "CloseSession")
                return case.Response(**values)

            async def close(self):
                self.closed = True

        self.clients = [FakeClient(i) for i in range(3)]
        self.owner = self.RemoteWorkers(self.manifest, self.clients)

    async def asyncTearDown(self):
        await self.owner.close()

    async def test_all_workers_are_verified_before_first_open(self):
        session = await self.owner.open_session(16)
        self.assertEqual([(i, method) for i, method, _ in self.calls],
                         [(0, "Describe"), (1, "Describe"), (2, "Describe"),
                          (0, "OpenSession"), (1, "OpenSession"), (2, "OpenSession")])
        await session.close()
        self.assertEqual(len([method for _, method, _ in self.calls if method == "CloseSession"]), 3)

    async def test_missing_third_worker_prevents_every_reservation(self):
        self.clients[2].failures["Describe"] = "EXECUTION_FAILED"
        with self.assertRaises(self.ProtocolError) as caught:
            await self.owner.open_session(16)
        self.assertEqual(caught.exception.code, "EXECUTION_FAILED")
        self.assertFalse(any(method == "OpenSession" for _, method, _ in self.calls))
        self.assertEqual(self.owner.boot_ids, [])

    async def test_wrong_assignment_prevents_every_reservation(self):
        self.clients[2].describe_changes["layer_start"] = 3
        with self.assertRaises(self.ProtocolError) as caught:
            await self.owner.open_session(16)
        self.assertEqual(caught.exception.code, "INCOMPATIBLE_MODEL")
        self.assertFalse(any(method == "OpenSession" for _, method, _ in self.calls))

    async def test_mismatched_manifest_prevents_every_reservation(self):
        self.clients[1].describe_changes["manifest_fingerprint"] = "0" * 64
        with self.assertRaises(self.ProtocolError) as caught:
            await self.owner.open_session(16)
        self.assertEqual(caught.exception.code, "INCOMPATIBLE_MODEL")
        self.assertFalse(any(method == "OpenSession" for _, method, _ in self.calls))

    async def test_unready_worker_prevents_every_reservation(self):
        self.clients[2].describe_changes["ready"] = False
        with self.assertRaises(self.ProtocolError):
            await self.owner.open_session(16)
        self.assertFalse(any(method == "OpenSession" for _, method, _ in self.calls))

    async def test_partial_admission_releases_every_known_lease(self):
        self.clients[2].failures["OpenSession"] = "CAPACITY_EXHAUSTED"
        with self.assertRaises(self.ProtocolError) as caught:
            await self.owner.open_session(16)
        self.assertEqual(caught.exception.code, "CAPACITY_EXHAUSTED")
        self.assertEqual([i for i, method, _ in self.calls if method == "CloseSession"], [0, 1])
        self.assertEqual(len(self.owner.sessions), 0)

    async def test_ambiguous_open_is_not_retried(self):
        self.clients[1].failures["OpenSession"] = "TIMEOUT"
        with self.assertRaises(self.ProtocolError) as caught:
            await self.owner.open_session(16)
        self.assertEqual(caught.exception.code, "TIMEOUT")
        self.assertEqual([i for i, method, _ in self.calls if method == "OpenSession"], [0, 1])
        self.assertEqual([i for i, method, _ in self.calls if method == "CloseSession"], [0])

    async def test_changed_boot_identity_refuses_new_admission(self):
        first = await self.owner.open_session(16)
        await first.close()
        self.calls.clear()
        self.clients[1].boot_id = uuid.uuid4().hex
        with self.assertRaises(self.ProtocolError) as caught:
            await self.owner.open_session(16)
        self.assertEqual(caught.exception.code, "STALE_WORKER")
        self.assertFalse(any(method == "OpenSession" for _, method, _ in self.calls))

    async def test_failed_close_does_not_prevent_other_cleanup(self):
        session = await self.owner.open_session(16)
        self.clients[0].failures["CloseSession"] = "TIMEOUT"
        await session.close()
        self.assertEqual([i for i, method, _ in self.calls if method == "CloseSession"], [0, 1, 2])
        self.assertEqual(len(self.owner.evidence["cleanup_errors"]), 1)
        self.assertTrue(all(timeout <= 5000 for _, method, timeout in self.calls if method == "CloseSession"))
        previous = len(self.calls)
        await session.close()
        self.assertEqual(len(self.calls), previous)

    async def test_context_reservation_validation_precedes_any_rpc(self):
        for maximum in (0, -1, 1153, True, 1.5):
            with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                await self.owner.open_session(maximum)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
