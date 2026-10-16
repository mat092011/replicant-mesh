"""M3 Linux process faults with real gRPC and independently enforced deadlines.

Opt in with STEAMBOAT_PROCESS_TESTS=1 and STEAMBOAT_ARTIFACT_DIR. The blocked
compute test exercises the actual frozen 15-second grace, not an accelerated
clock. Synthetic executors are injected only by a local test helper process.
"""

import asyncio
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ProcessHarness:
    def __init__(self, artifacts, *, real=False, block=False, delay_ms=0):
        self.port = unused_port()
        self.target = f"127.0.0.1:{self.port}"
        if real:
            command = [sys.executable, "-u", "-m", "steamboat_runtime.worker", "serve",
                       "--worker", "worker-1"]
        else:
            command = [sys.executable, "-u", str(Path(__file__).with_name("process_fixture.py")),
                       "supervise"]
            if block:
                command.append("--block")
            command += ["--delay-ms", str(delay_ms)]
        command += ["--artifacts", artifacts, "--host", self.target]
        self.stderr = tempfile.TemporaryFile()
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=self.stderr)
        self.events = []
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.process.stdout:
            self.events.append(json.loads(line))

    async def wait_ready(self, previous=None, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for event in list(self.events):
                if event["event"] == "worker_ready" and event["boot_id"] != previous:
                    return event
            if self.process.poll() is not None:
                self.stderr.seek(0)
                raise AssertionError(f"Worker supervisor exited: {self.stderr.read().decode()}")
            await asyncio.sleep(0.025)
        raise AssertionError(f"Worker readiness exceeded {timeout}s: {self.events}")

    async def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(asyncio.to_thread(self.process.wait), 18)
            except TimeoutError:
                self.process.kill()
                await asyncio.to_thread(self.process.wait)
                raise AssertionError("Supervisor failed bounded shutdown")
        self.reader.join(timeout=1)
        self.process.stdout.close()
        self.stderr.close()


@unittest.skipUnless(os.environ.get("STEAMBOAT_PROCESS_TESTS") == "1" and sys.platform == "linux",
                     "Set STEAMBOAT_PROCESS_TESTS=1 in the Linux runtime image")
class WorkerProcessTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        import torch
        from steamboat_runtime.manifest import load_manifest
        from steamboat_runtime.protocol.codec import encode_tensor
        from steamboat_runtime.protocol.transport import GrpcClient
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_runtime.worker import validate_ready
        cls.artifacts = os.environ["STEAMBOAT_ARTIFACT_DIR"]
        cls.manifest = load_manifest(cls.artifacts)
        cls.torch, cls.Client, cls.Request = torch, GrpcClient, Request
        cls.encode = staticmethod(encode_tensor)
        cls.validate = staticmethod(validate_ready)

    async def asyncSetUp(self):
        self.workers, self.clients, self.pending = [], [], []

    async def asyncTearDown(self):
        for pending in self.pending:
            pending.cancel()
        if self.pending:
            await asyncio.gather(*self.pending, return_exceptions=True)
        for client in self.clients:
            await client.close()
        for worker in self.workers:
            await worker.stop()

    async def start(self, **options):
        worker = ProcessHarness(self.artifacts, **options)
        self.workers.append(worker)
        ready = await worker.wait_ready()
        client = self.Client(worker.target)
        self.clients.append(client)
        self.worker, self.client, self.boot = worker, client, ready["boot_id"]
        return ready

    def request(self, **changes):
        values = dict(protocol_version=1, manifest_fingerprint=self.manifest["fingerprint"],
                      worker_boot_id=self.boot, timeout_ms=1000)
        values.update(changes)
        return self.Request(**values)

    async def open(self, name="process-A", idle=120000):
        response = await self.client.execute("OpenSession", self.request(session_id=name,
            max_positions=32, lifetime_ms=300000, idle_lease_ms=idle))
        self.assertEqual(response.code, "OK", response.message)
        return response

    def step(self, opened, timeout=30000):
        tensor = self.encode(self.torch.zeros(1, 1, 64))
        return self.request(session_id=opened.session_id, lease_token=opened.lease_token,
                            token_count=1, tensor=tensor, timeout_ms=timeout)

    async def wait_active(self):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            response = await self.client.execute("Describe", self.request())
            if response.active_operations == 1:
                return response
            await asyncio.sleep(0.02)
        self.fail("Compute never became active")

    async def test_real_partition_readiness_and_wrong_assignment_rejection(self):
        ready = await self.start(real=True)
        response = await self.client.execute("Describe", self.request())
        self.validate(response, self.manifest, "worker-1")
        with self.assertRaisesRegex(RuntimeError, "layer_start"):
            self.validate(response, self.manifest, "worker-2")
        import math
        expected = sum(math.prod(tensor["shape"]) for name, tensor in
                       self.manifest["components"]["worker-1"]["tensors"].items()
                       if not name.endswith("rotary_emb.inv_freq"))
        self.assertEqual(ready["parameter_count"], expected)
        self.assertEqual(ready["parameter_bytes"], expected * 4)
        self.assertGreater(ready["rss_bytes"], ready["parameter_bytes"])
        self.assertGreater(ready["startup_peak_rss_bytes"], 0)
        self.assertEqual((ready["layer_start"], ready["layer_end"]), (0, 3))

    async def test_connection_refusal_is_a_bounded_explicit_error(self):
        client = self.Client(f"127.0.0.1:{unused_port()}")
        self.clients.append(client)
        started = time.monotonic()
        response = await client.execute("Describe", self.Request(protocol_version=1, timeout_ms=500))
        self.assertEqual(response.code, "EXECUTION_FAILED")
        self.assertLess(time.monotonic() - started, 2)

    async def test_coordinator_loss_recovers_abandoned_cache_without_renewal(self):
        await self.start()
        opened = await self.open(idle=200)
        result = await self.client.execute("Step", self.step(opened))
        self.assertEqual(result.code, "OK")
        await self.client.close()
        await asyncio.sleep(self.manifest["limits"]["lease_check_interval_seconds"] + 0.5)
        client = self.Client(self.worker.target)
        self.clients.append(client)
        response = await client.execute("Describe", self.request())
        self.assertEqual((response.active_sessions, response.reserved_positions,
                          response.allocated_cache_bytes), (0, 0, 0))
        stale = await client.execute("Step", self.step(opened))
        self.assertEqual(stale.code, "EXPIRED_SESSION")

    async def test_worker_restart_changes_boot_and_refuses_previous_lease(self):
        ready = await self.start()
        opened = await self.open()
        old = self.step(opened)
        os.kill(ready["pid"], signal.SIGTERM)
        replacement = await self.worker.wait_ready(previous=self.boot)
        self.assertNotEqual(replacement["pid"], ready["pid"])
        # A fresh channel avoids waiting through gRPC's reconnect backoff.
        client = self.Client(self.worker.target)
        self.clients.append(client)
        stale = await client.execute("Step", old)
        self.assertEqual(stale.code, "STALE_WORKER")
        self.boot = replacement["boot_id"]
        status = await client.execute("Describe", self.request())
        self.assertEqual(status.active_sessions, 0)

    async def test_renewal_while_queued_keeps_the_session_alive(self):
        await self.start(delay_ms=1000)
        first = await self.open("queue-A")
        first_step = asyncio.create_task(self.client.execute("Step", self.step(first)))
        self.pending.append(first_step)
        await self.wait_active()
        second = await self.open("queue-B", idle=400)
        second_step = asyncio.create_task(self.client.execute("Step", self.step(second)))
        self.pending.append(second_step)
        saw_queued = False
        deadline = time.monotonic() + 5
        while not second_step.done() and time.monotonic() < deadline:
            await asyncio.sleep(0.1)
            renewed = await self.client.execute("RenewSession", self.request(
                session_id=second.session_id, lease_token=second.lease_token))
            self.assertEqual(renewed.code, "OK")
            saw_queued = saw_queued or renewed.state == "QUEUED"
        self.assertTrue(saw_queued, "The second request never waited in the worker queue")
        result = await asyncio.wait_for(second_step, 1)
        self.assertEqual(result.code, "OK")
        self.assertGreater(result.queue_ms, 500)
        self.assertEqual((await first_step).code, "OK")

    async def test_disconnect_during_compute_returns_error_and_new_boot(self):
        ready = await self.start(block=True)
        opened = await self.open()
        pending = asyncio.create_task(self.client.execute("Step", self.step(opened)))
        self.pending.append(pending)
        await self.wait_active()
        os.kill(ready["pid"], signal.SIGKILL)
        response = await asyncio.wait_for(pending, 2)
        self.assertEqual(response.code, "EXECUTION_FAILED")
        replacement = await self.worker.wait_ready(previous=self.boot)
        self.assertNotEqual(replacement["boot_id"], self.boot)

    async def test_actual_fifteen_second_cancel_grace_kills_wedged_compute(self):
        ready = await self.start(block=True)
        opened = await self.open()
        pending = asyncio.create_task(self.client.execute("Step", self.step(opened)))
        self.pending.append(pending)
        await self.wait_active()
        cancelled_at = time.monotonic()
        cancelled = await self.client.execute("CancelSession", self.request(
            session_id=opened.session_id, lease_token=opened.lease_token))
        self.assertEqual(cancelled.code, "OK")
        self.assertFalse(cancelled.reclaimed)
        replacement = await self.worker.wait_ready(previous=self.boot, timeout=25)
        duration = time.monotonic() - cancelled_at
        self.assertGreaterEqual(duration, 14.8)
        self.assertLess(duration, 25)
        reasons = [event.get("reason") for event in self.worker.events
                   if event["event"] == "worker_terminate"]
        self.assertIn("compute_cancel_grace_exceeded", reasons)
        self.assertNotEqual(replacement["pid"], ready["pid"])
        result = await asyncio.wait_for(pending, 2)
        self.assertIn(result.code, ("EXECUTION_FAILED", "CANCELLED"))
        with self.assertRaises(ProcessLookupError):
            os.kill(ready["pid"], 0)

    async def test_stopped_child_cannot_block_parent_heartbeat_watchdog(self):
        ready = await self.start()
        started = time.monotonic()
        os.kill(ready["pid"], signal.SIGSTOP)
        replacement = await self.worker.wait_ready(previous=self.boot, timeout=15)
        self.assertLess(time.monotonic() - started, 15)
        self.assertNotEqual(replacement["pid"], ready["pid"])
        self.assertTrue(any(event.get("reason") == "heartbeat_timeout"
                            for event in self.worker.events))
        with self.assertRaises(ProcessLookupError):
            os.kill(ready["pid"], 0)

    async def test_sigterm_stops_supervisor_and_reaps_child(self):
        ready = await self.start()
        await self.open()
        self.worker.process.terminate()
        code = await asyncio.wait_for(asyncio.to_thread(self.worker.process.wait), 5)
        self.assertEqual(code, 0)
        with self.assertRaises(ProcessLookupError):
            os.kill(ready["pid"], 0)


class SupervisorUnitTests(unittest.TestCase):
    def test_reader_exits_when_its_bounded_queue_is_full(self):
        import io
        import queue
        from steamboat_runtime.supervisor import ProcessSupervisor
        frames = queue.Queue(maxsize=1)
        stopped = threading.Event()
        stream = io.BytesIO(b'{"event":"heartbeat"}\n' * 100)
        reader = threading.Thread(target=ProcessSupervisor._read_frames,
                                  args=(stream, frames, stopped))
        reader.start()
        deadline = time.monotonic() + 1
        while frames.empty() and time.monotonic() < deadline:
            time.sleep(0.01)
        stopped.set()
        reader.join(timeout=0.5)
        self.assertFalse(reader.is_alive())
        self.assertTrue(stream.closed)

    def test_supervisor_import_does_not_load_torch(self):
        completed = subprocess.run([sys.executable, "-c",
            "import sys; import steamboat_runtime.supervisor; assert 'torch' not in sys.modules"],
            capture_output=True, text=True, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_restart_budget_bounds_permanent_startup_failure(self):
        from steamboat_runtime.supervisor import ProcessSupervisor
        events = []
        supervisor = ProcessSupervisor([sys.executable, "-c", "raise SystemExit(9)"],
            restart_limit=2, log=lambda event, **fields: events.append((event, fields)))
        self.assertEqual(supervisor.run(), 70)
        self.assertEqual(sum(event == "worker_start" for event, _ in events), 3)
        self.assertEqual(events[-1][0], "restart_budget_exhausted")

    def test_compute_deadline_is_enforced_while_child_keeps_heartbeating(self):
        from steamboat_runtime.supervisor import ProcessSupervisor
        code = """
import json, time
status = dict(ready=True, active_compute=True, compute_id='blocked',
              compute_deadline=time.monotonic() + 0.1, terminate_deadline=None)
print(json.dumps(dict(event='ready', status=status)), flush=True)
while True:
    print(json.dumps(dict(event='heartbeat', status=status)), flush=True)
    time.sleep(0.02)
"""
        events = []
        supervisor = ProcessSupervisor([sys.executable, "-u", "-c", code],
            shutdown_grace=0.15, restart_limit=0,
            log=lambda event, **fields: events.append((event, fields)))
        started = time.monotonic()
        self.assertEqual(supervisor.run(), 70)
        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(any(fields.get("reason") == "compute_deadline_grace_exceeded"
                            for _, fields in events))

    def test_shutdown_observes_cancellation_deadline_during_wedged_child(self):
        from steamboat_runtime.supervisor import ProcessSupervisor
        code = """
import json, signal, time
status = dict(ready=True, active_compute=True, compute_id='wedged',
              compute_deadline=time.monotonic() + 30, terminate_deadline=None)
stopping = False
def terminate(*_):
    global stopping
    stopping = True
    status['terminate_deadline'] = time.monotonic() + 0.25
signal.signal(signal.SIGTERM, terminate)
print(json.dumps(dict(event='ready', status=status)), flush=True)
while True:
    print(json.dumps(dict(event='heartbeat', status=status)), flush=True)
    time.sleep(0.02)
"""
        events = []
        stop = threading.Event()
        supervisor = ProcessSupervisor([sys.executable, "-u", "-c", code],
            shutdown_grace=0.25, child_shutdown_grace=5, restart_limit=0,
            log=lambda event, **fields: events.append((event, fields)))
        runner = threading.Thread(target=supervisor.run, args=(stop,))
        runner.start()
        deadline = time.monotonic() + 2
        while supervisor.child is None and time.monotonic() < deadline:
            time.sleep(0.01)
        while not any(event == "worker_ready" for event, _ in events) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(any(event == "worker_ready" for event, _ in events))
        stopped_at = time.monotonic()
        stop.set()
        runner.join(timeout=2)
        self.assertFalse(runner.is_alive(), "supervisor exceeded the compute cancellation bound")
        self.assertLess(time.monotonic() - stopped_at, 1.5)
        self.assertIsNotNone(supervisor.child.poll())

    def test_startup_heartbeats_do_not_extend_the_readiness_deadline(self):
        from steamboat_runtime.supervisor import ProcessSupervisor
        code = """
import json, time
while True:
    print(json.dumps(dict(event='heartbeat', status=dict(ready=False))), flush=True)
    time.sleep(0.02)
"""
        events = []
        supervisor = ProcessSupervisor([sys.executable, "-u", "-c", code],
            startup_timeout=0.2, restart_limit=0,
            log=lambda event, **fields: events.append((event, fields)))
        self.assertEqual(supervisor.run(), 70)
        self.assertTrue(any(fields.get("reason") == "startup_timeout" for _, fields in events))


if __name__ == "__main__":
    unittest.main()
