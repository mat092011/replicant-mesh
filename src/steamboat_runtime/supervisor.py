"""Independent, standard-library-only watchdog for a resident worker process.

The parent never imports Torch. A child holding the GIL, its asyncio loop, or a
compute kernel cannot prevent the parent from enforcing these process deadlines.
Only bounded, sanitized JSON status frames cross the local stdout control pipe.
"""

from collections import deque
import json
import math
import os
import queue
import signal
import subprocess
import threading
import time


def emit_event(event, **fields):
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


class ProcessSupervisor:
    def __init__(self, command, *, startup_timeout=60.0, heartbeat_timeout=2.0,
                 shutdown_grace=15.0, restart_limit=3, restart_window=60.0,
                 child_shutdown_grace=None,
                 log=emit_event):
        child_shutdown_grace = shutdown_grace if child_shutdown_grace is None else child_shutdown_grace
        for value in (startup_timeout, heartbeat_timeout, shutdown_grace, restart_window, child_shutdown_grace):
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError("Supervisor time budgets must be finite and positive")
        if type(restart_limit) is not int or restart_limit < 0:
            raise ValueError("Restart limit must be nonnegative")
        if not command or not all(isinstance(argument, str) for argument in command):
            raise ValueError("An explicit child argument list is required")
        self.command = command
        self.startup_timeout, self.heartbeat_timeout = startup_timeout, heartbeat_timeout
        self.shutdown_grace = shutdown_grace
        self.child_shutdown_grace = child_shutdown_grace
        self.restart_limit, self.restart_window = restart_limit, restart_window
        self.log = log
        self.child = None

    @staticmethod
    def _read_frames(stream, frames, stop):
        def publish(value):
            # A terminated child may leave a full queue. Never strand a reader
            # thread on put() across repeated restarts or graceful shutdown.
            while not stop.is_set():
                try:
                    frames.put(value, timeout=0.1)
                    return
                except queue.Full:
                    continue

        try:
            while not stop.is_set():
                line = stream.readline(4097)
                if not line:
                    break
                if len(line) > 4096 or not line.endswith(b"\n"):
                    publish({"event": "invalid_control"})
                    break
                try:
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValueError("Invalid frame")
                except (ValueError, UnicodeError):
                    publish({"event": "invalid_control"})
                    break
                publish(value)
        finally:
            stream.close()

    def _kill_and_reap(self, reason):
        child = self.child
        if child is None:
            return
        if child.poll() is None:
            self.log("worker_terminate", pid=child.pid, reason=reason)
            child.kill()
        child.wait(timeout=2)
        self.log("worker_exit", pid=child.pid, exit_code=child.returncode, reason=reason)

    def _shutdown(self, frames=None, compute_id=None, compute_deadline=None,
                  terminate_deadline=None):
        child = self.child
        if child is None:
            return
        if child.poll() is None:
            self.log("worker_shutdown", pid=child.pid, grace_seconds=self.child_shutdown_grace)
            child.terminate()
            # The ordinary shutdown allowance can be longer than the compute
            # cancellation allowance (the coordinator uses 40s vs 15s). Keep
            # draining control frames while the child tears down so newly
            # published deadlines can shorten the wait. A wedged event loop
            # cannot publish again, so retain its last observed compute bound.
            drain_deadline = time.monotonic() + self.child_shutdown_grace
            while child.poll() is None:
                now = time.monotonic()
                compute_limit = None
                if compute_deadline is not None:
                    compute_limit = compute_deadline + self.shutdown_grace
                if terminate_deadline is not None:
                    compute_limit = (terminate_deadline if compute_limit is None
                                     else min(compute_limit, terminate_deadline))
                limit = drain_deadline if compute_limit is None else min(drain_deadline, compute_limit)
                if now >= limit:
                    break
                try:
                    frame = frames.get(timeout=min(0.05, limit - now)) if frames is not None else None
                except queue.Empty:
                    continue
                if frame is None:
                    continue
                status = frame.get("status")
                if frame.get("event") not in ("ready", "heartbeat") or not isinstance(status, dict):
                    continue
                if status.get("active_compute"):
                    identity, deadline = status.get("compute_id"), status.get("compute_deadline")
                    termination = status.get("terminate_deadline")
                    if (not isinstance(identity, str) or not identity or len(identity) > 128
                            or not isinstance(deadline, (int, float)) or not math.isfinite(deadline)
                            or (termination is not None and (not isinstance(termination, (int, float))
                                or not math.isfinite(termination)))):
                        continue
                    if compute_id != identity:
                        compute_id, terminate_deadline = identity, None
                    compute_deadline = deadline
                    if termination is not None:
                        terminate_deadline = (termination if terminate_deadline is None
                                              else min(terminate_deadline, termination))
                else:
                    compute_id = compute_deadline = terminate_deadline = None
        self._kill_and_reap("shutdown")

    def run(self, stop=None):
        """Run until shutdown or a bounded restart budget is exhausted.

        Callers may supply an Event for tests. The CLI installs signal handlers
        that only set this event; all child management remains in this parent.
        """
        stop = stop or threading.Event()
        restarts = deque()
        reader = reader_stop = None
        try:
            while not stop.is_set():
                frames = queue.Queue(maxsize=256)
                options = {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE,
                           "stderr": None, "bufsize": 0}
                if os.name == "nt":
                    options["creationflags"] = subprocess.CREATE_NO_WINDOW
                self.child = subprocess.Popen(self.command, **options)
                child = self.child
                reader_stop = threading.Event()
                reader = threading.Thread(target=self._read_frames,
                                          args=(child.stdout, frames, reader_stop), daemon=True)
                reader.start()
                started = last_heartbeat = time.monotonic()
                ready = False
                compute_deadline = terminate_deadline = None
                compute_id = None
                self.log("worker_start", pid=child.pid)
                reason = "child_exit"
                while not stop.is_set() and child.poll() is None:
                    now = time.monotonic()
                    if (not ready and now - started >= self.startup_timeout):
                        reason = "startup_timeout"
                        break
                    if ready and now - last_heartbeat >= self.heartbeat_timeout:
                        reason = "heartbeat_timeout"
                        break
                    if terminate_deadline is not None and now >= terminate_deadline:
                        reason = "compute_cancel_grace_exceeded"
                        break
                    if compute_deadline is not None and now >= compute_deadline + self.shutdown_grace:
                        reason = "compute_deadline_grace_exceeded"
                        break
                    try:
                        frame = frames.get(timeout=0.05)
                    except queue.Empty:
                        continue
                    if frame.get("event") not in ("ready", "heartbeat"):
                        reason = "invalid_control"
                        break
                    status = frame.get("status")
                    if not isinstance(status, dict):
                        reason = "invalid_control"
                        break
                    last_heartbeat = time.monotonic()
                    if status.get("requires_restart"):
                        reason = "worker_requires_restart"
                        break
                    if frame["event"] == "ready":
                        if not status.get("ready") or ready:
                            reason = "invalid_control"
                            break
                        ready = True
                        # Deliberately whitelist fields; session IDs, leases and
                        # tensor payloads never enter supervisor logs.
                        detail = {name: frame[name] for name in (
                            "boot_id", "worker", "layer_start", "layer_end", "loading_seconds",
                            "rss_bytes", "startup_peak_rss_bytes", "parameter_bytes",
                            "parameter_count") if name in frame}
                        self.log("worker_ready", pid=child.pid, **detail)
                    if status.get("active_compute"):
                        identity, deadline = status.get("compute_id"), status.get("compute_deadline")
                        termination = status.get("terminate_deadline")
                        if (not isinstance(identity, str) or not identity or len(identity) > 128
                                or not isinstance(deadline, (int, float)) or not math.isfinite(deadline)
                                or (termination is not None and (not isinstance(termination, (int, float))
                                    or not math.isfinite(termination)))):
                            reason = "invalid_control"
                            break
                        if compute_id != identity:
                            compute_id, terminate_deadline = identity, None
                        compute_deadline = deadline
                        if termination is not None:
                            terminate_deadline = (termination if terminate_deadline is None
                                                  else min(terminate_deadline, termination))
                    else:
                        compute_id = compute_deadline = terminate_deadline = None
                if stop.is_set():
                    self._shutdown(frames, compute_id, compute_deadline, terminate_deadline)
                    reader_stop.set()
                    reader.join(timeout=1)
                    return 0
                self._kill_and_reap(reason)
                reader_stop.set()
                reader.join(timeout=1)
                now = time.monotonic()
                while restarts and now - restarts[0] >= self.restart_window:
                    restarts.popleft()
                if len(restarts) >= self.restart_limit:
                    self.log("restart_budget_exhausted", restarts=len(restarts),
                             window_seconds=self.restart_window)
                    return 70
                restarts.append(now)
                self.log("worker_restart", reason=reason, recent_restarts=len(restarts))
                stop.wait(0.1)
            return 0
        finally:
            if self.child is not None and self.child.poll() is None:
                self._kill_and_reap("supervisor_exit")
            if reader_stop is not None:
                reader_stop.set()
                reader.join(timeout=1)


def run_supervised(command, **options):
    stop = threading.Event()
    previous = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, lambda *_: stop.set())
    try:
        return ProcessSupervisor(command, **options).run(stop)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
