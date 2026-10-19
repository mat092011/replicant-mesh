"""Explicit no-network Paramiko 3.5.1 SFTP deadline regression probe.

Run only with the pinned operator-runtime Paramiko tree. This is intentionally
not named ``test_*.py`` so ordinary test discovery does not execute it.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import stat
import sys
import threading
import time
from unittest import mock


EXPECTED_PARAMIKO = "3.5.1"
UPLOAD_PATH = "/run/steamboat/probe/worker.tar"
PACKET_COUNT = 6
ACK_DELAY_SECONDS = 0.12
ACK_TIMEOUT_BUDGET_SECONDS = 0.50
CALLER_RETURN_MARGIN_SECONDS = 0.75
RETIREMENT_WAIT_SECONDS = 2.0


class ProbeFailure(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ProbeFailure(code)


class _AttributeMessage:
    """Tiny response body consumed by Paramiko's real SFTPAttributes parser."""

    def __init__(self, paramiko, sftp):
        attrs = paramiko.SFTPAttributes
        self._ints = [
            attrs.FLAG_SIZE | attrs.FLAG_UIDGID | attrs.FLAG_PERMISSIONS,
            1000,
            1000,
            stat.S_IFREG | sftp.file_mode,
        ]
        self._int_index = 0
        self._size = sftp.remote_size

    def get_int(self):
        value = self._ints[self._int_index]
        self._int_index += 1
        return value

    def get_int64(self):
        return self._size


class _Channel:
    def __init__(self, *, block_close: bool = False):
        self.timeouts: list[float] = []
        self.close_calls = 0
        self.close_started = threading.Event()
        self.release_close = threading.Event()
        self.closed = threading.Event()
        self.block_close = block_close
        self._lock = threading.Lock()

    @property
    def last_timeout(self):
        with self._lock:
            return self.timeouts[-1] if self.timeouts else None

    def settimeout(self, timeout):
        with self._lock:
            self.timeouts.append(float(timeout))

    def close(self):
        with self._lock:
            self.close_calls += 1
        self.close_started.set()
        if self.block_close and not self.release_close.wait(RETIREMENT_WAIT_SECONDS):
            raise ProbeFailure("controlled_close_not_released")
        self.closed.set()


class _FakeSftpServer:
    """SFTP server request/response boundary for real Paramiko SFTPFile calls."""

    def __init__(self, paramiko, channel, *, ack_delay=0.0,
                 held_ack_index: int | None = None):
        self.paramiko = paramiko
        self.channel = channel
        self.ack_delay = ack_delay
        self.held_ack_index = held_ack_index
        self.release_held_ack = threading.Event()
        self.held_ack_started = threading.Event()
        self.all_bytes_acknowledged = threading.Event()
        self.actual_write_finished = threading.Event()
        self.write_started_at = None
        self.write_finished_at = None
        self.write_socket_timeout = None
        self.open_requests: list[tuple[str, str]] = []
        self.events: list[str] = []
        self.file_mode = 0o644
        self.remote_size = 0
        self.requested_bytes = 0
        self.acknowledged_bytes = 0
        self.expected_payload_size = None
        self.write_packet_sizes: list[int] = []
        self.ack_delays: list[float] = []
        self.file_close_requests = 0
        self.client_close_calls = 0
        self._next_request_id = 1
        self._requests: dict[int, int] = {}
        self._lock = threading.Lock()
        self.stream = None

    def get_channel(self):
        return self.channel

    def _log(self, *_args, **_kwargs):
        return None

    def open(self, path, mode):
        self.events.append("open")
        self.open_requests.append((path, mode))
        stream = self.paramiko.SFTPFile(self, b"synthetic-handle", mode)
        original_write = stream.write

        def tracked_write(payload):
            self.write_started_at = time.monotonic()
            self.write_socket_timeout = self.channel.last_timeout
            self.expected_payload_size = len(payload)
            try:
                return original_write(payload)
            finally:
                self.write_finished_at = time.monotonic()
                self.actual_write_finished.set()

        # The original bound SFTPFile.write implementation still does all
        # buffering, chunking, request ordering and ACK waits.
        stream.write = tracked_write
        self.stream = stream
        return stream

    def _request(self, command, *args):
        constants = self.paramiko.sftp
        if command == constants.CMD_FSETSTAT:
            self.events.append("file_chmod")
            attributes = args[-1]
            if attributes.st_mode is not None:
                self.file_mode = attributes.st_mode
            return constants.CMD_STATUS, None
        if command == constants.CMD_FSTAT:
            self.events.append("file_stat")
            return constants.CMD_ATTRS, _AttributeMessage(self.paramiko, self)
        if command == constants.CMD_CLOSE:
            self.events.append("file_close")
            self.file_close_requests += 1
            return constants.CMD_STATUS, None
        raise ProbeFailure("unexpected_sftp_request")

    def _async_request(self, _fileobj, command, *args):
        if command != self.paramiko.sftp.CMD_WRITE:
            raise ProbeFailure("unexpected_sftp_async_request")
        payload = bytes(args[-1])
        with self._lock:
            request_id = self._next_request_id
            self._next_request_id += 1
            self._requests[request_id] = len(payload)
            self.write_packet_sizes.append(len(payload))
            self.requested_bytes += len(payload)
            self.remote_size += len(payload)
            if self.write_socket_timeout is None:
                self.write_socket_timeout = self.channel.last_timeout
        return request_id

    def _read_response(self, request_id):
        with self._lock:
            size = self._requests.get(request_id)
            response_index = len(self.ack_delays)
        if size is None:
            raise ProbeFailure("unknown_sftp_request_id")
        started = time.monotonic()
        if response_index == self.held_ack_index:
            self.held_ack_started.set()
            if not self.release_held_ack.wait(RETIREMENT_WAIT_SECONDS):
                raise ProbeFailure("controlled_ack_not_released")
        elif self.ack_delay:
            time.sleep(self.ack_delay)
        elapsed = time.monotonic() - started
        with self._lock:
            self.ack_delays.append(elapsed)
            self._requests.pop(request_id, None)
            self.acknowledged_bytes += size
            if (self.expected_payload_size is not None
                    and self.acknowledged_bytes == self.expected_payload_size):
                self.all_bytes_acknowledged.set()
        return self.paramiko.sftp.CMD_STATUS, None

    def stat(self, _path):
        self.events.append("path_stat")
        return type("Attributes", (), {
            "st_uid": 1000,
            "st_gid": 1000,
            "st_mode": stat.S_IFREG | self.file_mode,
            "st_size": self.remote_size,
        })()

    def close(self):
        self.events.append("sftp_close")
        self.client_close_calls += 1
        self.channel.close()


def _wait_for_owner_count(supervisor, expected: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if supervisor._pending_channel_operation_count() == expected:
            return True
        time.sleep(0.005)
    return supervisor._pending_channel_operation_count() == expected


def _run_upload_thread(supervisor, sftp, payload: bytes, deadline: float,
                       *, call_patch=None):
    result = {}

    def upload():
        try:
            supervisor._sftp_upload_bundle(
                object(), payload, "/run/steamboat/probe", 1000, deadline)
            result["success"] = True
        except BaseException as error:
            result["error"] = error

    caller = threading.Thread(target=upload, name="probe-upload-caller", daemon=True)
    start = time.monotonic()
    with mock.patch.object(supervisor, "_open_sftp", return_value=sftp):
        if call_patch is None:
            caller.start()
            caller.join(max(1.0, deadline - start + CALLER_RETURN_MARGIN_SECONDS))
        else:
            with mock.patch.object(supervisor, "_sftp_call", side_effect=call_patch):
                caller.start()
                caller.join(max(1.0, deadline - start + CALLER_RETURN_MARGIN_SECONDS))
        caller_returned = not caller.is_alive()
        elapsed = time.monotonic() - start
        if not caller_returned:
            # Keep test doubles from being stranded if a regression blocks the
            # caller in its close path. The captured return flag remains false.
            sftp.release_held_ack.set()
            sftp.channel.release_close.set()
            caller.join(1.0)
    return caller, result, elapsed, caller_returned


def _load_pinned_runtime(site_packages: Path):
    if "paramiko" in sys.modules:
        raise ProbeFailure("paramiko_preloaded_before_pin")
    site_packages = site_packages.resolve(strict=True)
    if not site_packages.is_dir():
        raise ProbeFailure("paramiko_site_packages_not_directory")
    repository_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repository_root))
    sys.path.insert(0, str(site_packages))

    import paramiko
    from paramiko.sftp import CMD_ATTRS, CMD_STATUS
    from paramiko.sftp_attr import SFTPAttributes

    try:
        distribution_version = importlib.metadata.version("paramiko")
    except importlib.metadata.PackageNotFoundError:
        raise ProbeFailure("paramiko_distribution_metadata_missing") from None
    package_file = Path(paramiko.__file__).resolve()
    common = os.path.commonpath((str(site_packages), str(package_file)))
    if os.path.normcase(common) != os.path.normcase(str(site_packages)):
        raise ProbeFailure("paramiko_import_outside_pinned_tree")
    if distribution_version != EXPECTED_PARAMIKO or paramiko.__version__ != EXPECTED_PARAMIKO:
        raise ProbeFailure("paramiko_version_mismatch")
    if (SFTPAttributes.FLAG_SIZE | SFTPAttributes.FLAG_UIDGID
            | SFTPAttributes.FLAG_PERMISSIONS) == 0 or CMD_ATTRS == CMD_STATUS:
        raise ProbeFailure("paramiko_protocol_contract_unexpected")
    return paramiko


def _exercise_successful_multipacket_upload(supervisor, paramiko, payload):
    channel = _Channel()
    sftp = _FakeSftpServer(paramiko, channel, ack_delay=0.001)
    owner_baseline = supervisor._pending_channel_operation_count()
    deadline = time.monotonic() + 5.0
    caller, result, _elapsed, caller_returned = _run_upload_thread(
        supervisor, sftp, payload, deadline)
    require(caller_returned and not caller.is_alive(), "normal_control_caller_timeout")
    require(result.get("success") is True, "normal_control_upload_failed")
    require(sftp.open_requests == [(UPLOAD_PATH, "wx")], "normal_control_open_mode")
    require(sftp.actual_write_finished.is_set(), "normal_control_write_not_finished")
    require(sftp.requested_bytes == len(payload), "normal_control_requested_bytes")
    require(sftp.acknowledged_bytes == len(payload), "normal_control_acked_bytes")
    expected_packets = (
        len(payload) + paramiko.SFTPFile.MAX_REQUEST_SIZE - 1
    ) // paramiko.SFTPFile.MAX_REQUEST_SIZE
    require(len(sftp.write_packet_sizes) == expected_packets,
            "normal_control_packet_count")
    require(all(size <= paramiko.SFTPFile.MAX_REQUEST_SIZE
                for size in sftp.write_packet_sizes), "normal_control_packet_limit")
    require(sftp.file_close_requests == 1, "normal_control_file_close_count")
    require(sftp.client_close_calls == 1, "normal_control_sftp_close_count")
    require(channel.close_calls == 1 and channel.closed.is_set(),
            "normal_control_channel_close")
    require(supervisor._pending_channel_operation_count() == owner_baseline,
            "normal_control_owner_leak")
    return {
        "write_packets": len(sftp.write_packet_sizes),
        "bytes_acknowledged": sftp.acknowledged_bytes,
    }


def _exercise_delayed_ack_timeout(supervisor, paramiko, payload):
    channel = _Channel(block_close=True)
    sftp = _FakeSftpServer(
        paramiko, channel, ack_delay=ACK_DELAY_SECONDS, held_ack_index=2)
    owner_baseline = supervisor._pending_channel_operation_count()
    started = time.monotonic()
    deadline = started + ACK_TIMEOUT_BUDGET_SECONDS
    caller, result, elapsed, caller_returned = _run_upload_thread(
        supervisor, sftp, payload, deadline)
    try:
        require(caller_returned and not caller.is_alive(),
                "delayed_ack_caller_not_bounded")
        error = result.get("error")
        require(isinstance(error, supervisor.SupervisorError),
                "delayed_ack_missing_supervisor_error")
        require(error.code == "ack_timeout_unknown", "delayed_ack_wrong_failure")
        require(elapsed < ACK_TIMEOUT_BUDGET_SECONDS + CALLER_RETURN_MARGIN_SECONDS,
                "delayed_ack_caller_exceeded_bound")
        require(sftp.held_ack_started.wait(0.5), "delayed_ack_barrier_not_reached")
        require(channel.close_started.wait(0.5), "owned_closer_not_started")
        require(channel.close_calls == 1, "duplicate_channel_close")
        require(sftp.file_close_requests == 0, "finally_sent_file_close")
        require(sftp.client_close_calls == 0, "finally_sent_sftp_close")
        require(sftp.requested_bytes < len(payload), "timeout_did_not_interrupt_write")
        require(supervisor._pending_channel_operation_count() == owner_baseline + 1,
                "pending_owner_not_retained")
        evidence = supervisor._pending_channel_operation_evidence()
        require(any(item.get("state") == "unknown_pending_retirement"
                    and item.get("failure_code") == "ack_timeout_unknown"
                    and item.get("close_started") is True for item in evidence),
                "pending_owner_evidence_missing")

        write_timeout = sftp.write_socket_timeout
        require(type(write_timeout) in (int, float) and write_timeout > 0,
                "write_socket_timeout_missing")
        require(ACK_DELAY_SECONDS < write_timeout,
                "individual_ack_delay_not_below_socket_timeout")
        expected_packets = (
            len(payload) + paramiko.SFTPFile.MAX_REQUEST_SIZE - 1
        ) // paramiko.SFTPFile.MAX_REQUEST_SIZE
        require(ACK_DELAY_SECONDS * expected_packets >
                ACK_TIMEOUT_BUDGET_SECONDS,
                "configured_total_ack_time_not_over_deadline")

        # The third response is deliberately withheld while the caller returns.
        # Releasing it lets actual Paramiko SFTPFile.write continue issuing and
        # awaiting its remaining packet ACKs while the owned closer stays held.
        sftp.release_held_ack.set()
        require(sftp.actual_write_finished.wait(1.5),
                "delayed_ack_write_did_not_retire_after_release")
        require(sftp.all_bytes_acknowledged.is_set(),
                "delayed_ack_write_not_fully_acknowledged_after_release")
        require(sftp.acknowledged_bytes == len(payload),
                "delayed_ack_acknowledged_byte_count")
        require(sftp.write_finished_at is not None and sftp.write_started_at is not None
                and sftp.write_finished_at - sftp.write_started_at > write_timeout,
                "multipacket_total_did_not_exceed_single_socket_timeout")
        require(all(delay < write_timeout for delay in sftp.ack_delays),
                "individual_ack_exceeded_socket_timeout")
        require(supervisor._pending_channel_operation_count() == owner_baseline + 1,
                "owner_released_before_closer_retired")
    finally:
        sftp.release_held_ack.set()
        channel.release_close.set()
        caller.join(1.0)
        if sftp.stream is not None and not supervisor._pending_channel_operation_count():
            # The fake channel is already closed. Avoid Paramiko's destructor
            # attempting another asynchronous CMD_CLOSE after the test.
            sftp.stream._closed = True

    require(_wait_for_owner_count(supervisor, owner_baseline, RETIREMENT_WAIT_SECONDS),
            "owner_not_released_after_actual_retirement")
    if sftp.stream is not None:
        # The fake channel close has now really retired. Dispose its synthetic
        # handle without an extra protocol request from SFTPFile.__del__.
        sftp.stream._closed = True
    return {
        "failure": "ack_timeout_unknown",
        "caller_elapsed_ms": round(elapsed * 1000, 1),
        "write_packets": len(sftp.write_packet_sizes),
        "bytes_acknowledged_after_release": sftp.acknowledged_bytes,
        "pending_evidence_observed": True,
        "finally_protocol_closes": 0,
    }


def _exercise_deadline_between_operations(supervisor, paramiko, payload):
    channel = _Channel(block_close=True)
    sftp = _FakeSftpServer(paramiko, channel)
    owner_baseline = supervisor._pending_channel_operation_count()
    original_call = supervisor._sftp_call
    call_count = [0]

    def expire_after_open(actual_sftp, deadline, stage, call):
        if call_count[0] == 0:
            call_count[0] += 1
            return original_call(actual_sftp, deadline, stage, call)
        raise supervisor.SupervisorError(stage, "deadline")

    caller = None
    result = {}
    started = time.monotonic()
    with mock.patch.object(supervisor, "_open_sftp", return_value=sftp), \
            mock.patch.object(supervisor, "_sftp_call", side_effect=expire_after_open):
        def upload():
            try:
                supervisor._sftp_upload_bundle(
                    object(), payload, "/run/steamboat/probe", 1000,
                    time.monotonic() + 5.0)
                result["success"] = True
            except BaseException as error:
                result["error"] = error

        caller = threading.Thread(target=upload, name="probe-expired-upload", daemon=True)
        caller.start()
        caller.join(0.75)
        caller_returned = not caller.is_alive()
        if not caller_returned:
            channel.release_close.set()
            caller.join(1.0)
    elapsed = time.monotonic() - started
    try:
        require(caller is not None and caller_returned and not caller.is_alive(),
                "between_calls_abort_not_bounded")
        error = result.get("error")
        require(isinstance(error, supervisor.SupervisorError)
                and error.code == "deadline", "between_calls_wrong_primary_error")
        require(elapsed < 0.75, "between_calls_abort_blocked_caller")
        require(channel.close_started.wait(0.5), "between_calls_owned_abort_not_started")
        require(channel.close_calls == 1, "between_calls_duplicate_close")
        require(sftp.write_packet_sizes == [], "between_calls_unexpected_write")
        require(sftp.file_close_requests == 0 and sftp.client_close_calls == 0,
                "between_calls_finally_protocol_close")
        require(supervisor._pending_channel_operation_count() == owner_baseline + 1,
                "between_calls_abort_owner_not_retained")
        evidence = supervisor._pending_channel_operation_evidence()
        require(any(item.get("state") == "unknown_pending_retirement"
                    and item.get("close_started") is True for item in evidence),
                "between_calls_abort_evidence_missing")
    finally:
        channel.release_close.set()
        if caller is not None:
            caller.join(1.0)
    require(_wait_for_owner_count(supervisor, owner_baseline, RETIREMENT_WAIT_SECONDS),
            "between_calls_abort_owner_not_retired")
    if sftp.stream is not None:
        sftp.stream._closed = True
    return {"failure": "deadline", "caller_elapsed_ms": round(elapsed * 1000, 1),
            "pending_abort_evidence_observed": True}


def run(site_packages: Path) -> dict:
    paramiko = _load_pinned_runtime(site_packages)
    from lab import secure_cohort_supervisor as supervisor

    packet_size = paramiko.SFTPFile.MAX_REQUEST_SIZE
    payload = bytes((index * 29 + 7) % 251 for index in range(
        PACKET_COUNT * packet_size - 19))
    require(len(payload) > 2 * packet_size, "payload_not_multipacket")
    success = _exercise_successful_multipacket_upload(supervisor, paramiko, payload)
    delayed_ack = _exercise_delayed_ack_timeout(supervisor, paramiko, payload)
    between_calls = _exercise_deadline_between_operations(supervisor, paramiko, payload)
    return {
        "status": "passed",
        "paramiko_version": paramiko.__version__,
        "network_used": False,
        "payload_bytes": len(payload),
        "packet_bytes": packet_size,
        "successful_control": success,
        "delayed_ack_timeout": delayed_ack,
        "expired_between_operations": between_calls,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--paramiko-site-packages", required=True, type=Path,
        help="site-packages directory containing the pinned Paramiko 3.5.1 wheel",
    )
    args = parser.parse_args(argv)
    try:
        result = run(args.paramiko_site_packages)
    except BaseException as error:
        result = {
            "status": "failed",
            "failure_type": type(error).__name__,
            "failure_code": getattr(error, "code", None),
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
