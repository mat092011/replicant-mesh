"""Required offline operator check for the pinned Paramiko 3.5.1 request wait.

Run from the repository root with the private 3.5.1 site-packages explicitly
prepended to sys.path, for example:

    python -c "import sys,runpy; sys.path.insert(0, r'<pinned-site-packages>'); runpy.run_path('tests/paramiko_deadline_check.py', run_name='__main__')"

This check uses actual Paramiko Channel instances and a fake Transport. It opens
no sockets and makes no SSH connection.
"""

from __future__ import annotations

import threading
import time

import paramiko

from lab import secure_cohort_supervisor as supervisor


EXPECTED_PARAMIKO = "3.5.1"
REQUEST_SECONDS = 0.12
RETIRE_SECONDS = 2.0


class _NoNetworkTransport:
    def __init__(self, *, acknowledge=False):
        self.acknowledge = acknowledge
        self.channel = None
        self.sent_messages = []

    def _send_user_message(self, message):
        self.sent_messages.append(message)
        if self.acknowledge and self.channel is not None:
            self.channel.event_ready = True
            self.channel.event.set()

    def get_exception(self):
        return None


def _channel(*, acknowledge=False, channel_id=1):
    transport = _NoNetworkTransport(acknowledge=acknowledge)
    channel = paramiko.Channel(channel_id)
    channel.transport = transport
    channel.active = True
    channel.remote_chanid = channel_id
    transport.channel = channel
    return channel, transport


def _wait_for_no_owned_operations():
    deadline = time.monotonic() + RETIRE_SECONDS
    while supervisor._pending_channel_operation_count() and time.monotonic() < deadline:
        time.sleep(0.005)
    if supervisor._pending_channel_operation_count():
        raise AssertionError("timed-out Paramiko operation remained owned")


def _prove_previous_unbounded_wait():
    channel, _transport = _channel()
    started = threading.Event()
    finished = threading.Event()
    result = []

    def unbounded_request():
        started.set()
        try:
            channel.exec_command("true")
            result.append("unexpected-success")
        except BaseException as error:
            result.append(type(error).__name__)
        finally:
            finished.set()

    thread = threading.Thread(
        target=unbounded_request, name="paramiko-unbounded-demonstration", daemon=True)
    thread.start()
    try:
        if not started.wait(1.0):
            raise AssertionError("actual Paramiko exec request did not start")
        if finished.wait(0.05):
            raise AssertionError("unacknowledged actual Paramiko request did not block")
        channel.close()
        if not finished.wait(1.0):
            raise AssertionError("explicit channel close did not wake request event wait")
        thread.join(1.0)
        if thread.is_alive():
            raise AssertionError("unbounded demonstration thread failed to retire")
        if not result or result[0] == "unexpected-success":
            raise AssertionError("closed unacknowledged request reported success")
    finally:
        channel.close()
        thread.join(1.0)
        if thread.is_alive():
            raise AssertionError("unbounded demonstration left a live thread")


def _prove_bounded_request(label, request):
    channel, transport = _channel()
    started_at = time.monotonic()
    try:
        try:
            supervisor._channel_operation(
                channel,
                lambda: request(channel),
                deadline=started_at + REQUEST_SECONDS,
                stage=f"paramiko_{label}",
                failure_code="request_failed",
            )
        except supervisor.SupervisorError as error:
            if error.code != "ack_timeout_unknown":
                raise AssertionError(
                    f"{label} returned wrong timeout classification: {error.code}") from None
        else:
            raise AssertionError(f"unacknowledged {label} unexpectedly succeeded")
        elapsed = time.monotonic() - started_at
        if elapsed > 1.0:
            raise AssertionError(f"{label} caller exceeded bounded return: {elapsed:.3f}s")
        if not channel.event.wait(1.0):
            raise AssertionError(f"{label} channel close did not signal its request event")
        _wait_for_no_owned_operations()
        message_count = len(transport.sent_messages)
        time.sleep(0.02)
        if len(transport.sent_messages) != message_count:
            raise AssertionError(f"{label} wrote again after operation retirement")
    finally:
        channel.close()


def _prove_successful_ack():
    channel, transport = _channel(acknowledge=True, channel_id=9)
    try:
        result = supervisor._channel_operation(
            channel,
            lambda: channel.exec_command("true"),
            deadline=time.monotonic() + 1.0,
            stage="paramiko_exec_control",
            failure_code="request_failed",
        )
        if result is not None or not channel.event_ready:
            raise AssertionError("successful actual exec acknowledgement was not preserved")
        if len(transport.sent_messages) != 1:
            raise AssertionError("successful request wrote an unexpected extra message")
        before = len(transport.sent_messages)
        time.sleep(0.02)
        if len(transport.sent_messages) != before:
            raise AssertionError("successful request wrote after returning")
        _wait_for_no_owned_operations()
    finally:
        channel.close()


def main():
    if getattr(paramiko, "__version__", None) != EXPECTED_PARAMIKO:
        raise AssertionError(
            f"expected pinned Paramiko {EXPECTED_PARAMIKO}, found "
            f"{getattr(paramiko, '__version__', 'unknown')} at {paramiko.__file__}")
    _prove_previous_unbounded_wait()
    _prove_bounded_request("exec", lambda channel: channel.exec_command("true"))
    _prove_bounded_request("subsystem", lambda channel: channel.invoke_subsystem("sftp"))
    _prove_successful_ack()
    print("paramiko_deadline_check: Paramiko 3.5.1 request acknowledgements bounded")


if __name__ == "__main__":
    main()
