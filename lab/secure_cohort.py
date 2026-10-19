"""Nonproduction secure cohort runner for the laptop/ZimaBlade C1b baseline.

The laptop process owns the temporary C0 authority and all laptop-side secure
services. It publishes only a bounded worker-3 bundle and fixed JSON control
files. A trusted parent operator transfers the bundle, starts/stops the remote
container, and writes acknowledgements after inspecting protected remote
status over SSH. This module never invokes SSH, Docker, a shell, or a command
named by a control file.

Control files are version-1 closed-schema JSON, at most 64 KiB, mode 0600 in
an existing owner-only mode-0700 handoff directory:

* ``bundle-ready.json``: run/nonce, private bundle path, expected worker boot,
  manifest/snapshot fingerprints, and the fixed endpoint.
* ``ready.json``: matching run/nonce/boot/fingerprints/endpoint, SSH host-key
  SHA-256, remote status owner/mode/mtime, measurement label, and the actual
  protected worker status object.
* ``observation-request-N.json`` / ``observation-response-N.json``: matching
  request/session IDs and sequence; the response includes a fresh remote
  heartbeat mtime later than the parent-observed remote wall-time mark and the
  actual protected status object.
* ``stop-request.json`` / ``stop-response.json``: the parent must report an
  observed process exit and final protected status, or positively report that
  startup never occurred. Missing/ambiguous acknowledgements are failures.

The fixed filenames and exported ``HANDOFF_*_FIELDS`` constants define the
wire contract. In short, bundle-ready carries the run/nonce, private bundle
path, worker boot, manifest and snapshot hashes, and endpoint; ready and
observation acknowledgements carry SSH host-key SHA-256 plus the protected
worker status and UID/mode/mtime evidence; observation messages additionally
bind sequence, case, request, session, and a same-host remote mark/heartbeat
mtime; stop acknowledgement binds process exit and final status. The runner
does not accept unknown fields or acknowledgement filenames.

The unit tests validate this protocol with explicitly synthetic objects; they
do not establish remote readiness or C1b acceptance.

The operator must mount the handoff directory on private tmpfs. The short-lived
C0 authority fixture is created as a private child of that directory so its
CA/signing keys and worker bundle stay on the same tmpfs; only the bundle path
is named in the handoff record.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
from dataclasses import dataclass
import gc
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time


REMOTE_PORT = 50061
REMOTE_ROOT = "/run/steamboat"
READY_TIMEOUT_SECONDS = 60.0
OBSERVATION_TIMEOUT_SECONDS = 60.0
STOP_TIMEOUT_SECONDS = 15.0
MAX_CONTROL_BYTES = 65_536
MAX_CONFIG_BYTES = 16_384
MAX_CERTIFICATE_BYTES = 65_536
MAX_PRIVATE_KEY_BYTES = 1_048_576
MAX_SNAPSHOT_BYTES = 64 * 1024
REMOTE_STATUS_UID = 1000
REMOTE_STATUS_MODE = 0o600
READY_LABEL = "ssh_protected_ready_status"
OBSERVATION_LABEL = "ssh_status_after_heartbeat"
STOP_LABEL = "ssh_supervisor_exit_and_final_status"
HANDOFF_BUNDLE_READY_FILE = "bundle-ready.json"
HANDOFF_READY_ACK_FILE = "ready.json"
HANDOFF_STOP_REQUEST_FILE = "stop-request.json"
HANDOFF_STOP_ACK_FILE = "stop-response.json"
HANDOFF_RESULT_FILE = "result.json"
HANDOFF_FAILURE_LOCATION_FILE = "failure-location.json"
OWNER_MATERIALS_READY_FILE = "owner-materials-ready.json"
OWNER_ACTION_REQUEST_FILES = ("owner-action-request-1.json", "owner-action-request-2.json")
OWNER_ACTION_RESPONSE_FILES = ("owner-action-response-1.json", "owner-action-response-2.json")
RESTART_STOP_REQUEST_FILE = "restart-stop-request.json"
RESTART_STOP_ACK_FILE = "restart-stop-response.json"
RESTART_BUNDLE_READY_FILE = "restart-bundle-ready.json"
RESTART_READY_ACK_FILE = "restart-ready-ack.json"
_HEX32 = re.compile(r"[0-9a-f]{32}", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_FAILURE_TYPE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z", re.ASCII)
_FAILURE_FRAME_FILE = re.compile(r"[A-Za-z0-9_.-]{1,80}\Z", re.ASCII)
_FAILURE_FRAME_FUNCTION = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z", re.ASCII)
_FAILURE_ERROR_CODES = frozenset((
    "INVALID_INPUT", "INCOMPATIBLE_MODEL", "CAPACITY_EXHAUSTED",
    "EXPIRED_SESSION", "STALE_WORKER", "OUT_OF_ORDER", "TIMEOUT",
    "EXECUTION_FAILED", "CANCELLED", "CLOSED_SESSION", "UNKNOWN_SESSION",
    "UNAUTHENTICATED", "PERMISSION_DENIED", "UNAVAILABLE",
    "RESOURCE_EXHAUSTED", "INVALID_ARGUMENT", "FAILED_PRECONDITION",
    "DEADLINE_EXCEEDED", "INTERNAL", "ABORTED", "DATA_LOSS",
    "UNIMPLEMENTED", "OUT_OF_RANGE", "NOT_FOUND", "ALREADY_EXISTS",
    "UNKNOWN", "SECURITY_ERROR", "AUTHORITY_UNAVAILABLE", "CLOCK_UNSAFE",
    "LOCAL_CREDENTIALS_UNSAFE", "UNRECOGNIZED_ERROR_CODE",
))
MAX_FAILURE_LOCATION_BYTES = 4096
MAX_FAILURE_TRACEBACK_FRAMES = 64
MAX_FAILURE_LOCATION_FRAMES = 12
_TYPED_ACCOUNT = re.compile(r"acct_[0-9a-f]{32}", re.ASCII)
_TYPED_DEVICE = re.compile(r"dev_[0-9a-f]{32}", re.ASCII)
_TYPED_ASSIGNMENT = re.compile(r"asg_[0-9a-f]{32}", re.ASCII)
_TYPED_REQUEST = re.compile(r"req_[0-9a-f]{32}", re.ASCII)
_TYPED_SESSION = re.compile(r"ses_[0-9a-f]{32}", re.ASCII)
_TYPED_ROUTE = re.compile(r"route_[0-9a-f]{32}", re.ASCII)
_TYPED_OPERATION = re.compile(r"op_[0-9a-f]{32}", re.ASCII)

_WORKER_CONFIG_FIELDS = frozenset((
    "schema_version", "protected_root", "account_id", "device_id", "boot_id",
    "assignment_id", "worker_name", "model_id", "model_revision",
    "manifest_fingerprint", "listen_ip", "listen_port",
    "clock_uncertainty_seconds", "certificate_path", "private_key_path",
    "cohort_ca_path", "snapshot_verification_key_path", "signed_snapshot_path",
    "artifact_directory", "acceptor_directory", "status_report_path",
))
_WORKER_STATUS_FIELDS = frozenset((
    "schema_version", "event", "phase", "worker_name", "account_id",
    "device_id", "boot_id", "assignment_id", "model_id", "model_revision",
    "manifest_fingerprint", "listen_endpoint", "layer_range",
    "clock_uncertainty_seconds", "torch_threads", "handler", "bridge",
    "transport", "external_supervision", "shutdown", "report_state",
    "resource_state",
))
_HANDLER_STATUS_FIELDS = frozenset((
    "state", "active_sessions", "tombstones", "retained_entries", "queued_operations",
    "active_compute", "cache_bytes_exact", "requires_restart", "stopping",
    "active_session_ids", "limits", "committed_cache_bytes", "committed_cache_bytes_lower_bound",
    "allocated_cache_bytes",
))
_HANDLER_LIMIT_FIELDS = frozenset((
    "max_sessions", "max_tombstones", "max_stage_queue", "max_positions",
    "max_cache_positions", "max_cache_bytes", "max_message_bytes",
))
_BRIDGE_STATUS_FIELDS = frozenset((
    "state", "ready", "unavailable", "requires_restart", "cleanup_confirmed",
    "active_authorizations", "owned_sessions", "pending_notices", "fault_present",
))
_TRANSPORT_STATUS_FIELDS = frozenset((
    "listener_slots", "max_connections", "max_pending", "reserved_connections",
    "reserved_pending", "reserved_listener_pending_capacity",
    "reserved_outbound_pending", "server_state",
))
HANDOFF_BUNDLE_READY_FIELDS = frozenset((
    "schema_version", "event", "run_id", "nonce", "bundle_path",
    "expected_boot_id", "manifest_fingerprint", "snapshot_sha256",
    "endpoint", "worker_name",
))
HANDOFF_READY_ACK_FIELDS = frozenset((
    "schema_version", "event", "run_id", "nonce", "boot_id",
    "manifest_fingerprint", "snapshot_sha256", "endpoint",
    "ssh_host_key_sha256", "remote_status_uid", "remote_status_mode",
    "remote_status_mtime_ns", "measurement_label", "remote_status",
))
HANDOFF_OBSERVATION_REQUEST_FIELDS = frozenset((
    "schema_version", "event", "run_id", "nonce", "expected_boot_id",
    "sequence", "case_id", "request_id", "session_id",
))
HANDOFF_OBSERVATION_ACK_FIELDS = frozenset((
    "schema_version", "event", "run_id", "nonce", "sequence", "case_id",
    "request_id", "session_id", "boot_id", "manifest_fingerprint", "endpoint",
    "ssh_host_key_sha256", "remote_status_uid", "remote_status_mode",
    "supervisor_monotonic_ns",
    "remote_mark_ns", "heartbeat_mtime_ns", "measurement_label", "remote_status",
))
HANDOFF_STOP_REQUEST_FIELDS = frozenset((
    "schema_version", "event", "run_id", "nonce", "expected_boot_id",
    "may_have_started", "maximum_wait_seconds",
))
HANDOFF_STOP_ACK_FIELDS = frozenset((
    "schema_version", "event", "run_id", "nonce", "boot_id", "process_state",
    "exit_code", "shutdown_confirmed", "ssh_host_key_sha256",
    "remote_status_uid", "remote_status_mode", "measurement_label", "remote_status",
))
HANDOFF_RESULT_FIELDS = frozenset((
    "schema_version", "event", "run_id", "baseline", "request_ids",
    "session_ids", "numerical_errors", "cases", "local_shutdown",
    "remote_shutdown", "failure_type", "pending_scope", "identities",
    "interleave", "cancellation", "partial_admission", "step_reply_loss",
    "capacity", "restart", "owner_actions",
))
_EXPECTED_STAGE_CASES = (
    ("greedy-one-token", 3),
    ("forced-length-1", 1),
    ("forced-length-128", 128),
    ("forced-length-1024", 1024),
)
PROFILE_BASELINE = "baseline-v1"
PROFILE_C1B_HAPPY = "c1b-happy-v1"
PROFILE_C1B_INTERLEAVE = "c1b-interleave-v1"
PROFILE_C1B_CANCEL = "c1b-cancel-v1"
PROFILE_C1B_PARTIAL = "c1b-partial-open-v1"
PROFILE_C1B_STEP_LOSS = "c1b-step-reply-loss-v1"
PROFILE_C1B_CAPACITY = "c1b-capacity-v1"
PROFILE_C1B_RESTART = "c1b-restart-v1"
PROFILE_C1B_OWNER_DRAIN = "c1b-owner-drain-v1"
PROFILE_C1B_OWNER_REMOVE = "c1b-owner-remove-v1"
LOCAL_COHORT_ACCEPTOR_DIRECTORY_NAME = "s"
_RETAINED_CANCELLATION_OWNERS = []
_RETAINED_RESTART_OWNERS = []
_RETAINED_OWNER_OWNERS = []


def _retain_owner_graph(authority, *resources):
    """Bounded owner-profile retention for any uncertain context or process exit."""
    for index, graph in enumerate(_RETAINED_OWNER_OWNERS):
        if type(graph) is tuple and graph and graph[0] is authority:
            retained = list(graph)
            retained.extend(resource for resource in resources
                            if all(resource is not existing for existing in retained))
            _RETAINED_OWNER_OWNERS[index] = tuple(retained)
            return
    if len(_RETAINED_OWNER_OWNERS) >= 1:
        raise CohortError("owner retained graph registry capacity exceeded")
    _RETAINED_OWNER_OWNERS.append((authority, *resources))


def _owner_authority_retention_required(*, active, cleanup_errors,
                                       direct_cleanup_unconfirmed,
                                       may_have_started, remote_shutdown):
    return (active and (bool(cleanup_errors) or direct_cleanup_unconfirmed is True
                        or (may_have_started and not remote_shutdown.get("confirmed"))))


async def _close_restart_owner_once(owner, attempts):
    """Close a restart owner once, preserving the first failure and owner strongly."""
    key = id(owner)
    prior = attempts.get(key)
    if prior is not None and prior[0] is owner:
        return prior[1]
    try:
        errors = await owner.close()
    except BaseException as error:
        errors = [error]
    attempts[key] = (owner, errors)
    return errors


async def _close_restart_probe_client_once(client, budget, state, *,
                                           expected_connections_before,
                                           expected_connections_after):
    """Close one stale-probe client once and retain its first outcome."""
    if state.get("attempted") is True:
        if state.get("failure") is not None:
            raise state["failure"]
        if state.get("confirmed") is True:
            return state
        raise CohortError("old restart client close remains unconfirmed")
    state.update({"attempted": True, "close_calls": 1,
                  "reserved_connections_before": budget.reserved_connections,
                  "reserved_connections_after": None, "client_closed": False,
                  "confirmed": False, "failure": None})
    if state["reserved_connections_before"] != expected_connections_before:
        error = CohortError("restart client budget changed before its first close")
        state["failure"] = error
        raise error
    try:
        result = client.close()
        if hasattr(result, "__await__"):
            await result
    except BaseException as error:
        state["reserved_connections_after"] = budget.reserved_connections
        state["client_closed"] = getattr(client, "_closed", False) is True
        state["failure"] = error
        raise
    state["reserved_connections_after"] = budget.reserved_connections
    state["client_closed"] = getattr(client, "_closed", False) is True
    if (state["client_closed"] is not True
            or state["reserved_connections_after"] != expected_connections_after):
        error = CohortError("old restart client close did not release its accounted slots")
        state["failure"] = error
        raise error
    state["confirmed"] = True
    return state


async def _close_restart_probe_client_for_cleanup(client, budget, state, *,
                                                  connection_slots):
    """Close an owned client at teardown using its current accounted slots once."""
    if state.get("attempted") is True:
        return await _close_restart_probe_client_once(
            client, budget, state,
            expected_connections_before=state["reserved_connections_before"],
            expected_connections_after=state["reserved_connections_before"] - connection_slots)
    before = budget.reserved_connections
    if before not in (connection_slots, 2 * connection_slots):
        raise CohortError("restart cleanup cannot attribute the original client reservation")
    return await _close_restart_probe_client_once(
        client, budget, state, expected_connections_before=before,
        expected_connections_after=before - connection_slots)


async def _close_restart_probe_owners_after_clients(probes, clients, budget,
                                                    close_outcomes):
    """Release Generate contexts only after every created transport closed once."""
    for client, state in clients:
        if (state.get("attempted") is not True or state.get("confirmed") is not True
                or type(state.get("close_calls")) is not int
                or state.get("close_calls") != 1
                or state.get("client_closed") is not True
                or getattr(client, "_closed", False) is not True):
            raise CohortError(
                "restart probe authorization retained until every client close is confirmed")
    counters = ("reserved_connections", "reserved_pending",
                "reserved_outbound_pending", "reserved_listener_pending_capacity")
    if any(type(getattr(budget, name, None)) is not int
           or getattr(budget, name) != 0 for name in counters):
        raise CohortError(
            "restart probe authorization retained while transport reservations remain")
    for probe in probes:
        key = id(probe)
        prior = close_outcomes.get(key)
        if prior is not None:
            if prior[0] is not probe:
                raise CohortError("restart probe close owner identity was reused")
            if prior[1] is not None:
                raise prior[1]
            continue
        close_outcomes[key] = (probe, None)
        try:
            result = probe.close()
            if hasattr(result, "__await__"):
                await result
        except BaseException as error:
            close_outcomes[key] = (probe, error)
            raise


async def _replace_restart_probe_client(client, budget, state, *,
                                        create_replacement, register_replacement,
                                        connection_slots):
    """Dispose the stale caller before creating its accounted replacement."""
    if state.get("replacement_attempted") is True:
        if state.get("replacement_failure") is not None:
            raise state["replacement_failure"]
        if state.get("replacement_confirmed") is True:
            return state["replacement_client"], state["replacement_counts"]
        raise CohortError("restart client replacement remains unconfirmed")
    state["replacement_attempted"] = True
    try:
        await _close_restart_probe_client_once(
            client, budget, state, expected_connections_before=2 * connection_slots,
            expected_connections_after=connection_slots)
    except BaseException as error:
        state["replacement_failure"] = error
        raise
    counts = [2, budget.reserved_connections // connection_slots]
    if (budget.reserved_connections != connection_slots
            or counts != [2, 1]):
        error = CohortError("restart client replacement began before old slots were released")
        state["replacement_failure"] = error
        raise error
    try:
        replacement = create_replacement()
        if hasattr(replacement, "__await__"):
            replacement = await replacement
    except BaseException as error:
        state["replacement_failure"] = error
        raise
    state["replacement_client"] = replacement
    register_replacement(replacement)
    counts.append(budget.reserved_connections // connection_slots)
    if (budget.reserved_connections != 2 * connection_slots
            or counts != [2, 1, 2]):
        error = CohortError("fresh restart client exceeded the two-client connection budget")
        state["replacement_failure"] = error
        raise error
    state["replacement_counts"] = counts
    state["replacement_confirmed"] = True
    return replacement, counts


def _restart_remote_exit_confirmed(value):
    return (type(value) is dict and value.get("confirmed") is True
            and value.get("process_state") == "exited"
            and type(value.get("exit_code")) is int and value.get("exit_code") == 0)


def _retain_restart_graph_if_uncertain(remote_shutdown, cleanup_errors, *resources):
    """Keep private authority and OS ownership graph alive until all exits are known."""
    if cleanup_errors or not _restart_remote_exit_confirmed(remote_shutdown):
        _RETAINED_RESTART_OWNERS.append(tuple(resources))
        return True
    return False


def _trusted_probe_cleanup_state(probe):
    """Report the real terminal Generate-auth failure and released context owner."""
    authorization = probe.authorization
    context_released = (
        probe._closed is True
        and id(probe.context) not in probe.context_factory._context_index)
    authorization_terminal = authorization._failed is True and authorization._finished is False
    return authorization_terminal, context_released


def _require_owner_probe_cleanup(probes, command_state):
    """Mark uncertain post-close predicates so outer cleanup retains the authority."""
    for probe in probes:
        try:
            auth_closed, context_released = _trusted_probe_cleanup_state(probe)
        except BaseException:
            command_state["direct_cleanup_unconfirmed"] = True
            raise
        if not auth_closed or not context_released:
            command_state["direct_cleanup_unconfirmed"] = True
            raise CohortError("owner Generate authorization/context was not truly released")


def _retain_cancellation_owners(owner, pipeline_state, authority, expectation, result):
    if len(_RETAINED_CANCELLATION_OWNERS) >= 1:
        raise CohortError("cancellation retained-owner registry capacity exceeded")
    _RETAINED_CANCELLATION_OWNERS.append(
        (owner, pipeline_state, authority, expectation, result))


def _partial_retained_shutdown_record(pipeline_state, result, cleanup_errors):
    """Describe only the exact partial-Open request graph retained through OS exit."""
    allowed_components = {
        "coordinator_close", "coordinator_service_streams", "secure_generate_streams",
    }
    binding = pipeline_state.get("partial_admission_owner_binding")
    extension = result.get("partial_admission")
    if (type(binding) is not dict or type(extension) is not dict
            or extension.get("profile") != PROFILE_C1B_PARTIAL
            or extension.get("status") != "passed"):
        return None
    coordinator = binding.get("coordinator")
    captured_state = binding.get("request_state")
    session_id = binding.get("session_id")
    if (coordinator is None or captured_state is None
            or type(session_id) is not str
            or extension.get("session_id") != session_id
            or pipeline_state.get("coordinator") is not coordinator
            or coordinator._requests.get(session_id) is not captured_state
            or captured_state.unknown_opens != {2} or captured_state.leases
            or captured_state.restart_required is not True
            or captured_state.completion.done() is not True):
        return None
    stats = coordinator.stats()
    if (type(stats) is not dict or type(stats.get("ready")) is not bool
            or stats.get("ready") is not False
            or type(stats.get("active_requests")) is not int
            or stats["active_requests"] != 1):
        return None

    service = pipeline_state.get("service")
    secure_service = pipeline_state.get("secure_service")
    capture_budget = pipeline_state.get("capture_budget")
    transport_budget = pipeline_state.get("transport_budget")
    worker_nodes = pipeline_state.get("worker_nodes")
    if (service is None or secure_service is None or capture_budget is None
            or transport_budget is None or type(worker_nodes) is not list
            or len(worker_nodes) != 2
            or getattr(service, "coordinator", None) is not coordinator
            or getattr(secure_service, "service", None) is not service
            or getattr(secure_service, "capture_budget", None) is not capture_budget):
        return None
    active_streams = service.active_streams
    raw_cleanup_tasks = service.cleanups
    if type(raw_cleanup_tasks) is not set:
        return None
    cleanup_tasks = len(raw_cleanup_tasks)
    active_generate_streams = secure_service.active_generate_streams
    if (type(active_streams) is not int or not 0 <= active_streams <= 1
            or type(cleanup_tasks) is not int or not 0 <= cleanup_tasks <= 1
            or type(active_generate_streams) is not int
            or not 0 <= active_generate_streams <= 1):
        return None
    retained_slot = binding.get("secure_slot")
    retained_slots = getattr(secure_service, "_unreclaimed_generate_slots", None)
    handle = retained_slot.get("handle") if type(retained_slot) is dict else None
    try:
        from steamboat_runtime.coordinator import RequestHandle
    except ImportError:
        return None
    if (type(retained_slots) is not list or len(retained_slots) != 1
            or retained_slots[0] is not retained_slot
            or type(handle) is not RequestHandle or handle._owner is not coordinator
            or handle._state is not captured_state
            or retained_slot.get("trusted_context") is not binding.get("trusted_context")
            or binding.get("trusted_context") is not captured_state.trusted_request_context
            or retained_slot.get("retained") is not True
            or retained_slot.get("resource_cleanup_required") is not True
            or retained_slot.get("resource_cleanup_confirmed") is not False
            or retained_slot.get("service") is not (active_streams == 1)
            or retained_slot.get("generate") is not (active_generate_streams == 1)):
        return None
    slot_cleanup_task = retained_slot.get("cleanup_task")
    if cleanup_tasks:
        actual_cleanup_tasks = tuple(raw_cleanup_tasks)
        if (cleanup_tasks != 1 or actual_cleanup_tasks[0] is not slot_cleanup_task
                or binding.get("secure_cleanup_task") is not slot_cleanup_task):
            return None
    elif (slot_cleanup_task is not None
          and (binding.get("secure_cleanup_task") is not slot_cleanup_task
               or not slot_cleanup_task.done())):
        return None

    task_roots = set()
    for name in ("cleanup_task", "context_release_task", "capture_cleanup_task",
                 "pending_cleanup_monitor_task", "authorization_owner_task"):
        task = retained_slot.get(name)
        if task is not None:
            task_roots.add(task)
    optional_task_sets = {"pending_cleanup_roots", "pending_cleanup_discovery_tasks"}
    for name in ("admission_cleanup_tasks", "admission_pending_tasks",
                 "pending_cleanup_tasks", "pending_cleanup_roots",
                 "pending_cleanup_discovery_tasks", "producer_wrapper_tasks"):
        if name in optional_task_sets and name not in retained_slot:
            continue
        tasks = retained_slot.get(name)
        if type(tasks) is not set:
            return None
        task_roots.update(tasks)
    try:
        from steamboat_runtime.protocol.secure_transport import _pending_task_descendants
    except ImportError:
        return None
    allowed_tasks = task_roots | set(_pending_task_descendants(task_roots))
    secure_pending = getattr(secure_service, "pending_tasks", None)
    runtime_owner = getattr(secure_service, "runtime_owner", None)
    runtime_pending = getattr(runtime_owner, "pending_tasks", None)
    unconfirmed_capacity_owners = getattr(
        secure_service, "_unconfirmed_capacity_rejection_authorizations", None)
    if (type(secure_pending) is not set or not secure_pending <= allowed_tasks
            or type(runtime_pending) is not set or not runtime_pending <= allowed_tasks
            or type(unconfirmed_capacity_owners) is not dict
            or unconfirmed_capacity_owners):
        return None
    # Keep the exact task graph strongly referenced with the retained request
    # binding until the owning process is confirmed exited.
    binding["secure_task_graph"] = tuple(allowed_tasks)

    worker_sessions = 0
    bridge_owned_sessions = 0
    bridge_active_authorizations = 0
    bridge_pending_notices = 0
    for node in worker_nodes:
        handler = node.get("handler")
        bridge = node.get("bridge")
        if handler is None or bridge is None:
            return None
        if (handler.sessions or handler._queue or handler._active_operation is not None
                or any(entry.in_flight or entry.queued or entry.committed_bytes != 0
                       or entry.cache.allocated_bytes() != 0
                       or any(entry.cache.lengths())
                       for entry in handler.tombstones.values())):
            return None
        bridge_status = bridge.status()
        if (type(bridge_status) is not dict
                or bridge_status.get("cleanup_confirmed") is not True
                or bridge_status.get("owned_sessions") != 0
                or bridge_status.get("active_authorizations") != 0
                or bridge_status.get("pending_notices") != 0):
            return None
        worker_sessions += len(handler.sessions)
        bridge_owned_sessions += bridge_status["owned_sessions"]
        bridge_active_authorizations += bridge_status["active_authorizations"]
        bridge_pending_notices += bridge_status["pending_notices"]

    capture = capture_budget.status()
    reserved_connections = transport_budget.reserved_connections
    reserved_pending = transport_budget.reserved_pending
    reserved_outbound_pending = transport_budget.reserved_outbound_pending
    reserved_listener_pending = transport_budget.reserved_listener_pending_capacity
    owner_counts = {
        "active_requests": stats["active_requests"],
        "active_streams": active_streams,
        "coordinator_cleanup_tasks": cleanup_tasks,
        "active_generate_streams": active_generate_streams,
        "worker_sessions": worker_sessions,
        "worker_active_compute": False,
        "bridge_owned_sessions": bridge_owned_sessions,
        "bridge_active_authorizations": bridge_active_authorizations,
        "bridge_pending_notices": bridge_pending_notices,
        "active_captures": capture.active_captures,
        "cleanup_pending_captures": capture.cleanup_pending_captures,
        "capture_reserved_bytes": capture.reserved_bytes,
        "transport_reserved_connections": reserved_connections,
        "transport_reserved_pending": reserved_pending,
        "transport_reserved_outbound_pending": reserved_outbound_pending,
        "transport_reserved_listener_pending": reserved_listener_pending,
    }
    if (any(type(owner_counts[key]) is not int or owner_counts[key] != 0 for key in (
            "worker_sessions", "bridge_owned_sessions", "bridge_active_authorizations",
            "bridge_pending_notices", "active_captures", "cleanup_pending_captures",
            "capture_reserved_bytes", "transport_reserved_connections",
            "transport_reserved_pending", "transport_reserved_outbound_pending",
            "transport_reserved_listener_pending"))):
        return None

    actual_components = set()
    if owner_counts["active_requests"] == 1:
        actual_components.add("coordinator_close")
    if active_streams or cleanup_tasks:
        actual_components.add("coordinator_service_streams")
    if active_generate_streams:
        actual_components.add("secure_generate_streams")
    tags = []
    for error in cleanup_errors:
        component = getattr(error, "cleanup_component", None)
        if (type(error) is not CohortError or component not in allowed_components
                or component in tags):
            return None
        tags.append(component)
    if set(tags) != actual_components or not tags:
        return None
    return {
        "confirmed": False,
        "failure_types": [type(error).__name__[:80] for error in cleanup_errors],
        "restart_fenced_retained": True,
        "retained_components": sorted(tags),
        "owner_counts": owner_counts,
    }
_BASELINE_OBSERVATIONS = tuple(
    (sequence, case_id, True)
    for sequence, (case_id, _prompt_length) in enumerate(_EXPECTED_STAGE_CASES, start=1)
)
_C1B_HAPPY_EXTRA_OBSERVATIONS = (
    (5, "unequal-concurrent-prompt-5", True),
    (6, "unequal-concurrent-prompt-11", True),
    (7, "context-boundary-1151-plus-1", True),
)
_C1B_INTERLEAVE_OBSERVATIONS = ((5, "ordered-step-interleave", True),)
_C1B_CANCEL_OBSERVATIONS = (
    (5, "cancel-held-worker3-session", True),
    (6, "cancel-worker3-reclaimed", True),
)
_C1B_PARTIAL_OBSERVATIONS = (
    (5, "partial-open-reply-held", True),
    (6, "partial-open-lease-expired", True),
)
_C1B_STEP_LOSS_OBSERVATIONS = (
    (5, "step-reply-loss-held", True),
    (6, "step-reply-loss-reclaimed", True),
)
_C1B_CAPACITY_OBSERVATIONS = (
    (5, "capacity-eight-held", True),
    (6, "capacity-eight-reclaimed", True),
)
_PROFILE_LOCAL_CASES = {
    PROFILE_BASELINE: (),
    PROFILE_C1B_HAPPY: ("context-over-boundary-1152-plus-1-local-preflight",),
    PROFILE_C1B_INTERLEAVE: (),
    PROFILE_C1B_CANCEL: (),
    PROFILE_C1B_PARTIAL: (),
    PROFILE_C1B_STEP_LOSS: (),
    PROFILE_C1B_CAPACITY: (),
    PROFILE_C1B_RESTART: (),
}
_PROFILE_OBSERVATIONS = {
    PROFILE_BASELINE: _BASELINE_OBSERVATIONS,
    PROFILE_C1B_HAPPY: _BASELINE_OBSERVATIONS + _C1B_HAPPY_EXTRA_OBSERVATIONS,
    PROFILE_C1B_INTERLEAVE: _BASELINE_OBSERVATIONS + _C1B_INTERLEAVE_OBSERVATIONS,
    PROFILE_C1B_CANCEL: _BASELINE_OBSERVATIONS + _C1B_CANCEL_OBSERVATIONS,
    PROFILE_C1B_PARTIAL: _BASELINE_OBSERVATIONS + _C1B_PARTIAL_OBSERVATIONS,
    PROFILE_C1B_STEP_LOSS: _BASELINE_OBSERVATIONS + _C1B_STEP_LOSS_OBSERVATIONS,
    PROFILE_C1B_CAPACITY: _BASELINE_OBSERVATIONS + _C1B_CAPACITY_OBSERVATIONS,
    PROFILE_C1B_RESTART: (
        _BASELINE_OBSERVATIONS
        + ((5, "restart-old-session-held", True),
           (6, "restart-new-boot-stale-binding-rejected", True))
        + tuple((sequence + 6, f"restart-new-{case_id}", True)
                for sequence, case_id, _requires_session in _BASELINE_OBSERVATIONS)
    ),
    PROFILE_C1B_OWNER_DRAIN: (
        _BASELINE_OBSERVATIONS
        + ((5, "owner-drain-held", True),
           (6, "owner-drain-controls", True),
           (7, "owner-drain-paused", True))
    ),
    PROFILE_C1B_OWNER_REMOVE: (
        _BASELINE_OBSERVATIONS
        + ((5, "owner-remove-held", True),
           (6, "owner-remove-revoked", True),
           (7, "owner-remove-final", True))
    ),
}
_C1B_EXTENSION_RESULT_FIELDS = frozenset((
    "profile", "status", "completed_requests", "numerical_errors",
    "request_ids", "session_ids", "remote_overlap_observed",
    "preflight_rejection",
))
_C1B_PREFLIGHT_RESULT_FIELDS = frozenset((
    "case_id", "request_id", "session_id", "accepted", "error_code",
    "tensor_allocations", "coordinator_submits", "remote_worker_contacted",
    "local_owner_check", "evidence_scope",
))
_LOCAL_OWNER_CHECK_FIELDS = frozenset((
    "confirmed", "active_requests", "active_streams", "active_generate_streams",
    "active_captures", "capture_reserved_bytes", "worker_sessions",
    "worker_active_compute", "transport_reserved_connections",
    "transport_reserved_pending",
))
_INTERLEAVE_RESULT_FIELDS = frozenset((
    "profile", "status", "completed_requests", "prompt_lengths",
    "captured_vectors", "comparison_errors", "max_absolute_error",
    "request_ids", "session_ids", "step_trace", "causal_barrier_confirmed",
    "local_owner_check", "remote_owner_check_confirmed",
))
MAX_OBSERVATION_SEQUENCE = max(
    sequence for observations in _PROFILE_OBSERVATIONS.values()
    for sequence, _case_id, _requires_session in observations)


class CohortError(RuntimeError):
    """A fail-closed cohort setup, handoff, validation, or cleanup error."""

    def __init__(self, message, *, cleanup_component=None):
        super().__init__(message)
        if cleanup_component is not None:
            self.cleanup_component = cleanup_component


@dataclass(frozen=True)
class RemoteExpectation:
    run_id: str
    nonce: str
    worker_name: str
    account_id: str
    device_id: str
    boot_id: str
    assignment_id: str
    model_id: str
    model_revision: str
    manifest_fingerprint: str
    snapshot_sha256: str
    endpoint: str
    clock_uncertainty_seconds: float
    layer_range: tuple[int, int]


def _pairs_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CohortError("control JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise CohortError("control JSON contains a non-finite value")


def decode_control_json(raw: bytes) -> dict:
    """Decode bounded strict JSON, rejecting duplicate keys and constants."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_CONTROL_BYTES:
        raise CohortError("control JSON is empty or exceeds its fixed byte bound")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except CohortError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise CohortError("control file is not strict UTF-8 JSON") from None
    if type(value) is not dict:
        raise CohortError("control JSON root must be an object")
    return value


def _json_bytes(value: dict, *, maximum: int = MAX_CONTROL_BYTES) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise CohortError("control value cannot be encoded as bounded JSON") from None
    if not 1 <= len(raw) <= maximum:
        raise CohortError("control JSON exceeds its fixed byte bound")
    return raw


def _exact_fields(value, required, *, optional=(), label="object"):
    if type(value) is not dict:
        raise CohortError(f"{label} must be a JSON object")
    allowed = set(required) | set(optional)
    if not set(required) <= set(value) or not set(value) <= allowed:
        raise CohortError(f"{label} has unknown or missing fields")


def _require_string(value, *, label, pattern=None, max_length=256):
    if (type(value) is not str or not value or len(value) > max_length
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)):
        raise CohortError(f"{label} is not a bounded printable string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise CohortError(f"{label} has an invalid identity encoding")
    return value


def _require_int(value, *, label, minimum=0, maximum=(1 << 63) - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise CohortError(f"{label} must be a bounded integer")
    return value


def _require_bool(value, *, label):
    if type(value) is not bool:
        raise CohortError(f"{label} must be a boolean")
    return value


def _validate_c1b_extension_summary(value):
    """Validate the closed local result object consumed by the C1b supervisor."""
    _exact_fields(value, _C1B_EXTENSION_RESULT_FIELDS, label="C1b extension summary")
    profile = _require_string(value["profile"], label="extension profile", max_length=32)
    status = _require_string(value["status"], label="extension status", max_length=16)
    if profile != PROFILE_C1B_HAPPY or status != "passed":
        raise CohortError("C1b extension summary has an unexpected profile or status")
    if _require_int(value["completed_requests"], label="completed extension requests",
                    minimum=0, maximum=3) != 3:
        raise CohortError("C1b extension summary must account for three requests")

    errors = value["numerical_errors"]
    if type(errors) is not list or len(errors) != 9:
        raise CohortError("C1b numerical_errors must contain nine flat vector errors")
    for error in errors:
        if (type(error) not in (int, float) or error < 0.0 or error > 1e-3
                or not math.isfinite(error)):
            raise CohortError("C1b numerical_errors contains an invalid comparison")

    request_ids = value["request_ids"]
    session_ids = value["session_ids"]
    if type(request_ids) is not list or len(request_ids) != 3:
        raise CohortError("C1b extension request IDs are incomplete")
    if type(session_ids) is not list or len(session_ids) != 3:
        raise CohortError("C1b extension session IDs are incomplete")
    for request_id in request_ids:
        _require_string(request_id, label="extension request ID", pattern=_TYPED_REQUEST,
                        max_length=36)
    for session_id in session_ids:
        _require_string(session_id, label="extension session ID", pattern=_TYPED_SESSION,
                        max_length=36)
    if len(set(request_ids)) != 3 or len(set(session_ids)) != 3:
        raise CohortError("C1b extension IDs must be unique")
    if _require_bool(value["remote_overlap_observed"],
                     label="remote overlap observed"):
        raise CohortError("idle remote status cannot establish overlapping compute")

    preflight = value["preflight_rejection"]
    _exact_fields(preflight, _C1B_PREFLIGHT_RESULT_FIELDS,
                  label="C1b preflight rejection")
    case_id = _require_string(preflight["case_id"], label="preflight case ID",
                              max_length=80)
    error_code = _require_string(preflight["error_code"], label="preflight error code",
                                 max_length=32)
    if case_id != _PROFILE_LOCAL_CASES[PROFILE_C1B_HAPPY][0]:
        raise CohortError("C1b preflight case ID is not the fixed local case")
    _require_string(preflight["request_id"], label="preflight request ID",
                    pattern=_TYPED_REQUEST, max_length=36)
    if (preflight["session_id"] is not None
            or _require_bool(preflight["accepted"], label="preflight accepted")
            or error_code != "INVALID_INPUT"
            or _require_int(preflight["tensor_allocations"], label="preflight tensor allocations") != 0
            or _require_int(preflight["coordinator_submits"], label="preflight coordinator submits") != 0
            or _require_bool(preflight["remote_worker_contacted"],
                             label="preflight remote worker contacted")):
        raise CohortError("C1b over-boundary preflight result is inconsistent")
    evidence_scope = _require_string(preflight["evidence_scope"],
                                     label="preflight evidence scope", max_length=128)
    if evidence_scope != (
            "public client preflight only; no worker RPC or remote compute claim"):
        raise CohortError("C1b preflight evidence scope is not the fixed local scope")

    owner = preflight["local_owner_check"]
    _exact_fields(owner, _LOCAL_OWNER_CHECK_FIELDS, label="preflight local owner check")
    if _require_bool(owner["confirmed"], label="preflight cleanup confirmed") is not True:
        raise CohortError("C1b preflight did not confirm local cleanup")
    for field in (
            "active_requests", "active_streams", "active_generate_streams",
            "active_captures", "capture_reserved_bytes", "worker_sessions",
            "transport_reserved_pending"):
        if _require_int(owner[field], label=f"preflight {field}") != 0:
            raise CohortError("C1b preflight left local owner state")
    if _require_bool(owner["worker_active_compute"],
                     label="preflight worker active compute"):
        raise CohortError("C1b preflight left worker compute active")
    if _require_int(owner["transport_reserved_connections"],
                    label="preflight reserved connections") != 15:
        raise CohortError("C1b preflight changed the fixed transport reservations")
    return value


def _validate_interleave_summary(value):
    _exact_fields(value, _INTERLEAVE_RESULT_FIELDS, label="interleave extension")
    if (type(value["profile"]) is not str or value["profile"] != PROFILE_C1B_INTERLEAVE
            or type(value["status"]) is not str or value["status"] != "passed"
            or _require_int(value["completed_requests"], label="interleave requests",
                            minimum=2, maximum=2) != 2
            or type(value["prompt_lengths"]) is not list
            or len(value["prompt_lengths"]) != 2
            or any(type(item) is not int for item in value["prompt_lengths"])
            or value["prompt_lengths"] != [5, 11]
            or _require_int(value["captured_vectors"], label="interleave vectors",
                            minimum=8, maximum=8) != 8):
        raise CohortError("interleave extension identity or accounting is invalid")
    errors = value["comparison_errors"]
    if (type(errors) is not list or len(errors) != 8
            or any(type(error) not in (int, float) or not math.isfinite(error)
                   or not 0 <= error <= 1e-3 for error in errors)
            or type(value["max_absolute_error"]) not in (int, float)
            or not math.isfinite(value["max_absolute_error"])
            or value["max_absolute_error"] != max(errors)):
        raise CohortError("interleave numerical comparison summary is invalid")
    requests, sessions = value["request_ids"], value["session_ids"]
    if (type(requests) is not list or len(requests) != 2
            or any(type(item) is not str or _TYPED_REQUEST.fullmatch(item) is None
                   for item in requests) or len(set(requests)) != 2
            or type(sessions) is not list or len(sessions) != 2
            or any(type(item) is not str or _TYPED_SESSION.fullmatch(item) is None
                   for item in sessions) or len(set(sessions)) != 2):
        raise CohortError("interleave request/session identities are invalid")
    if (value["step_trace"] != ["A0", "B0", "A1", "B1"]
            or _require_bool(value["causal_barrier_confirmed"],
                             label="interleave causal barrier") is not True
            or _require_bool(value["remote_owner_check_confirmed"],
                             label="interleave remote owner check") is not True):
        raise CohortError("interleave causal or remote proof is incomplete")
    owner = value["local_owner_check"]
    _exact_fields(owner, _LOCAL_OWNER_CHECK_FIELDS, label="interleave local owner check")
    if (_require_bool(owner["confirmed"], label="interleave local cleanup") is not True
            or any(_require_int(owner[field], label=f"interleave {field}") != 0
                   for field in ("active_requests", "active_streams", "active_generate_streams",
                                 "active_captures", "capture_reserved_bytes", "worker_sessions",
                                 "transport_reserved_pending"))
            or _require_bool(owner["worker_active_compute"],
                             label="interleave active compute")
            or _require_int(owner["transport_reserved_connections"],
                            label="interleave reserved connections") != 15):
        raise CohortError("interleave local owner cleanup is incomplete")
    return value


def _validate_ip_port(external_ip, external_port):
    if type(external_ip) is not str:
        raise CohortError("external IP must be a canonical numeric IPv4 literal")
    try:
        parsed = ipaddress.IPv4Address(external_ip)
    except ipaddress.AddressValueError:
        raise CohortError("external IP must be a canonical numeric IPv4 literal") from None
    private_networks = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if (str(parsed) != external_ip
            or not any(parsed in network for network in private_networks)
            or parsed.is_loopback or parsed.is_unspecified
            or parsed.is_multicast or parsed.is_reserved):
        raise CohortError("external IP must be a canonical private non-loopback IPv4 literal")
    if type(external_port) is not int or external_port != REMOTE_PORT:
        raise CohortError("external port must equal the fixed v1 port")
    return external_ip, external_port


def validate_cli_values(args) -> None:
    """Validate pure CLI policy before any fixture or secret allocation."""
    _validate_ip_port(args.external_ip, args.external_port)
    profile = getattr(args, "profile", PROFILE_BASELINE)
    if type(profile) is not str or profile not in _PROFILE_OBSERVATIONS:
        raise CohortError("profile must select one of the fixed cohort profiles")
    uncertainty = args.clock_uncertainty_seconds
    if (type(uncertainty) not in (int, float) or not math.isfinite(uncertainty)
            or not 0 < uncertainty <= 30):
        raise CohortError(
            "clock uncertainty must be explicitly supplied, finite, positive, and <=30 seconds")
    for name in ("artifacts", "reference", "handoff_directory"):
        value = getattr(args, name, None)
        if type(value) is not str or not value or "\x00" in value:
            raise CohortError(f"{name} must be an explicit path")
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts:
            raise CohortError(f"{name} must be an absolute path without parent traversal")
    handoff_path = Path(args.handoff_directory)
    if handoff_path == Path(handoff_path.anchor):
        raise CohortError("handoff directory cannot be a filesystem root")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True,
                        help="absolute path to the pinned read-only component artifacts")
    parser.add_argument("--reference", required=True,
                        help="absolute path to the pinned offline complete-model snapshot")
    parser.add_argument("--external-ip", required=True)
    parser.add_argument("--external-port", required=True, type=int)
    parser.add_argument("--clock-uncertainty-seconds", required=True, type=float,
                        help="measured positive uncertainty from the parent hardware inventory")
    parser.add_argument("--handoff-directory", required=True,
                        help="absolute pre-created private mode-0700 control directory")
    parser.add_argument("--profile", choices=tuple(_PROFILE_OBSERVATIONS),
                        default=PROFILE_BASELINE,
                        help="fixed case profile; baseline-v1 preserves the original four-case run")
    return parser


def _open_directory_chain(path: Path, *, expected_uid: int, final_mode: int) -> int:
    """Open an absolute directory without following any path component links."""
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "geteuid"):
        raise CohortError("secure cohort handoff requires POSIX no-follow file support")
    if not path.is_absolute() or ".." in path.parts:
        raise CohortError("protected directory path must be absolute and traversal-free")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        info = os.fstat(descriptor)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                or stat.S_IMODE(info.st_mode) != final_mode):
            raise CohortError("protected directory owner or mode is invalid")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def validate_handoff_directory(path: str | os.PathLike) -> int:
    """Return an open descriptor for an existing empty private handoff root."""
    directory = Path(path)
    if not directory.is_absolute():
        raise CohortError("handoff directory must be absolute")
    descriptor = _open_directory_chain(
        directory, expected_uid=os.geteuid(), final_mode=0o700)
    try:
        if os.listdir(descriptor):
            raise CohortError("handoff directory must be empty to exclude stale acknowledgements")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise CohortError("short write while publishing a protected file")
        view = view[written:]


def _atomic_create_at(directory_fd: int, name: str, raw: bytes, *, mode=0o600) -> None:
    if (type(name) is not str or not name or name in {".", ".."}
            or "/" in name or "\\" in name or "\x00" in name):
        raise CohortError("protected filename is outside the fixed basename scope")
    if not 1 <= len(raw) <= MAX_CONTROL_BYTES:
        raise CohortError("protected file content exceeds its fixed size bound")
    temporary = f".tmp-{secrets.token_hex(16)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = None
    try:
        fd = os.open(temporary, flags, mode, dir_fd=directory_fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != mode):
            raise CohortError("new protected file failed owner/mode validation")
        _write_all(fd, raw)
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.link(temporary, name, src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd, follow_symlinks=False)
        os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _read_control_at(directory_fd: int, name: str) -> dict:
    allowed = {
        HANDOFF_READY_ACK_FILE, HANDOFF_STOP_ACK_FILE,
        RESTART_STOP_ACK_FILE, RESTART_READY_ACK_FILE,
        *OWNER_ACTION_RESPONSE_FILES,
        *(f"observation-response-{sequence}.json"
          for sequence in range(1, MAX_OBSERVATION_SEQUENCE + 1)),
    }
    if name not in allowed:
        raise CohortError("control filename is outside the fixed acknowledgement allowlist")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        raise
    except OSError:
        raise CohortError("acknowledgement file could not be opened without following links") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or not 1 <= info.st_size <= MAX_CONTROL_BYTES):
            raise CohortError("acknowledgement file owner, mode, type, or size is invalid")
        chunks = []
        remaining = MAX_CONTROL_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != info.st_size or len(raw) > MAX_CONTROL_BYTES:
            raise CohortError("acknowledgement changed or exceeded its read bound")
        return decode_control_json(raw)
    finally:
        os.close(fd)


async def _wait_for_control(directory_fd: int, filename: str, *, timeout: float) -> dict:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        try:
            return _read_control_at(directory_fd, filename)
        except FileNotFoundError:
            if asyncio.get_running_loop().time() >= deadline:
                raise CohortError(f"timed out waiting for required {filename}") from None
            await asyncio.sleep(0.1)


def _validate_worker_status(status: dict, expected: RemoteExpectation, *, event: str,
                            expected_session_id: str | None = None,
                            expected_open_only: bool = False,
                            expected_session_ids: list[str] | None = None) -> dict:
    _exact_fields(status, _WORKER_STATUS_FIELDS, label="protected worker status")
    if status["schema_version"] != 1 or type(status["schema_version"]) is not int:
        raise CohortError("remote worker status has an unsupported schema")
    identity = {
        "event": event,
        "phase": "ready",
        "worker_name": expected.worker_name,
        "account_id": expected.account_id,
        "device_id": expected.device_id,
        "boot_id": expected.boot_id,
        "assignment_id": expected.assignment_id,
        "model_id": expected.model_id,
        "model_revision": expected.model_revision,
        "manifest_fingerprint": expected.manifest_fingerprint,
        "listen_endpoint": expected.endpoint,
        "layer_range": list(expected.layer_range),
        "clock_uncertainty_seconds": expected.clock_uncertainty_seconds,
        "resource_state": "observed",
        "report_state": "confirmed",
    }
    for key, value in identity.items():
        if type(status.get(key)) is not type(value) or status.get(key) != value:
            raise CohortError(f"remote worker status identity/state mismatch: {key}")
    _require_int(status["torch_threads"], label="worker torch thread count", minimum=1, maximum=24)
    if status["torch_threads"] != 2:
        raise CohortError("remote worker must use the assigned two CPU threads")

    bridge = status["bridge"]
    _exact_fields(bridge, _BRIDGE_STATUS_FIELDS, label="worker bridge status")
    if bridge.get("state") != "observed":
        raise CohortError("remote worker bridge status is not an observed runtime state")
    for key in ("ready", "cleanup_confirmed"):
        if _require_bool(bridge.get(key), label=f"bridge.{key}") is not True:
            raise CohortError("remote worker bridge is not confirmed ready and clean")
    for key in ("unavailable", "requires_restart", "fault_present"):
        if _require_bool(bridge.get(key), label=f"bridge.{key}") is not False:
            raise CohortError("remote worker bridge is unavailable or faulted")
    for key in ("active_authorizations", "owned_sessions", "pending_notices"):
        expected_count = (len(expected_session_ids) if expected_session_ids is not None
                          and key == "owned_sessions" else
                          (1 if expected_session_id is not None and key == "owned_sessions"
                           else 0))
        if _require_int(bridge.get(key), label=f"bridge.{key}") != expected_count:
            raise CohortError("remote worker bridge still owns authorization/session state")

    handler = status["handler"]
    _exact_fields(handler, _HANDLER_STATUS_FIELDS, label="worker handler status")
    if handler.get("state") != "observed":
        raise CohortError("remote worker handler status is not an observed runtime state")
    active_session_ids = handler.get("active_session_ids")
    if (type(active_session_ids) is not list or len(active_session_ids) > 8
            or any(type(item) is not str or _TYPED_SESSION.fullmatch(item) is None
                   for item in active_session_ids)
            or active_session_ids != sorted(set(active_session_ids))
            or _require_int(handler.get("active_sessions"), label="handler.active_sessions")
               != len(active_session_ids)):
        raise CohortError("remote worker active session identities are malformed")
    if expected_session_ids is not None:
        if (expected_session_id is None or type(expected_session_ids) is not list
                or len(expected_session_ids) != 8
                or any(type(item) is not str or _TYPED_SESSION.fullmatch(item) is None
                       for item in expected_session_ids)
                or expected_session_ids != sorted(set(expected_session_ids))):
            raise CohortError("expected capacity session identities are malformed")
        _require_string(expected_session_id, label="capacity anchor session",
                        pattern=_TYPED_SESSION, max_length=36)
        if expected_session_id not in expected_session_ids or active_session_ids != expected_session_ids:
            raise CohortError("remote worker does not hold the exact eight-session cohort")
        for key in ("committed_cache_bytes", "allocated_cache_bytes"):
            if _require_int(handler.get(key), label=f"handler.{key}") != 0:
                raise CohortError("held capacity sessions unexpectedly own cache before Step")
    elif expected_session_id is None:
        if active_session_ids:
            raise CohortError("remote worker retains an unrequested session")
        for key in ("committed_cache_bytes", "allocated_cache_bytes"):
            if _require_int(handler.get(key), label=f"handler.{key}") != 0:
                raise CohortError("remote worker still owns cache bytes")
    else:
        _require_string(expected_session_id, label="expected active session",
                        pattern=_TYPED_SESSION, max_length=36)
        if active_session_ids != [expected_session_id]:
            raise CohortError("remote worker does not hold the exact acknowledged session")
        if type(expected_open_only) is not bool:
            raise CohortError("remote held-session mode is malformed")
        for key in ("committed_cache_bytes", "allocated_cache_bytes"):
            minimum = 0 if expected_open_only else 1
            amount = _require_int(handler.get(key), label=f"handler.{key}", minimum=minimum)
            if expected_open_only and amount != 0:
                raise CohortError("Open-only remote reservation unexpectedly owns cache")
    if _require_int(handler.get("queued_operations"), label="handler.queued_operations") != 0:
        raise CohortError("remote worker still has queued work")
    for key in ("active_compute", "requires_restart", "stopping"):
        if _require_bool(handler.get(key), label=f"handler.{key}") is not False:
            raise CohortError("remote worker handler is active, stopping, or restart-fenced")
    if _require_bool(handler.get("cache_bytes_exact"), label="handler.cache_bytes_exact") is not True:
        raise CohortError("remote worker cache byte count is not exact")
    if handler.get("committed_cache_bytes_lower_bound") is not None:
        raise CohortError("remote worker reports an ambiguous cache byte lower bound")
    limits = handler.get("limits")
    _exact_fields(limits, _HANDLER_LIMIT_FIELDS, label="worker handler limits")
    for key in _HANDLER_LIMIT_FIELDS:
        _require_int(limits.get(key), label=f"handler.limits.{key}", minimum=1)
    if (limits["max_sessions"] != 8 or limits["max_positions"] != 1152
            or limits["max_cache_positions"] != 12_288
            or limits["max_cache_bytes"] != 16_777_216
            or limits["max_message_bytes"] != 1_048_576):
        raise CohortError("remote worker limits differ from the frozen v1 runtime")

    transport = status["transport"]
    _exact_fields(transport, _TRANSPORT_STATUS_FIELDS, label="worker transport status")
    expected_transport = {
        "listener_slots": 1,
        "max_connections": 16,
        "max_pending": 4,
        "reserved_connections": 1,
        "reserved_pending": 0,
        "reserved_listener_pending_capacity": 1,
        "reserved_outbound_pending": 0,
        "server_state": "running",
    }
    for key, value in expected_transport.items():
        if type(transport.get(key)) is not type(value) or transport.get(key) != value:
            raise CohortError(f"remote worker transport reservation mismatch: {key}")

    external = status["external_supervision"]
    _exact_fields(external, {"startup_watchdog_seconds", "termination_watchdog_seconds",
                             "resource_caps", "verified_by_worker"},
                  label="external supervisor declaration")
    if (external.get("startup_watchdog_seconds") != 60
            or external.get("termination_watchdog_seconds") != 15
            or external.get("resource_caps") != "configured_by_external_supervisor"
            or external.get("verified_by_worker") is not False):
        raise CohortError("remote worker supervision declaration is inconsistent")
    if type(external.get("verified_by_worker")) is not bool:
        raise CohortError("remote worker supervision verification flag is malformed")
    if status["shutdown"] != {"state": "not_started"}:
        raise CohortError("remote worker is not in its active serving lifecycle")
    return {
        "confirmed": True,
        "worker_boot_id": expected.boot_id,
        "active_sessions": handler["active_sessions"],
        "active_session_ids": list(active_session_ids),
        "queued_operations": 0,
        "active_compute": False,
        "cache_bytes_exact": True,
        "committed_cache_bytes": handler["committed_cache_bytes"],
        "allocated_cache_bytes": handler["allocated_cache_bytes"],
        "active_authorizations": 0,
        "owned_sessions": bridge["owned_sessions"],
        "transport_reserved_connections": 1,
    }


def validate_ready_ack(payload: dict, expected: RemoteExpectation) -> str:
    _exact_fields(payload, HANDOFF_READY_ACK_FIELDS, label="ready acknowledgement")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise CohortError("ready acknowledgement schema is unsupported")
    match = {
        "event": "ready_ack", "run_id": expected.run_id, "nonce": expected.nonce,
        "boot_id": expected.boot_id,
        "manifest_fingerprint": expected.manifest_fingerprint,
        "snapshot_sha256": expected.snapshot_sha256, "endpoint": expected.endpoint,
        "remote_status_uid": REMOTE_STATUS_UID,
        "remote_status_mode": REMOTE_STATUS_MODE,
        "measurement_label": READY_LABEL,
    }
    for key, value in match.items():
        if type(payload.get(key)) is not type(value) or payload.get(key) != value:
            raise CohortError(f"ready acknowledgement mismatch: {key}")
    _require_int(payload["remote_status_mtime_ns"], label="ready status mtime", minimum=1)
    host_key = _require_string(payload["ssh_host_key_sha256"],
                               label="SSH host-key SHA-256", pattern=_HEX64, max_length=64)
    remote_status = payload["remote_status"]
    if (type(remote_status) is not dict
            or type(remote_status.get("event")) is not str
            or remote_status["event"] not in {"ready", "heartbeat"}):
        raise CohortError("ready acknowledgement lacks a genuine ready/heartbeat status")
    _validate_worker_status(remote_status, expected, event=remote_status["event"])
    return host_key


def _profile_observation(profile: str, sequence: int):
    if type(profile) is not str or type(sequence) is not int:
        raise CohortError("observation profile and sequence must be exact types")
    observations = _PROFILE_OBSERVATIONS.get(profile)
    if observations is None:
        raise CohortError("observation profile is not allowlisted")
    for allowed_sequence, case_id, requires_session in observations:
        if sequence == allowed_sequence:
            return case_id, requires_session
    raise CohortError("observation sequence is outside the selected fixed profile")


def build_observation_request(expected: RemoteExpectation, *, sequence: int,
                              case_id: str, request_id: str,
                              session_id: str | None,
                              profile: str = PROFILE_BASELINE) -> dict:
    _require_int(sequence, label="observation sequence", minimum=1,
                 maximum=MAX_OBSERVATION_SEQUENCE)
    _require_string(case_id, label="observation case ID", max_length=64)
    expected_case, requires_session = _profile_observation(profile, sequence)
    if case_id != expected_case:
        raise CohortError("observation case does not match its fixed profile sequence")
    _require_string(request_id, label="request ID", pattern=_TYPED_REQUEST, max_length=36)
    if requires_session:
        _require_string(session_id, label="session ID", pattern=_TYPED_SESSION,
                        max_length=36)
    elif session_id is not None:
        raise CohortError("pre-admission observation must not claim a session ID")
    request = {
        "schema_version": 1, "event": "observe", "run_id": expected.run_id,
        "nonce": expected.nonce, "expected_boot_id": expected.boot_id,
        "sequence": sequence, "case_id": case_id, "request_id": request_id,
        "session_id": session_id,
    }
    if set(request) != HANDOFF_OBSERVATION_REQUEST_FIELDS:
        raise CohortError("observation request differs from the frozen handoff schema")
    return request


def validate_observation_ack(payload: dict, expected: RemoteExpectation, *,
                             sequence: int, case_id: str, request_id: str,
                             session_id: str | None, expected_host_key: str,
                             profile: str = PROFILE_BASELINE,
                             expected_session_ids: list[str] | None = None) -> dict:
    _exact_fields(payload, HANDOFF_OBSERVATION_ACK_FIELDS,
                  label="observation acknowledgement")
    _require_int(sequence, label="observation sequence", minimum=1,
                 maximum=MAX_OBSERVATION_SEQUENCE)
    expected_case, requires_session = _profile_observation(profile, sequence)
    if case_id != expected_case:
        raise CohortError("observation acknowledgement case differs from its profile")
    if requires_session:
        _require_string(session_id, label="session ID", pattern=_TYPED_SESSION,
                        max_length=36)
    elif session_id is not None:
        raise CohortError("pre-admission observation cannot claim a session ID")
    expected_values = {
        "schema_version": 1, "event": "observation_ack", "run_id": expected.run_id,
        "nonce": expected.nonce, "sequence": sequence, "case_id": case_id,
        "request_id": request_id, "session_id": session_id,
        "boot_id": expected.boot_id,
        "manifest_fingerprint": expected.manifest_fingerprint,
        "endpoint": expected.endpoint, "ssh_host_key_sha256": expected_host_key,
        "remote_status_uid": REMOTE_STATUS_UID,
        "remote_status_mode": REMOTE_STATUS_MODE,
        "measurement_label": OBSERVATION_LABEL,
    }
    for key, value in expected_values.items():
        if type(payload.get(key)) is not type(value) or payload.get(key) != value:
            raise CohortError(f"observation acknowledgement mismatch: {key}")
    remote_mark = _require_int(payload["remote_mark_ns"], label="remote observation mark", minimum=1)
    _require_int(payload["supervisor_monotonic_ns"],
                 label="supervisor monotonic observation time", minimum=1)
    heartbeat_mtime = _require_int(payload["heartbeat_mtime_ns"],
                                   label="remote heartbeat mtime", minimum=1)
    if heartbeat_mtime <= remote_mark:
        raise CohortError("remote heartbeat does not follow the same-host observation mark")
    expected_active = (session_id if profile in (
        PROFILE_C1B_CANCEL, PROFILE_C1B_PARTIAL, PROFILE_C1B_STEP_LOSS,
        PROFILE_C1B_CAPACITY, PROFILE_C1B_RESTART)
                       and sequence == 5
                       else None)
    owner_check = _validate_worker_status(
        payload["remote_status"], expected, event="heartbeat",
        expected_session_id=expected_active,
        expected_session_ids=expected_session_ids,
        expected_open_only=(profile == PROFILE_C1B_PARTIAL and sequence == 5))
    owner_check.update({
        "sequence": sequence,
        "case_id": case_id,
        "request_id": request_id,
        "session_id": session_id,
        "remote_mark_ns": remote_mark,
        "supervisor_monotonic_ns": payload["supervisor_monotonic_ns"],
        "heartbeat_mtime_ns": heartbeat_mtime,
        "measurement_label": OBSERVATION_LABEL,
    })
    return owner_check


def build_stop_request(*, run_id: str, nonce: str, boot_id: str | None,
                       may_have_started: bool) -> dict:
    _require_string(run_id, label="run ID", pattern=_HEX32, max_length=32)
    _require_string(nonce, label="handoff nonce", pattern=_HEX32, max_length=32)
    if boot_id is not None:
        _require_string(boot_id, label="expected worker boot ID", pattern=_HEX32,
                        max_length=32)
    _require_bool(may_have_started, label="may_have_started")
    if may_have_started != (boot_id is not None):
        raise CohortError("stop request boot identity and launch state disagree")
    request = {
        "schema_version": 1, "event": "stop", "run_id": run_id,
        "nonce": nonce, "expected_boot_id": boot_id,
        "may_have_started": may_have_started, "maximum_wait_seconds": 15,
    }
    if set(request) != HANDOFF_STOP_REQUEST_FIELDS:
        raise CohortError("stop request differs from the frozen handoff schema")
    return request


def _validate_final_worker_status(status: dict, expected: RemoteExpectation) -> None:
    _exact_fields(status, _WORKER_STATUS_FIELDS, optional={"startup_error_type"},
                  label="final protected worker status")
    if type(status.get("schema_version")) is not int or status["schema_version"] != 1:
        raise CohortError("final remote worker status has an unsupported schema")
    phase = status.get("phase")
    if (status.get("event") != "final" or type(phase) is not str
            or phase not in {"stopped", "startup_failed"}):
        raise CohortError("final remote worker status has an invalid lifecycle phase")
    identity = {
        "worker_name": expected.worker_name,
        "account_id": expected.account_id,
        "device_id": expected.device_id,
        "boot_id": expected.boot_id,
        "assignment_id": expected.assignment_id,
        "model_id": expected.model_id,
        "model_revision": expected.model_revision,
        "manifest_fingerprint": expected.manifest_fingerprint,
        "listen_endpoint": expected.endpoint,
        "clock_uncertainty_seconds": expected.clock_uncertainty_seconds,
        "report_state": "confirmed",
        "resource_state": "observed",
    }
    for key, value in identity.items():
        if type(status.get(key)) is not type(value) or status.get(key) != value:
            raise CohortError(f"final remote worker status identity mismatch: {key}")
    if phase == "stopped":
        if "startup_error_type" in status:
            raise CohortError("normally stopped worker reports a startup failure")
    else:
        _require_string(status.get("startup_error_type"),
                        label="startup failure type", max_length=80)

    shutdown = status.get("shutdown")
    _exact_fields(shutdown, {"server", "bridge", "handler", "overall"},
                  label="final shutdown evidence")
    allowed_shutdown = {"confirmed", "not_started"}
    if any(type(value) is not str or value not in allowed_shutdown
           for value in shutdown.values()):
        raise CohortError("final shutdown evidence contains an unknown owner")
    if shutdown["overall"] != "confirmed":
        raise CohortError("final shutdown was not confirmed")
    if phase == "stopped" and shutdown["handler"] != "confirmed":
        raise CohortError("normal worker stop did not confirm handler cleanup")

    handler = status.get("handler")
    if handler == {"state": "not_started"}:
        if phase != "startup_failed" or shutdown["handler"] != "not_started":
            raise CohortError("unstarted handler is inconsistent with final lifecycle")
        if status.get("layer_range") is not None:
            raise CohortError("unstarted handler unexpectedly reports a layer range")
        if type(status.get("torch_threads")) is not int or status["torch_threads"] not in (0, 2):
            raise CohortError("unstarted handler has an invalid thread observation")
    else:
        _exact_fields(handler, _HANDLER_STATUS_FIELDS,
                      label="final protected worker handler status")
        if shutdown["handler"] != "confirmed":
            raise CohortError("observed handler lacks confirmed shutdown")
        if handler.get("state") != "observed":
            raise CohortError("final handler resource state is unknown")
        if _require_int(handler.get("active_sessions"), label="final handler.active_sessions") != 0:
            raise CohortError("final worker handler retains live sessions")
        if handler.get("active_session_ids") != []:
            raise CohortError("final worker handler retains an active session identity")
        tombstones = _require_int(handler.get("tombstones"), label="final handler.tombstones")
        retained_entries = _require_int(
            handler.get("retained_entries"), label="final handler.retained_entries")
        for key in ("queued_operations", "committed_cache_bytes", "allocated_cache_bytes"):
            if _require_int(handler.get(key), label=f"final handler.{key}") != 0:
                raise CohortError("final worker handler retains live work or cache bytes")
        if handler.get("active_compute") is not False or handler.get("cache_bytes_exact") is not True:
            raise CohortError("final worker handler compute/cache state is not exact and idle")
        if handler.get("committed_cache_bytes_lower_bound") is not None:
            raise CohortError("final worker handler reports ambiguous cache ownership")
        for key in ("requires_restart", "stopping"):
            _require_bool(handler.get(key), label=f"final handler.{key}")
        limits = handler.get("limits")
        _exact_fields(limits, _HANDLER_LIMIT_FIELDS,
                      label="final protected worker handler limits")
        for key in _HANDLER_LIMIT_FIELDS:
            _require_int(limits.get(key), label=f"final handler.limits.{key}", minimum=1)
        if (tombstones > limits["max_tombstones"]
                or retained_entries != tombstones):
            raise CohortError("final worker terminal records exceed or contradict the tombstone bound")
        if (limits["max_sessions"] != 8 or limits["max_positions"] != 1152
                or limits["max_cache_positions"] != 12_288
                or limits["max_cache_bytes"] != 16_777_216
                or limits["max_message_bytes"] != 1_048_576):
            raise CohortError("final worker limits differ from the frozen v1 runtime")
        if status.get("layer_range") != list(expected.layer_range):
            raise CohortError("final worker layer range differs from the assignment")
        if type(status.get("torch_threads")) is not int or status["torch_threads"] != 2:
            raise CohortError("final worker thread count differs from the CPU assignment")

    bridge = status.get("bridge")
    if bridge == {"state": "not_started"}:
        if phase != "startup_failed" or shutdown["bridge"] != "not_started":
            raise CohortError("unstarted bridge is inconsistent with final lifecycle")
    else:
        _exact_fields(bridge, _BRIDGE_STATUS_FIELDS,
                      label="final protected worker bridge status")
        if bridge.get("state") != "observed":
            raise CohortError("final bridge cleanup state is unknown")
        if _require_bool(bridge.get("cleanup_confirmed"),
                         label="final bridge.cleanup_confirmed") is not True:
            raise CohortError("final bridge cleanup is unconfirmed")
        for key in ("active_authorizations", "owned_sessions", "pending_notices"):
            if _require_int(bridge.get(key), label=f"final bridge.{key}") != 0:
                raise CohortError("final bridge retains authorization or session owners")
        for key in ("ready", "unavailable", "requires_restart", "fault_present"):
            _require_bool(bridge.get(key), label=f"final bridge.{key}")

    transport = status.get("transport")
    if transport == {"state": "not_started"}:
        if phase != "startup_failed" or shutdown["server"] != "not_started":
            raise CohortError("unstarted listener is inconsistent with final lifecycle")
    else:
        _exact_fields(transport, _TRANSPORT_STATUS_FIELDS,
                      label="final protected worker transport status")
        if (type(transport.get("server_state")) is not str
                or transport["server_state"] not in {"stopped", "not_started"}):
            raise CohortError("final worker listener is not stopped")
        if transport.get("server_state") == "not_started" and shutdown["server"] != "not_started":
            raise CohortError("listener status contradicts shutdown evidence")
        if transport.get("server_state") == "stopped" and shutdown["server"] != "confirmed":
            raise CohortError("stopped listener lacks shutdown confirmation")
        for key in ("listener_slots", "max_connections", "max_pending"):
            _require_int(transport.get(key), label=f"final transport.{key}", minimum=1)
        for key in ("reserved_connections", "reserved_pending",
                    "reserved_listener_pending_capacity", "reserved_outbound_pending"):
            if _require_int(transport.get(key), label=f"final transport.{key}") != 0:
                raise CohortError("final worker listener retains connection reservations")
        if (transport["listener_slots"] != 1 or transport["max_connections"] != 16
                or transport["max_pending"] != 4):
            raise CohortError("final worker transport limits differ from the fixed v1 assignment")

    threads = status.get("torch_threads")
    if type(threads) is not int or threads not in (0, 2):
        raise CohortError("final worker thread observation is malformed")
    external = status.get("external_supervision")
    _exact_fields(external, {"startup_watchdog_seconds", "termination_watchdog_seconds",
                             "resource_caps", "verified_by_worker"},
                  label="final external supervisor declaration")
    if (external.get("startup_watchdog_seconds") != 60
            or external.get("termination_watchdog_seconds") != 15
            or external.get("resource_caps") != "configured_by_external_supervisor"
            or external.get("verified_by_worker") is not False):
        raise CohortError("final external supervisor declaration is inconsistent")


def validate_stop_ack(payload: dict, *, run_id: str, nonce: str,
                      expected_boot_id: str | None, may_have_started: bool,
                      readiness_observed: bool,
                      expected_host_key: str | None,
                      expected: RemoteExpectation | None = None) -> dict:
    _exact_fields(payload, HANDOFF_STOP_ACK_FIELDS, label="stop acknowledgement")
    _require_string(run_id, label="run ID", pattern=_HEX32, max_length=32)
    _require_string(nonce, label="handoff nonce", pattern=_HEX32, max_length=32)
    _require_bool(may_have_started, label="may_have_started")
    _require_bool(readiness_observed, label="readiness_observed")
    if expected_boot_id is not None:
        _require_string(expected_boot_id, label="expected worker boot ID",
                        pattern=_HEX32, max_length=32)
    if may_have_started != (expected_boot_id is not None):
        raise CohortError("stop acknowledgement boot identity and launch state disagree")
    if may_have_started and expected is None:
        raise CohortError("stop acknowledgement lacks the published worker expectation")
    if readiness_observed and not may_have_started:
        raise CohortError("observed readiness lacks a possible worker launch")
    if expected is not None and (
            expected.run_id != run_id or expected.nonce != nonce
            or expected.boot_id != expected_boot_id):
        raise CohortError("stop acknowledgement expectation differs from the run")
    expected_values = {
        "schema_version": 1, "event": "stop_ack", "run_id": run_id,
        "nonce": nonce, "boot_id": expected_boot_id,
        "shutdown_confirmed": True,
    }
    for key, value in expected_values.items():
        if type(payload.get(key)) is not type(value) or payload.get(key) != value:
            raise CohortError(f"stop acknowledgement mismatch: {key}")
    host_key = _require_string(payload["ssh_host_key_sha256"],
                               label="SSH host-key SHA-256", pattern=_HEX64, max_length=64)
    if expected_host_key is not None and host_key != expected_host_key:
        raise CohortError("stop acknowledgement SSH host key changed during the cohort")
    process_state = payload["process_state"]
    if type(process_state) is not str:
        raise CohortError("stop acknowledgement process state is malformed")
    if process_state == "not_started":
        if (readiness_observed
                or payload["exit_code"] is not None
                or payload["remote_status_uid"] is not None
                or payload["remote_status_mode"] is not None
                or payload["remote_status"] is not None
                or payload["measurement_label"] != "ssh_supervisor_not_started"):
            raise CohortError("not-started acknowledgement contains inconsistent exit evidence")
        return {"confirmed": True, "process_state": "not_started"}
    if process_state != "exited" or not may_have_started or expected_boot_id is None:
        raise CohortError("stop acknowledgement has no actual exit observation")
    _require_int(payload["exit_code"], label="remote worker exit code", maximum=255)
    if (_require_int(payload["remote_status_uid"], label="final status UID")
            != REMOTE_STATUS_UID
            or _require_int(payload["remote_status_mode"], label="final status mode")
            != REMOTE_STATUS_MODE
            or payload["measurement_label"] != STOP_LABEL):
        raise CohortError("final remote status provenance is invalid")
    status = payload["remote_status"]
    if type(status) is not dict:
        raise CohortError("final remote status is missing")
    _validate_final_worker_status(status, expected)
    return {
        "confirmed": True,
        "process_state": "exited",
        "exit_code": payload["exit_code"],
        "shutdown_overall": "confirmed",
        "worker_boot_id": expected_boot_id,
    }


def _validate_manifest_fingerprint(value):
    return _require_string(value, label="manifest fingerprint", pattern=_HEX64,
                           max_length=64)


def build_worker_config_payload(*, principal, manifest: dict, artifact_directory: str,
                                clock_uncertainty_seconds: float,
                                external_ip: str, external_port: int) -> dict:
    """Build only the fixed worker-3 config; never serialize authority keys."""
    _validate_ip_port(external_ip, external_port)
    if getattr(principal, "name", None) != "worker-3":
        raise CohortError("only the fixed worker-3 principal can be exported")
    if getattr(principal, "role", None) != "host":
        raise CohortError("worker-3 principal must have the C0 host role")
    for field, pattern in (("account_id", _TYPED_ACCOUNT),
                           ("device_id", _TYPED_DEVICE),
                           ("boot_id", _HEX32),
                           ("assignment_id", _TYPED_ASSIGNMENT)):
        _require_string(getattr(principal, field, None), label=f"worker-3 {field}",
                        pattern=pattern, max_length=37)
    if (type(clock_uncertainty_seconds) not in (int, float)
            or not math.isfinite(clock_uncertainty_seconds)
            or not 0 < clock_uncertainty_seconds <= 30):
        raise CohortError("worker-3 uncertainty must be explicit, finite, positive and <=30")
    if type(manifest) is not dict:
        raise CohortError("verified pinned manifest is required")
    from steamboat_runtime.manifest import MODEL_ID, MODEL_REVISION

    if manifest.get("model_id") != MODEL_ID or manifest.get("revision") != MODEL_REVISION:
        raise CohortError("only the C0 pinned tiny-model revision is supported")
    fingerprint = _validate_manifest_fingerprint(manifest.get("fingerprint"))
    if type(artifact_directory) is not str:
        raise CohortError("remote artifact mount path must be an absolute string")
    artifact_path = Path(artifact_directory)
    if (not artifact_path.is_absolute()
            or ".." in artifact_path.parts or "\x00" in artifact_directory):
        raise CohortError("remote artifact mount path must be absolute and traversal-free")
    return {
        "schema_version": 1,
        "protected_root": REMOTE_ROOT,
        "account_id": principal.account_id,
        "device_id": principal.device_id,
        "boot_id": principal.boot_id,
        "assignment_id": principal.assignment_id,
        "worker_name": "worker-3",
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "manifest_fingerprint": fingerprint,
        "listen_ip": external_ip,
        "listen_port": external_port,
        "clock_uncertainty_seconds": float(clock_uncertainty_seconds),
        "certificate_path": f"{REMOTE_ROOT}/host.crt",
        "private_key_path": f"{REMOTE_ROOT}/host.key",
        "cohort_ca_path": f"{REMOTE_ROOT}/cohort-ca.crt",
        "snapshot_verification_key_path": f"{REMOTE_ROOT}/snapshot.pub",
        "signed_snapshot_path": f"{REMOTE_ROOT}/snapshot.json",
        "artifact_directory": str(artifact_path),
        "acceptor_directory": f"{REMOTE_ROOT}/sockets",
        "status_report_path": f"{REMOTE_ROOT}/status.json",
    }


def _make_remote_expectation(*, run_id: str, nonce: str, principal, manifest: dict,
                             snapshot_sha256: str, uncertainty: float,
                             external_ip: str, external_port: int) -> RemoteExpectation:
    _validate_ip_port(external_ip, external_port)
    endpoint = f"{external_ip}:{external_port}"
    layer_range = manifest.get("components", {}).get("worker-3", {}).get("layer_range")
    if (type(layer_range) is not list or len(layer_range) != 2
            or any(type(value) is not int for value in layer_range)
            or layer_range != [6, 8]):
        raise CohortError("pinned worker-3 component range is not [6,8)")
    from steamboat_runtime.manifest import MODEL_ID, MODEL_REVISION

    return RemoteExpectation(
        run_id=run_id, nonce=nonce, worker_name="worker-3",
        account_id=principal.account_id, device_id=principal.device_id,
        boot_id=principal.boot_id, assignment_id=principal.assignment_id,
        model_id=MODEL_ID, model_revision=MODEL_REVISION,
        manifest_fingerprint=manifest["fingerprint"], snapshot_sha256=snapshot_sha256,
        endpoint=endpoint, clock_uncertainty_seconds=float(uncertainty),
        layer_range=tuple(layer_range),
    )


def _private_bundle_root(authority_root: Path) -> tuple[Path, int, int]:
    root_fd = _open_directory_chain(
        authority_root, expected_uid=os.geteuid(), final_mode=0o700)
    bundle_fd = None
    sockets_fd = None
    handed_off = False
    bundle_name = "worker-3-bundle"
    try:
        os.mkdir(bundle_name, mode=0o700, dir_fd=root_fd)
        bundle_fd = os.open(
            bundle_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0), dir_fd=root_fd)
        info = os.fstat(bundle_fd)
        if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
                or not stat.S_ISDIR(info.st_mode)):
            raise CohortError("worker bundle root failed owner/mode validation")
        os.mkdir("sockets", mode=0o700, dir_fd=bundle_fd)
        sockets_fd = os.open(
            "sockets", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0), dir_fd=bundle_fd)
        socket_info = os.fstat(sockets_fd)
        if (socket_info.st_uid != os.geteuid()
                or stat.S_IMODE(socket_info.st_mode) != 0o700
                or not stat.S_ISDIR(socket_info.st_mode)):
            raise CohortError("worker socket directory failed owner/mode validation")
        handed_off = True
        return authority_root / bundle_name, root_fd, bundle_fd
    finally:
        if sockets_fd is not None:
            os.close(sockets_fd)
        if not handed_off:
            if bundle_fd is not None:
                os.close(bundle_fd)
            os.close(root_fd)


def _write_bundle_file(bundle_fd: int, name: str, value: bytes, *, maximum: int) -> None:
    allowed = {
        "worker.json", "host.crt", "host.key", "cohort-ca.crt",
        "snapshot.pub", "snapshot.json",
    }
    if name not in allowed or type(value) is not bytes or not 1 <= len(value) <= maximum:
        raise CohortError("worker bundle file is outside the fixed name/size allowlist")
    fd = None
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(name, flags, 0o600, dir_fd=bundle_fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise CohortError("worker bundle file failed owner/mode validation")
        _write_all(fd, value)
        os.fsync(fd)
    finally:
        if fd is not None:
            os.close(fd)


def provision_worker3_bundle(*, authority, manifest: dict, artifact_directory: str,
                             uncertainty: float, external_ip: str,
                             external_port: int, run_id: str, nonce: str,
                             worker_config_out: dict | None = None):
    """Write exactly the remote worker's allowed leaf/public policy bundle."""
    principal = authority.principals.get("worker-3")
    if principal is None:
        raise CohortError("C0 authority has no worker-3 principal")
    if tuple(authority.ip_sans_by_principal.get("worker-3", ())) != (external_ip,):
        raise CohortError("worker-3 certificate was not issued for only the configured external IP")
    config = build_worker_config_payload(
        principal=principal, manifest=manifest, artifact_directory=artifact_directory,
        clock_uncertainty_seconds=uncertainty,
        external_ip=external_ip, external_port=external_port)
    config_raw = _json_bytes(config, maximum=MAX_CONFIG_BYTES)
    config_fields = set(config)
    if config_fields != _WORKER_CONFIG_FIELDS:
        raise CohortError("worker config differs from the installed closed schema")
    if worker_config_out is not None:
        if type(worker_config_out) is not dict or worker_config_out:
            raise CohortError("worker config output holder must be an empty exact dictionary")
        worker_config_out["worker_config"] = config
    snapshot = authority.signed_snapshot
    if type(snapshot) is not bytes or not 1 <= len(snapshot) <= MAX_SNAPSHOT_BYTES:
        raise CohortError("signed snapshot exceeds the worker bundle bound")
    snapshot_hash = hashlib.sha256(snapshot).hexdigest()
    bundle_path, root_fd, bundle_fd = _private_bundle_root(Path(authority.root))
    try:
        _write_bundle_file(bundle_fd, "worker.json", config_raw, maximum=MAX_CONFIG_BYTES)
        _write_bundle_file(bundle_fd, "host.crt", principal.certificate_pem,
                           maximum=MAX_CERTIFICATE_BYTES)
        _write_bundle_file(bundle_fd, "host.key", principal.private_key_pem,
                           maximum=MAX_PRIVATE_KEY_BYTES)
        _write_bundle_file(bundle_fd, "cohort-ca.crt", authority.cohort_ca_pem,
                           maximum=MAX_CERTIFICATE_BYTES)
        _write_bundle_file(bundle_fd, "snapshot.pub", authority.snapshot_verification_key_pem,
                           maximum=MAX_CERTIFICATE_BYTES)
        _write_bundle_file(bundle_fd, "snapshot.json", snapshot,
                           maximum=MAX_SNAPSHOT_BYTES)
        os.fsync(bundle_fd)
    finally:
        os.close(bundle_fd)
        os.close(root_fd)
    for name in ("host.crt", "host.key", "cohort-ca.crt", "snapshot.pub", "snapshot.json", "worker.json"):
        info = (bundle_path / name).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise CohortError("worker bundle file changed owner/mode after provisioning")
    expectation = _make_remote_expectation(
        run_id=run_id, nonce=nonce, principal=principal, manifest=manifest,
        snapshot_sha256=snapshot_hash, uncertainty=uncertainty,
        external_ip=external_ip, external_port=external_port)
    ready = {
        "schema_version": 1, "event": "bundle_ready", "run_id": run_id,
        "nonce": nonce, "bundle_path": str(bundle_path),
        "expected_boot_id": principal.boot_id,
        "manifest_fingerprint": manifest["fingerprint"],
        "snapshot_sha256": snapshot_hash, "endpoint": expectation.endpoint,
        "worker_name": "worker-3",
    }
    if set(ready) != HANDOFF_BUNDLE_READY_FIELDS:
        raise CohortError("bundle-ready record differs from the frozen handoff schema")
    return bundle_path, expectation, ready


def _safe_write_handoff(directory_fd: int, name: str, value: dict) -> None:
    allowed = {HANDOFF_BUNDLE_READY_FILE, HANDOFF_STOP_REQUEST_FILE,
               HANDOFF_RESULT_FILE, HANDOFF_FAILURE_LOCATION_FILE,
               RESTART_STOP_REQUEST_FILE, RESTART_BUNDLE_READY_FILE,
               RESTART_READY_ACK_FILE}
    allowed.update(
        f"observation-request-{sequence}.json"
        for sequence in range(1, MAX_OBSERVATION_SEQUENCE + 1))
    allowed.update((OWNER_MATERIALS_READY_FILE, *OWNER_ACTION_REQUEST_FILES))
    if name not in allowed:
        raise CohortError("handoff filename is outside the fixed request allowlist")
    _atomic_create_at(directory_fd, name, _json_bytes(value))


def _failure_location_record(run_id: str, nonce: str,
                             error: BaseException) -> dict:
    """Build a small traceback-location record without serializing error data."""
    _require_string(run_id, label="failure run ID", pattern=_HEX32, max_length=32)
    _require_string(nonce, label="failure nonce", pattern=_HEX32, max_length=32)
    if not isinstance(error, BaseException):
        raise CohortError("failure location requires the caught exception")
    failure_type = type(error).__name__
    if (type(failure_type) is not str
            or _FAILURE_TYPE_NAME.fullmatch(failure_type) is None):
        raise CohortError("failure location exception type is not an ASCII class name")

    try:
        error_code = getattr(error, "code", None)
    except BaseException:
        error_code = None
    if callable(error_code) or type(error_code) is not str:
        error_code = None
    elif error_code not in _FAILURE_ERROR_CODES:
        error_code = "UNRECOGNIZED_ERROR_CODE"

    frames = []
    tb = error.__traceback__
    walked = 0
    while tb is not None and walked < MAX_FAILURE_TRACEBACK_FRAMES:
        walked += 1
        code = tb.tb_frame.f_code
        filename = code.co_filename
        function = code.co_name
        line = tb.tb_lineno
        if type(filename) is str and type(function) is str and type(line) is int:
            basename = filename.replace("\\", "/").rsplit("/", 1)[-1]
            if (basename not in {".", ".."}
                    and _FAILURE_FRAME_FILE.fullmatch(basename) is not None
                    and _FAILURE_FRAME_FUNCTION.fullmatch(function) is not None
                    and 1 <= line <= 1_000_000):
                frames.append({"file": basename, "function": function, "line": line})
        tb = tb.tb_next

    record = {
        "schema_version": 2,
        "event": "cohort_failure_location",
        "run_id": run_id,
        "nonce": nonce,
        "failure_type": failure_type,
        "error_code": error_code,
        "frames": frames[-MAX_FAILURE_LOCATION_FRAMES:],
    }
    _json_bytes(record, maximum=MAX_FAILURE_LOCATION_BYTES)
    return record


async def _wait_for_ready(directory_fd: int, expected: RemoteExpectation) -> str:
    ack = await _wait_for_control(
        directory_fd, HANDOFF_READY_ACK_FILE, timeout=READY_TIMEOUT_SECONDS)
    return validate_ready_ack(ack, expected)


async def _observe_remote(directory_fd: int, expected: RemoteExpectation, *,
                          sequence: int, case_id: str, request_id: str,
                          session_id: str | None, host_key: str,
                          profile: str = PROFILE_BASELINE,
                          expected_session_ids: list[str] | None = None) -> dict:
    request = build_observation_request(
        expected, sequence=sequence, case_id=case_id,
        request_id=request_id, session_id=session_id, profile=profile)
    request_name = f"observation-request-{sequence}.json"
    response_name = f"observation-response-{sequence}.json"
    _safe_write_handoff(directory_fd, request_name, request)
    response = await _wait_for_control(
        directory_fd, response_name,
        timeout=OBSERVATION_TIMEOUT_SECONDS)
    return validate_observation_ack(
        response, expected, sequence=sequence, case_id=case_id,
        request_id=request_id, session_id=session_id, expected_host_key=host_key,
        profile=profile, expected_session_ids=expected_session_ids)


async def _observe_owner_remote(directory_fd, *, expected, owner_expected,
                               worker_config, sequence, request_id, session_id,
                               host_key, commands, terminal_frame=None):
    """Collect one exact owner observation and validate its protected raw frame."""
    case_id, requires_session = _profile_observation(owner_expected.profile, sequence)
    if not requires_session:
        raise CohortError("owner observation must bind the actual probe session")
    request = build_observation_request(
        expected, sequence=sequence, case_id=case_id, request_id=request_id,
        session_id=session_id, profile=owner_expected.profile)
    _safe_write_handoff(directory_fd, f"observation-request-{sequence}.json", request)
    response = await _wait_for_control(
        directory_fd, f"observation-response-{sequence}.json",
        timeout=OBSERVATION_TIMEOUT_SECONDS)
    _exact_fields(response, HANDOFF_OBSERVATION_ACK_FIELDS,
                  label="owner observation acknowledgement")
    values = {
        "schema_version": 1, "event": "observation_ack",
        "run_id": expected.run_id, "nonce": expected.nonce,
        "sequence": sequence, "case_id": case_id, "request_id": request_id,
        "session_id": session_id, "boot_id": expected.boot_id,
        "manifest_fingerprint": expected.manifest_fingerprint,
        "endpoint": expected.endpoint, "ssh_host_key_sha256": host_key,
        "remote_status_uid": REMOTE_STATUS_UID,
        "remote_status_mode": REMOTE_STATUS_MODE,
        "measurement_label": "ssh_protected_owner_status_v1",
    }
    for name, value in values.items():
        if type(response.get(name)) is not type(value) or response.get(name) != value:
            raise CohortError(f"owner observation acknowledgement mismatch: {name}")
    _require_int(response["supervisor_monotonic_ns"],
                 label="owner observation supervisor time", minimum=1)
    mark = _require_int(response["remote_mark_ns"],
                        label="owner observation remote mark", minimum=1)
    heartbeat = _require_int(response["heartbeat_mtime_ns"],
                             label="owner observation heartbeat mtime", minimum=1)
    status = response["remote_status"]
    if (owner_expected.profile == PROFILE_C1B_OWNER_REMOVE and sequence == 7
            and type(terminal_frame) is dict):
        if status != terminal_frame["remote_status"]:
            raise CohortError("final remove observation did not reuse command-2 protected frame")
        if (mark != terminal_frame["remote_mark_ns"]
                or response["heartbeat_mtime_ns"] != terminal_frame["heartbeat_mtime_ns"]
                or response["measurement_label"] != terminal_frame["measurement_label"]
                or response["ssh_host_key_sha256"] != terminal_frame["ssh_host_key_sha256"]
                or response["remote_status_uid"] != terminal_frame["remote_status_uid"]
                or response["remote_status_mode"] != terminal_frame["remote_status_mode"]):
            raise CohortError("final remove observation provenance differs from command 2")
    elif heartbeat <= mark:
        raise CohortError("owner observation heartbeat does not follow its same-host mark")
    _validate_owner_observation_status(
        status, owner_expected=owner_expected, worker_config=worker_config,
        sequence=sequence, commands=commands)
    return response


async def _publish_owner_action_and_read(directory_fd, *, owner_expected,
                                         worker_config, ssh_host_key_sha256,
                                         command_number, command):
    """Publish one fixed owner command and validate its actual paired response."""
    try:
        from lab.secure_cohort_owner import (
            build_owner_action_request, validate_owner_action_request,
            validate_owner_action_response,
        )
    except ModuleNotFoundError as error:
        if error.name != "lab":
            raise
        from secure_cohort_owner import (
            build_owner_action_request, validate_owner_action_request,
            validate_owner_action_response,
        )
    request = build_owner_action_request(owner_expected, command_number, command)
    parsed = validate_owner_action_request(request, owner_expected)
    if parsed.sequence != command_number or parsed.command_id != command["command_id"]:
        raise CohortError("owner request changed after shared command validation")
    request_file = OWNER_ACTION_REQUEST_FILES[command_number - 1]
    response_file = OWNER_ACTION_RESPONSE_FILES[command_number - 1]
    _safe_write_handoff(directory_fd, request_file, request)
    response = await _wait_for_control(
        directory_fd, response_file, timeout=OBSERVATION_TIMEOUT_SECONDS)
    try:
        validate_owner_action_response(
            response, request, owner_expected,
            expected_ssh_host_key_sha256=ssh_host_key_sha256,
            expected_worker_config=worker_config)
    except (ValueError, KeyError, TypeError) as error:
        raise CohortError("owner action response failed the shared validator") from error
    return response


def _expected_server(principal, identity_type, expected_ip: str):
    record = principal.record
    return identity_type(
        account_id=principal.account_id,
        device_id=principal.device_id,
        role=principal.role,
        serial=int(record["serial"], 16),
        public_key_hash=record["public_key_sha256"],
        certificate_hash=record["certificate_sha256"],
        expected_ip=expected_ip,
        ekus=tuple(record["ekus"]),
    )


class _CleanupOwner:
    def __init__(self):
        self._actions = []
        self._retained_actions = []

    def add(self, label, callback):
        self._actions.append((label, callback))

    async def close(self):
        errors = []
        while self._actions:
            label, callback = self._actions.pop()
            try:
                result = callback()
                if asyncio.iscoroutine(result) or hasattr(result, "__await__"):
                    await result
            except BaseException as error:
                try:
                    error.add_note(f"secure cohort cleanup: {label}")
                except (AttributeError, TypeError):
                    pass
                errors.append(error)
                self._retained_actions.append((label, callback))
        return errors


async def _close_worker_client(holder):
    client = holder.get("client")
    if client is None or getattr(client, "_closed", False):
        return
    result = client.close()
    if hasattr(result, "__await__"):
        await result


async def _stop_worker_listener(node):
    server = node.get("server")
    if server is not None and not getattr(server, "_stopped", False):
        await server.stop(0)


async def _stop_worker_bridge(node):
    bridge = node.get("bridge")
    if bridge is not None and bridge._started and not bridge._closed:
        result = await bridge.stop(grace_seconds=5)
        if result is not True:
            raise CohortError("local worker bridge shutdown was not confirmed")


async def _shutdown_worker_handler(node):
    handler = node.get("handler")
    if handler is not None:
        result = await handler.shutdown(grace_seconds=5)
        if result is not True:
            raise CohortError("local worker handler shutdown was not confirmed")


def _release_worker_executor(node):
    node["executor"] = None


def _reference_forced_last_positions(reference, torch, prompt_ids, *, forced_steps=8):
    vocabulary_size = 32_000
    if type(forced_steps) is not int or not 0 <= forced_steps <= 8:
        raise CohortError("forced reference continuation is outside the bounded case set")
    for forced_token in (vocabulary_size - 1, vocabulary_size - 2):
        reference_input = prompt_ids + [forced_token] * forced_steps
        input_tensor = torch.tensor([reference_input], dtype=torch.long)
        with torch.inference_mode():
            output = reference(input_ids=input_tensor, use_cache=False,
                               return_dict=True)
            rows = output.logits[0][len(prompt_ids) - 1:].detach().clone()
            greedy = int(rows[0].argmax().item())
        del output, input_tensor
        if greedy != forced_token:
            if tuple(rows.shape) != (forced_steps + 1, vocabulary_size):
                raise CohortError("complete-model reference returned an unexpected capture shape")
            return forced_token, rows
        del rows
    raise CohortError("reference could not select a forced token distinct from greedy output")


def _reference_last_row(reference, torch, prompt_ids):
    input_tensor = torch.tensor([prompt_ids], dtype=torch.long)
    with torch.inference_mode():
        output = reference(input_ids=input_tensor, use_cache=False, return_dict=True)
        row = output.logits[0, -1].detach().clone()
    del output, input_tensor
    if tuple(row.shape) != (32_000,) or not bool(torch.isfinite(row).all().item()):
        raise CohortError("complete-model boundary reference returned an invalid last row")
    return row


async def _secure_generate(client, outbound, input_ids, *, new_tokens,
                           forced_tokens=None, capture_logits=False,
                           on_token=None):
    from steamboat_security import ConsumerRequestContext

    context = outbound.create_consumer_request_context(lifetime_seconds=120)
    if type(context) is not ConsumerRequestContext:
        raise CohortError("consumer outbound did not issue the actual C0 request context")
    request_id = context.request_id
    _require_string(request_id, label="C0 request ID", pattern=_TYPED_REQUEST, max_length=36)
    stream = None
    primary = None
    cleanup_errors = []
    events = []
    try:
        stream = client.generate(
            input_ids, new_tokens, forced_tokens=forced_tokens,
            trusted_request_context=context, capture_logits=capture_logits,
            timeout_seconds=120)
        async for event in stream:
            if type(event) is not dict:
                raise CohortError("secure Generate emitted a non-object event")
            if event.get("type") == "token" and on_token is not None:
                on_token(event)
            events.append({key: event[key] for key in (
                "type", "session_id", "token_id", "index", "sequence", "position",
                "status", "cleanup_complete", "token_ids") if key in event})
    except BaseException as error:
        primary = error
    finally:
        if stream is not None:
            try:
                await stream.aclose()
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            context.close()
        except BaseException as error:
            cleanup_errors.append(error)
    failures = ([primary] if primary is not None else []) + cleanup_errors
    if failures:
        if len(failures) == 1:
            raise failures[0]
        raise BaseExceptionGroup("secure Generate and request cleanup failed", failures)
    return request_id, events


async def _wait_local_cleanup(*, coordinator, service, secure_service,
                              worker_nodes, capture_budget, transport_budget,
                              expected_connections: int, timeout: float = 10.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        try:
            return _local_owner_snapshot(
                coordinator=coordinator, service=service,
                secure_service=secure_service, worker_nodes=worker_nodes,
                capture_budget=capture_budget, transport_budget=transport_budget,
                expected_connections=expected_connections)
        except CohortError:
            if asyncio.get_running_loop().time() >= deadline:
                raise
            await asyncio.sleep(0.05)


def _local_owner_snapshot(*, coordinator, service, secure_service,
                          worker_nodes, capture_budget, transport_budget,
                          expected_connections: int,
                          expected_active_requests: int = 0):
    stats = coordinator.stats()
    capture = capture_budget.status()
    confirmed = (
        type(stats.get("active_requests")) is int
        and type(expected_active_requests) is int
        and expected_active_requests in (0, 1)
        and stats.get("active_requests") == expected_active_requests
        and service.active_streams == 0
        and not service.cleanups
        and secure_service.active_generate_streams == 0
        and capture.active_captures == 0
        and capture.cleanup_pending_captures == 0
        and capture.reserved_bytes == 0
        and transport_budget.reserved_connections == expected_connections
        and transport_budget.reserved_pending == 0
        and transport_budget.reserved_outbound_pending == 0
    )
    for node in worker_nodes:
        handler = node["handler"]
        bridge_status = node["bridge"].status()
        entries = tuple(handler.sessions.values()) + tuple(handler.tombstones.values())
        confirmed = confirmed and (
            not handler.sessions and not handler._queue
            and handler._active_operation is None
            and not any(entry.in_flight or entry.queued for entry in entries)
            and all(entry.committed_bytes == 0
                    and entry.cache.allocated_bytes() == 0
                    and not any(entry.cache.lengths()) for entry in entries)
            and bridge_status.get("owned_sessions") == 0
            and bridge_status.get("active_authorizations") == 0
            and bridge_status.get("pending_notices") == 0
            and bridge_status.get("cleanup_confirmed") is True
            and bridge_status.get("unavailable") is False
            and bridge_status.get("requires_restart") is False
        )
    if not confirmed:
        raise CohortError("local coordinator/worker/capture owners are not fully reclaimed")
    return {
        "confirmed": True,
        "active_requests": stats["active_requests"],
        "active_streams": 0,
        "active_generate_streams": 0,
        "active_captures": 0,
        "capture_reserved_bytes": 0,
        "worker_sessions": 0,
        "worker_active_compute": False,
        "transport_reserved_connections": expected_connections,
        "transport_reserved_pending": 0,
    }


def _cancellation_dispatch_prefix(events, session_id: str) -> bool:
    """Require the real prompt and first decode Step positions for one session."""
    relevant = [event for event in events
                if type(event) is dict and event.get("event") == "stage_dispatch"
                and event.get("session_id") == session_id]
    expected = [(1, 0, 0, 3), (1, 1, 3, 1),
                (2, 0, 0, 3), (3, 0, 0, 3)]
    actual = []
    for event in relevant:
        values = (event.get("worker"), event.get("sequence"),
                  event.get("position"), event.get("token_count"))
        if any(type(value) is not int for value in values):
            return False
        actual.append(values)
    return len(actual) == len(expected) and sorted(actual) == sorted(expected)


async def _run_real_pipeline(args, *, authority, manifest, expected, external_ip,
                             owner: _CleanupOwner, result: dict,
                             handoff_fd: int, remote_host_key: str,
                             pipeline_state: dict, profile: str = PROFILE_BASELINE,
                             owner_expected=None, worker_config=None,
                             observation_profile: str | None = None,
                             observation_sequence_offset: int = 0,
                             observation_case_prefix: str = ""):
    """Run actual local handlers, secure clients, coordinator and HF reference."""
    import torch
    import gc as gc_module
    from transformers import AutoModelForCausalLM

    from steamboat_runtime.coordinator import Coordinator
    from steamboat_runtime.coordinator_service import (
        CoordinatorService, supervised_model_class,
    )
    from steamboat_runtime.protocol.secure_transport import (
        C0ExpectedServerLeafAdapter, ExpectedServerIdentity, FixedPeer,
        LocalTlsIdentity, NodeConnectionBudget,
        create_secure_coordinator_client, create_secure_worker_client,
        create_secure_worker_server,
    )
    from steamboat_runtime.secure_coordinator_service import (
        create_secure_coordinator_server,
    )
    from steamboat_runtime.protocol.worker_pb2 import Request
    from steamboat_runtime.secure_context import BootstrapWorkerClient, ConsumerContextFactory
    from steamboat_runtime.capture_budget import CaptureBudget, CaptureBudgetConfig
    from steamboat_runtime.secure_worker_runtime import SecureWorkerRuntimeBridge
    from steamboat_runtime.worker_state import StageExecutor, WorkerHandler
    from steamboat_security import (
        AuthorizationWatcher, Authorizer, LocalIdentity, OutboundAuthorizer,
        OutboundTarget, SessionBindings, verify_expected_server_leaf,
    )
    from steamboat_security.codec import WORKER_SERVICE
    from steamboat_runtime.remote_client import SERVICE as COORDINATOR_SERVICE

    torch.set_num_threads(2)
    try:
        torch.set_num_interop_threads(2)
    except RuntimeError:
        if torch.get_num_interop_threads() > 2:
            raise CohortError("Torch interop thread pool exceeds the two-CPU cohort bound")
    if torch.get_num_threads() > 2 or torch.get_num_interop_threads() > 2:
        raise CohortError("Torch thread pools exceed the two-CPU cohort bound")

    fingerprint = manifest["fingerprint"]
    budget = NodeConnectionBudget(max_connections=16, max_pending=4)
    pipeline_state["transport_budget"] = budget
    acceptor_directory = authority.root / LOCAL_COHORT_ACCEPTOR_DIRECTORY_NAME
    os.mkdir(acceptor_directory, 0o700)
    if os.name == "posix" and stat.S_IMODE(acceptor_directory.stat().st_mode) != 0o700:
        raise CohortError("laptop acceptor directory is not mode 0700")
    worker_nodes = []
    pipeline_state["worker_nodes"] = worker_nodes
    worker_clients = []

    for index in (1, 2):
        principal = authority.principals[f"worker-{index}"]
        store, clock = authority.new_store()
        bindings = SessionBindings(clock=clock)
        authorizer = Authorizer(
            local_identity=LocalIdentity(
                principal.certificate_pem, principal.boot_id, fingerprint,
                principal.assignment_id),
            snapshot_store=store, clock=clock,
            session_bindings=bindings, worker_request_type=Request)
        node = {
            "principal": principal, "clock": clock, "store": store,
            "bindings": bindings, "authorizer": authorizer,
            "executor": None, "handler": None, "bridge": None, "server": None,
        }
        worker_nodes.append(node)
        owner.add(f"worker-{index} executor references",
                  lambda node=node: _release_worker_executor(node))
        executor = StageExecutor(args.artifacts, f"worker-{index}")
        node["executor"] = executor
        handler = WorkerHandler(
            manifest, f"worker-{index}", executor,
            boot_id=principal.boot_id, enable_queue=True)
        node["handler"] = handler
        owner.add(f"worker-{index} handler shutdown",
                  lambda node=node: _shutdown_worker_handler(node))
        bridge = SecureWorkerRuntimeBridge(
            authorizer, handler, sweep_interval_seconds=0.5)
        node["bridge"] = bridge
        owner.add(f"worker-{index} bridge stop",
                  lambda node=node: _stop_worker_bridge(node))
        await bridge.start()
        pipeline_state["worker_nodes"] = worker_nodes
        node["server"] = await create_secure_worker_server(
            bridge.handler, listen_endpoint="127.0.0.1:0",
            allowed_listen_addresses=("127.0.0.1",),
            server_identity=LocalTlsIdentity(
                principal.certificate_pem, principal.private_key_pem),
            client_ca_pem=authority.cohort_ca_pem,
            authorizer=bridge.incoming_authorizer,
            authorization_watcher=bridge.authorization_watcher,
            connection_controller=budget,
            listener_id=f"secure-cohort-local-worker-{index}", listener_slots=1,
            acceptor_directory=str(acceptor_directory))
        owner.add(f"worker-{index} listener stop",
                  lambda node=node: _stop_worker_listener(node))

    coordinator_principal = authority.principals["coordinator"]
    coordinator_local = LocalIdentity(
        coordinator_principal.certificate_pem, coordinator_principal.boot_id,
        fingerprint)
    watcher = AuthorizationWatcher(poll_interval_seconds=0.5)
    tls_verifier = C0ExpectedServerLeafAdapter(verify_expected_server_leaf)
    for index, name in enumerate(("worker-1", "worker-2", "worker-3"), start=1):
        principal = authority.principals[name]
        if name == "worker-3":
            endpoint = expected.endpoint
            allowed_addresses = (external_ip,)
            expected_ip = external_ip
        else:
            node = worker_nodes[index - 1]
            endpoint = f"127.0.0.1:{node['server'].port}"
            allowed_addresses = ("127.0.0.1",)
            expected_ip = "127.0.0.1"
        target = OutboundTarget.from_record(
            service=WORKER_SERVICE, record=principal.record,
            boot_id=principal.boot_id, model_id=fingerprint,
            assignment_id=principal.assignment_id)
        store, clock = authority.new_store()
        from steamboat_runtime.participant_context import TrustedRequestContext

        outbound = OutboundAuthorizer(
            local_identity=coordinator_local, snapshot_store=store, clock=clock,
            target=target, worker_request_type=Request,
            trusted_request_context_type=TrustedRequestContext,
            allow_bootstrap_describe=True)
        peer = FixedPeer(
            endpoint=endpoint, allowed_addresses=allowed_addresses,
            device_id=principal.device_id,
            server_leaf_pem=principal.certificate_pem,
            cohort_ca_pem=authority.cohort_ca_pem,
            expected_server=_expected_server(
                principal, ExpectedServerIdentity, expected_ip))
        secure_client = await create_secure_worker_client(
            peer, local_identity=LocalTlsIdentity(
                coordinator_principal.certificate_pem,
                coordinator_principal.private_key_pem),
            outbound_authorizer=outbound, authorization_watcher=watcher,
            verify_expected_server_leaf=tls_verifier,
            connection_controller=budget)
        holder = {"client": secure_client}
        owner.add(f"worker-{index} outbound client", lambda holder=holder: _close_worker_client(holder))
        bootstrap = outbound.create_bootstrap_context(lifetime_seconds=120, max_describes=2)
        wrapped = BootstrapWorkerClient(secure_client, bootstrap)
        holder["client"] = wrapped
        worker_clients.append(wrapped)
        probe = Request(protocol_version=1, manifest_fingerprint=fingerprint,
                        timeout_ms=5_000)
        await wrapped.execute("Describe", probe)

    from steamboat_runtime.prepare import verify_snapshot

    verify_snapshot(args.reference)
    reference = AutoModelForCausalLM.from_pretrained(
        args.reference, dtype=torch.float32, attn_implementation="eager",
        local_files_only=True, use_safetensors=True)
    reference = reference.to("cpu").eval().requires_grad_(False)
    reference_box = {"model": reference}
    owner.add("complete-model reference release", lambda: _release_reference(reference_box))

    model = supervised_model_class().from_artifacts(args.artifacts, args.reference)
    model_holder = {"model": model}
    owner.add("unattached coordinator model close", lambda: _close_model(model_holder))
    coordinator_holder = {"coordinator": None}
    coordinator = Coordinator(manifest, worker_clients, model)
    coordinator_holder = {"coordinator": coordinator}
    model_holder["model"] = None
    owner.add("coordinator close", lambda: _close_coordinator(coordinator_holder))
    await coordinator.start()
    pipeline_state["coordinator"] = coordinator

    coordinator_store, coordinator_clock = authority.new_store()
    coordinator_authorizer = Authorizer(
        local_identity=coordinator_local, snapshot_store=coordinator_store,
        clock=coordinator_clock)
    context_factory = ConsumerContextFactory(
        account_id=coordinator_principal.account_id,
        device_id=coordinator_principal.device_id,
        coordinator_boot_id=coordinator_principal.boot_id, model_id=fingerprint)
    capture_budget = CaptureBudget(CaptureBudgetConfig(
        vocabulary_size=32_000, output_queue_slots=16,
        max_active_captures=8, capacity_bytes=1 << 30))
    service = CoordinatorService(coordinator)
    pipeline_state["service"] = service
    coordinator_server, coordinator_secure_service = await create_secure_coordinator_server(
        service, listen_endpoint="127.0.0.1:0",
        allowed_listen_addresses=("127.0.0.1",),
        server_identity=LocalTlsIdentity(
            coordinator_principal.certificate_pem,
            coordinator_principal.private_key_pem),
        client_ca_pem=authority.cohort_ca_pem,
        authorizer=coordinator_authorizer,
        authorization_watcher=watcher,
        request_context_factory=context_factory,
        connection_controller=budget,
        listener_id="secure-cohort-laptop-coordinator", listener_slots=1,
        acceptor_directory=str(acceptor_directory), capture_budget=capture_budget)
    owner.add("coordinator listener stop", lambda: coordinator_server.stop(0))
    pipeline_state["secure_service"] = coordinator_secure_service
    pipeline_state["capture_budget"] = capture_budget

    consumer_principal = authority.principals["consumer"]
    consumer_store, consumer_clock = authority.new_store()
    consumer_target = OutboundTarget.from_record(
        service=COORDINATOR_SERVICE, record=coordinator_principal.record,
        boot_id=coordinator_principal.boot_id, model_id=fingerprint)
    consumer_outbound = OutboundAuthorizer(
        local_identity=LocalIdentity(
            consumer_principal.certificate_pem, consumer_principal.boot_id, fingerprint),
        snapshot_store=consumer_store, clock=consumer_clock, target=consumer_target)
    consumer_peer = FixedPeer(
        endpoint=f"127.0.0.1:{coordinator_server.port}",
        allowed_addresses=("127.0.0.1",),
        device_id=coordinator_principal.device_id,
        server_leaf_pem=coordinator_principal.certificate_pem,
        cohort_ca_pem=authority.cohort_ca_pem,
        expected_server=_expected_server(
            coordinator_principal, ExpectedServerIdentity, "127.0.0.1"))
    coordinator_client = await create_secure_coordinator_client(
        consumer_peer,
        local_identity=LocalTlsIdentity(
            consumer_principal.certificate_pem, consumer_principal.private_key_pem),
        outbound_authorizer=consumer_outbound,
        authorization_watcher=watcher,
        verify_expected_server_leaf=tls_verifier,
        connection_controller=budget)
    client_holder = {"client": coordinator_client}
    owner.add("consumer coordinator client close", lambda: _close_worker_client(client_holder))
    pipeline_state["transport_budget"] = budget

    if budget.reserved_connections != 15:
        raise CohortError("laptop process must hold exactly 15 of 16 static connection reservations")
    if (budget.reserved_pending != 0 or budget.reserved_outbound_pending != 0
            or budget.reserved_listener_pending_capacity != 3):
        raise CohortError("laptop node connection budget has unexpected pending reservations")

    pipeline_state.update({
        "torch": torch,
        "coordinator": coordinator, "coordinator_client": coordinator_client,
        "consumer_outbound": consumer_outbound, "service": service,
        "secure_service": coordinator_secure_service,
        "worker_nodes": worker_nodes, "capture_budget": capture_budget,
        "transport_budget": budget, "coordinator_server": coordinator_server,
    })

    observation_profile = profile if observation_profile is None else observation_profile
    if (type(observation_sequence_offset) is not int
            or observation_sequence_offset < 0
            or type(observation_case_prefix) is not str):
        raise CohortError("baseline observation projection is malformed")
    request_ids = []
    session_ids = []
    errors = []
    cases = []
    with torch.inference_mode():
        reference_output = reference_box["model"](
            input_ids=torch.tensor([[7, 13, 31]], dtype=torch.long),
            use_cache=False, return_dict=True)
        greedy_token = int(reference_output.logits[0, -1].argmax().item())
    del reference_output
    request_id, events = await _secure_generate(
        coordinator_client, consumer_outbound, [7, 13, 31],
        new_tokens=1, capture_logits=False)
    _check_generated_events(events, request_id, [greedy_token], capture=False)
    session_id = events[0]["session_id"]
    request_ids.append(request_id)
    session_ids.append(session_id)
    result["request_ids"] = list(request_ids)
    result["session_ids"] = list(session_ids)
    local = await _wait_local_cleanup(
        coordinator=coordinator, service=service,
        secure_service=coordinator_secure_service, worker_nodes=worker_nodes,
        capture_budget=capture_budget, transport_budget=budget,
        expected_connections=15)
    if owner_expected is not None:
        remote = await _observe_owner_remote(
            handoff_fd, expected=expected, owner_expected=owner_expected,
            worker_config=worker_config, sequence=1 + observation_sequence_offset,
            request_id=request_id, session_id=session_id,
            host_key=remote_host_key, commands=())
    else:
        remote = await _observe_remote(
            handoff_fd, expected, sequence=1 + observation_sequence_offset,
            case_id=f"{observation_case_prefix}greedy-one-token",
            request_id=request_id, session_id=session_id,
            host_key=remote_host_key, profile=observation_profile)
    cases.append({"case_id": f"{observation_case_prefix}greedy-one-token", "request_id": request_id,
                  "session_id": session_id, "local_owner_check": local,
                  "remote_owner_check": remote})
    result["cases"] = list(cases)
    result["baseline"]["completed_requests"] = 1

    for sequence, prompt_length in enumerate((1, 128, 1024), start=2):
        prompt = [3 + ((index * 37 + 11) % (32_000 - 3))
                  for index in range(prompt_length)]
        forced_token, expected_rows = _reference_forced_last_positions(
            reference_box["model"], torch, prompt)
        if prompt_length + 9 > manifest["limits"]["max_positions"]:
            raise CohortError("frozen prompt/continuation exceeds the pinned context limit")
        comparisons = []

        def compare(event):
            index = len(comparisons)
            if index >= 9 or type(event.get("logits")) is not list:
                raise CohortError("capture event ordering or vector shape is invalid")
            if len(event["logits"]) != 32_000:
                raise CohortError("captured last-position vector has the wrong vocabulary")
            actual = torch.tensor(event["logits"], dtype=torch.float32)
            expected_row = expected_rows[index]
            if not bool(torch.isfinite(actual).all().item()):
                raise CohortError("captured logits contain a non-finite value")
            maximum_error = float(torch.max(torch.abs(actual - expected_row)).item())
            if not bool(torch.allclose(actual, expected_row, atol=1e-3, rtol=0.0)):
                raise CohortError("captured logits differ from the same-stack complete reference")
            token_id = int(expected_row.argmax().item())
            if event.get("token_id") != token_id:
                raise CohortError("captured token feedback differs from the reference argmax")
            comparisons.append({
                "index": event.get("index"), "sequence": event.get("sequence"),
                "position": event.get("position"), "token_id": token_id,
                "max_abs_error": maximum_error,
            })
            del actual

        request_id, events = await _secure_generate(
            coordinator_client, consumer_outbound, prompt,
            new_tokens=9, forced_tokens=[forced_token] * 8,
            capture_logits=True, on_token=compare)
        _check_generated_events(events, request_id,
                                [item["token_id"] for item in comparisons], capture=True,
                                prompt_length=prompt_length, comparisons=comparisons,
                                forced_token=forced_token)
        session_id = events[0]["session_id"]
        request_ids.append(request_id)
        session_ids.append(session_id)
        errors.extend(item["max_abs_error"] for item in comparisons)
        local = await _wait_local_cleanup(
            coordinator=coordinator, service=service,
            secure_service=coordinator_secure_service, worker_nodes=worker_nodes,
            capture_budget=capture_budget, transport_budget=budget,
            expected_connections=15)
        if owner_expected is not None:
            remote = await _observe_owner_remote(
                handoff_fd, expected=expected, owner_expected=owner_expected,
                worker_config=worker_config,
                sequence=sequence + observation_sequence_offset,
                request_id=request_id, session_id=session_id,
                host_key=remote_host_key, commands=())
        else:
            remote = await _observe_remote(
                handoff_fd, expected, sequence=sequence + observation_sequence_offset,
                case_id=f"{observation_case_prefix}forced-length-{prompt_length}",
                request_id=request_id, session_id=session_id, host_key=remote_host_key,
                profile=observation_profile)
        cases.append({"case_id": f"{observation_case_prefix}forced-length-{prompt_length}",
                      "request_id": request_id, "session_id": session_id,
                      "local_owner_check": local, "remote_owner_check": remote})
        result["cases"] = list(cases)
        result["request_ids"] = list(request_ids)
        result["session_ids"] = list(session_ids)
        result["baseline"]["completed_requests"] = sequence
        result["baseline"]["captured_vectors"] = len(errors)
        result["numerical_errors"] = {
            "captured_vectors": len(errors), "values": list(errors),
            "atol": 1e-3, "rtol": 0.0,
        }
        del prompt, expected_rows, events, comparisons
        gc_module.collect()

    if (len(request_ids) != 4 or len(set(request_ids)) != 4
            or len(session_ids) != 4 or len(set(session_ids)) != 4
            or len(errors) != 27):
        raise CohortError("baseline request/session/vector accounting is incomplete")
    if any(_TYPED_REQUEST.fullmatch(value) is None for value in request_ids):
        raise CohortError("baseline request identity is not a typed C0 request ID")
    if any(_TYPED_SESSION.fullmatch(value) is None for value in session_ids):
        raise CohortError("baseline session identity is not a typed C0 session ID")
    result["request_ids"] = request_ids
    result["session_ids"] = session_ids
    result["numerical_errors"] = {
        "captured_vectors": len(errors), "max_absolute_error": max(errors),
        "values": errors, "atol": 1e-3, "rtol": 0.0,
    }
    result["cases"] = cases
    result["baseline"] = {
        "status": "passed", "completed_requests": 4,
        "captured_vectors": 27,
        "lifecycle_extensions": "pending_separate_C1b_gate",
    }
    if profile == PROFILE_C1B_HAPPY:
        await _run_c1b_happy_extensions(
            torch=torch, reference=reference_box["model"], manifest=manifest,
            client=coordinator_client, outbound=consumer_outbound,
            coordinator=coordinator, service=service,
            secure_service=coordinator_secure_service, worker_nodes=worker_nodes,
            capture_budget=capture_budget, transport_budget=budget,
            handoff_fd=handoff_fd, expected=expected,
            host_key=remote_host_key, result=result)
    elif profile == PROFILE_C1B_INTERLEAVE:
        await _run_c1b_interleave_extension(
            torch=torch, reference=reference_box["model"], manifest=manifest,
            client=coordinator_client, outbound=consumer_outbound,
            coordinator=coordinator, service=service,
            secure_service=coordinator_secure_service, worker_nodes=worker_nodes,
            capture_budget=capture_budget, transport_budget=budget,
            handoff_fd=handoff_fd, expected=expected,
            host_key=remote_host_key, result=result)
    elif profile == PROFILE_C1B_CANCEL:
        await _run_c1b_cancel_extension(
            torch=torch, client=coordinator_client, outbound=consumer_outbound,
            coordinator=coordinator, service=service,
            secure_service=coordinator_secure_service, worker_nodes=worker_nodes,
            capture_budget=capture_budget, transport_budget=budget,
            handoff_fd=handoff_fd, expected=expected,
            host_key=remote_host_key, result=result, pipeline_state=pipeline_state)
    elif profile == PROFILE_C1B_PARTIAL:
        await _run_c1b_partial_admission_extension(
            client=coordinator_client, outbound=consumer_outbound,
            coordinator=coordinator, service=service,
            secure_service=coordinator_secure_service, worker_nodes=worker_nodes,
            capture_budget=capture_budget, transport_budget=budget,
            handoff_fd=handoff_fd, expected=expected,
            host_key=remote_host_key, result=result, pipeline_state=pipeline_state)
    elif profile == PROFILE_C1B_STEP_LOSS:
        await _run_c1b_step_reply_loss_extension(
            client=coordinator_client, outbound=consumer_outbound,
            coordinator=coordinator, service=service,
            secure_service=coordinator_secure_service, worker_nodes=worker_nodes,
            capture_budget=capture_budget, transport_budget=budget,
            handoff_fd=handoff_fd, expected=expected,
            host_key=remote_host_key, result=result, pipeline_state=pipeline_state)
    elif profile == PROFILE_C1B_CAPACITY:
        await _run_c1b_capacity_extension(
            torch=torch, reference=reference_box["model"], client=coordinator_client,
            outbound=consumer_outbound, coordinator=coordinator, service=service,
            secure_service=coordinator_secure_service, worker_nodes=worker_nodes,
            capture_budget=capture_budget, transport_budget=budget,
            handoff_fd=handoff_fd, expected=expected, host_key=remote_host_key,
            result=result)
    return pipeline_state


def _check_generated_events(events, request_id, expected_tokens, *, capture,
                            prompt_length=None, comparisons=None, forced_token=None):
    expected_count = len(expected_tokens) if capture else 1
    if len(events) != expected_count + 1:
        raise CohortError("secure Generate output event count is incorrect")
    token_events, terminal = events[:-1], events[-1]
    if (any(event.get("type") != "token" for event in token_events)
            or terminal.get("type") != "result"):
        raise CohortError("secure Generate events are out of order")
    sessions = {event.get("session_id") for event in token_events}
    if len(sessions) != 1:
        raise CohortError("one request emitted multiple session identities")
    session_id = next(iter(sessions))
    _require_string(session_id, label="C0 session ID", pattern=_TYPED_SESSION, max_length=36)
    if terminal.get("session_id") != session_id:
        raise CohortError("terminal event session ID differs from generated output")
    token_ids = [event.get("token_id") for event in token_events]
    if token_ids != expected_tokens or terminal.get("token_ids") != expected_tokens:
        raise CohortError("secure Generate token output differs from the reference")
    if terminal.get("status") != "completed" or terminal.get("cleanup_complete") is not True:
        raise CohortError("secure Generate did not confirm completed session cleanup")
    if capture:
        if forced_token is not None and expected_tokens[0] == forced_token:
            raise CohortError("forced decode did not begin from the unforced greedy token")
        if type(comparisons) is not list or len(comparisons) != expected_count:
            raise CohortError("capture did not return every requested last-position vector")
        expected_indices = list(range(expected_count))
        if ([item.get("index") for item in comparisons] != expected_indices
                or [item.get("sequence") for item in comparisons] != expected_indices
                or [item.get("position") for item in comparisons]
                != [prompt_length + index for index in expected_indices]):
            raise CohortError("capture sequence, output order, or position is incorrect")
        if any(event.get("index") != index or event.get("sequence") != index
               or event.get("position") != prompt_length + index
               for index, event in enumerate(token_events)):
            raise CohortError("wire capture event metadata is out of order")


def _capture_comparator(torch, expected_rows, prompt_length, comparisons):
    if (type(prompt_length) is not int or prompt_length < 1
            or getattr(expected_rows, "ndim", None) != 2
            or tuple(expected_rows.shape)[1] != 32_000):
        raise CohortError("capture reference has an invalid bounded shape")

    def compare(event):
        index = len(comparisons)
        if index >= expected_rows.shape[0] or type(event.get("logits")) is not list:
            raise CohortError("capture event count or last-position vector shape is invalid")
        if len(event["logits"]) != 32_000:
            raise CohortError("captured last-position vector has the wrong vocabulary")
        actual = torch.tensor(event["logits"], dtype=torch.float32)
        expected_row = expected_rows[index]
        if not bool(torch.isfinite(actual).all().item()):
            raise CohortError("captured logits contain a non-finite value")
        maximum_error = float(torch.max(torch.abs(actual - expected_row)).item())
        if not bool(torch.allclose(actual, expected_row, atol=1e-3, rtol=0.0)):
            raise CohortError("captured logits differ from the same-stack complete reference")
        token_id = int(expected_row.argmax().item())
        if event.get("token_id") != token_id:
            raise CohortError("captured token feedback differs from the reference argmax")
        comparisons.append({
            "index": event.get("index"), "sequence": event.get("sequence"),
            "position": event.get("position"), "token_id": token_id,
            "max_abs_error": maximum_error,
        })
        del actual

    return compare


def _ordered_interleave_stage1_sessions(active_job, queued_jobs, before_sessions):
    """Return A/B only when real A0 is active and real B0 waits in stage-1 FIFO."""
    if active_job is None:
        return None
    active_request = getattr(active_job, "request", None)
    session_a = getattr(active_request, "session_id", None)
    if (type(session_a) is not str or session_a in before_sessions
            or getattr(active_job, "sequence", None) != 0
            or getattr(active_job, "position", None) != 0
            or getattr(active_job, "count", None) != 5):
        return None
    queued_b0 = [job for job in tuple(queued_jobs)
                 if getattr(job, "sequence", None) == 0
                 and getattr(job, "position", None) == 0
                 and getattr(job, "count", None) == 11
                 and getattr(getattr(job, "request", None), "session_id", None)
                 not in before_sessions]
    if len(queued_b0) > 1:
        raise CohortError("multiple B0 jobs violate the fixed interleave schedule")
    if not queued_b0:
        return None
    session_b = queued_b0[0].request.session_id
    if type(session_b) is not str or session_a == session_b:
        raise CohortError("stage-1 FIFO prefill identities are ambiguous")
    return session_a, session_b


def _ordered_interleave_reply_trace(events, session_a, session_b):
    """Label the first prefill/decode Step replies from actual worker-3 replies."""
    labels = []
    mapping = {(session_a, 0, 5): "A0", (session_b, 0, 11): "B0",
               (session_a, 5, 1): "A1", (session_b, 11, 1): "B1"}
    for item in events:
        if (type(item) is dict and item.get("event") == "stage_response"
                and item.get("worker") == 3):
            label = mapping.get((item.get("session_id"), item.get("position"),
                                 item.get("token_count")))
            if label is not None:
                labels.append(label)
    if labels != ["A0", "B0", "A1", "B1"]:
        raise CohortError("actual worker-3 Step replies did not follow A0/B0/A1/B1")
    return labels


async def _check_context_overflow_preflight(*, torch, client, outbound, coordinator,
                                            service, secure_service, worker_nodes,
                                            capture_budget, transport_budget):
    """Prove public client rejection occurs before tensors, RPC submit, or session work."""
    from steamboat_runtime.remote_client import RemoteError
    from steamboat_security import ConsumerRequestContext

    prompt = [3 + ((index * 37 + 61) % (32_000 - 3)) for index in range(1_152)]
    if len(prompt) + 1 != 1_153:
        raise CohortError("over-boundary preflight case has the wrong fixed shape")
    before = _local_owner_snapshot(
        coordinator=coordinator, service=service, secure_service=secure_service,
        worker_nodes=worker_nodes, capture_budget=capture_budget,
        transport_budget=transport_budget, expected_connections=15)
    before_trace = (len(coordinator.events), coordinator.trace_dropped)
    context = None
    stream = None
    original_tensor = torch.tensor
    original_ensure_channel = getattr(client, "_ensure_channel", None)
    original_submit = getattr(coordinator, "submit", None)
    if not callable(original_ensure_channel) or not callable(original_submit):
        raise CohortError("preflight guards require the secure client and coordinator dispatch APIs")
    try:
        rpc_channel = getattr(client, "channel")
    except Exception:
        raise CohortError("secure coordinator RPC channel is unavailable for preflight guard") from None
    if rpc_channel is None:
        raise CohortError("secure coordinator RPC channel is unavailable for preflight guard")
    missing_instance_attribute = object()
    client_ensure_instance_value = getattr(client, "__dict__", {}).get(
        "_ensure_channel", missing_instance_attribute)
    coordinator_submit_instance_value = getattr(coordinator, "__dict__", {}).get(
        "submit", missing_instance_attribute)
    client_channel_attempts = 0
    rpc_dispatch_attempts = 0
    coordinator_submit_attempts = 0
    client_guard_installed = False
    submit_guard_installed = False
    tensor_guard_installed = False
    rejected = False
    primary = None
    cleanup_errors = []
    request_id = None

    def tensor_forbidden(*_args, **_kwargs):
        raise CohortError("over-boundary request reached tensor allocation")

    class GuardedRpcChannel:
        """Proxy the secure client's actual unary RPC dispatch call site."""

        def __init__(self, channel):
            self._channel = channel

        def __getattr__(self, name):
            return getattr(self._channel, name)

        def unary_stream(self, *_stub_args, **_stub_kwargs):
            def dispatch_forbidden(*_call_args, **_call_kwargs):
                nonlocal rpc_dispatch_attempts
                rpc_dispatch_attempts += 1
                raise CohortError("over-boundary request reached client RPC dispatch")
            return dispatch_forbidden

        def unary_unary(self, *_stub_args, **_stub_kwargs):
            def dispatch_forbidden(*_call_args, **_call_kwargs):
                nonlocal rpc_dispatch_attempts
                rpc_dispatch_attempts += 1
                raise CohortError("over-boundary request reached client RPC dispatch")
            return dispatch_forbidden

    async def guarded_ensure_channel(*_args, **_kwargs):
        nonlocal client_channel_attempts
        client_channel_attempts += 1
        # SecureCoordinatorClient.generate obtains its channel through this
        # method immediately before selecting channel.unary_stream.  Do not
        # call the original connector here: the guard must never open a new
        # connection if local request validation regresses.
        return GuardedRpcChannel(rpc_channel)

    def submit_forbidden(*_args, **_kwargs):
        nonlocal coordinator_submit_attempts
        coordinator_submit_attempts += 1
        raise CohortError("over-boundary request reached Coordinator.submit")

    try:
        context = outbound.create_consumer_request_context(lifetime_seconds=30)
        if type(context) is not ConsumerRequestContext:
            raise CohortError("over-boundary preflight lacks an actual consumer request context")
        request_id = context.request_id
        _require_string(request_id, label="preflight request ID", pattern=_TYPED_REQUEST,
                        max_length=36)
        setattr(client, "_ensure_channel", guarded_ensure_channel)
        client_guard_installed = True
        setattr(coordinator, "submit", submit_forbidden)
        submit_guard_installed = True
        torch.tensor = tensor_forbidden
        tensor_guard_installed = True
        stream = client.generate(
            prompt, 1, trusted_request_context=context,
            capture_logits=True, timeout_seconds=30)
        try:
            async for _event in stream:
                raise CohortError("over-boundary preflight unexpectedly emitted an event")
        except RemoteError as error:
            if error.code != "INVALID_INPUT":
                raise CohortError("over-boundary request was not rejected as invalid input") from None
            rejected = True
    except BaseException as error:
        primary = error
    finally:
        if stream is not None:
            try:
                await stream.aclose()
            except BaseException as error:
                cleanup_errors.append(error)
        if context is not None:
            try:
                context.close()
            except BaseException as error:
                cleanup_errors.append(error)
        if tensor_guard_installed:
            try:
                torch.tensor = original_tensor
            except BaseException as error:
                cleanup_errors.append(error)
        if client_guard_installed:
            try:
                if client_ensure_instance_value is missing_instance_attribute:
                    delattr(client, "_ensure_channel")
                else:
                    client._ensure_channel = client_ensure_instance_value
            except BaseException as error:
                cleanup_errors.append(error)
        if submit_guard_installed:
            try:
                if coordinator_submit_instance_value is missing_instance_attribute:
                    delattr(coordinator, "submit")
                else:
                    coordinator.submit = coordinator_submit_instance_value
            except BaseException as error:
                cleanup_errors.append(error)
    failures = ([primary] if primary is not None else []) + cleanup_errors
    if failures:
        if len(failures) == 1:
            raise failures[0]
        raise BaseExceptionGroup("over-boundary preflight and cleanup failed", failures)
    if client_channel_attempts or rpc_dispatch_attempts:
        raise CohortError("over-boundary preflight crossed the secure client RPC boundary")
    if coordinator_submit_attempts:
        raise CohortError("over-boundary preflight crossed Coordinator.submit")
    if not rejected:
        raise CohortError("over-boundary request did not fail closed with INVALID_INPUT")
    after_trace = (len(coordinator.events), coordinator.trace_dropped)
    after = _local_owner_snapshot(
        coordinator=coordinator, service=service, secure_service=secure_service,
        worker_nodes=worker_nodes, capture_budget=capture_budget,
        transport_budget=transport_budget, expected_connections=15)
    if after_trace != before_trace or after != before:
        raise CohortError("over-boundary preflight changed local request or resource ownership")
    return {
        "case_id": _PROFILE_LOCAL_CASES[PROFILE_C1B_HAPPY][0],
        "request_id": request_id, "session_id": None,
        "accepted": False, "error_code": "INVALID_INPUT",
        "tensor_allocations": 0, "coordinator_submits": 0,
        "remote_worker_contacted": False,
        "local_owner_check": after,
        "evidence_scope": "public client preflight only; no worker RPC or remote compute claim",
    }


async def _run_c1b_happy_extensions(*, torch, reference, manifest, client, outbound,
                                    coordinator, service, secure_service, worker_nodes,
                                    capture_budget, transport_budget, handoff_fd,
                                    expected, host_key, result):
    preflight = await _check_context_overflow_preflight(
        torch=torch, client=client, outbound=outbound, coordinator=coordinator,
        service=service, secure_service=secure_service, worker_nodes=worker_nodes,
        capture_budget=capture_budget, transport_budget=transport_budget)

    prepared = []
    for prompt_length, offset in ((5, 37), (11, 41)):
        prompt = [3 + ((index * 37 + offset) % (32_000 - 3))
                  for index in range(prompt_length)]
        forced_token, expected_rows = _reference_forced_last_positions(
            reference, torch, prompt, forced_steps=3)
        if tuple(expected_rows.shape) != (4, 32_000):
            raise CohortError("unequal concurrent reference must contain four output rows")
        prepared.append({
            "prompt_length": prompt_length, "prompt": prompt,
            "forced_token": forced_token, "expected_rows": expected_rows,
        })

    async def run_forced(item):
        comparisons = []
        request_id, events = await _secure_generate(
            client, outbound, item["prompt"], new_tokens=4,
            forced_tokens=[item["forced_token"]] * 3, capture_logits=True,
            on_token=_capture_comparator(
                torch, item["expected_rows"], item["prompt_length"], comparisons))
        _check_generated_events(
            events, request_id, [entry["token_id"] for entry in comparisons],
            capture=True, prompt_length=item["prompt_length"],
            comparisons=comparisons, forced_token=item["forced_token"])
        session_id = events[0]["session_id"]
        _require_string(request_id, label="concurrent request ID", pattern=_TYPED_REQUEST,
                        max_length=36)
        _require_string(session_id, label="concurrent session ID", pattern=_TYPED_SESSION,
                        max_length=36)
        return {
            "case_id": f"unequal-concurrent-prompt-{item['prompt_length']}",
            "request_id": request_id, "session_id": session_id,
            "prompt_length": item["prompt_length"], "new_tokens": 4,
            "forced_feedback_count": 3, "captured_vectors": len(comparisons),
            "max_absolute_error": max(x["max_abs_error"] for x in comparisons),
            "comparison_errors": [x["max_abs_error"] for x in comparisons],
            "token_ids": [x["token_id"] for x in comparisons],
            "positions": [x["position"] for x in comparisons],
        }

    outcomes = await asyncio.gather(*(run_forced(item) for item in prepared),
                                    return_exceptions=True)
    failures = [outcome for outcome in outcomes if isinstance(outcome, BaseException)]
    if failures:
        raise BaseExceptionGroup("concurrent forced requests failed", failures)
    concurrent = list(outcomes)
    if (len(concurrent) != 2
            or concurrent[0]["prompt_length"] != 5
            or concurrent[1]["prompt_length"] != 11
            or len({item["request_id"] for item in concurrent}) != 2
            or len({item["session_id"] for item in concurrent}) != 2
            or any(item["captured_vectors"] != 4 for item in concurrent)):
        raise CohortError("unequal concurrent request accounting is incomplete")
    local_after_pair = await _wait_local_cleanup(
        coordinator=coordinator, service=service, secure_service=secure_service,
        worker_nodes=worker_nodes, capture_budget=capture_budget,
        transport_budget=transport_budget, expected_connections=15)
    for sequence, item in zip((5, 6), concurrent):
        remote = await _observe_remote(
            handoff_fd, expected, sequence=sequence, case_id=item["case_id"],
            request_id=item["request_id"], session_id=item["session_id"],
            host_key=host_key, profile=PROFILE_C1B_HAPPY)
        item["local_owner_check"] = local_after_pair
        item["remote_owner_check"] = remote
        item["remote_evidence_scope"] = (
            "fresh worker-3 idle status after both TLS requests; remote overlap was not observed")

    prompt = [3 + ((index * 37 + 53) % (32_000 - 3)) for index in range(1_151)]
    if len(prompt) + 1 != manifest["limits"]["max_positions"]:
        raise CohortError("context-boundary case does not equal the pinned position limit")
    expected_row = _reference_last_row(reference, torch, prompt)
    comparisons = []
    request_id, events = await _secure_generate(
        client, outbound, prompt, new_tokens=1, capture_logits=True,
        on_token=_capture_comparator(
            torch, expected_row.unsqueeze(0), len(prompt), comparisons))
    _check_generated_events(
        events, request_id, [entry["token_id"] for entry in comparisons],
        capture=True, prompt_length=len(prompt), comparisons=comparisons)
    session_id = events[0]["session_id"]
    boundary = {
        "case_id": "context-boundary-1151-plus-1",
        "request_id": request_id, "session_id": session_id,
        "prompt_length": len(prompt), "new_tokens": 1,
        "positions_total": len(prompt) + 1,
        "captured_vectors": len(comparisons),
        "max_absolute_error": max(x["max_abs_error"] for x in comparisons),
        "comparison_errors": [x["max_abs_error"] for x in comparisons],
        "token_ids": [x["token_id"] for x in comparisons],
        "positions": [x["position"] for x in comparisons],
    }
    if (boundary["positions_total"] != 1_152 or boundary["captured_vectors"] != 1
            or boundary["positions"] != [1_151]):
        raise CohortError("exact context-boundary accounting is incorrect")
    local_boundary = await _wait_local_cleanup(
        coordinator=coordinator, service=service, secure_service=secure_service,
        worker_nodes=worker_nodes, capture_budget=capture_budget,
        transport_budget=transport_budget, expected_connections=15)
    remote_boundary = await _observe_remote(
        handoff_fd, expected, sequence=7, case_id=boundary["case_id"],
        request_id=request_id, session_id=session_id, host_key=host_key,
        profile=PROFILE_C1B_HAPPY)
    boundary["local_owner_check"] = local_boundary
    boundary["remote_owner_check"] = remote_boundary
    boundary["remote_evidence_scope"] = "fresh protected worker-3 idle status after the TLS request"

    extension_vectors = sum(item["captured_vectors"] for item in concurrent) + 1
    extension_errors = [
        error for item in concurrent for error in item["comparison_errors"]
    ] + list(boundary["comparison_errors"])
    extension_request_ids = [item["request_id"] for item in concurrent] + [boundary["request_id"]]
    extension_session_ids = [item["session_id"] for item in concurrent] + [boundary["session_id"]]
    if (extension_vectors != 9
            or len(set(extension_request_ids)) != 3
            or len(set(extension_session_ids)) != 3
            or set(extension_request_ids) & set(result["request_ids"])
            or set(extension_session_ids) & set(result["session_ids"])):
        raise CohortError("happy profile captured-vector total is incomplete")
    result["cases"].extend([preflight, *concurrent, boundary])
    extension_summary = {
        "profile": PROFILE_C1B_HAPPY,
        "status": "passed",
        "completed_requests": 3,
        "numerical_errors": extension_errors,
        "request_ids": extension_request_ids,
        "session_ids": extension_session_ids,
        "remote_overlap_observed": False,
        "preflight_rejection": preflight,
    }
    _validate_c1b_extension_summary(extension_summary)
    result["baseline"]["lifecycle_extensions"] = extension_summary
    del prepared, prompt, expected_row, events, comparisons


async def _run_c1b_interleave_extension(*, torch, reference, manifest, client,
                                        outbound, coordinator, service,
                                        secure_service, worker_nodes, capture_budget,
                                        transport_budget, handoff_fd, expected,
                                        host_key, result):
    """Observe real worker-3 Step replies after a causal stage-1 queue barrier."""
    import threading

    if not worker_nodes or worker_nodes[0].get("executor") is None:
        raise CohortError("ordered interleave requires the owned worker-1 executor")
    executor = worker_nodes[0]["executor"]
    original_execute = executor.execute
    entered, release, gate_failed = (threading.Event() for _ in range(3))
    gate_lock = threading.Lock()
    gate_claimed = [False]

    def gated_execute(hidden, cache, position):
        output = original_execute(hidden, cache, position)
        with gate_lock:
            hold = not gate_claimed[0]
            if hold:
                gate_claimed[0] = True
        if hold:
            entered.set()
            if not release.wait(30.0):
                gate_failed.set()
                raise CohortError("ordered interleave stage-1 gate exceeded its bound")
        return output

    before_sessions = {
        item.get("session_id") for item in coordinator.events
        if type(item) is dict and type(item.get("session_id")) is str
    }
    trace_dropped_before = coordinator.trace_dropped
    executor.execute = gated_execute
    tasks = []
    try:
        prepared = []
        for prompt_length, offset in ((5, 37), (11, 41)):
            prompt = [3 + ((index * 37 + offset) % (32_000 - 3))
                      for index in range(prompt_length)]
            forced_token, expected_rows = _reference_forced_last_positions(
                reference, torch, prompt, forced_steps=3)
            if tuple(expected_rows.shape) != (4, 32_000):
                raise CohortError("interleave reference must contain four output rows")
            prepared.append({"prompt": prompt, "prompt_length": prompt_length,
                             "forced_token": forced_token,
                             "expected_rows": expected_rows})

        async def generate(item):
            comparisons = []
            request_id, events = await _secure_generate(
                client, outbound, item["prompt"], new_tokens=4,
                forced_tokens=[item["forced_token"]] * 3, capture_logits=True,
                on_token=_capture_comparator(
                    torch, item["expected_rows"], item["prompt_length"], comparisons))
            _check_generated_events(
                events, request_id, [entry["token_id"] for entry in comparisons],
                capture=True, prompt_length=item["prompt_length"],
                comparisons=comparisons, forced_token=item["forced_token"])
            session_id = events[0]["session_id"]
            _require_string(request_id, label="interleave request ID",
                            pattern=_TYPED_REQUEST, max_length=36)
            _require_string(session_id, label="interleave session ID",
                            pattern=_TYPED_SESSION, max_length=36)
            return {"request_id": request_id, "session_id": session_id,
                    "comparisons": comparisons}

        task_a = asyncio.create_task(generate(prepared[0]))
        tasks.append(task_a)
        deadline = asyncio.get_running_loop().time() + 15.0
        while not entered.is_set():
            if task_a.done():
                await task_a
                raise CohortError("request A completed before the actual Step gate")
            if asyncio.get_running_loop().time() >= deadline:
                raise CohortError("request A did not reach the actual StageExecutor gate")
            await asyncio.sleep(0.01)

        # The original A prefill has completed inside the real StageExecutor.
        # While its worker-1 reply is held, B must be dispatched and visibly
        # queued in the real coordinator's stage-1 FIFO before A is released.
        task_b = asyncio.create_task(generate(prepared[1]))
        tasks.append(task_b)
        barrier_deadline = asyncio.get_running_loop().time() + 15.0
        stage1_sessions = None
        while stage1_sessions is None:
            stage1_sessions = _ordered_interleave_stage1_sessions(
                coordinator._active_jobs[0], coordinator._queues[0].items,
                before_sessions)
            if stage1_sessions is not None:
                break
            if task_b.done():
                await task_b
                raise CohortError("request B completed before the causal queue barrier")
            if asyncio.get_running_loop().time() >= barrier_deadline:
                raise CohortError("request B did not queue behind gated A prefill")
            await asyncio.sleep(0.01)
        release.set()
        outcomes = await asyncio.wait_for(
            asyncio.gather(task_a, task_b), timeout=120.0)
        if gate_failed.is_set() or not gate_claimed[0]:
            raise CohortError("ordered interleave StageExecutor gate did not retire cleanly")
        if ([outcome["session_id"] for outcome in outcomes] != list(stage1_sessions)
                or any(len(outcome["comparisons"]) != 4 for outcome in outcomes)):
            raise CohortError("interleave request identity or vector accounting changed")

        session_a, session_b = stage1_sessions
        trace = _ordered_interleave_reply_trace(tuple(coordinator.events),
                                                session_a, session_b)
        if coordinator.trace_dropped != trace_dropped_before:
            raise CohortError("coordinator dropped causal Step reply trace records")

        local = await _wait_local_cleanup(
            coordinator=coordinator, service=service, secure_service=secure_service,
            worker_nodes=worker_nodes, capture_budget=capture_budget,
            transport_budget=transport_budget, expected_connections=15)
        remote = await _observe_remote(
            handoff_fd, expected, sequence=5, case_id="ordered-step-interleave",
            request_id=outcomes[0]["request_id"], session_id=session_a,
            host_key=host_key, profile=PROFILE_C1B_INTERLEAVE)
        errors = [entry["max_abs_error"] for outcome in outcomes
                  for entry in outcome["comparisons"]]
        extension = {
            "profile": PROFILE_C1B_INTERLEAVE, "status": "passed",
            "completed_requests": 2, "prompt_lengths": [5, 11],
            "captured_vectors": len(errors), "comparison_errors": errors,
            "max_absolute_error": max(errors),
            "request_ids": [outcome["request_id"] for outcome in outcomes],
            "session_ids": [outcome["session_id"] for outcome in outcomes],
            "step_trace": trace, "causal_barrier_confirmed": True,
            "local_owner_check": local,
            "remote_owner_check_confirmed": remote.get("confirmed") is True,
        }
        result["interleave"] = _validate_interleave_summary(extension)
    finally:
        release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        try:
            if tasks:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True), timeout=15.0)
        finally:
            executor.execute = original_execute


async def _run_c1b_cancel_extension(*, torch, client, outbound, coordinator,
                                    service, secure_service, worker_nodes,
                                    capture_budget, transport_budget, handoff_fd,
                                    expected, host_key, result, pipeline_state):
    """Cancel one real request after its first decode has mutated worker-1 cache."""
    import threading
    from steamboat_security.outbound import ConsumerRequestContext

    if not worker_nodes or len(worker_nodes) != 2:
        raise CohortError("cancellation profile requires both owned local workers")
    executor = worker_nodes[0]["executor"]
    originals = [node["executor"].execute for node in worker_nodes]
    local_executor_counts = [0, 0]
    trace_dropped_before = coordinator.trace_dropped
    entered, release, gate_failed = (threading.Event() for _ in range(3))
    request_context = outbound.create_consumer_request_context(lifetime_seconds=120)
    if type(request_context) is not ConsumerRequestContext:
        raise CohortError("cancellation did not obtain a trusted consumer request context")
    request_id = request_context.request_id
    _require_string(request_id, label="cancellation request ID",
                    pattern=_TYPED_REQUEST, max_length=36)
    received_tokens = []
    received_sessions = []
    cancellation_observed = [False]
    stream_box = {"stream": None}

    def wrap(index, original):
        def execute(hidden, cache, position):
            local_executor_counts[index] += 1
            output = original(hidden, cache, position)
            if index == 0 and local_executor_counts[index] == 2:
                entered.set()
                if not release.wait(20.0):
                    gate_failed.set()
                    raise CohortError("cancellation decode gate exceeded its bound")
            return output
        return execute

    for index, node in enumerate(worker_nodes):
        node["executor"].execute = wrap(index, originals[index])

    async def consume_request():
        stream = client.generate(
            [7, 13, 31], 3, trusted_request_context=request_context,
            capture_logits=False, timeout_seconds=30)
        stream_box["stream"] = stream
        try:
            async for event in stream:
                if type(event) is not dict:
                    raise CohortError("cancelled Generate emitted a malformed event")
                if event.get("type") == "token":
                    token = event.get("token_id")
                    session = event.get("session_id")
                    _require_int(token, label="cancellation output token",
                                 minimum=0, maximum=31_999)
                    _require_string(session, label="cancellation session ID",
                                    pattern=_TYPED_SESSION, max_length=36)
                    received_tokens.append(token)
                    if session not in received_sessions:
                        received_sessions.append(session)
        except asyncio.CancelledError:
            cancellation_observed[0] = True
            return
        finally:
            try:
                await stream.aclose()
            finally:
                request_context.close()

    task = asyncio.create_task(consume_request())

    def observed_step_dispatch_counts(session_id):
        if coordinator.trace_dropped != trace_dropped_before:
            raise CohortError("coordinator dropped cancellation Step dispatch evidence")
        events = [item for item in tuple(coordinator.events)
                  if type(item) is dict and item.get("event") == "stage_dispatch"
                  and item.get("session_id") == session_id]
        if any(type(item.get("worker")) is not int or item["worker"] not in (1, 2, 3)
               for item in events):
            raise CohortError("coordinator cancellation Step dispatch trace is malformed")
        return [sum(item["worker"] == worker for item in events)
                for worker in (1, 2, 3)]

    try:
        deadline = asyncio.get_running_loop().time() + 20.0
        while not entered.is_set() or not received_tokens:
            if task.done():
                await task
                raise CohortError("cancellation request retired before the decode gate")
            if asyncio.get_running_loop().time() >= deadline:
                raise CohortError("request did not reach first-decode gate with one token")
            await asyncio.sleep(0.01)
        if len(received_tokens) != 1 or len(received_sessions) != 1:
            raise CohortError("request did not produce exactly one first token before the gate")
        session_id = received_sessions[0]
        _require_string(session_id, label="cancellation session ID",
                        pattern=_TYPED_SESSION, max_length=36)
        dispatch_counts = observed_step_dispatch_counts(session_id)
        if (local_executor_counts != [2, 1] or dispatch_counts != [2, 1, 1]
                or not _cancellation_dispatch_prefix(
                    tuple(coordinator.events), session_id)):
            raise CohortError("first-decode gate did not stop the exact Step dispatch prefix")

        remote_held = await _observe_remote(
            handoff_fd, expected, sequence=5,
            case_id="cancel-held-worker3-session", request_id=request_id,
            session_id=session_id, host_key=host_key, profile=PROFILE_C1B_CANCEL)
        if (remote_held.get("confirmed") is not True
                or remote_held.get("active_sessions") != 1
                or remote_held.get("committed_cache_bytes", 0) <= 0):
            raise CohortError("remote worker did not prove the same committed held session")

        # The acknowledgement carries the operator's clock sampled before its
        # write; this local sample is only used for the child's bounded work.
        ack_ns = remote_held.get("supervisor_monotonic_ns")
        _require_int(ack_ns, label="operator cancellation arm time", minimum=1)
        task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=5.0)
        except asyncio.CancelledError:
            cancellation_observed[0] = True
        except TimeoutError:
            raise CohortError("cancelled consumer did not retire within its bound") from None
        finally:
            release.set()
        if not cancellation_observed[0]:
            raise CohortError("consumer task did not observe actual asyncio cancellation")
        if len(received_tokens) != 1:
            raise CohortError("an extra token was emitted after cancellation")
        compute_deadline = asyncio.get_running_loop().time() + 15.0
        while any(node["handler"]._active_operation is not None for node in worker_nodes):
            if asyncio.get_running_loop().time() >= compute_deadline:
                raise CohortError("owned local CPU work did not join after gate release")
            await asyncio.sleep(0.02)
        if (local_executor_counts != [2, 1]
                or observed_step_dispatch_counts(session_id) != dispatch_counts
                or gate_failed.is_set()):
            raise CohortError("cancellation dispatched an automatic retry or lost its gate")
        remote_idle = await _observe_remote(
            handoff_fd, expected, sequence=6,
            case_id="cancel-worker3-reclaimed", request_id=request_id,
            session_id=session_id, host_key=host_key, profile=PROFILE_C1B_CANCEL)
        if (remote_idle.get("confirmed") is not True
                or remote_idle.get("active_sessions") != 0
                or remote_idle.get("committed_cache_bytes") != 0
                or remote_idle.get("allocated_cache_bytes") != 0):
            raise CohortError("remote worker did not prove global post-cancel reclamation")

        cleanup_deadline = asyncio.get_running_loop().time() + 10.0
        local_owner_snapshot = None
        while True:
            stats = coordinator.stats()
            active_requests = stats.get("active_requests")
            try:
                local_owner_snapshot = _local_owner_snapshot(
                    coordinator=coordinator, service=service,
                    secure_service=secure_service, worker_nodes=worker_nodes,
                    capture_budget=capture_budget,
                    transport_budget=transport_budget, expected_connections=15,
                    expected_active_requests=active_requests)
                break
            except CohortError:
                pass
            if asyncio.get_running_loop().time() >= cleanup_deadline:
                raise CohortError("local worker/capture owners did not drain after cancellation")
            await asyncio.sleep(0.05)
        ready = stats.get("ready")
        active_requests = stats.get("active_requests")
        model_cleanup = stats.get("model_cleanup_complete")
        capture_status = capture_budget.status()
        request_reclaimed = (
            type(active_requests) is int and active_requests == 0
            and type(ready) is bool and ready
            and (model_cleanup is None or model_cleanup is True)
            and local_owner_snapshot["active_requests"] == 0)
        fenced = (type(active_requests) is int and active_requests == 1
                  and ready is False and not request_reclaimed)
        if not (request_reclaimed or fenced):
            raise CohortError("local cancellation cleanup is unknown, not reclaimed or fenced")
        # This is request/worker-owner reclamation. Model teardown happens only
        # during coordinator.close(), after this observation, and is reported
        # separately as nullable evidence.
        local_state = {
            "state": "fully_reclaimed" if request_reclaimed else "restart_fenced_retained",
            "logical_cleanup_confirmed": request_reclaimed,
            "coordinator_ready": ready,
            "active_requests": active_requests,
            "model_cleanup_complete": stats.get("model_cleanup_complete"),
            "active_streams": local_owner_snapshot["active_streams"],
            "active_generate_streams": local_owner_snapshot["active_generate_streams"],
            "active_captures": local_owner_snapshot["active_captures"],
            "cleanup_pending_captures": capture_status.cleanup_pending_captures,
            "capture_reserved_bytes": local_owner_snapshot["capture_reserved_bytes"],
            "worker_sessions": local_owner_snapshot["worker_sessions"],
            "worker_active_compute": local_owner_snapshot["worker_active_compute"],
            "transport_reserved_connections": local_owner_snapshot["transport_reserved_connections"],
            "transport_reserved_pending": local_owner_snapshot["transport_reserved_pending"],
        }
        pipeline_state["cancellation_state"] = local_state
        result["cancellation"] = {
            "profile": PROFILE_C1B_CANCEL,
            "status": "passed",
            "request_id": request_id,
            "session_id": session_id,
            "tokens_before_cancel": 1,
            "tokens_after_cancel": len(received_tokens),
            "step_counts": list(dispatch_counts),
            "stage_gate_after_cache_mutation": True,
            "remote_held_session_confirmed": True,
            "cancelled_error_observed": True,
            "compute_joined": True,
            "remote_reclaimed_confirmed": True,
            "supervisor_arm_monotonic_ns": ack_ns,
            "local_state": local_state,
        }
        result["pending_scope"] = [item for item in result["pending_scope"]
                                   if item != "cancellation"]
    finally:
        release.set()
        if not task.done():
            task.cancel()
        try:
            await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), timeout=15.0)
        finally:
            for node, original in zip(worker_nodes, originals):
                node["executor"].execute = original


async def _run_c1b_partial_admission_extension(*, client, outbound, coordinator,
                                               service, secure_service, worker_nodes,
                                               capture_budget, transport_budget,
                                               handoff_fd, expected, host_key, result,
                                               pipeline_state):
    """Lose one actual, completed worker-3 OpenSession reply at its caller boundary.

    The remote worker has already allocated a real bounded lease when the
    injected exception is raised. The coordinator must retain that unknown
    open, while its two known local opens are cleaned normally. This profile
    does not simulate packet loss and does not claim in-process recovery.
    """
    from steamboat_runtime.protocol.errors import ProtocolError
    from steamboat_runtime.protocol.worker_pb2 import Response
    from steamboat_runtime.participant_context import TrustedRequestContext
    from steamboat_security.outbound import ConsumerRequestContext

    if len(worker_nodes) != 2:
        raise CohortError("partial Open reply loss requires the two local workers")
    request_context = outbound.create_consumer_request_context(lifetime_seconds=120)
    if type(request_context) is not ConsumerRequestContext:
        raise CohortError("partial Open profile lacks trusted consumer request context")
    request_id = request_context.request_id
    _require_string(request_id, label="partial Open request ID",
                    pattern=_TYPED_REQUEST, max_length=36)

    attempts = [dict() for _ in coordinator.clients]
    lifetimes = [None, None, None]
    open_reply_order = []
    session_box = {"value": None}
    armed_box = {"value": None}
    original_methods = []
    trace_dropped_before = coordinator.trace_dropped
    injected = [False]

    try:
        for index, worker_client in enumerate(coordinator.clients):
            original = worker_client.execute
            original_methods.append((worker_client, original))

            async def observe_execute(method, request, *, trusted_request_context=None,
                                      _index=index, _original=original):
                attempts[_index][method] = attempts[_index].get(method, 0) + 1
                if method == "OpenSession":
                    if type(trusted_request_context) is not TrustedRequestContext:
                        raise CohortError("partial Open omitted trusted worker context")
                    if _index != 2 or lifetimes[_index] is not None:
                        if lifetimes[_index] is not None:
                            raise CohortError("partial Open profile repeated an Open attempt")
                    lifetimes[_index] = (request.lifetime_ms, request.idle_lease_ms,
                                         request.max_positions)
                response = await _original(
                    method, request, trusted_request_context=trusted_request_context)
                if method == "OpenSession" and type(response) is Response \
                        and response.code == "OK":
                    open_reply_order.append(_index)
                if _index == 2 and method == "OpenSession":
                    if injected[0] or type(response) is not Response:
                        raise CohortError("partial Open fault was duplicated or malformed")
                    if (response.code != "OK"
                            or response.session_id != request.session_id
                            or response.worker_boot_id != expected.boot_id
                            or response.max_positions != request.max_positions
                            or not response.lease_token):
                        raise CohortError("actual worker-3 Open reply identity is invalid")
                    lifetime_ms, idle_ms, max_positions = lifetimes[2]
                    if (type(lifetime_ms) is not int or not 1 <= lifetime_ms <= 10_000
                            or type(idle_ms) is not int or not 1 <= idle_ms <= lifetime_ms
                            or type(max_positions) is not int or max_positions != 4):
                        raise CohortError("target Open was not bounded by the ten-second request")
                    _require_string(request.session_id, label="partial Open session ID",
                                    pattern=_TYPED_SESSION, max_length=36)
                    session_box["value"] = request.session_id
                    held = await _observe_remote(
                        handoff_fd, expected, sequence=5,
                        case_id="partial-open-reply-held", request_id=request_id,
                        session_id=request.session_id, host_key=host_key,
                        profile=PROFILE_C1B_PARTIAL)
                    if (held.get("confirmed") is not True
                            or held.get("active_sessions") != 1
                            or held.get("active_session_ids") != [request.session_id]
                            or held.get("committed_cache_bytes") != 0
                            or held.get("allocated_cache_bytes") != 0
                            or held.get("active_compute") is not False):
                        raise CohortError("remote worker did not attest the exact held Open lease")
                    arm_ns = held.get("supervisor_monotonic_ns")
                    _require_int(arm_ns, label="partial Open disposal arm", minimum=1)
                    armed_box["value"] = arm_ns
                    injected[0] = True
                    # The actual TLS client has verified and completed this
                    # response. Only the coordinator caller loses the reply.
                    raise ProtocolError(
                        "EXECUTION_FAILED",
                        "test fault: successful worker-3 Open reply lost at caller boundary")
                return response

            worker_client.execute = observe_execute

        events = []
        stream = None
        failure = None
        try:
            stream = client.generate(
                [7, 13, 31], 1, trusted_request_context=request_context,
                capture_logits=False, timeout_seconds=10)
            async for event in stream:
                if type(event) is not dict:
                    raise CohortError("partial Open Generate emitted malformed event")
                events.append(event)
        except BaseException as error:
            failure = error
        finally:
            if stream is not None:
                await stream.aclose()
        if (failure is None or not isinstance(failure, Exception)
                or getattr(failure, "code", None) != "EXECUTION_FAILED"):
            raise CohortError("partial Open reply-loss did not fail Generate as expected")

        if not injected[0] or session_box["value"] is None or armed_box["value"] is None:
            raise CohortError("partial Open caller-boundary fault was not causally observed")
        if trace_dropped_before != coordinator.trace_dropped:
            raise CohortError("coordinator dropped partial Open dispatch evidence")
        session_id = session_box["value"]
        if ([item.get("OpenSession", 0) for item in attempts] != [1, 1, 1]
                or open_reply_order != [0, 1, 2]):
            raise CohortError("partial Open did not reach each worker exactly once")
        step_counts = [item.get("Step", 0) for item in attempts]
        if step_counts != [0, 0, 0]:
            raise CohortError("partial Open request dispatched a Step")
        if any(type(item) is dict and item.get("event") == "stage_dispatch"
               and item.get("session_id") == session_id
               for item in tuple(coordinator.events)):
            raise CohortError("partial Open request emitted a stage dispatch")
        if any(event.get("type") == "token" for event in events):
            raise CohortError("partial Open request emitted a token")
        terminal = [event for event in events if event.get("type") == "result"]
        if (len(terminal) != 1 or terminal[0].get("status") != "failed"
                or terminal[0].get("error_code") != "EXECUTION_FAILED"
                or terminal[0].get("token_ids") != []
                or terminal[0].get("cleanup_complete") is not False
                or terminal[0].get("session_id") != session_id):
            raise CohortError("partial Open result did not preserve unknown-cleanup failure")

        state = coordinator._requests.get(session_id)
        if (state is None or state.unknown_opens != {2} or state.leases
                or not state.restart_required or not state.completion.done()):
            raise CohortError("coordinator did not retain only the unknown worker-3 Open")
        request_result = state.completion.result()
        stats = coordinator.stats()
        if (request_result.cleanup_complete is not False
                or request_result.error_code != "EXECUTION_FAILED"
                or request_result.token_ids != ()
                or stats.get("ready") is not False
                or stats.get("active_requests") != 1):
            raise CohortError("coordinator did not preserve its truthful restart fence")
        retained_slots = getattr(secure_service, "_unreclaimed_generate_slots", None)
        trusted_context = state.trusted_request_context
        matching_slots = []
        if type(retained_slots) is list:
            for slot in retained_slots:
                handle = slot.get("handle") if type(slot) is dict else None
                if (getattr(handle, "_owner", None) is coordinator
                        and getattr(handle, "_state", None) is state
                        and slot.get("trusted_context") is trusted_context):
                    matching_slots.append(slot)
        if (type(retained_slots) is not list or len(retained_slots) != 1
                or len(matching_slots) != 1 or trusted_context is None):
            raise CohortError("partial Open did not retain exactly its trusted Generate slot")
        retained_slot = matching_slots[0]
        if (retained_slot.get("retained") is not True
                or retained_slot.get("resource_cleanup_required") is not True
                or retained_slot.get("resource_cleanup_confirmed") is not False):
            raise CohortError("partial Open retained slot has inconsistent cleanup ownership")
        pipeline_state["partial_admission_owner_binding"] = {
            "coordinator": coordinator,
            "request_state": state,
            "trusted_context": trusted_context,
            "session_id": session_id,
            "secure_slot": retained_slot,
            "secure_cleanup_task": retained_slot.get("cleanup_task"),
        }

        # Wait for a fresh supervisor observation after the worker's actual
        # ten-second lease expiry. The parent polls the remote worker's global
        # status; no local flag or worker process is reset to manufacture idle.
        idle = await _observe_remote(
            handoff_fd, expected, sequence=6,
            case_id="partial-open-lease-expired", request_id=request_id,
            session_id=session_id, host_key=host_key, profile=PROFILE_C1B_PARTIAL)
        if (idle.get("confirmed") is not True
                or idle.get("active_sessions") != 0
                or idle.get("active_session_ids") != []
                or idle.get("committed_cache_bytes") != 0
                or idle.get("allocated_cache_bytes") != 0
                or idle.get("active_compute") is not False):
            raise CohortError("remote worker did not confirm global idle after lease expiry")

        local_worker_sessions = 0
        local_active_compute = False
        bridge_owned_sessions = 0
        bridge_active_authorizations = 0
        bridge_pending_notices = 0
        for node in worker_nodes:
            handler = node["handler"]
            bridge = node["bridge"].status()
            if handler.sessions or handler._queue or handler._active_operation is not None:
                raise CohortError("known local Open sessions were not reclaimed")
            local_worker_sessions += len(handler.sessions)
            entries = tuple(handler.tombstones.values())
            if any(entry.in_flight or entry.queued
                   or entry.committed_bytes != 0 or entry.cache.allocated_bytes() != 0
                   or any(entry.cache.lengths()) for entry in entries):
                raise CohortError("local worker retained cache after known Open cleanup")
            if (bridge.get("owned_sessions") != 0
                    or bridge.get("active_authorizations") != 0
                    or bridge.get("pending_notices") != 0
                    or bridge.get("cleanup_confirmed") is not True):
                raise CohortError("local worker authorization owner cleanup is unknown")
            bridge_owned_sessions += bridge["owned_sessions"]
            bridge_active_authorizations += bridge["active_authorizations"]
            bridge_pending_notices += bridge["pending_notices"]
        capture = capture_budget.status()
        if capture.active_captures != 0 or capture.cleanup_pending_captures != 0 \
                or capture.reserved_bytes != 0:
            raise CohortError("partial Open request retained capture resources")
        if (transport_budget.reserved_pending != 0
                or transport_budget.reserved_outbound_pending != 0
                or transport_budget.reserved_connections != 15):
            raise CohortError("partial Open request retained a local transport operation")
        local_state = {
            "state": "restart_fenced_retained",
            "logical_cleanup_confirmed": False,
            "coordinator_ready": False,
            "active_requests": stats["active_requests"],
            "unknown_open_indices": sorted(state.unknown_opens),
            "known_lease_indices": sorted(state.leases),
            "active_streams": service.active_streams,
            "active_generate_streams": secure_service.active_generate_streams,
            "worker_sessions": local_worker_sessions,
            "worker_active_compute": local_active_compute,
            "bridge_owned_sessions": bridge_owned_sessions,
            "bridge_active_authorizations": bridge_active_authorizations,
            "bridge_pending_notices": bridge_pending_notices,
            "active_captures": capture.active_captures,
            "cleanup_pending_captures": capture.cleanup_pending_captures,
            "capture_reserved_bytes": capture.reserved_bytes,
            "transport_reserved_connections": transport_budget.reserved_connections,
            "transport_reserved_pending": transport_budget.reserved_pending,
        }
        pipeline_state["partial_admission_state"] = local_state
        result["partial_admission"] = {
            "profile": PROFILE_C1B_PARTIAL,
            "status": "passed",
            "request_id": request_id,
            "session_id": session_id,
            "open_attempts": [1, 1, 1],
            "open_reply_order": list(open_reply_order),
            "step_attempts": step_counts,
            "worker3_open_lifetime_ms": lifetimes[2][0],
            "actual_tls_open_reply_validated": True,
            "caller_boundary_reply_loss": True,
            "remote_held_session_confirmed": True,
            "unknown_cleanup_preserved": True,
            "remote_lease_expiry_reclaimed": True,
            "supervisor_arm_monotonic_ns": armed_box["value"],
            "local_state": local_state,
        }
        result["pending_scope"] = [item for item in result["pending_scope"]
                                   if item != "partial_admission"]
    finally:
        request_context.close()
        for worker_client, original in reversed(original_methods):
            worker_client.execute = original


async def _run_c1b_step_reply_loss_extension(*, client, outbound, coordinator,
                                             service, secure_service, worker_nodes,
                                             capture_budget, transport_budget,
                                             handoff_fd, expected, host_key, result,
                                             pipeline_state):
    """Lose the actual worker-3 first-prefill Step reply at the caller boundary."""
    from steamboat_runtime.protocol.errors import ProtocolError
    from steamboat_runtime.protocol.worker_pb2 import Response
    from steamboat_runtime.participant_context import TrustedRequestContext
    from steamboat_security.outbound import ConsumerRequestContext

    if len(worker_nodes) != 2 or len(coordinator.clients) != 3:
        raise CohortError("Step reply-loss profile requires two local and one remote worker")
    request_context = outbound.create_consumer_request_context(lifetime_seconds=120)
    if type(request_context) is not ConsumerRequestContext:
        raise CohortError("Step reply-loss profile lacks trusted consumer request context")
    request_id = request_context.request_id
    _require_string(request_id, label="Step reply-loss request ID",
                    pattern=_TYPED_REQUEST, max_length=36)

    attempts = [dict() for _ in coordinator.clients]
    open_reply_order = []
    original_methods = []
    trace_dropped_before = coordinator.trace_dropped
    session_box = {"value": None}
    request_state_box = {"value": None}
    arm_box = {"value": None}
    step_commit = {"value": None}
    injected = [False]
    try:
        for index, worker_client in enumerate(coordinator.clients):
            original = worker_client.execute
            original_methods.append((worker_client, original))

            async def observe_execute(method, request, *, trusted_request_context=None,
                                      _index=index, _original=original):
                attempts[_index][method] = attempts[_index].get(method, 0) + 1
                if type(trusted_request_context) is not TrustedRequestContext:
                    raise CohortError("Step reply-loss omitted trusted worker context")
                response = await _original(
                    method, request, trusted_request_context=trusted_request_context)
                if method == "OpenSession" and type(response) is Response:
                    if response.code != "OK" or response.session_id != request.session_id:
                        raise CohortError("real OpenSession response was not successful")
                    open_reply_order.append(_index)
                if _index != 2 or method != "Step":
                    return response
                if injected[0] or type(response) is not Response:
                    raise CohortError("Step reply-loss injection was duplicated or malformed")
                if (response.code != "OK"
                        or type(request.session_id) is not str
                        or response.session_id != request.session_id
                        or request.protocol_version != 1
                        or response.protocol_version != 1
                        or request.manifest_fingerprint != expected.manifest_fingerprint
                        or response.manifest_fingerprint != expected.manifest_fingerprint
                        or request.worker_boot_id != expected.boot_id
                        or response.worker_boot_id != expected.boot_id
                        or not request.lease_token
                        or response.lease_token != request.lease_token
                        or type(request.sequence) is not int or request.sequence != 0
                        or type(request.start_position) is not int or request.start_position != 0
                        or type(request.token_count) is not int or request.token_count != 3
                        or type(response.sequence) is not int or response.sequence != 0
                        or type(response.start_position) is not int or response.start_position != 0
                        or type(response.token_count) is not int or response.token_count != 3
                        or type(response.end_position) is not int or response.end_position != 3
                        or type(response.next_sequence) is not int or response.next_sequence != 1
                        or [item.get("OpenSession", 0) for item in attempts] != [1, 1, 1]
                        or open_reply_order != [0, 1, 2]
                        or [item.get("Step", 0) for item in attempts] != [1, 1, 1]):
                    raise CohortError("actual worker-3 first-prefill Step response is invalid")
                _require_string(request.session_id, label="Step reply-loss session ID",
                                pattern=_TYPED_SESSION, max_length=36)
                shape = list(response.tensor.shape)
                request_shape = list(request.tensor.shape)
                hidden = response.hidden_size
                tensor_bytes = response.tensor.byte_count
                if (len(shape) != 3 or any(type(item) is not int for item in shape)
                        or len(request_shape) != 3
                        or any(type(item) is not int for item in request_shape)
                        or type(hidden) is not int or hidden < 1 or hidden > 8192
                        or shape != [1, 3, hidden]
                        or request_shape != [1, 3, hidden]
                        or response.tensor.dtype != "float32_le"
                        or response.tensor.layout != "batch_sequence_hidden"
                        or request.tensor.dtype != "float32_le"
                        or request.tensor.layout != "batch_sequence_hidden"
                        or type(tensor_bytes) is not int or tensor_bytes != 3 * hidden * 4
                        or len(response.tensor.data) != tensor_bytes
                        or request.tensor.byte_count != 3 * hidden * 4
                        or len(request.tensor.data) != request.tensor.byte_count
                        or response.tensor.ByteSize() <= 0):
                    raise CohortError("actual Step response tensor shape or bounds are invalid")
                step_commit["value"] = {
                    "sequence": 0, "start_position": 0, "token_count": 3,
                    "end_position": 3, "next_sequence": 1,
                    "hidden_size": hidden, "tensor_shape": shape,
                    "tensor_dtype": response.tensor.dtype,
                    "tensor_layout": response.tensor.layout,
                    "response_tensor_bytes": len(response.tensor.data),
                    "response_tensor_envelope_bytes": response.tensor.ByteSize(),
                }
                held = await _observe_remote(
                    handoff_fd, expected, sequence=5,
                    case_id="step-reply-loss-held", request_id=request_id,
                    session_id=request.session_id, host_key=host_key,
                    profile=PROFILE_C1B_STEP_LOSS)
                if (held.get("confirmed") is not True
                        or held.get("active_sessions") != 1
                        or held.get("active_session_ids") != [request.session_id]
                        or held.get("committed_cache_bytes", 0) <= 0
                        or held.get("allocated_cache_bytes", 0) < held["committed_cache_bytes"]
                        or held.get("active_compute") is not False
                        or held.get("queued_operations") != 0
                        or held.get("active_authorizations") != 0
                        or held.get("owned_sessions") != 1):
                    raise CohortError("remote worker did not attest the exact committed Step session")
                step_commit["value"].update({
                    "committed_cache_bytes": held["committed_cache_bytes"],
                    "allocated_cache_bytes": held["allocated_cache_bytes"],
                })
                _require_int(held.get("supervisor_monotonic_ns"),
                             label="Step reply-loss disposal arm", minimum=1)
                session_box["value"] = request.session_id
                request_state = coordinator._requests.get(request.session_id)
                if (request_state is None
                        or request_state.session_id != request.session_id
                        or coordinator._requests.get(request.session_id) is not request_state):
                    raise CohortError("Step reply-loss request state was not registered")
                request_state_box["value"] = request_state
                arm_box["value"] = held["supervisor_monotonic_ns"]
                pipeline_state["step_reply_loss_state"] = {
                    "state": "restart_fenced_retained",
                    "logical_cleanup_confirmed": False,
                }
                injected[0] = True
                # SecureWorkerClient has completed and authenticated the real TLS
                # response. The coordinator caller alone loses the reply.
                raise ProtocolError(
                    "EXECUTION_FAILED",
                    "test fault: successful worker-3 Step reply lost at caller boundary")

            worker_client.execute = observe_execute

        events = []
        stream = None
        failure = None
        try:
            stream = client.generate(
                [7, 13, 31], 1, trusted_request_context=request_context,
                capture_logits=True, timeout_seconds=10)
            async for event in stream:
                if type(event) is not dict:
                    raise CohortError("Step reply-loss Generate emitted malformed output")
                events.append(event)
        except BaseException as error:
            failure = error
        finally:
            if stream is not None:
                await stream.aclose()
        if (failure is None or not isinstance(failure, Exception)
                or getattr(failure, "code", None) != "EXECUTION_FAILED"):
            raise CohortError("Step reply-loss did not fail Generate as expected")
        if (not injected[0] or session_box["value"] is None
                or arm_box["value"] is None or step_commit["value"] is None):
            raise CohortError("Step reply-loss did not reach its causal held-session point")
        if trace_dropped_before != coordinator.trace_dropped:
            raise CohortError("coordinator dropped Step reply-loss dispatch evidence")
        session_id = session_box["value"]
        if ([item.get("OpenSession", 0) for item in attempts] != [1, 1, 1]
                or [item.get("Step", 0) for item in attempts] != [1, 1, 1]
                or [item.get("CancelSession", 0) for item in attempts] != [1, 1, 1]):
            raise CohortError("Step reply-loss retried or failed to cancel all known leases")
        dispatches = [item for item in tuple(coordinator.events)
                      if type(item) is dict and item.get("event") == "stage_dispatch"
                      and item.get("session_id") == session_id]
        dispatch_shape = []
        for item in dispatches:
            values = (item.get("worker"), item.get("sequence"),
                      item.get("position"), item.get("token_count"))
            if any(type(value) is not int for value in values):
                raise CohortError("Step reply-loss dispatch trace is malformed")
            dispatch_shape.append(values)
        if sorted(dispatch_shape) != [(1, 0, 0, 3), (2, 0, 0, 3), (3, 0, 0, 3)]:
            raise CohortError("Step reply-loss dispatched a retry or decode Step")
        if (any(event.get("type") == "token" for event in events)
                or any(type(event) is dict and event.get("event") == "token"
                       and event.get("session_id") == session_id
                       for event in tuple(coordinator.events))):
            raise CohortError("Step reply-loss emitted output after losing the first-prefill reply")
        terminal = [event for event in events if event.get("type") == "result"]
        if (len(events) != 1 or len(terminal) != 1 or terminal[0].get("status") != "failed"
                or terminal[0].get("error_code") != "EXECUTION_FAILED"
                or terminal[0].get("token_ids") != []
                or type(terminal[0].get("cleanup_complete")) is not bool
                or terminal[0].get("session_id") != session_id):
            raise CohortError("Step reply-loss terminal event is not the exact failed request")

        state = request_state_box["value"]
        if (state is None or state.session_id != session_id or state.unknown_opens
                or not state.completion.done()
                or state.completion.result().error_code != "EXECUTION_FAILED"
                or state.completion.result().token_ids != ()
                or state.leases or coordinator._live_pending_tasks(state)):
            raise CohortError("Step reply-loss did not confirm cleanup of its three known leases")
        cleanup_complete = state.completion.result().cleanup_complete
        if (type(cleanup_complete) is not bool
                or type(terminal[0].get("cleanup_complete")) is not bool
                or terminal[0]["cleanup_complete"] is not cleanup_complete):
            raise CohortError("Step reply-loss terminal cleanup state differs from coordinator")
        stats = coordinator.stats()
        active_requests = stats.get("active_requests")
        if active_requests not in (0, 1):
            raise CohortError("Step reply-loss active request state is unknown")
        owner_snapshot = None
        cleanup_deadline = asyncio.get_running_loop().time() + 10.0
        while True:
            try:
                owner_snapshot = _local_owner_snapshot(
                    coordinator=coordinator, service=service,
                    secure_service=secure_service, worker_nodes=worker_nodes,
                    capture_budget=capture_budget, transport_budget=transport_budget,
                    expected_connections=15, expected_active_requests=active_requests)
                break
            except CohortError:
                if asyncio.get_running_loop().time() >= cleanup_deadline:
                    raise CohortError("Step reply-loss local owners did not drain") from None
                await asyncio.sleep(0.05)
            stats = coordinator.stats()
            active_requests = stats.get("active_requests")
            if active_requests not in (0, 1):
                raise CohortError("Step reply-loss active request state became unknown")
        stats = coordinator.stats()
        ready = stats.get("ready")
        active_requests = stats.get("active_requests")
        request_state_membership = _step_reply_loss_request_membership(
            coordinator._requests, session_id, state)
        resources_reclaimed = (cleanup_complete and active_requests == 0 and ready is False
                               and request_state_membership == "absent"
                               and not state.leases and not state.unknown_opens
                               and not state.restart_required)
        fenced = (not cleanup_complete and active_requests == 1 and ready is False
                  and request_state_membership == "retained"
                  and not state.leases and not state.unknown_opens
                  and state.restart_required)
        if not (resources_reclaimed or fenced):
            raise CohortError("Step reply-loss cleanup is neither confirmed nor truthfully fenced")
        remote_idle = await _observe_remote(
            handoff_fd, expected, sequence=6,
            case_id="step-reply-loss-reclaimed", request_id=request_id,
            session_id=session_id, host_key=host_key, profile=PROFILE_C1B_STEP_LOSS)
        if (remote_idle.get("confirmed") is not True
                or remote_idle.get("active_sessions") != 0
                or remote_idle.get("active_session_ids") != []
                or remote_idle.get("committed_cache_bytes") != 0
                or remote_idle.get("allocated_cache_bytes") != 0
                or remote_idle.get("active_compute") is not False
                or remote_idle.get("queued_operations") != 0
                or remote_idle.get("active_authorizations") != 0
                or remote_idle.get("owned_sessions") != 0):
            raise CohortError("remote worker did not confirm global idle after known cleanup")
        local_state = {
            "state": ("resources_reclaimed_service_failed" if resources_reclaimed
                      else "restart_fenced_retained"),
            "logical_cleanup_confirmed": resources_reclaimed,
            "request_state_membership": request_state_membership,
            "coordinator_ready": ready,
            "active_requests": active_requests,
            "known_leases_reclaimed": True,
            "active_streams": owner_snapshot["active_streams"],
            "active_generate_streams": owner_snapshot["active_generate_streams"],
            "active_captures": owner_snapshot["active_captures"],
            "capture_reserved_bytes": owner_snapshot["capture_reserved_bytes"],
            "worker_sessions": owner_snapshot["worker_sessions"],
            "worker_active_compute": owner_snapshot["worker_active_compute"],
            "transport_reserved_connections": owner_snapshot["transport_reserved_connections"],
            "transport_reserved_pending": owner_snapshot["transport_reserved_pending"],
        }
        pipeline_state["step_reply_loss_state"] = local_state
        result["step_reply_loss"] = {
            "profile": PROFILE_C1B_STEP_LOSS, "status": "passed",
            "request_id": request_id, "session_id": session_id,
            "open_attempts": [1, 1, 1], "step_attempts": [1, 1, 1],
            "cancel_attempts": [1, 1, 1],
            "step_reply_validated": True, "caller_boundary_reply_loss": True,
            "remote_held_session_confirmed": True,
            "remote_reclaimed_confirmed": True,
            "known_leases_reclaimed": True,
            "token_ids_emitted": [],
            "step_commit": step_commit["value"],
            "supervisor_arm_monotonic_ns": arm_box["value"],
            "local_state": local_state,
        }
        result["pending_scope"] = [item for item in result["pending_scope"]
                                   if item != "step_reply_loss"]
    finally:
        request_context.close()
        for worker_client, original in reversed(original_methods):
            worker_client.execute = original


async def _run_c1b_capacity_extension(*, torch, reference, client, outbound,
                                     coordinator, service, secure_service,
                                     worker_nodes, capture_budget, transport_budget,
                                     handoff_fd, expected, host_key, result):
    """Hold eight real captured requests, prove ninth preflight rejection, drain all."""
    import threading
    from steamboat_runtime.remote_client import RemoteError
    from steamboat_security import ConsumerRequestContext

    if len(worker_nodes) != 2 or len(coordinator.clients) != 3:
        raise CohortError("capacity profile requires the fixed two-local/one-remote cohort")
    executor = worker_nodes[0]["executor"]
    original_executor = executor.execute
    original_clients = [(item, item.execute) for item in coordinator.clients]
    original_submit = coordinator.submit
    entered, release, gate_failed = threading.Event(), threading.Event(), threading.Event()
    held = [False]
    attempts = [dict() for _ in coordinator.clients]
    submit_count = [0]
    trace_before = coordinator.trace_dropped
    base_events = len(coordinator.events)
    tasks = []

    def gated_execute(hidden, cache, position):
        output = original_executor(hidden, cache, position)
        if not held[0]:
            held[0] = True
            entered.set()
            if not release.wait(30.0):
                gate_failed.set()
                raise TimeoutError("capacity StageExecutor hold exceeded its bound")
        return output

    def count_submit(*args, **kwargs):
        submit_count[0] += 1
        return original_submit(*args, **kwargs)

    prompt = [7]
    expected_row = _reference_last_row(reference, torch, prompt)
    expected_token = int(expected_row.argmax().item())

    executor.execute = gated_execute
    coordinator.submit = count_submit
    for index, (worker_client, original) in enumerate(original_clients):
        async def counted_execute(method, request, *, trusted_request_context=None,
                                  _index=index, _original=original):
            attempts[_index][method] = attempts[_index].get(method, 0) + 1
            return await _original(method, request,
                                   trusted_request_context=trusted_request_context)
        worker_client.execute = counted_execute

    async def generate_one():
        comparisons = []
        request_id, events = await _secure_generate(
            client, outbound, prompt, new_tokens=1, capture_logits=True,
            on_token=_capture_comparator(torch, expected_row.unsqueeze(0), 1, comparisons))
        _check_generated_events(events, request_id, [expected_token], capture=True,
                                prompt_length=1, comparisons=comparisons)
        if len(comparisons) != 1:
            raise CohortError("capacity request did not return exactly one captured vector")
        return {"request_id": request_id, "session_id": events[0]["session_id"],
                "token_id": expected_token, "error": comparisons[0]["max_abs_error"]}

    try:
        for _ in range(8):
            tasks.append(asyncio.create_task(generate_one()))
        deadline = asyncio.get_running_loop().time() + 45.0
        while not entered.is_set():
            if any(task.done() for task in tasks):
                await asyncio.gather(*tasks)
                raise CohortError("capacity cohort ended before the real stage hold")
            if asyncio.get_running_loop().time() >= deadline:
                raise CohortError("capacity cohort did not reach the real stage hold")
            await asyncio.sleep(0.02)

        def held_state():
            states = list(coordinator._requests.values())
            if len(states) != 8 or any(item.trusted_request_context is None for item in states):
                return None
            pairs = []
            for item in states:
                context = item.trusted_request_context
                request_id, session_id = context.request_id, item.session_id
                if (_TYPED_REQUEST.fullmatch(request_id) is None
                        or _TYPED_SESSION.fullmatch(session_id) is None):
                    return None
                pairs.append((request_id, session_id))
            pairs.sort(key=lambda pair: pair[1])
            return states, pairs

        states_and_pairs = None
        while states_and_pairs is None:
            if gate_failed.is_set() or any(task.done() for task in tasks):
                raise CohortError("capacity request ended before the held queue topology was observed")
            candidate = held_state()
            if candidate is not None:
                states, pairs = candidate
                active_jobs = coordinator._active_jobs
                queued_jobs = tuple(coordinator._queues[0].items)
                if (capture_budget.status().active_captures == 8
                        and coordinator.stats().get("active_requests") == 8
                        and all(len(node["handler"].sessions) == 8 for node in worker_nodes)
                        and attempts[0].get("OpenSession", 0) == 8
                        and attempts[1].get("OpenSession", 0) == 8
                        and attempts[2].get("OpenSession", 0) == 8
                        and _capacity_held_queue_active_session(
                            active_jobs[0], queued_jobs,
                            [item[1] for item in pairs], active_jobs=active_jobs,
                            stage_count=len(coordinator.clients)) is not None):
                    states_and_pairs = (states, pairs)
                    break
            if asyncio.get_running_loop().time() >= deadline:
                raise CohortError("eight live captures and OpenSession leases were not observed")
            await asyncio.sleep(0.02)
        states, pairs = states_and_pairs
        request_ids = [item[0] for item in pairs]
        session_ids = [item[1] for item in pairs]
        if (len(set(request_ids)) != 8 or len(set(session_ids)) != 8
                or set(request_ids) & set(result.get("request_ids", ()))
                or set(session_ids) & set(result.get("session_ids", ()))
                or [item.get("OpenSession", 0) for item in attempts] != [8, 8, 8]
                or submit_count[0] != 8
                or capture_budget.status().active_captures != 8
                or capture_budget.status().reserved_bytes
                   != 8 * capture_budget.status().per_capture.total_bytes
                or coordinator.stats().get("active_requests") != 8):
            raise CohortError("capacity profile did not own exactly eight fresh requests")
        first_handler = worker_nodes[0]["handler"]
        active_job = coordinator._active_jobs[0]
        queued_jobs = tuple(coordinator._queues[0].items)
        active_session = _capacity_held_queue_active_session(
            active_job, queued_jobs, session_ids,
            active_jobs=coordinator._active_jobs, stage_count=len(coordinator.clients))
        if active_session is None:
            raise CohortError("seven other capacity requests were not queued behind the held prefill")
        in_flight = [entry for entry in first_handler.sessions.values() if entry.in_flight]
        owned_layers = executor.end - executor.start
        if (type(owned_layers) is not int or owned_layers < 1
                or len(in_flight) != 1
                or in_flight[0].cache.lengths() != [1] * owned_layers
                or in_flight[0].cache.allocated_bytes() <= 0):
            raise CohortError("worker-1 did not hold the actual mutated first-prefill cache")
        if (any(any(entry.cache.lengths()) for node in worker_nodes[1:]
                 for entry in node["handler"].sessions.values())
                or [item.get("Step", 0) for item in attempts] != [1, 0, 0]
                or transport_budget.reserved_connections != 15
                or transport_budget.reserved_pending != 0
                or transport_budget.reserved_outbound_pending != 0):
            raise CohortError("held capacity cohort has unexpected downstream work or transport")

        # The sequence-5 ACK is armed by the parent only after its independent
        # SSH read confirms exactly these eight remote OpenSession owners.
        held_remote = await _observe_remote(
            handoff_fd, expected, sequence=5, case_id="capacity-eight-held",
            request_id=request_ids[0], session_id=session_ids[0],
            host_key=host_key, profile=PROFILE_C1B_CAPACITY,
            expected_session_ids=session_ids)
        arm_ns = held_remote.get("supervisor_monotonic_ns")
        _require_int(arm_ns, label="capacity disposal arm", minimum=1)

        before_submit = submit_count[0]
        before_open = [item.get("OpenSession", 0) for item in attempts]
        before_step = [item.get("Step", 0) for item in attempts]
        before_used_ids = capture_budget.status().used_request_ids
        consumer_channel = client.channel
        original_tensor = torch.tensor
        tensor_allocations = [0]
        def count_tensor(*args, **kwargs):
            tensor_allocations[0] += 1
            return original_tensor(*args, **kwargs)
        rejected_context = outbound.create_consumer_request_context(lifetime_seconds=120)
        if type(rejected_context) is not ConsumerRequestContext:
            raise CohortError("ninth request has no trusted consumer context")
        rejected_stream = None
        rejected = None
        torch.tensor = count_tensor
        try:
            rejected_stream = client.generate(
                prompt, 1, trusted_request_context=rejected_context,
                capture_logits=True, timeout_seconds=10)
            async for _event in rejected_stream:
                raise CohortError("capacity-rejected ninth request emitted output")
        except BaseException as error:
            rejected = error
        finally:
            try:
                if rejected_stream is not None:
                    await rejected_stream.aclose()
            finally:
                torch.tensor = original_tensor
                rejected_context.close()
        refusal_deadline = asyncio.get_running_loop().time() + 10.0
        while (secure_service.active_generate_streams != 8
               or service.active_streams != 8):
            if asyncio.get_running_loop().time() >= refusal_deadline:
                raise CohortError("ninth capacity refusal did not release its stream slot")
            await asyncio.sleep(0.02)
        if (not isinstance(rejected, RemoteError)
                or rejected.code != "CAPACITY_EXHAUSTED"
                or submit_count[0] != before_submit
                or [item.get("OpenSession", 0) for item in attempts] != before_open
                or [item.get("Step", 0) for item in attempts] != before_step
                or tensor_allocations[0] != 0
                or capture_budget.status().used_request_ids != before_used_ids
                or capture_budget.status().active_captures != 8
                or capture_budget.status().reserved_bytes
                   != 8 * capture_budget.status().per_capture.total_bytes
                or coordinator.stats().get("active_requests") != 8
                or coordinator.stats().get("waiting_admissions") != 0
                or len(coordinator._requests) != 8
                or len({len(node["handler"].sessions) for node in worker_nodes}) != 1
                or any(len(node["handler"].sessions) != 8 for node in worker_nodes)
                or getattr(secure_service, "unavailable", False)
                or client.channel is not consumer_channel):
            raise CohortError("ninth capture was not rejected before submit or worker contact")

        release.set()
        outcomes = await asyncio.wait_for(asyncio.gather(*tasks), timeout=90.0)
        if gate_failed.is_set() or not held[0]:
            raise CohortError("capacity StageExecutor gate did not retire")
        if ([item.get("OpenSession", 0) for item in attempts] != [8, 8, 8]
                or [item.get("Step", 0) for item in attempts] != [8, 8, 8]
                or submit_count[0] != before_submit):
            raise CohortError("capacity cohort retried or dispatched a ninth request")
        by_session = {item["session_id"]: item for item in outcomes}
        if not _capacity_outcomes_match(pairs, outcomes, session_ids):
            raise CohortError("capacity request/session identities changed during drain")
        errors = [by_session[session]["error"] for session in session_ids]
        if (len(errors) != 8 or any(type(error) not in (int, float)
                                    or not math.isfinite(error) or error < 0 or error > 1e-3
                                   for error in errors)):
            raise CohortError("capacity vectors failed the complete-model reference")
        token_ids = [by_session[session]["token_id"] for session in session_ids]
        if token_ids != [expected_token] * 8:
            raise CohortError("capacity cohort produced inconsistent greedy tokens")
        local = await _wait_local_cleanup(
            coordinator=coordinator, service=service, secure_service=secure_service,
            worker_nodes=worker_nodes, capture_budget=capture_budget,
            transport_budget=transport_budget, expected_connections=15)
        if (local.get("confirmed") is not True or local.get("active_requests") != 0
                or local.get("active_captures") != 0 or local.get("worker_sessions") != 0
                or local.get("worker_active_compute") is not False):
            raise CohortError("local eight-request capacity owners did not drain")
        remote_idle = await _observe_remote(
            handoff_fd, expected, sequence=6, case_id="capacity-eight-reclaimed",
            request_id=request_ids[0], session_id=session_ids[0],
            host_key=host_key, profile=PROFILE_C1B_CAPACITY)
        if (remote_idle.get("confirmed") is not True
                or remote_idle.get("active_sessions") != 0
                or remote_idle.get("active_session_ids") != []
                or remote_idle.get("committed_cache_bytes") != 0
                or remote_idle.get("allocated_cache_bytes") != 0
                or remote_idle.get("owned_sessions") != 0):
            raise CohortError("remote worker did not confirm global idle after capacity drain")
        if coordinator.trace_dropped != trace_before:
            raise CohortError("capacity run dropped coordinator lifecycle evidence")
        result["capacity"] = {
            "profile": PROFILE_C1B_CAPACITY, "status": "passed",
            "completed_requests": 8, "captured_vectors": len(errors),
            "comparison_errors": errors, "max_absolute_error": max(errors),
            "request_ids": request_ids, "session_ids": session_ids,
            "token_ids": token_ids,
            "ninth_rejection": {
                "error_code": rejected.code, "coordinator_submits": 0,
                "tensor_allocations": tensor_allocations[0],
                "worker_open_attempts": [0, 0, 0], "worker_step_attempts": [0, 0, 0],
                "used_request_ids_unchanged": True,
            },
            "remote_held_confirmed": True, "remote_reclaimed_confirmed": True,
            "local_owner_check": local, "supervisor_arm_monotonic_ns": arm_ns,
        }
        result["pending_scope"] = [item for item in result["pending_scope"]
                                   if item != "capacity_faults"]
    finally:
        release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        try:
            if tasks:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True),
                                       timeout=15.0)
        finally:
            executor.execute = original_executor
            coordinator.submit = original_submit
            for worker_client, original in reversed(original_clients):
                worker_client.execute = original


def _release_reference(reference_box):
    reference_box["model"] = None
    gc.collect()


def _capacity_held_queue_active_session(
        active_job, queued_jobs, expected_session_ids, *, active_jobs, stage_count):
    """Return the active session only for the exact held 1+7 scheduler topology."""
    if (type(active_jobs) is not list or type(stage_count) is not int or stage_count != 3
            or len(active_jobs) != stage_count or active_jobs[0] is not active_job
            or any(item is not None for item in active_jobs[1:])
            or type(expected_session_ids) is not list or len(expected_session_ids) != 8
            or any(type(item) is not str or _TYPED_SESSION.fullmatch(item) is None
                   for item in expected_session_ids)
            or len(set(expected_session_ids)) != 8
            or type(queued_jobs) is not tuple or len(queued_jobs) != 7):
        return None
    request = getattr(active_job, "request", None)
    active_session = getattr(request, "session_id", None)
    sequence = getattr(active_job, "sequence", None)
    position = getattr(active_job, "position", None)
    if (type(active_session) is not str or _TYPED_SESSION.fullmatch(active_session) is None
            or active_session not in expected_session_ids
            or type(sequence) is not int or sequence != 0
            or type(position) is not int or position != 0):
        return None
    queued_sessions = []
    for job in queued_jobs:
        queued_request = getattr(job, "request", None)
        session_id = getattr(queued_request, "session_id", None)
        if type(session_id) is not str or _TYPED_SESSION.fullmatch(session_id) is None:
            return None
        queued_sessions.append(session_id)
    if (len(set(queued_sessions)) != 7
            or set(queued_sessions) != set(expected_session_ids) - {active_session}):
        return None
    return active_session


def _capacity_outcomes_match(expected_pairs, outcomes, expected_session_ids):
    """Check the complete request/session bijection in both orientations."""
    if (type(expected_pairs) is not list or type(outcomes) is not list
            or type(expected_session_ids) is not list):
        return False
    try:
        expected_by_request = dict(expected_pairs)
        expected_by_session = {session_id: request_id
                               for request_id, session_id in expected_pairs}
        actual_by_request = {item["request_id"]: item["session_id"] for item in outcomes}
        actual_by_session = {item["session_id"]: item["request_id"] for item in outcomes}
    except (KeyError, TypeError, ValueError):
        return False
    return (
        len(expected_by_request) == len(expected_pairs) == len(outcomes)
        and len(actual_by_request) == len(outcomes)
        and len(actual_by_session) == len(outcomes)
        and set(actual_by_session) == set(expected_session_ids)
        and actual_by_request == expected_by_request
        and actual_by_session == expected_by_session
    )


def _step_reply_loss_request_membership(requests, session_id, expected_state):
    """Report whether coordinator cleanup removed the captured request object."""
    current = requests.get(session_id)
    if current is None:
        return "absent"
    if current is expected_state:
        return "retained"
    return "replaced"


async def _close_coordinator(coordinator_holder):
    coordinator = coordinator_holder.get("coordinator")
    if coordinator is not None:
        if await coordinator.close() is not True:
            raise CohortError("coordinator shutdown did not confirm cleanup",
                              cleanup_component="coordinator_close")
        coordinator_holder["coordinator"] = None


async def _close_model(model_holder):
    model = model_holder.get("model")
    if model is not None:
        result = model.close()
        if hasattr(result, "__await__"):
            result = await result
        if result is not True:
            raise CohortError("coordinator model shutdown did not confirm cleanup")
        model_holder["model"] = None


async def _close_local_pipeline(owner: _CleanupOwner, state: dict,
                                *, expected_connections: int):
    errors = await owner.close()
    budget = state.get("transport_budget")
    if budget is not None:
        if (budget.reserved_connections != 0 or budget.reserved_pending != 0
                or budget.reserved_listener_pending_capacity != 0
                or budget.reserved_outbound_pending != 0):
            errors.append(CohortError("local transport reservations remain after shutdown"))
    for node in state.get("worker_nodes", ()):
        handler = node.get("handler")
        if handler is not None and (handler.sessions or handler._queue
                                    or handler._active_operation is not None):
            errors.append(CohortError("local worker retained sessions or active work at shutdown"))
    if state.get("service") is not None:
        service = state["service"]
        if service.active_streams != 0 or service.cleanups:
            errors.append(CohortError(
                "local coordinator service retained stream cleanup owners",
                cleanup_component="coordinator_service_streams"))
    secure = state.get("secure_service")
    if secure is not None and secure.active_generate_streams != 0:
        errors.append(CohortError(
            "secure coordinator retained Generate stream owners",
            cleanup_component="secure_generate_streams"))
    return errors


def _private_result_summary(result: dict, *, profile: str = PROFILE_BASELINE) -> dict:
    """Keep result output to bounded IDs, numerical errors, and owner evidence."""
    if not set(result) <= HANDOFF_RESULT_FIELDS:
        raise CohortError("result contains an unapproved field")
    owner_profile = profile in (PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE)
    if owner_profile and result.get("baseline", {}).get("status") == "passed" \
            and "owner_actions" not in result:
        raise CohortError("successful owner profile omitted its required owner actions")
    if "owner_actions" in result:
        actions = result["owner_actions"]
        if (not owner_profile or type(actions) is not dict
                or actions.get("profile") not in (
                    PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE)
                or actions.get("profile") != profile
                or any(name in result for name in (
                    "interleave", "cancellation", "partial_admission",
                    "step_reply_loss", "capacity", "restart"))):
            raise CohortError("owner action evidence is outside its two fixed profiles")
    return result


async def _stop_remote(directory_fd: int, *, run_id: str, nonce: str,
                       boot_id: str | None, may_have_started: bool,
                       readiness_observed: bool,
                       host_key: str | None,
                       expected: RemoteExpectation | None):
    request = build_stop_request(
        run_id=run_id, nonce=nonce,
        boot_id=boot_id if may_have_started else None,
        may_have_started=may_have_started)
    _safe_write_handoff(directory_fd, HANDOFF_STOP_REQUEST_FILE, request)
    ack = await _wait_for_control(
        directory_fd, HANDOFF_STOP_ACK_FILE, timeout=STOP_TIMEOUT_SECONDS)
    return validate_stop_ack(
        ack, run_id=run_id, nonce=nonce,
        expected_boot_id=boot_id if may_have_started else None,
        may_have_started=may_have_started,
        readiness_observed=readiness_observed, expected_host_key=host_key,
        expected=expected if may_have_started else None)


async def _stop_remote_owner(directory_fd, *, expected, owner_expected,
                             worker_config, host_key, last_command,
                             readiness_observed):
    """Stop an owner-profile worker using the actual owner-only raw-status parser."""
    request = build_stop_request(
        run_id=expected.run_id, nonce=expected.nonce,
        boot_id=expected.boot_id, may_have_started=True)
    _safe_write_handoff(directory_fd, HANDOFF_STOP_REQUEST_FILE, request)
    payload = await _wait_for_control(
        directory_fd, HANDOFF_STOP_ACK_FILE, timeout=STOP_TIMEOUT_SECONDS)
    _exact_fields(payload, HANDOFF_STOP_ACK_FIELDS, label="owner stop acknowledgement")
    expected_values = {
        "schema_version": 1, "event": "stop_ack", "run_id": expected.run_id,
        "nonce": expected.nonce, "boot_id": expected.boot_id,
        "shutdown_confirmed": True,
    }
    for name, value in expected_values.items():
        if type(payload.get(name)) is not type(value) or payload.get(name) != value:
            raise CohortError(f"owner stop acknowledgement mismatch: {name}")
    if payload["process_state"] == "not_started":
        return validate_stop_ack(
            payload, run_id=expected.run_id, nonce=expected.nonce,
            expected_boot_id=expected.boot_id, may_have_started=True,
            readiness_observed=readiness_observed,
            expected_host_key=host_key, expected=expected)
    if payload["process_state"] != "exited":
        raise CohortError("owner stop did not confirm actual worker process exit")
    if last_command is None:
        raise CohortError("started owner worker has no validated command ACK for final status")
    exit_code = _require_int(payload["exit_code"], label="owner worker exit code", maximum=255)
    if exit_code != 0:
        raise CohortError("owner worker process did not exit successfully")
    actual_host_key = _require_string(payload["ssh_host_key_sha256"],
                                      label="owner stop SSH key", pattern=_HEX64,
                                      max_length=64)
    if actual_host_key != host_key:
        raise CohortError("owner stop SSH host key changed during the cohort")
    if (_require_int(payload["remote_status_uid"], label="owner final status UID")
            != REMOTE_STATUS_UID
            or _require_int(payload["remote_status_mode"], label="owner final status mode")
            != REMOTE_STATUS_MODE
            or payload["measurement_label"] != STOP_LABEL):
        raise CohortError("owner final status provenance is invalid")
    status = payload["remote_status"]
    if type(status) is not dict or status.get("event") != "final":
        raise CohortError("owner stop lacks actual terminal worker status")
    _validate_owner_status_frame(status, owner_expected, worker_config,
                                 command=last_command, observation=False)
    return {"confirmed": True, "process_state": "exited", "exit_code": exit_code,
            "shutdown_overall": "confirmed", "worker_boot_id": expected.boot_id}


def _publish_bundle_ready(directory_fd: int, bundle_ready: dict, *,
                          boot_id: str, launch_state: dict) -> None:
    _require_string(boot_id, label="worker boot ID", pattern=_HEX32, max_length=32)
    launch_state["boot_id"] = boot_id
    launch_state["may_have_started"] = True
    _safe_write_handoff(directory_fd, HANDOFF_BUNDLE_READY_FILE, bundle_ready)


def _record_remote_shutdown(result: dict, remote_shutdown: dict,
                            cleanup_errors: list) -> None:
    result["remote_shutdown"] = remote_shutdown
    if (result["baseline"]["status"] == "passed"
            and (remote_shutdown.get("process_state") != "exited"
                 or remote_shutdown.get("exit_code") != 0)):
        result["baseline"]["status"] = "failed"
        cleanup_errors.append(CohortError(
            "remote worker did not exit successfully after the baseline"))


def _load_identity_fixture():
    try:
        from secure_pipeline_fixture import SecurePipelineIdentityFixture
    except ModuleNotFoundError as error:
        if error.name != "secure_pipeline_fixture":
            raise
        from tests.security.secure_pipeline_fixture import SecurePipelineIdentityFixture
    return SecurePipelineIdentityFixture


def _create_authority_fixture(fixture_class, *, handoff_directory,
                              fingerprint, external_ip, uncertainty):
    import tempfile

    previous_tempdir = tempfile.tempdir
    tempfile.tempdir = str(handoff_directory)
    try:
        authority = fixture_class(
            fingerprint,
            ip_sans_by_principal={"worker-3": (external_ip,)},
            clock_uncertainty_seconds=uncertainty)
    finally:
        tempfile.tempdir = previous_tempdir
    try:
        root = Path(authority.root)
        handoff_root = Path(handoff_directory).resolve(strict=True)
        root.resolve(strict=True).relative_to(handoff_root)
        info = root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise CohortError("C0 authority fixture root failed owner/mode validation")
    except BaseException as primary:
        try:
            authority.close()
        except BaseException as cleanup:
            raise BaseExceptionGroup(
                "authority path validation and cleanup failed", [primary, cleanup])
        if isinstance(primary, CohortError):
            raise
        raise CohortError("C0 authority fixture escaped or failed private-root validation") from None
    return authority


def _recording_outbound_authorizer(delegate, observations):
    """Delegate unchanged C0 authorization and retain only its validated IDs."""
    from steamboat_security.codec import METADATA_KEY, WORKER_SERVICE, parse_metadata

    recording = {"enabled": True}

    class RecordingOutbound:
        def authorize_outbound(self, *, service, method, payload,
                               trusted_request_context, peer_certificate_pem):
            authorization = delegate.authorize_outbound(
                service=service, method=method, payload=payload,
                trusted_request_context=trusted_request_context,
                peer_certificate_pem=peer_certificate_pem)
            if (recording["enabled"] and service == WORKER_SERVICE
                    and method != "Describe"):
                parsed = parse_metadata(
                    service, method,
                    ((METADATA_KEY, authorization.binding_bytes),))
                fields = parsed.fields
                names = ("operation_id", "request_id", "session_id", "route_id",
                         "route_epoch", "attempt", "worker_boot_id")
                if any(name not in fields for name in names):
                    raise CohortError("actual worker binding omitted a required session identity")
                observations.append({"method": method,
                                     **{name: fields[name] for name in names}})
                if len(observations) > 4:
                    raise CohortError("restart binding observer exceeded its four-call bound")
            return authorization

    return RecordingOutbound()


def _recording_owner_outbound_authorizer(delegate, observations, *, maximum_calls):
    """Record bounded owner RPC bindings from the actual delegated metadata."""
    from steamboat_security.codec import METADATA_KEY, WORKER_SERVICE, parse_metadata
    if type(maximum_calls) is not int or maximum_calls not in (4, 5):
        raise CohortError("owner RPC recorder requires the fixed four- or five-call bound")

    class RecordingOutbound:
        def authorize_outbound(self, *, service, method, payload,
                               trusted_request_context, peer_certificate_pem):
            authorization = delegate.authorize_outbound(
                service=service, method=method, payload=payload,
                trusted_request_context=trusted_request_context,
                peer_certificate_pem=peer_certificate_pem)
            if service == WORKER_SERVICE and method != "Describe":
                if len(observations) >= maximum_calls:
                    raise CohortError("owner RPC recorder exceeded its fixed method bound")
                parsed = parse_metadata(
                    service, method,
                    ((METADATA_KEY, authorization.binding_bytes),))
                fields = parsed.fields
                names = ("operation_id", "request_id", "session_id", "route_id",
                         "route_epoch", "attempt", "worker_boot_id")
                if any(name not in fields for name in names):
                    raise CohortError("actual owner binding omitted a required identity")
                observations.append({"method": method,
                                     **{name: fields[name] for name in names}})
            return authorization

    return RecordingOutbound()


def _serial_preface_authorizer(old_context, new_context, old_authorizer,
                               new_authorizer, preface_bindings, *, old_method):
    """Route only the two frozen restart routes to their original authorities."""
    from steamboat_security.codec import METADATA_KEY, WORKER_SERVICE, parse_metadata

    class RoutedAuthorizer:
        def __init__(self):
            self.old_authorizer = old_authorizer
            self.new_authorizer = new_authorizer

        def authorize_outbound(self, *, service, method, payload,
                               trusted_request_context, peer_certificate_pem):
            if (service == WORKER_SERVICE and method == "Describe"
                    and trusted_request_context is new_context):
                delegate = new_authorizer
                is_preface = True
            elif (service == WORKER_SERVICE and method == old_method
                    and trusted_request_context is old_context):
                delegate = old_authorizer
                is_preface = False
            else:
                raise CohortError("restart routed authorizer rejected an unconfigured route")
            authorization = delegate.authorize_outbound(
                service=service, method=method, payload=payload,
                trusted_request_context=trusted_request_context,
                peer_certificate_pem=peer_certificate_pem)
            if is_preface:
                parsed = parse_metadata(
                    service, method, ((METADATA_KEY, authorization.binding_bytes),))
                fields = parsed.fields
                required = ("operation_id", "worker_boot_id", "assignment_id",
                            "target_device_id")
                if any(name not in fields for name in required):
                    raise CohortError("actual C0 Describe binding omitted target identity")
                preface_bindings.append({"for_method": None, "method": method,
                                         **{name: fields[name] for name in required}})
            return authorization

    return RoutedAuthorizer()


async def _restart_channel_snapshot(client):
    """Return actual channel and connector identities after a successful RPC."""
    channel = client._subchannel.channel
    connector = client._subchannel.connector
    if channel is None or connector is None:
        raise CohortError("restart preface did not establish its secure subchannel")
    return channel, connector


def _guard_restart_dispatch(client, channel, connector):
    """Guard channel recreation at stale dispatch; never open a replacement."""
    original = client._ensure_channel

    state = {"same_channel_and_connector_at_dispatch": False}

    async def guarded(timeout, absolute_deadline=None):
        current_channel = client._subchannel.channel
        current_connector = client._subchannel.connector
        if current_channel is not channel or current_connector is not connector:
            raise CohortError("stale restart dispatch replaced its authenticated transport")
        returned = await original(timeout, absolute_deadline)
        if (returned is not channel or client._subchannel.channel is not channel
                or client._subchannel.connector is not connector):
            raise CohortError("stale restart dispatch changed channel or connector identity")
        state["same_channel_and_connector_at_dispatch"] = True
        return returned

    client._ensure_channel = guarded
    return state


def _assert_restart_describe(response, boot_id: str) -> dict:
    expected = {
        "worker_boot_id": boot_id,
        "ready": True,
        "active_sessions": 0,
        "reserved_positions": 0,
        "allocated_cache_bytes": 0,
        "active_operations": 0,
        "queued_operations": 0,
        "tombstones": 0,
        "cache_bytes_exact": True,
        "requires_restart": False,
    }
    for field, value in expected.items():
        actual = getattr(response, field, None)
        if type(actual) is not type(value) or actual != value:
            raise CohortError(f"fresh new-target Describe is not globally idle at {field}")
    if response.code != "OK":
        raise CohortError("fresh new-target Describe was not successful")
    return {field: getattr(response, field) for field in expected}


def _validate_restart_idle_projection(value: dict, boot_id: str, label: str) -> None:
    expected = {
        "worker_boot_id": boot_id, "ready": True, "active_sessions": 0,
        "reserved_positions": 0, "allocated_cache_bytes": 0,
        "active_operations": 0, "queued_operations": 0, "tombstones": 0,
        "cache_bytes_exact": True, "requires_restart": False,
    }
    _exact_fields(value, set(expected), label=label)
    for key, wanted in expected.items():
        if type(value.get(key)) is not type(wanted) or value[key] != wanted:
            raise CohortError(f"{label} differs from the validated new-target Describe")


def _native_unauthenticated(error) -> bool:
    import grpc

    visited = set()
    pending = [error]
    depth = 0
    while pending and depth < 3:
        current = pending.pop(0)
        if current is None or id(current) in visited:
            continue
        visited.add(id(current))
        if (isinstance(current, grpc.aio.AioRpcError)
                and current.code() is grpc.StatusCode.UNAUTHENTICATED):
            return True
        pending.extend((getattr(current, "__cause__", None),
                        getattr(current, "__context__", None)))
        depth += 1
    return False


def _new_baseline_result():
    return {
        "baseline": {"status": "failed", "completed_requests": 0,
                     "captured_vectors": 0,
                     "lifecycle_extensions": "pending_separate_C1b_gate"},
        "identities": {}, "request_ids": [], "session_ids": [],
        "numerical_errors": {"captured_vectors": 0, "values": [],
                             "atol": 1e-3, "rtol": 0.0},
        "cases": [],
    }


_RESTART_HELD_STATUS_FIELDS = (
    "worker_boot_id", "active_sessions", "active_session_ids",
    "queued_operations", "active_compute", "cache_bytes_exact",
    "committed_cache_bytes", "allocated_cache_bytes",
    "active_authorizations", "owned_sessions",
    "transport_reserved_connections",
)
_RESTART_HELD_OBSERVATION_ENVELOPE_FIELDS = (
    "confirmed", "sequence", "case_id", "request_id", "session_id",
    "remote_mark_ns", "supervisor_monotonic_ns", "heartbeat_mtime_ns",
    "measurement_label",
)


def _restart_held_status_projection(validated_observation: dict) -> dict:
    """Project an exact validated observation into the fixed restart result schema."""
    _exact_fields(
        validated_observation,
        _RESTART_HELD_STATUS_FIELDS + _RESTART_HELD_OBSERVATION_ENVELOPE_FIELDS,
        label="validated restart held observation")
    return {field: validated_observation[field]
            for field in _RESTART_HELD_STATUS_FIELDS}


def _validate_restart_result(result: dict) -> None:
    """Fail closed on the fixed successful producer result projection."""
    restart_fields = {
        "profile", "status", "scope", "old_boot_id", "new_boot_id",
        "old_snapshot_sha256", "new_snapshot_sha256",
        "old_owner_receipt_sha256", "old_local_shutdown", "direct_probe",
        "stale_binding_rejections", "new_baseline", "probe_cleanup",
        "same_leaf_continuity",
    }
    _exact_fields(result.get("restart"), restart_fields, label="restart result")
    restart = result["restart"]
    if (restart["profile"] != PROFILE_C1B_RESTART or restart["status"] != "passed"
            or restart["scope"] != "remote_worker_between_rpcs"):
        raise CohortError("restart result profile/status/scope is inconsistent")
    _require_string(restart["old_boot_id"], label="old restart boot", pattern=_HEX32,
                    max_length=32)
    _require_string(restart["new_boot_id"], label="new restart boot", pattern=_HEX32,
                    max_length=32)
    if restart["old_boot_id"] == restart["new_boot_id"]:
        raise CohortError("restart result reused its worker boot ID")
    for field in ("old_snapshot_sha256", "new_snapshot_sha256",
                  "old_owner_receipt_sha256"):
        _require_string(restart[field], label=field, pattern=_HEX64, max_length=64)
    if restart["old_snapshot_sha256"] == restart["new_snapshot_sha256"]:
        raise CohortError("restart result did not advance its signed snapshot")
    _exact_fields(restart["old_local_shutdown"],
                  {"confirmed", "failure_types"}, label="old local shutdown")
    if restart["old_local_shutdown"] != {"confirmed": True, "failure_types": []}:
        raise CohortError("old local pipeline cleanup was not confirmed")
    old_baseline = result.get("baseline")
    if (type(old_baseline) is not dict or old_baseline.get("status") != "passed"
            or old_baseline.get("completed_requests") != 4
            or old_baseline.get("captured_vectors") != 27):
        raise CohortError("original old-generation baseline is incomplete")
    if (result.get("local_shutdown") != {"confirmed": True, "failure_types": []}
            or type(result.get("remote_shutdown")) is not dict
            or result["remote_shutdown"].get("confirmed") is not True
            or result["remote_shutdown"].get("process_state") != "exited"
            or result["remote_shutdown"].get("exit_code") != 0
            or result["remote_shutdown"].get("worker_boot_id") != restart["new_boot_id"]):
        raise CohortError("final local/new-remote owner cleanup is not confirmed")

    direct = restart["direct_probe"]
    _exact_fields(direct, {"request_id", "session_id", "route_id", "route_epoch",
                           "attempt", "open_response", "step_response", "held_status",
                           "bindings", "new_target_before", "client_replacement"},
                  label="direct probe")
    _require_string(direct["request_id"], label="probe request ID",
                    pattern=_TYPED_REQUEST, max_length=36)
    _require_string(direct["session_id"], label="probe session ID",
                    pattern=_TYPED_SESSION, max_length=36)
    _require_string(direct["route_id"], label="probe route ID",
                    pattern=_TYPED_ROUTE, max_length=38)
    for field in ("route_epoch", "attempt"):
        if type(direct[field]) is not int or direct[field] != 1:
            raise CohortError(f"restart probe {field} is not the fresh route value")
    _exact_fields(direct["open_response"], {"session_id", "worker_boot_id", "code"},
                  label="probe OpenSession response")
    if (direct["open_response"]["session_id"] != direct["session_id"]
            or direct["open_response"]["worker_boot_id"] != restart["old_boot_id"]
            or direct["open_response"]["code"] != "OK"):
        raise CohortError("actual probe OpenSession response identity/status differs")
    _exact_fields(direct["step_response"], {
        "sequence", "start_position", "token_count", "end_position", "next_sequence",
        "tensor_shape", "dtype", "byte_count", "finite",
    }, label="probe Step response")
    expected_step = {
        "sequence": 0, "start_position": 0, "token_count": 3,
        "end_position": 3, "next_sequence": 1,
        "tensor_shape": [1, 3, 64], "dtype": "float32_le",
        "byte_count": 768, "finite": True,
    }
    if direct["step_response"] != expected_step:
        raise CohortError("actual probe Step response differs from the frozen tensor contract")
    _exact_fields(direct["held_status"], {
        "worker_boot_id", "active_sessions", "active_session_ids", "queued_operations",
        "active_compute", "cache_bytes_exact", "committed_cache_bytes",
        "allocated_cache_bytes", "active_authorizations", "owned_sessions",
        "transport_reserved_connections",
    }, label="held old-root status")
    held = direct["held_status"]
    if (held["worker_boot_id"] != restart["old_boot_id"]
            or held["active_sessions"] != 1
            or held["active_session_ids"] != [direct["session_id"]]
            or type(held["committed_cache_bytes"]) is not int
            or held["committed_cache_bytes"] <= 0
            or type(held["allocated_cache_bytes"]) is not int
            or held["allocated_cache_bytes"] <= 0
            or held["queued_operations"] != 0 or held["active_compute"] is not False
            or held["cache_bytes_exact"] is not True or held["owned_sessions"] != 1
            or held["active_authorizations"] != 0
            or held["transport_reserved_connections"] != 1):
        raise CohortError("protected old-root held-session evidence is incomplete")
    _exact_fields(direct["new_target_before"], {
        "worker_boot_id", "ready", "active_sessions", "reserved_positions",
        "allocated_cache_bytes", "active_operations", "queued_operations", "tombstones",
        "cache_bytes_exact", "requires_restart",
    }, label="new-target pre-control Describe")
    new_before = direct["new_target_before"]
    if (new_before["worker_boot_id"] != restart["new_boot_id"]
            or new_before["ready"] is not True or new_before["cache_bytes_exact"] is not True
            or new_before["requires_restart"] is not False
            or any(new_before[key] != 0 for key in (
                "active_sessions", "reserved_positions", "allocated_cache_bytes",
                "active_operations", "queued_operations", "tombstones"))):
        raise CohortError("new-target Describe did not prove a ready globally empty worker")
    _validate_restart_idle_projection(
        new_before, restart["new_boot_id"], "new-target pre-control Describe")

    replacement = direct["client_replacement"]
    _exact_fields(replacement, {"connection_mode", "original_close", "initial_new_close",
                                "stale_clients", "preface_bindings",
                                "accounted_client_counts", "max_accounted_clients"},
                  label="fresh old-client replacements")
    if replacement["connection_mode"] != "serial_new_describe_then_stale_control":
        raise CohortError("restart replacement connection mode changed")
    original_close = replacement["original_close"]
    _exact_fields(original_close, {
        "attempted", "confirmed", "close_calls", "reserved_connections_before",
        "reserved_connections_after", "client_closed",
    }, label="original old-client close")
    if (any(type(original_close.get(key)) is not bool or original_close[key] is not True
            for key in ("attempted", "confirmed", "client_closed"))
            or any(type(original_close.get(key)) is not int
                   for key in ("close_calls", "reserved_connections_before",
                               "reserved_connections_after"))
            or original_close != {
            "attempted": True, "confirmed": True, "close_calls": 1,
            "reserved_connections_before": 6,
            "reserved_connections_after": 3, "client_closed": True}):
        raise CohortError("original stale client was not closed exactly once before replacement")
    initial_new_close = replacement["initial_new_close"]
    _exact_fields(initial_new_close, {
        "attempted", "confirmed", "close_calls", "reserved_connections_before",
        "reserved_connections_after", "client_closed",
    }, label="initial new-client close")
    if (any(type(initial_new_close.get(key)) is not bool
            for key in ("attempted", "confirmed", "client_closed"))
            or any(type(initial_new_close.get(key)) is not int
                   for key in ("close_calls", "reserved_connections_before",
                               "reserved_connections_after"))
            or initial_new_close != {
            "attempted": True, "confirmed": True, "close_calls": 1,
            "reserved_connections_before": 3, "reserved_connections_after": 0,
            "client_closed": True}):
        raise CohortError("initial new client was not closed before serial stale callers")
    stale_clients = replacement["stale_clients"]
    if type(stale_clients) is not list or len(stale_clients) != 2:
        raise CohortError("restart requires one fresh stale-binding client per method")
    for row, method in zip(stale_clients, ("SessionStatus", "CancelSession")):
        _exact_fields(row, {
            "method", "created_after_close", "same_request_context",
            "old_authorizer_preserved", "same_target_peer", "same_local_tls_identity",
            "reserved_connections_after_create", "native_status", "close",
            "new_target_preface", "same_channel_and_connector_at_dispatch",
        }, label=f"fresh {method} client binding")
        _exact_fields(row["close"], {
            "attempted", "confirmed", "close_calls", "reserved_connections_before",
            "reserved_connections_after", "client_closed",
        }, label=f"{method} client close")
        close = row["close"]
        if (any(type(close.get(key)) is not bool or close[key] is not True
                for key in ("attempted", "confirmed", "client_closed"))
                or any(type(close.get(key)) is not int
                       for key in ("close_calls", "reserved_connections_before",
                                   "reserved_connections_after"))
                or row["method"] != method
                or any(row[key] is not True for key in (
                    "created_after_close", "same_request_context",
                    "old_authorizer_preserved", "same_target_peer",
                    "same_local_tls_identity"))
                or type(row["reserved_connections_after_create"]) is not int
                or row["reserved_connections_after_create"] != 3
                or row["native_status"] != "UNAUTHENTICATED"
                or row["same_channel_and_connector_at_dispatch"] is not True
                or close != {
                    "attempted": True, "confirmed": True, "close_calls": 1,
                    "reserved_connections_before": 3,
                    "reserved_connections_after": 0, "client_closed": True}):
            raise CohortError(f"fresh {method} binding was not denied and disposed once")
        _exact_fields(row["new_target_preface"], {
            "worker_boot_id", "ready", "active_sessions", "reserved_positions",
            "allocated_cache_bytes", "active_operations", "queued_operations", "tombstones",
            "cache_bytes_exact", "requires_restart",
        }, label=f"{method} genuine new-target preface")
        _validate_restart_idle_projection(
            row["new_target_preface"], restart["new_boot_id"],
            f"{method} genuine new-target preface")
    if (type(replacement["accounted_client_counts"]) is not list
            or any(type(count) is not int for count in replacement["accounted_client_counts"])
            or replacement["accounted_client_counts"] != [1, 2, 1, 0, 1, 0, 1, 0]
            or type(replacement["max_accounted_clients"]) is not int
            or replacement["max_accounted_clients"] != 2):
        raise CohortError("fresh stale clients exceeded the shared connection budget")

    prefaces = replacement["preface_bindings"]
    preface_fields = {"for_method", "method", "operation_id", "worker_boot_id",
                      "assignment_id", "target_device_id"}
    if type(prefaces) is not list or len(prefaces) != 2:
        raise CohortError("restart result lacks its two actual new-policy preface bindings")
    old_opids = {row["operation_id"] for row in direct["bindings"]}
    preface_opids = []
    for row, method in zip(prefaces, ("SessionStatus", "CancelSession")):
        _exact_fields(row, preface_fields, label="actual new Describe binding")
        if (row["for_method"] != method or row["method"] != "Describe"
                or row["worker_boot_id"] != restart["new_boot_id"]
                or type(row["operation_id"]) is not str
                or _TYPED_OPERATION.fullmatch(row["operation_id"]) is None
                or type(row["assignment_id"]) is not str
                or _TYPED_ASSIGNMENT.fullmatch(row["assignment_id"]) is None
                or type(row["target_device_id"]) is not str
                or _TYPED_DEVICE.fullmatch(row["target_device_id"]) is None):
            raise CohortError("new Describe binding identity or order changed")
        preface_opids.append(row["operation_id"])
    if len(set(preface_opids)) != 2 or set(preface_opids) & old_opids:
        raise CohortError("new Describe operation IDs collide with old worker bindings")

    binding_fields = {"method", "operation_id", "request_id", "session_id", "route_id",
                      "route_epoch", "attempt", "worker_boot_id"}
    methods = ["OpenSession", "Step", "SessionStatus", "CancelSession"]
    bindings = direct["bindings"]
    if type(bindings) is not list or len(bindings) != 4:
        raise CohortError("restart result lacks four actual worker bindings")
    operation_ids = []
    for row, method in zip(bindings, methods):
        _exact_fields(row, binding_fields, label="actual outbound binding observation")
        if (row["method"] != method or row["request_id"] != direct["request_id"]
                or row["session_id"] != direct["session_id"]
                or row["route_id"] != direct["route_id"]
                or row["route_epoch"] != 1 or row["attempt"] != 1
                or row["worker_boot_id"] != restart["old_boot_id"]):
            raise CohortError("actual restart binding changed method/session/route identity")
        _require_string(row["operation_id"], label="worker operation ID",
                        pattern=_TYPED_OPERATION, max_length=35)
        operation_ids.append(row["operation_id"])
    if len(set(operation_ids)) != 4:
        raise CohortError("restart worker operations reused an operation ID")
    denials = restart["stale_binding_rejections"]
    if denials != [{"method": "SessionStatus", "code": "UNAUTHENTICATED"},
                   {"method": "CancelSession", "code": "UNAUTHENTICATED"}]:
        raise CohortError("restart did not record both exact old-binding refusals")

    baseline_fields = {"baseline", "identities", "request_ids", "session_ids",
                       "numerical_errors", "cases"}
    new_baseline = restart["new_baseline"]
    _exact_fields(new_baseline, baseline_fields, label="new full baseline")
    baseline = new_baseline["baseline"]
    _exact_fields(baseline, {"status", "completed_requests", "captured_vectors",
                             "lifecycle_extensions"}, label="new baseline status")
    if (baseline["status"] != "passed" or baseline["completed_requests"] != 4
            or baseline["captured_vectors"] != 27):
        raise CohortError("new generation did not pass its independent 4/27 baseline")
    requests, sessions = new_baseline["request_ids"], new_baseline["session_ids"]
    if (type(requests) is not list or len(requests) != 4 or len(set(requests)) != 4
            or type(sessions) is not list or len(sessions) != 4 or len(set(sessions)) != 4):
        raise CohortError("new generation baseline identifiers are incomplete")
    for value in requests:
        _require_string(value, label="new baseline request ID", pattern=_TYPED_REQUEST,
                        max_length=36)
    for value in sessions:
        _require_string(value, label="new baseline session ID", pattern=_TYPED_SESSION,
                        max_length=36)
    errors = new_baseline["numerical_errors"]
    if (type(errors) is not dict or errors.get("captured_vectors") != 27
            or errors.get("atol") != 1e-3 or errors.get("rtol") != 0.0
            or type(errors.get("values")) is not list or len(errors["values"]) != 27
            or any(type(value) not in (int, float) or not math.isfinite(value)
                   or value > 1e-3 for value in errors["values"])):
        raise CohortError("new generation baseline lacks 27 finite reference comparisons")
    cases = new_baseline["cases"]
    expected_case_ids = ["restart-new-greedy-one-token", "restart-new-forced-length-1",
                         "restart-new-forced-length-128", "restart-new-forced-length-1024"]
    if (type(cases) is not list or len(cases) != 4
            or [case.get("case_id") for case in cases] != expected_case_ids
            or [case.get("request_id") for case in cases] != requests
            or [case.get("session_id") for case in cases] != sessions):
        raise CohortError("new generation baseline cases are not the exact prefixed 4/27 suite")
    old_requests, old_sessions = result.get("request_ids"), result.get("session_ids")
    if (type(old_requests) is not list or len(old_requests) != 4
            or type(old_sessions) is not list or len(old_sessions) != 4
            or set(old_requests) & set(requests)
            or set(old_sessions) & set(sessions)
            or direct["request_id"] in old_requests or direct["request_id"] in requests
            or direct["session_id"] in old_sessions or direct["session_id"] in sessions):
        raise CohortError("restart generations reused an old/new/probe request or session ID")
    old_identity = result.get("identities")
    new_identity = new_baseline.get("identities")
    identity_fields = {"run_id", "coordinator_boot_id", "consumer_boot_id",
                       "worker_boot_ids", "manifest_fingerprint"}
    _exact_fields(old_identity, identity_fields, label="old generation identity")
    _exact_fields(new_identity, identity_fields, label="new generation identity")
    if (old_identity["run_id"] != new_identity["run_id"]
            or old_identity["worker_boot_ids"]["worker-3"] != restart["old_boot_id"]
            or new_identity["worker_boot_ids"]["worker-3"] != restart["new_boot_id"]
            or new_identity["consumer_boot_id"] != old_identity["consumer_boot_id"]
            or new_identity["manifest_fingerprint"] != old_identity["manifest_fingerprint"]):
        raise CohortError("old/new identity metadata changed outside the worker boot generation")
    old_boots = {old_identity["coordinator_boot_id"], old_identity["consumer_boot_id"],
                 *old_identity["worker_boot_ids"].values()}
    new_boots = {new_identity["coordinator_boot_id"], new_identity["consumer_boot_id"],
                 *new_identity["worker_boot_ids"].values()}
    if (len(old_boots) != 5 or len(new_boots) != 5
            or old_boots.intersection(new_boots) != {old_identity["consumer_boot_id"]}):
        raise CohortError("restart did not preserve only the consumer boot across generations")

    _exact_fields(restart["probe_cleanup"], {
        "confirmed", "transport_reserved_connections", "transport_reserved_pending",
        "transport_reserved_outbound_pending", "authorization_closed", "context_released",
        "client_closed",
    }, label="probe cleanup")
    cleanup = restart["probe_cleanup"]
    if (cleanup["confirmed"] is not True
            or any(cleanup[key] != 0 for key in (
                "transport_reserved_connections", "transport_reserved_pending",
                "transport_reserved_outbound_pending"))
            or any(cleanup[key] is not True for key in (
                "authorization_closed", "context_released", "client_closed"))):
        raise CohortError("restart direct probe resources were not all reclaimed")
    continuity_fields = {"same_ca", "same_snapshot_signer_public_key",
                         "same_worker_leaf_certificate", "same_worker_private_key",
                         "same_device_id", "same_assignment_id", "same_credential_epoch"}
    _exact_fields(restart["same_leaf_continuity"], continuity_fields,
                  label="same-leaf continuity")
    if any(value is not True for value in restart["same_leaf_continuity"].values()):
        raise CohortError("restart changed CA/signer/leaf or stable worker identity")


async def _run_restart_cohort(args, handoff_fd: int) -> dict:
    """Run the fixed same-leaf remote-worker restart between worker RPCs."""
    from steamboat_runtime.manifest import load_manifest, MODEL_ID, MODEL_REVISION
    from steamboat_runtime.prepare import verify_snapshot

    try:
        from lab.secure_cohort_boot import (
            build_trusted_probe_context, prepare_boot_generation,
        )
        from lab.secure_cohort_restart import (
            PROFILE_C1B_RESTART as RESTART_PROFILE,
            RESTART_GENERATION_ROOT_NAME, validate_restart_bundle_ready,
            validate_restart_ready_ack, validate_restart_stop_ack,
            borrow_restart_generation,
        )
    except ModuleNotFoundError as error:
        if error.name != "lab":
            raise
        from secure_cohort_boot import build_trusted_probe_context, prepare_boot_generation
        from secure_cohort_restart import (
            PROFILE_C1B_RESTART as RESTART_PROFILE,
            RESTART_GENERATION_ROOT_NAME, validate_restart_bundle_ready,
            validate_restart_ready_ack, validate_restart_stop_ack,
            borrow_restart_generation,
        )

    run_id, old_nonce = secrets.token_hex(16), secrets.token_hex(16)
    last_validated_nonce = old_nonce
    result = {
        "schema_version": 1, "event": "result", "run_id": run_id,
        **_new_baseline_result(), "local_shutdown": {"confirmed": False},
        "remote_shutdown": {"confirmed": False},
        "pending_scope": ["interleaving", "cancellation", "partial_admission",
                          "step_reply_loss", "capacity_faults",
                          "additional_C1b_lifecycle_cases"],
    }
    authority = None
    old_expected = None
    old_host_key = None
    new_expected = None
    new_host_key = None
    active_launch = {"boot_id": None, "may_have_started": False}
    active_ready = False
    old_owner = None
    old_state = {}
    current_owner = None
    current_state = {}
    direct_owner = None
    direct_budget = None
    direct_client_owners = []
    direct_probe_owners = []
    direct_probe_close_outcomes = {}
    owner_close_attempts = {}
    pipeline_close_attempts = {}
    direct_bindings = []
    old_probe = None
    new_probe = None
    retained = False
    primary = None
    cleanup_errors = []
    restart_started = asyncio.get_running_loop().time()

    def require_overall_bound():
        if asyncio.get_running_loop().time() - restart_started > 300.0:
            raise CohortError("restart cohort exceeded its 300-second overall bound")

    async def close_pipeline(owner, state):
        key = id(owner)
        prior = pipeline_close_attempts.get(key)
        if prior is not None and prior[0] is owner and prior[1] is state:
            return prior[2]
        try:
            errors = await asyncio.wait_for(
                _close_local_pipeline(owner, state, expected_connections=15),
                timeout=40.0)
        except BaseException as error:
            errors = [error]
        pipeline_close_attempts[key] = (owner, state, errors)
        return errors

    async def close_direct_owner():
        if direct_owner is None:
            return []
        return await _close_restart_owner_once(direct_owner, owner_close_attempts)

    try:
        manifest = load_manifest(args.artifacts)
        if manifest.get("model_id") != MODEL_ID or manifest.get("revision") != MODEL_REVISION:
            raise CohortError("artifact directory is not the pinned C0 model")
        verify_snapshot(args.reference)
        fingerprint = _validate_manifest_fingerprint(manifest.get("fingerprint"))
        fixture_class = _load_identity_fixture()
        authority = _create_authority_fixture(
            fixture_class, handoff_directory=args.handoff_directory,
            fingerprint=fingerprint, external_ip=args.external_ip,
            uncertainty=args.clock_uncertainty_seconds)
        old_bundle_path, old_expected, old_bundle_ready = provision_worker3_bundle(
            authority=authority, manifest=manifest, artifact_directory=args.artifacts,
            uncertainty=args.clock_uncertainty_seconds, external_ip=args.external_ip,
            external_port=args.external_port, run_id=run_id, nonce=old_nonce)
        old_launch = {"boot_id": old_expected.boot_id, "may_have_started": True}
        active_launch, active_ready = old_launch, False
        _publish_bundle_ready(
            handoff_fd, old_bundle_ready, boot_id=old_expected.boot_id,
            launch_state=old_launch)
        old_host_key = await _wait_for_ready(handoff_fd, old_expected)
        active_launch, active_ready = old_launch, True
        result["identities"] = {
            "run_id": run_id,
            "coordinator_boot_id": authority.principals["coordinator"].boot_id,
            "consumer_boot_id": authority.principals["consumer"].boot_id,
            "worker_boot_ids": {name: authority.principals[name].boot_id
                                for name in ("worker-1", "worker-2", "worker-3")},
            "manifest_fingerprint": fingerprint,
        }

        old_owner = _CleanupOwner()
        current_owner, current_state = old_owner, old_state
        await _run_real_pipeline(
            args, authority=authority, manifest=manifest, expected=old_expected,
            external_ip=args.external_ip, owner=old_owner,
            result=result, handoff_fd=handoff_fd, remote_host_key=old_host_key,
            pipeline_state=old_state, profile=PROFILE_BASELINE)
        require_overall_bound()
        old_cleanup_errors = await close_pipeline(old_owner, old_state)
        if old_cleanup_errors:
            raise BaseExceptionGroup("old local pipeline cleanup failed", old_cleanup_errors)
        result["baseline"]["status"] = "passed"
        old_local_shutdown = {"confirmed": True, "failure_types": []}
        current_owner, current_state = None, {}

        from steamboat_runtime.protocol.secure_transport import (
            C0ExpectedServerLeafAdapter, ExpectedServerIdentity, FixedPeer,
            LocalTlsIdentity, NodeConnectionBudget, OUTBOUND_STATIC_CONNECTION_SLOTS,
            create_secure_worker_client,
        )
        from steamboat_runtime.protocol.worker_pb2 import Request
        from steamboat_runtime.protocol.codec import DTYPE, LAYOUT, decode_tensor, encode_tensor
        from steamboat_security import AuthorizationWatcher, verify_expected_server_leaf
        from steamboat_security.codec import WORKER_SERVICE
        import torch

        direct_owner = _CleanupOwner()
        # Static reservations account for each local gRPC client; remote
        # listener admission is observed separately by successful Describe.
        direct_budget = NodeConnectionBudget(max_connections=6, max_pending=2)
        direct_owner.add(
            "restart probe contexts after all client closes",
            lambda: _close_restart_probe_owners_after_clients(
                direct_probe_owners, direct_client_owners, direct_budget,
                direct_probe_close_outcomes))
        old_probe = build_trusted_probe_context(authority, timeout_seconds=120)
        direct_probe_owners.append(old_probe)
        old_principal = authority.principals["worker-3"]
        coordinator_principal = authority.principals["coordinator"]
        old_peer = FixedPeer(
            endpoint=old_expected.endpoint,
            allowed_addresses=(args.external_ip,), device_id=old_principal.device_id,
            server_leaf_pem=old_principal.certificate_pem,
            cohort_ca_pem=authority.cohort_ca_pem,
            expected_server=_expected_server(old_principal, ExpectedServerIdentity,
                                             args.external_ip))
        watcher = AuthorizationWatcher(poll_interval_seconds=0.5)
        tls_verifier = C0ExpectedServerLeafAdapter(verify_expected_server_leaf)
        old_observer = _recording_outbound_authorizer(
            old_probe.outbound_authorizer, direct_bindings)
        old_local_identity = LocalTlsIdentity(
            coordinator_principal.certificate_pem,
            coordinator_principal.private_key_pem)
        old_client = await create_secure_worker_client(
            old_peer, local_identity=old_local_identity,
            outbound_authorizer=old_observer, authorization_watcher=watcher,
            verify_expected_server_leaf=tls_verifier,
            connection_controller=direct_budget)
        original_close_state = {}
        direct_client_owners.append((old_client, original_close_state))
        first_client_accounted = (
            direct_budget.reserved_connections // OUTBOUND_STATIC_CONNECTION_SLOTS)
        original_old_client = old_client

        async def close_original_old_client():
            return await _close_restart_probe_client_for_cleanup(
                original_old_client, direct_budget, original_close_state,
                connection_slots=OUTBOUND_STATIC_CONNECTION_SLOTS)

        direct_owner.add("original old worker-3 probe client", close_original_old_client)

        request_id, session_id = old_probe.context.request_id, old_probe.context.session_id
        route_id = old_probe.context.route_id
        if (type(request_id) is not str or _TYPED_REQUEST.fullmatch(request_id) is None
                or type(session_id) is not str or _TYPED_SESSION.fullmatch(session_id) is None
                or type(route_id) is not str):
            raise CohortError("real old Generate context lacks typed request/session/route IDs")
        described = await old_client.execute(
            "Describe", Request(protocol_version=1, timeout_ms=5_000),
            trusted_request_context=old_probe.context)
        if described.code != "OK" or described.worker_boot_id != old_expected.boot_id:
            raise CohortError("actual old-root TLS Describe did not match the old worker")
        open_request = Request(
            protocol_version=1, manifest_fingerprint=fingerprint,
            worker_boot_id=old_expected.boot_id, session_id=session_id,
            timeout_ms=5_000, max_positions=12, lifetime_ms=120_000,
            idle_lease_ms=120_000)
        open_response = await old_client.execute(
            "OpenSession", open_request, trusted_request_context=old_probe.context)
        if (open_response.code != "OK" or open_response.worker_boot_id != old_expected.boot_id
                or open_response.session_id != session_id or not open_response.lease_token):
            raise CohortError("actual old-root OpenSession did not return its bound lease")
        hidden = torch.linspace(-1.0, 1.0, 192, dtype=torch.float32).reshape(1, 3, 64)
        activation = encode_tensor(hidden)
        step_request = Request(
            protocol_version=1, manifest_fingerprint=fingerprint,
            worker_boot_id=old_expected.boot_id, session_id=session_id,
            lease_token=open_response.lease_token, timeout_ms=5_000,
            sequence=0, start_position=0, token_count=3, tensor=activation)
        step_response = await old_client.execute(
            "Step", step_request, trusted_request_context=old_probe.context)
        if (step_response.code != "OK" or step_response.sequence != 0
                or step_response.start_position != 0 or step_response.token_count != 3
                or step_response.end_position != 3 or step_response.next_sequence != 1
                or step_response.tensor.dtype != DTYPE
                or step_response.tensor.layout != LAYOUT
                or tuple(step_response.tensor.shape) != (1, 3, 64)):
            raise CohortError("actual old-root Step did not acknowledge the exact probe tensor")
        held_tensor = decode_tensor(step_response.tensor, 3)
        if not bool(torch.isfinite(held_tensor).all().item()):
            raise CohortError("actual old-root Step returned a nonfinite activation")
        held_ack = await _observe_remote(
            handoff_fd, old_expected, sequence=5,
            case_id="restart-old-session-held", request_id=request_id,
            session_id=session_id, host_key=old_host_key,
            profile=RESTART_PROFILE)
        held = _restart_held_status_projection(held_ack)
        if (held["worker_boot_id"] != old_expected.boot_id
                or held["active_sessions"] != 1
                or held["active_session_ids"] != [session_id]
                or held["committed_cache_bytes"] <= 0
                or held["allocated_cache_bytes"] <= 0
                or held["queued_operations"] != 0
                or held["active_compute"] is not False):
            raise CohortError("protected old-root observation lacks the stepped live session")

        stop_request = {
            "schema_version": 1, "event": "restart_stop_request",
            "run_id": run_id, "old_nonce": old_nonce,
            "old_boot_id": old_expected.boot_id,
            "manifest_fingerprint": fingerprint, "endpoint": old_expected.endpoint,
        }
        _safe_write_handoff(handoff_fd, RESTART_STOP_REQUEST_FILE, stop_request)
        stop_ack = await _wait_for_control(
            handoff_fd, RESTART_STOP_ACK_FILE, timeout=15.0)
        stop_arm = stop_ack.get("old_owner", {}).get("stop_arm_monotonic_ns")
        old_receipt_digest = validate_restart_stop_ack(
            stop_ack, run_id=run_id, old_nonce=old_nonce,
            old_boot_id=old_expected.boot_id, manifest_fingerprint=fingerprint,
            endpoint=old_expected.endpoint, ssh_host_key_sha256=old_host_key,
            stop_arm_monotonic_ns=stop_arm)
        active_launch, active_ready = {"boot_id": None, "may_have_started": False}, False
        require_overall_bound()

        new_nonce = secrets.token_hex(16)
        new_boot_ids = {name: secrets.token_hex(16)
                        for name in ("coordinator", "worker-1", "worker-2", "worker-3")}
        generation = prepare_boot_generation(authority, new_boot_ids)
        generation_root = Path(authority.root) / RESTART_GENERATION_ROOT_NAME
        os.mkdir(generation_root, 0o700)
        if os.name == "posix" and stat.S_IMODE(generation_root.lstat().st_mode) != 0o700:
            raise CohortError("allocated restart generation root is not owner-only mode 0700")
        generation_view = borrow_restart_generation(authority, generation, generation_root)
        new_bundle_path, new_expected, new_bundle_ready = provision_worker3_bundle(
            authority=generation_view, manifest=manifest,
            artifact_directory=args.artifacts,
            uncertainty=args.clock_uncertainty_seconds, external_ip=args.external_ip,
            external_port=args.external_port, run_id=run_id, nonce=new_nonce)
        try:
            from lab.secure_cohort_supervisor import _validate_bundle_ready
        except ModuleNotFoundError as error:
            if error.name != "lab":
                raise
            from secure_cohort_supervisor import _validate_bundle_ready
        new_envelope = {
            "schema_version": 1, "event": "restart_bundle_ready",
            "run_id": run_id, "old_nonce": old_nonce, "new_nonce": new_nonce,
            "old_boot_id": old_expected.boot_id, "new_boot_id": new_expected.boot_id,
            "old_snapshot_sha256": old_expected.snapshot_sha256,
            "new_snapshot_sha256": new_expected.snapshot_sha256,
            "old_owner_receipt_sha256": old_receipt_digest,
            "bundle": new_bundle_ready,
        }
        validate_restart_bundle_ready(
            new_envelope, run_id=run_id, old_nonce=old_nonce,
            new_nonce=new_nonce, old_boot_id=old_expected.boot_id,
            new_boot_id=new_expected.boot_id,
            old_snapshot_sha256=old_expected.snapshot_sha256,
            new_snapshot_sha256=new_expected.snapshot_sha256,
            old_owner_receipt_sha256=old_receipt_digest,
            manifest_fingerprint=fingerprint, endpoint=new_expected.endpoint,
            bundle_validator=lambda value, endpoint: _validate_bundle_ready(value, endpoint))
        new_launch = {"boot_id": new_expected.boot_id, "may_have_started": True}
        active_launch, active_ready = new_launch, False
        _safe_write_handoff(handoff_fd, RESTART_BUNDLE_READY_FILE, new_envelope)
        ready_envelope = await _wait_for_control(
            handoff_fd, RESTART_READY_ACK_FILE, timeout=60.0)
        try:
            from lab.secure_cohort_restart import validate_restart_ready_ack
        except ModuleNotFoundError as error:
            if error.name != "lab":
                raise
            from secure_cohort_restart import validate_restart_ready_ack
        new_host_key = validate_restart_ready_ack(
            ready_envelope, run_id=run_id, old_nonce=old_nonce,
            new_nonce=new_nonce, old_boot_id=old_expected.boot_id,
            new_boot_id=new_expected.boot_id,
            old_owner_receipt_sha256=old_receipt_digest,
            expected_ssh_host_key_sha256=old_host_key,
            bundle=new_bundle_ready, expected=new_expected,
            ready_validator=validate_ready_ack)
        last_validated_nonce = new_expected.nonce
        active_ready = True
        require_overall_bound()

        new_probe = build_trusted_probe_context(
            authority, generation=generation, timeout_seconds=120)
        direct_probe_owners.append(new_probe)
        new_principal = generation_view.principals["worker-3"]
        new_peer = FixedPeer(
            endpoint=new_expected.endpoint,
            allowed_addresses=(args.external_ip,), device_id=new_principal.device_id,
            server_leaf_pem=new_principal.certificate_pem,
            cohort_ca_pem=generation_view.cohort_ca_pem,
            expected_server=_expected_server(new_principal, ExpectedServerIdentity,
                                             args.external_ip))
        new_local_identity = LocalTlsIdentity(
            generation_view.principals["coordinator"].certificate_pem,
            generation_view.principals["coordinator"].private_key_pem)
        new_client = await create_secure_worker_client(
            new_peer, local_identity=new_local_identity,
            outbound_authorizer=new_probe.outbound_authorizer,
            authorization_watcher=watcher,
            verify_expected_server_leaf=tls_verifier,
            connection_controller=direct_budget)
        new_close_state = {}
        direct_client_owners.append((new_client, new_close_state))
        direct_owner.add("new worker-3 Describe client",
            lambda: _close_restart_probe_client_for_cleanup(
                new_client, direct_budget, new_close_state,
                connection_slots=OUTBOUND_STATIC_CONNECTION_SLOTS))
        second_client_accounted = (
            direct_budget.reserved_connections // OUTBOUND_STATIC_CONNECTION_SLOTS)
        new_description = await new_client.execute(
            "Describe", Request(protocol_version=1, timeout_ms=5_000),
            trusted_request_context=new_probe.context)
        new_target_before = _assert_restart_describe(
            new_description, new_expected.boot_id)

        # Close the original clients in sequence before admitting either stale
        # control caller. Each caller first authenticates a genuine new-policy
        # Describe on its own channel, then presents the actual old lease.
        old_context_reference = old_probe.context
        old_authorizer_reference = old_observer
        await _close_restart_probe_client_once(
            original_old_client, direct_budget, original_close_state,
            expected_connections_before=2 * OUTBOUND_STATIC_CONNECTION_SLOTS,
            expected_connections_after=OUTBOUND_STATIC_CONNECTION_SLOTS)
        # The registered owner and this explicit first close share the same
        # first-result cache, so teardown can never retry an uncertain close.
        initial_new_close_state = new_close_state
        await _close_restart_probe_client_once(
            new_client, direct_budget, initial_new_close_state,
            expected_connections_before=OUTBOUND_STATIC_CONNECTION_SLOTS,
            expected_connections_after=0)
        if (first_client_accounted != 1 or second_client_accounted != 2
                or direct_budget.reserved_connections != 0):
            raise CohortError("serial restart clients did not release all slots before replacement")

        preface_bindings = []
        stale_client_rows = []
        stale_client_instances = []
        native_denials = []
        static_counts = [1, 2, 1, 0]
        method_clients = ("SessionStatus", "CancelSession")
        for method in method_clients:
            close_state = {}
            routed_authorizer = _serial_preface_authorizer(
                old_probe.context, new_probe.context, old_observer,
                new_probe.outbound_authorizer, preface_bindings,
                old_method=method)
            method_client = await create_secure_worker_client(
                old_peer, local_identity=old_local_identity,
                outbound_authorizer=routed_authorizer,
                authorization_watcher=watcher,
                verify_expected_server_leaf=tls_verifier,
                connection_controller=direct_budget)
            direct_client_owners.append((method_client, close_state))
            stale_client_instances.append(method_client)
            direct_owner.add(
                f"serial {method} stale-control client",
                lambda client=method_client, state=close_state:
                    _close_restart_probe_client_for_cleanup(
                        client, direct_budget, state,
                        connection_slots=OUTBOUND_STATIC_CONNECTION_SLOTS))
            if direct_budget.reserved_connections != OUTBOUND_STATIC_CONNECTION_SLOTS:
                raise CohortError("serial stale client exceeded the one-client reservation")
            preface = await method_client.execute(
                "Describe", Request(protocol_version=1, timeout_ms=5_000),
                trusted_request_context=new_probe.context)
            projected_preface = _assert_restart_describe(preface, new_expected.boot_id)
            channel, connector = await _restart_channel_snapshot(method_client)
            dispatch_guard = _guard_restart_dispatch(
                method_client, channel, connector)
            preface_bindings[-1]["for_method"] = method
            static_counts.append(direct_budget.reserved_connections //
                                 OUTBOUND_STATIC_CONNECTION_SLOTS)
            control = Request(
                protocol_version=1, manifest_fingerprint=fingerprint,
                worker_boot_id=old_expected.boot_id, session_id=session_id,
                lease_token=open_response.lease_token, timeout_ms=5_000)
            try:
                await method_client.execute(
                    method, control, trusted_request_context=old_probe.context)
            except Exception as error:
                if not _native_unauthenticated(error):
                    raise CohortError(
                        f"old {method} did not receive native UNAUTHENTICATED") from None
                native_denials.append({"method": method, "code": "UNAUTHENTICATED"})
            else:
                raise CohortError(f"new worker listener accepted old {method} binding")
            await _close_restart_probe_client_once(
                method_client, direct_budget, close_state,
                expected_connections_before=OUTBOUND_STATIC_CONNECTION_SLOTS,
                expected_connections_after=0)
            static_counts.append(direct_budget.reserved_connections //
                                 OUTBOUND_STATIC_CONNECTION_SLOTS)
            stale_client_rows.append({
                "method": method, "created_after_close": True,
                "same_request_context": old_probe.context is old_context_reference,
                "old_authorizer_preserved": (
                    routed_authorizer.old_authorizer is old_authorizer_reference),
                "same_target_peer": method_client.peer is old_peer,
                "same_local_tls_identity": method_client.local_identity is old_local_identity,
                "reserved_connections_after_create": OUTBOUND_STATIC_CONNECTION_SLOTS,
                "native_status": "UNAUTHENTICATED",
                "new_target_preface": projected_preface,
                "same_channel_and_connector_at_dispatch": (
                    dispatch_guard["same_channel_and_connector_at_dispatch"]),
                "close": {key: close_state[key] for key in (
                    "attempted", "confirmed", "close_calls",
                    "reserved_connections_before", "reserved_connections_after",
                    "client_closed")},
            })
        if (len(preface_bindings) != 2 or [row["for_method"] for row in preface_bindings]
                != ["SessionStatus", "CancelSession"]):
            raise CohortError("serial restart did not capture exactly two Describe prefaces")
        if any(row.get("worker_boot_id") != new_expected.boot_id
               or row.get("assignment_id") != new_principal.assignment_id
               or row.get("target_device_id") != new_principal.device_id
               for row in preface_bindings):
            raise CohortError("actual Describe binding changed the new target identity")
        accounted_client_counts = static_counts
        maximum_accounted_clients = max(accounted_client_counts)
        client_replacement = {
            "connection_mode": "serial_new_describe_then_stale_control",
            "original_close": {
                "attempted": original_close_state["attempted"],
                "confirmed": original_close_state["confirmed"],
                "close_calls": original_close_state["close_calls"],
                "reserved_connections_before": original_close_state[
                    "reserved_connections_before"],
                "reserved_connections_after": original_close_state[
                    "reserved_connections_after"],
                "client_closed": original_close_state["client_closed"],
            },
            "initial_new_close": {key: initial_new_close_state[key] for key in (
                "attempted", "confirmed", "close_calls",
                "reserved_connections_before", "reserved_connections_after",
                "client_closed")},
            "stale_clients": stale_client_rows,
            "preface_bindings": preface_bindings,
            "accounted_client_counts": accounted_client_counts,
            "max_accounted_clients": maximum_accounted_clients,
        }
        if (accounted_client_counts != [1, 2, 1, 0, 1, 0, 1, 0]
                or maximum_accounted_clients != 2
                or direct_budget.reserved_connections != 0):
            raise CohortError("stale client replacements exceeded or missed the shared budget")
        old_binding_rows = direct_bindings
        if len(old_binding_rows) != 4:
            raise CohortError("actual old probe did not produce exactly four bindings")
        if [row["method"] for row in old_binding_rows] != [
                "OpenSession", "Step", "SessionStatus", "CancelSession"]:
            raise CohortError("actual old probe did not produce exactly four ordered bindings")
        operation_ids = [row["operation_id"] for row in old_binding_rows]
        if len(set(operation_ids)) != 4:
            raise CohortError("restart probe reused a worker operation ID")
        preface_ids = [row["operation_id"] for row in preface_bindings]
        if (len(set(preface_ids)) != 2 or set(preface_ids) & set(operation_ids)
                or any(type(item) is not str or _TYPED_OPERATION.fullmatch(item) is None
                       for item in preface_ids)):
            raise CohortError("new Describe bindings reused an old operation identity")
        for binding in old_binding_rows:
            if (binding["request_id"] != request_id or binding["session_id"] != session_id
                    or binding["route_id"] != route_id or binding["route_epoch"] != 1
                    or binding["attempt"] != 1
                    or binding["worker_boot_id"] != old_expected.boot_id):
                raise CohortError("actual outgoing old binding changed its trusted route")

        new_idle = await _observe_remote(
            handoff_fd, new_expected, sequence=6,
            case_id="restart-new-boot-stale-binding-rejected",
            request_id=request_id, session_id=session_id,
            host_key=new_host_key, profile=RESTART_PROFILE)
        if (new_idle["worker_boot_id"] != new_expected.boot_id
                or new_idle["active_sessions"] != 0
                or new_idle["active_session_ids"]
                or new_idle["queued_operations"] != 0
                or new_idle["active_compute"] is not False
                or new_idle["committed_cache_bytes"] != 0
                or new_idle["allocated_cache_bytes"] != 0
                or new_idle["owned_sessions"] != 0
                or new_idle["active_authorizations"] != 0):
            raise CohortError("protected post-control status is not globally idle")

        direct_cleanup_errors = await close_direct_owner()
        if direct_cleanup_errors:
            raise BaseExceptionGroup("restart direct probe cleanup failed", direct_cleanup_errors)
        if (direct_budget.reserved_connections != 0 or direct_budget.reserved_pending != 0
                or direct_budget.reserved_outbound_pending != 0
                or direct_budget.reserved_listener_pending_capacity != 0):
            raise CohortError("restart probe transport budget did not return to zero")
        old_auth_terminal, old_context_released = _trusted_probe_cleanup_state(old_probe)
        new_auth_terminal, new_context_released = _trusted_probe_cleanup_state(new_probe)
        probe_cleanup = {
            "confirmed": True, "transport_reserved_connections": 0,
            "transport_reserved_pending": 0,
            "transport_reserved_outbound_pending": 0,
            "authorization_closed": old_auth_terminal and new_auth_terminal,
            "context_released": old_context_released and new_context_released,
            "client_closed": (original_old_client._closed and new_client._closed
                              and all(client._closed for client in stale_client_instances)),
        }
        if (probe_cleanup["authorization_closed"] is not True
                or probe_cleanup["context_released"] is not True
                or probe_cleanup["client_closed"] is not True):
            raise CohortError("restart probe auth/context/client owners are not closed")
        direct_owner, old_probe, new_probe = None, None, None
        old_client = new_client = None
        require_overall_bound()

        result["restart"] = {
            "profile": RESTART_PROFILE, "status": "running",
            "scope": "remote_worker_between_rpcs",
            "old_boot_id": old_expected.boot_id,
            "new_boot_id": new_expected.boot_id,
            "old_snapshot_sha256": old_expected.snapshot_sha256,
            "new_snapshot_sha256": new_expected.snapshot_sha256,
            "old_owner_receipt_sha256": old_receipt_digest,
            "old_local_shutdown": old_local_shutdown,
            "direct_probe": {
                "request_id": request_id, "session_id": session_id,
                "route_id": route_id, "route_epoch": 1, "attempt": 1,
                "open_response": {
                    "session_id": open_response.session_id,
                    "worker_boot_id": open_response.worker_boot_id,
                    "code": open_response.code,
                },
                "step_response": {
                    "sequence": step_response.sequence,
                    "start_position": step_response.start_position,
                    "token_count": step_response.token_count,
                    "end_position": step_response.end_position,
                    "next_sequence": step_response.next_sequence,
                    "tensor_shape": list(step_response.tensor.shape),
                    "dtype": step_response.tensor.dtype,
                    "byte_count": step_response.tensor.byte_count,
                    "finite": True,
                },
                "held_status": held,
                "new_target_before": new_target_before,
                "client_replacement": client_replacement,
                "bindings": old_binding_rows,
            },
            "stale_binding_rejections": native_denials,
            "new_baseline": _new_baseline_result(),
            "probe_cleanup": probe_cleanup,
            "same_leaf_continuity": {
                "same_ca": generation_view.cohort_ca_pem == authority.cohort_ca_pem,
                "same_snapshot_signer_public_key": (
                    generation_view.snapshot_verification_key_pem
                    == authority.snapshot_verification_key_pem),
                "same_worker_leaf_certificate": (
                    new_principal.certificate_pem == old_principal.certificate_pem),
                "same_worker_private_key": (
                    new_principal.private_key_pem == old_principal.private_key_pem),
                "same_device_id": new_principal.device_id == old_principal.device_id,
                "same_assignment_id": (
                    new_principal.assignment_id == old_principal.assignment_id),
                "same_credential_epoch": (
                    new_principal.record["credential_epoch"]
                    == old_principal.record["credential_epoch"]),
            },
        }
        restart_record = result["restart"]
        if not all(restart_record["same_leaf_continuity"].values()):
            raise CohortError("prepared restart changed an existing leaf or stable identity")

        new_baseline = restart_record["new_baseline"]
        new_baseline["identities"] = {
            "run_id": run_id,
            "coordinator_boot_id": generation_view.principals["coordinator"].boot_id,
            "consumer_boot_id": generation_view.principals["consumer"].boot_id,
            "worker_boot_ids": {
                name: generation_view.principals[name].boot_id
                for name in ("worker-1", "worker-2", "worker-3")},
            "manifest_fingerprint": fingerprint,
        }
        current_owner = _CleanupOwner()
        current_state = {}
        await _run_real_pipeline(
            args, authority=generation_view, manifest=manifest,
            expected=new_expected, external_ip=args.external_ip,
            owner=current_owner, result=new_baseline,
            handoff_fd=handoff_fd, remote_host_key=new_host_key,
            pipeline_state=current_state, profile=PROFILE_BASELINE,
            observation_profile=RESTART_PROFILE,
            observation_sequence_offset=6,
            observation_case_prefix="restart-new-")
        require_overall_bound()
        new_baseline["baseline"]["status"] = "passed"
        final_cleanup_errors = await close_pipeline(current_owner, current_state)
        if final_cleanup_errors:
            raise BaseExceptionGroup("new local pipeline cleanup failed", final_cleanup_errors)
        result["local_shutdown"] = {"confirmed": True, "failure_types": []}
        current_owner, current_state = None, {}
        restart_record["new_baseline"] = new_baseline
        restart_record["status"] = "passed"
        result["remote_shutdown"] = {"confirmed": False}
    except BaseException as error:
        primary = error
        result["baseline"]["status"] = result["baseline"].get("status", "failed")
        result["failure_type"] = type(error).__name__[:80]
        if type(result.get("restart")) is dict:
            result["restart"]["status"] = "failed"
        try:
            _safe_write_handoff(
                handoff_fd, HANDOFF_FAILURE_LOCATION_FILE,
                _failure_location_record(run_id, last_validated_nonce, error))
        except BaseException:
            pass
    finally:
        if current_owner is not None:
            errors = await close_pipeline(current_owner, current_state)
            cleanup_errors.extend(errors)
            if errors:
                retained = True
            else:
                current_owner, current_state = None, {}
        if direct_owner is not None:
            errors = await close_direct_owner()
            cleanup_errors.extend(errors)
            if errors:
                retained = True
        if active_launch.get("may_have_started"):
            try:
                remote_shutdown = await _stop_remote(
                    handoff_fd, run_id=run_id, nonce=(
                        old_expected.nonce if active_launch is not None
                        and active_launch.get("boot_id") == getattr(old_expected, "boot_id", None)
                        else (new_expected.nonce if new_expected is not None else old_nonce)),
                    boot_id=active_launch.get("boot_id"), may_have_started=True,
                    readiness_observed=active_ready, host_key=(
                        old_host_key if old_expected is not None
                        and active_launch.get("boot_id") == old_expected.boot_id else new_host_key),
                    expected=(old_expected if old_expected is not None
                              and active_launch.get("boot_id") == old_expected.boot_id
                              else new_expected))
                result["remote_shutdown"] = remote_shutdown
                if not _restart_remote_exit_confirmed(remote_shutdown):
                    cleanup_errors.append(CohortError("final remote owner exit was not successful"))
                    retained = True
            except BaseException as error:
                cleanup_errors.append(error)
                retained = True
                result["remote_shutdown"] = {
                    "confirmed": False, "failure_type": type(error).__name__[:80],
                }
        graph_resources = (
            authority, active_launch, old_expected, new_expected,
            old_host_key, new_host_key, old_owner, old_state,
            current_owner, current_state, direct_owner, direct_budget,
            old_probe, new_probe, result)
        graph_retained = False
        if authority is not None:
            graph_retained = _retain_restart_graph_if_uncertain(
                result.get("remote_shutdown"), cleanup_errors,
                *graph_resources)
            retained = retained or graph_retained
        if authority is not None and not retained:
            try:
                authority.close()
            except BaseException as error:
                cleanup_errors.append(error)
                retained = True
        if retained and not graph_retained:
            _RETAINED_RESTART_OWNERS.append(graph_resources)
        if (result.get("restart", {}).get("status") == "passed"
                and not cleanup_errors):
            try:
                _validate_restart_result(result)
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            if type(result.get("restart")) is dict:
                result["restart"]["status"] = "failed"
            result.setdefault("failure_type", type(cleanup_errors[0]).__name__[:80])
        try:
            _safe_write_handoff(
                handoff_fd, HANDOFF_RESULT_FILE,
                _private_result_summary(result, profile=PROFILE_C1B_RESTART))
        except BaseException as error:
            cleanup_errors.append(error)
        os.close(handoff_fd)

    failures = ([primary] if primary is not None else []) + cleanup_errors
    if failures:
        if len(failures) == 1:
            raise failures[0]
        raise BaseExceptionGroup("restart cohort and cleanup failed", failures)
    return result


def _prepare_owner_materials(authority, expected, *, command_ids):
    """Prepare two signed role-removal policies and their fixed public materials.

    This bounded producer helper performs no publication or worker action. It
    derives both policies independently from the verified original snapshot,
    removes every worker-3 credential and grant, and returns only public bytes
    plus the two command-bound signed intents.
    """
    try:
        from lab.secure_cohort_owner import (
            OWNER_MATERIAL_NAMES, PROFILE_C1B_OWNER_REMOVE, OwnerExpectation,
            build_owner_command, build_signed_owner_intent,
            validate_owner_materials_ready,
        )
        from lab.secure_cohort_boot import _read_private_signer, _strict_json_object
    except ModuleNotFoundError as error:
        if error.name != "lab":
            raise
        from secure_cohort_owner import (
            OWNER_MATERIAL_NAMES, PROFILE_C1B_OWNER_REMOVE, OwnerExpectation,
            build_owner_command, build_signed_owner_intent,
            validate_owner_materials_ready,
        )
        from secure_cohort_boot import _read_private_signer, _strict_json_object

    def need(condition, message):
        if not condition:
            raise CohortError(message)

    need(type(expected) is OwnerExpectation
         and expected.profile == PROFILE_C1B_OWNER_REMOVE,
         "owner material preparation requires a validated remove expectation")
    need(type(command_ids) in (tuple, list) and len(command_ids) == 2,
         "owner material preparation requires exactly two command IDs")
    id_pattern = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
    need(all(type(value) is str and id_pattern.fullmatch(value) is not None
             for value in command_ids)
         and command_ids[0] != command_ids[1],
         "owner command IDs must be distinct lowercase 32-character hex")
    required = ("root", "principals", "signed_snapshot",
                "snapshot_verification_key_pem", "cohort_ca_pem", "model_id",
                "clock_uncertainty_seconds", "new_store")
    need(all(hasattr(authority, name) for name in required),
         "owner material authority is missing fixed C0 material")
    need(type(authority.principals) is dict
         and set(authority.principals) == {
             "coordinator", "consumer", "worker-1", "worker-2", "worker-3"},
         "owner material authority has an unexpected principal set")
    worker = authority.principals["worker-3"]
    need(expected.manifest_fingerprint == authority.model_id
         and expected.worker_boot_id == worker.boot_id,
         "owner expectation does not bind the original model or worker-3 boot")

    from steamboat_security import snapshot_public_key_pem
    original_store, _original_clock = authority.new_store()
    original_view = original_store.current()
    need(original_view is not None
         and original_view.revision == expected.initial_revision
         and hashlib.sha256(authority.signed_snapshot).hexdigest()
         == expected.initial_snapshot_sha256,
         "owner expectation does not bind the currently signed initial policy")
    original_payload = _strict_json_object(original_view.canonical_payload)
    need(original_payload.get("revision") == expected.initial_revision
         and original_view.policy_digest,
         "initial policy view is inconsistent with its verified snapshot")

    credentials = original_payload.get("credentials")
    grants = original_payload.get("grants")
    need(type(credentials) is list and type(grants) is list,
         "initial policy credentials or grants are malformed")
    worker_device = worker.device_id
    worker_rows = [row for row in credentials
                   if type(row) is dict
                   and row.get("serial") == worker.record.get("serial")]
    need(len(worker_rows) == 1
         and worker_rows[0].get("account_id") == worker.account_id
         and worker_rows[0].get("device_id") == worker_device
         and worker_rows[0].get("role") == worker.role
         and worker_rows[0] == worker.record,
         "initial policy does not bind the exact worker-3 device credential")
    local_serials = sorted(
        row["serial"] for row in credentials
        if type(row) is dict and row.get("device_id") == worker_device
        and type(row.get("serial")) is str)
    need(local_serials and worker.record.get("serial") in local_serials,
         "initial policy does not contain the actual worker-3 leaf serial")
    local_serial_set = set(local_serials)
    worker_target_grants = [row for row in grants
                            if type(row) is dict
                            and row.get("target_device_id") == worker_device]
    need(worker_target_grants
         and all(row.get("target_boot_id") == expected.worker_boot_id
                 for row in worker_target_grants),
         "initial policy does not bind worker-3 grants to its current boot")

    def make_payload(revision):
        payload = copy.deepcopy(original_payload)
        payload["revision"] = revision
        payload["credentials"] = [
            row for row in payload["credentials"]
            if row.get("device_id") != worker_device and row.get("serial") not in local_serial_set
        ]
        payload["grants"] = [
            row for row in payload["grants"]
            if row.get("device_id") != worker_device
            and row.get("target_device_id") != worker_device
            and row.get("actor_serial") not in local_serial_set
            and row.get("target_serial") not in local_serial_set
        ]
        payload["revoked_devices"] = sorted(
            set(original_payload.get("revoked_devices", ())) | {worker_device})
        payload["revoked_serials"] = sorted(
            set(original_payload.get("revoked_serials", ())) | local_serial_set)
        return payload

    candidates = (make_payload(expected.initial_revision + 1),
                  make_payload(expected.initial_revision + 2))
    # No authority private key is read until all caller identities and the
    # targeted original records have been validated above.
    signer_key = _read_private_signer(Path(authority.root))
    try:
        need(snapshot_public_key_pem(signer_key)
             == authority.snapshot_verification_key_pem,
             "protected operator signer does not match the pinned snapshot key")
        from steamboat_security import sign_snapshot
        signed = tuple(sign_snapshot(payload, signer_key) for payload in candidates)
    finally:
        signer_key = b""

    # Verify the original and both new snapshots with the real, pinned C0
    # SnapshotStore and Clock. Nothing is installed into the authority's store.
    verifier, _verification_clock = authority.new_store()
    views = [verifier.install(encoded) for encoded in signed]
    for offset, (payload, encoded, view) in enumerate(zip(candidates, signed, views), 1):
        need(view.revision == expected.initial_revision + offset
             and view.policy_digest
             and hashlib.sha256(encoded).hexdigest(),
             "signed owner-removal policy failed actual pinned-store verification")
        verified_payload = _strict_json_object(view.canonical_payload)
        need(verified_payload == payload,
             "verified owner-removal policy differs from the prepared policy")
        need(worker_device in view.revoked_devices
             and local_serial_set <= set(view.revoked_serials)
             and not (local_serial_set & set(view.credentials_by_serial)),
             "verified policy did not revoke every worker-3 identity")
        need(all(grant.device_id != worker_device
                 and grant.target_device_id != worker_device
                 for grant in view.grants),
             "verified policy retained a grant to or from worker-3")

    snapshot_digests = tuple(hashlib.sha256(value).hexdigest() for value in signed)
    commands = [
        build_owner_command(
            expected, sequence, command_ids[sequence - 1],
            snapshot_sha256=snapshot_digests[sequence - 1],
            snapshot_revision=expected.initial_revision + sequence)
        for sequence in (1, 2)
    ]
    from steamboat_security.codec import canonical_json
    # Use the same actual worker inbox parser that will claim these documents.
    try:
        from lab.secure_worker_owner_control import parse_owner_command
    except ModuleNotFoundError as error:
        if error.name != "lab":
            raise
        from secure_worker_owner_control import parse_owner_command
    parsed_commands = [parse_owner_command(
        canonical_json(command), expected_run_id=expected.run_id,
        expected_worker_boot_id=expected.worker_boot_id) for command in commands]
    # Re-read only through the protected reader for command-bound intents; no
    # key bytes are returned or retained by this helper.
    intent_key = _read_private_signer(Path(authority.root))
    try:
        need(snapshot_public_key_pem(intent_key)
             == authority.snapshot_verification_key_pem,
             "protected operator signer changed before intent signing")
        intents = [build_signed_owner_intent(command, intent_key)
                   for command in parsed_commands]
    finally:
        intent_key = b""

    files = {
        "install-snapshot.json": signed[0],
        "remove-snapshot.json": signed[1],
        "install-intent.json": intents[0],
        "removal-intent.json": intents[1],
    }
    need(tuple(files) == OWNER_MATERIAL_NAMES
         and all(type(value) is bytes and value for value in files.values()),
         "owner material bytes do not match the fixed four-file contract")
    wrapper = {
        "schema_version": 1, "event": "owner_materials_ready",
        "profile": expected.profile, "run_id": expected.run_id,
        "nonce": expected.nonce, "worker_boot_id": expected.worker_boot_id,
        "files": {
            name: {"size": len(value), "sha256": hashlib.sha256(value).hexdigest()}
            for name, value in files.items()
        },
    }
    ready = validate_owner_materials_ready(wrapper, expected)
    return {
        "ready": ready, "files": files, "commands": commands,
        "initial_local_serials": local_serials,
    }


def _build_owner_actions_result(expected, *, worker_config,
                                ssh_host_key_sha256, initial_local_serials,
                                old_local_shutdown, direct_probe, commands,
                                controls, observations, probe_cleanup):
    """Assemble the fixed owner extension and run the shared strict validator."""
    try:
        from lab.secure_cohort_owner import validate_owner_result
    except ModuleNotFoundError as error:
        if error.name != "lab":
            raise
        from secure_cohort_owner import validate_owner_result
    actions = {
        "profile": expected.profile,
        "status": "passed",
        "scope": "remote_host_owner_control",
        "target_device_id": worker_config["device_id"],
        "worker_boot_id": expected.worker_boot_id,
        "initial_snapshot_sha256": expected.initial_snapshot_sha256,
        "initial_revision": expected.initial_revision,
        "initial_local_serials": initial_local_serials,
        "old_local_shutdown": old_local_shutdown,
        "direct_probe": direct_probe,
        "commands": commands,
        "controls": controls,
        "observations": observations,
        "probe_cleanup": probe_cleanup,
    }
    try:
        validate_owner_result(
            actions, expected,
            expected_ssh_host_key_sha256=ssh_host_key_sha256,
            expected_worker_config=worker_config)
    except (ValueError, KeyError, TypeError) as error:
        raise CohortError("owner action evidence failed the shared validator") from error
    return actions


def _validate_owner_status_frame(status, owner_expected, worker_config, *, command=None,
                                 observation=False):
    """Validate the actual owner-only raw status with the frozen shared schema."""
    try:
        from lab.secure_cohort_owner import _validate_owner_status
    except ModuleNotFoundError as error:
        if error.name != "lab":
            raise
        from secure_cohort_owner import _validate_owner_status
    try:
        return _validate_owner_status(status, owner_expected, worker_config,
                                      command=command, observation=observation)
    except (ValueError, KeyError, TypeError) as error:
        raise CohortError("protected owner status failed the shared validator") from error


def _validate_owner_ready_ack(payload, *, expected, owner_expected, worker_config):
    _exact_fields(payload, HANDOFF_READY_ACK_FIELDS, label="owner ready acknowledgement")
    expected_values = {
        "schema_version": 1, "event": "ready_ack", "run_id": expected.run_id,
        "nonce": expected.nonce, "boot_id": expected.boot_id,
        "manifest_fingerprint": expected.manifest_fingerprint,
        "snapshot_sha256": expected.snapshot_sha256, "endpoint": expected.endpoint,
        "remote_status_uid": REMOTE_STATUS_UID,
        "remote_status_mode": REMOTE_STATUS_MODE, "measurement_label": READY_LABEL,
    }
    for name, value in expected_values.items():
        if type(payload.get(name)) is not type(value) or payload.get(name) != value:
            raise CohortError(f"owner ready acknowledgement mismatch: {name}")
    _require_int(payload["remote_status_mtime_ns"], label="owner ready status mtime", minimum=1)
    host_key = _require_string(payload["ssh_host_key_sha256"],
                               label="owner SSH host-key SHA-256", pattern=_HEX64,
                               max_length=64)
    status = payload["remote_status"]
    if type(status) is not dict or status.get("event") not in ("ready", "heartbeat"):
        raise CohortError("owner ready acknowledgement lacks actual ready status")
    _validate_owner_status_frame(status, owner_expected, worker_config,
                                 observation=False)
    _require_owner_global_idle(status)
    return host_key


def _validate_owner_observation_status(status, *, owner_expected, worker_config,
                                       sequence, commands):
    command = None
    if sequence == 6:
        command_index = (1 if owner_expected.profile == PROFILE_C1B_OWNER_DRAIN else 0)
        command = commands[command_index]["worker_ack"]
    elif sequence == 7:
        command = commands[1]["worker_ack"]
    validated = _validate_owner_status_frame(
        status, owner_expected, worker_config, command=command, observation=True)
    if sequence in (1, 2, 3, 4):
        _require_owner_global_idle(status)
    return validated


def _require_owner_global_idle(status):
    """Require an actual pre-probe status to have no worker-owned work."""
    handler = status.get("handler") if type(status) is dict else None
    bridge = status.get("bridge") if type(status) is dict else None
    transport = status.get("transport") if type(status) is dict else None
    if type(handler) is not dict or type(bridge) is not dict or type(transport) is not dict:
        raise CohortError("owner idle status lacks actual resource counters")
    zero_fields = (
        (handler, ("active_sessions", "queued_operations", "committed_cache_bytes",
                   "allocated_cache_bytes")),
        (bridge, ("active_authorizations", "owned_sessions", "pending_notices")),
        (transport, ("reserved_pending", "reserved_outbound_pending")),
    )
    if (handler.get("active_session_ids") != []
            or handler.get("active_compute") is not False
            or any(type(value.get(key)) is not int or value[key] != 0
                   for value, keys in zero_fields for key in keys)
            or transport.get("reserved_connections") != 1
            or transport.get("reserved_listener_pending_capacity") != 1
            or transport.get("listener_slots") != 1):
        raise CohortError("owner pre-probe worker is not globally idle")


def _prepare_owner_drain_commands(expected, *, command_ids):
    """Build the two fixed drain commands with the actual shared parser."""
    try:
        from lab.secure_cohort_owner import (
            PROFILE_C1B_OWNER_DRAIN as DRAIN_PROFILE, build_owner_command,
        )
        from lab.secure_cohort_owner import OwnerExpectation
    except ModuleNotFoundError as error:
        if error.name != "lab":
            raise
        from secure_cohort_owner import (
            PROFILE_C1B_OWNER_DRAIN as DRAIN_PROFILE, build_owner_command,
            OwnerExpectation,
        )
    if type(expected) is not OwnerExpectation or expected.profile != DRAIN_PROFILE:
        raise CohortError("drain command preparation requires the validated drain expectation")
    if (type(command_ids) not in (tuple, list) or len(command_ids) != 2
            or any(type(value) is not str or _HEX32.fullmatch(value) is None
                   for value in command_ids)
            or command_ids[0] == command_ids[1]):
        raise CohortError("drain command IDs must be distinct lowercase 32-character hex")
    return [build_owner_command(expected, number, command_ids[number - 1])
            for number in (1, 2)]


def _owner_expectation(profile, *, remote_expected, authority, worker_config):
    try:
        from lab.secure_cohort_owner import OwnerExpectation
    except ModuleNotFoundError as error:
        if error.name != "lab":
            raise
        from secure_cohort_owner import OwnerExpectation
    if profile not in (PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE):
        raise CohortError("owner expectation requires a fixed owner profile")
    store, _clock = authority.new_store()
    view = store.current()
    if (view is None or view.revision < 1
            or worker_config.get("device_id") != remote_expected.device_id
            or worker_config.get("boot_id") != remote_expected.boot_id
            or worker_config.get("manifest_fingerprint") != remote_expected.manifest_fingerprint
            or worker_config.get("listen_ip") != remote_expected.endpoint.rsplit(":", 1)[0]
            or worker_config.get("listen_port") != REMOTE_PORT):
        raise CohortError("actual worker configuration does not match owner expectation")
    return OwnerExpectation(
        profile=profile, run_id=remote_expected.run_id, nonce=remote_expected.nonce,
        worker_boot_id=remote_expected.boot_id,
        manifest_fingerprint=remote_expected.manifest_fingerprint,
        endpoint=remote_expected.endpoint,
        initial_snapshot_sha256=remote_expected.snapshot_sha256,
        initial_revision=view.revision)


def _owner_initial_local_serials(authority, worker_config, owner_expected):
    try:
        from lab.secure_cohort_boot import _strict_json_object
    except ModuleNotFoundError as error:
        if error.name != "lab":
            raise
        from secure_cohort_boot import _strict_json_object
    store, _clock = authority.new_store()
    view = store.current()
    if view is None or view.revision != owner_expected.initial_revision:
        raise CohortError("initial owner policy view is unavailable or changed")
    payload = _strict_json_object(view.canonical_payload)
    credentials = payload.get("credentials")
    worker = authority.principals.get("worker-3")
    if type(credentials) is not list or worker is None:
        raise CohortError("initial owner credential inventory is malformed")
    rows = [row for row in credentials
            if type(row) is dict and row.get("device_id") == worker_config.get("device_id")]
    serials = sorted(row.get("serial") for row in rows
                     if type(row.get("serial")) is str)
    if (not serials or len(serials) > 16 or len(serials) != len(rows)
            or len(serials) != len(set(serials))
            or worker.record.get("serial") not in serials
            or any(re.fullmatch(r"[1-9a-f][0-9a-f]{0,39}", item, re.ASCII) is None
                   for item in serials)):
        raise CohortError("initial owner serial list is not the exact local device set")
    return serials


def _require_owner_drain_authority_margin(probe, authority, *, minimum_seconds=30.0,
                                          opened=None, opened_received_at=None):
    """Prove the original context, signed grants and optional Open lease outlive drain."""
    from steamboat_security.codec import WORKER_SERVICE
    context_remaining = probe.context.remaining_seconds()
    outbound = probe.outbound_authorizer
    sample = outbound.clock.sample()
    view = probe.snapshot_store.current(sample=sample)
    coordinator = authority.principals["coordinator"]
    worker = authority.principals["worker-3"]
    grants = [grant for grant in view.grants
              if grant.account_id == coordinator.account_id
              and grant.device_id == coordinator.device_id
              and grant.role == coordinator.role
              and grant.actor_serial == coordinator.record["serial"]
              and grant.tenant_account_id == coordinator.account_id
              and grant.target_account_id == worker.account_id
              and grant.actor_boot_id == coordinator.boot_id
              and grant.target_device_id == worker.device_id
              and grant.target_role == worker.role
              and grant.target_serial == worker.record["serial"]
              and grant.target_boot_id == worker.boot_id
              and grant.assignment_id == worker.assignment_id
              and grant.model_id == authority.model_id
              and grant.method in tuple(
                  f"{WORKER_SERVICE}/{method}"
                  for method in ("Describe", "OpenSession", "Step", "RenewSession"))]
    if not grants:
        raise CohortError("initial signed policy has no actual worker probe grants")
    required_methods = {f"{WORKER_SERVICE}/{method}"
                        for method in ("Describe", "OpenSession", "Step", "RenewSession")}
    if {grant.method for grant in grants} != required_methods:
        raise CohortError("initial policy does not cover every actual drain probe method")
    grant_deadlines = [view.grant_deadlines.get(grant.identity) for grant in grants]
    if any(type(deadline) not in (int, float) or isinstance(deadline, bool)
           or not math.isfinite(deadline) for deadline in grant_deadlines):
        raise CohortError("actual worker grant deadline is not finite")
    remaining = min(
        view.deadline_monotonic,
        view.credential_deadlines.get(coordinator.record["serial"], sample.monotonic),
        view.credential_deadlines.get(worker.record["serial"], sample.monotonic),
        *grant_deadlines) - sample.monotonic
    lease_remaining = None
    if opened is not None:
        if (type(opened_received_at) not in (int, float)
                or isinstance(opened_received_at, bool)
                or type(opened.remaining_lifetime_ms) is not int
                or type(opened.remaining_idle_ms) is not int
                or opened.remaining_lifetime_ms <= 0 or opened.remaining_idle_ms <= 0):
            raise CohortError("actual original OpenSession lease bounds are malformed")
        elapsed = asyncio.get_running_loop().time() - opened_received_at
        lease_remaining = min(opened.remaining_lifetime_ms,
                              opened.remaining_idle_ms) / 1000.0 - elapsed
    if (type(context_remaining) not in (int, float) or isinstance(context_remaining, bool)
            or context_remaining <= minimum_seconds or remaining <= minimum_seconds
            or (lease_remaining is not None and lease_remaining <= minimum_seconds)):
        raise CohortError("original Generate context, worker grant or Open lease expires before drain")


def _owner_material_archive(files):
    """Build the fixed public USTAR handoff using the dedicated bounded helper."""
    try:
        from lab.secure_owner_material_handoff import build_owner_material_archive
    except ModuleNotFoundError as error:
        if error.name != "lab":
            raise
        from secure_owner_material_handoff import build_owner_material_archive
    try:
        return build_owner_material_archive(files)
    except (ValueError, TypeError, KeyError) as error:
        raise CohortError("owner material archive failed its fixed USTAR bounds") from error


def _publish_owner_materials(directory_fd, prepared, expected):
    """Durably publish validated USTAR bytes before their exact ready wrapper."""
    try:
        from lab.secure_cohort_owner import validate_owner_material_archive
        from lab.secure_owner_material_handoff import write_owner_material_archive
    except ModuleNotFoundError as error:
        if error.name != "lab":
            raise
        from secure_cohort_owner import validate_owner_material_archive
        from secure_owner_material_handoff import write_owner_material_archive
    if type(prepared) is not dict or set(prepared) != {
            "ready", "files", "commands", "initial_local_serials"}:
        raise CohortError("owner material preparation differs from its frozen API")
    ready = prepared["ready"]
    files = prepared["files"]
    try:
        archive = _owner_material_archive(files)
        parsed = validate_owner_material_archive(archive, ready, expected)
        if parsed != files:
            raise CohortError("owner archive parser returned different public materials")
        receipt = write_owner_material_archive(directory_fd, archive)
    except (ValueError, TypeError, KeyError) as error:
        raise CohortError("owner material archive failed shared validation or durable write") from error
    _safe_write_handoff(directory_fd, OWNER_MATERIALS_READY_FILE, ready)
    return receipt


async def _run_owner_direct_probe(directory_fd, *, authority, expected,
                                  owner_expected, worker_config, host_key,
                                  commands, initial_local_serials,
                                  old_local_shutdown, command_state):
    """Execute the fixed live owner probes and retain first-close ownership evidence."""
    try:
        from lab.secure_cohort_boot import build_trusted_probe_context
    except ModuleNotFoundError as error:
        if error.name != "lab":
            raise
        from secure_cohort_boot import build_trusted_probe_context
    from steamboat_runtime.protocol.secure_transport import (
        C0ExpectedServerLeafAdapter, ExpectedServerIdentity, FixedPeer,
        LocalTlsIdentity, NodeConnectionBudget, OUTBOUND_STATIC_CONNECTION_SLOTS,
        create_secure_worker_client,
    )
    from steamboat_runtime.protocol.worker_pb2 import Request
    from steamboat_runtime.protocol.codec import DTYPE, LAYOUT, decode_tensor, encode_tensor
    from steamboat_security import AuthorizationWatcher, verify_expected_server_leaf
    from steamboat_security.codec import WORKER_SERVICE
    import torch

    if old_local_shutdown != {"confirmed": True, "failure_types": []}:
        raise CohortError("owner probe cannot begin before confirmed initial local shutdown")
    if type(commands) is not list or len(commands) != 2:
        raise CohortError("owner probe requires exactly two prepared shared commands")
    direct_budget = NodeConnectionBudget(max_connections=6, max_pending=2)
    direct_owner = _CleanupOwner()
    probes = []
    clients = []
    close_outcomes = {}
    bindings = []
    rows = {}
    cleanup_attempted = False
    cleanup_errors = []
    drain_ack_at = None
    # Registered first so LIFO cleanup closes every actual client before either
    # Generate context or its authorization can be released.
    direct_owner.add(
        "owner probe contexts after every client close",
        lambda: _close_restart_probe_owners_after_clients(
            probes, clients, direct_budget, close_outcomes))

    def make_probe():
        probe = build_trusted_probe_context(authority, timeout_seconds=120)
        probes.append(probe)
        return probe

    worker = authority.principals["worker-3"]
    coordinator = authority.principals["coordinator"]
    watcher = AuthorizationWatcher(poll_interval_seconds=0.5)
    tls_verifier = C0ExpectedServerLeafAdapter(verify_expected_server_leaf)

    async def make_client(probe, label):
        if (direct_budget.reserved_connections != 0
                or direct_budget.reserved_pending != 0
                or direct_budget.reserved_outbound_pending != 0
                or direct_budget.reserved_listener_pending_capacity != 0):
            raise CohortError("owner client creation began before prior capacity was released")
        local_ip = authority.ip_sans_by_principal["worker-3"][0]
        peer = FixedPeer(
            endpoint=expected.endpoint, allowed_addresses=(local_ip,),
            device_id=worker.device_id, server_leaf_pem=worker.certificate_pem,
            cohort_ca_pem=authority.cohort_ca_pem,
            expected_server=_expected_server(worker, ExpectedServerIdentity,
                                             local_ip))
        outbound = _recording_owner_outbound_authorizer(
            probe.outbound_authorizer, bindings,
            maximum_calls=(5 if owner_expected.profile == PROFILE_C1B_OWNER_DRAIN else 4))
        client = await create_secure_worker_client(
            peer, local_identity=LocalTlsIdentity(
                coordinator.certificate_pem, coordinator.private_key_pem),
            outbound_authorizer=outbound, authorization_watcher=watcher,
            verify_expected_server_leaf=tls_verifier,
            connection_controller=direct_budget)
        state = {}
        clients.append((client, state))
        row = {"label": label, "attempted": False, "confirmed": False,
               "close_calls": 0,
               "reserved_connections_before": 0,
               "reserved_connections_after": 0,
               "client_closed": False, "reserved_pending_after": 0}
        rows[label] = row

        async def cleanup_client():
            if state.get("attempted") is True:
                await _close_restart_probe_client_once(
                    client, direct_budget, state,
                    expected_connections_before=3,
                    expected_connections_after=0)
            else:
                await _close_restart_probe_client_once(
                    client, direct_budget, state,
                    expected_connections_before=3,
                    expected_connections_after=0)
            row.update({
                "attempted": state.get("attempted") is True,
                "confirmed": state.get("confirmed") is True,
                "close_calls": state.get("close_calls", 0),
                "reserved_connections_before": state.get("reserved_connections_before", 0),
                "reserved_connections_after": state.get("reserved_connections_after", 0),
                "client_closed": state.get("client_closed") is True,
                "reserved_pending_after": direct_budget.reserved_pending,
            })

        direct_owner.add(f"owner {label} client", cleanup_client)
        if direct_budget.reserved_connections != OUTBOUND_STATIC_CONNECTION_SLOTS:
            raise CohortError("owner probe exceeded its one-client transport budget")
        return client, state

    async def close_client(client, state, label):
        await _close_restart_probe_client_once(
            client, direct_budget, state,
            expected_connections_before=OUTBOUND_STATIC_CONNECTION_SLOTS,
            expected_connections_after=0)
        if (direct_budget.reserved_pending != 0
                or direct_budget.reserved_outbound_pending != 0
                or direct_budget.reserved_listener_pending_capacity != 0):
            raise CohortError("owner client close retained pending transport capacity")
        rows[label].update({
            "attempted": True, "confirmed": state.get("confirmed") is True,
            "close_calls": state.get("close_calls", 0),
            "reserved_connections_before": state.get("reserved_connections_before", 0),
            "reserved_connections_after": state.get("reserved_connections_after", 0),
            "client_closed": state.get("client_closed") is True,
            "reserved_pending_after": direct_budget.reserved_pending,
        })

    def binding(method, start):
        if len(bindings) != start + 1 or bindings[-1]["method"] != method:
            raise CohortError("owner client did not record exactly one actual RPC binding")
        return dict(bindings[-1])

    async def execute(client, method, request, probe):
        return await client.execute(
            method, request, trusted_request_context=probe.context)

    try:
        old_probe = make_probe()
        if owner_expected.profile == PROFILE_C1B_OWNER_DRAIN:
            _require_owner_drain_authority_margin(
                old_probe, authority,
                minimum_seconds=30.0 + OBSERVATION_TIMEOUT_SECONDS
                + worker_config["clock_uncertainty_seconds"])
        request_id, session_id, route_id = (
            old_probe.context.request_id, old_probe.context.session_id,
            old_probe.context.route_id)
        if (_TYPED_REQUEST.fullmatch(request_id) is None
                or _TYPED_SESSION.fullmatch(session_id) is None
                or _TYPED_ROUTE.fullmatch(route_id) is None):
            raise CohortError("actual owner Generate context lacks typed IDs")
        client, close_state = await make_client(old_probe, "initial")
        described = await execute(
            client, "Describe", Request(protocol_version=1, timeout_ms=5_000), old_probe)
        if described.code != "OK" or described.worker_boot_id != expected.boot_id:
            raise CohortError("owner direct probe Describe did not reach the pinned worker")
        open_request = Request(
            protocol_version=1, manifest_fingerprint=expected.manifest_fingerprint,
            worker_boot_id=expected.boot_id, session_id=session_id,
            timeout_ms=5_000, max_positions=12, lifetime_ms=120_000,
            idle_lease_ms=120_000)
        start = len(bindings)
        opened_received_at = asyncio.get_running_loop().time()
        opened = await execute(client, "OpenSession", open_request, old_probe)
        open_binding = binding("OpenSession", start)
        if (opened.code != "OK" or opened.worker_boot_id != expected.boot_id
                or opened.session_id != session_id or not opened.lease_token):
            raise CohortError("owner direct OpenSession lacks its actual bound lease")
        hidden = torch.linspace(-1.0, 1.0, 192, dtype=torch.float32).reshape(1, 3, 64)
        start = len(bindings)
        stepped = await execute(client, "Step", Request(
            protocol_version=1, manifest_fingerprint=expected.manifest_fingerprint,
            worker_boot_id=expected.boot_id, session_id=session_id,
            lease_token=opened.lease_token, timeout_ms=5_000,
            sequence=0, start_position=0, token_count=3,
            tensor=encode_tensor(hidden)), old_probe)
        step_binding = binding("Step", start)
        if (stepped.code != "OK" or stepped.sequence != 0 or stepped.start_position != 0
                or stepped.token_count != 3 or stepped.end_position != 3
                or stepped.next_sequence != 1 or stepped.tensor.dtype != DTYPE
                or stepped.tensor.layout != LAYOUT
                or tuple(stepped.tensor.shape) != (1, 3, 64)):
            raise CohortError("owner direct Step did not acknowledge the exact probe tensor")
        first_tensor = decode_tensor(stepped.tensor, 3)
        if not bool(torch.isfinite(first_tensor).all().item()):
            raise CohortError("owner direct Step returned a nonfinite tensor")
        direct_probe = {
            "request_id": request_id, "session_id": session_id,
            "route_id": route_id, "route_epoch": 1, "attempt": 1,
            "open_response": {"code": "OK", "session_id": session_id,
                              "worker_boot_id": expected.boot_id},
            "step_response": {"sequence": 0, "start_position": 0,
                              "token_count": 3, "end_position": 3,
                              "next_sequence": 1, "tensor_shape": [1, 3, 64],
                              "dtype": "float32_le", "byte_count": 768,
                              "finite": True},
            "bindings": [open_binding, step_binding],
        }
        observations = [await _observe_owner_remote(
            directory_fd, expected=expected, owner_expected=owner_expected,
            worker_config=worker_config, sequence=5, request_id=request_id,
            session_id=session_id, host_key=host_key, commands=())]
        if owner_expected.profile == PROFILE_C1B_OWNER_DRAIN:
            uncertainty = worker_config["clock_uncertainty_seconds"]
            _require_owner_drain_authority_margin(
                old_probe, authority,
                minimum_seconds=30.0 + OBSERVATION_TIMEOUT_SECONDS + uncertainty)
        responses = [await _publish_owner_action_and_read(
            directory_fd, owner_expected=owner_expected, worker_config=worker_config,
            ssh_host_key_sha256=host_key, command_number=1, command=commands[0])]
        command_state["last_response"] = responses[0]
        if owner_expected.profile == PROFILE_C1B_OWNER_DRAIN:
            uncertainty = worker_config["clock_uncertainty_seconds"]
            _require_owner_drain_authority_margin(
                old_probe, authority, minimum_seconds=30.0 + uncertainty,
                opened=opened, opened_received_at=opened_received_at)
            drain_ack_at = asyncio.get_running_loop().time()

        controls = {}
        if owner_expected.profile == PROFILE_C1B_OWNER_DRAIN:
            uncertainty = worker_config["clock_uncertainty_seconds"]
            _require_owner_drain_authority_margin(
                old_probe, authority, minimum_seconds=30.0 + uncertainty,
                opened=opened, opened_received_at=opened_received_at)
            continue_start = len(bindings)
            continued = await execute(client, "Step", Request(
                protocol_version=1, manifest_fingerprint=expected.manifest_fingerprint,
                worker_boot_id=expected.boot_id, session_id=session_id,
                lease_token=opened.lease_token, timeout_ms=5_000,
                sequence=1, start_position=3, token_count=1,
                tensor=encode_tensor(torch.zeros((1, 1, 64), dtype=torch.float32))), old_probe)
            continue_binding = binding("Step", continue_start)
            if (continued.code != "OK" or continued.sequence != 1
                    or continued.start_position != 3 or continued.token_count != 1
                    or continued.end_position != 4 or continued.next_sequence != 2
                    or continued.tensor.dtype != DTYPE or continued.tensor.layout != LAYOUT
                    or tuple(continued.tensor.shape) != (1, 1, 64)
                    or not bool(torch.isfinite(decode_tensor(continued.tensor, 1)).all().item())):
                raise CohortError("owner drain Step1 did not return one finite position")
            renew_start = len(bindings)
            renew = await execute(client, "RenewSession", Request(
                protocol_version=1, manifest_fingerprint=expected.manifest_fingerprint,
                worker_boot_id=expected.boot_id, session_id=session_id,
                lease_token=opened.lease_token, timeout_ms=5_000), old_probe)
            renew_binding = binding("RenewSession", renew_start)
            if (renew.code != "OK" or renew.worker_boot_id != expected.boot_id
                    or renew.session_id != session_id):
                raise CohortError("owner drain RenewSession failed")
            described = await execute(
                client, "Describe", Request(protocol_version=1, timeout_ms=5_000), old_probe)
            if (described.code != "OK" or described.ready is not False
                    or described.worker_boot_id != expected.boot_id):
                raise CohortError("owner drain did not cutoff authenticated Describe")
            controls["continued_step"] = {
                "binding": continue_binding,
                "response": {"sequence": 1, "start_position": 3,
                             "token_count": 1, "end_position": 4,
                             "next_sequence": 2, "tensor_shape": [1, 1, 64],
                             "dtype": "float32_le", "byte_count": 256,
                             "finite": True},
            }
            controls["renew"] = {
                "binding": renew_binding,
                "response": {"code": "OK", "worker_boot_id": expected.boot_id,
                             "session_id": session_id},
            }
            controls["describe"] = {
                "code": described.code, "worker_boot_id": described.worker_boot_id,
                "ready": described.ready, "active_sessions": described.active_sessions,
                "reserved_positions": described.reserved_positions,
                "allocated_cache_bytes": described.allocated_cache_bytes,
                "active_operations": described.active_operations,
                "queued_operations": described.queued_operations,
                "tombstones": described.tombstones,
                "cache_bytes_exact": described.cache_bytes_exact,
                "requires_restart": described.requires_restart,
            }
            await close_client(client, close_state, "initial")
            fresh_probe = make_probe()
            fresh_client, fresh_state = await make_client(fresh_probe, "new_open")
            fresh_request = Request(
                protocol_version=1, manifest_fingerprint=expected.manifest_fingerprint,
                worker_boot_id=expected.boot_id, session_id=fresh_probe.context.session_id,
                timeout_ms=5_000, max_positions=12, lifetime_ms=120_000,
                idle_lease_ms=120_000)
            start = len(bindings)
            try:
                await execute(fresh_client, "OpenSession", fresh_request, fresh_probe)
            except Exception as error:
                if not _native_unauthenticated(error):
                    raise CohortError("fresh drain OpenSession did not return native UNAUTHENTICATED") from None
            else:
                raise CohortError("fresh drain OpenSession unexpectedly succeeded")
            rejected_binding = binding("OpenSession", start)
            controls["new_open_rejection"] = {
                "method": "OpenSession", "binding": rejected_binding,
                "native_status": "UNAUTHENTICATED", "returned_response": False,
                "dispatch_count": 1,
                "policy_sha256": owner_expected.initial_snapshot_sha256,
            }
            await close_client(fresh_client, fresh_state, "new_open")
            responses.append(await _publish_owner_action_and_read(
                directory_fd, owner_expected=owner_expected,
                worker_config=worker_config, ssh_host_key_sha256=host_key,
                command_number=2, command=commands[1]))
            command_state["last_response"] = responses[1]
            observations.append(await _observe_owner_remote(
                directory_fd, expected=expected, owner_expected=owner_expected,
                worker_config=worker_config, sequence=6, request_id=request_id,
                session_id=session_id, host_key=host_key, commands=responses))
            if drain_ack_at is None:
                raise CohortError("drain command 1 lacks its actual receipt boundary")
            remaining = 30.0 - (asyncio.get_running_loop().time() - drain_ack_at)
            if remaining > 0:
                await asyncio.sleep(remaining)
            observations.append(await _observe_owner_remote(
                directory_fd, expected=expected, owner_expected=owner_expected,
                worker_config=worker_config, sequence=7, request_id=request_id,
                session_id=session_id, host_key=host_key, commands=responses))
        else:
            # Removal invalidates both the old status and a distinct new Open.
            await close_client(client, close_state, "initial")
            status_client, status_state = await make_client(old_probe, "old_status")
            start = len(bindings)
            try:
                await execute(status_client, "SessionStatus", Request(
                    protocol_version=1, manifest_fingerprint=expected.manifest_fingerprint,
                    worker_boot_id=expected.boot_id, session_id=session_id,
                    lease_token=opened.lease_token, timeout_ms=5_000), old_probe)
            except Exception as error:
                if not _native_unauthenticated(error):
                    raise CohortError("revoked old SessionStatus did not return native UNAUTHENTICATED") from None
            else:
                raise CohortError("revoked old SessionStatus unexpectedly succeeded")
            status_binding = binding("SessionStatus", start)
            controls["old_session_status_rejection"] = {
                "method": "SessionStatus", "binding": status_binding,
                "native_status": "UNAUTHENTICATED", "returned_response": False,
                "dispatch_count": 1,
                "policy_sha256": owner_expected.initial_snapshot_sha256,
            }
            await close_client(status_client, status_state, "old_status")
            fresh_probe = make_probe()
            fresh_client, fresh_state = await make_client(fresh_probe, "new_open")
            fresh_request = Request(
                protocol_version=1, manifest_fingerprint=expected.manifest_fingerprint,
                worker_boot_id=expected.boot_id, session_id=fresh_probe.context.session_id,
                timeout_ms=5_000, max_positions=12, lifetime_ms=120_000,
                idle_lease_ms=120_000)
            start = len(bindings)
            try:
                await execute(fresh_client, "OpenSession", fresh_request, fresh_probe)
            except Exception as error:
                if not _native_unauthenticated(error):
                    raise CohortError("fresh remove OpenSession did not return native UNAUTHENTICATED") from None
            else:
                raise CohortError("fresh remove OpenSession unexpectedly succeeded")
            controls["new_open_rejection"] = {
                "method": "OpenSession", "binding": binding("OpenSession", start),
                "native_status": "UNAUTHENTICATED", "returned_response": False,
                "dispatch_count": 1,
                "policy_sha256": owner_expected.initial_snapshot_sha256,
            }
            await close_client(fresh_client, fresh_state, "new_open")
            observations.append(await _observe_owner_remote(
                directory_fd, expected=expected, owner_expected=owner_expected,
                worker_config=worker_config, sequence=6, request_id=request_id,
                session_id=session_id, host_key=host_key, commands=responses))
            responses.append(await _publish_owner_action_and_read(
                directory_fd, owner_expected=owner_expected,
                worker_config=worker_config, ssh_host_key_sha256=host_key,
                command_number=2, command=commands[1]))
            command_state["last_response"] = responses[1]
            terminal = responses[1]["protected_status"]
            observations.append(await _observe_owner_remote(
                directory_fd, expected=expected, owner_expected=owner_expected,
                worker_config=worker_config, sequence=7, request_id=request_id,
                session_id=session_id, host_key=host_key, commands=responses,
                terminal_frame=terminal))

        if len(bindings) != (5 if owner_expected.profile == PROFILE_C1B_OWNER_DRAIN else 4):
            raise CohortError("owner direct probe made an unexpected RPC call count")
        if len({row["operation_id"] for row in bindings}) != len(bindings):
            raise CohortError("owner direct RPC calls reused an operation ID")
        cleanup_attempted = True
        cleanup_errors = await direct_owner.close()
        if cleanup_errors:
            raise BaseExceptionGroup("owner direct probe cleanup failed", cleanup_errors)
        expected_labels = (["initial", "new_open"]
                           if owner_expected.profile == PROFILE_C1B_OWNER_DRAIN
                           else ["initial", "old_status", "new_open"])
        close_rows = [rows[label] for label in expected_labels]
        _require_owner_probe_cleanup(probes, command_state)
        cleanup = {
            "confirmed": True, "failure_types": [], "client_closes": close_rows,
            "contexts_released": len(probes), "authorizations_closed": len(probes),
            "transport_reserved_connections": direct_budget.reserved_connections,
            "transport_reserved_pending": direct_budget.reserved_pending,
            "transport_reserved_outbound_pending": direct_budget.reserved_outbound_pending,
            "transport_reserved_listener_pending_capacity": direct_budget.reserved_listener_pending_capacity,
        }
        return _build_owner_actions_result(
            owner_expected, worker_config=worker_config,
            ssh_host_key_sha256=host_key,
            initial_local_serials=initial_local_serials,
            old_local_shutdown=old_local_shutdown, direct_probe=direct_probe,
            commands=responses, controls=controls, observations=observations,
            probe_cleanup=cleanup)
    except BaseException as primary:
        errors = [] if cleanup_attempted else await direct_owner.close()
        if errors or cleanup_errors:
            command_state["direct_cleanup_unconfirmed"] = True
        if errors or cleanup_errors or command_state.get("direct_cleanup_unconfirmed") is True:
            _retain_owner_graph(
                authority, owner_expected, direct_owner, direct_budget,
                tuple(probes), tuple(clients), tuple(bindings), primary)
        if errors or cleanup_errors:
            raise BaseExceptionGroup("owner probe and cleanup failed",
                                     [primary, *cleanup_errors, *errors])
        raise


async def run_cohort(args) -> dict:
    validate_cli_values(args)
    profile = getattr(args, "profile", PROFILE_BASELINE)
    if profile in (PROFILE_C1B_CANCEL, PROFILE_C1B_PARTIAL, PROFILE_C1B_STEP_LOSS) \
            and _RETAINED_CANCELLATION_OWNERS:
        raise CohortError("a prior fenced owner remains retained until process exit")
    if profile in (PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE) \
            and _RETAINED_OWNER_OWNERS:
        raise CohortError("an owner-profile authority/client graph remains retained")
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise CohortError("the secure C1b cohort runner requires the Linux laptop container")
    artifacts = Path(args.artifacts)
    reference_dir = Path(args.reference)
    if not artifacts.is_dir() or artifacts.is_symlink():
        raise CohortError("pinned artifact directory is unavailable or a symlink")
    if not reference_dir.is_dir() or reference_dir.is_symlink():
        raise CohortError("pinned complete-model reference is unavailable or a symlink")
    artifacts = artifacts.resolve(strict=True)
    reference_dir = reference_dir.resolve(strict=True)
    args.artifacts = str(artifacts)
    args.reference = str(reference_dir)
    handoff_fd = validate_handoff_directory(args.handoff_directory)
    if profile == PROFILE_C1B_RESTART:
        if _RETAINED_RESTART_OWNERS:
            os.close(handoff_fd)
            raise CohortError("a prior restart owner remains retained until process exit")
        return await _run_restart_cohort(args, handoff_fd)
    run_id, nonce = secrets.token_hex(16), secrets.token_hex(16)
    result = {
        "schema_version": 1, "event": "result", "run_id": run_id,
        "baseline": {"status": "failed", "completed_requests": 0,
                      "captured_vectors": 0,
                      "lifecycle_extensions": "pending_separate_C1b_gate"},
        "request_ids": [], "session_ids": [], "numerical_errors": {
            "captured_vectors": 0, "values": [], "atol": 1e-3, "rtol": 0.0,
        },
        "cases": [], "local_shutdown": {"confirmed": False},
        "remote_shutdown": {"confirmed": False},
        "pending_scope": [
            "interleaving", "cancellation", "partial_admission", "restart_boot_invalidation",
            "step_reply_loss", "capacity_faults", "additional_C1b_lifecycle_cases",
        ],
    }
    owner = _CleanupOwner()
    authority = None
    expectation = None
    owner_expected = None
    worker_config = None
    owner_commands = None
    owner_action_state = {"last_response": None}
    initial_local_serials = None
    old_local_shutdown = None
    launch_state = {"boot_id": None, "may_have_started": False}
    readiness_observed = False
    remote_host_key = None
    primary = None
    cleanup_errors = []
    pipeline_state = {}
    pipeline_close_attempted = False
    pipeline_close_errors = []

    async def close_pipeline_once():
        nonlocal pipeline_close_attempted, pipeline_close_errors
        if pipeline_close_attempted:
            return pipeline_close_errors
        pipeline_close_attempted = True
        try:
            pipeline_close_errors = await _close_local_pipeline(
                owner, pipeline_state, expected_connections=15)
        except BaseException as error:
            pipeline_close_errors = [error]
        return pipeline_close_errors
    try:
        from steamboat_runtime.manifest import load_manifest
        from steamboat_runtime.prepare import verify_snapshot

        manifest = load_manifest(args.artifacts)
        from steamboat_runtime.manifest import MODEL_ID, MODEL_REVISION
        if manifest.get("model_id") != MODEL_ID or manifest.get("revision") != MODEL_REVISION:
            raise CohortError("artifact directory is not the pinned C0 model")
        verify_snapshot(args.reference)
        fingerprint = _validate_manifest_fingerprint(manifest.get("fingerprint"))
        fixture_class = _load_identity_fixture()
        authority = _create_authority_fixture(
            fixture_class, handoff_directory=args.handoff_directory,
            fingerprint=fingerprint, external_ip=args.external_ip,
            uncertainty=args.clock_uncertainty_seconds)
        provisioned_config = {} if profile in (
            PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE) else None
        bundle_path, expectation, bundle_ready = provision_worker3_bundle(
            authority=authority, manifest=manifest,
            artifact_directory=args.artifacts,
            uncertainty=args.clock_uncertainty_seconds,
            external_ip=args.external_ip, external_port=args.external_port,
            run_id=run_id, nonce=nonce,
            worker_config_out=provisioned_config)
        if profile in (PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE):
            worker_config = provisioned_config.get("worker_config")
            if type(worker_config) is not dict or set(worker_config) != _WORKER_CONFIG_FIELDS:
                raise CohortError("owner profile worker config differs from the frozen schema")
            owner_expected = _owner_expectation(
                profile, remote_expected=expectation, authority=authority,
                worker_config=worker_config)
        _publish_bundle_ready(
            handoff_fd, bundle_ready, boot_id=expectation.boot_id,
            launch_state=launch_state)
        if owner_expected is not None:
            ready_ack = await _wait_for_control(
                handoff_fd, HANDOFF_READY_ACK_FILE, timeout=READY_TIMEOUT_SECONDS)
            remote_host_key = _validate_owner_ready_ack(
                ready_ack, expected=expectation, owner_expected=owner_expected,
                worker_config=worker_config)
        else:
            remote_host_key = await _wait_for_ready(handoff_fd, expectation)
        readiness_observed = True
        result["identities"] = {
            "run_id": run_id,
            "coordinator_boot_id": authority.principals["coordinator"].boot_id,
            "consumer_boot_id": authority.principals["consumer"].boot_id,
            "worker_boot_ids": {
                name: authority.principals[name].boot_id
                for name in ("worker-1", "worker-2", "worker-3")
            },
            "manifest_fingerprint": manifest["fingerprint"],
        }
        await _run_real_pipeline(
            args, authority=authority, manifest=manifest, expected=expectation,
            external_ip=args.external_ip,
            owner=owner, result=result, handoff_fd=handoff_fd,
            remote_host_key=remote_host_key, pipeline_state=pipeline_state,
            profile=profile, owner_expected=owner_expected,
            worker_config=worker_config)
        result["baseline"]["status"] = "passed"
        if owner_expected is not None:
            pipeline_errors = await close_pipeline_once()
            if pipeline_errors:
                raise BaseExceptionGroup("initial local pipeline cleanup failed",
                                         pipeline_errors)
            old_local_shutdown = {"confirmed": True, "failure_types": []}
            if profile == PROFILE_C1B_OWNER_REMOVE:
                prepared = _prepare_owner_materials(
                    authority, owner_expected,
                    command_ids=(secrets.token_hex(16), secrets.token_hex(16)))
                initial_local_serials = prepared["initial_local_serials"]
                _publish_owner_materials(handoff_fd, prepared, owner_expected)
                owner_commands = prepared["commands"]
            else:
                initial_local_serials = _owner_initial_local_serials(
                    authority, worker_config, owner_expected)
                owner_commands = _prepare_owner_drain_commands(
                    owner_expected,
                    command_ids=(secrets.token_hex(16), secrets.token_hex(16)))
            result["owner_actions"] = await _run_owner_direct_probe(
                handoff_fd, authority=authority, expected=expectation,
                owner_expected=owner_expected, worker_config=worker_config,
                host_key=remote_host_key, commands=owner_commands,
                initial_local_serials=initial_local_serials,
                old_local_shutdown=old_local_shutdown,
                command_state=owner_action_state)
    except BaseException as error:
        primary = error
        try:
            diagnostic = _failure_location_record(run_id, nonce, error)
            _safe_write_handoff(
                handoff_fd, HANDOFF_FAILURE_LOCATION_FILE, diagnostic)
        except BaseException:
            # Diagnostics must not replace the primary failure or imply cleanup.
            pass
        result["baseline"]["status"] = "failed"
        result["failure_type"] = type(error).__name__[:80]
    finally:
        cleanup_errors.extend(await close_pipeline_once())
        retained_state_key = {
            PROFILE_C1B_PARTIAL: "partial_admission_state",
            PROFILE_C1B_STEP_LOSS: "step_reply_loss_state",
            PROFILE_C1B_CANCEL: "cancellation_state",
        }.get(profile)
        expected_retained_fence = (
            retained_state_key is not None
            and type(pipeline_state.get(retained_state_key)) is dict
            and pipeline_state[retained_state_key].get("state")
                == "restart_fenced_retained")
        if (profile == PROFILE_C1B_PARTIAL and expected_retained_fence
                and cleanup_errors):
            retained_record = _partial_retained_shutdown_record(
                pipeline_state, result, cleanup_errors)
            if retained_record is not None:
                # This exception is limited to the exact original unknown-Open
                # graph. Keep every owner strongly reachable until the parent
                # proves disposal by this operator process's actual OS exit.
                try:
                    _retain_cancellation_owners(
                        owner, pipeline_state, authority, expectation, result)
                except CohortError:
                    retained_record = None
            if retained_record is not None:
                pipeline_state[retained_state_key]["logical_cleanup_confirmed"] = False
                result["local_shutdown"] = retained_record
                cleanup_errors.clear()
        elif expected_retained_fence and cleanup_errors:
            retained, other = [], []
            for error in cleanup_errors:
                notes = getattr(error, "__notes__", ())
                if (type(error) is CohortError
                        and any("coordinator close" in note for note in notes)):
                    retained.append(error)
                else:
                    other.append(error)
            if len(retained) == 1 and not other:
                # The owner action remains retained by _CleanupOwner and the
                # parent must verify disposal by owned operator-process exit.
                try:
                    _retain_cancellation_owners(
                        owner, pipeline_state, authority, expectation, result)
                except CohortError as error:
                    other.append(error)
                    retained = []
                # Keep coordinator, clients, callbacks, request contexts and
                # task graphs strongly reachable until this owned process exits.
            if len(retained) == 1 and not other:
                retained_state = pipeline_state[retained_state_key]
                retained_state["logical_cleanup_confirmed"] = False
                result["local_shutdown"] = {
                    "confirmed": False,
                    "failure_types": [type(error).__name__ for error in retained],
                    "restart_fenced_retained": True,
                }
                cleanup_errors.clear()
            else:
                cleanup_errors = other + retained
        if not result.get("local_shutdown", {}).get("restart_fenced_retained"):
            result["local_shutdown"] = {
                "confirmed": not cleanup_errors,
                "failure_types": [type(error).__name__[:80] for error in cleanup_errors],
            }
        remote_shutdown = {"confirmed": False}
        try:
            if owner_expected is not None and expectation is not None:
                last_response = owner_action_state.get("last_response")
                last_command = (last_response.get("worker_ack")
                                if type(last_response) is dict else None)
                remote_shutdown = await _stop_remote_owner(
                    handoff_fd, expected=expectation, owner_expected=owner_expected,
                    worker_config=worker_config, host_key=remote_host_key,
                    last_command=last_command,
                    readiness_observed=readiness_observed)
            else:
                remote_shutdown = await _stop_remote(
                    handoff_fd, run_id=run_id, nonce=nonce,
                    boot_id=launch_state["boot_id"],
                    may_have_started=launch_state["may_have_started"],
                    readiness_observed=readiness_observed,
                    host_key=remote_host_key, expected=expectation)
            _record_remote_shutdown(result, remote_shutdown, cleanup_errors)
        except BaseException as error:
            cleanup_errors.append(error)
            result["remote_shutdown"] = {
                "confirmed": False, "failure_type": type(error).__name__[:80],
            }
        owner_profile_active = profile in (
            PROFILE_C1B_OWNER_DRAIN, PROFILE_C1B_OWNER_REMOVE)
        owner_authority_retained = _owner_authority_retention_required(
            active=owner_profile_active, cleanup_errors=cleanup_errors,
            direct_cleanup_unconfirmed=owner_action_state.get(
                "direct_cleanup_unconfirmed"),
            may_have_started=launch_state["may_have_started"],
            remote_shutdown=remote_shutdown)
        if owner_authority_retained and authority is not None:
            try:
                _retain_owner_graph(
                    authority, owner_expected, expectation, worker_config,
                    owner, pipeline_state, result, remote_shutdown)
            except CohortError as error:
                cleanup_errors.append(error)
        elif authority is not None:
            try:
                authority.close()
            except BaseException as error:
                cleanup_errors.append(error)
                if owner_profile_active:
                    owner_authority_retained = True
                    try:
                        _retain_owner_graph(
                            authority, owner_expected, expectation, worker_config,
                            owner, pipeline_state, result, remote_shutdown, error)
                    except CohortError as retain_error:
                        cleanup_errors.append(retain_error)
        if owner_profile_active:
            local_confirmed = (not pipeline_close_errors
                               and not owner_authority_retained
                               and not cleanup_errors)
            result["local_shutdown"] = {
                "confirmed": local_confirmed,
                "failure_types": ([type(error).__name__[:80]
                                   for error in cleanup_errors]
                                  or (["CohortError"] if owner_authority_retained else []))
                    if not local_confirmed else [],
            }
        try:
            if cleanup_errors:
                result["baseline"]["status"] = "failed"
                extensions = result["baseline"].get("lifecycle_extensions")
                if type(extensions) is dict and extensions.get("status") == "passed":
                    extensions["status"] = "failed"
                result.setdefault("failure_type", type(cleanup_errors[0]).__name__[:80])
            _safe_write_handoff(
                handoff_fd, HANDOFF_RESULT_FILE,
                _private_result_summary(result, profile=profile))
        except BaseException as error:
            cleanup_errors.append(error)
        os.close(handoff_fd)

    failures = ([primary] if primary is not None else []) + cleanup_errors
    if failures:
        if len(failures) == 1:
            raise failures[0]
        raise BaseExceptionGroup("secure cohort run and cleanup failed", failures)
    return result


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        validate_cli_values(args)
        result = asyncio.run(run_cohort(args))
        print(json.dumps({"run_id": result["run_id"],
                          "baseline": result["baseline"]["status"]},
                         sort_keys=True, separators=(",", ":")))
        return 0
    except BaseException as error:
        print(f"secure_cohort: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
