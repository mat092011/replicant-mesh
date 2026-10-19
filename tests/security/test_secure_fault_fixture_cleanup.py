"""Stdlib regressions for the secure fault fixture's teardown helper.

The opt-in pipeline module imports the pinned model/runtime stack at module
load. These tests source-extract only its real teardown helper and the base
fixture's real failure combiner, so cleanup ownership can be checked without
protobuf, gRPC, or model dependencies.
"""

from __future__ import annotations

import ast
import asyncio
from collections import namedtuple
import inspect
from pathlib import Path
import re
import threading
import time
from types import SimpleNamespace
import unittest


_SECURITY_DIR = Path(__file__).resolve().parent
_FAULT_SOURCE = _SECURITY_DIR / "test_secure_pipeline_faults.py"
_BASE_SOURCE = _SECURITY_DIR / "test_secure_pipeline.py"
_REPO_ROOT = _SECURITY_DIR.parents[1]


def _selected_source(path: Path, *, function_names=(), class_names=(),
                     assignment_names=()):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    functions = set(function_names)
    classes = set(class_names)
    assignments = set(assignment_names)
    selected = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in functions:
                selected.append(node)
        elif isinstance(node, ast.ClassDef):
            if node.name in classes:
                selected.append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
            names = {target.id for target in targets if isinstance(target, ast.Name)}
            if names & assignments:
                selected.append(node)
    return ast.Module(body=selected, type_ignores=[])


def _selected_methods(path: Path, class_name: str, method_names):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    selected = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != class_name:
            continue
        selected = [item for item in node.body
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name in set(method_names)]
        break
    found = {node.name for node in selected}
    missing = set(method_names) - found
    if missing:
        raise AssertionError(f"production source methods missing: {sorted(missing)}")
    return selected


def _load_fault_helpers():
    namespace = {
        "asyncio": asyncio,
        "inspect": inspect,
        "time": time,
    }
    tree = _selected_source(
        _FAULT_SOURCE,
        function_names=("_wait_until", "_install_fenced_restart_cleanup",
                        "_assert_hard_expiry_cause",
                        "_assert_single_open_no_cleanup_retry"),
        assignment_names=(
            "FAULT_EXPIRY_PROOF_TIMEOUT_SECONDS",
            "FAULT_COORDINATOR_CLOSE_TIMEOUT_SECONDS",
            "FAULT_MODEL_CLOSE_TIMEOUT_SECONDS",
            "MAX_RETAINED_UNSAFE_FIXTURE_OWNERS",
            "_UNSAFE_FIXTURE_CLEANUP_OWNERS",
        ),
    )
    exec(compile(tree, str(_FAULT_SOURCE), "exec"), namespace)
    namespace["FAULT_EXPIRY_PROOF_TIMEOUT_SECONDS"] = 0.03
    namespace["FAULT_COORDINATOR_CLOSE_TIMEOUT_SECONDS"] = 0.03
    namespace["FAULT_MODEL_CLOSE_TIMEOUT_SECONDS"] = 0.03
    return namespace


class _ControlledMonotonic:
    """Shared monotonic clock for the extracted worker and core methods."""

    def __init__(self, value):
        self.value = value

    def monotonic(self):
        return self.value

    def __getattr__(self, name):
        return getattr(time, name)


def _load_production_hard_expiry_probe(probe_time=None):
    """Compile the real hard-expiry sweep, notice, invalidation and reclaim methods."""
    notice_type = namedtuple(
        "SessionNotice", "target_device_id worker_boot_id session_id reason")
    captured_notice_type = namedtuple(
        "CapturedNotice", "notice core_owner core_identity")
    methods = list(_selected_source(
        _REPO_ROOT / "src" / "steamboat_security" / "sessions.py",
        function_names=("_expiry_reason",),
    ).body)
    method_sets = (
        (_REPO_ROOT / "src" / "steamboat_security" / "sessions.py",
         "SessionBindings",
         ("_prune_locked", "_notice_locked", "_invalidate_locked",
          "poll", "mark_reclaimed")),
        (_REPO_ROOT / "src" / "steamboat_security" / "authorization.py",
         "Authorizer", ("sweep",)),
        (_REPO_ROOT / "src" / "steamboat_runtime" / "secure_worker_runtime.py",
         "SecureWorkerRuntimeBridge",
         ("_sweep_once", "_expire_drain", "_add_pending_notice", "_process_notices",
          "_invalidate_owner", "_has_live_rpc", "_handler_owns_session",
          "_reconcile", "_remove_owner")),
        (_REPO_ROOT / "src" / "steamboat_runtime" / "worker_state.py",
         "WorkerHandler", ("_terminate", "invalidate_for_authorization")),
    )
    for path, class_name, names in method_sets:
        methods.extend(_selected_methods(path, class_name, names))

    namespace = {
        "re": re,
        "threading": threading,
        "time": time if probe_time is None else probe_time,
        "SessionNotice": notice_type,
        "_SessionNotice": notice_type,
        "_CapturedNotice": captured_notice_type,
        "_CAPTURE_UNSET": object(),
        "ClockError": type("ClockError", (Exception,), {}),
        "SnapshotError": type("SnapshotError", (Exception,), {}),
    }
    exec(compile(ast.Module(body=methods, type_ignores=[]),
                 "production_hard_expiry_methods", "exec"), namespace)
    return namespace


def _load_base_failure_combiner():
    namespace = {}
    tree = _selected_source(
        _BASE_SOURCE,
        function_names=("_combined_pipeline_failure",),
        class_names=("_CleanupFailure",),
    )
    exec(compile(tree, str(_BASE_SOURCE), "exec"), namespace)
    return namespace


def _exception_leaves(error):
    if isinstance(error, BaseExceptionGroup):
        for child in error.exceptions:
            yield from _exception_leaves(child)
    else:
        yield error


class SecureFaultFixtureCleanupTests(unittest.IsolatedAsyncioTestCase):
    def _install(self, *, reclaimed, tombstone_code="EXPIRED_SESSION",
                 close_result=False, close_error=None, close_wait=None,
                 model_result=True, model_error=None, core_record_present=True):
        namespace = _load_fault_helpers()
        session_id = "ses_" + "a" * 32
        now = time.monotonic()
        close_calls = []
        model_calls = []

        class Cache:
            def allocated_bytes(self):
                return 0

            def lengths(self):
                return ()

        class Model:
            def supervision_status(self):
                return {"active_compute": False}

            async def close(self):
                model_calls.append("close")
                if model_error is not None:
                    raise model_error
                return model_result

        class Bindings:
            _records = {}

            @staticmethod
            def key_for(binding):
                return (binding["target_device_id"], binding["worker_boot_id"],
                        binding["session_id"])

        class Completion:
            @staticmethod
            def done():
                return True

        state = type("RequestState", (), {
            "unknown_opens": {0},
            "leases": {},
            "completion": Completion(),
        })()
        model = Model()
        coordinator = type("Coordinator", (), {})()
        coordinator.model = model
        coordinator._requests = {session_id: state}
        coordinator._closed = True
        coordinator._consumers = []
        coordinator._active_jobs = []
        coordinator.stats = lambda: {"stage_queue_sizes": []}

        record = type("BindingRecord", (), {
            "state": "tombstone",
            "reclaimed": True,
            "invalid_reason": "session-hard-expiry",
            "hard_expiry_monotonic": now - 1,
        })()
        principal = type("Principal", (), {
            "device_id": "dev_" + "1" * 32,
            "boot_id": "boot_" + "2" * 32,
        })()
        bindings = Bindings()
        binding_key = bindings.key_for({
            "target_device_id": principal.device_id,
            "worker_boot_id": principal.boot_id,
            "session_id": session_id,
        })
        bindings._records = ({binding_key: record} if core_record_present else {})
        handler = type("Handler", (), {})()
        handler.sessions = {} if reclaimed else {session_id: object()}
        handler.tombstones = {
            session_id: type("Tombstone", (), {
                "terminal_code": tombstone_code,
                "monotonic_terminated_at": now - 0.5,
                "committed_bytes": 0,
                "cache": Cache(),
            })()
        }

        class Bridge:
            @staticmethod
            def status():
                return {
                    "owned_sessions": 0 if reclaimed else 1,
                    "active_authorizations": 0 if reclaimed else 1,
                }

        worker = {
            "principal": principal,
            "bindings": bindings,
            "handler": handler,
            "bridge": Bridge(),
        }

        async def original_close():
            close_calls.append("close")
            if close_wait is not None:
                await asyncio.sleep(close_wait)
            if close_error is not None:
                raise close_error
            return close_result

        action = {
            "active": True,
            "label": "coordinator close",
            "callback": original_close,
        }
        cleanup_owner = type("CleanupOwner", (), {"_actions": [action]})()
        pipeline = {
            "coordinator": coordinator,
            "worker_nodes": [worker],
            "cleanup_owner": cleanup_owner,
        }
        observation = {
            "coordinator_close_action": None,
            "attempts": [{"OpenSession": 1}, {}, {}],
            "open_lifetimes_ms": [[(10_000, 5_000, 6)], [], []],
            "open_reservation": {
                "open_reply_monotonic": now - 10,
                "core_hard_expiry_monotonic": now - 1,
                "core_requested_expiry_monotonic": now - 1,
                "worker_deadline_monotonic": now - 1,
            },
        }
        namespace["_install_fenced_restart_cleanup"](
            self, pipeline, observation, session_id)
        return namespace, action, pipeline, model, close_calls, model_calls

    async def _invoke(self, action):
        result = action["callback"]()
        if inspect.isawaitable(result):
            return await result
        return result

    def test_expiry_oracle_accepts_only_proved_hard_expiry_terminals(self):
        namespace = _load_fault_helpers()
        assert_cause = namespace["_assert_hard_expiry_cause"]
        record = SimpleNamespace(state="tombstone", reclaimed=True,
                                  invalid_reason="session-hard-expiry",
                                  hard_expiry_monotonic=10.0)
        for terminal_code in ("CANCELLED", "EXPIRED_SESSION"):
            tombstone = SimpleNamespace(
                terminal_code=terminal_code, monotonic_terminated_at=10.0)
            assert_cause(self, tombstone=tombstone, binding_record=record,
                         original_hard_expiry=10.0, now_monotonic=10.01)

    def test_expiry_oracle_rejects_early_or_unrelated_cancellation(self):
        assert_cause = _load_fault_helpers()["_assert_hard_expiry_cause"]
        good_tombstone = SimpleNamespace(
            terminal_code="CANCELLED", monotonic_terminated_at=10.0)
        good_record = SimpleNamespace(state="tombstone", reclaimed=True,
                                      invalid_reason="session-hard-expiry",
                                      hard_expiry_monotonic=10.0)
        with self.assertRaises(AssertionError):
            assert_cause(self, tombstone=good_tombstone,
                         binding_record=good_record, original_hard_expiry=10.0,
                         now_monotonic=9.99)

        early_worker_tombstone = SimpleNamespace(
            terminal_code="CANCELLED", monotonic_terminated_at=9.5)
        with self.assertRaises(AssertionError):
            assert_cause(self, tombstone=early_worker_tombstone,
                         binding_record=good_record, original_hard_expiry=10.0,
                         now_monotonic=10.25)

        revoked_record = SimpleNamespace(state="tombstone", reclaimed=True,
                                         invalid_reason="authorization-revoked",
                                         hard_expiry_monotonic=10.0)
        with self.assertRaises(AssertionError):
            assert_cause(self, tombstone=good_tombstone,
                         binding_record=revoked_record, original_hard_expiry=10.0,
                         now_monotonic=10.01)

        unrelated_tombstone = SimpleNamespace(
            terminal_code="CLOSED_SESSION", monotonic_terminated_at=10.0)
        with self.assertRaises(AssertionError):
            assert_cause(self, tombstone=unrelated_tombstone,
                         binding_record=good_record, original_hard_expiry=10.0,
                         now_monotonic=10.01)

    def test_production_hard_expiry_bridge_path_maps_to_cancelled_and_reclaims(self):
        probe_time = _ControlledMonotonic(10.25)
        methods = _load_production_hard_expiry_probe(probe_time)
        target = "dev_" + "1" * 32
        boot = "boot_" + "2" * 32
        session_id = "ses_" + "a" * 32
        hard_expiry = 10.0
        session_key = (target, boot, session_id)

        class ProbeClock:
            def sample(self):
                return SimpleNamespace(monotonic=probe_time.monotonic())

        class ProbeRecord:
            def __init__(self):
                self.key = session_key
                self.state = "open"
                self.requested_expiry_monotonic = hard_expiry
                self.hard_expiry_monotonic = hard_expiry
                self.pending_deadline_monotonic = probe_time.monotonic() + 10
                self.tombstone_deadline = None
                self.invalid_reason = None
                self.reclaimed = False
                self.lease_digest = b"opaque-fixture-only"

        class ProbeBindings:
            _prune_locked = methods["_prune_locked"]
            _notice_locked = methods["_notice_locked"]
            _invalidate_locked = methods["_invalidate_locked"]
            poll = methods["poll"]
            mark_reclaimed = methods["mark_reclaimed"]

            def __init__(self):
                self.clock = ProbeClock()
                self._lock = threading.RLock()
                self._records = {session_key: ProbeRecord()}
                self._affected = {}
                self._callbacks = []
                self._callback_faulted = False
                self.max_records = 8
                self.tombstone_seconds = 30

            def revalidate_snapshot(self, _view, *, sample):
                self.last_revalidated_monotonic = sample.monotonic

        class ProbeCache:
            def __init__(self):
                self.bytes = 64
                self.positions = [1]

            def clear(self):
                self.bytes = 0
                self.positions.clear()

            def allocated_bytes(self):
                return self.bytes

            def lengths(self):
                return tuple(self.positions)

        class ProbeHandler:
            _terminate = methods["_terminate"]
            invalidate_for_authorization = methods["invalidate_for_authorization"]

            def __init__(self):
                self.sessions = {}
                self.tombstones = {}
                self._active_operation = None
                self._queue = []
                self.clock = probe_time.monotonic
                self.limits = {"rpc_timeout_seconds": 5}
                self.requires_restart = False

            @staticmethod
            def _bind_loop():
                return None

            @staticmethod
            def _notify_supervisor():
                return None

        class ProbeAuthorizer:
            sweep = methods["sweep"]

            def __init__(self, bindings):
                self.session_bindings = bindings
                self.clock = bindings.clock
                self.snapshot_store = SimpleNamespace(
                    current=lambda *, sample: sample)

            def _current_view(self):
                return object(), self.clock.sample()

        class ProbeOwner:
            def __init__(self):
                self.target_device_id = target
                self.worker_boot_id = boot
                self.assignment_id = "assignment-fixture"
                self.session_id = session_id
                self.core_owner = ("core-owner",)
                self.core_identity = ("core-identity",)
                self.invalidated = False
                self.invalidation_reason = ""
                self.invalidation_event = None

            @property
            def key(self):
                return (self.target_device_id, self.worker_boot_id,
                        self.assignment_id, self.session_id)

        class ProbeBridge:
            _sweep_once = methods["_sweep_once"]
            _expire_drain = methods["_expire_drain"]
            _add_pending_notice = methods["_add_pending_notice"]
            _process_notices = methods["_process_notices"]
            _invalidate_owner = methods["_invalidate_owner"]
            _has_live_rpc = methods["_has_live_rpc"]
            _handler_owns_session = methods["_handler_owns_session"]
            _reconcile = methods["_reconcile"]
            _remove_owner = methods["_remove_owner"]

            def __init__(self, authorizer, handler, owner, bindings):
                self.authorizer_core = authorizer
                self._handler = handler
                self.session_bindings = bindings
                self.target_device_id = target
                self.worker_boot_id = boot
                self.assignment_id = "assignment-fixture"
                self._SessionNotice = methods["_SessionNotice"]
                self._callback_fault = threading.Event()
                self._notice_lock = threading.RLock()
                self._capture_lock = threading.RLock()
                self._pending_notices = {}
                self._captured_owners = {}
                self._owners = {owner.key: owner}
                self._admitting = 0
                self._operations = {}
                self.notice_capacity = 8
                self._unconfirmed_cleanup = False
                # Match a freshly started bridge: no drain has been requested.
                # The extracted production sweep still invokes the real method.
                self._drain_deadline = None
                self._drain_deadline_reached = False

            @staticmethod
            def _fence(reason):
                raise AssertionError(f"unexpected source-probe fence: {reason}")

        bindings = ProbeBindings()
        handler = ProbeHandler()
        entry = SimpleNamespace(
            session_id=session_id, terminal_code="", terminated_at=None,
            monotonic_terminated_at=0.0, queued=False, in_flight=False,
            cache=ProbeCache(), committed_bytes=64, expires_at=0.0)
        handler.sessions[session_id] = entry
        owner = ProbeOwner()
        authorizer = ProbeAuthorizer(bindings)
        bridge = ProbeBridge(authorizer, handler, owner, bindings)

        # This is the actual source sequence used by bridge maintenance:
        # Authorizer.sweep -> SessionBindings.poll -> notice processing ->
        # WorkerHandler.invalidate_for_authorization -> mark_reclaimed.
        bridge._sweep_once()

        record = bindings._records[session_key]
        tombstone = handler.tombstones[session_id]
        self.assertGreaterEqual(probe_time.monotonic(), hard_expiry)
        self.assertEqual(record.invalid_reason, "session-hard-expiry")
        self.assertEqual(record.state, "tombstone")
        self.assertIs(record.reclaimed, True)
        self.assertEqual(tombstone.terminal_code, "CANCELLED")
        self.assertEqual(tombstone.monotonic_terminated_at,
                         probe_time.monotonic())
        self.assertGreaterEqual(tombstone.monotonic_terminated_at, hard_expiry)
        self.assertEqual(tombstone.committed_bytes, 0)
        self.assertEqual(tombstone.cache.allocated_bytes(), 0)
        self.assertFalse(any(tombstone.cache.lengths()))
        self.assertEqual(handler.sessions, {})
        self.assertEqual(bridge._owners, {})
        self.assertFalse(bridge._unconfirmed_cleanup)

    def test_production_early_cancel_then_core_expiry_is_rejected(self):
        probe_time = _ControlledMonotonic(9.5)
        methods = _load_production_hard_expiry_probe(probe_time)
        target = "dev_" + "1" * 32
        boot = "boot_" + "2" * 32
        session_id = "ses_" + "a" * 32
        key = (target, boot, session_id)
        hard_expiry = 10.0

        class ProbeClock:
            @staticmethod
            def sample():
                return SimpleNamespace(monotonic=probe_time.monotonic())

        class ProbeBindings:
            _prune_locked = methods["_prune_locked"]
            _notice_locked = methods["_notice_locked"]
            _invalidate_locked = methods["_invalidate_locked"]
            poll = methods["poll"]
            mark_reclaimed = methods["mark_reclaimed"]

            def __init__(self):
                self.clock = ProbeClock()
                self._lock = threading.RLock()
                self._records = {key: SimpleNamespace(
                    key=key, state="open", hard_expiry_monotonic=hard_expiry,
                    requested_expiry_monotonic=hard_expiry,
                    pending_deadline_monotonic=hard_expiry + 10,
                    tombstone_deadline=None, invalid_reason=None,
                    reclaimed=False, lease_digest=b"opaque-fixture-only")}
                self._affected = {}
                self._callbacks = []
                self._callback_faulted = False
                self.max_records = 8
                self.tombstone_seconds = 30

            def revalidate_snapshot(self, _view, *, sample):
                self.last_revalidated_monotonic = sample.monotonic

        class ProbeCache:
            def __init__(self):
                self.bytes = 64
                self.positions = [1]

            def clear(self):
                self.bytes = 0
                self.positions.clear()

            def allocated_bytes(self):
                return self.bytes

            def lengths(self):
                return tuple(self.positions)

        class ProbeHandler:
            _terminate = methods["_terminate"]
            invalidate_for_authorization = methods["invalidate_for_authorization"]

            def __init__(self):
                entry = SimpleNamespace(
                    session_id=session_id, terminal_code="", terminated_at=None,
                    monotonic_terminated_at=0.0, queued=False, in_flight=False,
                    cache=ProbeCache(), committed_bytes=64, expires_at=0.0)
                self.sessions = {session_id: entry}
                self.tombstones = {}
                self._active_operation = None
                self._queue = []
                self.clock = probe_time.monotonic
                self.limits = {"rpc_timeout_seconds": 5}
                self.requires_restart = False

            @staticmethod
            def _bind_loop():
                return None

            @staticmethod
            def _notify_supervisor():
                return None

        class ProbeOwner:
            def __init__(self):
                self.session_id = session_id
                self.invalidated = False
                self.invalidation_reason = ""
                self.invalidation_event = None

        class ProbeBridge:
            _invalidate_owner = methods["_invalidate_owner"]

            def __init__(self, selected_handler):
                self._handler = selected_handler
                self._unconfirmed_cleanup = False

            @staticmethod
            def _fence(reason):
                raise AssertionError(f"unexpected source-probe fence: {reason}")

        bindings = ProbeBindings()
        handler = ProbeHandler()

        # Exercise the production worker invalidation at 9.5, before the
        # production core poll reaches its original hard expiry at 10.0.
        self.assertTrue(handler.invalidate_for_authorization(session_id))
        early_tombstone = handler.tombstones[session_id]
        self.assertEqual(early_tombstone.terminal_code, "CANCELLED")
        self.assertEqual(early_tombstone.monotonic_terminated_at, 9.5)
        self.assertEqual(early_tombstone.committed_bytes, 0)
        self.assertEqual(handler.sessions, {})
        self.assertEqual(bindings._records[key].state, "open")

        # A later genuine core hard-expiry poll/reclamation must not make that
        # earlier worker cancellation appear to have been caused by expiry.
        probe_time.value = 10.25

        class ProbeAuthorizer:
            sweep = methods["sweep"]

            def __init__(self, selected_bindings):
                self.session_bindings = selected_bindings
                self.clock = selected_bindings.clock
                self.snapshot_store = SimpleNamespace(
                    current=lambda *, sample: sample)

            def _current_view(self):
                return object(), self.clock.sample()

        authorizer = ProbeAuthorizer(bindings)
        notices = authorizer.sweep()
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0].reason, "session-hard-expiry")
        self.assertEqual(bindings.last_revalidated_monotonic, 10.25)
        owner = ProbeOwner()
        bridge = ProbeBridge(handler)
        bridge._invalidate_owner(owner, notices[0].reason)
        self.assertTrue(owner.invalidated)
        self.assertEqual(owner.invalidation_reason, "session-hard-expiry")
        self.assertEqual(early_tombstone.monotonic_terminated_at, 9.5)
        self.assertTrue(bindings.mark_reclaimed(
            target_device_id=target, worker_boot_id=boot,
            session_id=session_id))
        record = bindings._records[key]
        self.assertEqual(record.state, "tombstone")
        self.assertIs(record.reclaimed, True)
        self.assertEqual(record.invalid_reason, "session-hard-expiry")
        self.assertGreaterEqual(probe_time.monotonic(), hard_expiry)
        self.assertGreaterEqual(probe_time.monotonic(),
                                record.hard_expiry_monotonic)
        self.assertEqual(early_tombstone.cache.allocated_bytes(), 0)
        self.assertFalse(any(early_tombstone.cache.lengths()))

        assert_cause = _load_fault_helpers()["_assert_hard_expiry_cause"]
        with self.assertRaises(AssertionError):
            assert_cause(self, tombstone=early_tombstone,
                         binding_record=record,
                         original_hard_expiry=hard_expiry,
                         now_monotonic=probe_time.monotonic())

    async def test_expiry_timeout_attempts_close_and_preserves_both_failures(self):
        primary = AssertionError("injected reply-loss proof failed")
        close_error = OSError("coordinator close failed")
        namespace, action, pipeline, model, close_calls, model_calls = self._install(
            reclaimed=False, close_error=close_error)

        with self.assertRaises(BaseExceptionGroup) as caught:
            await self._invoke(action)

        self.assertEqual(close_calls, ["close"])
        self.assertEqual(model_calls, [])
        retained = namespace["_UNSAFE_FIXTURE_CLEANUP_OWNERS"]
        self.assertEqual(len(retained), 1)
        self.assertIs(retained[0]["pipeline"], pipeline)
        self.assertIs(retained[0]["coordinator"], pipeline["coordinator"])
        self.assertIs(retained[0]["model"], model)
        leaves = tuple(_exception_leaves(caught.exception))
        self.assertTrue(any(isinstance(item, AssertionError)
                            and "timed out" in str(item) for item in leaves))
        self.assertTrue(any(item is close_error for item in leaves))

        base = _load_base_failure_combiner()
        cleanup_failure = base["_CleanupFailure"]("fenced close", caught.exception)
        combined = base["_combined_pipeline_failure"](
            primary, (cleanup_failure,))
        combined_leaves = tuple(_exception_leaves(combined))
        self.assertIn(primary, combined_leaves)
        self.assertIn(close_error, combined_leaves)

    async def test_failed_expiry_assertion_and_false_close_keep_model_owned(self):
        namespace, action, pipeline, model, close_calls, model_calls = self._install(
            reclaimed=True, tombstone_code="UNEXPECTED", close_result=False)

        with self.assertRaises(BaseExceptionGroup) as caught:
            await self._invoke(action)

        self.assertEqual(close_calls, ["close"])
        self.assertEqual(model_calls, [])
        self.assertTrue(any(isinstance(item, AssertionError)
                            and "EXPIRED_SESSION" in str(item)
                            for item in _exception_leaves(caught.exception)))
        self.assertTrue(any("did not confirm shutdown" in str(item)
                            for item in _exception_leaves(caught.exception)))
        self.assertIs(namespace["_UNSAFE_FIXTURE_CLEANUP_OWNERS"][0]["model"],
                      model)
        self.assertIs(namespace["_UNSAFE_FIXTURE_CLEANUP_OWNERS"][0]["pipeline"],
                      pipeline)

    async def test_missing_core_record_fails_teardown_proof_and_keeps_model(self):
        namespace, action, pipeline, model, close_calls, model_calls = self._install(
            reclaimed=True, close_result=False, core_record_present=False)

        with self.assertRaises(BaseExceptionGroup) as caught:
            await self._invoke(action)

        self.assertEqual(close_calls, ["close"])
        self.assertEqual(model_calls, [])
        self.assertTrue(any(isinstance(item, AssertionError)
                            and "fault-session core binding record is missing"
                            in str(item)
                            for item in _exception_leaves(caught.exception)))
        retained = namespace["_UNSAFE_FIXTURE_CLEANUP_OWNERS"][0]
        self.assertIs(retained["pipeline"], pipeline)
        self.assertIs(retained["model"], model)

    async def test_close_false_only_closes_model_after_full_proof_and_exact_true(self):
        namespace, action, _pipeline, _model, close_calls, model_calls = self._install(
            reclaimed=True, close_result=False, model_result=True)

        result = await self._invoke(action)

        self.assertIs(result, True)
        self.assertEqual(close_calls, ["close"])
        self.assertEqual(model_calls, ["close"])
        self.assertEqual(namespace["_UNSAFE_FIXTURE_CLEANUP_OWNERS"], [])

    async def test_model_close_false_keeps_failure_and_strong_owner(self):
        namespace, action, pipeline, model, close_calls, model_calls = self._install(
            reclaimed=True, close_result=False, model_result=False)

        with self.assertRaises(AssertionError):
            await self._invoke(action)

        self.assertEqual(close_calls, ["close"])
        self.assertEqual(model_calls, ["close"])
        retained = namespace["_UNSAFE_FIXTURE_CLEANUP_OWNERS"][0]
        self.assertIs(retained["pipeline"], pipeline)
        self.assertIs(retained["model"], model)
        self.assertIn(pipeline["worker_nodes"][0]["handler"],
                      retained["resources"])
        self.assertIn("model close was not confirmed", retained["failure"])

    async def test_model_close_nonboolean_return_keeps_failure_and_owner(self):
        model_result = "closed"
        namespace, action, pipeline, model, close_calls, model_calls = self._install(
            reclaimed=True, close_result=False, model_result=model_result)

        with self.assertRaises(AssertionError):
            await self._invoke(action)

        self.assertEqual(close_calls, ["close"])
        self.assertEqual(model_calls, ["close"])
        retained = namespace["_UNSAFE_FIXTURE_CLEANUP_OWNERS"][0]
        self.assertIs(retained["pipeline"], pipeline)
        self.assertIs(retained["model"], model)
        self.assertIn("model close was not confirmed", retained["failure"])

    async def test_model_close_exception_keeps_failure_and_strong_owner(self):
        model_error = OSError("model shutdown failed")
        namespace, action, pipeline, model, close_calls, model_calls = self._install(
            reclaimed=True, close_result=False, model_error=model_error)

        with self.assertRaises(OSError) as caught:
            await self._invoke(action)

        self.assertIs(caught.exception, model_error)
        self.assertEqual(close_calls, ["close"])
        self.assertEqual(model_calls, ["close"])
        retained = namespace["_UNSAFE_FIXTURE_CLEANUP_OWNERS"][0]
        self.assertIs(retained["pipeline"], pipeline)
        self.assertIs(retained["model"], model)
        self.assertIn("model close was not confirmed", retained["failure"])

    async def test_original_close_timeout_is_bounded_and_retains_unsafe_owner(self):
        namespace, action, pipeline, model, close_calls, model_calls = self._install(
            reclaimed=True, close_result=False, close_wait=1.0)

        with self.assertRaises(asyncio.TimeoutError):
            await self._invoke(action)

        self.assertEqual(close_calls, ["close"])
        self.assertEqual(model_calls, [])
        self.assertIs(namespace["_UNSAFE_FIXTURE_CLEANUP_OWNERS"][0]["pipeline"],
                      pipeline)
        self.assertIs(namespace["_UNSAFE_FIXTURE_CLEANUP_OWNERS"][0]["model"],
                      model)


if __name__ == "__main__":
    unittest.main()
