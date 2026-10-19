"""Worker adapters that execute only an active, verified host assignment.

These adapters do not start a process or establish worker readiness. The owning
supervisor must still enforce shared resource reservations and runtime policy.
The legacy unpinned path is blocking and intended only for tests/transition. The
production builder requires a lifetime RuntimeArtifactPin and in-memory guard;
the surrounding supervisor must retain pin ownership until child reaping and empty
cgroup confirmation before release.
"""

from .assigned_artifacts import AssignedArtifactError, AssignedArtifactView


_WORKERS = frozenset({"worker-1", "worker-2", "worker-3"})


def _validated_assignment(view):
    if type(view) is not AssignedArtifactView:
        raise AssignedArtifactError("worker execution requires an exact assigned artifact view")
    if view.role != "host":
        raise AssignedArtifactError("only an active host assignment can create a worker executor")
    manifest = view._locked_manifest()
    assignment = view.assignment
    if assignment is None or type(assignment.payload) is not dict:
        raise AssignedArtifactError("verified host assignment is unavailable")
    payload = assignment.payload
    component = payload.get("component")
    if (payload.get("assignment_id") != view.assignment_id
            or payload.get("account_id") != view.account_id
            or payload.get("device_id") != view.device_id
            or payload.get("role") != "host"
            or type(component) is not str or component not in _WORKERS
            or manifest["fingerprint"] != payload.get("manifest_fingerprint")):
        raise AssignedArtifactError("view does not match its active signed host assignment")
    if view.manifest is not manifest:
        # AssignedArtifactView publishes the just-verified manifest object.
        raise AssignedArtifactError("active assignment manifest view is inconsistent")
    return manifest, assignment, component


class AssignedStageExecutor:
    """StageExecutor-compatible adapter around one resident assigned shard."""

    def __init__(self, view, *, guard=None, allow_unpinned_test_only=False):
        if guard is None and allow_unpinned_test_only is not True:
            raise AssignedArtifactError("production assigned execution requires a runtime pin guard")
        if guard is not None:
            from steamboat_connector.artifact_pin import RuntimeAssignmentGuard
            if type(guard) is not RuntimeAssignmentGuard:
                raise AssignedArtifactError("assigned execution requires an exact runtime pin guard")
        manifest, assignment, component = _validated_assignment(view)
        self.view = view
        self.guard = guard
        self.manifest = manifest
        self.worker_name = component
        self.assignment_id = view.assignment_id
        self.assignment_sha256 = assignment.document_sha256
        self.manifest_fingerprint = manifest["fingerprint"]
        self.stage = view.load_stage()
        if (getattr(self.stage, "start", None), getattr(self.stage, "end", None)) != tuple(
                manifest["components"][component]["layer_range"]):
            raise AssignedArtifactError("loaded stage range differs from active assignment")
        current_manifest, current_assignment, current_component = _validated_assignment(view)
        if (current_component != component
                or current_manifest["fingerprint"] != self.manifest_fingerprint
                or current_assignment.document_sha256 != self.assignment_sha256):
            raise AssignedArtifactError("host assignment changed while its stage was loading")
        if guard is not None:
            if (guard.assignment_id != view.assignment_id
                    or guard.account_id != view.account_id
                    or guard.device_id != view.device_id
                    or guard.role != view.role or guard.component != component
                    or guard.manifest_fingerprint != self.manifest_fingerprint):
                raise AssignedArtifactError("runtime pin guard scope differs from assigned stage")
            guard.check()

    def _verify_live_assignment(self):
        if self.guard is not None:
            try:
                self.guard.check()
            except Exception as error:
                raise AssignedArtifactError("active assigned runtime pin is invalid") from error
            if (self.guard.assignment_id != self.assignment_id
                    or self.guard.component != self.worker_name
                    or self.guard.manifest_fingerprint != self.manifest_fingerprint):
                raise AssignedArtifactError("runtime pin guard identity changed")
            return
        manifest, assignment, component = _validated_assignment(self.view)
        if (component != self.worker_name
                or manifest["fingerprint"] != self.manifest_fingerprint
                or assignment.document_sha256 != self.assignment_sha256):
            raise AssignedArtifactError("active assigned stage authorization changed")

    def new_cache(self):
        self._verify_live_assignment()
        if self.guard is None:
            cache = self.view.new_layer_cache()
        else:
            from .model import LayerCache
            cache = LayerCache(self.stage.start, self.stage.end)
        if (getattr(cache, "start", None), getattr(cache, "end", None)) != (
                self.stage.start, self.stage.end):
            raise AssignedArtifactError("new cache does not match the resident assigned stage")
        self._verify_live_assignment()
        return cache

    def execute(self, hidden, cache, position):
        self._verify_live_assignment()
        if (getattr(cache, "start", None), getattr(cache, "end", None)) != (
                self.stage.start, self.stage.end):
            raise AssignedArtifactError("cache does not belong to the resident assigned stage")
        import torch
        # inference_mode is thread-local; WorkerHandler invokes this from its
        # dedicated compute thread, so the context must be entered here.
        with torch.inference_mode():
            result = self.stage(hidden, cache, position)
        # Authorization may expire or be withdrawn while the stage computes.
        # Do not deliver a result after that transition.
        self._verify_live_assignment()
        return result


def build_assigned_worker_handler(view, *, boot_id=None, clock=None,
                                  max_tombstones=4096, enable_queue=False,
                                  queue_capacity=None, on_supervision=None,
                                  pin=None, guard=None,
                                  allow_unpinned_test_only=False):
    """Build a WorkerHandler from one current host assignment.

    The function does not admit the worker to a gateway or claim readiness;
    those require the surrounding supervisor and its independent checks.
    """
    from steamboat_connector.artifact_pin import (RuntimeArtifactPin,
                                                   RuntimeAssignmentGuard)
    if pin is not None and type(pin) is not RuntimeArtifactPin:
        raise AssignedArtifactError("worker pin must be the exact runtime artifact pin")
    if guard is not None and type(guard) is not RuntimeAssignmentGuard:
        raise AssignedArtifactError("worker guard must be an inherited runtime assignment guard")
    if pin is not None and guard is not None:
        raise AssignedArtifactError("provide either a parent pin or a validated child guard")
    if pin is None and guard is None:
        if allow_unpinned_test_only is not True:
            raise AssignedArtifactError("production worker construction requires a runtime artifact pin")
    elif pin is not None:
        if clock is None:
            raise AssignedArtifactError("pinned worker construction requires its core Clock")
        if boot_id != pin.record.get("boot_id"):
            raise AssignedArtifactError("worker boot id must match the runtime pin record")
        try:
            guard = pin.make_guard(child_clock=clock,
                                   child_verifier=view.installer.verifier)
        except Exception as error:
            raise AssignedArtifactError("worker runtime pin guard could not be established") from error
    elif guard is not None and boot_id != guard.pin.record.get("boot_id"):
        raise AssignedArtifactError("worker boot id must match the inherited runtime pin")
    executor = AssignedStageExecutor(view, guard=guard,
                                     allow_unpinned_test_only=allow_unpinned_test_only)
    from .worker_state import WorkerHandler

    options = {
        "boot_id": boot_id,
        "max_tombstones": max_tombstones,
        "enable_queue": enable_queue,
        "queue_capacity": queue_capacity,
        "on_supervision": on_supervision,
    }
    if clock is not None:
        options["clock"] = clock
    return WorkerHandler(executor.manifest, executor.worker_name, executor,
                         **options)
