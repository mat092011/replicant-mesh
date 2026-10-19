"""Worker adapters that execute only an active, verified host assignment.

These adapters do not start a process or establish worker readiness. The owning
supervisor must still enforce shared resource reservations and runtime policy.
"""

from steamboat_connector.catalog import CatalogError

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

    def __init__(self, view):
        manifest, assignment, component = _validated_assignment(view)
        self.view = view
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

    def _verify_live_assignment(self):
        try:
            self.view._verify_current_expiry()
        except CatalogError as error:
            raise AssignedArtifactError(
                "catalog or assignment expired before assigned stage operation") from error
        assignment = self.view.assignment
        if (assignment is None
                or assignment.document_sha256 != self.assignment_sha256
                or assignment.payload.get("assignment_id") != self.assignment_id
                or assignment.payload.get("component") != self.worker_name
                or assignment.payload.get("manifest_fingerprint") != self.manifest_fingerprint):
            raise AssignedArtifactError("assigned stage authorization changed")

    def new_cache(self):
        self._verify_live_assignment()
        cache = self.view.new_layer_cache()
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
            return self.stage(hidden, cache, position)


def build_assigned_worker_handler(view, *, boot_id=None, clock=None,
                                  max_tombstones=4096, enable_queue=False,
                                  queue_capacity=None, on_supervision=None):
    """Build a WorkerHandler from one current host assignment.

    The function does not admit the worker to a gateway or claim readiness;
    those require the surrounding supervisor and its independent checks.
    """
    executor = AssignedStageExecutor(view)
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
