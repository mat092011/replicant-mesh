import re


ROLE_NAMES = ("consumer", "host", "coordinator")
TELEMETRY_NAMES = ("battery", "idle", "power", "thermal")
LIMIT_FIELDS = (
    "memory_ceiling_bytes", "memory_headroom_bytes", "cpu_quota_millis",
    "disk_ceiling_bytes", "send_bytes_per_second", "receive_bytes_per_second",
    "total_network_bytes", "cleanup_send_bytes_per_second",
    "cleanup_receive_bytes_per_second", "cleanup_total_network_bytes",
    "max_sessions", "max_queued_calls", "max_request_seconds",
)
MEMORY_FIELDS = (
    "weights_bytes", "kv_bytes", "temporary_bytes", "runtime_bytes",
    "communication_bytes", "capture_bytes",
)
RESERVATION_FIELDS = MEMORY_FIELDS + (
    "cpu_quota_millis", "disk_bytes", "send_bytes_per_second",
    "receive_bytes_per_second", "total_network_bytes",
    "cleanup_send_bytes_per_second", "cleanup_receive_bytes_per_second",
    "cleanup_total_network_bytes", "sessions", "queued_calls",
    "max_request_seconds",
)
MAX_INTEGER = (1 << 63) - 1
_POOL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _integer(value, name, *, minimum=0, maximum=MAX_INTEGER):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def validate_policy(document):
    if type(document) is not dict:
        raise ValueError("policy must be an object")
    if set(document) != {"version", "pool_id", "limits", "reservations", "required_telemetry"}:
        raise ValueError("policy fields do not match version 1")
    if document["version"] != 1 or type(document["version"]) is not int:
        raise ValueError("unsupported policy version")
    pool_id = document["pool_id"]
    if not isinstance(pool_id, str) or not _POOL_PATTERN.fullmatch(pool_id):
        raise ValueError("pool_id must be a bounded physical-pool label")
    limits = document["limits"]
    if type(limits) is not dict or set(limits) != set(LIMIT_FIELDS):
        raise ValueError("all owner resource limits are required")
    normalized_limits = {}
    for field in LIMIT_FIELDS:
        minimum = 0 if field in ("memory_headroom_bytes", "max_queued_calls") else 1
        maximum = MAX_INTEGER
        if field == "cpu_quota_millis":
            maximum = 100_000
        elif field == "max_sessions":
            maximum = 8
        elif field == "max_queued_calls":
            maximum = 8
        elif field == "max_request_seconds":
            maximum = 300
        normalized_limits[field] = _integer(limits[field], field, minimum=minimum,
                                              maximum=maximum)
    if normalized_limits["memory_headroom_bytes"] >= normalized_limits["memory_ceiling_bytes"]:
        raise ValueError("protected memory headroom must be below the memory ceiling")
    telemetry = document["required_telemetry"]
    if (type(telemetry) is not list or len(telemetry) != len(set(telemetry))
            or any(item not in TELEMETRY_NAMES for item in telemetry)):
        raise ValueError("required_telemetry must be a unique list of supported policy names")
    reservations = document["reservations"]
    if type(reservations) is not dict or any(role not in ROLE_NAMES for role in reservations):
        raise ValueError("reservations must be keyed by known roles")
    normalized_reservations = {}
    for role, values in reservations.items():
        if type(values) is not dict or set(values) != set(RESERVATION_FIELDS):
            raise ValueError(f"{role} reservation must name every bounded resource")
        item = {}
        for field in RESERVATION_FIELDS:
            minimum = 0
            maximum = MAX_INTEGER
            if field == "cpu_quota_millis":
                maximum = 100_000
            elif field == "sessions":
                maximum = 8
            elif field == "queued_calls":
                maximum = 8
            elif field == "max_request_seconds":
                minimum, maximum = 1, 300
            item[field] = _integer(values[field], f"{role}.{field}",
                                   minimum=minimum, maximum=maximum)
        normalized_reservations[role] = item
    return {
        "version": 1,
        "pool_id": pool_id,
        "limits": normalized_limits,
        "reservations": normalized_reservations,
        "required_telemetry": sorted(telemetry),
    }


def role_blockers(policy, role, *, enforcement, telemetry, secure_runtime=False):
    if role not in ROLE_NAMES:
        return ["unknown_role"]
    blockers = []
    if role == "consumer":
        if not secure_runtime:
            blockers.append("secure_consumer_transport_unavailable")
        return blockers
    if policy is None:
        return ["owner_resource_policy_missing", "secure_admission_unavailable",
                "approved_artifact_runtime_unavailable"]
    if role not in policy["reservations"]:
        blockers.append("role_reservation_missing")
    if not enforcement.get("memory_cpu", False):
        blockers.append("memory_cpu_enforcement_unavailable")
    if not enforcement.get("disk", False):
        blockers.append("disk_quota_enforcement_unavailable")
    if not enforcement.get("bandwidth", False):
        blockers.append("bandwidth_enforcement_unavailable")
    if not secure_runtime:
        blockers.extend(("secure_admission_unavailable", "approved_artifact_runtime_unavailable"))
    required = set(policy["required_telemetry"])
    for name in sorted(required):
        status = telemetry.get(name)
        if not isinstance(status, dict) or not status.get("fresh", False):
            blockers.append(f"telemetry_{name}_unavailable")
    return blockers
