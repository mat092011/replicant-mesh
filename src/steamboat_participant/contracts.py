"""C0 configuration and synthetic binding checks; no transport or authorization.

Validation establishes declarations and arithmetic only. It cannot verify real
capacity, certificates, revocation freshness, enforcement, or numerical execution.
"""

from datetime import datetime
import hashlib

from .contract_schema import ContractError, canonical_bytes, load_json, require, validate_structure


FIXED_RANGES = {"worker-1": (0, 3), "worker-2": (3, 6), "worker-3": (6, 8)}
WEIGHT_BYTES = {"worker-1": 787968, "worker-2": 787968, "worker-3": 525312,
                "coordinator": 16384256, "reference": 18485504, "consumer": 0, "daemon": 0, "gateway": 0}
COMPONENT_ROLES = {"worker-1": "host", "worker-2": "host", "worker-3": "host",
                   "coordinator": "orchestrator", "reference": "reference", "consumer": "consumer",
                   "daemon": "daemon", "gateway": "gateway"}
REQUIRED_FAULTS = {"wrong_root", "wrong_identity", "wrong_role", "expired_credential", "revoked_credential",
                   "stolen_session", "rotation", "stale_registry", "partial_admission", "ambiguous_mutation",
                   "restart_boot", "interleaving", "context_boundary", "cancellation", "hung_compute",
                   "slow_consumer", "capacity_exhaustion", "cleanup"}
REQUIRED_DEPENDENCIES = {"second_physical_device": "C1b", "gateway_owner_budget": "C2b",
                         "gpu_backend_hardware": "C3a", "trial_hardware_freeze": "remote_trials",
                         "registry_catalog_owner_budget": "remote_trials", "local_c0_review": "remote_trials",
                         "local_c1a_evidence": "C1b", "local_c1a_c2a_evidence": "C2b"}


def fingerprint(document):
    return hashlib.sha256(canonical_bytes(document)).hexdigest()


def _unique(items, key, rule, path):
    require(len({item[key] for item in items}) == len(items), rule, path, "duplicate keyed record")


def _endpoints(document):
    security, route = document["security"], document["route"]
    result = [security["registry"], security["catalog"], route["coordinator"]]
    result.extend(stage["owner"] for stage in route["stages"])
    if security["gateway"] is not None:
        result.append(security["gateway"])
    return result


def _security(document):
    security, limits, route = document["security"], document["limits"], document["route"]
    outbound = security["profile"] == "outbound_gateway_mtls"
    require((security["gateway"] is not None) == outbound
            and security["gateway_trust"] == ("trusted_terminates_plaintext" if outbound else "not_used"),
            "security_gateway", "$.security", "gateway presence and explicit terminating trust must match profile")
    require(limits["gateway_streams"] == int(outbound)
            and (limits["gateway_queue_messages"] > 0) == outbound
            and (limits["gateway_queue_bytes"] > 0) == outbound,
            "security_gateway", "$.limits", "outbound channel needs bounded flow control; direct uses none")
    require(limits["connection_lifetime_ms"] <= security["credential_lifetime_ms"]
            and limits["connection_idle_ms"] <= limits["connection_lifetime_ms"],
            "security_lifetime", "$.limits", "connection cannot outlive its credential or idle ceiling")
    require(security["credential_renew_before_ms"] < security["credential_lifetime_ms"]
            and security["authorization_refresh_ms"] + security["authorization_expiry_check_ms"]
            < security["authorization_snapshot_lifetime_ms"],
            "security_lifetime", "$.security", "renewal and authorization refresh must precede expiry")
    endpoints = _endpoints(document)
    device_accounts = {document["identity"]["device_id"]: document["identity"]["account_id"]}
    for endpoint in endpoints:
        identity = endpoint["identity"]
        account = device_accounts.setdefault(identity["device_id"], identity["account_id"])
        require(account == identity["account_id"], "identity_device", "$.security",
                "a stable device must belong to exactly one account")
        labels = endpoint["dns_name"].split(".")
        require(all(1 <= len(label) <= 63 and label[0] != "-" and label[-1] != "-" for label in labels),
                "security_endpoint", "$.security", "invalid fixed DNS authority")
    certificate_owners = {}
    for endpoint in endpoints:
        principal = (endpoint["identity"]["account_id"], endpoint["identity"]["device_id"])
        previous = certificate_owners.setdefault(endpoint["certificate_sha256"], principal)
        require(previous == principal, "identity_certificate", "$.security", "one certificate cannot assert different enrolled devices/accounts")
    require(len({(item["dns_name"], item["port"]) for item in endpoints}) == len(endpoints),
            "security_endpoint", "$.security", "each fixed service must have an explicit distinct endpoint")
    certificate_roles = {}
    endpoint_roles = ["registry", "catalog", "personal_coordinator"] + ["host"] * len(route["stages"])
    if security["gateway"] is not None:
        endpoint_roles.append("gateway")
    for endpoint, role in zip(endpoints, endpoint_roles):
        previous = certificate_roles.setdefault(endpoint["certificate_sha256"], role)
        require(previous == role, "identity_certificate_role", "$.security",
                "different device roles require distinct certificates and keys")
    executors = [route["coordinator"]["identity"]] + [stage["owner"]["identity"] for stage in route["stages"]]
    boots = [document["identity"]["boot_id"]] + [identity["boot_id"] for identity in executors]
    require(len(set(boots)) == len(boots), "identity_boot", "$.route",
            "daemon, coordinator and workers require distinct process boot identities")
    local_coordinator = route["coordinator"]["identity"]["device_id"] == document["identity"]["device_id"]
    require(local_coordinator == (document["roles"]["orchestrator"] == "personal"),
            "role_binding", "$.route.coordinator", "local coordinator needs explicit personal-role opt-in")
    if document["roles"]["orchestrator"] == "personal":
        require(route["coordinator"]["identity"]["account_id"] == document["identity"]["account_id"],
                "role_binding", "$.route.coordinator", "personal coordinator must belong to this account/device")


def _limits(document):
    limits, compatibility, policy = document["limits"], document["compatibility"], document["policy"]
    relations = (
        (limits["connections_per_peer"] <= limits["connections_total"], "peer connection budget"),
        (limits["control_streams"] + limits["gateway_streams"] + limits["pending_handshakes"] + 3
         + limits["client_tls_channels"] <= limits["connections_total"], "established TLS channels plus pending handshake slots"),
        (limits["client_streams"] <= limits["client_tls_channels"] * limits["streams_per_connection"],
         "client stream capacity across allocated TLS channels"),
        (limits["file_descriptors"] >= (limits["connections_total"] + limits["pending_handshakes"]) * 2
         + limits["management_connections"] + 16, "TLS, handshake and local Unix descriptor budget"),
        (limits["client_streams"] >= limits["active_sessions"] + limits["waiting_admissions"], "client stream budget"),
        (limits["tenant_active_sessions"] <= limits["active_sessions"], "tenant active budget"),
        (limits["tenant_waiting_admissions"] <= limits["waiting_admissions"], "tenant queue budget"),
        (limits["owner_reserved_sessions"] <= limits["active_sessions"], "owner share budget"),
        (limits["renew_ms"] + limits["lease_check_ms"] < limits["idle_lease_ms"], "renewal before lease expiry"),
        (max(limits["admission_ms"], limits["rpc_ms"], limits["idle_lease_ms"]) <= limits["request_ms"], "request lifetime budget"),
        (limits["tombstone_ms"] >= limits["rpc_ms"], "replay protection for RPC lifetime"),
        (limits["session_records"] >= limits["active_sessions"], "live plus tombstone records"),
        (limits["cleanup_ms"] >= limits["compute_cancel_grace_ms"] + limits["lease_check_ms"], "cleanup and cancellation grace"),
        (limits["shutdown_ms"] >= limits["cleanup_ms"], "shutdown budget"),
        (policy["stop_grace_ms"] <= limits["compute_cancel_grace_ms"], "owner stop grace"),
        (policy["drain_ms"] <= limits["request_ms"], "bounded owner drain"),
        (limits["activation_bytes"] == compatibility["runtime_context"] * 64 * 4, "activation shape bytes"),
        (limits["message_bytes"] >= limits["activation_bytes"] + 65536, "activation and metadata envelope"),
        (limits["logit_message_bytes"] <= limits["message_bytes"], "validation logit envelope"),
        (limits["logit_message_bytes"] >= compatibility["vocabulary_size"] * 32 + limits["token_event_bytes"],
         "conservative last-position float32 JSON logits and token metadata"),
        (limits["control_queue_bytes"] >= limits["control_queue_messages"] * limits["control_message_bytes"], "control queue bytes"),
        (limits["gateway_queue_bytes"] >= limits["gateway_queue_messages"] * limits["message_bytes"], "gateway queue bytes"),
        (limits["cache_positions_per_worker"] >= limits["active_sessions"] * compatibility["runtime_context"], "cache position reservations"),
        (limits["cache_bytes_per_worker"] >= limits["active_sessions"] * compatibility["runtime_context"] * 3 * 2 * 64 * 4, "largest stage KV reservation"),
        (policy["disk_ceiling_bytes"] >= policy["artifact_bytes"] + policy["download_staging_bytes"] + policy["logs_bytes"], "artifact, staging and log disk budget"),
        (policy["download_staging_bytes"] >= policy["artifact_bytes"], "interrupted download staging budget"),
        (limits["gateway_bytes_per_lifetime"] <= policy["traffic_bytes_per_day"], "gateway traffic allowance"),
    )
    for condition, explanation in relations:
        require(condition, "limits_relation", "$.limits", explanation)


def _resources(document):
    pools, reservations = document["pools"], document["reservations"]
    limits, roles = document["limits"], document["roles"]
    _unique(pools, "pool_id", "pool_identity", "$.pools")
    _unique(pools, "device_id", "pool_identity", "$.pools")
    _unique(reservations, "reservation_id", "reservation_identity", "$.reservations")
    _unique(reservations, "component", "reservation_identity", "$.reservations")
    by_pool = {pool["pool_id"]: pool for pool in pools}
    by_component = {item["component"]: item for item in reservations}
    required_components = {"daemon"}
    if roles["consumer"]:
        required_components.add("consumer")
    if document["route"]["coordinator"]["identity"]["device_id"] == document["identity"]["device_id"]:
        required_components.add("coordinator")
    local_stages = {stage["component"]: stage for stage in document["route"]["stages"]
                    if stage["owner"]["identity"]["device_id"] == document["identity"]["device_id"]}
    require(roles["host"] == bool(local_stages), "role_binding", "$.roles.host",
            "host permission must explicitly cover local assigned stages")
    required_components.update(local_stages)
    require(required_components <= set(by_component)
            and set(by_component) <= required_components | {"reference", "gateway"},
            "role_reservation", "$.reservations", "all enabled local roles need separate accounted components")
    for item in reservations:
        component = item["component"]
        require(item["pool_id"] in by_pool, "pool_binding", "$.reservations", "reservation refers to unknown pool")
        require(item["role"] == COMPONENT_ROLES[component], "role_reservation", "$.reservations", "role/component mismatch")
        pool = by_pool[item["pool_id"]]
        require(pool["device_id"] == document["identity"]["device_id"], "pool_binding", "$.pools",
                "local ledger cannot claim another device's physical memory")
        require(item["weights_bytes"] >= WEIGHT_BYTES[component], "reservation_weights", "$.reservations",
                "resident learned weights including coordinator input/output must fit")
        if component in FIXED_RANGES or component == "reference":
            layers = FIXED_RANGES[component][1] - FIXED_RANGES[component][0] if component in FIXED_RANGES else 8
            required_kv = layers * 2 * 64 * 4 * document["compatibility"]["runtime_context"] * limits["active_sessions"]
            require(item["kv_bytes"] >= required_kv, "reservation_kv", "$.reservations", "all session KV reservations must fit")
        minimum_buffers = ((2 * (limits["stage_queue"] + 1) + limits["connections_total"]
                            + limits["pending_handshakes"]) * limits["message_bytes"]
                           + limits["control_queue_bytes"] + limits["gateway_queue_bytes"]
                           + limits["output_queue_tokens"] * limits["active_sessions"] * limits["token_event_bytes"]
                           + limits["logit_message_bytes"])
        if component == "coordinator":
            minimum_buffers += (limits["active_sessions"] * (limits["output_queue_tokens"] + 2)
                                * limits["logit_message_bytes"])
        require(item["communication_bytes"] >= minimum_buffers, "reservation_buffers", "$.reservations",
                "conservative connection, handshake, queue, output and validation buffers must fit")
    for pool in pools:
        require(pool["ceiling_bytes"] + pool["owner_margin_bytes"] <= pool["capacity_bytes"],
                "pool_capacity", "$.pools", "policy ceiling plus owner margin exceeds physical capacity")
        require((pool["free_before_start_bytes"] is None) == (pool["observation"] == "unavailable"),
                "pool_observation", "$.pools", "unavailable telemetry must be null, not invented")
        if pool["free_before_start_bytes"] is not None:
            require(pool["free_before_start_bytes"] <= pool["capacity_bytes"], "pool_capacity", "$.pools", "free bytes exceed capacity")
        owned = [item for item in reservations if item["pool_id"] == pool["pool_id"]]
        require(bool(owned), "pool_binding", "$.pools", "unused pools cannot inflate advertised capacity")
        peak = sum(sum(item[name] for name in ("weights_bytes", "kv_bytes", "temporary_bytes", "communication_bytes",
                                               "runtime_bytes", "startup_extra_bytes")) for item in owned)
        available = pool["free_before_start_bytes"]
        ceiling = pool["ceiling_bytes"] if available is None else min(pool["ceiling_bytes"], available - pool["owner_margin_bytes"])
        require(peak <= ceiling, "pool_reservation", "$.reservations",
                "sum of all role and simultaneous startup reservations exceeds physical pool")


def _participant(document):
    _unique(document["route"]["stages"], "assignment_id", "assignment_identity", "$.route.stages")
    for stage in document["route"]["stages"]:
        require((stage["layer_start"], stage["layer_stop"]) == FIXED_RANGES[stage["component"]],
                "placement_range", "$.route.stages", "only the unchanged M0-M5 partition is supported")
    require([stage["component"] for stage in document["route"]["stages"]] == list(FIXED_RANGES),
            "placement_coverage", "$.route.stages", "each fixed layer range must appear exactly once in order")
    _security(document)
    _limits(document)
    _resources(document)


def _experiment(document):
    _unique(document["dependencies"], "dependency_id", "dependency_identity", "$.dependencies")
    dependencies = {item["dependency_id"]: item for item in document["dependencies"]}
    require(set(REQUIRED_DEPENDENCIES) <= set(dependencies), "dependency_missing", "$.dependencies", "required external dependency omitted")
    for dependency_id, required_for in REQUIRED_DEPENDENCIES.items():
        require(dependencies[dependency_id]["required_for"] == required_for, "dependency_scope", "$.dependencies", "dependency assigned to wrong gate")
    for dependency in document["dependencies"]:
        require(dependency["required_for"] != "C0" or dependency["state"] == "confirmed",
                "dependency_local", "$.dependencies", "an unresolved local design choice cannot be deferred as hardware")
        require((dependency["state"] == "confirmed") == (dependency["owner_account_id"] is not None and dependency["resolution"] is not None),
                "dependency_confirmation", "$.dependencies", "confirmation needs a named accountable owner and resolution")
    require(REQUIRED_FAULTS <= set(document["fault_cases"]), "experiment_faults", "$.fault_cases", "mandatory negative/lifecycle cases omitted")
    require(max(document["prompt_tokens"]) + document["forced_decode_tokens"] <= document["compatibility"]["runtime_context"],
            "experiment_context", "$.prompt_tokens", "prompt and forced continuation exceed runtime context")
    frozen_fields = ("participant_config_sha256", "source_commit", "image_digest", "frozen_at_utc")
    if document["status"] == "awaiting_hardware":
        require(not document["hardware"] and not document["execution_device_ids"]
                and all(document[name] is None for name in frozen_fields)
                and any(item["state"] == "open" for item in document["dependencies"]),
                "experiment_awaiting", "$", "unfrozen template must not resemble a measured/frozen environment")
    else:
        require(document["gate"] in ("C1b", "C2b") and bool(document["hardware"])
                and all(document[name] is not None for name in frozen_fields)
                and document["compatibility"]["artifact_manifest_sha256"] is not None,
                "experiment_freeze", "$", "trials require actual hardware, source, image, config and freeze time")
        try:
            datetime.strptime(document["frozen_at_utc"], "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as error:
            raise ContractError("experiment_freeze", "$.frozen_at_utc", "invalid UTC calendar date") from error
        _unique(document["hardware"], "device_id", "hardware_identity", "$.hardware")
        _unique(document["hardware"], "physical_host_id", "hardware_identity", "$.hardware")
        require(len(document["hardware"]) >= 2, "experiment_hardware", "$.hardware", "remote gate requires distinct physical hosts")
        hardware = {item["device_id"]: item for item in document["hardware"]}
        execution_devices = set(document["execution_device_ids"])
        require(execution_devices <= set(hardware)
                and len({hardware[device]["physical_host_id"] for device in execution_devices}) >= 2,
                "experiment_hardware", "$.execution_device_ids", "the declared executing route must span two physical hosts")
        for dependency in document["dependencies"]:
            if dependency["required_for"] in (document["gate"], "remote_trials"):
                require(dependency["state"] == "confirmed", "experiment_dependency", "$.dependencies", "trial dependency still open")
        require(document["gate"] != "C2b" or document["route_profile"] == "outbound_gateway_mtls",
                "experiment_route", "$.route_profile", "C2b requires the outbound route, not direct-only evidence")


def _evidence(document):
    _unique(document["checks"], "check_id", "evidence_identity", "$.checks")
    template = document["status"] == "template_not_executed"
    require(template or document["source_commit"] is not None, "evidence_provenance", "$", "executed checks require exact source provenance")
    require(not template or document["source_commit"] is None, "evidence_template", "$", "template must not claim executed provenance")
    for check in document["checks"]:
        executed = check["outcome"] in ("passed", "failed")
        require(not template or check["outcome"] == "not_run", "evidence_template", "$.checks", "template cannot claim execution")
        require(executed == (check["exit_code"] is not None and check["sanitized_report_sha256"] is not None),
                "evidence_result", "$.checks", "executed check needs exit status and sanitized report hash")
        if executed:
            require((check["exit_code"] == 0) == (check["outcome"] == "passed"), "evidence_exit", "$.checks", "outcome and exit status disagree")
        else:
            require(check["reason"] is not None and check["exit_code"] is None and check["sanitized_report_sha256"] is None,
                    "evidence_skip", "$.checks", "missing/skipped execution needs reason and no invented result")


def _operation(document):
    method = document["method"]
    require(document["timeout_ms"] <= document["remaining_request_ms"], "operation_deadline", "$", "RPC must be clipped to remaining monotonic request budget")
    require(document["position"] + document["token_count"] <= document["reserved_context"],
            "operation_context", "$", "operation exceeds its session reservation")
    require((document["lease_sha256"] is None) == (method == "OpenSession"), "operation_lease", "$", "lease is mandatory after Open only")
    require((document["payload_sha256"] is not None) == (method == "Step")
            and (document["token_count"] > 0) == (method == "Step"),
            "operation_payload", "$", "only Step has activation identity/count; irrelevant fields forbidden")
    if method == "OpenSession":
        require(document["sequence"] == document["position"] == 0, "operation_open", "$", "new session starts at zero")


def validate_document(document):
    validate_structure(document)
    validators = {"participant": _participant, "experiment": _experiment,
                  "evidence": _evidence, "session_operation": _operation}
    validators[document["kind"]](document)
    return document


def validate_binding(operation, participant):
    """Check declared bindings, not possession of credentials or live cache state."""
    validate_document(operation)
    validate_document(participant)
    require(operation["kind"] == "session_operation" and participant["kind"] == "participant",
            "binding_kind", "$", "binding requires operation and participant documents")
    route = participant["route"]
    stage = next(item for item in route["stages"] if item["component"] == operation["component"])
    require(operation["consumer"]["account_id"] == operation["coordinator"]["account_id"],
            "binding_consumer", "$", "personal coordination is limited to the consumer's account")
    require(operation["coordinator"] == route["coordinator"]["identity"],
            "binding_coordinator", "$", "coordinator account/device/boot differs from the route")
    require(operation["worker"] == stage["owner"]["identity"], "binding_worker", "$", "worker device/boot changed; invalidate old bindings")
    local_device = participant["identity"]["device_id"]
    local_roles = ((operation["consumer"], participant["roles"]["consumer"]),
                   (operation["coordinator"], participant["roles"]["orchestrator"] == "personal"),
                   (operation["worker"], participant["roles"]["host"]))
    require(any(identity["device_id"] == local_device and enabled for identity, enabled in local_roles),
            "binding_role", "$", "operation must involve an enabled local role")
    for identity, enabled in local_roles:
        if identity["device_id"] == local_device:
            require(enabled and identity["account_id"] == participant["identity"]["account_id"],
                    "binding_role", "$", "local principal must have its role enabled under the device owner")
    require(operation["assignment_id"] == stage["assignment_id"]
            and operation["binding_version"] == stage["binding_version"],
            "binding_assignment", "$", "assignment or secure binding version differs from the stage")
    require(operation["route_id"] == route["route_id"] and operation["route_epoch"] == route["epoch"],
            "binding_route", "$", "route binding mismatch")
    require(operation["credential_epoch"] == participant["security"]["credential_epoch"],
            "binding_credential", "$", "credential rotation requires a fresh session binding")
    require(operation["compatibility_sha256"] == fingerprint(participant["compatibility"]),
            "binding_compatibility", "$", "model/runtime/artifact compatibility mismatch")
    require(operation["reserved_context"] <= participant["compatibility"]["runtime_context"]
            and operation["timeout_ms"] <= participant["limits"]["rpc_ms"]
            and operation["remaining_request_ms"] <= participant["limits"]["request_ms"],
            "binding_limits", "$", "operation exceeds admitted configuration")
    return operation


def validate_experiment_binding(experiment, participant):
    """Check a trial freeze against declarations; actual inventory still needs review."""
    validate_document(experiment)
    validate_document(participant)
    require(experiment["kind"] == "experiment" and participant["kind"] == "participant",
            "binding_kind", "$", "expected experiment and participant documents")
    require(experiment["status"] == "frozen_for_trials", "experiment_freeze", "$", "hardware is not frozen")
    require(experiment["participant_config_sha256"] == fingerprint(participant)
            and experiment["compatibility"] == participant["compatibility"]
            and experiment["route_profile"] == participant["security"]["profile"],
            "experiment_binding", "$", "frozen config, compatibility or route differs")
    hardware = {item["device_id"]: item for item in experiment["hardware"]}
    execution_devices = {participant["route"]["coordinator"]["identity"]["device_id"]}
    execution_devices.update(stage["owner"]["identity"]["device_id"] for stage in participant["route"]["stages"])
    require(execution_devices == set(experiment["execution_device_ids"])
            and execution_devices <= set(hardware)
            and len({hardware[device]["physical_host_id"] for device in execution_devices}) >= 2,
            "experiment_hardware", "$.hardware", "remote route must use at least two inventoried physical hosts")
    require(all(pool["observation"] == "measured" and pool["device_id"] in hardware
                and pool["capacity_bytes"] == hardware[pool["device_id"]]["ram_bytes"] for pool in participant["pools"]),
            "experiment_pools", "$.hardware", "local pools require matching actual measured inventory")
    return experiment


def load_contract(path):
    return validate_document(load_json(path))
