"""C0 declaration checks, never network/security or numerical execution evidence."""

import ast
from copy import deepcopy
import hashlib
from io import BytesIO
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from steamboat_participant.contract_schema import (
    ContractError, MAX_DEPTH, MAX_DOCUMENT_BYTES, SCHEMA_PATH, load_json, validate_type,
)
from steamboat_participant.contracts import (
    fingerprint, load_contract, validate_binding, validate_document, validate_experiment_binding,
)


EXAMPLES = ROOT / "config/participant/examples"


def example(name="local-c1a-c2a.json"):
    return load_json(EXAMPLES / name)


def replace_path(document, path, value=None, remove=False):
    target = document
    for segment in path[:-1]:
        target = target[segment]
    if remove:
        del target[path[-1]]
    else:
        target[path[-1]] = deepcopy(value)


def paths(document, path=()):
    yield path, document
    if type(document) is dict:
        for name, value in document.items():
            yield from paths(value, path + (name,))
    elif type(document) is list:
        for index, value in enumerate(document):
            yield from paths(value, path + (index,))


def synthetic_frozen_trial():
    """A fabricated test input, not an actual hardware inventory or trial record."""
    participant = example()
    participant["compatibility"]["artifact_manifest_sha256"] = "e" * 64
    participant["pools"][0]["observation"] = "measured"
    participant["route"]["stages"][2]["owner"]["identity"]["device_id"] = "dev_" + "2" * 32
    participant["route"]["stages"][2]["owner"]["certificate_sha256"] = "f" * 64
    participant["reservations"] = [item for item in participant["reservations"] if item["component"] != "worker-3"]
    experiment = example("experiment-awaiting-hardware.json")
    experiment.update(status="frozen_for_trials", source_commit="a" * 40, image_digest="b" * 64,
                      frozen_at_utc="2026-10-17T12:00:00Z", compatibility=deepcopy(participant["compatibility"]),
                      participant_config_sha256=fingerprint(participant),
                      execution_device_ids=[participant["identity"]["device_id"], "dev_" + "2" * 32])
    for dependency in experiment["dependencies"]:
        if dependency["required_for"] in ("C1b", "remote_trials"):
            dependency.update(state="confirmed", owner_account_id=participant["identity"]["account_id"],
                              resolution="Synthetic unit-test confirmation, not real hardware evidence.")
    for index, device in enumerate((participant["identity"]["device_id"], "dev_" + "2" * 32)):
        experiment["hardware"].append({
            "device_id": device, "physical_host_id": f"synthetic_host_{index}", "cpu_model": "Synthetic test CPU",
            "ram_bytes": participant["pools"][0]["capacity_bytes"], "os_release": "Synthetic Linux",
            "kernel": "Synthetic kernel", "cpu_quota_millicores": 8000,
            "inventory_sha256": "c" * 64, "network_route_sha256": "d" * 64, "resource_policy_sha256": "e" * 64,
        })
    return experiment, participant


def single_role_participant(role):
    document = example("all-roles-off.json")
    local = example()
    component = {"consumer": "consumer", "host": "worker-1", "coordinator": "coordinator"}[role]
    document["roles"]["orchestrator" if role == "coordinator" else role] = "personal" if role == "coordinator" else True
    document["reservations"].append(deepcopy(next(item for item in local["reservations"] if item["component"] == component)))
    if role in ("host", "coordinator"):
        endpoint = document["route"]["coordinator"] if role == "coordinator" else document["route"]["stages"][0]["owner"]
        endpoint["identity"]["device_id"] = document["identity"]["device_id"]
        endpoint["certificate_sha256"] = "8" * 64
    return document


def declared_operation(participant):
    operation = example("session-operation.json")
    operation["coordinator"] = deepcopy(participant["route"]["coordinator"]["identity"])
    operation["worker"] = deepcopy(participant["route"]["stages"][0]["owner"]["identity"])
    if not participant["roles"]["consumer"]:
        operation["consumer"].update(device_id="dev_" + "9" * 32, boot_id="e" * 32)
    return operation


class ContractFixtureTests(unittest.TestCase):
    def test_all_roles_default_off_requires_only_daemon_reservation(self):
        document = example("all-roles-off.json")
        validate_document(document)
        self.assertEqual(document["roles"]["orchestrator"], "disabled")
        self.assertFalse(document["roles"]["consumer"])
        self.assertFalse(document["roles"]["host"])
        self.assertEqual([item["component"] for item in document["reservations"]], ["daemon"])

    def test_disabled_local_coordinator_cannot_omit_its_reservation(self):
        document = example()
        document["roles"]["orchestrator"] = "disabled"
        document["reservations"] = [item for item in document["reservations"] if item["component"] != "coordinator"]
        with self.assertRaises(ContractError) as raised:
            validate_document(document)
        self.assertEqual(raised.exception.rule, "role_binding")

    def test_stable_device_has_one_account_across_all_endpoint_roles(self):
        document = example()
        document["route"]["stages"][0]["owner"]["identity"]["account_id"] = "acct_" + "2" * 32
        with self.assertRaises(ContractError) as raised:
            validate_document(document)
        self.assertEqual(raised.exception.rule, "identity_device")

    def test_tls_stream_capacity_and_unix_management_have_separate_budgets(self):
        document = example()
        document["limits"].update(connections_total=12, management_connections=4)
        validate_document(document)
        document["limits"]["streams_per_connection"] = 1
        with self.assertRaises(ContractError) as raised:
            validate_document(document)
        self.assertEqual(raised.exception.rule, "limits_relation")
        document["limits"].update(connections_total=13, client_tls_channels=2, streams_per_connection=20)
        validate_document(document)

    def test_json_logits_token_envelope_and_capture_queue_are_reserved(self):
        document = example()
        minimum = document["compatibility"]["vocabulary_size"] * 32 + 4096
        document["limits"]["logit_message_bytes"] = minimum
        validate_document(document)
        document["limits"]["logit_message_bytes"] -= 1
        with self.assertRaises(ContractError):
            validate_document(document)
        document = example()
        coordinator = next(item for item in document["reservations"] if item["component"] == "coordinator")
        coordinator["communication_bytes"] = 192937984
        validate_document(document)
        coordinator["communication_bytes"] -= 1
        with self.assertRaises(ContractError) as raised:
            validate_document(document)
        self.assertEqual(raised.exception.rule, "reservation_buffers")

    def test_all_examples_are_valid_declarations(self):
        files = sorted(EXAMPLES.glob("*.json"))
        self.assertEqual(len(files), 6)
        for path in files:
            with self.subTest(example=path.name):
                load_contract(path)

    def test_versioned_negative_fixtures_fail_for_the_intended_reason(self):
        fixtures = load_json(ROOT / "config/participant/fixtures/negative.json")
        self.assertGreaterEqual(len(fixtures), 90)
        self.assertEqual(len({fixture["name"] for fixture in fixtures}), len(fixtures))
        for fixture in fixtures:
            with self.subTest(fixture=fixture["name"]):
                self.assertEqual(set(fixture), {"name", "base", "changes", "rule"})
                self.assertEqual(Path(fixture["base"]).name, fixture["base"])
                document = example(fixture["base"])
                for change in fixture["changes"]:
                    replace_path(document, change["path"], change.get("value"), change.get("remove", False))
                with self.assertRaises(ContractError) as raised:
                    validate_document(document)
                self.assertEqual(raised.exception.rule, fixture["rule"])

    def test_every_integer_leaf_rejects_boolean_and_float(self):
        for source in sorted(EXAMPLES.glob("*.json")):
            original = example(source.name)
            for path, value in paths(original):
                if type(value) is int:
                    for replacement in (True, False, float(value)):
                        with self.subTest(example=source.name, path=path, replacement=replacement):
                            document = deepcopy(original)
                            replace_path(document, path, replacement)
                            with self.assertRaises(ContractError):
                                validate_document(document)

    def test_every_object_rejects_unknown_properties_and_missing_fields(self):
        for source in sorted(EXAMPLES.glob("*.json")):
            original = example(source.name)
            for path, value in paths(original):
                if type(value) is dict:
                    for mode in ("unknown", "missing"):
                        with self.subTest(example=source.name, path=path, mode=mode):
                            replacement = deepcopy(value)
                            if mode == "unknown":
                                replacement["unexpected"] = None
                            else:
                                replacement.pop(next(iter(replacement)))
                            document = deepcopy(original)
                            if path:
                                replace_path(document, path, replacement)
                            else:
                                document = replacement
                            with self.assertRaises(ContractError):
                                validate_document(document)

    def test_every_document_rejects_unknown_versions_and_kinds(self):
        for source in EXAMPLES.glob("*.json"):
            for key, value in (("schema_version", 2), ("schema_version", "1"), ("kind", "unknown")):
                with self.subTest(example=source.name, key=key, value=value):
                    document = example(source.name)
                    document[key] = value
                    with self.assertRaises(ContractError):
                        validate_document(document)

    def test_unavailable_memory_is_valid_declaration_not_execution_readiness(self):
        document = example()
        document["pools"][0].update(observation="unavailable", free_before_start_bytes=None)
        validate_document(document)
        self.assertEqual(document["policy"]["unknown_telemetry"], "unavailable_reject_execution")
        self.assertEqual(document["policy"]["enforcement"], "unimplemented_contract_only")

    def test_shared_pool_sum_not_independent_component_checks(self):
        document = example()
        for item in document["reservations"]:
            item["temporary_bytes"] = 4 * 1024 ** 3
        with self.assertRaises(ContractError) as raised:
            validate_document(document)
        self.assertEqual(raised.exception.rule, "pool_reservation")

    def test_certificate_digest_cannot_assert_two_devices(self):
        document = example()
        document["security"]["registry"]["certificate_sha256"] = document["route"]["coordinator"]["certificate_sha256"]
        with self.assertRaises(ContractError) as raised:
            validate_document(document)
        self.assertEqual(raised.exception.rule, "identity_certificate")

    def test_outbound_gateway_needs_all_flow_control_fields(self):
        for field in ("gateway_streams", "gateway_queue_messages", "gateway_queue_bytes"):
            document = example("outbound-c2b.json")
            document["limits"][field] = 0
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_document(document)

    def test_role_opt_in_and_lightweight_consumer_only_configuration(self):
        document = example()
        document["roles"].update(host=False, orchestrator="disabled")
        for stage in document["route"]["stages"]:
            stage["owner"]["identity"]["device_id"] = "dev_" + "2" * 32
        document["route"]["coordinator"]["identity"]["device_id"] = "dev_" + "2" * 32
        document["reservations"] = [item for item in document["reservations"] if item["component"] in ("consumer", "daemon")]
        validate_document(document)


class BindingTests(unittest.TestCase):
    def test_independent_consumer_host_and_coordinator_binding_contexts(self):
        for role in ("consumer", "host", "coordinator"):
            with self.subTest(role=role):
                participant = single_role_participant(role)
                validate_binding(declared_operation(participant), participant)

    def test_personal_consumer_may_use_another_device_and_process_boot(self):
        participant = single_role_participant("coordinator")
        self.assertNotEqual(participant["identity"]["boot_id"], participant["route"]["coordinator"]["identity"]["boot_id"])
        validate_binding(declared_operation(participant), participant)

    def test_unrelated_or_disabled_local_roles_do_not_authorize_binding(self):
        participant = example("all-roles-off.json")
        with self.assertRaises(ContractError) as raised:
            validate_binding(declared_operation(participant), participant)
        self.assertEqual(raised.exception.rule, "binding_role")

    def test_assignment_change_and_unsupported_binding_version_fail(self):
        operation = example("session-operation.json")
        operation["assignment_id"] = "asg_" + "f" * 32
        with self.assertRaises(ContractError) as raised:
            validate_binding(operation, example())
        self.assertEqual(raised.exception.rule, "binding_assignment")
        operation = example("session-operation.json")
        operation["binding_version"] = 2
        with self.assertRaises(ContractError) as raised:
            validate_binding(operation, example())
        self.assertEqual(raised.exception.rule, "schema_const")

    def test_wrong_document_kinds_produce_contract_error_not_key_error(self):
        for operation, participant in ((example(), example()),
                                       (example("session-operation.json"), example("c0-evidence-template.json"))):
            with self.subTest(kind=participant["kind"]), self.assertRaises(ContractError) as raised:
                validate_binding(operation, participant)
            self.assertEqual(raised.exception.rule, "binding_kind")

    def test_valid_declared_step_binding(self):
        validate_binding(example("session-operation.json"), example())

    def test_stolen_or_rotated_identity_binding_fails_closed(self):
        mutations = (
            (("consumer", "account_id"), "acct_" + "2" * 32, "binding_consumer"),
            (("coordinator", "device_id"), "dev_" + "2" * 32, "binding_coordinator"),
            (("worker", "boot_id"), "2" * 32, "binding_worker"),
            (("worker", "device_id"), "dev_" + "2" * 32, "binding_worker"),
            (("route_id",), "route_" + "2" * 32, "binding_route"),
            (("credential_epoch",), 2, "binding_credential"),
            (("compatibility_sha256",), "2" * 64, "binding_compatibility"),
        )
        for path, value, expected_rule in mutations:
            with self.subTest(path=path):
                operation = example("session-operation.json")
                replace_path(operation, path, value)
                with self.assertRaises(ContractError) as raised:
                    validate_binding(operation, example())
                self.assertEqual(raised.exception.rule, expected_rule)

    def test_boot_restart_invalidates_binding(self):
        participant = example()
        participant["route"]["stages"][0]["owner"]["identity"]["boot_id"] = "f" * 32
        with self.assertRaises(ContractError) as raised:
            validate_binding(example("session-operation.json"), participant)
        self.assertEqual(raised.exception.rule, "binding_worker")

    def test_open_and_control_operations_reject_irrelevant_payload(self):
        for method in ("OpenSession", "RenewSession", "SessionStatus", "CloseSession", "CancelSession"):
            document = example("session-operation.json")
            document.update(method=method, token_count=0, payload_sha256=None)
            if method == "OpenSession":
                document["lease_sha256"] = None
            validate_binding(document, example())
            document["payload_sha256"] = "a" * 64
            with self.subTest(method=method), self.assertRaises(ContractError):
                validate_document(document)

    def test_operation_cannot_escape_lower_admitted_deadline(self):
        participant = example()
        participant["limits"]["rpc_ms"] = 10000
        with self.assertRaises(ContractError) as raised:
            validate_binding(example("session-operation.json"), participant)
        self.assertEqual(raised.exception.rule, "binding_limits")

    def test_exact_context_boundary_is_accepted_but_one_position_more_is_not(self):
        operation = example("session-operation.json")
        operation.update(position=1024, sequence=1)
        validate_binding(operation, example())
        operation["position"] += 1
        with self.assertRaises(ContractError) as raised:
            validate_binding(operation, example())
        self.assertEqual(raised.exception.rule, "operation_context")


class ExperimentEvidenceTests(unittest.TestCase):
    def test_awaiting_hardware_is_not_a_trial_freeze(self):
        with self.assertRaises(ContractError) as raised:
            validate_experiment_binding(example("experiment-awaiting-hardware.json"), example())
        self.assertEqual(raised.exception.rule, "experiment_freeze")

    def test_synthetic_frozen_fixture_obeys_trial_requirements(self):
        experiment, participant = synthetic_frozen_trial()
        validate_experiment_binding(experiment, participant)

    def test_missing_hardware_source_and_artifact_fields_block_trials(self):
        for field in ("participant_config_sha256", "source_commit", "image_digest", "frozen_at_utc"):
            experiment, participant = synthetic_frozen_trial()
            experiment[field] = None
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_experiment_binding(experiment, participant)
        experiment, participant = synthetic_frozen_trial()
        experiment["compatibility"]["artifact_manifest_sha256"] = None
        with self.assertRaises(ContractError):
            validate_document(experiment)

    def test_containers_or_duplicate_device_aliases_are_not_two_hosts(self):
        experiment, participant = synthetic_frozen_trial()
        experiment["hardware"][1]["physical_host_id"] = experiment["hardware"][0]["physical_host_id"]
        with self.assertRaises(ContractError) as raised:
            validate_experiment_binding(experiment, participant)
        self.assertEqual(raised.exception.rule, "hardware_identity")

    def test_frozen_execution_device_list_must_match_the_actual_declared_route(self):
        experiment, participant = synthetic_frozen_trial()
        participant["route"]["stages"][2]["owner"]["identity"]["device_id"] = participant["identity"]["device_id"]
        participant["route"]["stages"][2]["owner"]["certificate_sha256"] = participant["route"]["stages"][0]["owner"]["certificate_sha256"]
        participant["reservations"].append(example()["reservations"][5])
        experiment["participant_config_sha256"] = fingerprint(participant)
        with self.assertRaises(ContractError) as raised:
            validate_experiment_binding(experiment, participant)
        self.assertEqual(raised.exception.rule, "experiment_hardware")

    def test_unused_hardware_record_cannot_make_single_device_route_remote(self):
        experiment, participant = synthetic_frozen_trial()
        stage = participant["route"]["stages"][2]["owner"]
        stage["identity"]["device_id"] = participant["identity"]["device_id"]
        stage["certificate_sha256"] = participant["route"]["stages"][0]["owner"]["certificate_sha256"]
        participant["reservations"].append(example()["reservations"][5])
        experiment["participant_config_sha256"] = fingerprint(participant)
        experiment["execution_device_ids"] = [participant["identity"]["device_id"]]
        with self.assertRaises(ContractError) as standalone:
            validate_document(experiment)
        self.assertEqual(standalone.exception.rule, "experiment_hardware")
        with self.assertRaises(ContractError) as raised:
            validate_experiment_binding(experiment, participant)
        self.assertEqual(raised.exception.rule, "experiment_hardware")

    def test_unconfirmed_hardware_dependency_blocks_trial(self):
        experiment, participant = synthetic_frozen_trial()
        dependency = next(item for item in experiment["dependencies"] if item["dependency_id"] == "second_physical_device")
        dependency.update(state="open", owner_account_id=None, resolution=None)
        with self.assertRaises(ContractError) as raised:
            validate_experiment_binding(experiment, participant)
        self.assertEqual(raised.exception.rule, "experiment_dependency")

    def test_synthetic_pool_cannot_become_measured_evidence_by_hashing(self):
        experiment, participant = synthetic_frozen_trial()
        participant["pools"][0]["observation"] = "synthetic"
        experiment["participant_config_sha256"] = fingerprint(participant)
        with self.assertRaises(ContractError) as raised:
            validate_experiment_binding(experiment, participant)
        self.assertEqual(raised.exception.rule, "experiment_pools")

    def test_invalid_freeze_date_is_not_accepted_as_timestamp(self):
        experiment, participant = synthetic_frozen_trial()
        experiment["frozen_at_utc"] = "2026-02-30T12:00:00Z"
        with self.assertRaises(ContractError) as raised:
            validate_experiment_binding(experiment, participant)
        self.assertEqual(raised.exception.rule, "experiment_freeze")

    def test_changed_configuration_invalidates_trial_freeze(self):
        experiment, participant = synthetic_frozen_trial()
        participant["policy"]["torch_threads"] = 1
        with self.assertRaises(ContractError) as raised:
            validate_experiment_binding(experiment, participant)
        self.assertEqual(raised.exception.rule, "experiment_binding")

    def test_c2b_requires_outbound_route_and_gateway_budget_owner(self):
        experiment, participant = synthetic_frozen_trial()
        experiment["gate"] = "C2b"
        for dependency in experiment["dependencies"]:
            if dependency["required_for"] == "C2b":
                dependency.update(state="confirmed", owner_account_id=participant["identity"]["account_id"],
                                  resolution="Synthetic gateway and local prerequisite confirmation.")
        with self.assertRaises(ContractError) as raised:
            validate_document(experiment)
        self.assertEqual(raised.exception.rule, "experiment_route")

    def test_synthetic_c2b_freeze_covers_gateway_and_local_dependencies(self):
        experiment, participant = synthetic_frozen_trial()
        outbound = example("outbound-c2b.json")
        participant["security"] = outbound["security"]
        participant["limits"] = outbound["limits"]
        experiment.update(gate="C2b", route_profile="outbound_gateway_mtls",
                          participant_config_sha256=fingerprint(participant))
        for dependency in experiment["dependencies"]:
            if dependency["required_for"] == "C2b":
                dependency.update(state="confirmed", owner_account_id=participant["identity"]["account_id"],
                                  resolution="Synthetic gateway and local prerequisite confirmation.")
        validate_experiment_binding(experiment, participant)

    def test_recorded_checks_do_not_imply_phase_or_network_pass(self):
        evidence = example("c0-evidence-template.json")
        evidence.update(status="recorded_checks_not_phase_pass", source_commit="a" * 40)
        evidence["checks"][0].update(outcome="passed", exit_code=0, sanitized_report_sha256="b" * 64, reason=None)
        validate_document(evidence)
        evidence["checks"][0]["exit_code"] = 1
        with self.assertRaises(ContractError) as raised:
            validate_document(evidence)
        self.assertEqual(raised.exception.rule, "evidence_exit")


class LoaderAndBaselineTests(unittest.TestCase):
    def test_loader_depth_limit_does_not_depend_on_interpreter_recursion_limit(self):
        for depth in (MAX_DEPTH, MAX_DEPTH + 1, 2000):
            payload = b"[" * depth + b"0" + b"]" * depth
            with self.subTest(depth=depth), patch.object(Path, "open", return_value=BytesIO(payload)):
                if depth == MAX_DEPTH:
                    load_json("synthetic-depth.json")
                else:
                    with self.assertRaises(ContractError):
                        load_json("synthetic-depth.json")
        parsed = 0
        for level in range(2000):
            parsed = [parsed]
        with patch.object(Path, "open", return_value=BytesIO(b"[]")), \
                patch("steamboat_participant.contract_schema.json.loads", return_value=parsed):
            with self.assertRaises(ContractError) as raised:
                load_json("synthetic-python312-parser.json")
        self.assertEqual(raised.exception.rule, "json_depth")

    def test_bounded_loader_rejects_duplicate_nonfinite_malformed_and_oversized_json(self):
        payloads = (b'{"kind":"participant","kind":"experiment"}', b'{"value":NaN}', b'{"value":Infinity}',
                    b'{"value":1e999}', b'{"value":-1e999}',
                    b'\xff', b'{', b' ' * (MAX_DOCUMENT_BYTES + 1), b'[' * 2000 + b']' * 2000)
        for payload in payloads:
            with self.subTest(length=len(payload)), patch.object(Path, "open", return_value=BytesIO(payload)):
                with self.assertRaises(ContractError):
                    load_json("synthetic-invalid.json")

    def test_schema_dialect_is_not_silently_extended(self):
        with self.assertRaises(ContractError) as raised:
            validate_type({}, {"json_schema_magic": {}}, {})
        self.assertEqual(raised.exception.rule, "schema_definition")
        schema = load_json(SCHEMA_PATH)
        self.assertEqual(schema["dialect"], "steamboat.closed-types.v1")
        self.assertEqual(set(schema["documents"]), {"participant", "experiment", "evidence", "session_operation"})

    def test_normative_boundaries_keep_role_and_evidence_authority_separate(self):
        boundaries = load_json(ROOT / "config/participant/v1/boundaries.json")
        self.assertIs(type(boundaries["schema_version"]), int)
        self.assertEqual(boundaries["schema_version"], 1)
        self.assertEqual(boundaries["status"], "contract_only_not_implementation_or_phase_acceptance")
        roles = boundaries["role_permissions"]
        self.assertFalse(roles["consumer"]["execution_environment_required"])
        self.assertFalse(roles["host"]["grants_orchestration_authority"])
        self.assertFalse(roles["personal_orchestrator"]["grants_ledger_authority"])
        for role in ("community_operator", "ledger", "public_enrollment"):
            self.assertFalse(roles[role]["supported_in_v1"])

    def test_dependency_lock_hash_is_exact(self):
        contract = example()["compatibility"]
        digest = hashlib.sha256((ROOT / contract["runtime_lock"]).read_bytes()).hexdigest()
        self.assertEqual(digest, contract["runtime_lock_sha256"])

    def test_existing_runtime_control_limits_are_preserved_not_extended(self):
        tree = ast.parse((ROOT / "src/steamboat_runtime/manifest.py").read_text(encoding="utf-8"))
        limit_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ResourceLimits")
        original = {node.target.id: ast.literal_eval(node.value) for node in limit_class.body if isinstance(node, ast.AnnAssign)}
        limits = example()["limits"]
        mapping = {"max_sessions": "active_sessions", "max_compute_calls": "compute_calls_per_worker",
                   "max_stage_queue": "stage_queue", "max_waiting_admissions": "waiting_admissions",
                   "output_queue_tokens": "output_queue_tokens", "max_message_bytes": "message_bytes",
                   "worker_cache_positions": "cache_positions_per_worker", "worker_cache_bytes": "cache_bytes_per_worker"}
        for old_name, new_name in mapping.items():
            self.assertEqual(original[old_name], limits[new_name])
        for name, target in (("admission_timeout_seconds", "admission_ms"), ("request_timeout_seconds", "request_ms"),
                             ("rpc_timeout_seconds", "rpc_ms"), ("idle_lease_seconds", "idle_lease_ms"),
                             ("lease_check_interval_seconds", "lease_check_ms"), ("renew_interval_seconds", "renew_ms"),
                             ("compute_cancel_grace_seconds", "compute_cancel_grace_ms")):
            self.assertEqual(original[name] * 1000, limits[target])
        self.assertEqual(original["max_positions"], example()["compatibility"]["runtime_context"])


if __name__ == "__main__":
    (ROOT / ".lab").mkdir(exist_ok=True)
    unittest.main()
