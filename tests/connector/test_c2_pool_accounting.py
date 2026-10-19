import hashlib
import json
import unittest
from dataclasses import replace

from steamboat_connector.c2_pool_accounting import (
    C2PoolAccountingError, C2PoolAccountingPlan, C2PoolGenerationDescriptor,
    C2RoleAllocation, MAX_ACCOUNTING_BYTES,
    build_c2_pool_accounting_plan, build_c2_pool_generation_descriptor,
    canonical_c2_pool_accounting_bytes, canonical_c2_pool_generation_bytes,
    c2_pool_accounting_sha256, c2_pool_generation_sha256,
    c2_pool_accounting_to_document, c2_pool_generation_to_document,
    parse_c2_pool_accounting, parse_c2_pool_generation,
)
from steamboat_connector.c2_pool_config import (
    C2PoolConfig, PROFILE as CONFIG_PROFILE, parse_c2_pool_config,
)
from steamboat_connector.validation import json_bytes


def config_document(**overrides):
    document = {
        "schema_version": 2,
        "profile": CONFIG_PROFILE,
        "physical_host_id": "a" * 64,
        "allocation_id": "b" * 64,
        "pool_kind": "system_ram",
        "pool_id": "primary-system-memory",
        "owner_uid": 1000,
        "operator_root": "/var/lib/steamboat/operator",
        "cgroup_parent": "/sys/fs/cgroup/steamboat",
        "memory_ceiling_bytes": 10_000,
        "memory_headroom_bytes": 1_000,
        "cpu_quota_millis": 2_000,
        "pids_max": 100,
        "swap_max_bytes": 0,
        "disk_ceiling_bytes": 8_000,
        "control": {
            "memory_bytes": 2_000,
            "cpu_quota_millis": 200,
            "pids_max": 10,
            "disk_bytes": 2_000,
        },
    }
    document.update(overrides)
    return document


def config(**overrides):
    return parse_c2_pool_config(json_bytes(config_document(**overrides)))


def host(memory=4_000, cpu=700, pids=30, disk=1_000):
    return C2RoleAllocation("host", memory, cpu, pids, disk)


def coordinator(memory=3_000, cpu=1_100, pids=60, disk=5_000):
    return C2RoleAllocation("coordinator", memory, cpu, pids, disk)


def plan_for(pool=None, allocations=None, maxima=None):
    pool = pool or config()
    allocations = allocations or (host(), coordinator())
    if maxima is None:
        maxima = {item.role: 300 for item in allocations}
    return build_c2_pool_accounting_plan(pool, allocations, maxima)


class C2PoolAccountingTests(unittest.TestCase):
    def test_exact_boundary_fit_and_asymmetric_roles(self):
        pool = config()
        plan = plan_for(pool)
        self.assertEqual(tuple(item.role for item in plan.role_allocations),
                         ("host", "coordinator"))
        self.assertEqual(sum(item.memory_bytes for item in plan.role_allocations)
                         + pool.control.memory_bytes + pool.memory_headroom_bytes,
                         pool.memory_ceiling_bytes)
        self.assertEqual(sum(item.cpu_quota_millis for item in plan.role_allocations)
                         + pool.control.cpu_quota_millis, pool.cpu_quota_millis)
        self.assertEqual(sum(item.pids_max for item in plan.role_allocations)
                         + pool.control.pids_max, pool.pids_max)
        self.assertEqual(sum(item.disk_bytes for item in plan.role_allocations)
                         + pool.control.disk_bytes, pool.disk_ceiling_bytes)
        self.assertNotEqual(plan.role_allocations[0], plan.role_allocations[1])

    def test_rejects_each_aggregate_overcommit(self):
        cases = (
            (config(), (host(memory=4_001), coordinator()), {"host": 1, "coordinator": 1}, "memory"),
            (config(), (host(cpu=701), coordinator()), {"host": 1, "coordinator": 1}, "CPU"),
            (config(), (host(pids=31), coordinator()), {"host": 1, "coordinator": 1}, "PIDs"),
            (config(), (host(disk=1_001), coordinator()), {"host": 1, "coordinator": 1}, "disk"),
        )
        for pool, allocations, maxima, message in cases:
            with self.subTest(resource=message):
                with self.assertRaisesRegex(C2PoolAccountingError, message):
                    plan_for(pool, allocations, maxima)

    def test_control_disk_equal_total_leaves_no_positive_role_disk(self):
        pool = config(disk_ceiling_bytes=8_000,
                      control={"memory_bytes": 2_000, "cpu_quota_millis": 200,
                               "pids_max": 10, "disk_bytes": 8_000})
        role = host(disk=0)
        plan = plan_for(pool, (role,), {"host": 300})
        self.assertEqual(plan.role_allocations[0].disk_bytes, 0)
        with self.assertRaisesRegex(C2PoolAccountingError, "disk"):
            plan_for(pool, (host(disk=1),), {"host": 300})

    def test_maximum_seconds_are_independent_and_never_added_to_capacity(self):
        pool = config()
        allocations = (host(), coordinator())
        plan = plan_for(pool, allocations, {"host": 300, "coordinator": 300})
        self.assertEqual(plan.maximum_seconds, (("host", 300), ("coordinator", 300)))
        with self.assertRaises(C2PoolAccountingError):
            plan_for(pool, allocations, {"host": 301, "coordinator": 300})
        self.assertEqual(sum(item.memory_bytes for item in plan.role_allocations), 7_000)

    def test_roles_must_be_unique_supported_fixed_order_and_complete(self):
        pool = config()
        invalid = (
            ((host(), host()), {"host": 10}),
            ((host(),), {"host": 10, "coordinator": 10}),
            ((coordinator(), host()), {"coordinator": 10, "host": 10}),
            ((C2RoleAllocation("consumer", 1, 1, 1, 0),), {"consumer": 1}),
        )
        for allocations, maxima in invalid:
            with self.subTest(allocations=allocations, maxima=maxima):
                with self.assertRaises(C2PoolAccountingError):
                    plan_for(pool, allocations, maxima)

    def test_builder_rejects_unknown_missing_and_extra_maximum_roles(self):
        pool = config()
        with self.assertRaises(C2PoolAccountingError):
            plan_for(pool, (host(),), {})
        with self.assertRaises(C2PoolAccountingError):
            plan_for(pool, (host(),), {"host": 10, "coordinator": 10})
        with self.assertRaises(C2PoolAccountingError):
            plan_for(pool, (host(),), {"host": 10, "consumer": 10})

    def test_exact_types_reject_bool_float_and_bounds_on_allocation_fields(self):
        for field, value in (
            ("memory_bytes", True), ("memory_bytes", 0), ("memory_bytes", 1.0),
            ("cpu_quota_millis", False), ("cpu_quota_millis", 0),
            ("pids_max", True), ("pids_max", 0),
            ("disk_bytes", False), ("disk_bytes", -1), ("disk_bytes", 1.5),
        ):
            with self.subTest(field=field, value=value):
                bad = replace(host(), **{field: value})
                with self.assertRaises(C2PoolAccountingError):
                    plan_for(config(), (bad,), {"host": 1})

    def test_exact_immutable_class_checks_reject_subclasses_and_fabricated_config(self):
        class AllocationSubclass(C2RoleAllocation):
            pass

        with self.assertRaises(C2PoolAccountingError):
            plan_for(config(), (AllocationSubclass("host", 1, 1, 1, 0),), {"host": 1})
        with self.assertRaises(C2PoolAccountingError):
            plan_for(config(), [host()], {"host": 1})
        with self.assertRaises(C2PoolAccountingError):
            plan_for(replace(config(), memory_ceiling_bytes=True), (host(),), {"host": 1})
        class PlanSubclass(C2PoolAccountingPlan):
            pass
        valid = plan_for(config(), (host(),), {"host": 1})
        with self.assertRaises(C2PoolAccountingError):
            c2_pool_accounting_to_document(PlanSubclass(*valid.__getstate__()), config())
        class ConfigSubclass(C2PoolConfig):
            pass
        pool = config()
        with self.assertRaises(C2PoolAccountingError):
            plan_for(ConfigSubclass(*pool.__getstate__()), (host(),), {"host": 1})

    def test_canonical_roundtrip_digest_and_mutation_independence(self):
        pool = config()
        maxima = {"coordinator": 81, "host": 43}
        plan = plan_for(pool, (host(), coordinator()), maxima)
        maxima["host"] = 1
        encoded = canonical_c2_pool_accounting_bytes(plan, pool)
        parsed = parse_c2_pool_accounting(encoded, pool)
        self.assertEqual(parsed, plan)
        self.assertEqual(canonical_c2_pool_accounting_bytes(parsed, pool), encoded)
        self.assertEqual(c2_pool_accounting_sha256(plan, pool), hashlib.sha256(encoded).hexdigest())
        document = c2_pool_accounting_to_document(plan, pool)
        document["role_allocations"][0]["memory_bytes"] = 1
        document["maximum_seconds"]["host"] = 1
        self.assertEqual(plan.role_allocations[0].memory_bytes, 4_000)
        self.assertEqual(dict(plan.maximum_seconds)["host"], 43)
        self.assertLessEqual(len(encoded), MAX_ACCOUNTING_BYTES)

    def test_unknown_missing_duplicate_noncanonical_and_malformed_fields_rejected(self):
        pool = config()
        encoded = canonical_c2_pool_accounting_bytes(plan_for(pool), pool)
        document = json.loads(encoded)
        document["unexpected"] = 1
        with self.assertRaises(C2PoolAccountingError):
            parse_c2_pool_accounting(json_bytes(document), pool)
        document = json.loads(encoded)
        del document["maximum_seconds"]
        with self.assertRaises(C2PoolAccountingError):
            parse_c2_pool_accounting(json_bytes(document), pool)
        # Duplicate a real key explicitly; the JSON loader must reject it.
        duplicate = encoded[:-1] + b',"profile":"x"}'
        with self.assertRaises(C2PoolAccountingError):
            parse_c2_pool_accounting(duplicate, pool)
        with self.assertRaises(C2PoolAccountingError):
            parse_c2_pool_accounting(encoded + b"\n", pool)
        with self.assertRaises(C2PoolAccountingError):
            parse_c2_pool_accounting(encoded.replace(b'"memory_bytes":4000',
                                                       b'"memory_bytes":NaN'), pool)
        with self.assertRaises(C2PoolAccountingError):
            parse_c2_pool_accounting(encoded.replace(b'"memory_bytes":4000',
                                                       b'"memory_bytes":4000.0'), pool)

    def test_config_digest_is_exact_and_changed_config_rejected(self):
        pool = config()
        plan = plan_for(pool)
        with self.assertRaises(C2PoolAccountingError):
            c2_pool_accounting_to_document(replace(plan, config_sha256="c" * 64), pool)
        with self.assertRaises(C2PoolAccountingError):
            c2_pool_accounting_to_document(plan, config(memory_headroom_bytes=999))
        with self.assertRaises(C2PoolAccountingError):
            build_c2_pool_accounting_plan(object(), (host(),), {"host": 1})

    def test_generation_descriptor_roundtrip_pins_identity_and_rejects_alterations(self):
        pool = config()
        plan = plan_for(pool, (host(),), {"host": 120})
        descriptor = build_c2_pool_generation_descriptor(
            role="host", boot_id="d" * 32, policy_sha256="e" * 64,
            cgroup_basename="participant-host-1", config=pool, plan=plan,
        )
        encoded = canonical_c2_pool_generation_bytes(descriptor, pool, plan)
        parsed = parse_c2_pool_generation(encoded, pool, plan)
        self.assertEqual(parsed, descriptor)
        self.assertEqual(c2_pool_generation_sha256(parsed, pool, plan),
                         hashlib.sha256(encoded).hexdigest())
        for changed in (
            replace(descriptor, role="coordinator"),
            replace(descriptor, boot_id="f" * 64),
            replace(descriptor, policy_sha256="F" * 64),
            replace(descriptor, config_sha256="a" * 64),
            replace(descriptor, cgroup_basename="../participant-host"),
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(C2PoolAccountingError):
                    c2_pool_generation_to_document(changed, pool, plan)
        with self.assertRaises(C2PoolAccountingError):
            parse_c2_pool_generation(encoded, config(memory_headroom_bytes=999), plan)
        changed = json.loads(encoded)
        changed["boot_id"] = "F" * 32
        with self.assertRaises(C2PoolAccountingError):
            parse_c2_pool_generation(json_bytes(changed), pool, plan)

    def test_generation_rejects_bad_basename_role_hash_and_exact_type(self):
        pool = config()
        plan = plan_for(pool, (host(),), {"host": 120})
        for role, boot_id, policy, name in (
            ("consumer", "a" * 32, "b" * 64, "participant-x"),
            ("host", "A" * 32, "b" * 64, "participant-x"),
            ("host", "a" * 32, "b" * 63, "participant-x"),
            ("host", "a" * 32, "b" * 64, "participant-" + "x" * 41),
        ):
            with self.subTest(role=role, boot=boot_id, basename=name):
                with self.assertRaises(C2PoolAccountingError):
                    build_c2_pool_generation_descriptor(
                        role=role, boot_id=boot_id, policy_sha256=policy,
                        cgroup_basename=name, config=pool, plan=plan,
                    )
        descriptor = build_c2_pool_generation_descriptor(
            role="host", boot_id="a" * 32, policy_sha256="b" * 64,
            cgroup_basename="participant-x", config=pool, plan=plan,
        )
        class GenerationSubclass(C2PoolGenerationDescriptor):
            pass
        subclass = GenerationSubclass(*descriptor.__getstate__())
        with self.assertRaises(C2PoolAccountingError):
            c2_pool_generation_to_document(subclass, pool, plan)

    def test_unknown_generation_fields_and_duplicate_json_keys_are_rejected(self):
        pool = config()
        plan = plan_for(pool, (coordinator(),), {"coordinator": 120})
        descriptor = build_c2_pool_generation_descriptor(
            role="coordinator", boot_id="a" * 32, policy_sha256="b" * 64,
            cgroup_basename="participant-coord-1", config=pool, plan=plan,
        )
        encoded = canonical_c2_pool_generation_bytes(descriptor, pool, plan)
        extra = json.loads(encoded)
        extra["authority"] = True
        with self.assertRaises(C2PoolAccountingError):
            parse_c2_pool_generation(json_bytes(extra), pool, plan)
        duplicate = encoded[:-1] + b',"role":"host"}'
        with self.assertRaises(C2PoolAccountingError):
            parse_c2_pool_generation(duplicate, pool, plan)
        with self.assertRaises(C2PoolAccountingError):
            parse_c2_pool_generation(encoded + b" " * MAX_ACCOUNTING_BYTES, pool, plan)


if __name__ == "__main__":
    unittest.main()
