"""Portable tests for inert per-device C2 local-plan projection."""
from __future__ import annotations

import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import tests.security.test_root_c2_selected as selected_fixture
from steamboat_security.codec import canonical_json
from steamboat_security.errors import CredentialError
from steamboat_security.root_c2_local_plan import (
    C2LocalPlan, c2_local_plan_document, derive_c2_local_plan,
    parse_c2_local_plan, read_selected_c2_local_plan, revalidate_c2_local_plan,
)


class C2LocalPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected_fixture.policy_fixture.RootTransitionPolicyTests.setUpClass()

    def setUp(self):
        fixture = object.__new__(selected_fixture.C2SelectedCohortTests)
        fixture.setUp()
        self.fixture = fixture
        self.selector, self.bundle, self.active, self.group = fixture._inputs(grant_fault="none")
        cohort = selected_fixture.validate_c2_selected_cohort(
            self.selector, self.bundle, self.active, clock=fixture.fx.clock_source.clock)
        self.host = next(x for x in cohort.new_specs if x.role == "host")
        self.clock = fixture.fx.clock_source.clock
        self.owner = (self.host.account_id, self.host.device_id)

    def tearDown(self):
        self.fixture.tearDown()

    def _derive(self, roles=("host",), *, owner=None, epoch=1):
        account, device = owner or self.owner
        return derive_c2_local_plan(self.selector, self.bundle, self.active,
            clock=self.clock, account_id=account, device_id=device,
            enable_epoch=epoch, enabled_roles=roles)

    def test_host_device_projection_keeps_remote_coordinator_disabled(self):
        plan = self._derive()
        self.assertEqual(tuple(x.role for x in plan.enabled_specs), ("host",))
        self.assertEqual(tuple(x.role for x in plan.disabled_specs), ())
        self.assertEqual(len(plan.enabled_host_groups), 1)
        remote = [x for x in self.fixture.candidate.new_launch_specs
                  if x.role == "personal_coordinator"]
        self.assertTrue(remote)
        self.assertFalse(any(x.identity == remote[0].identity for x in plan.complete_local_specs))

    def test_paused_owner_has_empty_enabled_projection_and_no_run(self):
        plan = self._derive(())
        self.assertEqual(plan.enabled_specs, ())
        self.assertEqual(plan.enabled_host_groups, ())
        self.assertEqual(tuple(x.role for x in plan.disabled_specs), ("host",))
        self.assertEqual(len(plan.disabled_host_groups), 1)

    def test_wrong_principal_and_missing_enabled_remote_role_reject(self):
        with self.assertRaises(CredentialError):
            self._derive(owner=("acct_" + "9" * 32, "dev_" + "9" * 32))
        with self.assertRaisesRegex(CredentialError, "absent"):
            self._derive(("personal_coordinator",))

    def test_enabled_roles_must_be_sorted_unique_known_tuple(self):
        for roles in (["host"], ("host", "host"), ("z",), ("personal_coordinator", "host")):
            with self.subTest(roles=roles), self.assertRaises(CredentialError):
                self._derive(roles)

    def test_serialized_plan_revalidates_against_global_head_and_enable_snapshot(self):
        plan = self._derive(epoch=4)
        encoded = canonical_json(c2_local_plan_document(plan))
        self.assertEqual(parse_c2_local_plan(encoded), plan)
        revalidated = revalidate_c2_local_plan(encoded, self.selector, self.bundle,
            self.active, clock=self.clock, account_id=self.owner[0],
            device_id=self.owner[1], enable_epoch=4, enabled_roles=("host",))
        self.assertEqual(revalidated, plan)
        for epoch, roles in ((5, ("host",)), (4, ())):
            with self.subTest(epoch=epoch, roles=roles), self.assertRaises(CredentialError):
                revalidate_c2_local_plan(encoded, self.selector, self.bundle,
                    self.active, clock=self.clock, account_id=self.owner[0],
                    device_id=self.owner[1], enable_epoch=epoch, enabled_roles=roles)
        changed = json.loads(encoded)
        changed["selector_sha256"] = "e" * 64
        with self.assertRaises(CredentialError):
            revalidate_c2_local_plan(canonical_json(changed), self.selector,
                self.bundle, self.active, clock=self.clock, account_id=self.owner[0],
                device_id=self.owner[1], enable_epoch=4, enabled_roles=("host",))
        changed_head = selected_fixture.RootGenerationSelector(
            self.selector.generation_sha256, "f" * 64, self.selector.policy_revision,
            self.selector.policy_digest, self.selector.active_policy_snapshot_sha256,
            self.selector.artifact_sha256)
        with self.assertRaises(CredentialError):
            revalidate_c2_local_plan(encoded, changed_head, self.bundle, self.active,
                clock=self.clock, account_id=self.owner[0], device_id=self.owner[1],
                enable_epoch=4, enabled_roles=("host",))

    def test_omitted_enabled_spec_and_claimed_disabled_role_are_rejected(self):
        plan = self._derive(epoch=2)
        raw = c2_local_plan_document(plan)
        raw["enabled_specs"] = []
        with self.assertRaises(CredentialError):
            revalidate_c2_local_plan(canonical_json(raw), self.selector, self.bundle,
                self.active, clock=self.clock, account_id=self.owner[0],
                device_id=self.owner[1], enable_epoch=2, enabled_roles=("host",))
        paused = self._derive((), epoch=3)
        raw = c2_local_plan_document(paused)
        raw["enabled_specs"] = raw["disabled_specs"]
        with self.assertRaises(CredentialError):
            revalidate_c2_local_plan(canonical_json(raw), self.selector, self.bundle,
                self.active, clock=self.clock, account_id=self.owner[0],
                device_id=self.owner[1], enable_epoch=3, enabled_roles=())

    def test_direct_dataclass_forgery_is_revalidated_when_serialized(self):
        plan = self._derive()
        forged = replace(plan, global_cohort_sha256="e" * 64)
        self.assertIs(type(forged), C2LocalPlan)
        with self.assertRaises(CredentialError):
            c2_local_plan_document(forged)

    def test_read_selected_adapter_captures_inert_plan_and_returns_normally(self):
        class Store:
            def read_selected(inner, *, validate):
                result = validate(self.selector, self.bundle, self.active)
                self.assertIsNone(result)
                return object()
        plan = read_selected_c2_local_plan(Store(), clock=self.clock,
            account_id=self.owner[0], device_id=self.owner[1], enable_epoch=1,
            enabled_roles=("host",))
        self.assertEqual(plan, self._derive())


if __name__ == "__main__":
    unittest.main()
