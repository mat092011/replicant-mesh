"""Pure bounds checks for C2 binding-local deadline retention."""
from dataclasses import replace
from types import MappingProxyType
import unittest

from steamboat_security.clock import ClockSample
from steamboat_security.errors import SnapshotError
from steamboat_security.root_c2_deadlines import (
    DeadlineFloors, MAX_POLICY_FLOORS, MAX_CREDENTIAL_FLOORS, MAX_GRANT_FLOORS,
)
from steamboat_security.snapshot import CredentialRecord, Grant, SnapshotView


def _view(*, expiry=200, credential_expiry=200, grant_expiry=190, grants=True):
    record = CredentialRecord("acct_" + "1" * 32, "dev_" + "2" * 32,
        "personal_coordinator", "a1", "3" * 64, "4" * 64, 1, 50,
        credential_expiry, (), (), ())
    grant = Grant(record.account_id, record.device_id, record.role, record.serial,
        record.public_key_sha256, record.credential_epoch, record.account_id,
        record.account_id, record.device_id, "host", "b2", "5" * 64, 1,
        "boot_" + "6" * 32, "boot_" + "7" * 32, "asg_" + "8" * 32,
        "9" * 64, "steamboat.worker.v1.Worker/Step", 50, grant_expiry)
    selected_grants = (grant,) if grants else ()
    return SnapshotView(1, 50, expiry, float(expiry),
        MappingProxyType({record.serial: float(credential_expiry)}),
        MappingProxyType({grant.identity: float(grant_expiry)} if grants else {}),
        MappingProxyType({record.serial: record}), selected_grants, frozenset(),
        frozenset(), b"signed-payload-fixture", 0.0)


class DeadlineFloorTests(unittest.TestCase):
    def test_uncertainty_tightening_survives_lower_uncertainty_and_new_head(self):
        floors = DeadlineFloors()
        first = floors.retain(_view(), ClockSample(100.0, 100.0, 20.0, 0))
        self.assertEqual(first.deadline_monotonic, 180.0)
        self.assertEqual(first.credential_deadlines["a1"], 180.0)
        original_grant = next(iter(first.grant_deadlines))
        self.assertEqual(first.grant_deadlines[original_grant], 170.0)

        # A re-signed same-expiry head cannot clear any old floor.
        same_expiry = replace(_view(), revision=2, canonical_payload=b"new-signature-payload")
        second = floors.retain(same_expiry, ClockSample(101.0, 121.0, 0.0, 0))
        self.assertEqual(second.deadline_monotonic, 180.0)
        self.assertEqual(second.credential_deadlines["a1"], 180.0)
        self.assertEqual(second.grant_deadlines[original_grant], 170.0)

        # A new signed expiry and new grant identity may renew those bounds;
        # the unchanged role credential identity keeps its earlier floor.
        renewed = floors.retain(_view(expiry=220, credential_expiry=200,
                                      grant_expiry=210),
                                ClockSample(101.0, 121.0, 0.0, 0))
        self.assertGreater(renewed.deadline_monotonic, 180.0)
        self.assertEqual(renewed.credential_deadlines["a1"], 180.0)
        self.assertGreater(next(iter(renewed.grant_deadlines.values())), 180.0)

    def test_removed_then_readded_identical_grant_keeps_old_floor(self):
        floors = DeadlineFloors()
        with_grant = _view(grant_expiry=190)
        first = floors.retain(with_grant, ClockSample(100.0, 100.0, 20.0, 0))
        key = next(iter(first.grant_deadlines))
        without = floors.retain(_view(grants=False), ClockSample(101.0, 121.0, 0.0, 0))
        self.assertEqual(dict(without.grant_deadlines), {})
        readded = floors.retain(with_grant, ClockSample(101.0, 121.0, 0.0, 0))
        self.assertEqual(readded.grant_deadlines[key], 170.0)

    def test_floor_histories_fail_closed_at_fixed_bounds(self):
        sample = ClockSample(100.0, 100.0, 0.0, 0)
        for name, capacity, view in (
            ("policy", MAX_POLICY_FLOORS, _view(expiry=300)),
            ("credentials", MAX_CREDENTIAL_FLOORS, _view()),
            ("grants", MAX_GRANT_FLOORS, _view()),
        ):
            floors = DeadlineFloors()
            mapping = getattr(floors, name)
            mapping.update({("old", i): 1.0 for i in range(capacity)})
            with self.subTest(name=name), self.assertRaisesRegex(SnapshotError, "history is full"):
                floors.retain(view, sample)
            self.assertEqual(len(mapping), capacity)

    def test_untrusted_view_shape_is_rejected(self):
        floors = DeadlineFloors()
        with self.assertRaises(SnapshotError):
            floors.retain(object(), ClockSample(100.0, 100.0, 0.0, 0))


if __name__ == "__main__":
    unittest.main()
