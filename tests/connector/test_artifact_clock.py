"""Conservative C1 clock authority applies even to an already installed package."""

import unittest

from steamboat_connector.catalog import CatalogError, CatalogVerifier
from steamboat_security.clock import Clock
from steamboat_security.errors import ClockError
from tests.connector.test_artifacts import (
    _ACCOUNT, _DEVICE, _NOW, _PUBLIC, _assignment_payload, _catalog_payload,
    _sign_document,
)


class ArtifactClockTests(unittest.TestCase):
    def setUp(self):
        self.wall = float(_NOW)
        self.mono = 100.0
        self.uncertainty = 0.0
        self.clock = Clock(wall=lambda: self.wall, monotonic=lambda: self.mono,
                           uncertainty_seconds=lambda: self.uncertainty)
        self.verifier = CatalogVerifier(_PUBLIC, clock=self.clock)

    def catalog(self, **changes):
        return _sign_document(_catalog_payload(**changes), "catalog")

    def test_expired_catalog_cannot_be_revived_by_caller_now(self):
        raw = self.catalog(expires_at=_NOW + 10)
        self.verifier.verify_catalog(raw, now=_NOW - 1000)
        self.wall += 10
        self.mono += 10
        with self.assertRaises(CatalogError):
            self.verifier.verify_catalog(raw, now=_NOW)

    def test_not_before_and_expiry_cover_full_uncertainty_interval(self):
        self.uncertainty = 2
        with self.assertRaises(CatalogError):
            self.verifier.verify_catalog(self.catalog(issued_at=_NOW - 1))
        with self.assertRaises(CatalogError):
            self.verifier.verify_catalog(self.catalog(expires_at=_NOW + 2))

    def test_assignment_expiry_uses_core_clock(self):
        catalog = self.verifier.verify_catalog(self.catalog())
        payload = _assignment_payload(catalog, expires_at=_NOW + 5)
        raw = _sign_document(payload, "assignment")
        self.verifier.verify_assignment(raw, catalog, account_id=_ACCOUNT,
                                       device_id=_DEVICE, role="host", now=_NOW)
        self.wall += 5
        self.mono += 5
        with self.assertRaises(CatalogError):
            self.verifier.verify_assignment(raw, catalog, account_id=_ACCOUNT,
                                           device_id=_DEVICE, role="host", now=_NOW)

    def test_clock_anomaly_remains_latched_across_rechecks(self):
        raw = self.catalog()
        self.verifier.verify_catalog(raw)
        self.wall -= 1
        with self.assertRaises(ClockError):
            self.verifier.verify_catalog(raw)
        self.wall += 2
        self.mono += 1
        with self.assertRaises(ClockError):
            self.verifier.verify_catalog(raw)

    def test_decreasing_uncertainty_cannot_extend_monotonic_authority(self):
        raw = self.catalog(expires_at=_NOW + 10)
        self.uncertainty = 2
        self.verifier.verify_catalog(raw)
        original = next(iter(self.verifier._deadlines.values()))
        self.uncertainty = 0
        self.verifier.verify_catalog(raw)
        self.assertEqual(next(iter(self.verifier._deadlines.values())), original)
        self.wall += 8
        self.mono += 8
        with self.assertRaises(CatalogError):
            self.verifier.verify_catalog(raw)

    def test_bounded_deadlines_fail_closed_without_evicting_live_authority(self):
        for revision in range(1, 129):
            self.verifier.verify_catalog(self.catalog(revision=revision))
        with self.assertRaises(CatalogError):
            self.verifier.verify_catalog(self.catalog(revision=129))
        self.verifier.verify_catalog(self.catalog(revision=1))
        self.assertEqual(len(self.verifier._deadlines), 128)

    def test_intervening_document_cannot_prune_a_still_revivable_fence(self):
        raw = self.catalog(expires_at=_NOW + 10)
        self.uncertainty = 2
        self.verifier.verify_catalog(raw)
        self.wall += 8
        self.mono += 8
        # Latest plausible wall time is at the first expiry. Actual wall time
        # has not reached it; reducing uncertainty must not revive that fence.
        self.verifier.verify_catalog(self.catalog(revision=2))
        self.wall += 1
        self.mono += 1
        self.uncertainty = 0
        with self.assertRaises(CatalogError):
            self.verifier.verify_catalog(raw)

    def test_cached_parent_cannot_authorize_after_its_monotonic_fence(self):
        self.uncertainty = 2
        catalog = self.verifier.verify_catalog(self.catalog(expires_at=_NOW + 10))
        raw = _sign_document(_assignment_payload(catalog, expires_at=_NOW + 10),
                             "assignment")
        self.wall += 9
        self.mono += 9
        self.uncertainty = 0
        with self.assertRaises(CatalogError):
            self.verifier.verify_assignment(raw, catalog, account_id=_ACCOUNT,
                                           device_id=_DEVICE, role="host")

    def test_assignment_captures_shorter_parent_deadline(self):
        self.uncertainty = 2
        catalog = self.verifier.verify_catalog(self.catalog(expires_at=_NOW + 10))
        self.uncertainty = 0
        raw = _sign_document(_assignment_payload(catalog, expires_at=_NOW + 10),
                             "assignment")
        child = self.verifier.verify_assignment(raw, catalog, account_id=_ACCOUNT,
                                                device_id=_DEVICE, role="host")
        self.assertEqual(self.verifier._deadlines[self.verifier._authority_identity(child)][0],
                         self.verifier._deadlines[self.verifier._authority_identity(catalog)][0])

    def test_unconfigured_core_clock_does_not_become_trusted(self):
        verifier = CatalogVerifier(_PUBLIC, clock=Clock())
        with self.assertRaises(ClockError):
            verifier.verify_catalog(self.catalog(), now=_NOW)


if __name__ == "__main__":
    unittest.main()
