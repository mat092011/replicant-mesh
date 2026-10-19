"""C2 target views share one policy-pinned coordinator egress owner."""

import unittest

from steamboat_security.authorization import LocalIdentity
from steamboat_security.gateway_egress import (
    GatewayEgressError, is_owned_gateway_target_view,
)
from steamboat_security.outbound import OutboundAuthorizer, OutboundTarget
from tests.security import test_gateway_egress as egress_tests
from tests.security import test_outbound_authorization as outbound_tests
from steamboat_runtime.participant_context import TrustedRequestContext


class GatewayEgressCohortTests(unittest.TestCase):
    def setUp(self):
        egress_tests.GatewayEgressTests.setUpClass()
        self.fx = egress_tests.GatewayEgressTests(
            methodName="test_route_guard_reuses_c1_scope_and_checks_live_gateway_on_completion")
        self.addCleanup(self.fx.tearDown)
        self.fx.setUp()

    def test_primary_target_view_is_minted_duplicate_and_transport_bound(self):
        view = self.fx.egress.register_target(
            self.fx.adapter, self.fx.fx.credentials["host"]["certificate"])
        self.assertTrue(is_owned_gateway_target_view(view))
        self.assertIs(view, self.fx.egress.register_target(
            self.fx.adapter, self.fx.fx.credentials["host"]["certificate"]))
        self.assertIs(view.egress, self.fx.egress)
        self.assertIs(view.authorizer, self.fx.adapter)
        self.assertTrue(view.assert_transport_live())
        with self.assertRaises(AttributeError):
            view.authorizer = object()
        self.fx.egress.close()
        with self.assertRaises(GatewayEgressError):
            view.assert_transport_live()

    def test_conflicting_or_foreign_target_authority_is_rejected(self):
        cert = self.fx.fx.credentials["host"]["certificate"]
        target = self.fx.adapter.target
        conflicting = OutboundAuthorizer(
            local_identity=self.fx.adapter.local_identity,
            snapshot_store=self.fx.snapshot_store, clock=self.fx.clock,
            target=target,
            worker_request_type=outbound_tests.ParsedWorkerRequest,
            trusted_request_context_type=TrustedRequestContext,
            allow_bootstrap_describe=True)
        self.fx.egress.register_target(self.fx.adapter, cert)
        with self.assertRaises(GatewayEgressError):
            self.fx.egress.register_target(conflicting, cert)
        foreign_local = LocalIdentity(
            self.fx.fx.credentials["alt_coordinator"]["certificate"],
            egress_tests.identity_tests.BOOT_ALT_COORDINATOR,
            egress_tests.identity_tests.MODEL)
        foreign_target = OutboundTarget.from_record(
            service="steamboat.v1.Worker",
            record=self.fx.fx.records["host"], boot_id="e" * 32,
            model_id=egress_tests.identity_tests.MODEL,
            assignment_id=egress_tests.identity_tests.ASSIGNMENT)
        foreign = OutboundAuthorizer(
            local_identity=foreign_local, snapshot_store=self.fx.snapshot_store,
            clock=self.fx.clock, target=foreign_target,
            worker_request_type=outbound_tests.ParsedWorkerRequest,
            trusted_request_context_type=TrustedRequestContext,
            allow_bootstrap_describe=True)
        with self.assertRaises(GatewayEgressError):
            self.fx.egress.register_target(foreign, cert)
        with self.assertRaises(TypeError):
            self.fx.egress.register_target(object(), cert)

    def test_target_view_detects_authorizer_retarget_after_mint(self):
        cert = self.fx.fx.credentials["host"]["certificate"]
        view = self.fx.egress.register_target(self.fx.adapter, cert)
        original = self.fx.adapter.target
        self.fx.adapter.target = OutboundTarget.from_record(
            service="steamboat.v1.Worker", record=self.fx.fx.records["host"],
            boot_id="e" * 32,
            model_id=egress_tests.identity_tests.MODEL,
            assignment_id=egress_tests.identity_tests.ASSIGNMENT)
        try:
            with self.assertRaises(GatewayEgressError):
                view.mint_route_guard(
                    method="Describe",
                    trusted_request_context=self.fx.adapter.create_bootstrap_context())
        finally:
            self.fx.adapter.target = original


if __name__ == "__main__":
    unittest.main()
