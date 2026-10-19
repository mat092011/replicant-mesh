"""Exercise the context capability with real signed core authorization."""

import time

from steamboat_runtime.participant_context import TrustedRequestContext, TrustedRequestContextExpired
from steamboat_security import new_id

from .test_identity_core import (ACCOUNT_A, BOOT_COORDINATOR, DEVICE_CONSUMER,
                                 DEVICE_COORDINATOR, IdentityFixture)


class CoreContextBridgeTests(IdentityFixture):
    def test_real_consumer_authorization_is_accepted_and_expiry_fails_closed(self):
        authorizer, time_source = self.coordinator_authorizer()
        fields = {
            "binding_version": 1, "operation_id": new_id("op"),
            "account_id": ACCOUNT_A, "device_id": DEVICE_CONSUMER,
            "role": "consumer", "credential_epoch": 1,
            "target_device_id": DEVICE_COORDINATOR, "request_id": new_id("req"),
        }
        payload = {"input_ids": [1], "new_tokens": 1, "timeout_seconds": 30,
                   "capture_logits": False}
        authorization = authorizer.authorize(
            "steamboat.v1.Coordinator", "Generate", payload,
            self.metadata("steamboat.v1.Coordinator", "Generate", fields),
            self.credentials["consumer"]["certificate"])
        self.assertIs(authorization.assert_live(), True)
        context = TrustedRequestContext(
            tenant_account_id=ACCOUNT_A, request_id=fields["request_id"],
            session_id=new_id("ses"), route_id=new_id("route"),
            coordinator_boot_id=BOOT_COORDINATOR, route_epoch=1, attempt=1,
            authorization=authorization, hard_monotonic_deadline=time.monotonic() + 30)
        context.assert_data_live()
        context.claim_admission()
        time_source.advance(301)
        with self.assertRaises(TrustedRequestContextExpired):
            context.assert_data_live()
