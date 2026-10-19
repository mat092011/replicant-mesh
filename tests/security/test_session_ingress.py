import dataclasses
from types import SimpleNamespace
import unittest

from steamboat_security.clock import Clock
from steamboat_security.errors import SessionError
from steamboat_security.sessions import SessionBindings


class _Binding:
    def __init__(self, index=0):
        self.fields = {
            "target_device_id": "dev_" + "1" * 32,
            "worker_boot_id": "2" * 32,
            "session_id": f"session-{index}",
            "request_id": f"request-{index}",
            "route_id": f"route-{index}",
            "assignment_id": "asg_" + "3" * 32,
            "operation_id": f"operation-{index}",
        }

    def __getitem__(self, key):
        return self.fields[key]


def _clock():
    return Clock(wall=lambda: 1000.0, monotonic=lambda: 100.0,
                 uncertainty_seconds=lambda: 0.0)


ACTOR = SimpleNamespace(
    account_id="acct-1", device_id="device-coordinator", role="coordinator",
    serial="actor-serial", public_key_sha256="a" * 64,
    certificate_sha256="b" * 64, credential_epoch=1)
LOCAL = SimpleNamespace(
    account_id="acct-1", device_id="device-worker", role="host",
    serial="local-serial", public_key_sha256="c" * 64,
    certificate_sha256="d" * 64, credential_epoch=1)
GRANT = SimpleNamespace(identity=("grant-id", 1))
GATEWAY_ONE = ("gateway-v1", "e" * 64, "f" * 32)
GATEWAY_NEXT = ("gateway-v1", "e" * 64, "0" * 32)
GATEWAY_PEER = ("gateway-v1", "1" * 64, "f" * 32)


class SessionIngressTests(unittest.TestCase):
    def setUp(self):
        self.sessions = SessionBindings(clock=_clock())

    def claim(self, ingress=None, index=0):
        return self.sessions.claim(
            _Binding(index), actor=ACTOR, local=LOCAL, grant=GRANT,
            model_id="model-fixed", lifetime_ms=30_000, max_positions=64,
            idle_lease_ms=10_000, ingress_identity=ingress)

    def check(self, ingress=None, index=0, lease="a" * 32):
        return self.sessions.check(
            _Binding(index), actor=ACTOR, local=LOCAL, grant=GRANT,
            model_id="model-fixed", session_id=f"session-{index}",
            worker_boot_id="2" * 32, lease_token=lease,
            ingress_identity=ingress)

    def open(self, ingress=None, index=0, lease="a" * 32):
        claim = self.claim(ingress, index)
        self.sessions.seal_open(claim, lease)
        return claim

    def test_direct_ingress_remains_default_and_duplicate_open_is_compatible(self):
        first = self.claim()
        self.assertIsNone(first.ingress_identity)
        self.sessions.seal_open(first, "a" * 32)
        duplicate = self.claim(None)
        self.assertFalse(duplicate.is_new)
        self.assertIsNone(duplicate.ingress_identity)
        self.sessions.seal_open(duplicate, "a" * 32)
        self.assertEqual(self.check(), first.key)

    def test_gateway_duplicate_open_requires_exact_certificate_and_generation(self):
        first = self.open(GATEWAY_ONE)
        duplicate = self.claim(GATEWAY_ONE)
        self.assertFalse(duplicate.is_new)
        self.sessions.seal_open(duplicate, "a" * 32)
        self.assertEqual(first.ingress_identity, GATEWAY_ONE)
        for ingress in (None, GATEWAY_NEXT, GATEWAY_PEER):
            with self.subTest(ingress=ingress), self.assertRaises(SessionError):
                self.claim(ingress)

    def test_gateway_ingress_is_required_for_checks_claims_and_terminal_responses(self):
        claim = self.open(GATEWAY_ONE)
        for ingress in (None, GATEWAY_NEXT, GATEWAY_PEER):
            with self.subTest(check=ingress), self.assertRaises(SessionError):
                self.check(ingress)
        self.assertEqual(self.check(GATEWAY_ONE), claim.key)

        forged = dataclasses.replace(claim, ingress_identity=GATEWAY_NEXT)
        with self.assertRaises(SessionError):
            self.sessions.assert_claim_live(forged)
        with self.assertRaises(SessionError):
            self.sessions.authorization_deadline(
                claim.key, now_monotonic=100.0, claim=forged)

        self.sessions.complete_operation(claim.key, "CloseSession", reclaimed=False)
        for ingress in (None, GATEWAY_NEXT, GATEWAY_PEER):
            with self.subTest(terminal=ingress), self.assertRaises(SessionError):
                self.sessions.assert_terminal(
                    _Binding(), actor=ACTOR, local=LOCAL, grant=GRANT,
                    model_id="model-fixed", key=claim.key,
                    ingress_identity=ingress)
        self.sessions.assert_terminal(
            _Binding(), actor=ACTOR, local=LOCAL, grant=GRANT,
            model_id="model-fixed", key=claim.key,
            ingress_identity=GATEWAY_ONE)

    def test_forged_claim_cannot_seal_or_fail_the_real_ingress_claim(self):
        claim = self.claim(GATEWAY_ONE)
        forged = dataclasses.replace(claim, ingress_identity=None)
        with self.assertRaises(SessionError):
            self.sessions.seal_open(forged, "a" * 32)
        self.sessions.fail_open(forged, cache_may_exist=False)
        self.sessions.assert_claim_live(claim)
        self.sessions.seal_open(claim, "a" * 32)

    def test_ingress_grammar_is_closed_and_rejects_non_tuple_or_invalid_hashes(self):
        malformed = (
            True,
            [*GATEWAY_ONE],
            ("other-v1", "e" * 64, "f" * 32),
            ("gateway-v1", "E" * 64, "f" * 32),
            ("gateway-v1", "e" * 63, "f" * 32),
            ("gateway-v1", "e" * 64, "F" * 32),
            ("gateway-v1", "e" * 64, "f" * 31),
            ("gateway-v1", "e" * 64, "f" * 32, "extra"),
        )
        for ingress in malformed:
            with self.subTest(ingress=ingress), self.assertRaises(SessionError):
                self.claim(ingress)
        self.assertEqual(self.sessions.record_count(), 0)

    def test_stream_loss_invalidates_only_matching_generation_without_reclaim(self):
        direct = self.open(None, 0)
        affected = self.open(GATEWAY_ONE, 1)
        next_generation = self.open(GATEWAY_NEXT, 2)
        peer = self.open(GATEWAY_PEER, 3)
        callback_notices = []
        self.sessions.subscribe(callback_notices.append)

        self.assertEqual(self.sessions.invalidate_ingress(GATEWAY_ONE), 1)
        self.assertEqual(self.sessions.invalidate_ingress(GATEWAY_ONE), 0)
        self.assertEqual(len(callback_notices), 1)
        self.assertEqual(callback_notices[0].session_id, "session-1")
        self.assertEqual(callback_notices[0].reason, "gateway-stream-lost")
        notices = self.sessions.poll()
        self.assertEqual(tuple(n.session_id for n in notices), ("session-1",))

        record = self.sessions._records[affected.key]
        self.assertEqual(record.state, "invalidated")
        self.assertFalse(record.reclaimed)
        self.assertIsNotNone(record.lease_digest)
        self.assertEqual(self.sessions.record_count(), 4)
        self.assertEqual(self.check(None, 0), direct.key)
        self.assertEqual(self.check(GATEWAY_NEXT, 2), next_generation.key)
        self.assertEqual(self.check(GATEWAY_PEER, 3), peer.key)
        with self.assertRaises(SessionError):
            self.check(GATEWAY_ONE, 1)

    def test_invalidation_rejects_direct_identity_and_unbounded_reason(self):
        for ingress, reason in ((None, "gateway-stream-lost"),
                                (GATEWAY_ONE, "x" * 65),
                                (GATEWAY_ONE, "bad\nreason")):
            with self.subTest(ingress=ingress, reason=reason), self.assertRaises(SessionError):
                self.sessions.invalidate_ingress(ingress, reason)


if __name__ == "__main__":
    unittest.main()
