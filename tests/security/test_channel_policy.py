from __future__ import annotations

import base64
import json
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from steamboat_security.channel_policy import (
    DOMAIN,
    ChannelPolicyStore,
    MAX_CHANNEL_POLICY_BYTES,
    sign_channel_policy,
)
from steamboat_security.clock import Clock
from steamboat_security.codec import canonical_json
from steamboat_security.certificates import public_key_sha256
from steamboat_security.errors import SnapshotError


def pem_private(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def pem_public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


class ChannelPolicyTests(unittest.TestCase):
    def setUp(self):
        self.wall, self.mono = 1000.0, 50.0
        self.clock = Clock(
            wall=lambda: self.wall,
            monotonic=lambda: self.mono,
            uncertainty_seconds=lambda: 0.0,
        )
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.payload = {
            "version": 1,
            "revision": 1,
            "issued_at": 1000,
            "expires_at": 1100,
            "gateways": [
                {
                    "gateway_id": "gw-east",
                    "serial": "ab12",
                    "certificate_sha256": "1" * 64,
                    "public_key_sha256": "2" * 64,
                    "not_before": 900,
                    "not_after": 1500,
                    "endpoint_host": "gateway.example.net",
                    "endpoint_port": 443,
                }
            ],
            "workers": [
                {
                    "account_id": "acct_" + "1" * 32,
                    "device_id": "dev_" + "2" * 32,
                    "host_serial": "ab13",
                    "host_credential_epoch": 2,
                    "host_certificate_sha256": "3" * 64,
                    "worker_boot_id": "4" * 32,
                    "assignment_id": "asg_" + "5" * 32,
                    "model_id": "6" * 64,
                    "channel_serial": "ab14",
                    "channel_certificate_sha256": "7" * 64,
                    "channel_public_key_sha256": "8" * 64,
                    "not_before": 900,
                    "not_after": 1500,
                    "gateway_id": "gw-east",
                }
            ],
            "routes": [
                {
                    "gateway_id": "gw-east",
                    "account_id": "acct_" + "1" * 32,
                    "device_id": "dev_" + "9" * 32,
                    "actor_serial": "ab15",
                    "actor_credential_epoch": 3,
                    "actor_certificate_sha256": "a" * 64,
                    "coordinator_boot_id": "b" * 32,
                    "tenant_account_id": "acct_" + "1" * 32,
                    "target_device_id": "dev_" + "2" * 32,
                    "worker_boot_id": "4" * 32,
                    "assignment_id": "asg_" + "5" * 32,
                    "model_id": "6" * 64,
                    "methods": ["Describe", "Step"],
                }
            ],
        }
        self.commit_calls = []
        self.store = self.new_store()

    def new_store(self, **kwargs):
        options = {
            "verification_key_pem": pem_public(self.key),
            "clock": self.clock,
            "durable_commit": lambda *args: self.commit_calls.append(args),
        }
        options.update(kwargs)
        return ChannelPolicyStore(**options)

    def sign(self, payload=None):
        return sign_channel_policy(
            self.payload if payload is None else payload, pem_private(self.key)
        )

    def test_install_view_is_immutable_and_lookup_matches_full_route(self):
        view = self.store.install(self.sign())
        self.assertEqual(view.gateway("gw-east")["serial"], "ab12")
        self.assertEqual(
            view.worker("dev_" + "2" * 32, "4" * 32)["assignment_id"], "asg_" + "5" * 32
        )
        self.assertIsNotNone(
            view.route(
                gateway_id="gw-east",
                account_id="acct_" + "1" * 32,
                device_id="dev_" + "9" * 32,
                actor_serial="ab15",
                actor_credential_epoch=3,
                actor_certificate_sha256="a" * 64,
                coordinator_boot_id="b" * 32,
                tenant_account_id="acct_" + "1" * 32,
                target_device_id="dev_" + "2" * 32,
                worker_boot_id="4" * 32,
                assignment_id="asg_" + "5" * 32,
                model_id="6" * 64,
                method="Step",
            )
        )
        with self.assertRaises(TypeError):
            view.gateway("gw-east")["serial"] = "1"
        with self.assertRaises(TypeError):
            view.workers[("dev_" + "2" * 32, "4" * 32)]["model_id"] = "0" * 64
        self.assertIs(view, self.store.current())

    def test_domain_signature_low_s_and_canonical_envelope(self):
        signed = self.sign()
        self.store.install(signed)
        envelope = json.loads(signed)
        sig = base64.b64decode(envelope["signature"])
        _r, s = decode_dss_signature(sig)
        self.assertLessEqual(
            s, 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 // 2
        )
        # A valid signature from another domain is rejected.
        alternate = self.key.sign(
            canonical_json(self.payload), ec.ECDSA(hashes.SHA256())
        )
        envelope["signature"] = base64.b64encode(alternate).decode("ascii")
        with self.assertRaises(SnapshotError):
            self.new_store().install(canonical_json(envelope))
        r, s = decode_dss_signature(sig)
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        envelope["signature"] = base64.b64encode(
            encode_dss_signature(r, order - s)
        ).decode("ascii")
        with self.assertRaises(SnapshotError):
            self.new_store().install(canonical_json(envelope))
        with self.assertRaises(SnapshotError):
            self.new_store().install(b" " + signed)
        self.assertTrue(DOMAIN.endswith(b"\0"))

    def test_rejects_duplicate_nonfinite_unknown_and_oversize_before_crypto(self):
        signed = self.sign()
        duplicate = signed.decode().replace(
            b'"version":1,'.decode(), b'"version":1,"version":1,'.decode(), 1
        )
        for raw in (
            duplicate.encode(),
            signed.replace(b'"expires_at":1100', b'"expires_at":NaN'),
            b"x" * (MAX_CHANNEL_POLICY_BYTES + 1),
        ):
            with self.subTest(raw_len=len(raw)), self.assertRaises(SnapshotError):
                self.new_store().install(raw)
        with self.assertRaises(SnapshotError):
            self.sign({**self.payload, "extra": True})

    def test_rejects_unmatched_scope_cross_account_duplicate_route_and_signer_key(self):
        bad_route = {
            **self.payload,
            "routes": [
                {**self.payload["routes"][0], "assignment_id": "asg_" + "f" * 32}
            ],
        }
        with self.assertRaises(SnapshotError):
            self.sign(bad_route)
        cross = {
            **self.payload,
            "routes": [
                {**self.payload["routes"][0], "tenant_account_id": "acct_" + "f" * 32}
            ],
        }
        with self.assertRaises(SnapshotError):
            self.sign(cross)
        duplicated = {**self.payload, "routes": self.payload["routes"] * 2}
        with self.assertRaises(SnapshotError):
            self.sign(duplicated)
        signer_hash = public_key_sha256(self.key.public_key())
        bad_gateway = {
            **self.payload,
            "gateways": [
                {**self.payload["gateways"][0], "public_key_sha256": signer_hash}
            ],
        }
        with self.assertRaises(SnapshotError):
            self.sign(bad_gateway)
        channel_key_collision = json.loads(json.dumps(self.payload))
        channel_key_collision["workers"][0]["channel_public_key_sha256"] = "2" * 64
        with self.assertRaises(SnapshotError):
            self.sign(channel_key_collision)
        host_serial_collision = json.loads(json.dumps(self.payload))
        host_serial_collision["workers"][0]["host_serial"] = "ab12"
        with self.assertRaises(SnapshotError):
            self.sign(host_serial_collision)

    def test_policy_expiry_clock_uncertainty_rollback_and_equivocation(self):
        view = self.store.install(self.sign())
        self.wall += 100.0
        self.mono += 100.0
        with self.assertRaises(SnapshotError):
            self.store.current()
        self.wall, self.mono = 1000.0, 50.0
        self.clock = Clock(
            wall=lambda: self.wall,
            monotonic=lambda: self.mono,
            uncertainty_seconds=lambda: 0.0,
        )
        self.store = self.new_store()
        self.store.install(self.sign())
        changed = {**self.payload, "routes": []}
        with self.assertRaises(SnapshotError):
            self.store.install(self.sign(changed))

    def test_same_revision_resign_is_idempotent_and_never_extends(self):
        first = self.store.install(self.sign())
        self.wall += 10
        self.mono += 10
        second = self.store.install(self.sign())
        self.assertIs(first, second)
        self.assertEqual(first.deadline_monotonic, second.deadline_monotonic)
        self.assertEqual(len(self.commit_calls), 1)

    def test_new_revision_with_same_expiry_cannot_extend_deadline(self):
        self.wall = 1002.0
        uncertainty = [2.0]
        self.clock = Clock(
            wall=lambda: self.wall,
            monotonic=lambda: self.mono,
            uncertainty_seconds=lambda: uncertainty[0],
        )
        self.store = self.new_store()
        first = self.store.install(self.sign())
        uncertainty[0] = 0.0
        self.wall += 5
        self.mono += 5
        renewed = {**self.payload, "revision": 2, "issued_at": 1007}
        second = self.store.install(self.sign(renewed))
        self.assertEqual(second.deadline_monotonic, first.deadline_monotonic)

    def test_cross_account_worker_route_is_policy_valid_and_pins_assignment(self):
        payload = json.loads(json.dumps(self.payload))
        payload["workers"][0]["account_id"] = "acct_" + "c" * 32
        # The actor remains in its own tenant account; C1 grant evaluation binds
        # the foreign host account separately at admission time.
        policy = self.sign(payload)
        view = self.store.install(policy)
        self.assertIsNotNone(
            view.route(
                gateway_id="gw-east",
                account_id="acct_" + "1" * 32,
                device_id="dev_" + "9" * 32,
                actor_serial="ab15",
                actor_credential_epoch=3,
                actor_certificate_sha256="a" * 64,
                coordinator_boot_id="b" * 32,
                tenant_account_id="acct_" + "1" * 32,
                target_device_id="dev_" + "2" * 32,
                worker_boot_id="4" * 32,
                assignment_id="asg_" + "5" * 32,
                model_id="6" * 64,
                method="Step",
            )
        )

    def test_new_policy_revision_removes_stale_worker_and_gateway(self):
        self.store.install(self.sign())
        replaced = {
            **self.payload,
            "revision": 2,
            "gateways": [],
            "workers": [],
            "routes": [],
        }
        view = self.store.install(self.sign(replaced))
        self.assertIsNone(view.gateway("gw-east"))
        self.assertIsNone(view.worker("dev_" + "2" * 32, "4" * 32))

    def test_explicit_memory_only_store_can_install_without_durable_hook(self):
        store = ChannelPolicyStore(
            pem_public(self.key), clock=self.clock, require_durable=False
        )
        self.assertEqual(store.install(self.sign()).revision, 1)

    def test_requires_exact_clock_and_bounds_keys_and_integer_fields(self):
        class DerivedClock(Clock):
            pass

        with self.assertRaises(TypeError):
            ChannelPolicyStore(pem_public(self.key), clock=DerivedClock())
        with self.assertRaises(SnapshotError):
            ChannelPolicyStore(
                b"x" * (MAX_CHANNEL_POLICY_BYTES + 1),
                clock=self.clock,
                durable_commit=lambda *_: None,
            )
        huge = {**self.payload, "revision": 2**63}
        with self.assertRaises(SnapshotError):
            self.sign(huge)

    def test_current_rejects_during_callback_and_faults_after_postcommit_clock_error(
        self,
    ):
        self.store.install(self.sign())
        self.payload = {**self.payload, "revision": 2, "issued_at": 1000}

        def probe(*_args):
            self.store.current()

        self.store._commit = probe
        with self.assertRaises(SnapshotError):
            self.store.install(self.sign())
        with self.assertRaises(SnapshotError):
            self.store.current()

        should_fail = [False]
        clock = Clock(
            wall=lambda: (
                (_ for _ in ()).throw(RuntimeError("clock fault"))
                if should_fail[0]
                else 1000.0
            ),
            monotonic=lambda: 50.0,
            uncertainty_seconds=lambda: 0.0,
        )

        def fail_after_commit(*_args):
            should_fail[0] = True

        store = ChannelPolicyStore(
            pem_public(self.key), clock=clock, durable_commit=fail_after_commit
        )
        with self.assertRaises(SnapshotError):
            store.install(self.sign())
        should_fail[0] = False
        clock.revalidate_after_resume(trusted_clock=True)
        with self.assertRaises(SnapshotError):
            store.current()

    def test_postcommit_widened_uncertainty_shortens_deadline_permanently(self):
        uncertainty = [0.0]
        self.clock = Clock(
            wall=lambda: self.wall,
            monotonic=lambda: self.mono,
            uncertainty_seconds=lambda: uncertainty[0],
        )

        def widen_during_commit(*_args):
            self.wall += 10
            self.mono += 10
            uncertainty[0] = 5.0

        store = ChannelPolicyStore(
            pem_public(self.key), clock=self.clock, durable_commit=widen_during_commit
        )
        view = store.install(self.sign())
        self.assertEqual(view.deadline_monotonic, 145.0)
        uncertainty[0] = 0.0
        self.wall += 87
        self.mono += 87
        with self.assertRaises(SnapshotError):
            store.current()

    def test_revision_and_digest_fence_and_rollback(self):
        fenced = self.new_store(minimum_revision=1, minimum_policy_digest="f" * 64)
        with self.assertRaises(SnapshotError):
            fenced.install(self.sign())
        self.store.install(self.sign())
        lower = {**self.payload, "revision": 2, "issued_at": 999, "expires_at": 1100}
        # Invalid issue time is rejected even when revision increases.
        with self.assertRaises(SnapshotError):
            self.store.install(self.sign(lower))

    def test_durable_hook_required_fault_reentry_and_post_commit_expiry(self):
        with self.assertRaises(ValueError):
            ChannelPolicyStore(pem_public(self.key), clock=self.clock)
        holder = {}

        def reenter(*args):
            holder["store"].install(args[0])

        holder["store"] = ChannelPolicyStore(
            pem_public(self.key), clock=self.clock, durable_commit=reenter
        )
        with self.assertRaises(SnapshotError):
            holder["store"].install(self.sign())
        with self.assertRaises(SnapshotError):
            holder["store"].current()

        def expire(*_args):
            self.wall, self.mono = 1100.0, 150.0

        failed = ChannelPolicyStore(
            pem_public(self.key), clock=self.clock, durable_commit=expire
        )
        with self.assertRaises(SnapshotError):
            failed.install(self.sign())
        with self.assertRaises(SnapshotError):
            failed.current()


if __name__ == "__main__":
    unittest.main()
