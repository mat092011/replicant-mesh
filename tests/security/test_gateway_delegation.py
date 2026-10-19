from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from dataclasses import replace
from unittest.mock import patch
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from steamboat_security.authorization import LocalIdentity
from steamboat_security.certificates import (certificate_sha256, generate_ca,
    generate_private_key_pem, issue_leaf, make_csr, public_key_sha256, serial_hex,
    ROLE_EKUS)
from steamboat_security.channel_certificates import (issue_channel_certificate,
    make_channel_csr)
from steamboat_security.channel_policy import ChannelPolicyStore, sign_channel_policy
from steamboat_security.clock import Clock, ClockSample
from steamboat_security.codec import METADATA_KEY, WORKER_SERVICE, encode_binding
from steamboat_security.errors import SecurityError
from steamboat_security.gateway_delegation import (DOMAIN, DelegationError,
    GatewayDelegationVerifier, sign_gateway_delegation)


NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc).timestamp()
ACTOR_ACCOUNT = "acct_" + "1" * 32
ACTOR_DEVICE = "dev_" + "9" * 32
WORKER_ACCOUNT = ACTOR_ACCOUNT
WORKER_DEVICE = "dev_" + "2" * 32
WORKER_BOOT = "4" * 32
COORD_BOOT = "b" * 32
ASSIGNMENT = "asg_" + "5" * 32
MODEL = "6" * 64
GENERATION = "c" * 32


def private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def public_pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


class GatewayDelegationTests(unittest.TestCase):
    def setUp(self):
        self.wall, self.mono, self.uncertainty = NOW, 20.0, 0.0
        self.clock = Clock(wall=lambda: self.wall, monotonic=lambda: self.mono,
                           uncertainty_seconds=lambda: self.uncertainty)
        self.participant_ca, self.participant_ca_key = generate_ca(now=NOW - 100)
        self.gateway_ca, self.gateway_ca_key = generate_ca(now=NOW - 100)
        self.operator_key = ec.generate_private_key(ec.SECP256R1())

        actor_key = generate_private_key_pem()
        actor_csr = make_csr(actor_key, account_id=ACTOR_ACCOUNT,
                             device_id=ACTOR_DEVICE,
                             role="personal_coordinator")
        self.actor_pem = issue_leaf(self.participant_ca, self.participant_ca_key,
            actor_csr, account_id=ACTOR_ACCOUNT, device_id=ACTOR_DEVICE,
            role="personal_coordinator", not_before=NOW - 30, not_after=NOW + 700,
            serial=0xAB15, ekus=ROLE_EKUS["personal_coordinator"])

        host_key = generate_private_key_pem()
        host_csr = make_csr(host_key, account_id=WORKER_ACCOUNT,
                            device_id=WORKER_DEVICE, role="host")
        self.host_pem = issue_leaf(self.participant_ca, self.participant_ca_key,
            host_csr, account_id=WORKER_ACCOUNT, device_id=WORKER_DEVICE,
            role="host", not_before=NOW - 30, not_after=NOW + 700,
            serial=0xAB13, ekus=ROLE_EKUS["host"])
        self.local_identity = LocalIdentity(self.host_pem, WORKER_BOOT, MODEL, ASSIGNMENT)

        self.gateway_key = generate_private_key_pem()
        gateway_csr = make_channel_csr(self.gateway_key, kind="gateway",
            identity="gw-east", dns_names=("gateway.example.net",))
        self.gateway_pem = issue_channel_certificate(self.gateway_ca,
            self.gateway_ca_key, gateway_csr, kind="gateway", identity="gw-east",
            now=datetime.fromtimestamp(NOW - 20, timezone.utc), lifetime_seconds=600,
            dns_names=("gateway.example.net",))
        gateway_cert = x509.load_pem_x509_certificate(self.gateway_pem)
        actor_cert = x509.load_pem_x509_certificate(self.actor_pem)
        host_cert = x509.load_pem_x509_certificate(self.host_pem)
        self.payload = {
            "version": 1, "revision": 1, "issued_at": int(NOW - 10),
            "expires_at": int(NOW + 270),
            "gateways": [{"gateway_id": "gw-east",
                "serial": serial_hex(gateway_cert.serial_number),
                "certificate_sha256": certificate_sha256(gateway_cert),
                "public_key_sha256": public_key_sha256(gateway_cert.public_key()),
                "not_before": int(NOW - 20), "not_after": int(NOW + 280),
                "endpoint_host": "gateway.example.net", "endpoint_port": 443}],
            "workers": [{"account_id": WORKER_ACCOUNT, "device_id": WORKER_DEVICE,
                "host_serial": serial_hex(host_cert.serial_number),
                "host_credential_epoch": 2,
                "host_certificate_sha256": certificate_sha256(host_cert),
                "worker_boot_id": WORKER_BOOT, "assignment_id": ASSIGNMENT,
                "model_id": MODEL, "channel_serial": "ab14",
                "channel_certificate_sha256": "7" * 64,
                "channel_public_key_sha256": "8" * 64,
                "not_before": int(NOW - 10), "not_after": int(NOW + 270),
                "gateway_id": "gw-east"}],
            "routes": [{"gateway_id": "gw-east", "account_id": ACTOR_ACCOUNT,
                "device_id": ACTOR_DEVICE,
                "actor_serial": serial_hex(actor_cert.serial_number),
                "actor_credential_epoch": 3,
                "actor_certificate_sha256": certificate_sha256(actor_cert),
                "coordinator_boot_id": COORD_BOOT,
                "tenant_account_id": ACTOR_ACCOUNT,
                "target_device_id": WORKER_DEVICE, "worker_boot_id": WORKER_BOOT,
                "assignment_id": ASSIGNMENT, "model_id": MODEL,
                "methods": ["Describe", "OpenSession", "Step"]}],
        }
        self.policy_bytes = sign_channel_policy(self.payload, private_pem(self.operator_key))
        self.policy_store = ChannelPolicyStore(public_pem(self.operator_key),
            clock=self.clock, durable_commit=lambda *_: None)
        self.view = self.policy_store.install(self.policy_bytes)
        self.verifier = GatewayDelegationVerifier(self.policy_store, clock=self.clock,
            gateway_ca_pem=self.gateway_ca, participant_ca_pem=self.participant_ca,
            local_identity=self.local_identity, endpoint_host="gateway.example.net",
            endpoint_port=443)
        self.binding = encode_binding(WORKER_SERVICE, "OpenSession", {
            "binding_version": 1, "operation_id": "op_" + "a" * 32,
            "account_id": ACTOR_ACCOUNT, "device_id": ACTOR_DEVICE,
            "role": "personal_coordinator", "credential_epoch": 3,
            "target_device_id": WORKER_DEVICE, "coordinator_boot_id": COORD_BOOT,
            "tenant_account_id": ACTOR_ACCOUNT, "request_id": "req_" + "1" * 32,
            "session_id": "ses_" + "2" * 32, "route_id": "route_" + "3" * 32,
            "route_epoch": 1, "attempt": 1, "assignment_id": ASSIGNMENT,
            "worker_boot_id": WORKER_BOOT})
        self.metadata = [(METADATA_KEY, self.binding)]
        self.request = b"bounded raw protobuf request"
        self.delegation = self.make_delegation()

    def make_delegation(self, *, changes=None, signer=None):
        payload = {
            "version": 1, "policy_revision": self.view.revision,
            "policy_digest": self.view.policy_digest, "gateway_id": "gw-east",
            "gateway_certificate_sha256": self.payload["gateways"][0]["certificate_sha256"],
            "actor_certificate_base64": base64.b64encode(self.actor_pem).decode("ascii"),
            "coordinator_boot_id": COORD_BOOT, "tenant_account_id": ACTOR_ACCOUNT,
            "target_device_id": WORKER_DEVICE, "worker_boot_id": WORKER_BOOT,
            "assignment_id": ASSIGNMENT, "model_id": MODEL,
            "stream_generation": GENERATION, "frame_sequence": 1,
            "service": WORKER_SERVICE, "method": "OpenSession",
            "binding_sha256": hashlib.sha256(self.binding).hexdigest(),
            "request_sha256": hashlib.sha256(self.request).hexdigest(),
            "issued_at": int(NOW - 1), "expires_at": int(NOW + 120),
        }
        payload.update(changes or {})
        return sign_gateway_delegation(payload, signer or self.gateway_key, self.gateway_pem)

    def verify(self, envelope=None, **kwargs):
        args = dict(gateway_peer_certificate_pem=self.gateway_pem,
                    metadata=self.metadata, request_bytes=self.request,
                    expected_stream_generation=GENERATION,
                    expected_frame_sequence=1)
        args.update(kwargs)
        return self.verifier.verify(self.delegation if envelope is None else envelope, **args)

    def test_signed_delegation_pins_both_hops_route_and_ingress_generation(self):
        verified = self.verify()
        self.assertEqual(verified.ingress_identity,
            ("gateway-v1", self.payload["gateways"][0]["certificate_sha256"], GENERATION))
        self.assertTrue(verified.assert_live(self.verifier))
        self.assertEqual(DOMAIN, b"steamboat-gateway-delegation-v1\0")

    def test_describe_binding_accepts_both_schema_forms_and_still_pins_route(self):
        base = {
            "binding_version": 1,
            "operation_id": "op_" + "a" * 32,
            "account_id": ACTOR_ACCOUNT,
            "device_id": ACTOR_DEVICE,
            "role": "personal_coordinator",
            "credential_epoch": 3,
            "target_device_id": WORKER_DEVICE,
        }
        for optional in (False, True):
            fields = dict(base)
            if optional:
                fields.update(worker_boot_id=WORKER_BOOT, assignment_id=ASSIGNMENT)
            binding = encode_binding(WORKER_SERVICE, "Describe", fields)
            metadata = [(METADATA_KEY, binding)]
            envelope = self.make_delegation(
                changes={
                    "method": "Describe",
                    "binding_sha256": hashlib.sha256(binding).hexdigest(),
                }
            )
            with self.subTest(optional_worker_identity=optional):
                verified = self.verify(envelope, metadata=metadata)
                self.assertEqual(verified.payload["worker_boot_id"], WORKER_BOOT)
                self.assertTrue(verified.assert_live(self.verifier))

        mismatched = dict(base, worker_boot_id="f" * 32, assignment_id=ASSIGNMENT)
        binding = encode_binding(WORKER_SERVICE, "Describe", mismatched)
        envelope = self.make_delegation(
            changes={
                "method": "Describe",
                "binding_sha256": hashlib.sha256(binding).hexdigest(),
            }
        )
        with self.assertRaises(SecurityError):
            self.verify(envelope, metadata=[(METADATA_KEY, binding)])

    def test_exact_binding_request_tls_gateway_and_stream_sequence_are_required(self):
        bads = [
            {"metadata": [(METADATA_KEY, self.binding + b" ")]},
            {"request_bytes": self.request + b"!"},
            {"gateway_peer_certificate_pem": self.participant_ca},
            {"expected_stream_generation": "d" * 32},
            {"expected_frame_sequence": 2},
        ]
        for kwargs in bads:
            with self.subTest(kwargs=kwargs), self.assertRaises(SecurityError):
                self.verify(**kwargs)

    def test_signed_payload_must_match_pinned_policy_and_route(self):
        changes = [
            {"gateway_id": "gw-unknown"}, {"target_device_id": "dev_" + "f" * 32},
            {"worker_boot_id": "f" * 32}, {"assignment_id": "asg_" + "f" * 32},
            {"model_id": "f" * 64}, {"coordinator_boot_id": "f" * 32},
            {"tenant_account_id": "acct_" + "f" * 32},
            {"policy_revision": 2}, {"policy_digest": "f" * 64},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(SecurityError):
                self.verify(self.make_delegation(changes=change))

    def test_envelope_canonicality_signature_domain_and_key_binding(self):
        valid = self.delegation
        for raw in (valid + b" ", b"x" * 32769,
                    valid.replace(b'"version":1', b'"version":true', 1)):
            with self.subTest(length=len(raw)), self.assertRaises(SecurityError):
                self.verify(raw)
        other = generate_private_key_pem()
        with self.assertRaises(DelegationError):
            self.make_delegation(signer=other)
        envelope = json.loads(valid)
        sig = base64.b64decode(envelope["signature"])
        r, s = __import__("cryptography.hazmat.primitives.asymmetric.utils",
                          fromlist=["decode_dss_signature"]).decode_dss_signature(sig)
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        envelope["signature"] = base64.b64encode(encode_dss_signature(r, order - s)).decode()
        with self.assertRaises(SecurityError):
            self.verify(json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode())

    def test_policy_replacement_and_clock_uncertainty_widening_fail_closed(self):
        verified = self.verify()
        # A wider uncertainty moves earliest wall past issued_at, so liveness
        # rejects and clips permanently instead of restoring its former cap.
        self.wall += 0.5
        self.mono += 0.5
        self.uncertainty = 20.0
        with self.assertRaises(SecurityError):
            verified.assert_live(self.verifier)
        self.uncertainty = 0.0
        self.wall += 0.1
        self.mono += 0.1
        with self.assertRaises(SecurityError):
            verified.assert_live(self.verifier)

    def test_verify_uses_one_clock_sample_accepted_with_policy_view(self):
        replacement = copy.deepcopy(self.payload)
        replacement["revision"] = 2
        replacement["issued_at"] = int(NOW)
        replacement["expires_at"] = int(NOW + 15)
        self.view = self.policy_store.install(
            sign_channel_policy(replacement, private_pem(self.operator_key))
        )
        self.payload = replacement
        narrow = ClockSample(NOW, self.mono, 0.0, object())
        wide = ClockSample(NOW, self.mono + 0.1, 20.0, object())
        samples = iter((narrow, wide))
        envelope = self.make_delegation()
        with patch.object(self.clock, "sample", side_effect=lambda: next(samples)) as sample_clock:
            verified = self.verify(envelope)
        sample_clock.assert_called_once_with()
        self.assertGreater(verified.deadline_monotonic, self.mono)

    def test_clock_provider_fault_permanently_kills_old_verified_object(self):
        verified = self.verify()
        prior_deadline = verified.deadline_monotonic

        def broken_clock():
            raise RuntimeError("clock source unavailable")

        self.clock._uncertainty = broken_clock
        with self.assertRaises(SecurityError):
            verified.assert_live(self.verifier)
        self.assertLess(verified.deadline_monotonic, prior_deadline)
        self.assertEqual(verified.deadline_monotonic, float("-inf"))
        self.clock._uncertainty = lambda: 0.0
        self.clock.revalidate_after_resume(trusted_clock=True)
        with self.assertRaises(SecurityError):
            verified.assert_live(self.verifier)

    def test_public_deadline_tracks_monotonic_tightening_and_stays_tight(self):
        verified = self.verify()
        initial = verified.deadline_monotonic
        self.wall += 0.5
        self.mono += 0.5
        self.uncertainty = 0.5
        self.assertTrue(verified.assert_live(self.verifier))
        tightened = verified.deadline_monotonic
        self.assertLess(tightened, initial)
        self.wall += 0.1
        self.mono += 0.1
        self.uncertainty = 0.0
        self.assertTrue(verified.assert_live(self.verifier))
        self.assertLessEqual(verified.deadline_monotonic, tightened)

    def test_verified_delegation_is_bound_to_minting_verifier_and_object(self):
        verified = self.verify()
        another_verifier = GatewayDelegationVerifier(
            self.policy_store,
            clock=self.clock,
            gateway_ca_pem=self.gateway_ca,
            participant_ca_pem=self.participant_ca,
            local_identity=self.local_identity,
            endpoint_host="gateway.example.net",
            endpoint_port=443,
        )
        with self.assertRaises(SecurityError):
            verified.assert_live(another_verifier)
        fabricated = replace(verified)
        with self.assertRaises(SecurityError):
            fabricated.assert_live(self.verifier)
        self.assertTrue(verified.assert_live(self.verifier))

    def test_policy_refresh_does_not_adopt_delegation(self):
        verified = self.verify()
        replacement = copy.deepcopy(self.payload)
        replacement["revision"] = 2
        replacement["issued_at"] = int(NOW)
        self.policy_store.install(sign_channel_policy(
            replacement, private_pem(self.operator_key)))
        with self.assertRaises(SecurityError):
            verified.assert_live(self.verifier)

    def test_actor_certificate_is_not_adopted_from_another_route(self):
        replacement_key = generate_private_key_pem()
        csr = make_csr(replacement_key, account_id=ACTOR_ACCOUNT,
                       device_id=ACTOR_DEVICE, role="personal_coordinator")
        replacement = issue_leaf(self.participant_ca, self.participant_ca_key, csr,
            account_id=ACTOR_ACCOUNT, device_id=ACTOR_DEVICE,
            role="personal_coordinator", not_before=NOW - 30, not_after=NOW + 700,
            serial=0xAB16, ekus=ROLE_EKUS["personal_coordinator"])
        with self.assertRaises(SecurityError):
            self.verify(self.make_delegation(changes={
                "actor_certificate_base64": base64.b64encode(replacement).decode()}))


if __name__ == "__main__":
    unittest.main()
