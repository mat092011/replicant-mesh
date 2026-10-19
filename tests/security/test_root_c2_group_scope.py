import base64
import json
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from steamboat_security.certificates import public_key_sha256
from steamboat_security.clock import Clock
from steamboat_security.codec import canonical_json
from steamboat_security.errors import SnapshotError
from steamboat_security.root_c2_group_scope import (
    MAX_SCOPE_BYTES, POLICY_DOMAIN, PROFILE, parse_c2_host_group_scope,
    parse_c2_host_group_scope_bytes, sign_c2_host_group_policy,
    validate_c2_scope_expectations, verify_c2_host_group_policy,
)


def scope_doc():
    return {
        "version": 1, "profile": PROFILE, "account_id": "acct_" + "1"*32,
        "device_id": "dev_" + "2"*32, "role": "host",
        "credential": {"serial": "a1", "credential_epoch": 2,
            "certificate_sha256": "a"*64, "public_key_sha256": "b"*64},
        "generation_sha256": "c"*64, "admission_epoch": 3,
        "parent_boot_id": "4"*32, "model_id": "d"*64,
        "catalog_sha256": "e"*64, "catalog_public_key_sha256": "f"*64,
        "operator_public_key_sha256": "0"*64,
        "components": [{"component": "worker-1", "worker_boot_id": "5"*32,
            "assignment_id": "asg_"+"6"*32, "assignment_sha256": "7"*64,
            "channel_certificate_sha256": "8"*64, "channel_public_key_sha256": "9"*64}],
    }


def policy_key():
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, private, public


def FakeClock(wall=100.0, mono=20.0):
    state = {"wall": wall, "mono": mono}
    clock = Clock(wall=lambda: state["wall"], monotonic=lambda: state["mono"],
        uncertainty_seconds=lambda: 0.0)
    clock._test_state = state
    return clock


class RootC2GroupScopeTests(unittest.TestCase):
    def test_scope_round_trip_and_deep_immutability(self):
        raw = scope_doc()
        encoded = canonical_json(raw)
        parsed = parse_c2_host_group_scope_bytes(encoded)
        raw["components"][0]["worker_boot_id"] = "a"*32
        self.assertEqual(parsed.components[0].worker_boot_id, "5"*32)
        with self.assertRaises((AttributeError, TypeError)):
            parsed.components[0].worker_boot_id = "a"*32
        with self.assertRaises(AttributeError):
            parsed.components += ()

    def test_closed_types_and_duplicate_identity_guards(self):
        for field, bad in (("profile", "other"), ("role", "consumer"),
                ("version", True), ("admission_epoch", True),
                ("generation_sha256", "C"*64)):
            raw = scope_doc(); raw[field] = bad
            with self.subTest(field=field), self.assertRaises(SnapshotError):
                parse_c2_host_group_scope(raw)
        raw = scope_doc(); raw["components"].append(dict(raw["components"][0]))
        with self.assertRaises(SnapshotError): parse_c2_host_group_scope(raw)

    def test_component_order_boot_assignment_parent_and_bounds(self):
        raw = scope_doc(); raw["components"].append({**raw["components"][0],
            "component":"worker-2", "worker_boot_id":"4"*32})
        raw["components"].sort(key=lambda x: x["component"])
        with self.assertRaises(SnapshotError): parse_c2_host_group_scope(raw)
        raw = scope_doc(); raw["components"][0]["assignment_id"] = "bad"
        with self.assertRaises(SnapshotError): parse_c2_host_group_scope(raw)
        with self.assertRaises(SnapshotError): parse_c2_host_group_scope_bytes(b" "*(MAX_SCOPE_BYTES+1))

    def test_canonical_duplicate_and_unknown_json_rejected(self):
        with self.assertRaises(SnapshotError):
            parse_c2_host_group_scope_bytes(b'{"a":1,"a":1}')
        encoded = canonical_json(scope_doc())
        with self.assertRaises(SnapshotError): parse_c2_host_group_scope_bytes(encoded+b" ")
        raw = scope_doc(); raw["resource_limit"] = 7
        with self.assertRaises(SnapshotError): parse_c2_host_group_scope(raw)

    def test_trusted_expectations_and_forbidden_boots(self):
        scope = parse_c2_host_group_scope(scope_doc())
        args = dict(account_id=scope.account_id, device_id=scope.device_id,
            credential_serial=scope.credential.serial, credential_epoch=2,
            certificate_sha256="a"*64, public_key_sha256="b"*64,
            parent_boot_id="4"*32, generation_sha256="c"*64, admission_epoch=3)
        self.assertIs(validate_c2_scope_expectations(scope, **args), scope)
        for key, val in (("generation_sha256", "0"*64), ("admission_epoch", 4),
                         ("account_id", "acct_"+"0"*32)):
            changed = dict(args); changed[key] = val
            with self.subTest(key=key), self.assertRaises(SnapshotError):
                validate_c2_scope_expectations(scope, **changed)
        with self.assertRaises(SnapshotError):
            validate_c2_scope_expectations(scope, **args, forbidden_worker_boot_ids=["5"*32])

    def test_signed_policy_signature_key_pin_lifetime_and_deadline(self):
        key, private, public = policy_key()
        raw = scope_doc(); raw["operator_public_key_sha256"] = public_key_sha256(key.public_key())
        payload = {"version":1,"issued_at":95,"expires_at":200,"scope":raw}
        encoded = sign_c2_host_group_policy(payload, private)
        clock = FakeClock()
        verified = verify_c2_host_group_policy(encoded, public, clock=clock)
        self.assertEqual(verified.scope.account_id, raw["account_id"])
        self.assertEqual(verified.deadline_monotonic, 120.0)
        for edit in (lambda p: p.update(expires_at=396),
                     lambda p: p["scope"].update(operator_public_key_sha256="a"*64)):
            bad = json.loads(json.dumps(payload)); edit(bad)
            with self.assertRaises(SnapshotError): sign_c2_host_group_policy(bad, private)
        wrong_key, _, wrong_public = policy_key()
        with self.assertRaises(SnapshotError): verify_c2_host_group_policy(encoded, wrong_public, clock=FakeClock())

    def test_signature_envelope_mutation_and_noncanonical_rejected(self):
        key, private, public = policy_key()
        raw = scope_doc(); raw["operator_public_key_sha256"] = public_key_sha256(key.public_key())
        payload = {"version":1,"issued_at":95,"expires_at":200,"scope":raw}
        encoded = sign_c2_host_group_policy(payload, private)
        envelope = json.loads(encoded); envelope["signature"] = base64.b64encode(b"x"*64).decode()
        with self.assertRaises(SnapshotError): verify_c2_host_group_policy(canonical_json(envelope), public, clock=FakeClock())
        with self.assertRaises(SnapshotError): verify_c2_host_group_policy(encoded+b" ", public, clock=FakeClock())
        self.assertEqual(POLICY_DOMAIN, b"steamboat-c2-host-group-policy-v1\0")

    def test_clock_expiry_and_rollback_fail_closed(self):
        key, private, public = policy_key()
        raw = scope_doc(); raw["operator_public_key_sha256"] = public_key_sha256(key.public_key())
        payload = {"version":1,"issued_at":95,"expires_at":200,"scope":raw}
        encoded = sign_c2_host_group_policy(payload, private)
        with self.assertRaises(SnapshotError): verify_c2_host_group_policy(encoded, public, clock=FakeClock(200))
        clock = FakeClock(); verify_c2_host_group_policy(encoded, public, clock=clock)
        clock._test_state["wall"] = 99
        with self.assertRaises(Exception): verify_c2_host_group_policy(encoded, public, clock=clock)


if __name__ == "__main__":
    unittest.main()
