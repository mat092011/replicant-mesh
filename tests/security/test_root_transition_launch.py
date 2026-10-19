"""Closed parsing tests for root-transition launch declarations."""

from dataclasses import replace
import unittest

from steamboat_security.errors import BindingError
from steamboat_security.root_transition_launch import (
    RoleLaunchSpec, canonical_role_launch_digest, parse_role_launch_spec,
    role_launch_document,
)


def _spec(**updates):
    values = {
        "generation_sha256": "a" * 64,
        "account_id": "acct_" + "1" * 32,
        "device_id": "dev_" + "2" * 32,
        "role": "host",
        "serial": "abc123",
        "certificate_sha256": "b" * 64,
        "public_key_sha256": "c" * 64,
        "credential_epoch": 1,
        "boot_id": "3" * 32,
        "admission_epoch": 2,
        "configuration_sha256": "d" * 64,
        "launch_nonce": "4" * 32,
    }
    values.update(updates)
    return values


class RootTransitionLaunchTests(unittest.TestCase):
    def test_round_trip_is_closed_and_digest_is_stable(self):
        parsed = parse_role_launch_spec(_spec())
        self.assertEqual(role_launch_document(parsed), _spec())
        self.assertEqual(canonical_role_launch_digest((parsed,)),
                         canonical_role_launch_digest((parsed,)))

    def test_rejects_unknown_missing_and_wrongly_typed_fields(self):
        for change in (
                {"extra": True}, {"credential_epoch": True},
                {"admission_epoch": 0}, {"generation_sha256": "A" * 64},
                {"launch_nonce": "z" * 32}, {"role": "unknown"},
                {"serial": "0"}, {"boot_id": "f" * 31}):
            raw = _spec()
            if "extra" in change:
                raw["extra"] = True
            else:
                raw.update(change)
            with self.subTest(change=change), self.assertRaises(BindingError):
                parse_role_launch_spec(raw)
        raw = _spec()
        del raw["serial"]
        with self.assertRaises(BindingError):
            parse_role_launch_spec(raw)

    def test_digest_requires_sorted_unique_exact_tuple(self):
        first = parse_role_launch_spec(_spec())
        second = parse_role_launch_spec(_spec(device_id="dev_" + "5" * 32))
        ordered = tuple(sorted((first, second), key=lambda item: item.identity))
        canonical_role_launch_digest(ordered)
        with self.assertRaises(BindingError):
            canonical_role_launch_digest((second, first))
        with self.assertRaises(BindingError):
            canonical_role_launch_digest((first, first))
        with self.assertRaises(BindingError):
            canonical_role_launch_digest([first])

    def test_document_revalidates_exact_dataclass(self):
        with self.assertRaises(BindingError):
            role_launch_document(object())
        for malformed in (
                replace(parse_role_launch_spec(_spec()), credential_epoch=True),
                replace(parse_role_launch_spec(_spec()), role="invalid"),
                replace(parse_role_launch_spec(_spec()), generation_sha256="x" * 64)):
            with self.assertRaises(BindingError):
                role_launch_document(malformed)
            with self.assertRaises(BindingError):
                canonical_role_launch_digest((malformed,))


if __name__ == "__main__":
    unittest.main()
