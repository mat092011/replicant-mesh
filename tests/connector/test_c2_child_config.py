"""Contracts and real selected-root checks for C2 fixed child config."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from dataclasses import replace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives import serialization

from steamboat_connector.c2_child_config import (
    C2ChildConfig, MAX_C2_CHILD_CONFIG_BYTES, MAX_OPERATOR_PUBLIC_KEY_BYTES,
    build_c2_child_config, open_c2_child_binding, parse_c2_child_config,
)
from steamboat_security.certificates import generate_private_key_pem
from steamboat_security.clock import Clock
from steamboat_security.codec import canonical_json
from steamboat_security.errors import CredentialError, SnapshotError
from steamboat_security.root_transition_storage import RootGenerationStore
import tests.security.test_root_c2_runtime as host_fixture
import tests.security.test_root_c2_coordinator as coordinator_fixture


def _public_key(private_pem=None):
    private_pem = private_pem or generate_private_key_pem()
    key = serialization.load_pem_private_key(private_pem, password=None)
    return key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def _host_config(fx, **overrides):
    values = {
        "role": "host", "selected_root": str(fx.root),
        "protected_root": str(fx.protected),
        "configuration_path": str(fx.header_path),
        "launch_spec": fx.host_spec,
        "operator_verification_key_pem": fx.operator_public,
    }
    values.update(overrides)
    return build_c2_child_config(**values)


class C2ChildConfigContractTests(unittest.TestCase):
    def setUp(self):
        # A structurally valid, selected-shaped spec is enough for pure schema tests.
        from steamboat_security.root_transition_launch import RoleLaunchSpec
        self.spec = RoleLaunchSpec("a"*64, "acct_"+"1"*32, "dev_"+"2"*32,
            "host", "1a", "b"*64, "c"*64, 1, "d"*32, 1, "e"*64, "f"*32)
        self.key = _public_key()

    def make_host(self, **changes):
        values = {"role": "host", "selected_root": "/protected/selected",
            "protected_root": "/protected", "configuration_path": "/protected/role.json",
            "launch_spec": self.spec, "operator_verification_key_pem": self.key}
        values.update(changes)
        return build_c2_child_config(**values)

    def test_host_round_trips_canonical_bytes_with_full_spec_and_public_key(self):
        document = self.make_host()
        encoded = canonical_json(document)
        parsed = parse_c2_child_config(encoded)
        self.assertEqual(parsed.role, "host")
        self.assertEqual(parsed.launch_spec, self.spec)
        self.assertEqual(parsed.operator_verification_key_pem, self.key)
        self.assertEqual(canonical_json(parsed.to_document()), encoded)
        self.assertLessEqual(len(encoded), MAX_C2_CHILD_CONFIG_BYTES)

    def test_coordinator_requires_exact_role_and_null_operator_key(self):
        from steamboat_security.root_transition_launch import RoleLaunchSpec
        coordinator = replace(self.spec, role="personal_coordinator")
        document = build_c2_child_config(role="coordinator",
            selected_root="/protected/selected", protected_root="/protected",
            configuration_path="/protected/coordinator.json", launch_spec=coordinator)
        self.assertIsNone(parse_c2_child_config(document).operator_verification_key_pem)
        with self.assertRaisesRegex(CredentialError, "must not carry"):
            build_c2_child_config(role="coordinator", selected_root="/protected/selected",
                protected_root="/protected", configuration_path="/protected/coordinator.json",
                launch_spec=coordinator, operator_verification_key_pem=self.key)
        with self.assertRaisesRegex(CredentialError, "differs"):
            self.make_host(launch_spec=coordinator)

    def test_closed_schema_exact_types_paths_and_canonical_json(self):
        good = self.make_host()
        for change, message in (
            ({"unexpected": 1}, "unknown or missing"),
            ({"version": True}, "version"),
            ({"selected_root": "relative"}, "absolute POSIX"),
            ({"protected_root": "/protected/../escape"}, "absolute POSIX"),
            ({"configuration_path": "/protected/role.json\x00"}, "invalid"),
            ({"configuration_path": "/elsewhere/role.json"}, "outside"),
            ({"operator_verification_key_pem": 7}, "PEM text"),
        ):
            value = dict(good)
            value.update(change)
            with self.subTest(change=change), self.assertRaisesRegex(CredentialError, message):
                parse_c2_child_config(value)
        duplicate = canonical_json(good)[:-1] + b',"version":2}'
        with self.assertRaisesRegex(CredentialError, "duplicate"):
            parse_c2_child_config(duplicate)
        with self.assertRaisesRegex(CredentialError, "canonical"):
            parse_c2_child_config(canonical_json(good) + b" ")

    def test_size_pem_and_public_key_algorithm_bounds(self):
        with self.assertRaisesRegex(CredentialError, "16 KiB"):
            parse_c2_child_config(b" " * (MAX_C2_CHILD_CONFIG_BYTES + 1))
        with self.assertRaisesRegex(CredentialError, "4 KiB"):
            self.make_host(operator_verification_key_pem=b"x" *
                           (MAX_OPERATOR_PUBLIC_KEY_BYTES + 1))
        with self.assertRaisesRegex(CredentialError, "P-256"):
            self.make_host(operator_verification_key_pem=b"not a public key")
        with self.assertRaisesRegex(CredentialError, "ASCII"):
            self.make_host(operator_verification_key_pem=b"\xff")
        # The accepted bytes must be exactly a canonical public SPKI PEM; the
        # PEM loader alone can ignore material appended after a valid key.
        with self.assertRaisesRegex(CredentialError, "exactly one canonical public key"):
            self.make_host(operator_verification_key_pem=(
                self.key + generate_private_key_pem()))
        with self.assertRaisesRegex(CredentialError, "exactly one canonical public key"):
            self.make_host(operator_verification_key_pem=b"\n" + self.key)

    def test_config_is_inert_and_import_does_not_load_torch(self):
        code = ("import sys; sys.path.insert(0, " + repr(str(ROOT / "src")) + "); "
                "import steamboat_connector.c2_child_config; "
                "assert 'torch' not in sys.modules; print('stdlib-security-only')")
        result = subprocess.run([sys.executable, "-I", "-c", code],
            check=True, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.stdout.strip(), "stdlib-security-only")


@unittest.skipUnless(os.name == "posix", "selected root fixtures require POSIX protected files")
class C2ChildBindingIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        host_fixture.C2RuntimeStoreIntegrationTests.setUpClass()
        coordinator_fixture.C2CoordinatorStoreIntegrationTests.setUpClass()

    def setUp(self):
        self.fx_case = host_fixture.C2RuntimeStoreIntegrationTests(
            "test_real_binding_guards_three_components_and_durably_advances_policy")
        self.fx_case.setUp()
        self.fx = self.fx_case

    def tearDown(self):
        self.fx_case.tearDown()

    def test_real_host_root_loads_signed_group_and_retains_store_until_close(self):
        child = open_c2_child_binding(parse_c2_child_config(_host_config(self.fx)),
            clock=self.fx.clock, expected_uid=os.geteuid())
        with child.borrow() as binding:
            self.assertEqual(binding.host_identity.boot_id, self.fx.host_spec.boot_id)
            self.assertEqual(tuple(item.component for item in binding.components),
                             ("worker-1", "worker-2", "worker-3"))
        descriptors = (child._root_store._root_fd, child._root_store._generations_fd,
                      child._root_store._policies_fd)
        self.assertTrue(all(os.fstat(fd) for fd in descriptors))
        child.assert_live()
        child.close()
        self.assertEqual(child._root_store._root_fd, -1)
        with self.assertRaises(CredentialError):
            with child.borrow():
                pass
        child.close()  # Idempotent close does not reopen or replace authority.

    def test_wrong_operator_key_and_changed_selected_spec_fail_with_store_closed(self):
        config = parse_c2_child_config(_host_config(self.fx,
            operator_verification_key_pem=_public_key()))
        real_close = RootGenerationStore.close
        closed = []
        def record_close(store):
            closed.append(store)
            return real_close(store)
        with patch.object(RootGenerationStore, "close", record_close):
            with self.assertRaises((CredentialError, SnapshotError)):
                open_c2_child_binding(config, clock=self.fx.clock,
                                      expected_uid=os.geteuid())
        self.assertEqual(len(closed), 1)
        self.assertEqual(closed[0]._root_fd, -1)

        changed_spec = replace(self.fx.host_spec, boot_id="0"*32)
        changed = parse_c2_child_config(_host_config(self.fx, launch_spec=changed_spec))
        with self.assertRaises((CredentialError, SnapshotError)):
            open_c2_child_binding(changed, clock=self.fx.clock,
                                  expected_uid=os.geteuid())

    def test_changed_header_and_wrong_protected_root_are_rejected(self):
        config = parse_c2_child_config(_host_config(self.fx))
        original = self.fx.header_path.read_bytes()
        self.fx._private(self.fx.header_path, original + b" ")
        try:
            with self.assertRaises((CredentialError, SnapshotError)):
                open_c2_child_binding(config, clock=self.fx.clock,
                                      expected_uid=os.geteuid())
        finally:
            self.fx._private(self.fx.header_path, original)
        wrong_root = parse_c2_child_config(_host_config(self.fx,
            protected_root=str(self.fx.protected.parent)))
        with self.assertRaises((CredentialError, SnapshotError, OSError)):
            open_c2_child_binding(wrong_root, clock=self.fx.clock,
                                  expected_uid=os.geteuid())

    def test_teardown_callback_can_close_owner_without_deadlock(self):
        child = open_c2_child_binding(parse_c2_child_config(_host_config(self.fx)),
            clock=self.fx.clock, expected_uid=os.geteuid())
        with child.borrow() as binding:
            binding.subscribe_teardown(lambda _reason: child.close())
        child.close()
        self.assertEqual(child._root_store._root_fd, -1)
        child.close()

    def test_close_during_borrowed_guard_keeps_root_fds_until_lease_exits(self):
        child = open_c2_child_binding(parse_c2_child_config(_host_config(self.fx)),
            clock=self.fx.clock, expected_uid=os.geteuid())
        entered, proceed = threading.Event(), threading.Event()
        outcome = []
        with child.borrow() as binding:
            binding_type = type(binding)
            original_guard = binding_type.assert_live

        def blocked_guard(instance):
            entered.set()
            if not proceed.wait(5):
                raise AssertionError("guard barrier timed out")
            return original_guard(instance)

        def guarded_use():
            try:
                with child.borrow() as borrowed:
                    borrowed.assert_live()
            except BaseException as error:
                outcome.append(error)

        with patch.object(binding_type, "assert_live", blocked_guard):
            worker = threading.Thread(target=guarded_use)
            worker.start()
            self.assertTrue(entered.wait(5), "borrowed guard did not reach barrier")
            root_fd = child._root_store._root_fd
            child.close()  # Must return while the guarded borrow remains active.
            os.fstat(root_fd)
            other_fd = os.open(os.devnull, os.O_RDONLY)
            try:
                self.assertNotEqual(other_fd, root_fd)
            finally:
                os.close(other_fd)
            proceed.set()
            worker.join(5)
            self.assertFalse(worker.is_alive(), "borrowed guard did not finish")
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], CredentialError)
        self.assertEqual(child._root_store._root_fd, -1)

    def test_real_coordinator_root_loads_with_no_operator_key(self):
        coordinator_case = coordinator_fixture.C2CoordinatorStoreIntegrationTests(
            "test_real_selected_coordinator_guard_and_same_head_cas_reconcile")
        coordinator_case.setUp()
        try:
            fx = coordinator_case.fx
            document = build_c2_child_config(role="coordinator",
                selected_root=str(fx.root), protected_root=str(fx.protected),
                configuration_path=str(fx.coordinator_header_path),
                launch_spec=fx.coordinator_spec)
            child = open_c2_child_binding(parse_c2_child_config(document),
                clock=fx.clock, expected_uid=os.geteuid())
            try:
                self.assertEqual(child.binding.local_identity.boot_id,
                                 fx.coordinator_spec.boot_id)
                child.assert_live()
            finally:
                child.close()
        finally:
            coordinator_case.tearDown()
