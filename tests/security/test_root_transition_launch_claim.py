"""Tests for append-only, single-use cold-launch claims."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from steamboat_security.codec import canonical_json
from steamboat_security.errors import BindingError, StorageError
from steamboat_security.root_transition_launch import (
    RoleLaunchSpec,
    canonical_role_launch_digest,
    role_launch_document,
)
from steamboat_security.root_transition_launch_claim import (
    MAX_CLAIMS,
    LaunchClaimRecord,
    LaunchClaimStore,
    _check_file,
    launch_claim_document,
    parse_launch_claim,
)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _role(tag: str, *, generation=None, boot=None, epoch=1, nonce=None,
          config=None, identity_tag=None) -> RoleLaunchSpec:
    identity_tag = identity_tag or tag
    return RoleLaunchSpec(
        generation_sha256=generation or _sha(b"generation-" + tag.encode()),
        account_id="acct_" + hashlib.sha256((identity_tag + "acct").encode()).hexdigest()[:32],
        device_id="dev_" + hashlib.sha256((identity_tag + "dev").encode()).hexdigest()[:32],
        role="host",
        serial="a123456789",
        certificate_sha256=_sha(("cert-" + tag).encode()),
        public_key_sha256=_sha(("key-" + tag).encode()),
        credential_epoch=1,
        boot_id=boot or hashlib.sha256(("boot-" + tag).encode()).hexdigest()[:32],
        admission_epoch=epoch,
        configuration_sha256=config or _sha(("config-" + tag).encode()),
        launch_nonce=nonce or hashlib.sha256(("nonce-" + tag).encode()).hexdigest()[:32],
    )


def _specs(*specs):
    return tuple(sorted(specs, key=lambda spec: spec.identity))


def _claim(store, specs, *, selector=None, manifest=None, validator=None):
    return store.claim(
        selector_sha256=selector or _sha(b"selector"),
        activation_manifest_sha256=manifest or _sha(b"activation-manifest"),
        generation_sha256=specs[0].generation_sha256,
        role_launch_specs=specs,
        fresh_selected_validator=validator or (lambda *_: None),
    )


def _concurrent_claim(root, uid, specs, start_event, output):
    try:
        if not start_event.wait(5):
            output.put("start_timeout")
            return
        with LaunchClaimStore(root, expected_uid=uid) as store:
            _claim(store, specs)
        output.put("claimed")
    except BindingError:
        output.put("rejected")
    except BaseException as error:
        output.put(f"error:{type(error).__name__}")


class LaunchClaimParserTests(unittest.TestCase):
    def test_closed_canonical_exact_record_and_role_specs(self):
        role = _role("parse")
        record = LaunchClaimRecord(_sha(b"selector"), _sha(b"manifest"),
                                   _sha(canonical_json([role_launch_document(role)])),
                                   role.generation_sha256, (role,))
        encoded = canonical_json(launch_claim_document(record))
        self.assertEqual(parse_launch_claim(encoded), record)
        with self.assertRaises(StorageError):
            parse_launch_claim(encoded + b" ")
        raw = json.loads(encoded)
        raw["role_launch_specs"][0]["admission_epoch"] = True
        with self.assertRaises((BindingError, StorageError)):
            parse_launch_claim(canonical_json(raw))
        raw = json.loads(encoded)
        raw["role_launch_specs"][0]["generation_sha256"] = _sha(b"different")
        with self.assertRaises((BindingError, StorageError)):
            parse_launch_claim(canonical_json(raw))
        raw = json.loads(encoded)
        raw["role_launch_specs"][0]["admission_epoch"] = 1.0
        with self.assertRaises((BindingError, StorageError)):
            parse_launch_claim(canonical_json(raw))

    def test_invalid_claim_fields_and_hashes_reject(self):
        role = _role("invalid")
        record = LaunchClaimRecord(_sha(b"selector"), _sha(b"manifest"),
                                   canonical_role_launch_digest((role,)),
                                   role.generation_sha256, (role,))
        raw = launch_claim_document(record)
        raw["selector_sha256"] = "A" * 64
        with self.assertRaises(BindingError):
            launch_claim_document(LaunchClaimRecord(
                raw["selector_sha256"], record.activation_manifest_sha256,
                record.role_launch_digest, record.generation_sha256,
                record.role_launch_specs))
        encoded = canonical_json(launch_claim_document(record))
        with self.assertRaises(StorageError):
            parse_launch_claim(encoded.replace(b'"schema_version":1',
                                               b'"schema_version":true'))


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "launch claim durability requires POSIX no-follow support")
class LaunchClaimStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "claims"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def _store(self, **kwargs):
        return LaunchClaimStore(self.root, expected_uid=os.geteuid(), **kwargs)

    def test_claim_is_single_use_across_selector_head_changes(self):
        specs = _specs(_role("one"))
        with self._store() as store:
            receipt = _claim(store, specs)
            self.assertEqual(parse_launch_claim(
                (self.root / receipt.filename).read_bytes()), receipt.record)
            with self.assertRaises(BindingError):
                _claim(store, specs, selector=_sha(b"refreshed selector"))
        with self._store() as restarted:
            with self.assertRaises(BindingError):
                _claim(restarted, specs, selector=_sha(b"another head"))

    def test_boot_reuse_blocked_and_admission_must_advance(self):
        first = _specs(_role("first"))
        with self._store() as store:
            _claim(store, first)
            same_boot_new_generation = _specs(_role(
                "second", generation=_sha(b"new-generation"), boot=first[0].boot_id,
                epoch=2, nonce=_sha(b"fresh-nonce")[:32], identity_tag="first"))
            with self.assertRaises(BindingError):
                _claim(store, same_boot_new_generation,
                       selector=_sha(b"fresh-selector"))
            new_boot_same_epoch = _specs(_role(
                "third", generation=_sha(b"new-generation-2"), epoch=1,
                nonce=_sha(b"another-nonce")[:32], identity_tag="first"))
            with self.assertRaises(BindingError):
                _claim(store, new_boot_same_epoch,
                       selector=_sha(b"fresh-selector-2"))
            new_boot_advanced_epoch = _specs(_role(
                "fourth", generation=_sha(b"new-generation-3"), epoch=2,
                nonce=_sha(b"third-nonce")[:32], identity_tag="first"))
            receipt = _claim(store, new_boot_advanced_epoch,
                             selector=_sha(b"fresh-selector-3"))
        self.assertEqual(receipt.record.role_launch_specs, new_boot_advanced_epoch)

    def test_boot_identity_cannot_be_reused_by_a_different_principal(self):
        first = _specs(_role("principal-one"))
        with self._store() as store:
            _claim(store, first)
            other_identity_same_boot = _specs(_role(
                "principal-two", generation=_sha(b"other-generation"),
                boot=first[0].boot_id, epoch=1))
            with self.assertRaises(BindingError):
                _claim(store, other_identity_same_boot,
                       selector=_sha(b"other-selector"))

    def test_shared_process_boot_requires_same_nonce_and_configuration(self):
        generation = _sha(b"shared-process-generation")
        boot = "a" * 32
        nonce = "b" * 32
        config = _sha(b"shared-process-config")
        same_process = _specs(
            _role("shared-a", generation=generation, boot=boot, nonce=nonce,
                  config=config, identity_tag="shared-a"),
            _role("shared-b", generation=generation, boot=boot, nonce=nonce,
                  config=config, identity_tag="shared-b"),
        )
        with self._store() as store:
            _claim(store, same_process)

        invalid_boot = "d" * 32
        different_nonce = _specs(
            _role("nonce-a", generation=generation, boot=invalid_boot, nonce=nonce,
                  config=config, identity_tag="nonce-a"),
            _role("nonce-b", generation=generation, boot=invalid_boot, nonce="c" * 32,
                  config=config, identity_tag="nonce-b"),
        )
        different_config = _specs(
            _role("config-a", generation=generation, boot=invalid_boot, nonce=nonce,
                  config=config, identity_tag="config-a"),
            _role("config-b", generation=generation, boot=invalid_boot, nonce=nonce,
                  config=_sha(b"other-config"), identity_tag="config-b"),
        )
        with self._store() as store:
            for invalid in (different_nonce, different_config):
                with self.subTest(specs=invalid), self.assertRaises(BindingError):
                    _claim(store, invalid)

    def test_whole_cohort_is_validated_before_one_atomic_claim(self):
        generation = _sha(b"shared generation")
        specs = _specs(
            _role("cohort-a", generation=generation),
            _role("cohort-b", generation=generation),
        )
        calls = []
        with self._store() as store:
            with self.assertRaises(RuntimeError):
                _claim(store, specs, validator=lambda *_: (_ for _ in ()).throw(RuntimeError()))
            self.assertEqual(os.listdir(self.root), ["claim.lock"])
            receipt = _claim(store, specs, validator=lambda record, roles: calls.append((record, roles)))
        self.assertEqual(len(calls), 1)
        self.assertEqual(receipt.record.role_launch_specs, specs)

    def test_callback_contract_rejects_truthy_and_async_values_without_claim(self):
        specs = _specs(_role("callbacks"))
        with self._store() as store:
            with self.assertRaises(TypeError):
                _claim(store, specs, validator=lambda *_: True)

            async def async_validator(*_):
                return None

            with self.assertRaises(TypeError):
                _claim(store, specs, validator=async_validator)
            self.assertEqual(os.listdir(self.root), ["claim.lock"])

    def test_generation_mismatch_and_direct_bad_spec_reject(self):
        spec = _role("mismatch")
        with self._store() as store:
            with self.assertRaises(BindingError):
                store.claim(selector_sha256=_sha(b"selector"),
                            activation_manifest_sha256=_sha(b"manifest"),
                            generation_sha256=_sha(b"other generation"),
                            role_launch_specs=(spec,),
                            fresh_selected_validator=lambda *_: None)
            bad = RoleLaunchSpec(
                spec.generation_sha256, spec.account_id, spec.device_id, spec.role,
                spec.serial, spec.certificate_sha256, spec.public_key_sha256,
                True, spec.boot_id, spec.admission_epoch, spec.configuration_sha256,
                spec.launch_nonce)
            with self.assertRaises(BindingError):
                _claim(store, (bad,))

    def test_post_create_fault_consumes_claim_and_restart_fails_closed(self):
        specset = _specs(_role("fault"))
        for boundary in ("claim.write", "claim.file.fsync", "claim.root.fsync"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "claims"
                root.mkdir(mode=0o700)

                def fault(label, target=boundary):
                    if label == target:
                        raise OSError("injected claim persistence failure")

                with LaunchClaimStore(root, expected_uid=os.geteuid(),
                                      _fault_hook=fault) as store:
                    with self.assertRaises(StorageError):
                        _claim(store, specset)
                    with self.assertRaises(StorageError):
                        _claim(store, _specs(_role("later")))
                if boundary == "claim.write":
                    with self.assertRaises(StorageError):
                        LaunchClaimStore(root, expected_uid=os.geteuid())
                else:
                    with LaunchClaimStore(root, expected_uid=os.geteuid()) as restarted:
                        with self.assertRaises(BindingError):
                            _claim(restarted, specset)

    def test_pre_create_fault_does_not_consume_claim(self):
        specset = _specs(_role("pre-create"))
        fired = {"value": False}

        def fault(label):
            if label == "claim.create" and not fired["value"]:
                fired["value"] = True
                raise OSError("before exclusive file creation")

        with self._store(_fault_hook=fault) as store:
            with self.assertRaises(OSError):
                _claim(store, specset)
            self.assertEqual(set(os.listdir(self.root)), {"claim.lock"})
            receipt = _claim(store, specset)
        self.assertTrue((self.root / receipt.filename).exists())

    def test_same_plan_concurrent_processes_consume_once_and_reap_children(self):
        context = multiprocessing.get_context("fork")
        gate, output = context.Event(), context.Queue()
        specs = _specs(_role("concurrent"))
        processes = [context.Process(target=_concurrent_claim,
                                     args=(str(self.root), os.geteuid(), specs,
                                           gate, output)) for _ in range(2)]
        started, results = [], None
        try:
            for process in processes:
                process.start()
                started.append(process)
            gate.set()
            results = [output.get(timeout=15) for _ in processes]
            for process in started:
                process.join(timeout=15)
        finally:
            gate.set()
            for process in started:
                if process.is_alive():
                    process.terminate()
            for process in started:
                process.join(timeout=3)
                if process.is_alive() and hasattr(process, "kill"):
                    process.kill()
                    process.join(timeout=3)
            output.cancel_join_thread()
            output.close()
            for process in started:
                if process.exitcode is None:
                    self.fail("owned claim writer survived bounded cleanup")
        self.assertEqual(len(started), 2)
        self.assertIsNotNone(results)
        self.assertCountEqual(results, ["claimed", "rejected"])
        for process in started:
            self.assertEqual(process.exitcode, 0)

    def test_claim_count_mode_links_and_unknown_entries_fail_closed(self):
        with self._store() as store:
            _claim(store, _specs(_role("one")))
        claim_file = next(self.root.glob("claim-*.json"))
        outside_link = Path(self.temporary.name) / "outside-link"
        os.link(claim_file, outside_link)
        self.assertEqual(claim_file.stat().st_nlink, 2)
        with self.assertRaises(StorageError):
            self._store()
        with tempfile.TemporaryDirectory() as temporary:
            unsafe_root = Path(temporary) / "claims"
            unsafe_root.mkdir(mode=0o700)
            os.chmod(unsafe_root, 0o700)
            target = Path(temporary) / "outside-lock"
            target.write_bytes(b"")
            os.chmod(target, 0o600)
            (unsafe_root / "claim.lock").symlink_to(target)
            with self.assertRaises(StorageError):
                LaunchClaimStore(unsafe_root, expected_uid=os.geteuid())
        outside_link.unlink()

        os.chmod(claim_file, 0o644)
        with self.assertRaises(StorageError):
            self._store()
        os.chmod(claim_file, 0o600)
        unknown = self.root / "unexpected"
        unknown.write_bytes(b"x")
        os.chmod(unknown, 0o600)
        with self.assertRaises(StorageError):
            self._store()

    def test_root_and_lock_modes_are_exact(self):
        os.chmod(self.root, 0o755)
        with self.assertRaises(StorageError):
            self._store()
        os.chmod(self.root, 0o700)
        with self._store() as store:
            _claim(store, _specs(_role("lock-mode")))
        lock = self.root / "claim.lock"
        os.chmod(lock, 0o644)
        with self.assertRaises(StorageError):
            self._store()

    def test_claim_capacity_is_bounded(self):
        with self._store() as store:
            for index in range(MAX_CLAIMS):
                spec = _specs(_role(f"capacity-{index}", identity_tag=f"capacity-{index}"))
                _claim(store, spec)
            with self.assertRaises(StorageError):
                _claim(store, _specs(_role("capacity-overflow")))

    @unittest.skipUnless(sys.platform == "linux", "requires baked Linux foreign-owner fixture")
    def test_baked_foreign_inode_is_rejected_without_mutation(self):
        fixture = os.environ.get("STEAMBOAT_IDENTITY_FOREIGN_FIXTURE")
        if not fixture:
            self.fail("Docker-provisioned foreign-owner fixture is required")
        foreign = Path(fixture)
        self.assertNotEqual(foreign.stat().st_uid, os.geteuid())
        self.assertEqual(foreign.stat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE(foreign.stat().st_mode), 0o600)
        with self.assertRaises(StorageError):
            _check_file(foreign.stat(), os.geteuid())
