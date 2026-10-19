"""Tests for the low-level, fail-closed root-generation storage primitive."""

from __future__ import annotations

import hashlib
import multiprocessing
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from steamboat_security.codec import canonical_json
from steamboat_security.errors import StorageError
from steamboat_security.root_transition_storage import (
    ARTIFACT_NAMES,
    RootGenerationSelector,
    RootGenerationStore,
    _candidate_bundle,
    _open_read_file,
    _private_file,
    parse_root_generation_selector,
    root_generation_selector_document,
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bundle(tag: str) -> dict[str, bytes]:
    return {
        "activation_manifest.json": (f'{{"manifest":"{tag}"}}').encode(),
        "policy_snapshot.json": (f'{{"policy":"{tag}"}}').encode(),
        "ca_certificate.pem": f"CA {tag}\n".encode(),
        "snapshot_signer_public.pem": f"signer {tag}\n".encode(),
    }


def _selector(tag: str, bundle: dict[str, bytes]) -> RootGenerationSelector:
    return RootGenerationSelector(
        generation_sha256=_sha(f"generation-{tag}".encode()),
        activation_manifest_sha256=_sha(bundle["activation_manifest.json"]),
        policy_revision=1 if tag == "old" else 2,
        policy_digest=_sha(f"policy-digest-{tag}".encode()),
        active_policy_snapshot_sha256=_sha(bundle["policy_snapshot.json"]),
        artifact_sha256={name: _sha(data) for name, data in bundle.items()},
    )


def _provision_initial(root: Path) -> tuple[RootGenerationSelector, dict[str, bytes], str]:
    """Create the explicit test bootstrap state, outside the production API."""
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    generations = root / "generations"
    generations.mkdir(mode=0o700)
    policies = root / "policies"
    policies.mkdir(mode=0o700)
    lock = root / "transition.lock"
    lock.touch(mode=0o600)
    os.chmod(lock, 0o600)
    bundle = _bundle("old")
    selector = _selector("old", bundle)
    policy_path = policies / f"{selector.active_policy_snapshot_sha256}.json"
    policy_path.write_bytes(bundle["policy_snapshot.json"])
    os.chmod(policy_path, 0o600)
    with policy_path.open("rb") as handle:
        os.fsync(handle.fileno())
    gen_dir = generations / selector.generation_sha256
    gen_dir.mkdir(mode=0o700)
    descriptor = {
        "schema_version": 1,
        "purpose": "root_generation_descriptor",
        "generation_sha256": selector.generation_sha256,
        "activation_manifest_sha256": selector.activation_manifest_sha256,
        "artifact_sha256": dict(selector.artifact_sha256),
    }
    files = {"descriptor.json": canonical_json(descriptor), **bundle}
    for name, contents in files.items():
        path = gen_dir / name
        path.write_bytes(contents)
        os.chmod(path, 0o600)
        with path.open("rb") as handle:
            os.fsync(handle.fileno())
    selector_bytes = canonical_json(root_generation_selector_document(selector))
    selector_path = root / "selector.json"
    selector_path.write_bytes(selector_bytes)
    os.chmod(selector_path, 0o600)
    with selector_path.open("rb") as handle:
        os.fsync(handle.fileno())
    for path in (gen_dir, generations, policies, root):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return selector, bundle, _sha(selector_bytes)


def _concurrent_commit(root, uid, old_hash, bundle, selector, start_event, output):
    try:
        if not start_event.wait(5):
            output.put(("error", "start gate timeout"))
            return
        with RootGenerationStore(root, expected_uid=uid) as store:
            result = store.commit(selector, bundle,
                                 active_policy_snapshot=bundle["policy_snapshot.json"],
                                 expected_old_selector_sha256=old_hash,
                                 validate=lambda *_: None)
        output.put(("committed", result))
    except StorageError as error:
        output.put(("rejected", type(error).__name__))
    except BaseException as error:
        output.put(("error", type(error).__name__))


class RootGenerationSelectorTests(unittest.TestCase):
    def test_selector_is_closed_canonical_and_exactly_typed(self):
        bundle = _bundle("parse")
        selector = _selector("parse", bundle)
        encoded = canonical_json(root_generation_selector_document(selector))
        parsed = parse_root_generation_selector(encoded)
        self.assertEqual(parsed, selector)
        with self.assertRaises(StorageError):
            parse_root_generation_selector(encoded[:-1] + b" ")

        raw = root_generation_selector_document(selector)
        raw["policy_revision"] = True
        with self.assertRaises(StorageError):
            parse_root_generation_selector(canonical_json(raw))

        for malformed in (
            encoded.replace(b'"policy_revision":2', b'"policy_revision":2,"policy_revision":2'),
            encoded.replace(b'"policy_revision":2', b'"policy_revision":2.0'),
        ):
            with self.assertRaises(StorageError):
                parse_root_generation_selector(malformed)

    def test_directly_constructed_selector_is_revalidated(self):
        bundle = _bundle("direct")
        good = _selector("direct", bundle)
        bad_selectors = (
            RootGenerationSelector(True, good.activation_manifest_sha256,
                                   good.policy_revision, good.policy_digest,
                                   good.active_policy_snapshot_sha256,
                                   good.artifact_sha256),
            RootGenerationSelector(good.generation_sha256, good.activation_manifest_sha256,
                                   True, good.policy_digest,
                                   good.active_policy_snapshot_sha256,
                                   good.artifact_sha256),
            RootGenerationSelector(good.generation_sha256, "F" * 64,
                                   good.policy_revision, good.policy_digest,
                                   good.active_policy_snapshot_sha256,
                                   good.artifact_sha256),
        )
        for selector in bad_selectors:
            with self.subTest(selector=selector):
                with self.assertRaises(StorageError):
                    root_generation_selector_document(selector)
                with self.assertRaises(StorageError):
                    _candidate_bundle(selector, bundle)

    def test_whitelist_has_exactly_thirteen_public_artifacts(self):
        self.assertEqual(len(ARTIFACT_NAMES), 13)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "protected fd-relative storage requires POSIX no-follow support")
class RootGenerationStoreTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name) / "root-store"
        self.old_selector, self.old_bundle, self.old_hash = _provision_initial(self.root)

    def tearDown(self):
        self._temp.cleanup()

    @staticmethod
    def _validator(_selector, _bundle, _active_policy):
        return None

    def _store(self, **kwargs):
        return RootGenerationStore(self.root, expected_uid=os.geteuid(), **kwargs)

    def test_namespace_scan_waits_for_transaction_lock_before_rejecting_temp_names(self):
        completed = threading.Event()
        outcome = []
        with self._store() as store:
            with store._lock(exclusive=True):
                fd = os.open("selector.tmp.synthetic", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             0o600, dir_fd=store._root_fd)
                os.write(fd, b"transaction temporary")
                os.close(fd)

                def read_selected():
                    try:
                        outcome.append(("ok", store.read_selected(self._validator)))
                    except BaseException as error:
                        outcome.append(("error", error))
                    finally:
                        completed.set()

                try:
                    thread = threading.Thread(target=read_selected)
                    thread.start()
                    self.assertFalse(completed.wait(timeout=0.2),
                                     "namespace scan rejected a live transaction tempfile before flock")
                finally:
                    os.unlink("selector.tmp.synthetic", dir_fd=store._root_fd)
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertEqual(outcome[0][0], "ok", repr(outcome[0][1]))

    def test_pending_entry_removed_before_flock_does_not_fail_stale_precheck(self):
        pending_check_entered = threading.Event()
        completed = threading.Event()
        outcome = []
        with self._store() as store:
            original_check = store._check_private_file

            def observe_pending_check(name, *, may_missing):
                if name == "pending.json":
                    pending_check_entered.set()
                return original_check(name, may_missing=may_missing)

            store._check_private_file = observe_pending_check
            with store._lock(exclusive=True):
                fd = os.open("pending.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             0o600, dir_fd=store._root_fd)
                os.write(fd, b"temporary pending marker")
                os.close(fd)

                def read_selected():
                    try:
                        outcome.append(("ok", store.read_selected(self._validator)))
                    except BaseException as error:
                        outcome.append(("error", error))
                    finally:
                        completed.set()

                thread = threading.Thread(target=read_selected)
                try:
                    thread.start()
                    self.assertFalse(pending_check_entered.wait(timeout=0.2),
                                     "pre-flock validation inspected a transient pending entry")
                    self.assertFalse(completed.is_set(), "reader should wait for the held root flock")
                finally:
                    os.unlink("pending.json", dir_fd=store._root_fd)
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertEqual(outcome[0][0], "ok", repr(outcome[0][1]))

    def test_commit_selects_complete_immutable_bundle(self):
        new_bundle = _bundle("new")
        new_selector = _selector("new", new_bundle)
        with self._store() as store:
            digest = store.commit(new_selector, new_bundle,
                                 active_policy_snapshot=new_bundle["policy_snapshot.json"],
                                 expected_old_selector_sha256=self.old_hash,
                                 validate=self._validator)
            selected = store.read_selected(self._validator)
        self.assertEqual(digest, _sha(canonical_json(root_generation_selector_document(new_selector))))
        self.assertEqual(selected.selector, new_selector)
        self.assertEqual(dict(selected.artifacts), new_bundle)
        self.assertEqual(set(os.listdir(self.root / "generations")),
                         {self.old_selector.generation_sha256, new_selector.generation_sha256})

    def test_validator_must_be_sync_and_return_exact_none(self):
        with self._store() as store:
            for callback in (lambda *_: True, lambda *_: 0):
                with self.assertRaises(TypeError):
                    store.read_selected(callback)

            async def asynchronous(*_):
                return None

            with self.assertRaises(TypeError):
                store.read_selected(asynchronous)

    def test_pre_marker_rejections_leave_old_selector_readable(self):
        new_bundle = _bundle("new")
        new_selector = _selector("new", new_bundle)
        altered = dict(new_bundle)
        altered["policy_snapshot.json"] = b"wrong bytes"
        with self._store() as store:
            with self.assertRaises(StorageError):
                store.commit(new_selector, altered,
                             active_policy_snapshot=altered["policy_snapshot.json"],
                             expected_old_selector_sha256=self.old_hash,
                             validate=self._validator)
            with self.assertRaises(TypeError):
                store.commit(new_selector, new_bundle,
                             active_policy_snapshot=new_bundle["policy_snapshot.json"],
                             expected_old_selector_sha256=self.old_hash,
                             validate=lambda *_: False)
            self.assertEqual(store.read_selected(self._validator).selector, self.old_selector)
        self.assertFalse((self.root / "pending.json").exists())

    def test_pending_old_selector_stays_blocked_without_rollback(self):
        new_bundle = _bundle("new")
        new_selector = _selector("new", new_bundle)

        def fail_after_marker(label):
            if label == "generation.mkdir":
                raise RuntimeError("injected after durable pending marker")

        with self._store(_fault_hook=fail_after_marker) as store:
            with self.assertRaises(RuntimeError):
                store.commit(new_selector, new_bundle,
                             active_policy_snapshot=new_bundle["policy_snapshot.json"],
                             expected_old_selector_sha256=self.old_hash,
                             validate=self._validator)
            with self.assertRaises(StorageError):
                store.read_selected(self._validator)
            with self.assertRaises(StorageError):
                store.recover_committed(validate=self._validator)
        self.assertTrue((self.root / "pending.json").exists())

    def test_exact_new_selector_pending_marker_can_be_recovered(self):
        new_bundle = _bundle("new")
        new_selector = _selector("new", new_bundle)

        def fail_on_unlink(label):
            if label == "pending.unlink":
                raise RuntimeError("leave marker after selector replacement")

        with self._store(_fault_hook=fail_on_unlink) as store:
            with self.assertRaises(RuntimeError):
                store.commit(new_selector, new_bundle,
                             active_policy_snapshot=new_bundle["policy_snapshot.json"],
                             expected_old_selector_sha256=self.old_hash,
                             validate=self._validator)
        self.assertTrue((self.root / "pending.json").exists())
        with self._store() as store:
            selected = store.recover_committed(validate=self._validator)
            self.assertEqual(dict(selected.artifacts), new_bundle)
            self.assertFalse((self.root / "pending.json").exists())

    def test_each_commit_io_boundary_fails_closed(self):
        """Faults before the marker preserve old selection; later faults block/recover."""
        new_bundle = _bundle("new")
        new_selector = _selector("new", new_bundle)
        observed = []
        with self._store(_fault_hook=observed.append) as store:
            store.commit(new_selector, new_bundle,
                         active_policy_snapshot=new_bundle["policy_snapshot.json"],
                         expected_old_selector_sha256=self.old_hash,
                         validate=self._validator)
        self.assertGreater(len(observed), 10)

        for boundary in dict.fromkeys(observed):
            with self.subTest(boundary=boundary):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary) / "store"
                    _old, _bundle_old, old_hash = _provision_initial(root)

                    def inject(label, target=boundary):
                        if label == target:
                            raise OSError("injected filesystem boundary fault")

                    with RootGenerationStore(root, expected_uid=os.geteuid(),
                                             _fault_hook=inject) as store:
                        with self.assertRaises(OSError):
                            store.commit(new_selector, new_bundle,
                                         active_policy_snapshot=new_bundle["policy_snapshot.json"],
                                         expected_old_selector_sha256=old_hash,
                                         validate=self._validator)
                    pending = (root / "pending.json").exists()
                    try:
                        store = RootGenerationStore(root, expected_uid=os.geteuid())
                    except StorageError:
                        # Residual selector.tmp.* is deliberately ambiguous and
                        # rejected by the root-name allowlist after a write fault.
                        self.assertTrue(pending or any(
                            name.startswith("selector.tmp.") for name in os.listdir(root)))
                        continue
                    with store:
                        if not pending:
                            self.assertEqual(store.read_selected(self._validator).selector,
                                             _old)
                        else:
                            with self.assertRaises(StorageError):
                                store.read_selected(self._validator)
                            selected_hash = _sha((root / "selector.json").read_bytes())
                            if selected_hash == _sha(canonical_json(
                                    root_generation_selector_document(new_selector))):
                                store.recover_committed(validate=self._validator)
                                self.assertEqual(store.read_selected(self._validator).selector,
                                                 new_selector)
                            else:
                                with self.assertRaises(StorageError):
                                    store.recover_committed(validate=self._validator)
                                self.assertTrue((root / "pending.json").exists())

    def test_concurrent_activators_share_head_and_only_one_commits(self):
        ctx = multiprocessing.get_context("fork")
        start = ctx.Event()
        output = ctx.Queue()
        candidates = []
        for tag in ("one", "two"):
            bundle = _bundle(tag)
            candidates.append((bundle, _selector(tag, bundle)))
        processes = [ctx.Process(target=_concurrent_commit,
                                 args=(str(self.root), os.geteuid(), self.old_hash,
                                       bundle, selector, start, output))
                     for bundle, selector in candidates]
        started = []
        results = None
        try:
            for process in processes:
                process.start()
                started.append(process)
            start.set()
            results = [output.get(timeout=15) for _ in processes]
            for process in started:
                process.join(timeout=15)
        finally:
            start.set()
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
                    self.fail("owned concurrent storage writer survived bounded cleanup")
        self.assertEqual(len(started), len(processes))
        self.assertIsNotNone(results)
        for process in started:
            self.assertEqual(process.exitcode, 0)
        self.assertCountEqual([kind for kind, _ in results], ["committed", "rejected"])
        with self._store() as store:
            selected = store.read_selected(self._validator)
        self.assertIn(selected.selector, [candidate[1] for candidate in candidates])
        self.assertFalse((self.root / "pending.json").exists())

    def test_same_generation_id_with_different_artifact_pins_is_rejected(self):
        changed = _bundle("changed")
        conflicted = RootGenerationSelector(
            generation_sha256=self.old_selector.generation_sha256,
            activation_manifest_sha256=_sha(changed["activation_manifest.json"]),
            policy_revision=3,
            policy_digest=_sha(b"conflicting policy"),
            active_policy_snapshot_sha256=_sha(changed["policy_snapshot.json"]),
            artifact_sha256={name: _sha(data) for name, data in changed.items()},
        )
        with self._store() as store:
            with self.assertRaises(StorageError):
                store.commit(conflicted, changed,
                             active_policy_snapshot=changed["policy_snapshot.json"],
                             expected_old_selector_sha256=self.old_hash,
                             validate=self._validator)
            self.assertEqual(store.read_selected(self._validator).selector,
                             self.old_selector)
        self.assertFalse((self.root / "pending.json").exists())

    def test_generation_capacity_and_aggregate_payload_bound(self):
        generations = self.root / "generations"
        for index in range(3):
            path = generations / _sha(f"extra-{index}".encode())
            path.mkdir(mode=0o700)
        bundle = _bundle("new")
        selector = _selector("new", bundle)
        with self._store() as store:
            with self.assertRaises(StorageError):
                store.commit(selector, bundle,
                             active_policy_snapshot=bundle["policy_snapshot.json"],
                             expected_old_selector_sha256=self.old_hash,
                             validate=self._validator)
        self.assertFalse((self.root / "pending.json").exists())

        names = sorted(ARTIFACT_NAMES)
        large_bundle = {name: b"x" * (48 * 1024) for name in names}
        large_bundle["ca_certificate.pem"] = b"c" * 100
        large_bundle["snapshot_signer_public.pem"] = b"s" * 100
        large_selector = RootGenerationSelector(
            _sha(b"large generation"), _sha(large_bundle["activation_manifest.json"]),
            9, _sha(b"large policy"), _sha(large_bundle["policy_snapshot.json"]),
            {name: _sha(data) for name, data in large_bundle.items()},
        )
        with self.assertRaises(StorageError):
            _candidate_bundle(large_selector, large_bundle)

        oversize = dict(bundle)
        oversize["ca_certificate.pem"] = b"c" * (16 * 1024 + 1)
        oversized_selector = RootGenerationSelector(
            selector.generation_sha256, _sha(oversize["activation_manifest.json"]),
            2, selector.policy_digest, _sha(oversize["policy_snapshot.json"]),
            {name: _sha(data) for name, data in oversize.items()},
        )
        with self.assertRaises(StorageError):
            _candidate_bundle(oversized_selector, oversize)

    def test_corrupt_selector_artifact_and_pending_never_fall_back(self):
        selector_path = self.root / "selector.json"
        original = selector_path.read_bytes()
        selector_path.write_bytes(b"{}")
        with self._store() as store:
            with self.assertRaises(StorageError):
                store.read_selected(self._validator)
        selector_path.write_bytes(original)

        artifact = self.root / "generations" / self.old_selector.generation_sha256 / "policy_snapshot.json"
        artifact.write_bytes(b"corrupt")
        os.chmod(artifact, 0o600)
        with self._store() as store:
            with self.assertRaises(StorageError):
                store.read_selected(self._validator)

        artifact.write_bytes(self.old_bundle["policy_snapshot.json"])
        os.chmod(artifact, 0o600)
        marker = self.root / "pending.json"
        marker.write_bytes(b"not canonical")
        os.chmod(marker, 0o600)
        with self._store() as store:
            with self.assertRaises(StorageError):
                store.read_selected(self._validator)
            with self.assertRaises(StorageError):
                store.recover_committed(validate=self._validator)

    def test_root_lock_and_selector_protection_modes_and_links(self):
        self._store().close()
        os.chmod(self.root, 0o755)
        with self.assertRaises(StorageError):
            self._store()
        os.chmod(self.root, 0o700)
        lock = self.root / "transition.lock"
        os.chmod(lock, 0o644)
        with self.assertRaises(StorageError):
            self._store()
        os.chmod(lock, 0o600)
        selector = self.root / "selector.json"
        linked = Path(self._temp.name) / "selector-copy-outside-root"
        os.link(selector, linked)
        self.assertEqual(selector.stat().st_nlink, 2)
        with self.assertRaises(StorageError):
            self._store()
        linked.unlink()

    @unittest.skipUnless(sys.platform == "linux", "requires Linux foreign-owner fixture")
    def test_baked_foreign_owner_file_guard_rejects_actual_inode(self):
        fixture = os.environ.get("STEAMBOAT_IDENTITY_FOREIGN_FIXTURE")
        if not fixture:
            self.fail("Docker-provisioned foreign-owner fixture is required")
        source = Path(fixture)
        self.assertNotEqual(source.stat().st_uid, os.geteuid())
        self.assertEqual(source.stat().st_nlink, 1)
        self.assertEqual(source.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(StorageError):
            _private_file(source.stat(), os.geteuid(), "baked foreign-owner fixture")
        parent_fd = os.open(source.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            with self.assertRaises(StorageError):
                _open_read_file(parent_fd, source.name, os.geteuid(), 128,
                                "baked foreign-owner fixture")
        finally:
            os.close(parent_fd)

    def test_symlinked_lock_is_rejected(self):
        lock = self.root / "transition.lock"
        lock.unlink()
        target = self.root / "lock-target"
        target.write_bytes(b"")
        os.chmod(target, 0o600)
        lock.symlink_to(target)
        with self.assertRaises(StorageError):
            self._store()


if __name__ == "__main__":
    unittest.main()
