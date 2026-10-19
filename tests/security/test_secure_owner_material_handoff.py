from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import unittest
from unittest import mock

from lab import secure_owner_material_handoff as handoff
from lab.secure_cohort_owner import (
    MAX_ARCHIVE_BYTES,
    MAX_INTENT_BYTES,
    MAX_SNAPSHOT_BYTES,
    OWNER_MATERIAL_NAMES,
    PROFILE_C1B_OWNER_REMOVE,
    OwnerExpectation,
    OwnerProtocolError,
    validate_owner_material_archive,
    validate_owner_materials_ready,
)


def _expectation():
    return OwnerExpectation(
        profile=PROFILE_C1B_OWNER_REMOVE,
        run_id="1" * 32,
        nonce="2" * 32,
        worker_boot_id="3" * 32,
        manifest_fingerprint="4" * 64,
        endpoint="127.0.0.1:50061",
        initial_snapshot_sha256="5" * 64,
        initial_revision=7,
    )


def _files():
    return {
        "install-snapshot.json": b"install snapshot\n",
        "remove-snapshot.json": b"remove snapshot\n",
        "install-intent.json": b"install intent\n",
        "removal-intent.json": b"removal intent\n",
    }


def _wrapper(files):
    return {
        "schema_version": 1,
        "event": "owner_materials_ready",
        "profile": PROFILE_C1B_OWNER_REMOVE,
        "run_id": "1" * 32,
        "nonce": "2" * 32,
        "worker_boot_id": "3" * 32,
        "files": {
            name: {"size": len(files[name]),
                   "sha256": hashlib.sha256(files[name]).hexdigest()}
            for name in OWNER_MATERIAL_NAMES
        },
    }


def _rewrite_checksum(raw, header_offset=0):
    changed = bytearray(raw)
    header = bytearray(changed[header_offset:header_offset + 512])
    header[148:156] = b"        "
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\x00 ".encode("ascii")
    changed[header_offset:header_offset + 512] = header
    return bytes(changed)


class OwnerMaterialArchiveBuilderTests(unittest.TestCase):
    def test_builder_archive_passes_the_existing_shared_parser(self):
        files = _files()
        expected = _expectation()
        wrapper = validate_owner_materials_ready(_wrapper(files), expected)
        encoded = handoff.build_owner_material_archive(files)
        self.assertEqual(len(encoded) % 512, 0)
        self.assertLessEqual(len(encoded), MAX_ARCHIVE_BYTES)
        self.assertEqual(validate_owner_material_archive(encoded, wrapper, expected), files)

    def test_builder_uses_the_shared_fixed_order_and_exact_file_bounds(self):
        files = _files()
        encoded = handoff.build_owner_material_archive(files)
        offsets = []
        offset = 0
        for name in OWNER_MATERIAL_NAMES:
            header = encoded[offset:offset + 512]
            offsets.append(encoded[offset:offset + 100].split(b"\x00", 1)[0].decode())
            self.assertEqual(int(header[100:108].rstrip(b"\x00 "), 8), 0o600)
            self.assertEqual(int(header[108:116].rstrip(b"\x00 "), 8), 1000)
            self.assertEqual(int(header[116:124].rstrip(b"\x00 "), 8), 1000)
            self.assertEqual(int(header[136:148].rstrip(b"\x00 "), 8), 0)
            self.assertEqual(header[156:157], b"0")
            self.assertEqual(header[157:257], bytes(100))
            self.assertEqual(header[257:263], b"ustar\x00")
            self.assertEqual(header[263:265], b"00")
            self.assertEqual(header[265:500], bytes(235))
            size = len(files[name])
            offset += 512 + ((size + 511) // 512) * 512
        self.assertEqual(offsets, list(OWNER_MATERIAL_NAMES))
        self.assertEqual(encoded[offset:offset + 1024], bytes(1024))

    def test_builder_rejects_wrong_maps_types_and_per_file_oversize(self):
        files = _files()
        for invalid in (
                {}, dict(files, extra=b"x"),
                {name: bytearray(value) for name, value in files.items()},
                {**files, "install-snapshot.json": b""},
                {**files, "install-snapshot.json": b"x" * (MAX_SNAPSHOT_BYTES + 1)},
                {**files, "install-intent.json": b"x" * (MAX_INTENT_BYTES + 1)}):
            with self.subTest(keys=tuple(invalid)):
                with self.assertRaises(handoff.OwnerMaterialHandoffError):
                    handoff.build_owner_material_archive(invalid)
        with self.assertRaises(handoff.OwnerMaterialHandoffError):
            handoff.build_owner_material_archive(list(files.items()))

    def test_existing_parser_rejects_reordered_and_non_strict_ustar_records(self):
        files = _files()
        expected = _expectation()
        wrapper = _wrapper(files)
        encoded = handoff.build_owner_material_archive(files)

        reordered = bytearray(encoded)
        reordered[0:100] = (OWNER_MATERIAL_NAMES[1].encode()
                            + bytes(100 - len(OWNER_MATERIAL_NAMES[1])))
        malformed = _rewrite_checksum(reordered)
        with self.assertRaises(OwnerProtocolError):
            validate_owner_material_archive(malformed, wrapper, expected)

        wrong_uid = bytearray(encoded)
        wrong_uid[108:116] = b"0001751\x00"
        malformed = _rewrite_checksum(wrong_uid)
        with self.assertRaises(OwnerProtocolError):
            validate_owner_material_archive(malformed, wrapper, expected)

        linked = bytearray(encoded)
        linked[156:157] = b"2"
        malformed = _rewrite_checksum(linked)
        with self.assertRaises(OwnerProtocolError):
            validate_owner_material_archive(malformed, wrapper, expected)


@unittest.skipUnless(os.name == "posix", "requires POSIX descriptor-relative file operations")
class OwnerMaterialHandoffPosixTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.chmod(self.tempdir.name, 0o700)
        self.dir_fd = os.open(self.tempdir.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.encoded = handoff.build_owner_material_archive(_files())

    def tearDown(self):
        if self.dir_fd is not None:
            os.close(self.dir_fd)
        self.tempdir.cleanup()

    def _create_named(self, data=b"archive", mode=0o600):
        fd = os.open(handoff.OWNER_MATERIALS_ARCHIVE_BASENAME,
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode,
                     dir_fd=self.dir_fd)
        try:
            view = memoryview(data)
            offset = 0
            while offset < len(view):
                offset += os.write(fd, view[offset:])
        finally:
            os.close(fd)

    def test_roundtrip_receipt_reports_actual_bounded_readback(self):
        receipt = handoff.write_owner_material_archive(self.dir_fd, self.encoded)
        self.assertEqual(receipt, {
            "size": len(self.encoded),
            "sha256": hashlib.sha256(self.encoded).hexdigest(),
        })
        self.assertEqual(handoff.read_owner_material_archive(self.dir_fd), self.encoded)

    def test_writer_is_exclusive_and_preserves_existing_contents(self):
        self._create_named(b"keep me")
        with self.assertRaises(handoff.OwnerMaterialHandoffError):
            handoff.write_owner_material_archive(self.dir_fd, self.encoded)
        self.assertEqual(handoff.read_owner_material_archive(self.dir_fd), b"keep me")
        fd = os.open(handoff.OWNER_MATERIALS_ARCHIVE_BASENAME,
                     os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.dir_fd)
        try:
            self.assertEqual(os.read(fd, 16), b"keep me")
        finally:
            os.close(fd)

    def test_descriptor_validation_rejects_bool_non_directory_and_unsafe_mode(self):
        with self.assertRaises(handoff.OwnerMaterialHandoffError):
            handoff.read_owner_material_archive(True)
        with self.assertRaises(handoff.OwnerMaterialHandoffError):
            handoff.write_owner_material_archive(self.dir_fd, b"x" * 511)
        file_fd = os.open(__file__, os.O_RDONLY)
        try:
            with self.assertRaises(handoff.OwnerMaterialHandoffError):
                handoff.read_owner_material_archive(file_fd)
        finally:
            os.close(file_fd)
        unsafe = tempfile.TemporaryDirectory()
        try:
            os.chmod(unsafe.name, 0o755)
            unsafe_fd = os.open(unsafe.name, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(handoff.OwnerMaterialHandoffError):
                    handoff.write_owner_material_archive(unsafe_fd, self.encoded)
            finally:
                os.close(unsafe_fd)
        finally:
            unsafe.cleanup()

    def test_raw_transport_bytes_still_require_pinned_archive_validation(self):
        raw = b"x" * 512
        receipt = handoff.write_owner_material_archive(self.dir_fd, raw)
        self.assertEqual(receipt, {
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
        self.assertEqual(handoff.read_owner_material_archive(self.dir_fd), raw)

        files = _files()
        expected = _expectation()
        wrapper = validate_owner_materials_ready(_wrapper(files), expected)
        with self.assertRaises(OwnerProtocolError):
            validate_owner_material_archive(raw, wrapper, expected)

    def test_reader_rejects_symlink_fifo_hardlink_and_wrong_mode(self):
        target = os.path.join(self.tempdir.name, "target")
        with open(target, "wb") as stream:
            stream.write(b"safe target")
        os.symlink(target, os.path.join(self.tempdir.name,
                                        handoff.OWNER_MATERIALS_ARCHIVE_BASENAME))
        with self.assertRaises(handoff.OwnerMaterialHandoffError):
            handoff.read_owner_material_archive(self.dir_fd)
        os.unlink(os.path.join(self.tempdir.name, handoff.OWNER_MATERIALS_ARCHIVE_BASENAME))

        os.mkfifo(os.path.join(self.tempdir.name, handoff.OWNER_MATERIALS_ARCHIVE_BASENAME),
                  0o600)
        with self.assertRaises(handoff.OwnerMaterialHandoffError):
            handoff.read_owner_material_archive(self.dir_fd)
        os.unlink(os.path.join(self.tempdir.name, handoff.OWNER_MATERIALS_ARCHIVE_BASENAME))

        self._create_named(self.encoded)
        os.link(handoff.OWNER_MATERIALS_ARCHIVE_BASENAME,
                "archive-hardlink", src_dir_fd=self.dir_fd, dst_dir_fd=self.dir_fd)
        with self.assertRaises(handoff.OwnerMaterialHandoffError):
            handoff.read_owner_material_archive(self.dir_fd)
        os.unlink("archive-hardlink", dir_fd=self.dir_fd)
        os.chmod(os.path.join(self.tempdir.name, handoff.OWNER_MATERIALS_ARCHIVE_BASENAME),
                 0o640)
        with self.assertRaises(handoff.OwnerMaterialHandoffError):
            handoff.read_owner_material_archive(self.dir_fd)

    def test_writer_and_reader_reject_oversize_files(self):
        with self.assertRaises(handoff.OwnerMaterialHandoffError):
            handoff.write_owner_material_archive(
                self.dir_fd, b"x" * (MAX_ARCHIVE_BYTES + 512))
        self._create_named(b"x" * (MAX_ARCHIVE_BYTES + 512))
        with self.assertRaises(handoff.OwnerMaterialHandoffError):
            handoff.read_owner_material_archive(self.dir_fd)

    def test_post_create_fsync_failures_preserve_archive(self):
        for fail_on in (1, 2):
            with self.subTest(fail_on=fail_on):
                if os.path.exists(os.path.join(
                        self.tempdir.name, handoff.OWNER_MATERIALS_ARCHIVE_BASENAME)):
                    os.unlink(os.path.join(
                        self.tempdir.name, handoff.OWNER_MATERIALS_ARCHIVE_BASENAME))
                calls = {"count": 0}

                def fsync(_fd):
                    calls["count"] += 1
                    if calls["count"] == fail_on:
                        raise OSError("injected fsync failure")

                with mock.patch.object(handoff.os, "fsync", side_effect=fsync):
                    with self.assertRaises(handoff.OwnerMaterialHandoffError):
                        handoff.write_owner_material_archive(self.dir_fd, self.encoded)
                info = os.stat(handoff.OWNER_MATERIALS_ARCHIVE_BASENAME,
                               dir_fd=self.dir_fd, follow_symlinks=False)
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(info.st_size, len(self.encoded))
                self.assertEqual(
                    handoff.read_owner_material_archive(self.dir_fd), self.encoded)


if __name__ == "__main__":
    unittest.main()
