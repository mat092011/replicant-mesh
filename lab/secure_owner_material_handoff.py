"""Bounded fixed-name handoff for the public C1b owner materials archive."""

from __future__ import annotations

import hashlib
import os
import stat

from lab.secure_cohort_owner import (
    MAX_ARCHIVE_BYTES,
    MAX_INTENT_BYTES,
    MAX_MATERIAL_BYTES,
    MAX_SNAPSHOT_BYTES,
    OWNER_MATERIAL_NAMES,
)


OWNER_MATERIALS_ARCHIVE_BASENAME = "owner-materials.tar"
_MATERIAL_LIMITS = {
    "install-snapshot.json": MAX_SNAPSHOT_BYTES,
    "remove-snapshot.json": MAX_SNAPSHOT_BYTES,
    "install-intent.json": MAX_INTENT_BYTES,
    "removal-intent.json": MAX_INTENT_BYTES,
}
_BLOCK_BYTES = 512
_TERMINATOR_BYTES = 1024
_MAX_MATERIAL_TOTAL = MAX_MATERIAL_BYTES


class OwnerMaterialHandoffError(ValueError):
    """The fixed owner-material handoff is invalid or could not be verified."""


def _require_posix_dirfd(directory_fd):
    if os.name != "posix":
        raise OwnerMaterialHandoffError("owner material handoff requires POSIX")
    required_flags = ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required_flags):
        raise OwnerMaterialHandoffError("required POSIX no-follow flags are unavailable")
    if (os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd
            or os.stat not in os.supports_follow_symlinks or not hasattr(os, "fchmod")):
        raise OwnerMaterialHandoffError("POSIX descriptor-relative file access is unavailable")
    if type(directory_fd) is not int or directory_fd < 0:
        raise OwnerMaterialHandoffError("handoff directory descriptor is invalid")
    try:
        info = os.fstat(directory_fd)
    except OSError:
        raise OwnerMaterialHandoffError("handoff directory descriptor cannot be inspected") from None
    if (not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.geteuid()
            or info.st_gid != os.getegid()):
        raise OwnerMaterialHandoffError("handoff directory ownership or mode is unsafe")
    return info


def _octal(value, width):
    encoded = (f"{value:0{width - 1}o}".encode("ascii") + b"\x00")
    if len(encoded) != width:
        raise OwnerMaterialHandoffError("owner material TAR numeric field overflow")
    return encoded


def _tar_header(name, size):
    try:
        name_bytes = name.encode("ascii")
    except UnicodeEncodeError:
        raise OwnerMaterialHandoffError("owner material TAR name is not ASCII") from None
    if not 1 <= len(name_bytes) < 100:
        raise OwnerMaterialHandoffError("owner material TAR name exceeds its fixed field")
    header = bytearray(_BLOCK_BYTES)
    header[0:100] = name_bytes + bytes(100 - len(name_bytes))
    header[100:108] = _octal(0o600, 8)
    header[108:116] = _octal(1000, 8)
    header[116:124] = _octal(1000, 8)
    header[124:136] = _octal(size, 12)
    header[136:148] = _octal(0, 12)
    header[148:156] = b"        "
    header[156:157] = b"0"
    header[257:263] = b"ustar\x00"
    header[263:265] = b"00"
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\x00 ".encode("ascii")
    return bytes(header)


def build_owner_material_archive(files):
    """Build the four fixed public material files as strict deterministic USTAR."""
    if type(files) is not dict or set(files) != set(OWNER_MATERIAL_NAMES):
        raise OwnerMaterialHandoffError("owner material file map is not the fixed four-name set")
    total = 0
    chunks = []
    for name in OWNER_MATERIAL_NAMES:
        raw = files[name]
        if type(raw) is not bytes or not 1 <= len(raw) <= _MATERIAL_LIMITS[name]:
            raise OwnerMaterialHandoffError("owner material bytes exceed their fixed file bound")
        total += len(raw)
        padding = (-len(raw)) % _BLOCK_BYTES
        chunks.extend((_tar_header(name, len(raw)), raw, bytes(padding)))
    if total > _MAX_MATERIAL_TOTAL:
        raise OwnerMaterialHandoffError("owner material bytes exceed their aggregate bound")
    chunks.append(bytes(_TERMINATOR_BYTES))
    archive = b"".join(chunks)
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise OwnerMaterialHandoffError("owner material TAR exceeds its archive bound")
    return archive


def _metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _validate_regular_file(info):
    if (not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid()
            or info.st_gid != os.getegid()
            or info.st_nlink != 1):
        raise OwnerMaterialHandoffError("owner material archive file ownership or type is unsafe")


def _named_info(directory_fd):
    try:
        return os.stat(OWNER_MATERIALS_ARCHIVE_BASENAME,
                       dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        raise OwnerMaterialHandoffError("owner material archive name cannot be inspected") from None


def _write_all(fd, raw):
    view = memoryview(raw)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except OSError:
            raise OwnerMaterialHandoffError("owner material archive write failed after creation") from None
        if type(written) is not int or written <= 0:
            raise OwnerMaterialHandoffError("owner material archive write made no progress")
        offset += written


def _read_bounded(fd):
    chunks = []
    total = 0
    while total <= MAX_ARCHIVE_BYTES:
        try:
            chunk = os.read(fd, min(64 * 1024, MAX_ARCHIVE_BYTES + 1 - total))
        except OSError:
            raise OwnerMaterialHandoffError("owner material archive readback failed") from None
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > MAX_ARCHIVE_BYTES:
        raise OwnerMaterialHandoffError("owner material archive exceeds its read bound")
    return b"".join(chunks)


def write_owner_material_archive(handoff_fd, encoded):
    """Exclusively store bounded, block-aligned bytes and return their receipt.

    This is protected transport I/O, not TAR validation. Callers must supply
    bytes from the trusted builder and validate archive semantics against the
    pinned wrapper and expectation before publication.
    """
    _require_posix_dirfd(handoff_fd)
    if (type(encoded) is not bytes or not 1 <= len(encoded) <= MAX_ARCHIVE_BYTES
            or len(encoded) % _BLOCK_BYTES != 0):
        raise OwnerMaterialHandoffError("owner material TAR is outside its fixed byte bound")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        archive_fd = os.open(OWNER_MATERIALS_ARCHIVE_BASENAME, flags, 0o600,
                             dir_fd=handoff_fd)
    except OSError:
        raise OwnerMaterialHandoffError("owner material archive cannot be created exclusively") from None
    try:
        try:
            os.fchmod(archive_fd, 0o600)
            before = os.fstat(archive_fd)
            _validate_regular_file(before)
            if before.st_size != 0:
                raise OwnerMaterialHandoffError("new owner material archive is not empty")
            named = _named_info(handoff_fd)
            _validate_regular_file(named)
            if (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino):
                raise OwnerMaterialHandoffError("owner material archive name changed during creation")
            _write_all(archive_fd, encoded)
            os.fsync(archive_fd)
            written_info = os.fstat(archive_fd)
            _validate_regular_file(written_info)
            if written_info.st_size != len(encoded):
                raise OwnerMaterialHandoffError("owner material archive size changed during write")
            os.lseek(archive_fd, 0, os.SEEK_SET)
            readback = _read_bounded(archive_fd)
            if readback != encoded:
                raise OwnerMaterialHandoffError("owner material archive readback differs from input")
            after = os.fstat(archive_fd)
            named_after = _named_info(handoff_fd)
            _validate_regular_file(after)
            _validate_regular_file(named_after)
            if (_metadata(written_info) != _metadata(after)
                    or (after.st_dev, after.st_ino) != (named_after.st_dev, named_after.st_ino)
                    or len(readback) != after.st_size):
                raise OwnerMaterialHandoffError("owner material archive metadata changed after write")
            os.fsync(handoff_fd)
            return {"size": len(readback), "sha256": hashlib.sha256(readback).hexdigest()}
        except OwnerMaterialHandoffError:
            raise
        except OSError:
            raise OwnerMaterialHandoffError(
                "owner material archive verification failed after creation") from None
    finally:
        try:
            os.close(archive_fd)
        except OSError:
            raise OwnerMaterialHandoffError("owner material archive close outcome is uncertain") from None


def read_owner_material_archive(handoff_fd):
    """Return bounded raw bytes with no-follow and stable-inode checks.

    The result still requires semantic validation by
    ``validate_owner_material_archive`` against its pinned wrapper and
    expectation before publication.
    """
    _require_posix_dirfd(handoff_fd)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        archive_fd = os.open(OWNER_MATERIALS_ARCHIVE_BASENAME, flags,
                             dir_fd=handoff_fd)
    except OSError:
        raise OwnerMaterialHandoffError("owner material archive cannot be opened safely") from None
    try:
        try:
            before = os.fstat(archive_fd)
            _validate_regular_file(before)
            if not 1 <= before.st_size <= MAX_ARCHIVE_BYTES:
                raise OwnerMaterialHandoffError("owner material archive size is outside its bound")
            named_before = _named_info(handoff_fd)
            _validate_regular_file(named_before)
            if ((before.st_dev, before.st_ino) != (named_before.st_dev, named_before.st_ino)
                    or _metadata(before) != _metadata(named_before)):
                raise OwnerMaterialHandoffError("owner material archive name changed before read")
            raw = _read_bounded(archive_fd)
            after = os.fstat(archive_fd)
            named_after = _named_info(handoff_fd)
            _validate_regular_file(after)
            _validate_regular_file(named_after)
            if (len(raw) != before.st_size
                    or _metadata(before) != _metadata(after)
                    or _metadata(after) != _metadata(named_after)):
                raise OwnerMaterialHandoffError("owner material archive changed during read")
            return raw
        except OwnerMaterialHandoffError:
            raise
        except OSError:
            raise OwnerMaterialHandoffError("owner material archive read failed") from None
    finally:
        try:
            os.close(archive_fd)
        except OSError:
            raise OwnerMaterialHandoffError("owner material archive close outcome is uncertain") from None
