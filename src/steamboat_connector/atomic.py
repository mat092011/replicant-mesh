"""Small fail-closed Linux atomic publication primitive for owned directories."""

import ctypes
import errno
import os
import sys


RENAME_NOREPLACE = 1


class AtomicPublishConflict(FileExistsError):
    pass


def _basename(value):
    if (type(value) is not str or not value or value in {".", ".."}
            or "/" in value or "\\" in value or "\0" in value):
        raise ValueError("atomic publication requires a single safe directory name")
    return os.fsencode(value)


def publish_directory_noreplace(parent_fd, source_name, destination_name):
    if not sys.platform.startswith("linux"):
        raise OSError(errno.ENOSYS, "atomic no-replace publication requires Linux")
    if type(parent_fd) is not int or parent_fd < 0:
        raise ValueError("atomic publication requires an open parent directory descriptor")
    source = _basename(source_name)
    destination = _basename(destination_name)
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError) as error:
        raise OSError(errno.ENOSYS, "libc renameat2 is unavailable") from error
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    if renameat2(parent_fd, source, parent_fd, destination, RENAME_NOREPLACE) == 0:
        return
    error_number = ctypes.get_errno()
    message = os.strerror(error_number)
    if error_number == errno.EEXIST:
        raise AtomicPublishConflict(error_number, message, destination_name)
    raise OSError(error_number, message, destination_name)
