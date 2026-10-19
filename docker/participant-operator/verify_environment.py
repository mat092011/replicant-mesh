from __future__ import annotations

import argparse
import importlib
import platform
from pathlib import Path
import struct
import sys
import sysconfig


EXPECTED_PYTHON = {(3, 12), (3, 14)}
EXPECTED_PLATFORMS = {"Windows", "Linux"}
EXPECTED_MACHINES = {"amd64", "x86_64"}
EXPECTED_MODULES = (
    ("paramiko", "paramiko", "3.5.1"),
    ("bcrypt", "bcrypt", "4.3.0"),
    ("nacl", "PyNaCl", "1.5.0"),
    ("cryptography", "cryptography", "50.0.2"),
    ("cffi", "cffi", "2.1.1"),
    ("pycparser", "pycparser", "3.11"),
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify the isolated participant operator Python environment.")
    parser.add_argument(
        "--root", type=Path,
        help="require all six imported modules to reside inside this install root")
    return parser


def _is_beneath(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if sys.implementation.name != "cpython":
        print("unsupported interpreter: CPython is required", file=sys.stderr)
        return 1
    if sys.version_info[:2] not in EXPECTED_PYTHON:
        print("unsupported Python version: CPython 3.12 or 3.14 is required",
              file=sys.stderr)
        return 1
    if sysconfig.get_config_var("Py_GIL_DISABLED"):
        print("unsupported interpreter build: free-threaded CPython is not supported",
              file=sys.stderr)
        return 1
    if (platform.system() not in EXPECTED_PLATFORMS
            or platform.machine().lower() not in EXPECTED_MACHINES
            or struct.calcsize("P") != 8):
        print("unsupported platform: 64-bit Windows or Linux x86_64 is required",
              file=sys.stderr)
        return 1

    root = None
    if args.root is not None:
        try:
            root = args.root.resolve(strict=True)
        except (OSError, RuntimeError):
            print("install root does not exist", file=sys.stderr)
            return 1
        if not root.is_dir():
            print("install root must be a directory", file=sys.stderr)
            return 1

    failures = []
    for module_name, distribution, expected_version in EXPECTED_MODULES:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            failures.append(f"{distribution}: import failed")
            continue
        version = getattr(module, "__version__", None)
        if version != expected_version:
            failures.append(
                f"{distribution}: expected {expected_version}, found {version!r}")
        module_file = getattr(module, "__file__", None)
        if type(module_file) is not str:
            failures.append(f"{distribution}: module has no file path")
        elif root is not None:
            try:
                resolved_file = Path(module_file).resolve(strict=True)
            except (OSError, RuntimeError):
                failures.append(f"{distribution}: module path cannot be resolved")
            else:
                if not _is_beneath(resolved_file, root):
                    failures.append(f"{distribution}: imported outside requested root")

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("operator environment OK: pinned SSH/SFTP dependencies and platform verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
