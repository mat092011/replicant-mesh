"""Internal root-bound worker entry point for the fixed native Linux lab.

The exact protected header and one host launch-spec declaration only bind a
local worker to the selected policy. This entry point does not consume the
whole-cohort launch claim and does not authorize a fresh incarnation. The
trusted cohort launcher must perform that claim/spawn/ownership protocol.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


MAX_ROLE_SPEC_INPUT_BYTES = 16 * 1024
MAX_READY_PACKET_BYTES = 16 * 1024
MAX_CONFIGURATION_HEADER_BYTES = 16 * 1024
MAX_RUNTIME_CONFIGURATION_BYTES = 16 * 1024
_READY_DOMAIN = "root_role_ready"


class RootWorkerError(RuntimeError):
    """A bounded root-worker invocation or protected input was rejected."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RootWorkerError("input contains a duplicate field")
        result[key] = value
    return result


def _reject_number(_value):
    raise RootWorkerError("input contains a non-integer numeric value")


def parse_host_launch_spec_input(encoded: bytes):
    """Parse one canonical host spec followed by exactly one newline and EOF."""
    if (type(encoded) is not bytes or not 2 <= len(encoded) <= MAX_ROLE_SPEC_INPUT_BYTES
            or not encoded.endswith(b"\n") or encoded.count(b"\n") != 1):
        raise RootWorkerError("role specification input is outside its exact framing bound")
    from steamboat_security.codec import canonical_json
    from steamboat_security.root_transition_launch import (
        parse_role_launch_spec, role_launch_document)

    try:
        raw = json.loads(encoded[:-1].decode("utf-8", errors="strict"),
                         object_pairs_hook=_pairs, parse_constant=_reject_number,
                         parse_float=_reject_number)
        if type(raw) is not list or len(raw) != 1:
            raise RootWorkerError("input must contain exactly one host role specification")
        if canonical_json(raw) != encoded[:-1]:
            raise RootWorkerError("role specification input is not canonical JSON")
        spec = parse_role_launch_spec(raw[0])
        if spec.role != "host" or canonical_json([role_launch_document(spec)]) != encoded[:-1]:
            raise RootWorkerError("input does not contain one exact host role specification")
        return spec
    except RootWorkerError:
        raise
    except Exception as error:
        raise RootWorkerError("role specification input is malformed") from error


def root_role_ready_packet(spec) -> bytes:
    """Return the fixed bounded READY frame; this function itself proves nothing."""
    from steamboat_security.codec import canonical_json
    from steamboat_security.root_transition_launch import (
        RoleLaunchSpec, parse_role_launch_spec, role_launch_document)

    if type(spec) is not RoleLaunchSpec:
        raise RootWorkerError("READY requires an exact host launch specification")
    doc = role_launch_document(spec)
    spec = parse_role_launch_spec(doc)
    if spec.role != "host":
        raise RootWorkerError("READY supports only a host role")
    packet = canonical_json({
        "schema_version": 1,
        "event": _READY_DOMAIN,
        "launch_nonce": spec.launch_nonce,
        "roles": [doc],
    }) + b"\n"
    if len(packet) > MAX_READY_PACKET_BYTES:
        raise RootWorkerError("READY packet exceeds its fixed bound")
    return packet


def _write_packet(packet: bytes) -> None:
    if type(packet) is not bytes or not 1 <= len(packet) <= MAX_READY_PACKET_BYTES:
        raise RootWorkerError("status packet exceeds its fixed bound")
    view = memoryview(packet)
    while view:
        written = os.write(sys.stdout.fileno(), view)
        if written <= 0:
            raise OSError("status output is unavailable")
        view = view[written:]


def _write_failure() -> None:
    # Never include paths, keys, prompts, exception text, or peer-controlled data.
    _write_packet(
        b'{"category":"startup_rejected","event":"root_role_startup_failed",'
        b'"schema_version":1}\n')


def _fixed_code_profile() -> None:
    """Require isolated Linux and a read-only fixed /app code mount."""
    if os.name != "posix" or sys.platform != "linux" or sys.flags.isolated != 1:
        raise RootWorkerError("fixed isolated Linux profile is required")
    app = Path("/app")
    try:
        app_info = app.lstat()
        readonly_flag = getattr(os, "ST_RDONLY", None)
        if (stat.S_ISLNK(app_info.st_mode) or not stat.S_ISDIR(app_info.st_mode)
                or type(readonly_flag) is not int or readonly_flag <= 0
                or not os.statvfs(app).f_flag & readonly_flag):
            raise RootWorkerError("fixed /app code mount is not read-only")
        trusted_files = (
            app / "lab" / "root_worker.py",
            app / "lab" / "secure_worker.py",
            app / "src" / "steamboat_security" / "root_runtime.py",
        )
        trusted_directories = (
            app / "lab",
            app / "src",
            app / "src" / "steamboat_security",
        )
        for directory in trusted_directories:
            info = directory.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise RootWorkerError("fixed /app code directory is unavailable")
            if not os.statvfs(directory).f_flag & readonly_flag:
                raise RootWorkerError("fixed /app code directory is writable")
        for source_root in (app / "lab", app / "src" / "steamboat_security"):
            for parent, directories, files in os.walk(
                    source_root, topdown=True, followlinks=False):
                parent_path = Path(parent)
                parent_info = parent_path.lstat()
                if (stat.S_ISLNK(parent_info.st_mode)
                        or not stat.S_ISDIR(parent_info.st_mode)
                        or not os.statvfs(parent_path).f_flag & readonly_flag):
                    raise RootWorkerError("fixed /app source tree is not immutable")
                for name in tuple(directories) + tuple(files):
                    child = parent_path / name
                    info = child.lstat()
                    if (stat.S_ISLNK(info.st_mode)
                            or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                            or not os.statvfs(child).f_flag & readonly_flag):
                        raise RootWorkerError("fixed /app source tree is not immutable")
        for target in trusted_files:
            info = target.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise RootWorkerError("fixed /app code source is unavailable")
            if not os.statvfs(target).f_flag & readonly_flag:
                raise RootWorkerError("fixed /app code source is writable")
    except RootWorkerError:
        raise
    except OSError as error:
        raise RootWorkerError("fixed /app code source is unavailable") from error

    # Python -I excludes ambient import paths. Reconstruct only this interpreter's
    # stdlib/site-package paths, then prepend the fixed mounted project paths.
    import sysconfig

    trusted_paths = ["/app", "/app/src"]
    for key in ("stdlib", "platstdlib", "purelib", "platlib"):
        value = sysconfig.get_path(key)
        if value and os.path.isabs(value) and value not in trusted_paths:
            trusted_paths.append(value)
    native_modules = sysconfig.get_config_var("DESTSHARED")
    if (type(native_modules) is str and os.path.isabs(native_modules)
            and native_modules not in trusted_paths):
        trusted_paths.append(native_modules)
    sys.path[:] = trusted_paths


def _read_header(path: Path, *, uid: int):
    from steamboat_security.codec import canonical_json
    from steamboat_security.files import safe_read
    from steamboat_security.root_runtime import _configuration_header, _pairs as header_pairs

    if not path.is_absolute() or ".." in path.parts:
        raise RootWorkerError("configuration header path must be absolute and normalized")
    try:
        encoded = safe_read(path, root=path.parent, expected_uid=uid,
                            max_bytes=MAX_CONFIGURATION_HEADER_BYTES)
        value = json.loads(encoded.decode("utf-8", errors="strict"),
                           object_pairs_hook=header_pairs,
                           parse_constant=_reject_number, parse_float=_reject_number)
        _configuration_header(value)
        if canonical_json(value) != encoded:
            raise RootWorkerError("configuration header is not canonical")
        return encoded, value
    except RootWorkerError:
        raise
    except Exception as error:
        raise RootWorkerError("protected configuration header was rejected") from error


def _run_root_worker(configuration_path: str, spec_input: bytes) -> int:
    """Resolve protected inputs, serve with the exact binding, and close the store."""
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise RootWorkerError("root-bound worker requires native POSIX support")
    uid = os.geteuid()
    path = Path(configuration_path)
    header_bytes, header = _read_header(path, uid=uid)
    spec = parse_host_launch_spec_input(spec_input)

    from steamboat_security.clock import Clock
    from steamboat_security.files import safe_read
    from steamboat_security.root_runtime import load_root_runtime_binding
    from steamboat_security.root_transition_storage import RootGenerationStore
    from lab.secure_worker_config import parse_config_bytes

    runtime_bytes = safe_read(
        header["runtime_configuration_path"], root=header["protected_root"],
        expected_uid=uid, max_bytes=MAX_RUNTIME_CONFIGURATION_BYTES)
    config = parse_config_bytes(runtime_bytes,
                                config_path=header["runtime_configuration_path"])
    if header["runtime_configuration_sha256"] != hashlib.sha256(runtime_bytes).hexdigest():
        raise RootWorkerError("protected runtime configuration hash differs")
    if os.path.abspath(config.status_report_path) == os.path.abspath(path):
        raise RootWorkerError("worker status output conflicts with the protected role header")
    clock = Clock.system(
        uncertainty_seconds=lambda: config.clock_uncertainty_seconds)
    root_store = RootGenerationStore(header["selected_root"], expected_uid=uid)
    try:
        binding = load_root_runtime_binding(
            root_store=root_store, clock=clock, expected_launch_spec=spec,
            configuration_path=path,
            configuration_root=path.parent, expected_uid=uid)
        if (binding.configuration_header != header_bytes
                or binding.runtime_configuration != runtime_bytes):
            raise RootWorkerError("protected root binding changed during startup")
        from lab.secure_worker import serve

        ready_emitted = False

        def emit_ready():
            nonlocal ready_emitted
            if ready_emitted:
                raise RootWorkerError("READY was already emitted for this process")
            _write_packet(root_role_ready_packet(spec))
            ready_emitted = True
            return None

        code = asyncio.run(serve(config, root_binding=binding,
                                 root_ready_callback=emit_ready))
        if type(code) is not int or not 0 <= code <= 255:
            raise RootWorkerError("worker returned an invalid exit status")
        if code != 0 and not ready_emitted:
            _write_failure()
        return code
    finally:
        root_store.close()


def _parse_arguments(argv):
    if type(argv) is not list or len(argv) != 2 or argv[0] != "--config":
        raise RootWorkerError("expected only --config and one protected header path")
    path = argv[1]
    if type(path) is not str or not Path(path).is_absolute() or ".." in Path(path).parts:
        raise RootWorkerError("configuration header path must be absolute and normalized")
    return path


def main(argv=None) -> int:
    try:
        _fixed_code_profile()
        configuration_path = _parse_arguments(sys.argv[1:] if argv is None else argv)
        spec_input = sys.stdin.buffer.read(MAX_ROLE_SPEC_INPUT_BYTES + 1)
        if len(spec_input) > MAX_ROLE_SPEC_INPUT_BYTES:
            raise RootWorkerError("role specification input exceeds its fixed byte bound")
        return _run_root_worker(configuration_path, spec_input)
    except Exception:
        try:
            _write_failure()
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
