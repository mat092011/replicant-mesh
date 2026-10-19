"""Fixed-profile entry point for one root-bound local CPU coordinator."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys


MAX_ROLE_SPEC_INPUT_BYTES = 16 * 1024
MAX_CONFIGURATION_HEADER_BYTES = 16 * 1024
MAX_RUNTIME_CONFIGURATION_BYTES = 16 * 1024
MAX_READY_PACKET_BYTES = 16 * 1024
_RETAINED_ROOT_STORES = []
_READY_EMITTED = False


class RootCoordinatorError(RuntimeError):
    """A bounded coordinator invocation or protected input was rejected."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RootCoordinatorError("input contains a duplicate field")
        result[key] = value
    return result


def _reject_number(_value):
    raise RootCoordinatorError("input contains a non-integer numeric value")


def parse_coordinator_launch_spec_input(encoded: bytes):
    """Parse one canonical coordinator spec, newline, and EOF."""
    if (type(encoded) is not bytes or not 2 <= len(encoded) <= MAX_ROLE_SPEC_INPUT_BYTES
            or not encoded.endswith(b"\n") or encoded.count(b"\n") != 1):
        raise RootCoordinatorError("role specification input is outside its framing bound")
    from steamboat_security.codec import canonical_json
    from steamboat_security.root_transition_launch import (
        parse_role_launch_spec, role_launch_document)

    try:
        raw = json.loads(encoded[:-1].decode("utf-8", errors="strict"),
                         object_pairs_hook=_pairs, parse_constant=_reject_number,
                         parse_float=_reject_number)
        if type(raw) is not list or len(raw) != 1 or canonical_json(raw) != encoded[:-1]:
            raise RootCoordinatorError("input must contain one canonical coordinator role")
        spec = parse_role_launch_spec(raw[0])
        if (spec.role != "personal_coordinator"
                or canonical_json([role_launch_document(spec)]) != encoded[:-1]):
            raise RootCoordinatorError("input is not one exact coordinator specification")
        return spec
    except RootCoordinatorError:
        raise
    except Exception as error:
        raise RootCoordinatorError("coordinator role input is malformed") from error


def root_coordinator_ready_packet(spec) -> bytes:
    """Build the fixed READY frame; it is emitted only by the runtime callback."""
    from steamboat_security.codec import canonical_json
    from steamboat_security.root_transition_launch import (
        RoleLaunchSpec, parse_role_launch_spec, role_launch_document)

    if type(spec) is not RoleLaunchSpec:
        raise RootCoordinatorError("READY requires an exact coordinator specification")
    document = role_launch_document(spec)
    spec = parse_role_launch_spec(document)
    if spec.role != "personal_coordinator":
        raise RootCoordinatorError("READY supports only the coordinator role")
    packet = canonical_json({
        "schema_version": 1, "event": "root_role_ready",
        "launch_nonce": spec.launch_nonce, "roles": [document],
    }) + b"\n"
    if len(packet) > MAX_READY_PACKET_BYTES:
        raise RootCoordinatorError("READY packet exceeds its fixed bound")
    return packet


def _write_packet(packet: bytes) -> None:
    if type(packet) is not bytes or not 1 <= len(packet) <= MAX_READY_PACKET_BYTES:
        raise RootCoordinatorError("status packet exceeds its fixed bound")
    view = memoryview(packet)
    while view:
        count = os.write(sys.stdout.fileno(), view)
        if count <= 0:
            raise OSError("status output is unavailable")
        view = view[count:]


def _write_failure() -> None:
    _write_packet(
        b'{"category":"startup_rejected","event":"root_coordinator_startup_failed",'
        b'"schema_version":1}\n')


def _fixed_code_profile() -> None:
    """Require the fixed isolated Linux interpreter and immutable /app code."""
    if os.name != "posix" or sys.platform != "linux" or sys.flags.isolated != 1:
        raise RootCoordinatorError("fixed isolated Linux profile is required")
    app = Path("/app")
    try:
        info = app.lstat()
        readonly = getattr(os, "ST_RDONLY", None)
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                or type(readonly) is not int or readonly <= 0
                or not os.statvfs(app).f_flag & readonly):
            raise RootCoordinatorError("fixed /app code mount is not read-only")
        directories = (app / "lab", app / "src", app / "src" / "steamboat_security")
        for directory in directories:
            item = directory.lstat()
            if (stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode)
                    or not os.statvfs(directory).f_flag & readonly):
                raise RootCoordinatorError("fixed coordinator code directory is unavailable")
        for source in (app / "lab", app / "src" / "steamboat_security"):
            for parent, children, files in os.walk(source, topdown=True, followlinks=False):
                parent_path = Path(parent)
                parent_info = parent_path.lstat()
                if (stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode)
                        or not os.statvfs(parent_path).f_flag & readonly):
                    raise RootCoordinatorError("fixed coordinator code is not immutable")
                for name in tuple(children) + tuple(files):
                    child = parent_path / name
                    child_info = child.lstat()
                    if (stat.S_ISLNK(child_info.st_mode)
                            or not (stat.S_ISDIR(child_info.st_mode)
                                    or stat.S_ISREG(child_info.st_mode))
                            or not os.statvfs(child).f_flag & readonly):
                        raise RootCoordinatorError("fixed coordinator code is not immutable")
        for path in (app / "lab" / "root_coordinator.py",
                     app / "lab" / "root_coordinator_runtime.py",
                     app / "lab" / "root_coordinator_config.py",
                     app / "src" / "steamboat_security" / "root_runtime.py"):
            item = path.lstat()
            if (stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode)
                    or not os.statvfs(path).f_flag & readonly):
                raise RootCoordinatorError("fixed coordinator source is unavailable")
    except RootCoordinatorError:
        raise
    except OSError as error:
        raise RootCoordinatorError("fixed coordinator code is unavailable") from error

    import sysconfig
    paths = ["/app", "/app/src"]
    for key in ("stdlib", "platstdlib", "purelib", "platlib"):
        value = sysconfig.get_path(key)
        if value and os.path.isabs(value) and value not in paths:
            paths.append(value)
    native = sysconfig.get_config_var("DESTSHARED")
    if type(native) is str and os.path.isabs(native) and native not in paths:
        paths.append(native)
    sys.path[:] = paths


def _parse_arguments(argv):
    if type(argv) is not list or len(argv) != 2 or argv[0] != "--config":
        raise RootCoordinatorError("expected only --config and one protected header path")
    value = argv[1]
    if (type(value) is not str or not Path(value).is_absolute()
            or ".." in Path(value).parts or os.path.abspath(value) != value):
        raise RootCoordinatorError("configuration header path must be absolute and normalized")
    return value


def _check_status_path(config, header_path):
    status = os.path.normcase(os.path.abspath(config.status_report_path))
    header = os.path.normcase(os.path.abspath(os.fspath(header_path)))
    if status == header:
        raise RootCoordinatorError("status output conflicts with the protected role header")


def _read_header(path: Path, uid: int):
    from steamboat_security.codec import canonical_json
    from steamboat_security.files import safe_read
    from steamboat_security.root_runtime import _configuration_header

    try:
        raw = safe_read(path, root=path.parent, expected_uid=uid,
                        max_bytes=MAX_CONFIGURATION_HEADER_BYTES)
        value = json.loads(raw.decode("utf-8", errors="strict"),
                           object_pairs_hook=_pairs, parse_constant=_reject_number,
                           parse_float=_reject_number)
        _configuration_header(value)
        if canonical_json(value) != raw:
            raise RootCoordinatorError("configuration header is not canonical")
        return raw, value
    except RootCoordinatorError:
        raise
    except Exception as error:
        raise RootCoordinatorError("protected coordinator header was rejected") from error


def _signal_stop_handlers(loop, stop_event, hold_event):
    """First signal requests graceful stop; a second releases a fenced process."""
    count = {"signals": 0}

    def request_stop():
        count["signals"] += 1
        if count["signals"] == 1:
            stop_event.set()
        else:
            hold_event.set()

    installed = []
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, request_stop)
            installed.append(signum)
    except BaseException:
        for signum in installed:
            loop.remove_signal_handler(signum)
        raise
    return tuple(installed)


def _ready_callback(spec, stop_event, state):
    def emit_ready():
        nonlocal state
        global _READY_EMITTED
        if stop_event.is_set():
            raise RootCoordinatorError("shutdown was requested before coordinator readiness")
        if state["emitted"]:
            raise RootCoordinatorError("coordinator READY was already emitted")
        _write_packet(root_coordinator_ready_packet(spec))
        state["emitted"] = True
        _READY_EMITTED = True
        return None
    return emit_ready


async def _serve_bound_coordinator(configuration_path: str, spec_input: bytes) -> int:
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise RootCoordinatorError("root coordinator requires native POSIX protected files")
    uid = os.geteuid()
    header_path = Path(configuration_path)
    if not header_path.is_absolute() or ".." in header_path.parts:
        raise RootCoordinatorError("configuration header path must be normalized")
    header_bytes, header = _read_header(header_path, uid)
    spec = parse_coordinator_launch_spec_input(spec_input)
    if (spec.account_id != header["account_id"] or spec.device_id != header["device_id"]
            or spec.boot_id != header["boot_id"] or spec.role != header["role"]):
        raise RootCoordinatorError("coordinator declaration differs from protected header")

    from steamboat_security.clock import Clock
    from steamboat_security.files import safe_read
    from steamboat_security.root_runtime import load_root_runtime_binding
    from steamboat_security.root_transition_storage import RootGenerationStore
    from lab.root_coordinator_config import parse_config_bytes
    from lab.root_coordinator_runtime import serve

    runtime_bytes = safe_read(
        header["runtime_configuration_path"], root=header["protected_root"],
        expected_uid=uid, max_bytes=MAX_RUNTIME_CONFIGURATION_BYTES)
    if hashlib.sha256(runtime_bytes).hexdigest() != header["runtime_configuration_sha256"]:
        raise RootCoordinatorError("protected coordinator runtime hash differs")
    config = parse_config_bytes(runtime_bytes,
                                config_path=header["runtime_configuration_path"],
                                protected_root=header["protected_root"])
    _check_status_path(config, header_path)
    clock = Clock.system(uncertainty_seconds=lambda: config.clock_uncertainty_seconds)
    root_store = RootGenerationStore(header["selected_root"], expected_uid=uid)
    loop = asyncio.get_running_loop()
    stop_event, hold_event = asyncio.Event(), asyncio.Event()
    handlers = ()
    try:
        handlers = _signal_stop_handlers(loop, stop_event, hold_event)
        binding = load_root_runtime_binding(
            root_store=root_store, clock=clock, expected_launch_spec=spec,
            configuration_path=header_path, configuration_root=header_path.parent,
            expected_uid=uid)
        if (binding.configuration_header != header_bytes
                or binding.runtime_configuration != runtime_bytes):
            raise RootCoordinatorError("protected coordinator binding changed during startup")
        ready_state = {"emitted": False}
        emit_ready = _ready_callback(spec, stop_event, ready_state)
        await serve(config, root_binding=binding, root_ready_callback=emit_ready,
                    stop_event=stop_event)
        return 0
    except BaseException:
        from lab import root_coordinator_runtime as runtime
        unresolved = bool(runtime._RETAINED_UNKNOWN_OWNERS or runtime._RETAINED_CLEANUP_TASKS)
        if unresolved:
            # Keep the selected-root lock/store and runtime owner registry alive
            # until the process supervisor confirms physical process exit.
            _RETAINED_ROOT_STORES.append(root_store)
            await hold_event.wait()
        raise
    finally:
        for signum in handlers:
            loop.remove_signal_handler(signum)
        if root_store not in _RETAINED_ROOT_STORES:
            root_store.close()


def _run(configuration_path: str, spec_input: bytes) -> int:
    return asyncio.run(_serve_bound_coordinator(configuration_path, spec_input))


def main(argv=None) -> int:
    global _READY_EMITTED
    _READY_EMITTED = False
    try:
        _fixed_code_profile()
        configuration_path = _parse_arguments(sys.argv[1:] if argv is None else argv)
        spec_input = sys.stdin.buffer.read(MAX_ROLE_SPEC_INPUT_BYTES + 1)
        if len(spec_input) > MAX_ROLE_SPEC_INPUT_BYTES:
            raise RootCoordinatorError("role specification input exceeds its bound")
        return _run(configuration_path, spec_input)
    except Exception:
        if not _READY_EMITTED:
            try:
                _write_failure()
            except Exception:
                pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
