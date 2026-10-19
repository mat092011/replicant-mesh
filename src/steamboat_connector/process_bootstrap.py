"""Private stdlib-only child bootstrap for fixed connector role processes."""

import importlib
import os
import sys


ROLE_MODULES = {
    "host": "steamboat_connector.role_worker",
    "coordinator": "steamboat_connector.role_coordinator",
}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3:
        return 64
    role, config_path, gate_text = argv
    module_name = ROLE_MODULES.get(role)
    if module_name is None or not config_path.startswith("/"):
        return 64
    try:
        gate_fd = int(gate_text)
        if gate_fd < 0:
            return 64
    except ValueError:
        return 64

    # The parent attaches this still-blocked process to its delegated cgroup
    # before writing the single release byte.
    try:
        release = os.read(gate_fd, 1)
    finally:
        os.close(gate_fd)
    if release != b"R":
        return 65

    module = importlib.import_module(module_name)
    # start() must return only after the role has loaded and is actually ready.
    role_service = module.start(config_path)
    run = getattr(role_service, "run", None)
    if not callable(run):
        return 66
    sys.stdout.write("READY\n")
    sys.stdout.flush()
    # Runtime diagnostics never flow into the protocol pipe. stderr is already
    # discarded by the parent; this also contains native writes to fd 1.
    null_fd = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(null_fd, 1)
    finally:
        if null_fd != 1:
            os.close(null_fd)
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
