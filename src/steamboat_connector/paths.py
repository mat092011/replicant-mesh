import os
from pathlib import Path


APP_DIRECTORY = "steamboat-participant"


def default_runtime_directory():
    runtime_root = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_root:
        return Path(runtime_root) / APP_DIRECTORY
    return Path.home() / ".local" / "run" / APP_DIRECTORY


def default_state_directory():
    state_root = os.environ.get("XDG_STATE_HOME")
    if state_root:
        return Path(state_root) / APP_DIRECTORY
    return Path.home() / ".local" / "state" / APP_DIRECTORY


def socket_path(runtime_directory):
    return Path(runtime_directory) / "control.sock"


def token_path(runtime_directory):
    return Path(runtime_directory) / "boot.token"
