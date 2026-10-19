import argparse
import json
import sys

from .client import LocalManagementClient
from .daemon import run_daemon
from .errors import ConnectorError
from .paths import default_runtime_directory, default_state_directory
from .storage import StorageError
from .validation import MAX_JSON_BYTES, strict_json_loads


def _parser():
    parser = argparse.ArgumentParser(prog="steamboat-connector")
    parser.add_argument("--runtime-dir", default=None)
    parser.add_argument("--state-dir", default=None)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("daemon", help="run the headless Linux AF_UNIX daemon")
    commands.add_parser("status")
    commands.add_parser("diagnostics")
    policy = commands.add_parser("policy")
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    policy_commands.add_parser("show")
    policy_commands.add_parser("set", help="read a bounded version-1 policy JSON document from stdin")
    role = commands.add_parser("role")
    role_commands = role.add_subparsers(dest="role_command", required=True)
    for name in ("enable", "disable"):
        item = role_commands.add_parser(name)
        item.add_argument("role", choices=("consumer", "host", "coordinator"))
    start = commands.add_parser("start")
    start.add_argument("roles", nargs="*", choices=("consumer", "host", "coordinator"))
    drain = commands.add_parser("drain")
    drain.add_argument("roles", nargs="*", choices=("consumer", "host", "coordinator"))
    drain.add_argument("--deadline-seconds", type=int, default=30)
    stop = commands.add_parser("stop")
    stop.add_argument("roles", nargs="*", choices=("consumer", "host", "coordinator"))
    remove = commands.add_parser("remove")
    remove.add_argument("--delete-owned-data", action="store_true")
    operation = commands.add_parser("operation")
    operation.add_argument("operation_id")
    return parser


def _emit(value):
    sys.stdout.write(json.dumps(value, ensure_ascii=False, allow_nan=False,
                                sort_keys=True, indent=2) + "\n")


def main(argv=None):
    args = _parser().parse_args(argv)
    runtime_directory = args.runtime_dir or default_runtime_directory()
    state_directory = args.state_dir or default_state_directory()
    if args.command == "daemon":
        try:
            return run_daemon(runtime_directory=runtime_directory,
                              state_directory=state_directory)
        except (StorageError, OSError):
            _emit({"error": {"code": "DAEMON_START_FAILED",
                              "message": "Linux daemon could not start with the requested private paths"}})
            return 2
    try:
        client = LocalManagementClient(runtime_directory)
        if args.command == "status":
            result = client.status()
        elif args.command == "diagnostics":
            result = client.diagnostics()
        elif args.command == "policy":
            if args.policy_command == "show":
                result = client.get_policy()
            else:
                data = sys.stdin.buffer.read(MAX_JSON_BYTES + 1)
                policy = strict_json_loads(data)
                result = client.set_policy(policy)
        elif args.command == "role":
            method = client.enable_role if args.role_command == "enable" else client.disable_role
            result = method(args.role)
        elif args.command == "start":
            result = client.start(args.roles or None)
        elif args.command == "drain":
            result = client.drain(args.roles or None,
                                  deadline_seconds=args.deadline_seconds)
        elif args.command == "stop":
            result = client.stop(args.roles or None)
        elif args.command == "remove":
            result = client.remove(delete_owned_data=args.delete_owned_data)
        else:
            result = client.operation(args.operation_id)
        _emit(result)
        return 0
    except ConnectorError as error:
        _emit({"error": {"code": error.code, "message": error.message}})
        return 2
    except (ValueError, UnicodeError):
        _emit({"error": {"code": "INVALID_ARGUMENT",
                          "message": "management input is invalid or exceeds its bound"}})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
