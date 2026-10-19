import copy

from .policy import ROLE_NAMES, validate_policy
from .validation import valid_typed_id


OPERATION_STATES = {"queued", "running", "succeeded", "blocked", "incomplete",
                    "failed", "interrupted"}
OPERATION_ACTIONS = {"start", "drain", "stop", "remove", "policy.set",
                     "role.enable", "role.disable"}


def initial_state():
    return {
        "version": 1,
        "boot_id": None,
        "roles": {role: False for role in ROLE_NAMES},
        "paused_roles": {role: False for role in ROLE_NAMES},
        "removed": False,
        "revocation_pending": False,
        "policy": None,
        "drain": None,
        "operations": [],
    }


def validate_state(value):
    expected = {"version", "boot_id", "roles", "paused_roles", "removed",
                "revocation_pending", "policy", "drain", "operations"}
    if (type(value) is not dict or set(value) != expected
            or type(value["version"]) is not int or value["version"] != 1):
        raise ValueError("connector state has an unsupported shape")
    if value["boot_id"] is not None and (not isinstance(value["boot_id"], str)
                                         or len(value["boot_id"]) != 32
                                         or any(char not in "0123456789abcdef"
                                                for char in value["boot_id"])):
        raise ValueError("connector boot identity is malformed")
    for name in ("roles", "paused_roles"):
        roles = value[name]
        if type(roles) is not dict or set(roles) != set(ROLE_NAMES) \
                or any(type(enabled) is not bool for enabled in roles.values()):
            raise ValueError("connector role state is malformed")
    if any(type(value[name]) is not bool for name in ("removed", "revocation_pending")):
        raise ValueError("connector removal state is malformed")
    if value["removed"] and not value["revocation_pending"]:
        raise ValueError("removed state must retain the revocation-pending marker")
    if value["policy"] is not None:
        value["policy"] = validate_policy(value["policy"])
    if value["drain"] is not None:
        drain = value["drain"]
        if (type(drain) is not dict or set(drain) != {"operation_id", "roles", "deadline_seconds"}
                or not valid_typed_id(drain["operation_id"], "op")
                or type(drain["roles"]) is not list
                or any(role not in ROLE_NAMES for role in drain["roles"])
                or type(drain["deadline_seconds"]) is not int
                or not 1 <= drain["deadline_seconds"] <= 300):
            raise ValueError("connector drain state is malformed")
    operations = value["operations"]
    if type(operations) is not list or len(operations) > 64:
        raise ValueError("connector operation history is malformed")
    seen = set()
    for item in operations:
        if (type(item) is not dict or set(item) != {"operation_id", "action", "status", "result"}
                or not valid_typed_id(item["operation_id"], "op")
                or not isinstance(item["action"], str)
                or item["action"] not in OPERATION_ACTIONS
                or not isinstance(item["status"], str)
                or item["status"] not in OPERATION_STATES
                or type(item["result"]) is not dict):
            raise ValueError("connector operation record is malformed")
        if item["operation_id"] in seen:
            raise ValueError("duplicate connector operation identity")
        seen.add(item["operation_id"])
    return value


def copy_state(value):
    return copy.deepcopy(value)
