"""Small closed-type dialect, not a general JSON Schema implementation.

All object properties are required and additional properties are forbidden.
Only the published v1 operators below are accepted; no coercion or dependencies.
"""

import json
import math
from pathlib import Path
import re


MAX_DOCUMENT_BYTES = 1048576
MAX_DEPTH = 64
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "config/participant/v1/contracts.schema.json"


class ContractError(ValueError):
    def __init__(self, rule, path, message):
        self.rule, self.path = rule, path
        super().__init__(f"{rule} at {path}: {message}")


def require(condition, rule, path, message):
    if not condition:
        raise ContractError(rule, path, message)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "json_duplicate", "$", "duplicate property")
        result[key] = value
    return result


def _nonfinite(value):
    raise ContractError("json_number", "$", "nonfinite numbers are forbidden")


def _finite_float(value):
    result = float(value)
    require(math.isfinite(result), "json_number", "$", "nonfinite numbers are forbidden")
    return result


def load_json(path):
    with Path(path).open("rb") as stream:
        payload = stream.read(MAX_DOCUMENT_BYTES + 1)
    require(len(payload) <= MAX_DOCUMENT_BYTES, "json_size", "$", "document exceeds 1 MiB")
    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_pairs,
                              parse_constant=_nonfinite, parse_float=_finite_float)
        pending = [(document, 0)]
        while pending:
            value, depth = pending.pop()
            require(depth <= MAX_DEPTH, "json_depth", "$", "nesting exceeds the contract")
            if type(value) is float:
                require(math.isfinite(value), "json_number", "$", "nonfinite numbers are forbidden")
            elif type(value) is dict:
                pending.extend((child, depth + 1) for child in value.values())
            elif type(value) is list:
                pending.extend((child, depth + 1) for child in value)
        return document
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError("json_syntax", "$", "invalid bounded UTF-8 JSON") from error


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def validate_type(value, descriptor, types, path="$", depth=0):
    require(depth <= MAX_DEPTH, "schema_depth", path, "nesting exceeds the contract")
    if type(descriptor) is str:
        require(descriptor in types, "schema_definition", path, "unknown named type")
        return validate_type(value, types[descriptor], types, path, depth + 1)
    require(type(descriptor) is dict and len(descriptor) == 1,
            "schema_definition", path, "expected one closed-type operator")
    operator, specification = next(iter(descriptor.items()))
    if operator == "nullable":
        if value is not None:
            validate_type(value, specification, types, path, depth + 1)
    elif operator == "const":
        require(type(value) is type(specification) and value == specification,
                "schema_const", path, "unsupported constant or version")
    elif operator == "enum":
        require(any(type(value) is type(item) and value == item for item in specification),
                "schema_enum", path, "unsupported choice")
    elif operator == "bool":
        require(type(value) is bool, "schema_bool", path, "expected boolean")
    elif operator == "int":
        require(type(value) is int and specification[0] <= value <= specification[1],
                "schema_int", path, "expected integer within the declared range, not boolean")
    elif operator == "string":
        require(type(value) is str and len(value) <= specification["max"]
                and re.fullmatch(specification["pattern"], value, flags=re.ASCII) is not None,
                "schema_string", path, "invalid bounded string or identity")
    elif operator == "object":
        require(type(value) is dict, "schema_object", path, "expected object")
        require(set(value) == set(specification), "schema_properties", path,
                "properties must exactly match the versioned contract")
        for name, child_type in specification.items():
            validate_type(value[name], child_type, types, f"{path}.{name}", depth + 1)
    elif operator == "list":
        require(type(value) is list and specification["min"] <= len(value) <= specification["max"],
                "schema_list", path, "invalid list length or type")
        for index, item in enumerate(value):
            validate_type(item, specification["items"], types, f"{path}[{index}]", depth + 1)
        if specification["unique"]:
            require(len({canonical_bytes(item) for item in value}) == len(value),
                    "schema_unique", path, "duplicate list item")
    else:
        raise ContractError("schema_definition", path, "unsupported schema operator")


def validate_structure(document):
    schema = load_json(SCHEMA_PATH)
    require(schema.get("dialect") == "steamboat.closed-types.v1"
            and type(schema.get("schema_version")) is int and schema["schema_version"] == 1,
            "schema_definition", "$", "unsupported schema dialect")
    require(type(document) is dict, "schema_object", "$", "expected document object")
    kind = document.get("kind")
    require(type(kind) is str and kind in schema["documents"], "schema_kind", "$.kind", "unknown document kind")
    validate_type(document, schema["documents"][kind], schema["types"])
