import json
import re
import secrets


MAX_JSON_BYTES = 65_536
MAX_JSON_DEPTH = 16
ID_PATTERN = re.compile(r"^(?:acct|dev|req|ses|route|op|asg)_[0-9a-f]{32}$")


def new_id(kind):
    if kind not in {"acct", "dev", "req", "ses", "route", "op", "asg"}:
        raise ValueError("unsupported identity kind")
    return f"{kind}_{secrets.token_hex(16)}"


def valid_typed_id(value, kind=None):
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        return False
    return kind is None or value.startswith(f"{kind}_")


def _pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(f"non-finite JSON number {value}")


def _check_depth(text, maximum):
    depth = 0
    quoted = False
    escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            continue
        if character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > maximum:
                raise ValueError("JSON nesting limit exceeded")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("invalid JSON nesting")


def strict_json_loads(data, *, maximum_bytes=MAX_JSON_BYTES, maximum_depth=MAX_JSON_DEPTH):
    if isinstance(data, bytes):
        if len(data) > maximum_bytes:
            raise ValueError("JSON byte limit exceeded")
        text = data.decode("utf-8", errors="strict")
    elif isinstance(data, str):
        if len(data.encode("utf-8")) > maximum_bytes:
            raise ValueError("JSON byte limit exceeded")
        text = data
    else:
        raise TypeError("JSON input must be bytes or text")
    _check_depth(text, maximum_depth)
    return json.loads(text, object_pairs_hook=_pairs_no_duplicates,
                      parse_constant=_reject_constant)


def json_bytes(value, *, maximum_bytes=MAX_JSON_BYTES):
    data = json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(data) > maximum_bytes:
        raise ValueError("JSON byte limit exceeded")
    return data
