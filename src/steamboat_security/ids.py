"""Strict v1 identity grammars and cryptographically random ID creation."""

import re
import secrets

from .errors import BindingError


_TYPED_PREFIXES = frozenset({"acct", "dev", "req", "ses", "route", "op", "asg"})
_ID = re.compile(r"^(acct|dev|req|ses|route|op|asg)_[0-9a-f]{32}$", re.ASCII)
_BOOT = re.compile(r"^[0-9a-f]{32}$", re.ASCII)


def validate_id(value: object, prefix: str | None = None) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise BindingError("identifier has an invalid v1 grammar")
    if prefix is not None and value.split("_", 1)[0] != prefix:
        raise BindingError("identifier has the wrong type")
    return value


def validate_boot(value: object) -> str:
    if type(value) is not str or not _BOOT.fullmatch(value):
        raise BindingError("boot identifier has an invalid v1 grammar")
    return value


def new_id(prefix: str) -> str:
    if prefix not in _TYPED_PREFIXES:
        raise ValueError("unsupported identity prefix")
    return f"{prefix}_{secrets.token_hex(16)}"


def new_boot_id() -> str:
    return secrets.token_hex(16)
