"""Identify a Linux monotonic clock domain for same-host trace validation.

A matching identifier is necessary, not sufficient: callers also bracket a
Describe sample with their own monotonic timestamps. Other hosts need explicit
clock synchronization; an empty identity never authorizes cross-process alignment.
"""

from functools import lru_cache
from pathlib import Path
import re
import sys


@lru_cache(maxsize=1)
def clock_identity():
    if sys.platform != "linux":
        return ""
    try:
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        offsets = Path("/proc/self/timens_offsets").read_text().splitlines()
    except OSError:
        return ""
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot):
        return ""
    # Docker can create distinct time namespaces with identical clock values.
    # Linux exposes each offset relative to the initial time namespace; equal
    # boot identity + equal CLOCK_MONOTONIC offset define the same time base.
    # See time_namespaces(7). Namespace inode equality is unnecessarily strict.
    rows = [line.split() for line in offsets if line.split()[:1] == ["monotonic"]]
    if len(rows) != 1 or len(rows[0]) != 3:
        return ""
    try:
        seconds, nanos = map(int, rows[0][1:])
    except ValueError:
        return ""
    if not 0 <= nanos < 1_000_000_000:
        return ""
    return f"linux:{boot}:monotonic-offset-ns:{seconds * 1_000_000_000 + nanos}"
