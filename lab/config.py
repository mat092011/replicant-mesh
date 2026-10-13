"""Small, dependency-free configuration and reporting helpers."""

import json
import math
import os
from pathlib import Path

DEFAULT_MODEL = "Maykeye/TinyLLama-v0"
DEFAULT_REVISION = "298338802ab94432b917bcce11382aa151aee50f"
PEER_FILE = Path("/state/peers.json")


def model_settings():
    model = os.environ.get("MODEL_ID", DEFAULT_MODEL)
    revision = os.environ.get("MODEL_REVISION", DEFAULT_REVISION)
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        raise ValueError("MODEL_REVISION must be a full immutable checkpoint SHA")
    return model, revision


def block_range(value):
    start, stop = (int(v) for v in value.split(":"))
    if start < 0 or stop <= start:
        raise ValueError("BLOCK_RANGE must be start:stop with 0 <= start < stop")
    return start, stop


def read_peers():
    peers = json.loads(PEER_FILE.read_text())
    if not isinstance(peers, list) or not peers or not all(isinstance(p, str) for p in peers):
        raise ValueError("No private bootstrap peers are available")
    return peers


def percentile(values, percent):
    """Nearest-rank percentile; returns None for an empty measurement set."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percent / 100) - 1)]


def summarize_requests(records, elapsed_seconds):
    successes = [r for r in records if r.get("success")]
    tokens = sum(r["output_tokens"] for r in successes)
    return {
        "attempted": len(records),
        "completed": len(successes),
        "failed": len(records) - len(successes),
        "accepted_output_tokens": tokens,
        "measurement_seconds": elapsed_seconds,
        "aggregate_output_tokens_per_second": tokens / elapsed_seconds if elapsed_seconds > 0 else None,
        "ttft_seconds_p50": percentile([r["ttft_seconds"] for r in successes], 50),
        "ttft_seconds_p95": percentile([r["ttft_seconds"] for r in successes], 95),
        "inter_token_seconds_p50": percentile([v for r in successes for v in r["inter_token_seconds"]], 50),
        "inter_token_seconds_p95": percentile([v for r in successes for v in r["inter_token_seconds"]], 95),
    }
