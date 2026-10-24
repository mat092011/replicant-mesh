"""Container entry points. No public swarm, host port, or Docker socket is used."""

import argparse
import json
import os
import signal
import socket
import sys
import time
from pathlib import Path

from lab.config import PEER_FILE, block_range, model_settings, read_peers


def snapshot_path(*, local_files_only):
    from huggingface_hub import snapshot_download

    model, revision = model_settings()
    return snapshot_download(
        model, revision=revision,
        cache_dir=os.environ.get("HF_HUB_CACHE"),
        allow_patterns=["*.json", "*.safetensors", "tokenizer.model", "*.txt"],
        local_files_only=local_files_only,
    )


def prepare():
    from transformers import AutoConfig, AutoTokenizer

    model, revision = model_settings()
    path = snapshot_path(local_files_only=False)
    if not list(Path(path).glob("*.safetensors")):
        raise RuntimeError("Checkpoint must provide safetensors weights")
    config = AutoConfig.from_pretrained(model, revision=revision, local_files_only=True)
    AutoTokenizer.from_pretrained(model, revision=revision, local_files_only=True)
    print(json.dumps({"model": model, "revision": revision, "layers": config.num_hidden_layers,
                      "hidden_size": config.hidden_size, "cache": path}), flush=True)


def bootstrap():
    import hivemind

    # A persisted peer file belongs to the previous process identity. Publish a
    # new one only after this bootstrap DHT has started successfully.
    PEER_FILE.unlink(missing_ok=True)
    dht = hivemind.DHT(start=True, initial_peers=[], host_maddrs=["/ip4/0.0.0.0/tcp/31337"])
    # A loopback address would refer to a different container on each peer.
    peers = [str(p) for p in dht.get_visible_maddrs()
             if not str(p).startswith(("/ip4/127.", "/ip6/::1/"))]
    if not peers:
        raise RuntimeError("Private bootstrap did not advertise an address")
    PEER_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = PEER_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(peers))
    temporary.replace(PEER_FILE)
    print(json.dumps({"private_peers": peers}), flush=True)
    try:
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        while True:
            time.sleep(10)
    finally:
        PEER_FILE.unlink(missing_ok=True)
        dht.shutdown()


def worker():
    from petals.cli import run_server
    from transformers import AutoConfig

    _, revision = model_settings()
    # Petals uses a separate weight-cache setting and its sharded index lookup
    # omits revision in one upstream code path. A local immutable snapshot avoids
    # both fallback downloads and accidental lookups of a different revision.
    path = snapshot_path(local_files_only=True)
    start, stop = block_range(os.environ["BLOCK_RANGE"])
    config = AutoConfig.from_pretrained(path, local_files_only=True)
    if stop > config.num_hidden_layers:
        raise ValueError("Worker block range exceeds this checkpoint's layer count")
    command = [
        "petals.cli.run_server", path,
        "--revision", revision, "--block_indices", f"{start}:{stop}",
        "--device", "cpu", "--torch_dtype", "float32", "--quant_type", "none",
        "--compression", "NONE", "--throughput", "1", "--num_handlers", "2",
        "--port", "31337", "--no_auto_relay", "--balance_quality", "0",
        # Eight sessions reserving 1152 positions need 9216 cache tokens per block;
        # 12288 provides headroom. TinyLLama's hidden64 uses 18 MiB for three blocks.
        "--attn_cache_tokens", "12288", "--inference_max_length", "1152",
        "--max_batch_size", "1152", "--max_alloc_timeout", "15",
        "--session_timeout", "120", "--step_timeout", "60",
        "--dht_prefix", os.environ.get("LAB_DHT_PREFIX", "replicant-mesh-local-v1"),
        "--initial_peers", *read_peers(),
    ]
    # Experimental wrapper deviation: the pinned upstream CLI checks PyPI with
    # requests.get() and no timeout before serving. HF_HUB_OFFLINE does not cover
    # that request. Skip only this update notification in our isolated swarm;
    # preserve the CLI's model loading, runtime, and scheduler unchanged.
    def skip_online_version_check():
        print("Pinned Petals runtime: online PyPI version notification disabled for offline lab.", flush=True)

    run_server.validate_version = skip_online_version_check
    sys.argv = command
    run_server.main()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["prepare", "bootstrap", "worker", "client", "health-worker", "health-bootstrap"])
    role = parser.parse_args().role
    if role == "prepare":
        prepare()
    elif role == "bootstrap":
        bootstrap()
    elif role == "worker":
        worker()
    elif role in ("health-worker", "health-bootstrap"):
        # DHT listener readiness only. The benchmark's warm-up validates loaded blocks.
        with socket.create_connection(("127.0.0.1", 31337), timeout=2):
            pass
        if role == "health-bootstrap":
            read_peers()  # Startup is usable only after the new identity is published.
    else:
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        print("Client ready. Run python -m lab.benchmark check or bench via compose exec.", flush=True)
        while True:
            time.sleep(60)


if __name__ == "__main__":
    main()
