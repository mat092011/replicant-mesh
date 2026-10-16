"""Resource-matched complete-model replica control for the PyTorch lab.

Each replica owns a full copy of the pinned model. A thin client round-robins
independent requests across replicas; each request remains on one replica.
"""

import argparse
import asyncio
from contextlib import aclosing
import os
import time

from steamboat_runtime.remote_client import (SERVICE, MAX_MESSAGE_BYTES,
    MAX_GENERATE_BYTES, MAX_TOKENIZE_BYTES, decode_json, encode_json,
    validate_generate, validate_text)


async def drain_cancelled_step(step):
    """Keep ownership through repeated cancellation; terminate a wedged replica."""
    deadline = asyncio.get_running_loop().time() + 15
    while not step.done():
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            os._exit(70)
        try:
            await asyncio.wait_for(asyncio.shield(step), timeout=remaining)
        except asyncio.CancelledError:
            continue
        except TimeoutError:
            os._exit(70)


class ReplicaService:
    def __init__(self, model, tokenizer, loading_seconds=0):
        self.model, self.tokenizer = model, tokenizer
        self.loading_seconds = loading_seconds
        self.sessions = {}
        self.active_operations = self.queued_operations = 0
        self.execution_slots = asyncio.Semaphore(2)
        from steamboat_runtime.manifest import load_manifest
        self.manifest = load_manifest(os.environ.get("STEAMBOAT_ARTIFACT_DIR", "/artifacts"))

    async def describe_rpc(self, data, context):
        if decode_json(data, 64):
            await context.abort(__import__("grpc").StatusCode.INVALID_ARGUMENT, "Invalid request")
        import torch
        cache_bytes, cache_exact = self._cache_snapshot()
        return encode_json({"ready": True, "control_kind": "matched_complete_model_replica",
            "fingerprint": self.manifest["fingerprint"],
            "model": {key: self.manifest[key] for key in ("model_id", "revision", "dtype", "device", "attention")},
            "config": {"vocab_size": int(self.model.config.vocab_size)},
            "limits": {"max_positions": min(1152, int(self.model.config.max_position_embeddings))},
            "service": {"active_streams": len(self.sessions),
                        "active_sessions": len(self.sessions),
                        "active_operations": self.active_operations,
                        "queued_operations": self.queued_operations,
                        "allocated_cache_bytes": cache_bytes,
                        "cache_bytes_exact": cache_exact,
                        "loading_seconds": self.loading_seconds},
            "resources": {"cpu_quota": 2}, "device": str(next(self.model.parameters()).device),
            "torch_threads": torch.get_num_threads()})

    def _cache_snapshot(self):
        import torch
        total, exact = 0, True
        def visit(value):
            nonlocal total, exact
            if isinstance(value, torch.Tensor):
                total += value.numel() * value.element_size()
            elif isinstance(value, (tuple, list)):
                for item in value:
                    visit(item)
            elif hasattr(value, "to_legacy_cache"):
                visit(value.to_legacy_cache())
            elif hasattr(value, "key_cache") and hasattr(value, "value_cache"):
                visit(value.key_cache)
                visit(value.value_cache)
            elif hasattr(value, "keys") and hasattr(value, "values"):
                visit(value.keys)
                visit(value.values)
            elif value is not None:
                exact = False
        for session in self.sessions.values():
            visit(session.cache.layers if hasattr(session.cache, "layers") else session.cache)
        return total, exact

    async def tokenize_rpc(self, data, context):
        request = decode_json(data, MAX_TOKENIZE_BYTES)
        try:
            text = validate_text(request)
            ids = self.tokenizer(text, return_tensors="pt", truncation=False,
                                 add_special_tokens=request.get("add_special_tokens", True))["input_ids"]
            if not 1 <= ids.shape[1] <= 1152:
                raise ValueError()
            return encode_json({"input_ids": ids.reshape(-1).tolist()})
        except Exception:
            await context.abort(__import__("grpc").StatusCode.INVALID_ARGUMENT, "Invalid tokenized input")

    async def generate_rpc(self, data, context):
        import torch
        request = validate_generate(decode_json(data, MAX_GENERATE_BYTES))
        import grpc
        if (len(self.sessions) >= 6 or len(request["input_ids"]) + request["new_tokens"] >
                int(self.model.config.max_position_embeddings) or
                any(token >= int(self.model.config.vocab_size) for token in request["input_ids"]) or
                any(token >= int(self.model.config.vocab_size) for token in request.get("forced_tokens") or [])):
            await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "Replica stream capacity exhausted")
        sid = __import__("uuid").uuid4().hex
        output = []
        started = time.monotonic()
        from lab.benchmark import LocalSession
        session = LocalSession(self.model, len(request["input_ids"]) + request["new_tokens"])
        self.sessions[sid] = session
        try:
            ids = torch.tensor([request["input_ids"]], dtype=torch.long)
            with session:
                async with asyncio.timeout(request["timeout_seconds"]):
                    for index in range(request["new_tokens"]):
                        if context.cancelled():
                            raise asyncio.CancelledError()
                        if self.queued_operations >= 4:
                            await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED,
                                                "Replica execution queue is full")
                        self.queued_operations += 1
                        try:
                            await self.execution_slots.acquire()
                        finally:
                            self.queued_operations -= 1
                        self.active_operations += 1
                        def execute_step():
                            with torch.inference_mode():
                                return session.step(ids)
                        step = asyncio.create_task(asyncio.to_thread(execute_step))
                        try:
                            logits = await asyncio.shield(step)
                        except asyncio.CancelledError:
                            await drain_cancelled_step(step)
                            raise
                        finally:
                            self.active_operations -= 1
                            self.execution_slots.release()
                        token = int(logits[0, -1].argmax())
                        output.append(token)
                        event = {"type": "token", "session_id": sid,
                            "index": index, "position": len(request["input_ids"]) + index,
                            "sequence": index, "token_id": token}
                        if request["capture_logits"]:
                            event["logits"] = logits[0, -1].tolist()
                        await context.write(encode_json(event))
                        feedback = (request["forced_tokens"][index]
                                    if request.get("forced_tokens") is not None
                                    and index < request["new_tokens"] - 1 else token)
                        ids = torch.tensor([[feedback]], dtype=torch.long)
            await context.write(encode_json({"type": "result", "session_id": sid,
                "status": "completed", "token_ids": output, "cleanup_complete": True,
                "error": None, "error_code": None,
                "metrics": {"server_elapsed_ms": (time.monotonic() - started) * 1000,
                            "execution": "complete-model replica"}}))
        except TimeoutError:
            await context.abort(__import__("grpc").StatusCode.DEADLINE_EXCEEDED,
                                "Replica request deadline expired")
        except Exception:
            await context.abort(__import__("grpc").StatusCode.INTERNAL, "Replica inference failed")
        finally:
            session.close()
            self.sessions.pop(sid, None)


async def create_server(service, host):
    import grpc
    server = grpc.aio.server(options=(
        ("grpc.max_send_message_length", MAX_MESSAGE_BYTES),
        ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
        ("grpc.enable_retries", 0),), maximum_concurrent_rpcs=48)
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(SERVICE, {
        "Describe": grpc.unary_unary_rpc_method_handler(service.describe_rpc),
        "Tokenize": grpc.unary_unary_rpc_method_handler(service.tokenize_rpc),
        "Generate": grpc.unary_stream_rpc_method_handler(service.generate_rpc)}),))
    if not server.add_insecure_port(host):
        raise RuntimeError("Could not bind replica listener")
    await server.start()
    return server


async def serve(artifacts, reference, host):
    import torch
    torch.set_num_threads(int(os.environ.get("OMP_NUM_THREADS", "2")))
    from steamboat_runtime.backends import load_model
    model, tokenizer, loading = load_model("local", artifacts, reference)
    service = ReplicaService(model, tokenizer, loading)
    server = await create_server(service, host)
    try:
        await server.wait_for_termination()
    finally:
        await server.stop(5)


async def validate_replicas(artifacts, reference, endpoints, atol=1e-3):
    """Compare forced-continuation logits against the pinned local full model."""
    import torch
    from lab.benchmark import LocalSession, fixture_ids
    from lab.pipeline_benchmark import assert_matched_reclaimed
    from steamboat_runtime.backends import load_model
    from steamboat_runtime.remote_client import RemoteClient
    model, tokenizer, loading = load_model("local", artifacts, reference)
    clients = [RemoteClient(endpoint, private_network=True) for endpoint in endpoints]
    pool = MatchedReplicaPool(clients)
    report = {"success": False, "model_loading_seconds": loading, "comparisons": [],
              "atol": atol, "control": "four same-stack complete-model replicas"}
    try:
        description = await pool.describe()
        if not description.get("ready"):
            raise RuntimeError("A complete-model replica is not ready")
        tokens = fixture_ids(tokenizer, 128)
        forced = fixture_ids(tokenizer, 64)
        for replica_index, client in enumerate(clients, 1):
            local_outputs = []
            with torch.inference_mode(), LocalSession(model, 192) as session:
                current = torch.tensor([tokens], dtype=torch.long)
                local_outputs.append(session.step(current)[0, -1].clone())
                for token in forced[:63]:
                    current = torch.tensor([[token]], dtype=torch.long)
                    local_outputs.append(session.step(current)[0, -1].clone())
            remote_outputs = []
            async for event in client.generate(tokens, 64, forced_tokens=forced[:63],
                                               capture_logits=True, timeout_seconds=300):
                if event.get("type") == "token":
                    remote_outputs.append(torch.tensor(event["logits"], dtype=torch.float32))
            if len(remote_outputs) != len(local_outputs):
                raise AssertionError(f"Replica {replica_index} returned incomplete logit vectors")
            for index, (expected, actual) in enumerate(zip(local_outputs, remote_outputs)):
                error = float((expected - actual).abs().max())
                agrees = bool(expected.argmax() == actual.argmax())
                passed = bool(torch.isfinite(actual).all() and torch.allclose(expected, actual,
                                                                              atol=atol, rtol=0))
                report["comparisons"].append({"replica": replica_index, "position": index,
                    "max_absolute_logit_error": error, "greedy_token_agreement": agrees,
                    "passed": passed})
                if not passed:
                    raise AssertionError(f"Replica {replica_index} logits differ at position {index}")
        async def consume(client):
            result = []
            async for event in client.generate(tokens, 8, timeout_seconds=300):
                if event.get("type") == "token":
                    result.append(event["token_id"])
            return result
        overlap = await asyncio.gather(consume(clients[0]), consume(clients[1]))
        if not overlap[0] or not overlap[1]:
            raise AssertionError("Interleaved replica sessions returned no tokens")
        stream = clients[0].generate(tokens, 64, timeout_seconds=300)
        await stream.__anext__()
        await stream.aclose()
        deadline = asyncio.get_running_loop().time() + 20
        while asyncio.get_running_loop().time() < deadline:
            current = await pool.describe()
            if current["replicas"][0]["service"]["active_sessions"] == 0:
                break
            await asyncio.sleep(0.1)
        report["service_description_after"] = await pool.describe()
        assert_matched_reclaimed(report["service_description_after"])
        report["success"] = True
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        await pool.close()
    return report


class MatchedReplicaPool:
    """RemoteClient-compatible round-robin request routing across replicas."""
    def __init__(self, clients):
        if len(clients) != 4:
            raise ValueError("The matched control requires exactly four replicas")
        self.clients, self.next = clients, 0
        self.in_flight = [0] * len(clients)

    async def describe(self):
        details = await asyncio.gather(*(client.describe() for client in self.clients))
        if not all(item.get("ready") for item in details):
            raise RuntimeError("A complete-model replica is not ready")
        fingerprints = {item.get("fingerprint") for item in details}
        if len(fingerprints) != 1 or None in fingerprints:
            raise RuntimeError("Complete-model replica identities do not match")
        first = details[0]
        return {**first, "ready": True, "replicas": details,
            "service": {"active_streams": sum(x["service"]["active_streams"] for x in details),
                        "loading_seconds": [x["service"]["loading_seconds"] for x in details]},
            "control_kind": "matched_complete_model_replica", "fingerprint": next(iter(fingerprints)),
            "replicas": details}

    async def tokenize(self, *args, **kwargs):
        return await self.clients[0].tokenize(*args, **kwargs)

    def generate(self, *args, **kwargs):
        return self._route(*args, **kwargs)

    def reserve_replica(self):
        minimum = min(self.in_flight)
        choices = [(self.next + offset) % len(self.clients) for offset in range(len(self.clients))]
        index = next(index for index in choices if self.in_flight[index] == minimum)
        self.next = (index + 1) % len(self.clients)
        self.in_flight[index] += 1
        return index

    async def _route(self, *args, **kwargs):
        index = self.reserve_replica()
        try:
            async with aclosing(self.clients[index].generate(*args, **kwargs)) as stream:
                async for event in stream:
                    yield event
        finally:
            self.in_flight[index] -= 1

    async def close(self):
        await asyncio.gather(*(client.close() for client in self.clients))

    async def warmup_all(self, prompt, new_tokens, timeout_seconds):
        from lab.pipeline_benchmark import generate_remote_request
        return await asyncio.gather(*(generate_remote_request(client, prompt, new_tokens,
            f"warmup-{index + 1}", timeout_seconds=timeout_seconds)
            for index, client in enumerate(self.clients)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["serve", "check"])
    parser.add_argument("--artifacts", default="/artifacts")
    parser.add_argument("--reference", default=os.environ.get("STEAMBOAT_REFERENCE_DIR",
        "/cache/huggingface/hub/models--Maykeye--TinyLLama-v0/snapshots/298338802ab94432b917bcce11382aa151aee50f"))
    parser.add_argument("--host", default="0.0.0.0:50053")
    parser.add_argument("--replicas", nargs=4, default=[f"replica-{index}:50053" for index in range(1, 5)])
    parser.add_argument("--output", default="/results/matched-control-check.json")
    args = parser.parse_args()
    if args.command == "serve":
        asyncio.run(serve(args.artifacts, args.reference, args.host))
    else:
        import json
        from pathlib import Path
        try:
            report = asyncio.run(validate_replicas(args.artifacts, args.reference, args.replicas))
        except Exception as error:
            report = {"success": False, "error": f"{type(error).__name__}: {error}",
                      "control": "four same-stack complete-model replicas", "comparisons": []}
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(report, indent=2, allow_nan=False) + "\n")
        print(json.dumps({"report": str(destination), "success": report["success"],
                          "comparisons": len(report["comparisons"])}, indent=2))
        raise SystemExit(0 if report["success"] else 1)


if __name__ == "__main__":
    main()
