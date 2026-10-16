"""Bounded coordinator-owned embeddings, final projection and offline tokenizer.

No transformer layer or KV cache is constructed here. CPU operations execute on
one dedicated thread, with inference mode set in that thread. There are at most
``max_sessions`` submitted operations, including an operation whose awaiter was
cancelled while CPU work was still running. Cancellation cannot kill a thread;
``close`` reports whether that thread actually drained within its time budget.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import math
from pathlib import Path

import torch


class CoordinatorModel:
    MAX_PROMPT_BYTES = 64 * 1024

    def __init__(self, manifest, input_output, tokenizer):
        """Use already verified components; production callers use from_artifacts."""
        self.manifest = manifest
        self.config = manifest["config"]
        self.limits = manifest["limits"]
        self.input_output = input_output
        self.tokenizer = tokenizer
        self._capacity = self.limits["max_sessions"]
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="coordinator-model")
        self._pending = set()
        self._loop = None
        self._closed = False
        self.requires_restart = False

    @classmethod
    def from_artifacts(cls, artifacts, tokenizer_reference=None):
        """Load only the coordinator slice and a pinned local tokenizer.

        Prepared artifacts already contain hash-checked tokenizer files. An
        optional original snapshot is checked against the same pinned source
        hashes before loading its tokenizer; its model weights are never loaded.
        """
        from safetensors.torch import load_file
        from transformers import AutoTokenizer, LlamaConfig
        from .manifest import artifact_path, load_manifest
        from .model import InputOutput
        from .prepare import verify_snapshot

        directory = Path(artifacts)
        manifest = load_manifest(directory)
        source = directory if tokenizer_reference is None else Path(tokenizer_reference)
        if tokenizer_reference is not None:
            verify_snapshot(source)
        config = LlamaConfig.from_dict(manifest["config"])
        config._attn_implementation = "eager"
        input_output = InputOutput(config, load_file(
            str(artifact_path(directory, manifest, "coordinator")), device="cpu"))
        tokenizer = AutoTokenizer.from_pretrained(
            str(source), local_files_only=True, trust_remote_code=False)
        if len(tokenizer) != config.vocab_size:
            raise ValueError("Tokenizer vocabulary differs from the pinned model")
        return cls(manifest, input_output, tokenizer)

    def validate_tokens(self, ids):
        if (not isinstance(ids, torch.Tensor) or ids.device.type != "cpu"
                or ids.dtype != torch.int64 or ids.ndim != 2 or ids.shape[0] != 1
                or not 1 <= ids.shape[1] <= self.limits["max_positions"]):
            raise ValueError("Input IDs must be CPU int64 [1, tokens] within the context limit")
        if int(ids.min()) < 0 or int(ids.max()) >= self.config["vocab_size"]:
            raise ValueError("Input token outside the model vocabulary")
        return ids.shape[1]

    def _check_hidden(self, hidden):
        if (not isinstance(hidden, torch.Tensor) or hidden.device.type != "cpu"
                or hidden.dtype != torch.float32 or hidden.ndim != 3
                or hidden.shape[0] != 1 or hidden.shape[2] != self.config["hidden_size"]
                or not 1 <= hidden.shape[1] <= self.limits["max_positions"]):
            raise ValueError("Hidden state must be CPU float32 [1, tokens, hidden_size]")

    async def _call(self, operation, *args):
        if self._closed:
            raise RuntimeError("Coordinator model is closed")
        loop = asyncio.get_running_loop()
        if self._loop is not None and loop is not self._loop:
            raise RuntimeError("Coordinator model must stay on one event loop")
        self._loop = loop
        # Purge completed futures here as well as in their callback. This avoids
        # a stale capacity rejection while an event-loop callback is pending.
        self._pending.difference_update(future for future in tuple(self._pending) if future.done())
        if len(self._pending) >= self._capacity:
            raise RuntimeError("Coordinator CPU operation capacity exhausted")

        def execute():
            with torch.inference_mode():
                return operation(*args)

        future = self._executor.submit(execute)
        self._pending.add(future)

        def completed(done):
            try:
                loop.call_soon_threadsafe(self._pending.discard, done)
            except RuntimeError:
                # The owning loop may already be closed after a timed-out close.
                pass

        future.add_done_callback(completed)
        try:
            # Shield keeps cancellation of the awaiter from hiding the actual
            # completion of an executing CPU call or releasing its capacity.
            wrapped = asyncio.wrap_future(future)
            wrapped.add_done_callback(self._observe_completion)
            return await asyncio.shield(wrapped)
        except asyncio.CancelledError:
            future.cancel()  # Effective only if execution has not started.
            raise

    @staticmethod
    def _observe_completion(future):
        # An abandoned awaiter still needs its eventual exception observed.
        if not future.cancelled():
            future.exception()

    async def embed(self, ids):
        self.validate_tokens(ids)
        return await self._call(self._embed, ids.detach().clone())

    def _embed(self, ids):
        hidden = self.input_output.embed_tokens(ids)
        self._check_hidden(hidden)
        if not bool(torch.isfinite(hidden).all()):
            raise RuntimeError("Non-finite embedding output")
        return hidden

    async def finish(self, hidden, all_logits=False):
        if type(all_logits) is not bool:
            raise ValueError("all_logits must be a boolean")
        self._check_hidden(hidden)
        return await self._call(self._finish, hidden.detach().clone(), all_logits)

    def _finish(self, hidden, all_logits):
        if not bool(torch.isfinite(hidden).all()):
            raise ValueError("Non-finite hidden state")
        if not all_logits:
            hidden = hidden[:, -1:, :]
        logits = self.input_output.lm_head(self.input_output.norm(hidden))
        if (logits.dtype != torch.float32 or logits.device.type != "cpu"
                or logits.shape != (1, hidden.shape[1], self.config["vocab_size"])
                or not bool(torch.isfinite(logits).all())):
            raise RuntimeError("Invalid coordinator logits")
        return logits

    async def tokenize(self, text):
        if not isinstance(text, str) or not text or len(text) > self.MAX_PROMPT_BYTES:
            raise ValueError("Prompt must be nonempty text of at most 64 KiB UTF-8")
        if len(text.encode("utf-8")) > self.MAX_PROMPT_BYTES:
            raise ValueError("Prompt must be at most 64 KiB UTF-8")
        return await self._call(self._tokenize, text)

    def _tokenize(self, text):
        ids = self.tokenizer(text, return_tensors="pt", truncation=False,
                             add_special_tokens=True)["input_ids"]
        self.validate_tokens(ids)
        return ids

    def diagnostics(self):
        return {
            "pending_cpu_operations": sum(not future.done() for future in self._pending),
            "max_cpu_operations": self._capacity,
            "closed": self._closed,
            "requires_restart": self.requires_restart,
            "parameter_count": sum(parameter.numel() for parameter in self.input_output.parameters()),
            "parameter_bytes": sum(parameter.numel() * parameter.element_size()
                                   for parameter in self.input_output.parameters()),
        }

    async def close(self, timeout_seconds=None):
        """Stop admission and return False if executing CPU work did not drain.

        A False result requires termination of the owning process to reclaim a
        wedged thread. The caller must not treat this as successful reclamation.
        """
        timeout = (self.limits["compute_cancel_grace_seconds"] if timeout_seconds is None
                   else timeout_seconds)
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout)
                or not 0 <= timeout <= self.limits["compute_cancel_grace_seconds"]):
            raise ValueError("Close timeout must be within the configured cancellation grace")
        self._closed = True
        futures = list(self._pending)
        for future in futures:
            future.cancel()
        self._executor.shutdown(wait=False, cancel_futures=True)
        waiting = [asyncio.wrap_future(future) for future in futures if not future.done()]
        for future in waiting:
            future.add_done_callback(self._observe_completion)
        if waiting:
            _, unfinished = await asyncio.wait(waiting, timeout=timeout)
            self.requires_restart = bool(unfinished)
        else:
            self.requires_restart = False
        return not self.requires_restart
