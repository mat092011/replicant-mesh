"""Local process fixture: exercise actual coordinator model supervision plumbing."""

import asyncio
import sys
import time

import torch

from replicant_mesh.coordinator_service import supervised_model_class
from replicant_mesh.worker import _frame
from test_manifest import sample_manifest


async def main():
    manifest = sample_manifest()
    manifest["limits"]["compute_cancel_grace_seconds"] = 0.15
    if len(sys.argv) > 1:
        manifest["limits"]["rpc_timeout_seconds"] = 0.15
    model = supervised_model_class()(manifest, torch.nn.Identity(), None)
    model.on_supervision = lambda status: _frame("heartbeat", status)
    _frame("ready", model.supervision_status(), worker="coordinator-test")
    operation = asyncio.create_task(model._call(time.sleep, 10))
    await asyncio.sleep(0.05)
    if len(sys.argv) == 1:
        operation.cancel()
        await asyncio.gather(operation, return_exceptions=True)
    while True:
        _frame("heartbeat", model.supervision_status())
        await asyncio.sleep(0.02)


if __name__ == "__main__":
    asyncio.run(main())
