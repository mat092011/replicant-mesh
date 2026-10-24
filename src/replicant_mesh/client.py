"""Thin in-process streamed-token client for the M4 coordinator.

The caller sends token IDs or bounded text and receives token events. Model
components, stage scheduling and worker leases belong to the coordinator. A
network-facing client API and benchmark adapter remain M5 work.
"""


class CoordinatorClient:
    def __init__(self, coordinator):
        self.coordinator = coordinator

    async def generate(self, prompt, new_tokens, **options):
        """Yield token events; cancel all owned reservations on early close.

        Explicitly ``aclose`` the generator when abandoning a stream (or use
        ``contextlib.aclosing``). Closing this client does not own or shut down
        the shared coordinator.
        """
        ids = (await self.coordinator.model.tokenize(prompt)
               if isinstance(prompt, str) else prompt)
        handle = self.coordinator.submit(ids, new_tokens, **options)
        completed = False
        try:
            async for event in handle:
                yield event
            await handle.result()
            completed = True
        finally:
            if not completed:
                await handle.cancel()
