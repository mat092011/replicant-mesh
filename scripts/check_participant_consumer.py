"""Prove the consumer image is model-runtime-free and run its frozen suite."""

from importlib import metadata
from importlib.abc import MetaPathFinder
from importlib.machinery import PathFinder
from pathlib import Path
import signal
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
FROZEN_MODULES = (
    "connector.test_consumer_transport",
    "connector.test_validation_client",
    "security.test_channel_certificates",
    "security.test_channel_policy",
)
FORBIDDEN_DISTRIBUTIONS = frozenset({
    "torch", "transformers", "safetensors", "huggingface-hub",
})
FORBIDDEN_MODULES = ("torch", "transformers", "safetensors", "huggingface_hub")
MAX_SECONDS = 120.0
_BLOCKED_IMPORT_ATTEMPTS = []


class _ForbiddenImportFinder(MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if any(fullname == name or fullname.startswith(name + ".")
               for name in FORBIDDEN_MODULES):
            _BLOCKED_IMPORT_ATTEMPTS.append(fullname)
            raise ImportError("model runtime imports are forbidden in consumer image")
        return None


def _check_model_dependencies_absent():
    installed = {
        (distribution.metadata.get("Name") or "").lower().replace("_", "-")
        for distribution in metadata.distributions()
    }
    present = installed & FORBIDDEN_DISTRIBUTIONS
    if present:
        raise RuntimeError("consumer image contains forbidden model distributions")
    for module in FORBIDDEN_MODULES:
        if PathFinder.find_spec(module) is not None:
            raise RuntimeError("consumer image contains a forbidden model module")


def _import_consumer_clients():
    # Import the actual thin connector API and C1 secure consumer transport and
    # authorization factory. This catches accidental eager model dependencies.
    from steamboat_connector.client import ConsumerClient, LocalManagementClient
    from steamboat_runtime.protocol.secure_transport import (
        SecureCoordinatorClient, create_secure_coordinator_client,
    )
    from steamboat_security.outbound import AuthorizationWatcher, OutboundAuthorizer

    if not all((ConsumerClient, LocalManagementClient, SecureCoordinatorClient,
                create_secure_coordinator_client, AuthorizationWatcher,
                OutboundAuthorizer)):
        raise RuntimeError("consumer client imports are incomplete")


def _timeout_handler(_signum, _frame):
    raise TimeoutError("consumer validation exceeded 120 seconds")


def main():
    started = time.monotonic()
    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(int(MAX_SECONDS))
    sys.path[:0] = [str(ROOT / "src"), str(ROOT), str(ROOT / "tests")]
    try:
        _check_model_dependencies_absent()
        sys.meta_path.insert(0, _ForbiddenImportFinder())
        _import_consumer_clients()

        for module in FROZEN_MODULES:
            if importlib_spec(f"{module}") is None:
                raise RuntimeError("a frozen consumer test module is missing")

        suite = unittest.defaultTestLoader.loadTestsFromNames(FROZEN_MODULES)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        elapsed = time.monotonic() - started
        signal.alarm(0)
        if _BLOCKED_IMPORT_ATTEMPTS:
            raise RuntimeError("a test attempted a forbidden model import")
        print(f"Consumer image gate: modules={','.join(FROZEN_MODULES)}; "
              f"tests={result.testsRun}; skipped={len(result.skipped)}; "
              f"elapsed_seconds={elapsed:.3f}.")
        return int(not result.wasSuccessful() or result.testsRun == 0
                   or bool(result.skipped) or elapsed > MAX_SECONDS)
    except TimeoutError:
        print("Consumer image gate failed: validation exceeded 120 seconds.",
              file=sys.stderr)
        return 1
    except Exception as error:
        print(f"Consumer image gate failed: {type(error).__name__}.", file=sys.stderr)
        return 1
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)


def importlib_spec(name):
    # Resolve just the frozen test module. Importing it happens later in the
    # unittest loader after forbidden model imports are actively blocked.
    from importlib.util import find_spec

    return find_spec(name)


if __name__ == "__main__":
    raise SystemExit(main())
