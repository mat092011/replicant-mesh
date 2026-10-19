"""Require nonempty, skip-free Linux connector foundation checks."""

from pathlib import Path
import sys
import unittest


def main():
    root = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(root / "src"), str(root), str(root / "tests")]
    suite = unittest.defaultTestLoader.loadTestsFromNames([
        "connector.test_linux_ipc", "connector.test_linux_ledger",
        "connector.test_resources_controller", "connector.test_validation_client",
    ])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"Connector foundation: {result.testsRun} tests; {len(result.skipped)} skipped; C2 remains incomplete.")
    return int(not result.wasSuccessful() or bool(result.skipped) or result.testsRun == 0)


if __name__ == "__main__":
    raise SystemExit(main())
