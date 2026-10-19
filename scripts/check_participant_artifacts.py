"""Require every Linux foundation/artifact case, including assigned model parity."""

import os
from pathlib import Path
import sys
import unittest


def main():
    root = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(root / "src"), str(root), str(root / "tests")]
    if not sys.platform.startswith("linux"):
        raise RuntimeError("artifact validation requires Linux")
    source = os.environ.get("STEAMBOAT_ASSIGNED_TEST_SOURCE")
    scratch = os.environ.get("STEAMBOAT_ASSIGNED_TEST_SCRATCH")
    if not source or not Path(source).is_dir() or not scratch:
        raise RuntimeError("required assigned-model source/scratch is missing")
    Path(scratch).mkdir(mode=0o700, exist_ok=False)
    suite = unittest.defaultTestLoader.discover(str(root / "tests/connector"),
                                               top_level_dir=str(root / "tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"Connector and artifacts: {result.testsRun} tests; {len(result.skipped)} skipped. C2 remains incomplete.")
    return int(not result.wasSuccessful() or bool(result.skipped) or result.testsRun < 41)


if __name__ == "__main__":
    raise SystemExit(main())
