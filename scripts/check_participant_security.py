"""Run the required offline C1a suite; missing tests/dependencies/skips fail."""

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def main():
    sys.path[:0] = [str(ROOT / "src"), str(ROOT), str(ROOT / "tests")]
    directory = ROOT / "tests/security"
    if not directory.is_dir() or not any(directory.glob("test_*.py")):
        print("C1a security tests are missing", file=sys.stderr)
        return 1
    suite = unittest.defaultTestLoader.discover(str(directory), top_level_dir=str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"C1a checks: {result.testsRun} tests; {len(result.skipped)} skipped. No C1b/device evidence.")
    return int(not result.wasSuccessful() or bool(result.skipped) or result.testsRun == 0)


if __name__ == "__main__":
    raise SystemExit(main())
