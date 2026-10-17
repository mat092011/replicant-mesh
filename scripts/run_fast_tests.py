"""Run the dependency-free suite explicitly, without skipped runtime gates."""

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEST_FILES = (
    'test_benchmark.py', 'test_config.py', 'test_device_inventory.py',
    'test_experiment_audit.py', 'test_network_probe.py',
    'test_pipeline_benchmark.py', 'test_release_checks.py', 'test_security_reporting.py',
)


def main():
    sys.path[:0] = [str(ROOT), str(ROOT / 'src'), str(ROOT / 'tests')]
    loader = unittest.TestLoader()
    suite = unittest.TestSuite(loader.discover(str(ROOT / 'tests'), pattern=name)
                               for name in TEST_FILES)
    suite.addTests(loader.loadTestsFromName('test_matched_control.MatchedControlTests'))
    suite.addTests(loader.loadTestsFromName('participant.test_participant_contracts'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(f'Fast checks: {result.testsRun} tests; {len(result.skipped)} skipped')
    return int(not result.wasSuccessful() or bool(result.skipped))


if __name__ == '__main__':
    raise SystemExit(main())
