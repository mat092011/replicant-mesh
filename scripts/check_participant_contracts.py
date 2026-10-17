"""Validate C0 examples and negative fixtures without runtime dependencies."""

import argparse
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from steamboat_participant.contracts import (
    ContractError, load_contract, validate_binding, validate_experiment_binding,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", nargs="+", type=Path, help="validate only these declarations, without the test suite")
    parser.add_argument("--participant", type=Path, help="also check operation/trial bindings against this participant config")
    arguments = parser.parse_args()
    if arguments.participant and not arguments.validate:
        parser.error("--participant requires --validate")
    try:
        if arguments.validate:
            participant = load_contract(arguments.participant) if arguments.participant else None
            for path in arguments.validate:
                document = load_contract(path)
                if participant is not None:
                    if document["kind"] == "session_operation":
                        validate_binding(document, participant)
                    elif document["kind"] == "experiment":
                        validate_experiment_binding(document, participant)
                    else:
                        raise ContractError("binding_kind", "$", "--participant accepts operation or frozen experiment input only")
                print(f"Valid declaration: {path}")
            print("Declarations only: no live authorization, security, hardware or phase-pass evidence.")
            return 0
        (ROOT / ".lab").mkdir(exist_ok=True)
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests/participant"),
                                                    pattern="test_participant*.py", top_level_dir=str(ROOT / "tests"))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        print(f"C0 contract checks: {result.testsRun} tests; {len(result.skipped)} skipped. Not a network/security or phase pass.")
        return int(not result.wasSuccessful() or bool(result.skipped) or result.testsRun == 0)
    except (ContractError, OSError) as error:
        print(f"Contract validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
