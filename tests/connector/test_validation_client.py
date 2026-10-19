import os
from pathlib import Path
import subprocess
import sys
import unittest

from steamboat_connector import ConsumerClient, FeatureUnavailable
from steamboat_connector.validation import new_id, strict_json_loads, valid_typed_id


class ValidationClientTests(unittest.TestCase):
    def test_json_rejects_duplicate_nonfinite_oversize_and_excess_depth(self):
        for document in ('{"value":1,"value":2}', '{"value":NaN}',
                         "{" + "[" * 16 + "0" + "]" * 16 + "}", "x" * 65_537):
            with self.subTest(document=document[:24]), self.assertRaises(ValueError):
                strict_json_loads(document)

    def test_ids_use_typed_random_lowercase_hex(self):
        first = new_id("req")
        second = new_id("req")
        self.assertTrue(valid_typed_id(first, "req"))
        self.assertTrue(valid_typed_id(second, "req"))
        self.assertNotEqual(first, second)
        self.assertFalse(valid_typed_id("req_" + "A" * 32, "req"))
        self.assertFalse(valid_typed_id("req_" + "0" * 31, "req"))

    def test_consumer_builder_is_lightweight_and_attempt_is_one(self):
        project_root = Path(__file__).resolve().parents[2]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(project_root / "src")
        script = """
import sys
from steamboat_connector import ConsumerClient, FeatureUnavailable
from steamboat_connector.validation import valid_typed_id

submission = ConsumerClient.build_submission("hello", max_new_tokens=12)
assert submission.attempt == 1
assert valid_typed_id(submission.request_id, "req")
try:
    ConsumerClient().submit("hello", max_new_tokens=12)
except FeatureUnavailable as error:
    assert error.code == "TRANSPORT_UNAVAILABLE"
else:
    raise AssertionError("consumer transport must remain unavailable in this slice")
assert not any(name == "torch" or name.startswith("torch.") for name in sys.modules)
assert not any(name == "transformers" or name.startswith("transformers.")
               or name == "huggingface_hub" or name.startswith("huggingface_hub.")
               for name in sys.modules)
assert not any(name == "cryptography" or name.startswith("cryptography.")
               for name in sys.modules)
"""
        result = subprocess.run(
            [sys.executable, "-B", "-S", "-c", script], cwd=project_root,
            env=environment,
            capture_output=True, text=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 0, msg=f"{result.stdout}\n{result.stderr}")

    def test_consumer_transport_is_called_once_without_retry(self):
        class FailingTransport:
            def __init__(self):
                self.calls = 0

            def submit(self, submission):
                self.calls += 1
                raise TimeoutError("ambiguous response")

            def cancel(self, request_id):
                self.calls += 1

        transport = FailingTransport()
        client = ConsumerClient(transport)
        with self.assertRaises(TimeoutError):
            client.submit("hello", max_new_tokens=12)
        self.assertEqual(transport.calls, 1)

    def test_consumer_input_bounds(self):
        client = ConsumerClient()
        for arguments in (
            {"prompt": "x" * 65_537, "max_new_tokens": 1},
            {"prompt": "x", "max_new_tokens": 0},
            {"prompt": "x", "max_new_tokens": 1_153},
            {"prompt": "x", "max_new_tokens": 1, "deadline_seconds": 301},
        ):
            prompt = arguments.pop("prompt")
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                client.build_submission(prompt, **arguments)


if __name__ == "__main__":
    unittest.main()
