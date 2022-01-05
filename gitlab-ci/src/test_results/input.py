import json
from types import SimpleNamespace


def read_test_results(filepath):
    """Read from a file a JSON object containing test results."""
    with open(filepath) as f:
        return json.load(f, object_hook=lambda d: SimpleNamespace(**d))
