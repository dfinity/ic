import json
import types
from types import SimpleNamespace
from typing import Any
from typing import Tuple


def format_node_result(node_result: Any) -> Tuple[str, str]:
    if isinstance(node_result, types.SimpleNamespace):
        node_result = node_result.__dict__
        if len(node_result.keys()) != 1:
            raise TypeError("node.result should contain exactly one key-value pair.")
        execution_result = next(iter(node_result.keys()))
        execution_message = node_result[execution_result]
    elif isinstance(node_result, str):
        execution_result = node_result
        execution_message = ""
    else:
        raise TypeError("node result should be either of str or SimpleNamespace type.")
    return execution_result, execution_message


def read_test_results(filepath):
    """Read from a file a JSON object containing test results."""
    with open(filepath) as f:
        return json.load(f, object_hook=lambda d: SimpleNamespace(**d))
