import sys


def assert_with_trace(condition: bool, message: str) -> None:
    if not condition:
        raise message


def eprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)
