import sys


def eprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)
