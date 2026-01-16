#!/usr/bin/env python3

import argparse
import shlex
import subprocess
import sys
from pathlib import Path
from string import Template

THIS_SCRIPT_PATH = Path(__file__)
THIS_SCRIPT_DIR = THIS_SCRIPT_PATH.parent


def log(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)


def query(title, log_query: bool, query: str):
    """Run the given read-only SQL query against the github database."""
    args = ["psql", "-h", "githubstats.idx.dfinity.network", "-U", "githubstats_read", "-d", "github"]
    if log_query:
        log(f"""{title}:
{shlex.join(args) } << EOF
{query}
EOF
""")
    subprocess.run(
        args,
        check=True,
        input=query.encode(),
    )


def last_runs(args):
    """
    Get all runs of the specified test
    that have either succeeded, flaked, timed out or failed
    in the last specified period.
    """
    overall_statuses = []
    statuses = []
    if args.success:
        overall_statuses.append(1)
        statuses.append("successful")
    if args.flaky:
        overall_statuses.append(2)
        statuses.append("flaky")
    if args.timeout:
        overall_statuses.append(3)
        statuses.append("timed out")
    if args.failed:
        overall_statuses.append(4)
        statuses.append("failed")
    if len(overall_statuses) == 0:
        overall_statuses = [1, 2, 3, 4]

    statuses = f"{', '.join(statuses)} " if statuses else ""

    period = "month" if args.month else "week" if args.week else ""

    query(
        f"Last {statuses}runs of {args.test_target}{f' in the last {period}' if period else ''}",
        args.verbose,
        Template((THIS_SCRIPT_DIR / "test_runs.sql").read_text()).substitute(
            test_target=args.test_target,
            overall_statuses=",".join(map(str, overall_statuses)),
            period=period,
        ),
    )


def main():
    parser = argparse.ArgumentParser()

    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--verbose", action="store_true", help="Log queries")

    subparsers = parser.add_subparsers(required=True)

    last_runs_parser = subparsers.add_parser(
        "last-runs", parents=[common_parser], help="Get all runs of the specified test in the last week"
    )
    last_runs_parser.add_argument("--success", action="store_true")
    last_runs_parser.add_argument("--flaky", action="store_true")
    last_runs_parser.add_argument("--failed", action="store_true")
    last_runs_parser.add_argument("--timeout", action="store_true")

    period = last_runs_parser.add_mutually_exclusive_group()
    period.add_argument("--week", action="store_true", help="Limit to last week (default)")
    period.add_argument("--month", action="store_true", help="Limit to last month")

    last_runs_parser.add_argument("test_target", type=str, help="Bazel label of the test target to get runs of")
    last_runs_parser.set_defaults(func=last_runs)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
