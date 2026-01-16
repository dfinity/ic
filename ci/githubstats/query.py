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
        log(f"""# {title}:
{shlex.join(args) } << EOF
{query}
EOF
""")
    subprocess.run(args, input=query.encode(), check=True)


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


def top(args):
    """
    Get the top N non-successful/flaky/failed/timed-out tests
    in the last specified period.
    """
    period = "month" if args.month else "week" if args.week else ""

    query(
        f"Top {args.N} {args.order_by} tests{f' in the last {period}' if period else ''}",
        args.verbose,
        Template((THIS_SCRIPT_DIR / "top_tests.sql").read_text()).substitute(
            period=period,
            N=args.N,
            order_by=args.order_by,
        ),
    )


def main():
    parser = argparse.ArgumentParser()

    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--verbose", action="store_true", help="Log queries")

    period_parser = argparse.ArgumentParser(add_help=False)
    period_group = period_parser.add_mutually_exclusive_group()
    period_group.add_argument("--week", action="store_true", help="Limit to last week (default)")
    period_group.add_argument("--month", action="store_true", help="Limit to last month")

    subparsers = parser.add_subparsers(required=True)

    ## last-runs ##############################################################

    last_runs_parser = subparsers.add_parser(
        "last-runs",
        parents=[common_parser, period_parser],
        help="Get all runs of the specified test in the last period",
    )
    last_runs_parser.add_argument("--success", action="store_true")
    last_runs_parser.add_argument("--flaky", action="store_true")
    last_runs_parser.add_argument("--failed", action="store_true")
    last_runs_parser.add_argument("--timeout", action="store_true")

    last_runs_parser.add_argument("test_target", type=str, help="Bazel label of the test target to get runs of")
    last_runs_parser.set_defaults(func=last_runs)

    ## top ####################################################################

    top_parser = subparsers.add_parser(
        "top",
        parents=[common_parser, period_parser],
        help="Get the top N non-successful/flaky/failed/timed-out tests in the last period",
    )
    top_parser.add_argument("N", type=int, nargs="?", default=100, help="Number of tests to show (default: 100)")

    top_parser.add_argument(
        "order_by",
        type=str,
        choices=[
            "total_count",
            "non_success_count",
            "non_success_rate",
            "flaky_count",
            "flaky_rate",
            "timeout_count",
            "timeout_rate",
            "fail_count",
            "fail_rate",
            "p90_duration",
        ],
        default="flaky_rate",
        help="Column to order by (default: flaky_rate)",
    )

    top_parser.set_defaults(func=top)

    ###########################################################################

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
