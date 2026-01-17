#!/usr/bin/env python3

import argparse
import contextlib
import shlex
import sys
from pathlib import Path
from string import Template

import pandas as pd
import psycopg
import requests
from tabulate import tabulate

THIS_SCRIPT_PATH = Path(__file__)
THIS_SCRIPT_DIR = THIS_SCRIPT_PATH.parent

POSTGRESQL_SERVER = "githubstats.idx.dfinity.network"
POSTGRESQL_USER = "githubstats_read"
POSTGRESQL_DB = "github"


def get_redirect_location(url):
    """Request a URL and return its redirect location."""
    response = requests.get(url, allow_redirects=False)
    if response.is_redirect:
        return response.headers.get("location")
    return None


def terminal_hyperlink(text: str, url: str) -> str:
    """Return a terminal hyperlink if supported, otherwise return plain text."""
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\" if sys.stdout.isatty() else text


def log(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)


@contextlib.contextmanager
def githubstats_db_cursor():
    """Context manager that yields a cursor connected to the github database."""
    conn = psycopg.connect(
        host=POSTGRESQL_SERVER,
        user=POSTGRESQL_USER,
        dbname=POSTGRESQL_DB,
    )
    try:
        with conn.cursor() as cursor:
            yield cursor
    finally:
        conn.close()


def log_psql_query(log_query: bool, title: str, query: str):
    if log_query:
        args = ["psql", "-h", POSTGRESQL_SERVER, "-U", POSTGRESQL_USER, "-d", POSTGRESQL_DB]
        log(f"""# {title}:
{shlex.join(args) } << EOF
{query}
EOF
""")


def top(args):
    """
    Get the top N non-successful/flaky/failed/timed-out tests
    in the last specified period.
    """
    period = "month" if args.month else "week" if args.week else ""

    query = Template((THIS_SCRIPT_DIR / "top_tests.sql").read_text()).substitute(
        period=period,
        N=args.N,
        order_by=args.order_by,
    )

    log_psql_query(
        args.verbose, f"Top {args.N} {args.order_by} tests{f' in the last {period}' if period else ''}", query
    )

    with githubstats_db_cursor() as cursor:
        cursor.execute(query)
        headers = [desc[0] for desc in cursor.description]
        df = pd.DataFrame(cursor, columns=headers)

    print(tabulate(df, headers="keys", tablefmt="github"))


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

    query = Template((THIS_SCRIPT_DIR / "test_runs.sql").read_text()).substitute(
        test_target=args.test_target,
        overall_statuses=",".join(map(str, overall_statuses)),
        period=period,
    )

    log_psql_query(
        args.verbose, f"Last {statuses}runs of {args.test_target}{f' in the last {period}' if period else ''}", query
    )

    with githubstats_db_cursor() as cursor:
        cursor.execute(query)
        headers = [desc[0] for desc in cursor.description]
        df = pd.DataFrame(cursor, columns=headers)

    # Turn the buildbuddy URLs into terminal hyperlinks to the logs of the test target
    df["buildbuddy_url"] = (
        df["buildbuddy_url"].apply(get_redirect_location).apply(lambda url: f"{url}?target={args.test_target}")
    )
    df["buildbuddy_log_link"] = df["buildbuddy_url"].apply(lambda url: terminal_hyperlink("log", url))
    # Turn the commit SHAs into terminal hyperlinks to the GitHub commit page
    df["head_sha"] = df["head_sha"].apply(
        lambda commit: terminal_hyperlink(commit[:7], f"https://github.com/dfinity/ic/commit/{commit}")
    )

    df = df.drop(columns=["buildbuddy_url"])
    columns = list(df.columns)
    print(tabulate(df[columns], headers="keys", tablefmt="github"))


def main():
    parser = argparse.ArgumentParser()

    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--verbose", action="store_true", help="Log queries")

    period_parser = argparse.ArgumentParser(add_help=False)
    period_group = period_parser.add_mutually_exclusive_group()
    period_group.add_argument("--week", action="store_true", help="Limit to last week (default)")
    period_group.add_argument("--month", action="store_true", help="Limit to last month")

    subparsers = parser.add_subparsers(required=True)

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

    ###########################################################################

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
