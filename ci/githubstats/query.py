#!/usr/bin/env python3
#
# Run via:
#
#   bazel run //ci/githubstats:query -- --help
#
import argparse
import contextlib
import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from string import Template

import codeowners
import pandas as pd
import psycopg
import requests
from tabulate import tabulate

THIS_SCRIPT_PATH = Path(__file__)
THIS_SCRIPT_DIR = THIS_SCRIPT_PATH.parent


# Structure to hold DB connection info
@dataclass
class DBConfig:
    host: str
    user: str
    db: str


def get_redirect_location(url):
    """Request a URL and return its redirect location."""
    response = requests.get(url, allow_redirects=False)
    if response.is_redirect:
        return response.headers.get("location")
    return None


def terminal_hyperlink(text: str, url: str) -> str:
    """Return a terminal hyperlink if supported, otherwise return plain text."""
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\" if sys.stdout.isatty() else text


def sourcegraph_url(label: str) -> str:
    parts = label.rsplit(":", 1)
    dir = parts[0].replace("//", "")
    test = parts[1].removesuffix("_head_nns").removesuffix("_colocate")
    return f"https://sourcegraph.com/search?q=repo:^github\\.com/dfinity/ic$+file:{dir}/BUILD.bazel+{test}"


def owner_link(owner: codeowners.OwnerTuple):
    if owner[0] == "TEAM":
        parts = owner[1][1:].rsplit("/")
        org = parts[0]
        team = parts[1]
        return f"https://github.com/orgs/{org}/teams/{team}"
    elif owner[0] == "USERNAME":
        username = owner[1][1:]
        return f"https://github.com/{username}"
    else:  # owner[0] == "EMAIL":
        return owner[1]


def find_owner_of_target(owners, label: str) -> str:
    parts = label.rsplit(":", 1)
    directory = parts[0].replace("//", "") + "/"
    return ", ".join([terminal_hyperlink(owner[1], owner_link(owner)) for owner in owners.of(directory)])


def log(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)


@contextlib.contextmanager
def githubstats_db_cursor(db_config: DBConfig):
    """Context manager that yields a cursor connected to the github database."""
    conn = psycopg.connect(
        host=db_config.host,
        user=db_config.user,
        dbname=db_config.db,
    )
    try:
        with conn.cursor() as cursor:
            yield cursor
    finally:
        conn.close()


def log_psql_query(log_query: bool, title: str, query: str, db_config: DBConfig):
    if log_query:
        args = [
            "psql",
            "-h",
            db_config.host,
            "-U",
            db_config.user,
            "-d",
            db_config.db,
        ]
        log(f"""# {title}:
{shlex.join(args) } << EOF
{query}
EOF
""")


def top(args, db_config):
    """
    Get the top N non-successful/flaky/failed/timed-out tests
    in the last specified period.
    """
    period = "month" if args.month else "week" if args.week else ""

    query = Template((THIS_SCRIPT_DIR / "top_tests.sql").read_text()).substitute(
        period=period,
        only_prs="TRUE" if args.prs else "FALSE",
        N=args.N,
        order_by=args.order_by,
    )

    log_psql_query(
        args.verbose,
        f"Top {args.N} {args.order_by} tests{f' in the last {period}' if period else ''}",
        query,
        db_config,
    )

    with githubstats_db_cursor(db_config) as cursor:
        cursor.execute(query)
        headers = [desc[0] for desc in cursor.description]
        df = pd.DataFrame(cursor, columns=headers)

    owners = codeowners.CodeOwners(Path(os.environ["CODEOWNERS_PATH"]).read_text())
    df["owners"] = df["label"].apply(lambda label: find_owner_of_target(owners, label))

    df["label"] = df["label"].apply(lambda label: terminal_hyperlink(label, sourcegraph_url(label)))

    print(tabulate(df, headers="keys", tablefmt="github"))


def last(args, db_config):
    """
    Get the last runs of the specified test
    that have either succeeded, flaked, timed out or failed
    in the specified period.
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
        only_prs="TRUE" if args.prs else "FALSE",
    )

    log_psql_query(
        args.verbose,
        f"Last {statuses}runs of {args.test_target}{f' in the last {period}' if period else ''}",
        query,
        db_config,
    )

    with githubstats_db_cursor(db_config) as cursor:
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
    common_parser.add_argument(
        "--postgresql-server",
        type=str,
        default="githubstats.idx.dfinity.network",
        help="PostgreSQL server hostname (default: githubstats.idx.dfinity.network)",
    )
    common_parser.add_argument(
        "--postgresql-user",
        type=str,
        default="githubstats_read",
        help="PostgreSQL user (default: githubstats_read)",
    )
    common_parser.add_argument(
        "--postgresql-db",
        type=str,
        default="github",
        help="PostgreSQL database name (default: github)",
    )

    period_parser = argparse.ArgumentParser(add_help=False)
    period_group = period_parser.add_mutually_exclusive_group()
    period_group.add_argument("--week", action="store_true", help="Limit to last week (default)")
    period_group.add_argument("--month", action="store_true", help="Limit to last month")

    prs_parser = argparse.ArgumentParser(add_help=False)
    prs_parser.add_argument("--prs", action="store_true", help="Only show test runs on Pull Requests")

    subparsers = parser.add_subparsers(required=True)

    ## top ####################################################################

    top_parser = subparsers.add_parser(
        "top",
        parents=[common_parser, period_parser, prs_parser],
        help="Get the top N non-successful/flaky/failed/timed-out tests in the last period",
    )
    top_parser.add_argument("N", type=int, nargs="?", default=100, help="Number of tests to show (default: 100)")

    top_parser.add_argument(
        "order_by",
        type=str,
        choices=[
            "total",
            "non_success",
            "non_success_rate",
            "flaky",
            "flaky_rate",
            "timeout",
            "timeout_rate",
            "fail",
            "fail_rate",
            "p90_duration",
        ],
        default="flaky_rate",
        help="Column to order by (default: flaky_rate)",
    )

    top_parser.set_defaults(func=top)

    ## last ###################################################################

    last_runs_parser = subparsers.add_parser(
        "last",
        parents=[common_parser, period_parser, prs_parser],
        help="Get the last runs of the specified test in the given period",
    )
    last_runs_parser.add_argument("--success", action="store_true")
    last_runs_parser.add_argument("--flaky", action="store_true")
    last_runs_parser.add_argument("--failed", action="store_true")
    last_runs_parser.add_argument("--timeout", action="store_true")

    last_runs_parser.add_argument("test_target", type=str, help="Bazel label of the test target to get runs of")
    last_runs_parser.set_defaults(func=last)

    ###########################################################################

    args = parser.parse_args()
    db_config = DBConfig(
        host=args.postgresql_server,
        user=args.postgresql_user,
        db=args.postgresql_db,
    )
    args.func(args, db_config)


if __name__ == "__main__":
    main()
