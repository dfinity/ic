#!/usr/bin/env python3
#
# Run via:
#
#   bazel run //ci/githubstats:query -- --help
#
import argparse
import contextlib
import os
import re
import sys
from pathlib import Path

import codeowners
import pandas as pd
import psycopg
import requests
from psycopg import sql
from tabulate import tabulate

THIS_SCRIPT_DIR = Path(__file__).parent

ORG = "dfinity"
REPO = "ic"


@contextlib.contextmanager
def githubstats_db_cursor(conninfo: str, timeout: int):
    """Context manager that yields a cursor connected to the github PostgreSQL database."""
    conn = psycopg.connect(conninfo, connect_timeout=timeout)
    try:
        with conn.cursor() as cursor:
            cursor.execute(f"SET statement_timeout = {timeout * 1000}")
            yield cursor
    finally:
        conn.close()


def get_redirect_location(url):
    """Request a URL and return its redirect location."""
    response = requests.get(url, allow_redirects=False)
    return response.headers.get("location") if response.is_redirect else None


def terminal_hyperlink(text: str, url: str) -> str:
    """Return a terminal hyperlink if supported, otherwise return plain text."""
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\" if sys.stdout.isatty() else text


def sourcegraph_url(label: str) -> str:
    """Return a URL to SourceGraph that will search for the given Bazel label."""
    parts = label.rsplit(":", 1)
    dir = parts[0].replace("//", "")
    url = f"https://sourcegraph.com/search?q=repo:^github\\.com/{ORG}/{REPO}$+file:{dir}/BUILD.bazel"
    if len(parts) == 2:
        test = parts[1].removesuffix("_head_nns").removesuffix("_colocate")
        url += f"+{test}"
    return url


def owner_link(owner: codeowners.OwnerTuple):
    """Return a URL to the right GitHub page (team / user) based on the type of code owner."""
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


def shorten_owner(owner: str) -> str:
    """Shorten a code owner string for display. For example '@dfinity/node' -> 'node'."""
    parts = owner.split("/", 1)
    return parts[1] if len(parts) == 2 else owner


def log_psql_query(log_query: bool, query: str, conninfo: str):
    """Optionally log the given query to stderr in a form that can be copy-pasted into psql."""
    if log_query:
        print(f"psql {conninfo} << EOF\n{query}\nEOF", file=sys.stderr)


def period(args) -> str:
    """Return the period string based on the given args."""
    return "month" if args.month else "week" if args.week else "day" if args.day else "week"


def top(args):
    """
    Get the top N non-successful / flaky / failed / timed-out tests
    in the last specified period.
    """

    operator, value = (
        (">", args.gt)
        if args.gt is not None
        else (">=", args.ge)
        if args.ge is not None
        else ("<", args.lt)
        if args.lt is not None
        else ("<=", args.le)
        if args.le is not None
        else ("=", args.eq)
        if args.eq is not None
        else (None, None)
    )

    order_by = sql.Identifier(args.order_by)

    query = sql.SQL((THIS_SCRIPT_DIR / "top.sql").read_text()).format(
        hide=sql.Literal(args.hide if args.hide else ""),
        period=sql.SQL(period(args)),
        only_prs=sql.Literal(args.prs),
        branch=sql.Literal(args.branch if args.branch else ""),
        order_by=order_by,
        N=sql.Literal(args.N),
        condition=sql.Literal(True)
        if operator is None
        else sql.SQL("{order_by} {operator} {value}").format(
            order_by=order_by,
            operator=sql.SQL(operator),
            value=sql.Literal(value),
        ),
    )

    log_psql_query(args.verbose, query.as_string(), args.conninfo)

    with githubstats_db_cursor(args.conninfo, args.timeout) as cursor:
        cursor.execute(query)
        headers = [desc[0] for desc in cursor.description]
        df = pd.DataFrame(cursor, columns=headers)

    # Find the CODEOWNERS for each test target:
    owners = codeowners.CodeOwners(Path(os.environ["CODEOWNERS_PATH"]).read_text())
    df["owners"] = df["label"].apply(lambda label: owners.of(label.rsplit(":")[0].replace("//", "") + "/"))

    # Optionally filter by owner regex:
    if args.owner:
        df = df[
            df["owners"].apply(lambda owners: any(re.search(args.owner, owner[1], re.IGNORECASE) for owner in owners))
        ]

    # Turn the owners into terminal hyperlinks to their GitHub user/team page:
    df["owners"] = df["owners"].apply(
        lambda owners: ", ".join([terminal_hyperlink(shorten_owner(owner[1]), owner_link(owner)) for owner in owners])
    )

    # Turn the Bazel labels into terminal hyperlinks to a SourceGraph search for the test target:
    df["label"] = df["label"].apply(lambda label: terminal_hyperlink(label, sourcegraph_url(label)))

    print(tabulate(df, headers="keys", tablefmt=args.tablefmt))


def last(args):
    """
    Get the last runs of the specified test
    that have either succeeded, flaked, timed out or failed
    in the specified period.
    """
    overall_statuses = []
    if args.success:
        overall_statuses.append(1)
    if args.flaky:
        overall_statuses.append(2)
    if args.timedout:
        overall_statuses.append(3)
    if args.failed:
        overall_statuses.append(4)
    if len(overall_statuses) == 0:
        overall_statuses = [1, 2, 3, 4]

    query = sql.SQL((THIS_SCRIPT_DIR / "last.sql").read_text()).format(
        test_target=sql.Literal(args.test_target),
        overall_statuses=sql.SQL(",".join(map(str, overall_statuses))),
        period=sql.SQL(period(args)),
        only_prs=sql.Literal(args.prs),
        branch=sql.Literal(args.branch if args.branch else ""),
    )

    log_psql_query(args.verbose, query.as_string(), args.conninfo)

    with githubstats_db_cursor(args.conninfo, args.timeout) as cursor:
        cursor.execute(query)
        headers = [desc[0] for desc in cursor.description]
        df = pd.DataFrame(cursor, columns=headers)

    # Turn the buildbuddy URLs into terminal hyperlinks to the logs of the test target
    df["buildbuddy_url"] = (
        df["buildbuddy_url"].apply(get_redirect_location).apply(lambda url: f"{url}?target={args.test_target}")
    )
    df["buildbuddy"] = df["buildbuddy_url"].apply(lambda url: terminal_hyperlink("log", url))

    # Turn the commit SHAs into terminal hyperlinks to the GitHub commit page
    df["commit"] = df["commit"].apply(
        lambda commit: terminal_hyperlink(commit[:7], f"https://github.com/{ORG}/{REPO}/commit/{commit}")
    )

    df["last started at (UTC)"] = df["last started at (UTC)"].apply(lambda t: t.strftime("%a %Y-%m-%d %X"))

    df["branch"] = df["branch"].apply(
        lambda branch: terminal_hyperlink(branch, f"https://github.com/{ORG}/{REPO}/tree/{branch}")
    )

    df["PR"] = df["PR"].apply(
        lambda pr: terminal_hyperlink(f"#{pr}", f"https://github.com/{ORG}/{REPO}/pull/{pr}") if pr else ""
    )

    df = df.drop(columns=["buildbuddy_url"])
    columns = list(df.columns)
    print(tabulate(df[columns], headers="keys", tablefmt=args.tablefmt))


def main():
    parser = argparse.ArgumentParser(prog="bazel run //ci/githubstats:query --")

    # Arguments common to all subcommands:
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--verbose", action="store_true", help="Log queries")
    common_parser.add_argument(
        "--conninfo",
        metavar="STR",
        type=str,
        default="postgresql://githubstats_read@githubstats.idx.dfinity.network/github",
        help="PostgreSQL connection string",
    )
    common_parser.add_argument(
        "--timeout", metavar="T", type=int, default=60, help="PostgreSQL connect and query timeout in seconds"
    )
    common_parser.add_argument(
        "--tablefmt",
        metavar="FMT",
        type=str,
        default="mixed_outline",
        help="Table format. See: https://pypi.org/project/tabulate/",
    )

    filter_parser = argparse.ArgumentParser(add_help=False)
    period_group = filter_parser.add_mutually_exclusive_group()
    period_group.add_argument("--day", action="store_true", help="Limit to last day")
    period_group.add_argument("--week", action="store_true", help="Limit to last week (default)")
    period_group.add_argument("--month", action="store_true", help="Limit to last month")

    filter_parser.add_argument("--prs", action="store_true", help="Only show test runs on Pull Requests")
    filter_parser.add_argument("--branch", metavar="B", type=str, help="Filter by branch SQL LIKE pattern")

    subparsers = parser.add_subparsers(required=True)

    ## top ####################################################################

    top_parser = subparsers.add_parser(
        "top",
        parents=[common_parser, filter_parser],
        help="Get the top non-successful / flaky / failed / timed-out tests in the last period",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    top_parser.add_argument(
        "N", type=int, nargs="?", default=10, help="If specified, limits the number of tests to show"
    )

    top_parser.add_argument(
        "order_by",
        type=str,
        choices=[
            "total",
            "non_success",
            "non_success%",
            "flaky",
            "flaky%",
            "timeout",
            "timeout%",
            "fail",
            "fail%",
            "duration_p90",
        ],
        help="COLUMN to order by and have the condition flags like --gt, --ge, etc. apply to",
    )

    condition_group = top_parser.add_mutually_exclusive_group()
    condition_group.add_argument("--gt", metavar="F", type=float, help="Only show tests where COLUMN > F")
    condition_group.add_argument("--ge", metavar="F", type=float, help="Only show tests where COLUMN >= F")
    condition_group.add_argument("--lt", metavar="F", type=float, help="Only show tests where COLUMN < F")
    condition_group.add_argument("--le", metavar="F", type=float, help="Only show tests where COLUMN <= F")
    condition_group.add_argument("--eq", metavar="F", type=float, help="Only show tests where COLUMN = F")

    top_parser.add_argument(
        "--owner", metavar="TEAM", type=str, help="Filter tests by owner (a regex for the GitHub username or team)"
    )

    top_parser.add_argument("--hide", metavar="TEST", type=str, help="Hide tests matching this SQL LIKE pattern")

    top_parser.set_defaults(func=top)

    ## last ###################################################################

    last_runs_parser = subparsers.add_parser(
        "last",
        parents=[common_parser, filter_parser],
        help="Get the last runs of the specified test in the given period",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    last_runs_parser.add_argument("--success", action="store_true", help="Include successful runs")
    last_runs_parser.add_argument("--flaky", action="store_true", help="Include flaky runs")
    last_runs_parser.add_argument("--failed", action="store_true", help="Include failed runs")
    last_runs_parser.add_argument("--timedout", action="store_true", help="Include timed-out runs")

    last_runs_parser.add_argument("test_target", type=str, help="Bazel label of the test target to get runs of")
    last_runs_parser.set_defaults(func=last)

    ###########################################################################

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
