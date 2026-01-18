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
import shlex
import sys
from pathlib import Path
from string import Template

import codeowners
import pandas as pd
import psycopg
import requests
from tabulate import tabulate

THIS_SCRIPT_DIR = Path(__file__).parent

ORG = "dfinity"
REPO = "ic"


@contextlib.contextmanager
def githubstats_db_cursor(conninfo: str):
    """Context manager that yields a cursor connected to the github PostgreSQL database."""
    conn = psycopg.connect(conninfo)
    try:
        with conn.cursor() as cursor:
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


def log_psql_query(log_query: bool, title: str, query: str, conninfo: str):
    """Optionally log the given query to stderr in a form that can be copy-pasted into psql."""
    if log_query:
        print(
            f"""# {title}:
{shlex.join(["psql", conninfo])} << EOF
{query}
EOF
""",
            file=sys.stderr,
        )


def top(args):
    """
    Get the top N non-successful / flaky / failed / timed-out tests
    in the last specified period.
    """
    period = "month" if args.month else "week" if args.week else ""

    query = Template((THIS_SCRIPT_DIR / "top.sql").read_text()).substitute(
        N=args.N,
        order_by=args.order_by,
        period=period,
        only_prs="TRUE" if args.prs else "FALSE",
        branch=args.branch if args.branch else "",
    )

    log_psql_query(
        args.verbose,
        f"Top {args.N} {args.order_by} tests{f' in the last {period}' if period else ''}",
        query,
        args.conninfo,
    )

    with githubstats_db_cursor(args.conninfo) as cursor:
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

    print(tabulate(df, headers="keys", tablefmt="github"))


def last(args):
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

    query = Template((THIS_SCRIPT_DIR / "last.sql").read_text()).substitute(
        test_target=args.test_target,
        overall_statuses=",".join(map(str, overall_statuses)),
        period=period,
        only_prs="TRUE" if args.prs else "FALSE",
        branch=args.branch if args.branch else "",
    )

    log_psql_query(
        args.verbose,
        f"Last {statuses}runs of {args.test_target}{f' in the last {period}' if period else ''}",
        query,
        args.conninfo,
    )

    with githubstats_db_cursor(args.conninfo) as cursor:
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

    df["time"] = df["time"].apply(lambda t: t.strftime("%a %Y-%m-%d %X"))

    df["branch"] = df["branch"].apply(
        lambda branch: terminal_hyperlink(branch, f"https://github.com/{ORG}/{REPO}/tree/{branch}")
    )

    df["pr"] = df["pr"].apply(
        lambda pr: terminal_hyperlink(f"#{pr}", f"https://github.com/{ORG}/{REPO}/pull/{pr}") if pr else ""
    )

    df = df.drop(columns=["buildbuddy_url"])
    columns = list(df.columns)
    print(tabulate(df[columns], headers="keys", tablefmt="github"))


def main():
    parser = argparse.ArgumentParser(prog="bazel run //ci/githubstats:query --")

    # Arguments common to all subcommands:
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--verbose", action="store_true", help="Log queries")
    common_parser.add_argument(
        "--conninfo",
        type=str,
        default="postgresql://githubstats_read@githubstats.idx.dfinity.network/github",
        help="PostgreSQL connection string",
    )

    filter_parser = argparse.ArgumentParser(add_help=False)
    period_group = filter_parser.add_mutually_exclusive_group()
    period_group.add_argument("--week", action="store_true", help="Limit to last week")
    period_group.add_argument("--month", action="store_true", help="Limit to last month")

    filter_parser.add_argument("--prs", action="store_true", help="Only show test runs on Pull Requests")
    filter_parser.add_argument("--branch", type=str, help="Filter by branch SQL LIKE pattern")

    subparsers = parser.add_subparsers(required=True)

    ## top ####################################################################

    top_parser = subparsers.add_parser(
        "top",
        parents=[common_parser, filter_parser],
        help="Get the top N non-successful / flaky / failed / timed-out tests in the last period",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    top_parser.add_argument("N", type=int, nargs="?", default=100, help="Number of tests to show")

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
        help="Column to order by",
    )

    top_parser.add_argument("--owner", type=str, help="Filter tests by owner (a regex for the GitHub username or team)")

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
    last_runs_parser.add_argument("--timeout", action="store_true", help="Include timed-out runs")

    last_runs_parser.add_argument("test_target", type=str, help="Bazel label of the test target to get runs of")
    last_runs_parser.set_defaults(func=last)

    ###########################################################################

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
