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
import subprocess
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import codeowners
import pandas as pd
import psycopg
import requests
from proto import target_pb2
from psycopg import sql
from tabulate import tabulate

THIS_SCRIPT_DIR = Path(__file__).parent

ORG = "dfinity"
REPO = "ic"


def die(*args):
    print(*args, file=sys.stderr)
    sys.exit(1)


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


def is_git_commit_sha(s: str) -> bool:
    """Check if a string looks like a git commit SHA (7-40 hex characters)."""
    return bool(re.match(r"^[0-9a-fA-F]{7,40}$", s))


def get_commit_timestamp(sha: str) -> datetime:
    """Fetch a git commit and return its commit timestamp as a timezone-aware datetime object (UTC)."""
    repo_root = THIS_SCRIPT_DIR.parent.parent

    try:
        # First, resolve the full commit SHA
        result = subprocess.run(
            ["git", "rev-parse", sha],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        full_sha = result.stdout.strip()

        # Then, fetch the commit to ensure it's available locally
        subprocess.run(
            ["git", "fetch", "origin", full_sha],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        die(f"Failed to fetch git commit '{sha}': {e.stderr.strip()}\nMake sure the commit exists in the repository.")

    try:
        # Get the commit timestamp in ISO 8601 format
        result = subprocess.run(
            ["git", "log", "-1", "--format=%cI", sha],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        timestamp_str = result.stdout.strip()

        if not timestamp_str:
            die(f"Could not get timestamp for git commit '{sha}'")

        # Parse the ISO 8601 timestamp and convert to UTC
        dt = pd.to_datetime(timestamp_str, utc=True)
        return dt.to_pydatetime()
    except subprocess.CalledProcessError as e:
        die(f"Failed to get timestamp for git commit '{sha}': {e.stderr.strip()}")
    except Exception as e:
        die(f"Failed to parse timestamp for git commit '{sha}': {e}")


def parse_datetime(dt_str: str) -> datetime:
    """Parse datetime string or git commit SHA and return a timezone-aware datetime object (UTC)."""
    # Check if it looks like a git commit SHA
    if is_git_commit_sha(dt_str):
        return get_commit_timestamp(dt_str)

    # Otherwise, try to parse as a datetime string
    try:
        dt = pd.to_datetime(dt_str, utc=True)
        return dt.to_pydatetime()
    except Exception as e:
        die(
            f"Invalid datetime format '{dt_str}': {e}\nExpected format like '2024-01-15', '2024-01-15 14:30:00', or a git commit SHA"
        )


def get_time_filter(args) -> sql.Composable:
    """
    Return an SQL WHERE clause fragment for time filtering.
    Uses either period-based (--day/--week/--month) or explicit datetime (--since/--until) filtering.
    """
    # Check for mutual exclusivity
    has_period = args.day or args.week or args.month
    has_datetime = args.since or args.until

    if has_period and has_datetime:
        die("Cannot use both period flags (--day/--week/--month) and datetime flags (--since/--until)")

    if has_datetime:
        conditions = []

        if args.since:
            since_dt = parse_datetime(args.since)
            conditions.append(sql.SQL("bt.first_start_time >= {since}").format(since=sql.Literal(since_dt)))

        if args.until:
            if not args.since:
                die(
                    "Please specify --since when --until is specified to avoid unbounded queries that might put high load on the database."
                )
            until_dt = parse_datetime(args.until)
            conditions.append(sql.SQL("bt.first_start_time < {until}").format(until=sql.Literal(until_dt)))

        return sql.SQL(" AND ").join(conditions)

    # Period mode (default to week)
    p = "month" if args.month else "day" if args.day else "week"
    return sql.SQL("bt.first_start_time > now() - ('1 {period}'::interval)").format(period=sql.SQL(p))


def normalize_duration(td: pd.Timedelta):
    c = td.components
    return (
        f"{c.days} days {c.hours:02d}:{c.minutes:02d}:{c.seconds:02d}"
        if c.days > 0
        else f"{c.hours:d}:{c.minutes:02d}:{c.seconds:02d}"
        if c.hours > 0
        else f"{c.minutes:d}:{c.seconds:02d}"
    )


def download_logs(output_dir: str, test_target: str, df: pd.DataFrame):
    """
    This function is invoked when --download-logs is specified for the 'last' subcommand.
    It downloads all logs of the test runs of the test_target in the given DataFrame
    and saves them to the specified output_dir. If output_dir is empty it defaults to "./logs_of_{test_name}_{timestamp}".
    """
    timestamp = datetime.now().isoformat(timespec="seconds")
    if output_dir == "":
        test_name = test_target.split(":")[-1]
        dir_name = f"logs_of_{test_name}_{timestamp}"
    else:
        dir_name = output_dir

    original_cwd = Path(os.environ.get("BUILD_WORKING_DIRECTORY", Path.cwd()))
    output_dir = original_cwd / dir_name

    output_dir.mkdir(parents=True, exist_ok=True)

    write_log_dir_readme(output_dir / "README.md", test_target, df, timestamp)

    print(f"Downloading logs to: {output_dir}", file=sys.stderr)

    # Collect all download tasks
    download_tasks = []
    for _ix, row in df.iterrows():
        url = row["buildbuddy_url"]

        invocation_id = row["invocation_id"]

        last_started_at = row["last_started_at"].strftime("%Y-%m-%dT%H:%M:%S")

        invocation_dir = output_dir / f"{last_started_at}_{invocation_id}"
        invocation_dir.mkdir(exist_ok=True)

        # Parse the BuildBuddy URL to extract base URL and invocation ID
        parsed = urllib.parse.urlparse(url)
        buildbuddy_base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Get all log URLs for this test run
        log_urls = get_all_buildbuddy_log_urls(buildbuddy_base_url, str(invocation_id), test_target)

        for attempt_num, download_url, attempt_status in log_urls:
            attempt_dir = invocation_dir / str(attempt_num)
            attempt_dir.mkdir(exist_ok=True)

            filename = f"{attempt_status}.log"
            filepath = attempt_dir / filename
            download_tasks.append((download_url, filepath, filename))

    if not download_tasks:
        print("No logs to download", file=sys.stderr)
    else:
        print(f"Downloading {len(download_tasks)} log files...", file=sys.stderr)

        # Download logs in parallel
        def download_log(task):
            download_url, filepath, filename = task
            try:
                response = requests.get(download_url, timeout=30, stream=True)
                if response.ok:
                    with open(filepath, "wb") as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    return True
                else:
                    print(f"Failed to download {filename}: HTTP {response.status_code}", file=sys.stderr)
                    return False
            except Exception as e:
                print(f"Error downloading {filename}: {e}", file=sys.stderr)
                return False

        # Use ThreadPoolExecutor to download in parallel (limit to 10 concurrent downloads)
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(download_log, download_tasks))

        successful = sum(results)
        print(f"Successfully downloaded {successful}/{len(download_tasks)} logs to {output_dir}", file=sys.stderr)


def write_log_dir_readme(readme_path: Path, test_target: str, df: pd.DataFrame, timestamp: datetime.timestamp):
    """
    Write a nice README.md in the log output directory describing the //ci/githubstats:query invocation
    that was used to generate the log output directory. This is useful when the invocation has to be redone or tweaked later.
    """
    colalignments = [
        ("last started at (UTC)", "right"),
        ("duration", "right"),
        ("status", "left"),
        ("branch", "left"),
        ("PR", "left"),
        ("commit", "left"),
        ("buildbuddy_url", "left"),
    ]

    cmd = shlex.join(["bazel", "run", "//ci/githubstats:query", "--", *sys.argv[1:]])
    columns, alignments = zip(*colalignments)
    table_md = tabulate(df[list(columns)], headers="keys", tablefmt="github", colalign=["decimal"] + list(alignments))
    readme = f"""Logs of `{test_target}`
===
Generated at {timestamp} using:
```
{cmd}
```
{table_md}
"""
    readme_path.write_text(readme)


def get_all_buildbuddy_log_urls(buildbuddy_base_url: str, invocation_id: str, test_target: str) -> list:
    """
    Get all log download URLs from BuildBuddy using its protobuf API.

    Args:
        buildbuddy_base_url: Base URL like "https://dash.dm1-idx1.dfinity.network"
        invocation_id: The invocation UUID like "7ba81d70-..."
        test_target: The Bazel test target like "//rs/tests/consensus/upgrade:upgrade_downgrade_nns_subnet_test"

    Returns:
        List of tuples: [(attempt_number, download_url, attempt_status), ...]
        where attempt_status is "PASSED" or "FAILED"

    """

    try:
        target_request = target_pb2.GetTargetRequest()
        target_request.invocation_id = invocation_id
        target_request.target_label = test_target

        response = requests.post(
            f"{buildbuddy_base_url}/rpc/BuildBuddyService/GetTarget",
            headers={"Content-Type": "application/proto"},
            data=target_request.SerializeToString(),
            timeout=10,
        )

        if not response.ok:
            return []

        # Parse the protobuf response
        target_response = target_pb2.GetTargetResponse()
        target_response.ParseFromString(response.content)

        # Collect all log URLs with their attempt numbers and status
        log_urls = []

        for target_group in target_response.target_groups:
            for target in target_group.targets:
                if not target.HasField("test_summary"):
                    continue

                test_summary = target.test_summary

                # Collect failed attempts
                for attempt_num, file in enumerate(test_summary.failed, start=1):
                    if file.uri:
                        encoded_file_uri = urllib.parse.quote(file.uri, safe="")
                        download_url = f"{buildbuddy_base_url}/file/download?bytestream_url={encoded_file_uri}&invocation_id={invocation_id}"
                        log_urls.append((attempt_num, download_url, "FAILED"))

                # Collect passed attempts (continue numbering from failed attempts)
                start_num = len(test_summary.failed) + 1
                for attempt_num, file in enumerate(test_summary.passed, start=start_num):
                    if file.uri:
                        encoded_file_uri = urllib.parse.quote(file.uri, safe="")
                        download_url = f"{buildbuddy_base_url}/file/download?bytestream_url={encoded_file_uri}&invocation_id={invocation_id}"
                        log_urls.append((attempt_num, download_url, "PASSED"))

        return log_urls

    except Exception as e:
        print(f"Error calling BuildBuddy API: {e}", file=sys.stderr)
        return []


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
    if value is not None:
        if args.order_by in ("impact", "duration_p90"):
            try:
                value = pd.Timedelta(value).to_pytimedelta()
            except ValueError as e:
                die(f"Can't parse '{value}' to an interval because: {e}!")
        else:
            try:
                value = float(value)
            except ValueError:
                die(f"Can't parse '{value}' to a number!")

    order_by = sql.Identifier(args.order_by)

    query = sql.SQL((THIS_SCRIPT_DIR / "top.sql").read_text()).format(
        exclude=sql.Literal(args.exclude if args.exclude else ""),
        include=sql.Literal(args.include if args.include else ""),
        time_filter=get_time_filter(args),
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

    df["impact"] = df["impact"].apply(normalize_duration)
    df["duration_p90"] = df["duration_p90"].apply(normalize_duration)

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

    colalignments = [
        # (column, alignment)
        ("label", "left"),
        ("total", "decimal"),
        ("non_success", "decimal"),
        ("flaky", "decimal"),
        ("timeout", "decimal"),
        ("fail", "decimal"),
        ("non_success%", "decimal"),
        ("flaky%", "decimal"),
        ("timeout%", "decimal"),
        ("fail%", "decimal"),
        ("impact", "right"),
        ("duration_p90", "right"),
        ("owners", "left"),
    ]

    columns, alignments = zip(*colalignments)
    print(tabulate(df[list(columns)], headers="keys", tablefmt=args.tablefmt, colalign=["decimal"] + list(alignments)))


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
        time_filter=get_time_filter(args),
        only_prs=sql.Literal(args.prs),
        branch=sql.Literal(args.branch if args.branch else ""),
    )

    log_psql_query(args.verbose, query.as_string(), args.conninfo)

    with githubstats_db_cursor(args.conninfo, args.timeout) as cursor:
        cursor.execute(query)
        headers = [desc[0] for desc in cursor.description]
        df = pd.DataFrame(cursor, columns=headers)

    # We need to create links to the cluster-specific BuildBuddy service.
    # To get the cluster-specific BuildBuddy URL we need to resolve the redirect via the BuildBuddy redirect service.
    # Since this I/O takes time we parallelize to speed it up by an order of magnitude.
    def direct_url_to_buildbuddy(invocation_id):
        url = f"https://dash.idx.dfinity.network/invocation/{invocation_id}"
        redirect = get_redirect_location(url)
        return f"{redirect}?target={args.test_target}" if redirect else url

    with ThreadPoolExecutor() as executor:
        df["buildbuddy_url"] = list(executor.map(direct_url_to_buildbuddy, df["invocation_id"]))

    df["buildbuddy_links"] = df["buildbuddy_url"].apply(lambda url: terminal_hyperlink("logs", url))

    # Turn the commit SHAs into terminal hyperlinks to the GitHub commit page
    df["commit_link"] = df["commit"].apply(
        lambda commit: terminal_hyperlink(commit[:7], f"https://github.com/{ORG}/{REPO}/commit/{commit}")
    )

    df["last started at (UTC)"] = df["last_started_at"].apply(lambda t: t.strftime("%a %Y-%m-%d %X"))

    df["branch_link"] = df["branch"].apply(
        lambda branch: terminal_hyperlink(branch, f"https://github.com/{ORG}/{REPO}/tree/{branch}")
    )

    df["PR_link"] = df["PR"].apply(
        lambda pr: terminal_hyperlink(f"#{pr}", f"https://github.com/{ORG}/{REPO}/pull/{pr}") if pr else ""
    )

    df["duration"] = df["duration"].apply(normalize_duration)

    colalignments = [
        # (column, header, alignment)
        ("last started at (UTC)", "last started at (UTC)", "right"),
        ("duration", "duration", "right"),
        ("status", "status", "left"),
        ("branch_link", "branch", "left"),
        ("PR_link", "PR", "left"),
        ("commit_link", "commit", "left"),
        ("buildbuddy_links", "buildbuddy", "left"),
    ]

    columns, headers, alignments = zip(*colalignments)
    print(
        tabulate(
            df[list(columns)], headers=list(headers), tablefmt=args.tablefmt, colalign=["decimal"] + list(alignments)
        )
    )

    if args.download_logs is not None:
        download_logs(args.download_logs, args.test_target, df)


# argparse formatter to allow newlines in --help.
class RawDefaultsFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawTextHelpFormatter):
    pass


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

    filter_parser.add_argument(
        "--since",
        metavar="DATETIME_OR_SHA",
        type=str,
        help="""Start of time range (inclusive). Can be a datetime (e.g., '2024-01-15' or '2024-01-15 14:30:00', assumed UTC)
or a git commit SHA (e.g., 'abc123def') from which the time is taken.
Mutually exclusive with --day/--week/--month""",
    )
    filter_parser.add_argument(
        "--until",
        metavar="DATETIME_OR_SHA",
        type=str,
        help="""End of time range (exclusive). Can be a datetime (e.g., '2024-01-15' or '2024-01-15 14:30:00', assumed UTC)
or a git commit SHA (e.g., 'def456abc') from which the time is taken.
When --until is specified, --since must also be specified to avoid unbounded queries.
Mutually exclusive with --day/--week/--month""",
    )

    filter_parser.add_argument("--prs", action="store_true", help="Only show test runs on Pull Requests")
    filter_parser.add_argument("--branch", metavar="B", type=str, help="Filter by branch SQL LIKE pattern")

    subparsers = parser.add_subparsers(required=True)

    ## top ####################################################################

    top_parser = subparsers.add_parser(
        "top",
        parents=[common_parser, filter_parser],
        formatter_class=RawDefaultsFormatter,
        help="Get the top non-successful / flaky / failed / timed-out tests in the last period",
        epilog="""
Examples:
  # Show the top 10 most flaky tests in the last week
  bazel run //ci/githubstats:query -- top 10 flaky% --week

  # Show the top 5 tests on PRs where failures had the highest impact in the last week
  bazel run //ci/githubstats:query -- top 5 impact --prs --week

  # Show the 100 slowest tests in the last month that took at least 30 minutes
  bazel run //ci/githubstats:query -- top 100 duration_p90 --ge '30 minutes' --month

  # Show tests in a specific date range
  bazel run //ci/githubstats:query -- top 20 fail% --since '2026-01-01' --until '2026-01-31'

  # Show the top 10 most impactful tests that ran since the time of a specific commit
  bazel run //ci/githubstats:query -- top 10 impact --since abc123def
""",
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
            "flaky",
            "timeout",
            "fail",
            "non_success%",
            "flaky%",
            "timeout%",
            "fail%",
            "impact",
            "duration_p90",
        ],
        help="""COLUMN to order by and have the condition flags like --gt, --ge, etc. apply to.

total:\t\tTotal runs in the specified period
non_success:\tNumber of non-successful runs in the specified period
flaky:\t\tNumber of flaky runs in the specified period
timeout:\tNumber of timed-out runs in the specified period
fail:\t\tNumber of failed runs in the specified period
non_success%%:\tPercentage of non-successful runs in the specified period
flaky%%:\t\tPercentage of flaky runs in the specified period
timeout%%:\tPercentage of timed-out runs in the specified period
fail%%:\t\tPercentage of failed runs in the specified period
impact:\t\tnon_success * duration_p90. A rough estimate on the impact of failures
duration_p90:\t90th percentile duration of all runs in the specified period""",
    )

    condition_group = top_parser.add_mutually_exclusive_group()
    condition_group.add_argument("--gt", metavar="F", type=str, help="Only show tests where COLUMN > F")
    condition_group.add_argument("--ge", metavar="F", type=str, help="Only show tests where COLUMN >= F")
    condition_group.add_argument("--lt", metavar="F", type=str, help="Only show tests where COLUMN < F")
    condition_group.add_argument("--le", metavar="F", type=str, help="Only show tests where COLUMN <= F")
    condition_group.add_argument("--eq", metavar="F", type=str, help="Only show tests where COLUMN = F")

    top_parser.add_argument(
        "--owner", metavar="TEAM", type=str, help="Filter tests by owner (a regex for the GitHub username or team)"
    )

    top_parser.add_argument("--exclude", metavar="TEST", type=str, help="Exclude tests matching this SQL LIKE pattern")
    top_parser.add_argument(
        "--include", metavar="TEST", type=str, help="Include only tests matching this SQL LIKE pattern"
    )

    top_parser.set_defaults(func=top)

    ## last ###################################################################

    last_runs_parser = subparsers.add_parser(
        "last",
        parents=[common_parser, filter_parser],
        formatter_class=RawDefaultsFormatter,
        help="Get the last runs of the specified test in the given period",
        epilog="""
Examples:
  # Show the last flaky runs of the root_tests in the last week and download their logs
  bazel run //ci/githubstats:query -- last --flaky //rs/tests/node:root_tests --week --download-logs
  ...
  Downloading logs to: /ic/logs_of_root_tests_2026-02-06_16:09:27
  Downloading 40 log files...
  Successfully downloaded 40/40 logs to /ic/logs_of_root_tests_2026-02-06_16:09:27

  # Show all runs of a test in a specific date range
  bazel run //ci/githubstats:query -- last //rs/tests/nns:rent_subnet_test --since '2026-01-29 13:00' --until '2026-01-30'

  # Show all runs of a test since the time of a specific commit
  bazel run //ci/githubstats:query -- last //rs/tests/nns:rent_subnet_test --since abc123def
""",
    )
    last_runs_parser.add_argument("--success", action="store_true", help="Include successful runs")
    last_runs_parser.add_argument("--flaky", action="store_true", help="Include flaky runs")
    last_runs_parser.add_argument("--failed", action="store_true", help="Include failed runs")
    last_runs_parser.add_argument("--timedout", action="store_true", help="Include timed-out runs")

    last_runs_parser.add_argument(
        "--download-logs",
        nargs="?",
        const="",
        default=None,
        metavar="DIR",
        help="""Download all test logs to a local directory.
If DIR is not specified the directory will be `./logs_of_{test_name}_{timestamp}`
The directory will contain log files named like `{timestamp}_{invocation_id}/{attempt_num}/{attempt_status}.log`, for example:
2026-02-01T04:22:13_459bd6b8-a538-48d4-8644-363bbe64eb8f/1/FAILED.log
2026-02-01T04:22:13_459bd6b8-a538-48d4-8644-363bbe64eb8f/2/PASSED.log
2026-02-01T20:01:40_b1429b38-723e-4938-9bc5-470f08d624f1/1/FAILED.log
2026-02-01T20:01:40_b1429b38-723e-4938-9bc5-470f08d624f1/2/PASSED.log
and a README.md describing the test runs and the //ci/githubstats:query invocation that generated the logs.
""",
    )

    last_runs_parser.add_argument("test_target", type=str, help="Bazel label of the test target to get runs of")
    last_runs_parser.set_defaults(func=last)

    ###########################################################################

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
