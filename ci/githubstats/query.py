#!/usr/bin/env python3
#
# Run via:
#
#   bazel run //ci/githubstats:query -- --help
#
import argparse
import contextlib
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import codeowners
import dacite
import pandas as pd
import psycopg
import requests
from proto import target_pb2
from psycopg import sql
from tabulate import tabulate

THIS_SCRIPT_DIR = Path(__file__).parent

ORG = "dfinity"
REPO = "ic"

FAILED = "FAILED"
PASSED = "PASSED"


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


def download_and_process_logs(logs_base_dir, test_target: str, download_ic_logs: bool, df: pd.DataFrame):
    """
    Download the logs of all runs of test_target in the given DataFrame,
    save them to the specified logs_base_dir
    and annotate the DataFrame with error summaries from the downloaded logs.
    """
    original_cwd = Path(os.environ.get("BUILD_WORKING_DIRECTORY", Path.cwd()))
    test_name = test_target.split(":")[-1]
    timestamp = datetime.now().isoformat(timespec="seconds")
    output_dir = original_cwd / logs_base_dir / test_name / timestamp

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Downloading logs to: {output_dir}", file=sys.stderr)

    # Create a new column "error_summaries" in the DataFrame of type dict[int, SystemGroupSummary | str]
    # mapping the attempt number to either the SystemGroupSummary in case of a system-test
    # or the last line of the log for other tests.
    df["error_summaries"] = [{} for _ in range(len(df))]

    # Collect all download tasks
    download_tasks = []
    for _ix, row in df.iterrows():
        # Add a lock to each row for thread-safe updates when annotating the DataFrame with errors below
        row["lock"] = threading.Lock()

        buildbuddy_url = row["buildbuddy_url"]
        invocation_id = row["invocation_id"]
        last_started_at = row["last_started_at"].strftime("%Y-%m-%dT%H:%M:%S")
        invocation_dir = output_dir / f"{last_started_at}_{invocation_id}"

        # Parse the BuildBuddy URL to extract the cluster and its base URL for use with gRPC later.
        parsed_buildbuddy_url = urllib.parse.urlparse(buildbuddy_url)
        cluster = parsed_buildbuddy_url.netloc.split(".")[1]  # e.g., "dash.zh1-idx1.dfinity.network'" -> "zh1-idx1"
        buildbuddy_base_url = f"{parsed_buildbuddy_url.scheme}://{parsed_buildbuddy_url.netloc}"

        # Get all log URLs for this test run
        log_urls = get_all_log_urls_from_buildbuddy(buildbuddy_base_url, cluster, str(invocation_id), test_target)

        for attempt_num, download_url, attempt_status in log_urls:
            attempt_dir = invocation_dir / str(attempt_num)
            download_to_path = attempt_dir / f"{attempt_status}.log"
            download_tasks.append((row, attempt_num, attempt_status, download_url, attempt_dir, download_to_path))

    execute_download_tasks(download_tasks, test_target, output_dir, download_ic_logs, df)

    write_log_dir_readme(output_dir / "README.md", test_target, df, timestamp)


def get_all_log_urls_from_buildbuddy(
    buildbuddy_base_url: str, cluster: str, invocation_id: str, test_target: str
) -> list[tuple[int, str, str]]:
    """
    Get all log download URLs from BuildBuddy using its gRPC-based API.

    Args:
        buildbuddy_base_url: Base URL like "https://dash.dm1-idx1.dfinity.network"
        cluster: the IDX cluster like "dm1-idx1" from which bazel-remote we'll download the logs from.
        invocation_id: The Bazel invocation UUID like "7ba81d70-..."
        test_target: The Bazel test target like "//rs/tests/consensus/upgrade:upgrade_downgrade_nns_subnet_test"

    Returns:
        List of tuples: [(attempt_number, download_url, attempt_status), ...]
        where attempt_status is PASSED or FAILED

    """

    try:
        # See: https://github.com/buildbuddy-io/buildbuddy/blob/v2.241.0/proto/target.proto
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

                # See: https://github.com/buildbuddy-io/buildbuddy/blob/v2.241.0/proto/build_event_stream.proto
                test_summary = target.test_summary

                # Collect failed attempts
                for attempt_num, file in enumerate(test_summary.failed, start=1):
                    if file.uri:
                        log_urls.append((attempt_num, convert_download_url(file.uri, cluster), FAILED))

                # Collect passed attempts (continue numbering from failed attempts)
                start_num = len(test_summary.failed) + 1
                for attempt_num, file in enumerate(test_summary.passed, start=start_num):
                    if file.uri:
                        log_urls.append((attempt_num, convert_download_url(file.uri, cluster), PASSED))

        return log_urls

    except Exception as e:
        print(f"Error calling BuildBuddy API: {e}", file=sys.stderr)
        return []


def convert_download_url(uri, cluster) -> str:
    """
    The log URLs are retrieved from BuildBuddy like:

    "bytestream://bazel-remote.idx.dfinity.network/blobs/{hash}/{size}"

    We could download the log via BuildBuddy using the download_url:

        encoded_file_uri = urllib.parse.quote(uri, safe="")
        download_url = f"{buildbuddy_base_url}/file/download?bytestream_url={encoded_file_uri}&invocation_id={invocation_id}"

    However, to reduce the dependency on BuildBuddy,
    we download the log directly from our bazel-remote HTTP server at:

    "https://artifacts.{cluster}.dfinity.network/cas/{hash}"

    This has the additional benefit of getting 404 errors instead of 500
    for already garbage collected logs, which we can handle more gracefully.
    """
    parsed = urllib.parse.urlparse(uri)
    hash = parsed.path.split("/")[2]
    return f"https://artifacts.{cluster}.dfinity.network/cas/{hash}"


def execute_download_tasks(
    download_tasks: list, test_target: str, output_dir: Path, download_ic_logs: bool, df: pd.DataFrame
):
    print(f"Downloading {len(download_tasks)} log files...", file=sys.stderr)

    # This executor is used for downloading IC logs from ElasticSearch concurrently.
    # Limit to 10 concurrent downloads to not overwhelm ElasticSearch.
    with ThreadPoolExecutor(max_workers=10) as download_ic_log_executor:

        def download_log(task):
            row, attempt_num, attempt_status, download_url, attempt_dir, download_to_path = task
            shortened_path = download_to_path.relative_to(output_dir)
            try:
                response = requests.get(download_url, timeout=60, stream=True)
                if response.ok:
                    download_to_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(download_to_path, "wb") as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    # Fork a thread to process the log while the other logs are still downloading to speed up the whole process.
                    thread = threading.Thread(
                        target=process_log,
                        args=(
                            row,
                            test_target,
                            attempt_num,
                            attempt_status,
                            attempt_dir,
                            download_to_path,
                            df,
                            download_ic_logs,
                            download_ic_log_executor,
                        ),
                    )
                    thread.start()
                    return thread
                else:
                    error_line = shorten(response.text.split("\n")[0].strip(), 80)
                    msg = f"Download {download_url} to .../{shortened_path} failed with HTTP {response.status_code}: '{error_line}'."
                    if response.status_code == 404:
                        msg += " The log has probably already been garbage collected from the bazel-remote cache."
                    print(msg, file=sys.stderr)
                    return None
            except Exception as e:
                print(f"Error downloading {download_url} -> .../{shortened_path}: {e}", file=sys.stderr)
                return None

        # Download test logs concurrently.
        # Limit to 10 concurrent downloads to not overwhelm the bazel-remote HTTP server.
        with ThreadPoolExecutor(max_workers=10) as download_test_log_executor:
            threads = list(download_test_log_executor.map(download_log, download_tasks))

        # Wait for all annotation threads to finish.
        successes = 0
        for thread in threads:
            if thread is not None:
                successes += 1
                thread.join()

    # Render the error_summaries to human-readable form.
    df["errors"] = df["error_summaries"].apply(render_error_summaries)

    print(
        f"Successfully downloaded and processed {successes}/{len(download_tasks)} logs to {output_dir}",
        file=sys.stderr,
    )


TIMESTAMP_LEN = 23


def process_log(
    row: pd.Series,
    test_target: str,
    attempt_num: int,
    attempt_status: str,
    attempt_dir: Path,
    download_to_path: Path,
    df: pd.DataFrame,
    download_ic_logs: bool,
    download_ic_log_executor: ThreadPoolExecutor,
):
    """
    Process the log

    * Download IC logs from ElasticSearch in case of a system-test.
    * Annotate the DataFrame with a summary of the error(s).
    """

    last_seen_timestamp = None
    test_start_time = None
    group_name = None
    summary = None
    vm_ipv6s = {}

    # system-tests have structured logs with JSON objects that we can parse to get more detailed error summaries
    # and to determine the group (testnet) name for downloading the IC logs from ElasticSearch.
    # Non-system-tests just get annotated with the last line of the log which usually contains the error message.
    if test_target.startswith("//rs/tests/"):
        with open(download_to_path, 'r', encoding='utf-8') as f:
            for line in f:
                if len(line) < TIMESTAMP_LEN:
                    continue
                try:
                    # Here we try parsing a timestamp from the first 23 characters of a line
                    # assuming the line looks something like: "2026-02-03 13:55:09.645 INFO..."
                    last_seen_timestamp = datetime.strptime(line[:TIMESTAMP_LEN], "%Y-%m-%d %H:%M:%S.%f")
                except ValueError:
                    continue

                ix = line.find("{", TIMESTAMP_LEN)
                if ix == -1:
                    continue
                obj = line[ix:]

                try:
                    log_event = LogEvent.from_json(obj)
                    match log_event.event_name:
                        case "infra_group_name_created_event":
                            group_name = GroupName.from_dict(log_event.body).group
                            test_start_time = last_seen_timestamp
                        case "farm_vm_created_event":
                            farm_vm_created = FarmVMCreated.from_dict(log_event.body)
                            vm_ipv6s[farm_vm_created.vm_name] = farm_vm_created.ipv6
                        case "json_report_created_event":
                            summary = SystemGroupSummary.from_dict(log_event.body)
                            break
                except (ValueError, dacite.DaciteError):
                    continue

        if group_name is not None and download_ic_logs:
            # If it's a system-test, we want to download the IC logs from ElasticSearch to get more context on the failure.
            # We fork a thread for downloading the IC logs to speed up the whole process instead of doing it sequentially after downloading all test logs.
            download_ic_log_executor.submit(
                download_ic_logs_for_system_test,
                attempt_dir,
                group_name,
                test_start_time,
                last_seen_timestamp,
                vm_ipv6s,
            )
    else:
        # Efficiently get the last line of the log:
        parts = download_to_path.read_text().rstrip().rsplit(sep="\n", maxsplit=1)
        line = (parts[0] if len(parts) == 1 else parts[1]).lstrip()
        if line == "":
            line = None

    with row["lock"]:
        row["error_summaries"][attempt_num] = (
            summary if summary is not None else line if attempt_status == FAILED else None
        )


@dataclass
class DataClassJsonMixin:
    @classmethod
    def from_dict(cls, data: dict):
        return dacite.from_dict(data_class=cls, data=data, config=dacite.Config(strict=True))

    @classmethod
    def from_json(cls, json_str: str):
        try:
            value = json.loads(json_str)
            if not isinstance(value, dict):
                raise ValueError(f"Expected dict but got {type(value).__name__}: {value}")
            return cls.from_dict(value)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
        except dacite.DaciteError as e:
            raise ValueError(f"JSON does not match {cls.__name__} structure: {e}")


@dataclass
class LogEvent(DataClassJsonMixin):
    """Matches the Rust struct `ic_system_test_driver::log_events::LogEvent`"""

    event_name: str
    body: dict


@dataclass
class GroupName(DataClassJsonMixin):
    """Matches the Rust struct `ic_system_test_driver::driver::test_env_api::emit_group_event::GroupName`"""

    message: str
    group: str


@dataclass
class FarmVMCreated(DataClassJsonMixin):
    """Matches the Rust struct `ic_system_test_driver::driver::farm::FarmVMCreated`"""

    vm_name: str
    hostname: str
    ipv6: str
    v_cpus: int
    memory_ki_b: int


@dataclass
class TaskReport:
    """Matches the Rust struct `ic_system_test_driver::report::TaskReport`"""

    name: str
    runtime: float
    message: Optional[str]


@dataclass
class SystemGroupSummary(DataClassJsonMixin):
    """Matches the Rust struct `ic_system_test_driver::report::SystemGroupSummary`"""

    test_name: str
    success: List[TaskReport]
    failure: List[TaskReport]
    skipped: List[TaskReport]


def render_error_summaries(summaries: dict[int, SystemGroupSummary | str | None]) -> str:
    """
    Render the error summaries of all attempts to a human-readable string. For example:

    "1: upgrade_downgrade_nns_subnet: Replica did reboot, but never came back online!
        assert_no_replica_restarts: assertion `left == right` failed: The replica process on node 4q7mj-2koq2-vbcih-...
     2: upgrade_downgrade_nns_subnet: Replica did reboot, but never came back online!
        assert_no_replica_restarts: assertion `left == right` failed: The replica process on node l6edn-e5wfk-ooxb7-...
     3: upgrade_downgrade_nns_subnet: Replica did reboot, but never came back online!
        assert_no_replica_restarts: assertion `left == right` failed: The replica process on node yafn5-op57q-xfatj-..."
    """
    lines = []
    for attempt_num, summary in sorted(summaries.items()):
        summary_lines = render_error_summary(summary)
        if len(summary_lines) > 0:
            lines.append(
                f"{attempt_num}: {summary_lines[0]}"
                + (
                    "\n" + "\n".join([f"   {summary_line}" for summary_line in summary_lines[1:]])
                    if len(summary_lines[1:]) > 0
                    else ""
                )
            )
    return "\n".join(lines)


def render_error_summary(summary: SystemGroupSummary | str | None) -> list[str]:
    MAX_ERROR_LINE_LENGTH = 80

    if summary is None:
        return []

    if isinstance(summary, str):
        return [shorten(summary, MAX_ERROR_LINE_LENGTH)]

    return [
        f"{failed_task.name}: {shorten(failed_task.message.replace("\n", "\\n"), MAX_ERROR_LINE_LENGTH)}"
        for failed_task in summary.failure
    ]


def shorten(msg: str, max_length: int) -> str:
    if len(msg) > max_length:
        return msg[:max_length] + "..."
    return msg


def download_ic_logs_for_system_test(
    attempt_dir: Path,
    group_name: str,
    test_start_time: datetime,
    test_end_time: datetime,
    vm_ipv6s: dict[str, str],
):
    ic_logs_dir = attempt_dir / "ic_logs"
    ic_logs_dir.mkdir(exist_ok=True)

    elasticsearch_query = {
        "size": 10000,
        "query": {
            "bool": {
                "must": [
                    {"match_phrase": {"ic": group_name}},
                    {
                        "range": {
                            "timestamp": {
                                "gte": test_start_time.isoformat(),
                                "lte": test_end_time.isoformat(),
                            }
                        }
                    },
                ]
            }
        },
        "_source": ["MESSAGE", "ic_subnet", "ic_node", "timestamp"],
        # Sort by timestamp, using _doc as a tie-breaker for stable pagination.
        "sort": [{"timestamp": {"order": "asc", "format": "strict_date_optional_time_nanos"}}, {"_doc": "asc"}],
    }

    try:
        url = "https://elasticsearch.testnet.dfinity.network/testnet-vector-push-*/_search"
        params = {"filter_path": "hits.hits"}
        all_hits = []
        while True:
            response = requests.post(url, params=params, json=elasticsearch_query, timeout=60)

            if not response.ok:
                print(
                    f"Failed to download IC logs for {group_name}: {response.status_code} {response.text}",
                    file=sys.stderr,
                )
                return

            hits = response.json().get("hits", {}).get("hits", [])
            all_hits.extend(hits)

            if len(hits) < elasticsearch_query["size"]:
                break

            last_hit = hits[-1]
            elasticsearch_query["search_after"] = last_hit["sort"]

        logs_by_node = {}
        for hit in all_hits:
            if "_source" not in hit:
                continue
            source = hit["_source"]
            if "ic_node" not in source or "timestamp" not in source or "MESSAGE" not in source:
                continue
            node = source["ic_node"]
            try:
                timestamp = datetime.strptime(source["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                continue
            logs_by_node.setdefault(node, []).append((timestamp, source["MESSAGE"]))

        for node, messages in logs_by_node.items():
            log_file = ic_logs_dir / f"{node}.log"
            if node in vm_ipv6s:
                ipv6_symlink_path = ic_logs_dir / f"{vm_ipv6s[node]}.log"
                ipv6_symlink_path.symlink_to(log_file.name)
            log_file.write_text(
                "\n".join([f"{timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')} {msg}" for timestamp, msg in messages])
            )
            print(f"Downloaded {len(messages)} log entries for node {node} to {log_file}", file=sys.stderr)

    except requests.exceptions.RequestException as e:
        print(f"Error downloading IC logs for {group_name}: {e}", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON response for {group_name}: {e}", file=sys.stderr)


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
        lambda branch: terminal_hyperlink(shorten(branch, 16), f"https://github.com/{ORG}/{REPO}/tree/{branch}")
    )

    df["PR_link"] = df["PR"].apply(
        lambda pr: terminal_hyperlink(f"#{pr}", f"https://github.com/{ORG}/{REPO}/pull/{pr}") if pr else ""
    )

    df["duration"] = df["duration"].apply(normalize_duration)

    if not args.skip_download:
        download_and_process_logs(args.logs_base_dir, args.test_target, args.download_ic_logs, df)

    colalignments = [
        # (column, header, alignment)
        ("last started at (UTC)", "last started at (UTC)", "right"),
        ("duration", "duration", "right"),
        ("status", "status", "left"),
        ("branch_link", "branch", "left"),
        ("PR_link", "PR", "left"),
        ("commit_link", "commit", "left"),
        ("buildbuddy_links", "buildbuddy", "left"),
    ] + ([] if args.skip_download else [("errors", "errors per attempt", "left")])

    columns, headers, alignments = zip(*colalignments)
    print(
        tabulate(
            df[list(columns)], headers=list(headers), tablefmt=args.tablefmt, colalign=["decimal"] + list(alignments)
        )
    )


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

    top_parser.add_argument(
        "--tablefmt",
        metavar="FMT",
        type=str,
        default="mixed_outline",
        help="Table format. See: https://pypi.org/project/tabulate/",
    )

    ## last ###################################################################

    last_runs_parser = subparsers.add_parser(
        "last",
        parents=[common_parser, filter_parser],
        formatter_class=RawDefaultsFormatter,
        help="Get the last runs of the specified test in the given period",
        epilog="""
Examples:
  # Show the last flaky runs of the root_tests in the last week
  bazel run //ci/githubstats:query -- last --flaky //rs/tests/node:root_tests --week

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
        "--skip-download", action="store_true", help="Don't download logs of the runs, just show the table"
    )

    last_runs_parser.add_argument(
        "--download-ic-logs", action="store_true", help="Download IC logs from ElasticSearch for system-tests"
    )

    last_runs_parser.add_argument(
        "--logs-base-dir",
        metavar="DIR",
        type=str,
        default="logs",
        help="""Download the logs of all runs of test_target to {DIR}/{test_name}/{now}.
That directory will contain log files named like `{invocation_timestamp}_{invocation_id}/{attempt_num}/{attempt_status}.log`, for example:
logs
└── unstuck_subnet_test
    └── 2026-02-10T15:51:30
        ├── 2026-02-10T09:44:34_9e523887-572b-41e9-89e0-85db6cc6d307
        │   ├── 1
        │   │   ├── FAILED.log
        │   │   └── ic_logs    # Only available for system-tests when --download-ic-logs is specified
        │   │       ├── 2602:fb2b:110:10:5021:ccff:fe09:9c04.log -> eps42-sqcwm-mxa3t-v5udw-hvnhs-cpyhm-hlemr-rv5gn-ysojg-eo2tw-tqe.log
        │   │       ├── 2602:fb2b:110:10:5063:d6ff:fed9:84ea.log -> e57ej-6tme6-pisxz-6xhho-a5hag-xhqnm-ll6a6-ywghj-a4wes-yrmw6-iae.log
        │   │       ├── 2602:fb2b:110:10:506b:8ff:feca:8381.log -> oyqdk-jrqx2-rh2i4-myf6p-svq5r-erpyu-7iizo-fmjuk-oqmsp-rj4ua-bqe.log
        │   │       ├── 2602:fb2b:110:10:50dc:f7ff:fe99:e6e9.log -> uwls4-qoxto-stzfb-cmngz-ynygb-lf3fs-eahfe-l5bgs-koaw2-m6rum-3qe.log
        │   │       ├── e57ej-6tme6-pisxz-6xhho-a5hag-xhqnm-ll6a6-ywghj-a4wes-yrmw6-iae.log
        │   │       ├── eps42-sqcwm-mxa3t-v5udw-hvnhs-cpyhm-hlemr-rv5gn-ysojg-eo2tw-tqe.log
        │   │       ├── oyqdk-jrqx2-rh2i4-myf6p-svq5r-erpyu-7iizo-fmjuk-oqmsp-rj4ua-bqe.log
        │   │       └── uwls4-qoxto-stzfb-cmngz-ynygb-lf3fs-eahfe-l5bgs-koaw2-m6rum-3qe.log
        │   └── 2
        │       ├── PASSED.log
        │       └── ic_logs
        │           ├── 2602:fb2b:110:10:5027:50ff:fe3b:646f.log -> th33r-jxkvk-3cdru-fzrcc-w2smz-bnovv-a5jue-isjz5-ax4v6-au7tw-nqe.log
        │           ├── 2602:fb2b:110:10:5035:efff:fea1:fbf5.log -> flemd-fap2g-uohsu-ahgbv-sndvl-jvyzk-uytpv-4tazh-7jej7-bcqrn-mqe.log
        │           ├── 2602:fb2b:110:10:508a:3eff:fe00:8438.log -> xvyo4-ngkcp-sj6j5-yxh4i-pmc5b-6ev4k-64xbw-tmnid-epliz-s2woi-2ae.log
        │           ├── 2602:fb2b:110:10:50c4:e9ff:fe10:e4f1.log -> qmovl-k62dw-6z4ik-d4tn3-wwhlk-33rsp-7442w-52zjq-3yaxd-cqsee-gqe.log
        │           ├── flemd-fap2g-uohsu-ahgbv-sndvl-jvyzk-uytpv-4tazh-7jej7-bcqrn-mqe.log
        │           ├── qmovl-k62dw-6z4ik-d4tn3-wwhlk-33rsp-7442w-52zjq-3yaxd-cqsee-gqe.log
        │           ├── th33r-jxkvk-3cdru-fzrcc-w2smz-bnovv-a5jue-isjz5-ax4v6-au7tw-nqe.log
        │           └── xvyo4-ngkcp-sj6j5-yxh4i-pmc5b-6ev4k-64xbw-tmnid-epliz-s2woi-2ae.log
        └── README.md
""",
    )

    last_runs_parser.add_argument("test_target", type=str, help="Bazel label of the test target to get runs of")
    last_runs_parser.set_defaults(func=last)

    last_runs_parser.add_argument(
        "--tablefmt",
        metavar="FMT",
        type=str,
        default="fancy_grid",
        help="Table format. See: https://pypi.org/project/tabulate/",
    )

    ###########################################################################

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
