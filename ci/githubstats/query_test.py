"""Tests of query.py downloading the logs of tests on RBE @ Namespace from GitHub artifacts, without network access."""

import contextlib
import datetime
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import query
import requests

TOKEN = "gho_test"
RBE_JOB = "bazel-test-all-rbe-bazel-test-1"
BAZEL_REMOTE_URL = "https://artifacts.zh1-idx1.dfinity.network/cas/0123abcd"


def make_zip(files: dict[str, bytes]) -> bytes:
    """Zip the files like actions/upload-artifact, which streams the zip and so writes data descriptors."""

    class Unseekable(io.RawIOBase):
        def __init__(self):
            self.data = bytearray()

        def writable(self):
            return True

        def write(self, b):
            self.data += b
            return len(b)

    out = Unseekable()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return bytes(out.data)


def response(status: int, content: bytes = b"", headers: dict = None) -> requests.Response:
    r = requests.Response()
    r.status_code = status
    r._content = content
    r._content_consumed = True
    r.headers.update(headers or {})
    return r


class FakeGitHub:
    """
    Fakes requests.get for GitHub's API, the Azure Blob Storage that GitHub redirects the download of artifacts to,
    BuildBuddy's redirect service and bazel-remote.
    """

    def __init__(self, artifacts: dict[tuple[int, str], bytes], logs: dict[str, bytes] = None):
        """Artifacts maps (run_id, artifact name) to its zip and logs maps other URLs to their content."""
        self.artifacts = dict(enumerate(artifacts.items()))  # artifact id -> ((run_id, name), zip)
        self.logs = logs or {}
        self.blob_url_version = {id: 0 for id in self.artifacts}  # Only the latest blob URL of an artifact is valid.
        self.api_calls = []
        self.blob_ranges = []
        self.buildbuddy_invocations = []
        self.violations = []
        self.ignore_ranges = False
        self.blob_urls_expire_immediately = False
        self.listing_error = None

    def check(self, condition: bool, violation: str):
        if not condition:
            self.violations.append(violation)
            raise AssertionError(violation)

    def expire_blob_urls(self):
        for id in self.blob_url_version:
            self.blob_url_version[id] += 1

    def get(self, url, params=None, headers=None, allow_redirects=True, timeout=None, stream=False):
        headers = headers or {}
        if url.startswith("https://api.github.com/"):
            self.check(headers.get("Authorization") == f"Bearer {TOKEN}", f"no token sent to {url}")
            self.api_calls.append(url)
            if m := re.fullmatch(r"https://api\.github\.com/repos/dfinity/ic/actions/runs/(\d+)/artifacts", url):
                if self.listing_error is not None:
                    return self.listing_error
                artifacts = [
                    {
                        "name": name,
                        "expired": False,
                        "size_in_bytes": len(data),
                        "archive_download_url": f"https://api.github.com/repos/dfinity/ic/actions/artifacts/{id}/zip",
                        "workflow_run": {"id": run_id},
                    }
                    for id, ((run_id, name), data) in self.artifacts.items()
                    if run_id == int(m[1]) and name == params["name"]
                ]
                return response(200, json.dumps({"total_count": len(artifacts), "artifacts": artifacts}).encode())
            if m := re.fullmatch(r"https://api\.github\.com/repos/dfinity/ic/actions/artifacts/(\d+)/zip", url):
                self.check(not allow_redirects, "the redirect to the whole zip is followed")
                id = int(m[1])
                self.blob_url_version[id] += 1
                return response(
                    302, headers={"Location": f"https://blob.example/{id}.zip?sig={self.blob_url_version[id]}"}
                )
        if m := re.fullmatch(r"https://blob\.example/(\d+)\.zip\?sig=(\d+)", url):
            self.check("Authorization" not in headers, "the token is sent to the blob storage")
            self.check(stream, "a blob is requested without stream=True")
            id, version = int(m[1]), int(m[2])
            data = self.artifacts[id][1]
            if self.blob_urls_expire_immediately or version != self.blob_url_version[id]:
                return response(403, headers={"x-ms-error-code": "AuthenticationFailed"})
            if self.ignore_ranges:
                return response(200, data)
            r = re.fullmatch(r"bytes=(\d+)-(\d+)", headers.get("Range", ""))
            self.check(r is not None, f"not an absolute range: {headers.get('Range')}")
            start, end = int(r[1]), int(r[2])
            self.check(start <= end < len(data), f"range {start}-{end} outside the {len(data)} bytes of the zip")
            self.blob_ranges.append((start, end))
            return response(206, data[start : end + 1], {"Content-Range": f"bytes {start}-{end}/{len(data)}"})
        if m := re.fullmatch(r"https://dash\.idx\.dfinity\.network/invocation/(.+)", url):
            self.buildbuddy_invocations.append(m[1])
            return response(308, headers={"Location": f"https://dash.zh1-idx1.dfinity.network/invocation/{m[1]}"})
        if url in self.logs:
            return response(200, self.logs[url])
        self.check(False, f"unexpected request to {url}")


class LogsArtifactTest(unittest.TestCase):
    FILES = {
        "rs/foo/flaky_test/test.cache_status": b"\x08\x02",
        "rs/foo/flaky_test/test.log": b"attempt 2 passed\n",
        "rs/foo/flaky_test/test.xml": b"<testsuites/>\n",
        "rs/foo/flaky_test/test_attempts/attempt_1.log": b"attempt 1 failed\n",
        "rs/foo/failed_test/test_attempts/attempt_1.log": b"attempt 1 failed\n",
        "rs/foo/failed_test/test_attempts/attempt_2.log": b"attempt 2 failed\n",
        "rs/foo/failed_test/test.log": b"attempt 3 failed\n",
        "rs/foo/bar/test.log": b"bar\n",
        "rs/foo/bar/baz/test.log": b"baz\n",
        "rs/http/public_integration_tests/test/test.log": b"a target name with a slash\n",
        "root/test.log": b"a target in the root package\n",
        "rs/foo/big_test/test.log": b"".join(b"line %d\n" % i for i in range(100_000)),
    }

    def open(self, fake: FakeGitHub, run_id: int = 1) -> query.LogsArtifact:
        with mock.patch.object(query.requests, "get", side_effect=fake.get):
            return query.open_logs_artifact(run_id, RBE_JOB, TOKEN)

    def read(self, fake: FakeGitHub, artifact: query.LogsArtifact, name: str) -> bytes:
        with mock.patch.object(query.requests, "get", side_effect=fake.get):
            return artifact.read(name)

    def test_reads_the_central_directory_and_each_file_with_one_request(self):
        fake = FakeGitHub({(1, f"{RBE_JOB}-logs"): make_zip(self.FILES)})
        artifact = self.open(fake)
        self.assertEqual(len(fake.api_calls), 2)  # The listing and the redirect.
        self.assertEqual(len(fake.blob_ranges), 1)
        self.assertEqual(str(artifact), f"the artifact {RBE_JOB}-logs of workflow run 1")
        for name, content in self.FILES.items():
            self.assertEqual(self.read(fake, artifact, name), content)
        self.assertEqual(len(fake.blob_ranges), 1 + len(self.FILES))
        self.assertEqual(len(fake.api_calls), 2)
        self.assertEqual(fake.violations, [])

    def test_central_directory_larger_than_the_tail(self):
        fake = FakeGitHub({(1, f"{RBE_JOB}-logs"): make_zip(self.FILES)})
        with mock.patch.object(query, "ZIP_TAIL_SIZE", 100):
            artifact = self.open(fake)
        self.assertEqual(len(fake.blob_ranges), 2)
        self.assertEqual(sorted(artifact.members), sorted(self.FILES))
        self.assertEqual(self.read(fake, artifact, "rs/foo/big_test/test.log"), self.FILES["rs/foo/big_test/test.log"])
        self.assertEqual(fake.violations, [])

    def test_no_artifact(self):
        fake = FakeGitHub({(1, f"{RBE_JOB}-logs"): make_zip(self.FILES)})
        self.assertIsNone(self.open(fake, run_id=2))
        self.assertEqual(len(fake.api_calls), 1)
        self.assertEqual(fake.blob_ranges, [])
        self.assertEqual(fake.violations, [])

    def test_renews_the_blob_url_once_when_it_expired(self):
        fake = FakeGitHub({(1, f"{RBE_JOB}-logs"): make_zip(self.FILES)})
        artifact = self.open(fake)
        fake.expire_blob_urls()
        self.assertEqual(self.read(fake, artifact, "rs/foo/bar/test.log"), b"bar\n")
        self.assertEqual(len(fake.api_calls), 3)

        fake.blob_urls_expire_immediately = True
        with self.assertRaisesRegex(RuntimeError, "HTTP 403 AuthenticationFailed"):
            self.read(fake, artifact, "rs/foo/bar/test.log")
        self.assertEqual(len(fake.api_calls), 4)
        self.assertEqual(fake.violations, [])

    def test_rejects_the_whole_zip_instead_of_a_range(self):
        fake = FakeGitHub({(1, f"{RBE_JOB}-logs"): make_zip(self.FILES)})
        artifact = self.open(fake)
        fake.ignore_ranges = True
        with self.assertRaisesRegex(RuntimeError, "HTTP 200"):
            self.read(fake, artifact, "rs/foo/bar/test.log")

    def test_errors_dont_reveal_the_blob_url(self):
        fake = FakeGitHub({(1, f"{RBE_JOB}-logs"): make_zip(self.FILES)})
        artifact = self.open(fake)

        def fail(url, **kwargs):
            raise requests.ConnectionError(f"Max retries exceeded with url: {url}")

        with mock.patch.object(query.requests, "get", side_effect=fail):
            with self.assertRaises(RuntimeError) as e:
                artifact.read("rs/foo/bar/test.log")
        self.assertNotIn("sig=", str(e.exception))
        self.assertIsNone(e.exception.__cause__)
        self.assertTrue(e.exception.__suppress_context__)

    def test_checks_the_crc(self):
        fake = FakeGitHub({(1, f"{RBE_JOB}-logs"): make_zip(self.FILES)})
        artifact = self.open(fake)
        artifact.members["rs/foo/bar/test.log"][0].CRC ^= 1
        with self.assertRaisesRegex(zipfile.BadZipFile, "rs/foo/bar/test.log"):
            self.read(fake, artifact, "rs/foo/bar/test.log")

    def test_finds_the_attempts_of_a_test(self):
        fake = FakeGitHub({(1, f"{RBE_JOB}-logs"): make_zip(self.FILES)})
        artifact = self.open(fake)

        def attempts(label, status):
            return [
                (attempt, member.name, attempt_status)
                for attempt, member, attempt_status in query.get_all_log_members_from_artifact(artifact, label, status)
            ]

        flaky = "rs/foo/flaky_test/"
        self.assertEqual(
            attempts("//rs/foo:flaky_test", "FLAKY"),
            [(1, flaky + "test_attempts/attempt_1.log", "FAILED"), (2, flaky + "test.log", "PASSED")],
        )
        failed = "rs/foo/failed_test/"
        self.assertEqual(
            attempts("//rs/foo:failed_test", "FAILED"),
            [
                (1, failed + "test_attempts/attempt_1.log", "FAILED"),
                (2, failed + "test_attempts/attempt_2.log", "FAILED"),
                (3, failed + "test.log", "FAILED"),
            ],
        )
        # The logs of //rs/foo:bar/baz are in a directory of //rs/foo:bar.
        self.assertEqual(attempts("//rs/foo:bar", "SUCCESS"), [(1, "rs/foo/bar/test.log", "PASSED")])
        self.assertEqual(attempts("//rs/foo:bar", "TIMEOUT"), [(1, "rs/foo/bar/test.log", "FAILED")])
        self.assertEqual(attempts("//rs/foo:bar/baz", "SUCCESS"), [(1, "rs/foo/bar/baz/test.log", "PASSED")])
        self.assertEqual(
            attempts("//rs/http:public_integration_tests/test", "SUCCESS"),
            [(1, "rs/http/public_integration_tests/test/test.log", "PASSED")],
        )
        self.assertEqual(attempts("//:root", "SUCCESS"), [(1, "root/test.log", "PASSED")])

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(attempts("//rs/foo:missing_test", "FAILED"), [])
            self.assertEqual(attempts("//rs/foo:bar", "FLAKY"), [(1, "rs/foo/bar/test.log", "PASSED")])
        self.assertEqual(
            stderr.getvalue().splitlines(),
            [
                f"No logs of //rs/foo:missing_test in {artifact}.",
                f"No failed attempts of the FLAKY //rs/foo:bar in {artifact}, only its last attempt.",
            ],
        )


class GitHubTokenTest(unittest.TestCase):
    def github_token(self, run, env=None):
        with (
            mock.patch.object(query.subprocess, "run", side_effect=run) as mocked_run,
            mock.patch.dict(os.environ, env or {}, clear=True),
        ):
            return query.github_token(), mocked_run

    def test_reuses_the_authentication_of_gh(self):
        token, run = self.github_token(
            lambda args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=f"{TOKEN}\n"), {"GH_TOKEN": "unused"}
        )
        self.assertEqual(token, TOKEN)
        self.assertEqual(run.call_args.args[0], ["gh", "auth", "token", "--hostname", "github.com"])

    def test_gh_is_not_logged_in(self):
        self.assertIsNone(self.github_token(subprocess.CalledProcessError(1, "gh"))[0])
        self.assertIsNone(self.github_token(subprocess.TimeoutExpired("gh", 10))[0])

    def test_gh_is_not_installed(self):
        not_installed = FileNotFoundError("gh")
        self.assertEqual(self.github_token(not_installed, {"GH_TOKEN": "a", "GITHUB_TOKEN": "b"})[0], "a")
        self.assertEqual(self.github_token(not_installed, {"GITHUB_TOKEN": "b"})[0], "b")
        self.assertIsNone(self.github_token(not_installed)[0])


# The columns of last.sql.
COLUMNS = [
    "first_start_time",
    "label",
    "duration",
    "status",
    "build_id",
    "head_branch",
    "pull_request_number",
    "head_sha",
    "run_id",
    "job_name",
    "cached",
]


def row(label: str, status: str, build_id: str, run_id: int, job_name: str, cached: bool = False) -> tuple:
    return (
        datetime.datetime(2026, 9, 30, 12, 0, tzinfo=datetime.timezone.utc),
        label,
        datetime.timedelta(seconds=77),
        status,
        build_id,
        "master",
        "",
        "604eae6c0a901032d22363b4607b0c13e9b1786c",
        run_id,
        job_name,
        cached,
    )


class FakeCursor:
    def __init__(self, rows: list[tuple]):
        self.rows = rows
        self.description = [(column,) for column in COLUMNS]

    def execute(self, query):
        pass

    def __iter__(self):
        return iter(self.rows)


def system_test_log(failure: list[dict]) -> bytes:
    """Return the log of an attempt of a system-test with the given failed tasks."""
    group = {"message": "Created new InfraProvider group", "group": "flaky-test--1"}
    report = {"test_name": "flaky_test", "success": [], "failure": failure, "skipped": []}
    return (
        "exec ${PAGER:-/usr/bin/less} \"$0\" || exit 1\n"
        f'2026-09-30 12:00:01.000 INFO[log_events.rs:20:9] {json.dumps({"event_name": "infra_group_name_created_event", "body": group})}\n'
        f'2026-09-30 12:00:02.000 INFO[log_events.rs:20:9] {json.dumps({"event_name": "json_report_created_event", "body": report})}\n'
    ).encode()


FAILED_SYSTEM_TEST_LOG = system_test_log([{"name": "test", "runtime": 1.5, "message": "boom"}])
PASSED_SYSTEM_TEST_LOG = system_test_log([])
FAILED_TEST_LOG = b"running 2 tests\ntest result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n"


class LastTest(unittest.TestCase):
    """Runs `last` on fake database rows."""

    def last(self, rows: list[tuple], *args: str, artifacts: dict = None, listing_error=None, token=TOKEN) -> dict:
        fake = FakeGitHub(artifacts or {}, {BAZEL_REMOTE_URL: FAILED_TEST_LOG})
        fake.listing_error = listing_error
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            tempfile.TemporaryDirectory() as cwd,
            mock.patch.dict(os.environ, {"BUILD_WORKING_DIRECTORY": cwd}),
            mock.patch.object(sys, "argv", ["query", "last", "--day", *args]),
            mock.patch.object(query, "githubstats_db_cursor", lambda *_: contextlib.nullcontext(FakeCursor(rows))),
            mock.patch.object(query, "github_token", return_value=token),
            mock.patch.object(query.requests, "get", side_effect=fake.get),
            mock.patch.object(query.requests, "post") as post,
            mock.patch.object(
                query, "get_all_log_urls_from_buildbuddy", return_value=[(1, BAZEL_REMOTE_URL, "FAILED")]
            ) as buildbuddy,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            query.main()
            # Leave out the directory named after the time of the download.
            files = {
                re.sub(r"^(logs/[^/]+)/[^/]+/", r"\1/<now>/", str(path.relative_to(cwd))): path.read_bytes()
                for path in Path(cwd).rglob("*")
                if path.is_file()
            }
        self.assertEqual(fake.violations, [])
        self.assertNotIn("sig=", stderr.getvalue())
        self.assertNotIn(TOKEN, stderr.getvalue() + stdout.getvalue())
        return {
            "fake": fake,
            "post": post,
            "buildbuddy": buildbuddy,
            "stdout": stdout.getvalue(),
            "stderr": stderr.getvalue(),
            "files": files,
        }

    def test_downloads_the_logs_of_tests_on_rbe_from_github(self):
        artifacts = {
            (1, f"{RBE_JOB}-logs"): make_zip(
                {
                    "rs/tests/foo/flaky_test_local/test_attempts/attempt_1.log": FAILED_SYSTEM_TEST_LOG,
                    "rs/tests/foo/flaky_test_local/test.log": PASSED_SYSTEM_TEST_LOG,
                    "rs/foo/other_test/test.log": b"other\n",
                }
            )
        }
        rows = [
            row("//rs/tests/foo:flaky_test_local", "FLAKY", "b1", 1, RBE_JOB),
            row("//rs/foo:cached_test", "SUCCESS", "b1", 1, RBE_JOB, cached=True),
            row("//rs/foo:old_test", "FLAKY", "b2", 2, RBE_JOB),
            row("//rs/foo:ci_main_test", "FAILED", "b3", 3, "bazel-test-all-__self_3"),
            row("//rs/foo:no_job_test", "FAILED", "b4", 4, None),
        ]
        result = self.last(rows, "--download-ic-logs", artifacts=artifacts)

        invocation = "2026-09-30T12:00:00"
        self.assertEqual(
            result["files"],
            {
                f"logs/flaky_test_local/<now>/{invocation}_b1/1/FAILED.log": FAILED_SYSTEM_TEST_LOG,
                f"logs/flaky_test_local/<now>/{invocation}_b1/2/PASSED.log": PASSED_SYSTEM_TEST_LOG,
                f"logs/ci_main_test/<now>/{invocation}_b3/1/FAILED.log": FAILED_TEST_LOG,
                f"logs/no_job_test/<now>/{invocation}_b4/1/FAILED.log": FAILED_TEST_LOG,
            },
        )
        # Only the rows of other jobs use BuildBuddy.
        self.assertEqual(
            sorted(call.args[3] for call in result["buildbuddy"].call_args_list),
            ["//rs/foo:ci_main_test", "//rs/foo:no_job_test"],
        )
        self.assertEqual(sorted(result["fake"].buildbuddy_invocations), ["b3", "b4"])
        # The listings of both workflow runs, and the redirect of the one that has the artifact.
        self.assertEqual(len(result["fake"].api_calls), 3)
        # No IC logs from ElasticSearch for the *_local system-test.
        result["post"].assert_not_called()

        stderr = result["stderr"]
        self.assertEqual(stderr.count("bazel took their result from the remote cache"), 1)
        self.assertIn("Not downloading the logs of 1 of the runs on RBE @ Namespace: bazel took their result", stderr)
        self.assertIn(
            "Not downloading the logs of 1 of the runs on RBE @ Namespace:"
            " 1 of their workflow runs have no <job_name>-logs artifact",
            stderr,
        )
        self.assertEqual(stderr.count("Not downloading IC logs from ElasticSearch"), 1)
        self.assertNotIn("Error downloading", stderr)
        self.assertNotIn("Could not open", stderr)

        stdout = result["stdout"]
        self.assertEqual(stdout.count("GitHub"), 3)
        self.assertEqual(stdout.count("BuildBuddy"), 2)
        self.assertIn("1: test: boom", stdout)
        self.assertIn("1: test result: FAILED. 1 passed; 1 failed;", stdout)

    def test_writes_a_readme_for_a_test_on_rbe(self):
        artifacts = {
            (7, f"{RBE_JOB}-logs"): make_zip({"rs/tests/foo/flaky_test_local/test.log": PASSED_SYSTEM_TEST_LOG})
        }
        result = self.last([row("//rs/tests/foo:flaky_test_local", "SUCCESS", "b1", 7, RBE_JOB)], artifacts=artifacts)
        readme = result["files"]["logs/flaky_test_local/<now>/README.md"].decode()
        self.assertIn("https://github.com/dfinity/ic/actions/runs/7/attempts/1", readme)
        self.assertIn("come from the `<job_name>-logs` artifact of their", readme)
        self.assertIn("| logs", readme)
        self.assertNotIn("buildbuddy", readme)

    def test_columns(self):
        result = self.last(
            [row("//rs/foo:ci_main_test", "FAILED", "b3", 3, "bazel-test-all-__self_3")],
            "--skip-download",
            "--columns",
            "logs",
        )
        self.assertIn("BuildBuddy", result["stdout"])
        self.assertEqual(result["fake"].api_calls, [])

    def test_prints_an_error_of_several_artifacts_once(self):
        rows = [
            row("//rs/tests/foo:flaky_test_local", "FLAKY", "b1", 1, RBE_JOB),
            row("//rs/tests/foo:flaky_test_local", "FAILED", "b2", 2, RBE_JOB),
        ]
        result = self.last(rows, listing_error=response(401, b'{"message": "Bad credentials"}'))
        self.assertEqual(
            [line for line in result["stderr"].splitlines() if line.startswith("Could not open")],
            [
                f"Could not open the artifact {RBE_JOB}-logs of https://github.com/dfinity/ic/actions/runs/1"
                """ and of 1 more workflow runs: listing the artifacts failed with HTTP 401: '{"message": "Bad credentials"}'"""
            ],
        )
        self.assertEqual(list(result["files"]), ["logs/flaky_test_local/<now>/README.md"])

    def test_no_token(self):
        result = self.last([row("//rs/tests/foo:flaky_test_local", "FLAKY", "b1", 1, RBE_JOB)], token=None)
        self.assertIn(
            "Not downloading the logs of 1 of the runs on RBE @ Namespace: they're in GitHub artifacts,"
            " which need a GitHub token. Log in with"
            " `gh auth login --hostname github.com --git-protocol ssh --skip-ssh-key --web` or set GH_TOKEN.",
            result["stderr"],
        )
        self.assertEqual(result["fake"].api_calls, [])

    def test_no_rows(self):
        result = self.last([])
        self.assertEqual(result["files"], {})
        self.assertEqual(result["fake"].api_calls, [])
        result["post"].assert_not_called()


if __name__ == "__main__":
    unittest.main()
