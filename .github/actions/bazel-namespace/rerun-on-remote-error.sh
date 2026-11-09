#!/usr/bin/env bash
# Runs a bazel command in the `run` input of ./.github/actions/bazel-namespace (action.yaml), and runs
# it once more when it fails with exit code 34.
#
# Bazel exits with 34 (REMOTE_ERROR) after a remote execution or caching error that it doesn't retry
# itself, like "Remote Execution Failure" or "UNAVAILABLE: connection error" from Namespace's RBE.
# From 2026-10-26 to 2026-11-09 that failed 4 of 92 master runs of bazel-test-all on RBE, 3 in the test
# step and 1 in the build step. Lost inputs don't end up here: action rewinding and
# --experimental_remote_cache_eviction_retries handle them (rbe.bazelrc).
#
# The rerun reuses what the first attempt built and the results of the tests that passed (action cache,
# remote cache), so it repeats the rest. It is skipped:
# * when the first attempt reported a FAILED test: an exit code 34 outranks test failures (3), and the
#   rerun would run the failed tests again with all their flaky attempts, which could hide the failure;
# * when less than 15 minutes of the action's timeout-minutes are left (BAZEL_NAMESPACE_DEADLINE), since
#   bin/bazel interrupts a rerun at that deadline anyway.
# It starts after a minute (RERUN_DELAY_SECONDS, for tests), so that the outage behind the error has a
# chance to end.
#
# Usage: rerun-on-remote-error.sh bazel COMMAND ARGS...

# Not -e, even when started with it: the exit code of the first attempt decides what happens next.
set +e -uo pipefail

if [ $# -lt 2 ]; then
    echo "usage: $0 bazel COMMAND ARGS..." >&2
    exit 2
fi

first_log="$(mktemp)"
# tee -i: an interrupt at the action's deadline must not break bazel's output, see action.yaml.
"$@" 2>&1 | tee -i "$first_log"
status="${PIPESTATUS[0]}"
if [ "$status" -ne 34 ]; then
    exit "$status"
fi

what="'$1 $2' failed with exit code 34, a remote execution or caching error at Namespace"
# A failed test in bazel's test summary, e.g. "//rs/foo:bar_test   FAILED in 3 out of 3 in 12.3s".
if grep -qE '^//[^ ]+ +FAILED in ' "$first_log"; then
    echo "::warning title=Bazel not rerun::$what, but tests failed too: not running it again."
    exit "$status"
fi
if [ -n "${BAZEL_NAMESPACE_DEADLINE:-}" ]; then
    remaining=$((BAZEL_NAMESPACE_DEADLINE - $(date +%s)))
    if [ "$remaining" -lt $((15 * 60)) ]; then
        echo "::warning title=Bazel not rerun::$what, but only $((remaining / 60)) minutes of the step's timeout are left: not running it again."
        exit "$status"
    fi
fi
delay="${RERUN_DELAY_SECONDS:-60}"
echo "::warning title=Bazel rerun::$what: running it once more in $delay seconds."
sleep "$delay"
"$@"
