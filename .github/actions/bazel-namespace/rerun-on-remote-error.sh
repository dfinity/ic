#!/usr/bin/env bash
# Runs a bazel command in the `run` input of ./.github/actions/bazel-namespace (action.yaml), and runs
# it once more when it fails with exit code 34.
#
# Bazel exits with 34 (REMOTE_ERROR) after a remote execution or caching error that it doesn't retry
# itself, like "Remote Execution Failure" or "UNAVAILABLE: connection error" from Namespace's RBE.
# From 2026-10-26 to 2026-11-09 that failed 4 of 92 master runs of bazel-test-all on RBE, 3 in the test
# step and 1 in the build step. Lost inputs don't end up here: action rewinding and
# --experimental_remote_cache_eviction_retries handle them (rbe.bazelrc). The rerun reuses what the
# first attempt completed (action cache, remote cache), so it only repeats what didn't complete.
# Both attempts count against the action's timeout-minutes: bin/bazel doesn't start the rerun when
# that has run out.
#
# Usage: rerun-on-remote-error.sh bazel COMMAND ARGS...
set -uo pipefail

if [ $# -lt 2 ]; then
    echo "usage: $0 bazel COMMAND ARGS..." >&2
    exit 2
fi

status=0
"$@" || status=$?
if [ "$status" -eq 34 ]; then
    echo "::warning title=Bazel rerun::'$1 $2' failed with exit code 34, a remote execution or caching error at Namespace: running it once more."
    status=0
    "$@" || status=$?
fi
exit "$status"
