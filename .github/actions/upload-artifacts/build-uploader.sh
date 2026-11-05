#!/usr/bin/env bash
# Builds the artifact uploader TARGET with bazel and writes a script that runs it to
# $RUNNER_TEMP/upload-artifacts.sh. Run by ./.github/actions/upload-artifacts/action.yaml through one
# of the bazel actions, so `bazel` is that action's wrapper and the job's bazel server is used. The
# uploader itself is run by a later step, the only one whose environment holds the upload credentials.
#
# Environment:
#   TARGET            the uploader target, e.g. //:upload-artifacts
#   BAZEL_ARGS        options for the bazel commands, whitespace separated: those of the job's build step
#   CHECK_UP_TO_DATE  'true' adds --check_up_to_date to the bazel run
#   MATERIALIZE       when set, first download the outputs and runfiles of the target: under
#                     Build-without-the-Bytes (the Namespace RBE jobs) they may only exist in the remote
#                     CAS, and bazel materializes such a file by re-running its action (a remote cache
#                     hit), which --check_up_to_date forbids. See materialize below.
set -euo pipefail

read -r -a bazel_args <<<"${BAZEL_ARGS:-}"
script="$RUNNER_TEMP/upload-artifacts.sh"

# Downloads the outputs and runfiles of the target without weakening the --check_up_to_date guarantee
# that exactly what the job's build step built gets uploaded:
# 1. --check_up_to_date in the default download mode downloads nothing and so only consults the action
#    cache: it proves that the build step built the whole closure of the target;
# 2. the download, with --remote_download_toplevel, may then only consist of remote cache hits. A
#    process of any other kind means that bazel executed an action, i.e. regenerated an output that the
#    remote cache had lost in the meantime, which may differ from the one the build step produced (and
#    build-determinism compared) for a non-reproducible action.
materialize() {
    bazel build "${bazel_args[@]}" --check_up_to_date "$TARGET"

    local log="$RUNNER_TEMP/materialize.log"
    bazel build "${bazel_args[@]}" --remote_download_toplevel "$TARGET" 2>&1 | tee "$log"
    # The summary line, e.g. "INFO: 7 processes: 5 remote cache hit, 2 internal." or "INFO: 0 processes.",
    # minus the kinds of processes that execute nothing (cache hits and internal actions like file writes).
    local executed
    executed="$(sed -E 's/\x1b\[[0-9;]*m//g' "$log" \
        | grep -E '^INFO: [0-9]+ process(es)?[:.]' | tail -n 1 \
        | sed -E 's/^INFO: [0-9]+ process(es)?[:.] ?//; s/[0-9]+ (remote cache hit|disk cache hit|action cache hit|internal)//g; s/[ ,.]//g')"
    if [ -n "$executed" ]; then
        echo "::error title=Artifacts regenerated::Downloading the outputs of $TARGET executed actions ($executed in the summary line above) instead of only hitting the remote cache, so they may differ from what the build step built. Rerun the job."
        exit 1
    fi
}

if [ -n "${MATERIALIZE:-}" ]; then
    materialize
fi

run_args=()
if [ "${CHECK_UP_TO_DATE:-}" = true ]; then
    run_args+=(--check_up_to_date)
fi
# Builds the target and writes a script that runs it (with BUILD_WORKSPACE_DIRECTORY set, like
# `bazel run` would) instead of running it here.
bazel run "${bazel_args[@]}" "${run_args[@]}" --script_path="$script" "$TARGET"
