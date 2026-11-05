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
#   MATERIALIZE       when set, first build the target with --remote_download_toplevel: under
#                     Build-without-the-Bytes (the Namespace RBE jobs) the outputs and runfiles of the
#                     target may only exist in the remote CAS, and bazel materializes such a file by
#                     re-running its action (a remote cache hit), which --check_up_to_date forbids.
set -euo pipefail

read -r -a bazel_args <<<"${BAZEL_ARGS:-}"
script="$RUNNER_TEMP/upload-artifacts.sh"

if [ -n "${MATERIALIZE:-}" ]; then
    bazel build "${bazel_args[@]}" --remote_download_toplevel "$TARGET"
fi

run_args=()
if [ "${CHECK_UP_TO_DATE:-}" = true ]; then
    run_args+=(--check_up_to_date)
fi
# Builds the target and writes a script that runs it (with BUILD_WORKSPACE_DIRECTORY set, like
# `bazel run` would) instead of running it here.
bazel run "${bazel_args[@]}" "${run_args[@]}" --script_path="$script" "$TARGET"
