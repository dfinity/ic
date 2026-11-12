#!/usr/bin/env bash
# Builds the artifact uploader TARGET with bazel and writes a script that runs it to
# $RUNNER_TEMP/upload-artifacts.sh. Run by ./.github/actions/upload-artifacts/action.yaml through one
# of the bazel actions, so `bazel` is that action's wrapper and the job's bazel server is used. The
# uploader itself is run by a later step, the only one whose environment holds the upload credentials.
#
# Environment:
#   TARGET               the uploader target, e.g. //:upload-artifacts
#   BAZEL_ARGS           options for the bazel run, whitespace separated: those of the job's build step
#   CHECK_UP_TO_DATE     'true' adds --check_up_to_date: bazel fails if any action would have to run, so
#                        exactly what the job's build step built gets uploaded
#   NO_EVICTION_RETRIES  when set (the Namespace RBE jobs), a blob lost by the remote cache fails the
#                        bazel run right away instead of being recovered, see below
set -euo pipefail

read -r -a bazel_args <<<"${BAZEL_ARGS:-}"
script="$RUNNER_TEMP/upload-artifacts.sh"

run_args=()
if [ "${CHECK_UP_TO_DATE:-}" = true ]; then
    run_args+=(--check_up_to_date)
fi
if [ -n "${NO_EVICTION_RETRIES:-}" ]; then
    # Under Build-without-the-Bytes the outputs of the build step may only exist in the remote cache.
    # bazel run downloads the outputs and runfiles of TARGET by the digests that the build step
    # recorded, and checks them. If the remote cache lost one of them, bazel would recover by
    # rerunning the action that produced it (action rewinding, see rbe.bazelrc) or the whole command
    # (rbe.bazelrc allows 10 retries) after dropping the recorded metadata of all remote outputs.
    # Either way --check_up_to_date would then fail with '... is not up-to-date', on that action or
    # on some unrelated one. Without both the bazel run fails on the lost output itself.
    run_args+=(--experimental_remote_cache_eviction_retries=0 --norewind_lost_inputs)
fi

# Builds the target and writes a script that runs it (with BUILD_WORKSPACE_DIRECTORY set, like
# `bazel run` would) instead of running it here.
status=0
bazel run "${bazel_args[@]}" "${run_args[@]}" --script_path="$script" "$TARGET" || status=$?
if [ "$status" -ne 0 ]; then
    # Exit code 1 is a build failure, which includes both failures that --check_up_to_date and the
    # missing retries cause; timeouts and command-line errors have their own codes and messages.
    if [ "$status" -eq 1 ] && [ "${CHECK_UP_TO_DATE:-}" = true ]; then
        echo "::error title=Uploader not built::bazel run --check_up_to_date $TARGET failed (see above). '... is not up-to-date': the job's build step didn't leave that action up to date, so a rerun fails the same way: fix the cause, keep check-up-to-date. 'Unexpected lost outputs': the remote cache lost an output of the build step: rerun the job."
    fi
    exit "$status"
fi
