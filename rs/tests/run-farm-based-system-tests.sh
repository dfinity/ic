#!/usr/bin/env bash
set -eExou pipefail

function usage() {
    cat <<EOF
Usage:
  run-farm-based-system-tests.sh [--git-use-current-branch] {test-driver-arguments}

  Run upgraded system tests [farm-based].

  --git-use-current-commit
    
    Test with the artifacts of the current commit.

    This requires the commit to be built by CI/CD. I.e., it must be pushed to
    origin and a corresponding MR has to be created. If the script can't find
    artifacts for the current commit, it will fail.

    Note: If you just want to test with the newest artifacts available for a
    particular branch, you can do that by setting the TEST_BRANCH environment
    variable.
    E.g.,
    
      $ TEST_BRANCH=origin/my_other_branch ./run-farm-based-system-tests.sh ...

  --help

    Displays this help message and the help-message of test driver.
EOF
}

if [[ ${TMPDIR-/tmp} == /run/* ]]; then
    echo "Running in nix-shell on Linux, unsetting TMPDIR"
    export TMPDIR=
fi

SHELL_WRAPPER=${SHELL_WRAPPER:-/usr/bin/time}
CI_PROJECT_DIR=${CI_PROJECT_DIR:-"$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../"}
RESULT_FILE="${CI_PROJECT_DIR}/test-results.json"
JOB_ID="${CI_JOB_ID:-}"

if [[ -z "${JOB_ID}" ]]; then
    ARTIFACT_DIR="$(mktemp -d)/artifacts"
    JOB_ID="$(whoami)-$(hostname)-$(date +%s)"
    RUN_CMD="cargo"
    ADDITIONAL_ARGS=(run --bin prod-test-driver --)
else
    ARTIFACT_DIR="artifacts"
    RUN_CMD="${ARTIFACT_DIR}/prod-test-driver"
fi

echo "Storing artifacts in: ${ARTIFACT_DIR}"

# Parse arguments
# if --help is provided, print both, the usage of this script and the help of
# the test-driver
for arg in "$@"; do
    if [ "$arg" == "--help" ]; then
        usage
        $SHELL_WRAPPER "${RUN_CMD}" "${ADDITIONAL_ARGS[@]}" "--help"
        exit 0
    fi
    if [ "$arg" == "--git-use-current-commit" ]; then
        GIT_REVISION=$(git log --pretty=format:'%H' -n 1)
    else
        RUNNER_ARGS+=("$arg")
    fi
done

if [ -z "${GIT_REVISION:-}" ]; then
    TEST_BRANCH="${TEST_BRANCH:-origin/master}"
    echo "Using newest artifacts from branch $TEST_BRANCH"

    SCRIPT="$CI_PROJECT_DIR/gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh"
    GIT_REVISION=$("$SCRIPT" "$TEST_BRANCH")
    export GIT_REVISION
fi

if [ -z "${SSH_KEY_DIR:-}" ]; then
    SSH_KEY_DIR=$(mktemp -d)
    # Prepare admin key
    echo "Preparing default ssh key for admin."
    ssh-keygen -t ed25519 -N '' -f "$SSH_KEY_DIR/admin"
fi

RCLONE_ARGS=("--git-rev" "$GIT_REVISION" "--out=$ARTIFACT_DIR" "--unpack" "--mark-executable")
# prod-test-driver and (NNS) canisters
"${CI_PROJECT_DIR}"/gitlab-ci/src/artifacts/rclone_download.py --remote-path=canisters "${RCLONE_ARGS[@]}"
"${CI_PROJECT_DIR}"/gitlab-ci/src/artifacts/rclone_download.py --remote-path=release "${RCLONE_ARGS[@]}"

ls -R "$ARTIFACT_DIR"

# Make prod-test-driver available on the path
export PATH="$ARTIFACT_DIR:${PATH}"

# Make guest OS build scripts available
export PATH="${CI_PROJECT_DIR}/ic-os/guestos/scripts:$PATH"

# Download sha256 sum for revision
DEV_IMG_BASE_URL="https://download.dfinity.systems/ic/${GIT_REVISION}/guest-os/disk-img-dev/"
DEV_IMG_URL="${DEV_IMG_BASE_URL}disk-img.tar.gz"
DEV_IMG_SHA256_URL="${DEV_IMG_BASE_URL}SHA256SUMS"
DEV_IMG_SHA256=$(curl "${DEV_IMG_SHA256_URL}" | sed -E 's/^([0-9a-fA-F]+)\s.*/\1/')

{
    $SHELL_WRAPPER "${RUN_CMD}" \
        "${ADDITIONAL_ARGS[@]}" \
        "${RUNNER_ARGS[@]}" \
        --job-id "${JOB_ID}" \
        --initial-replica-version "$GIT_REVISION" \
        --base-img-url "${DEV_IMG_URL}" \
        --base-img-sha256 "${DEV_IMG_SHA256}" \
        --nns-canister-path "${ARTIFACT_DIR}" \
        --authorized-ssh-accounts "${SSH_KEY_DIR}" \
        --result-file "${RESULT_FILE}" 2>&1
} && RES=0 || RES=$?

# Export spans to Honeycomb if the script is run by a CI pipeline.
if [[ -n "${CI_JOB_ID:-}" ]] && [[ -n "${ROOT_PIPELINE_ID:-}" ]]; then
    python3 "${CI_PROJECT_DIR}/gitlab-ci/src/test_spans/exporter.py" \
        --runtime_stats "${RESULT_FILE}" \
        --trace_id "${ROOT_PIPELINE_ID}" \
        --parent_id "${CI_JOB_ID}" \
        --type "farm-based-tests"
fi

exit $RES
