#!/usr/bin/env bash
set -eEou pipefail

RED='\033[1;31m'
GREEN='\033[1;32m'
NC='\033[0m'

function log() {
    echo -e "${GREEN}System Tests $(date --iso-8601=seconds): $1${NC}"
}

function usage() {
    cat <<EOF
Usage:
  run-farm-based-system-tests.sh [--git-use-current-commit] {test-driver-arguments}

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
    log "Running in nix-shell on Linux, unsetting TMPDIR"
    export TMPDIR=
fi

SHELL_WRAPPER=${SHELL_WRAPPER:-/usr/bin/time}
CI_PROJECT_DIR=${CI_PROJECT_DIR:-"$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../"}
RESULT_FILE="$(mktemp -d)/test-results.json"

JOB_ID="${CI_JOB_ID:-}"
if [[ -z "${JOB_ID}" ]]; then
    # We run locally, not in CI
    ARTIFACT_DIR="$(mktemp -d)/artifacts"
    JOB_ID="$(whoami)-$(hostname)-$(date +%s)"
    RUN_CMD="cargo"
    ADDITIONAL_ARGS=(run --bin prod-test-driver --)
else
    # We assume that we are running on CI
    set -x
    ARTIFACT_DIR="artifacts"
    RUN_CMD="${ARTIFACT_DIR}/prod-test-driver"
fi

log "Artifacts will be stored in: ${ARTIFACT_DIR}"

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
    log "Downloading newest artifacts from branch ${RED}$TEST_BRANCH${NC}"

    SCRIPT="$CI_PROJECT_DIR/gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh"
    GIT_REVISION=$("$SCRIPT" "$TEST_BRANCH")
    export GIT_REVISION
fi

if [ -z "${SSH_KEY_DIR:-}" ]; then
    SSH_KEY_DIR=$(mktemp -d)
    # Prepare admin key
    log "Preparing default ssh key for admin."
    ssh-keygen -t ed25519 -N '' -f "$SSH_KEY_DIR/admin"
fi

JOURNALBEAT_HOSTS=()
if [ -n "${TEST_ES_HOSTNAMES:-}" ]; then
    JOURNALBEAT_HOSTS+=("--journalbeat-hosts" "${TEST_ES_HOSTNAMES//[[:space:]]/}")
fi

RCLONE_ARGS=("--git-rev" "$GIT_REVISION" "--out=$ARTIFACT_DIR" "--unpack" "--mark-executable")
# prod-test-driver and (NNS) canisters
log "Downloading dependencies built from commit: ${RED}$GIT_REVISION${NC}"
log "NOTE: Dependencies include canisters, rust-binaries (such as ic-rosetta-binaries), etc."
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
        --result-file "${RESULT_FILE}" \
        "${JOURNALBEAT_HOSTS[@]}" 2>&1
} && RES=0 || RES=$?

SUMMARY_ARGS=(--test_results "${RESULT_FILE}")
# Export spans to Honeycomb if the script is run by a CI pipeline.
if [[ -n "${CI_JOB_ID:-}" ]] && [[ -n "${ROOT_PIPELINE_ID:-}" ]]; then
    python3 "${CI_PROJECT_DIR}/gitlab-ci/src/test_results/honeycomb.py" \
        --test_results "${RESULT_FILE}" \
        --trace_id "${ROOT_PIPELINE_ID}" \
        --parent_id "${CI_JOB_ID}" \
        --type "farm-based-tests"
else
    SUMMARY_ARGS+=(--verbose)
fi

# Print a summary of the executed test suite.
python3 "${CI_PROJECT_DIR}/gitlab-ci/src/test_results/summary.py" "${SUMMARY_ARGS[@]}"

exit $RES
