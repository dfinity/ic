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
  run-farm-based-system-tests.sh {test-driver-arguments}

  Run (Farm-based) system tests.

  --help

    Displays this help message and the help message of the test driver.


  Environment Variables:

  IC_VERSION_ID
    
    Defines the version of the default GuestOS image and other build artifacts
    (NNS canisters, ic-rosetta-api, etc.) used when executing the test.

    This requires the commit to be built by CI/CD. I.e., it must be pushed to
    origin and a corresponding MR has to be created. As of now, the version id
    must be fetched manually.

  Example: 
    
      $ IC_VERSION_ID=<a1ffee..> ./run-farm-based-system-tests.sh --suite hourly --include-pattern basic_health_test

EOF
}

cleanup_artifacts=true

if [[ ${TMPDIR-/tmp} == /run/* ]]; then
    log "Running in nix-shell on Linux, unsetting TMPDIR"
    export TMPDIR=
fi

SHELL_WRAPPER=${SHELL_WRAPPER:-/usr/bin/time}
CI_PROJECT_DIR=${CI_PROJECT_DIR:-"$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../"}

JOB_ID="${CI_JOB_ID:-}"
if [[ -z "${JOB_ID}" ]]; then
    # We run locally, not in CI
    ARTIFACT_DIR="$(mktemp -d)/artifacts"
    JOB_ID="$(whoami)-$(hostname)-$(date +%s)"
    RUN_CMD="cargo"
    ADDITIONAL_ARGS=(run --bin prod-test-driver --)
    RESULT_FILE="$(mktemp -d)/test-results.json"
else
    # We assume that we are running on CI
    set -x
    ARTIFACT_DIR="artifacts"
    RUN_CMD="${ARTIFACT_DIR}/prod-test-driver"
    cleanup_artifacts=false
    RESULT_FILE="${CI_PROJECT_DIR}/test-results.json"
fi

log "Artifacts will be stored in: ${ARTIFACT_DIR}"

# Call cleanup() when the user presses Ctrl+C
trap on_sigterm 2

on_sigterm() {
    log "Received SIGTERM ..."
    cleanup_dirs
    exit 1
}

cleanup_dirs() {
    if [[ "$cleanup_artifacts" == true ]]; then
        log "${RED}Removing artifacts directory: ${ARTIFACT_DIR}"
        rm -rf "$ARTIFACT_DIR"
    fi
}

# Parse arguments
# if --help is provided, print both, the usage of this script and the help of
# the test-driver
for arg in "$@"; do
    if [ "$arg" == "--help" ]; then
        usage
        $SHELL_WRAPPER "${RUN_CMD}" "${ADDITIONAL_ARGS[@]}" "--help"
        exit 0
    else
        RUNNER_ARGS+=("$arg")
    fi
done

if [ -z "${IC_VERSION_ID:-}" ]; then
    log "${RED}You must specify GuestOS image version via IC_VERSION_ID. You have two options:"
    log "${RED}1) To obtain a GuestOS image version for your commit, please push your branch to origin and create an MR. See http://go/guestos-image-version"
    log "${RED}2) To obtain the latest GuestOS image version for origin/master (e.g., if your changes are withing ic/rs/tests), use the following command: "
    log "${RED}   $ ic/gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh origin/master"
    log "${RED}   Note: this command is not guaranteed to be deterministic."
    exit 1
else
    log "Using GuestOS image version $IC_VERSION_ID"
fi

if [ -z "${SSH_KEY_DIR:-}" ]; then
    SSH_KEY_DIR=$(mktemp -d)
    # Prepare admin key
    log "Preparing default ssh key for admin."
    ssh-keygen -t ed25519 -N '' -f "$SSH_KEY_DIR/admin"
fi

if [ -z "${TEST_ES_HOSTNAMES:-}" ]; then
    TEST_ES_HOSTNAMES+="elasticsearch-node-0.testnet.dfinity.systems:443,"
    TEST_ES_HOSTNAMES+="elasticsearch-node-1.testnet.dfinity.systems:443,"
    TEST_ES_HOSTNAMES+="elasticsearch-node-2.testnet.dfinity.systems:443"
fi
JOURNALBEAT_HOSTS=("--journalbeat-hosts" "${TEST_ES_HOSTNAMES//[[:space:]]/}")

RCLONE_ARGS=("--git-rev" "$IC_VERSION_ID" "--out=$ARTIFACT_DIR" "--unpack" "--mark-executable")
# prod-test-driver and (NNS) canisters
if [[ -z "${JOB_ID}" || "${CI_PARENT_PIPELINE_SOURCE:-}" != "merge_request_event" ]]; then
    log "Downloading dependencies built from commit: ${RED}$IC_VERSION_ID"
    log "NOTE: Dependencies include canisters, rust-binaries (such as ic-rosetta-binaries), etc."
    "${CI_PROJECT_DIR}"/gitlab-ci/src/artifacts/rclone_download.py --remote-path=canisters "${RCLONE_ARGS[@]}"
    "${CI_PROJECT_DIR}"/gitlab-ci/src/artifacts/rclone_download.py --remote-path=release "${RCLONE_ARGS[@]}"
else
    # On CI, we have these dependencies as artifacts, but they are gzipped
    set +x
    for f in artifacts/canisters/*.gz; do
        mv "$f" "${ARTIFACT_DIR}"
        gunzip "${ARTIFACT_DIR}/$(basename "$f")"
    done
    for f in artifacts/release/*.gz; do
        mv "$f" "${ARTIFACT_DIR}"
        gunzip "${ARTIFACT_DIR}/$(basename "$f")"
        chmod +x "${ARTIFACT_DIR}/$(basename "$f" .gz)"
    done
    set -x
fi

ls -R "$ARTIFACT_DIR"

# Make prod-test-driver available on the path
export PATH="$ARTIFACT_DIR:${PATH}"

# Make guest OS build scripts available
export PATH="${CI_PROJECT_DIR}/ic-os/guestos/scripts:$PATH"

# Download sha256 sum for revision
DEV_IMG_BASE_URL="https://download.dfinity.systems/ic/${IC_VERSION_ID}/guest-os/disk-img-dev/"
DEV_IMG_URL="${DEV_IMG_BASE_URL}disk-img.tar.gz"
DEV_IMG_SHA256_URL="${DEV_IMG_BASE_URL}SHA256SUMS"
DEV_IMG_SHA256=$(curl "${DEV_IMG_SHA256_URL}" | sed -E 's/^([0-9a-fA-F]+)\s.*/\1/')

{
    $SHELL_WRAPPER "${RUN_CMD}" \
        "${ADDITIONAL_ARGS[@]}" \
        "${RUNNER_ARGS[@]}" \
        --job-id "${JOB_ID}" \
        --initial-replica-version "$IC_VERSION_ID" \
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
    echo "!!! NOTE: Logs from tests and unstructured stdout/err output is stored away with the gitlab-job-artifacts."
    echo "You can download the job artifacts by clicking the 'Download' button in the top right corner of the job"
    echo "view."
    # Push notifications to Slack for all failed pots, if a job is run periodically.
    if [[ ${CI_PIPELINE_SOURCE:-} == "schedule" ]]; then
        SUMMARY_ARGS+=(--slack_message "Pot \`{}\` *failed*. <${CI_JOB_URL:-}|log>. Commit: <${CI_PROJECT_URL:-}/-/commit/${CI_COMMIT_SHA:-}|${CI_COMMIT_SHORT_SHA:-}>.")
    fi
else
    SUMMARY_ARGS+=(--verbose)
fi

# Print a summary of the executed test suite.
# Do not propagate errors, if the script fails.
export PYTHONPATH="${CI_PROJECT_DIR}/gitlab-ci/src/notify_slack":"${PYTHONPATH:-}"
python3 "${CI_PROJECT_DIR}/gitlab-ci/src/test_results/summary.py" "${SUMMARY_ARGS[@]}" 1>&2 || true

cleanup_dirs

exit $RES
