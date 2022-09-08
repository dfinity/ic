#!/usr/bin/env bash

set -exuo pipefail

cd "${CI_PROJECT_DIR}/rs"
# Setup PATH
TMP_DIR=$(mktemp -d)
for f in "${CI_PROJECT_DIR}"/artifacts/release/*.gz; do
    target=$(basename "$f" .gz)
    gunzip -c -d "$f" >"${TMP_DIR}/$target"
    chmod +x "${TMP_DIR}/$target"
done

for f in "${CI_PROJECT_DIR}"/artifacts/release-malicious/*.gz; do
    target=$(basename "$f" .gz)
    gunzip -c -d "$f" >"${TMP_DIR}/$target"
    chmod +x "${TMP_DIR}/$target"
done

gunzip -c -d "${CI_PROJECT_DIR}/artifacts/release/orchestrator.gz" >"${TMP_DIR}/orchestrator"
chmod +x "${TMP_DIR}/orchestrator"
export PATH="${TMP_DIR}:$PATH"

# shellcheck source=/dev/null
source "$CI_PROJECT_DIR/gitlab-ci/src/canisters/wasm-build-functions.sh"
export_wasm_canister_paths "${CI_PROJECT_DIR}/artifacts/canisters"

# Run system tests, writing its JSON output to disk to be uploaded to CI.
# Only tests that are being selected by test runner options are run.
# Note: due to the bash settings to fail on any error, we have to be very careful how we
# get the command exit status. If we don't collect the exit status properly, GitLab status
# will not be updated at the end of this script
"$SHELL_WRAPPER" nix-shell --run "
  set -exuo pipefail
  system-tests $TEST_RUNNER_ARGS | tee ci_output.json
" && RES=0 || RES=$?
echo "System tests finished with exit code $RES"

# Export runtime statistics of system tests to Honeycomb.
python3 "${CI_PROJECT_DIR}"/gitlab-ci/src/test_results/honeycomb.py \
    --test_results "${CI_PROJECT_DIR}"/test-results.json \
    --trace_id "$ROOT_PIPELINE_ID" \
    --parent_id "$CI_JOB_ID" \
    --type "legacy-system-tests"

# Print a summary of system tests execution.
python3 "${CI_PROJECT_DIR}"/gitlab-ci/src/test_results/summary.py \
    --test_results "${CI_PROJECT_DIR}"/test-results.json

/usr/bin/time "${CI_PROJECT_DIR}/gitlab-ci/src/artifacts/collect_core_dumps.sh"

exit $RES
