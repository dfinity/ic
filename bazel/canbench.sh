#!/bin/bash

# Runs canbench for benchmarking. Should only be invoked by bazel rules defined in canbench.bzl.
# Usage ./canbench.sh [--update]
# When --update is specified, the results file will be updated.
# Environment variables:
# - CANBENCH_BIN: Path to the canbench binary.
# - CANBENCH_RESULTS_PATH: Path to the results file, which will be:
#     - updated if --update is specified.
#     - used for comparison if it's not empty.
# - WASM_PATH: Path to the wasm file to be benchmarked.

set -eEuo pipefail

RUNFILES="$PWD"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
REPO_RESULTS_PATH="${REPO_PATH}/${CANBENCH_RESULTS_PATH}"
CANBENCH_OUTPUT=/tmp/canbench_output.txt

# Generates a canbench.yml dynamically to be used by canbench.
CANBENCH_YML="${RUNFILES}/canbench.yml"

echo "wasm_path:" >${CANBENCH_YML}
echo "  ${WASM_PATH}" >>${CANBENCH_YML}

if [ -s "${REPO_RESULTS_PATH}" ]; then
    echo "results_path:" >>${CANBENCH_YML}
    echo "  ${REPO_RESULTS_PATH}" >>${CANBENCH_YML}
fi

echo ${RUNFILES}

if [ $# -eq 0 ]; then
    # Runs the benchmark without updating the results file.
    ${CANBENCH_BIN}
elif [ "$1" = "--update" ]; then
    # Runs the benchmark while updating the results file.
    ${CANBENCH_BIN} --persist

    # Since we cannot specify an empty results file for the first time, we need to copy the default
    # results file to the desired location.
    if [ ! -s ${REPO_RESULTS_PATH} ]; then
        cp "${RUNFILES}/canbench_results.yml" "${REPO_RESULTS_PATH}"
    fi
else
    # Runs the benchmark test that fails if the diffs are new or above the threshold.
    ${CANBENCH_BIN} >$CANBENCH_OUTPUT
    if grep -q "(regress\|(improved by \|(new)" "$CANBENCH_OUTPUT"; then
        cat "$CANBENCH_OUTPUT"
        echo "**\`$REPO_RESULTS_PATH\` is not up to date ❌**
        If the performance change is expected, run \`_update\` target to save the updated benchmark results."
        exit 1
    else
        cat "$CANBENCH_OUTPUT"
        echo "**\`$REPO_RESULTS_PATH\` is up to date ✅**"
        exit 0
    fi
fi
