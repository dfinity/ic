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

# Whether to update the results file.
UPDATE=${1:-}

RUNFILES="$PWD"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
REPO_RESULTS_PATH="${REPO_PATH}/${CANBENCH_RESULTS_PATH}"

# Generates a canbench.yml dynamically to be used by canbench.
CANBENCH_YML="${RUNFILES}/canbench.yml"

echo "wasm_path:" >${CANBENCH_YML}
echo "  ${WASM_PATH}" >>${CANBENCH_YML}

if [ -s "${REPO_RESULTS_PATH}" ]; then
    echo "results_path:" >>${CANBENCH_YML}
    echo "  ${REPO_RESULTS_PATH}" >>${CANBENCH_YML}
fi

echo ${RUNFILES}

if [ -n "${UPDATE}" ]; then
    # Runs the benchmark while updating the results file.
    ${CANBENCH_BIN} --persist

    # Since we cannot specify an empty results file for the first time, we need to copy the default
    # results file to the desired location.
    if [ ! -s ${REPO_RESULTS_PATH} ]; then
        cp "${RUNFILES}/canbench_results.yml" "${REPO_RESULTS_PATH}"
    fi
else
    # Runs the benchmark without updating the results file.
    ${CANBENCH_BIN}
fi
