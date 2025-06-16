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
# - NOISE_THRESHOLD: The noise threshold in percentage. If the difference between the current
#     benchmark and the results file is above this threshold, the benchmark test will fail.

set -eEuo pipefail

RUNFILES="$PWD"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
REPO_RESULTS_PATH="${REPO_PATH}/${CANBENCH_RESULTS_PATH}"
CANBENCH_OUTPUT="$(mktemp -t canbench_output.txt.XXXX)"
NOISE_THRESHOLD_ARG="${NOISE_THRESHOLD:+--noise-threshold ${NOISE_THRESHOLD}}"

# Generates a canbench.yml dynamically to be used by canbench.
CANBENCH_YML="${RUNFILES}/canbench.yml"

echo "wasm_path:" >${CANBENCH_YML}
echo "  ${WASM_PATH}" >>${CANBENCH_YML}

if [ -s "${REPO_RESULTS_PATH}" ]; then
    echo "results_path:" >>${CANBENCH_YML}
    echo "  ${REPO_RESULTS_PATH}" >>${CANBENCH_YML}
fi

if [ -n "${CANBENCH_INIT_ARGS_HEX:-}" ]; then
    echo "init_args:" >>${CANBENCH_YML}
    echo "  hex: ${CANBENCH_INIT_ARGS_HEX}" >>${CANBENCH_YML}
fi

if [ -s "${CANBENCH_STABLE_MEMORY_FILE:-}" ]; then
    TMP_MEMORY_FILE=$(mktemp -p . XXXXXXX.mem)
    if [[ "${CANBENCH_STABLE_MEMORY_FILE}" =~ [.]gz$ ]]; then
        gunzip -c "${CANBENCH_STABLE_MEMORY_FILE}" >"$TMP_MEMORY_FILE"
    else
        cp "${CANBENCH_STABLE_MEMORY_FILE}" "$TMP_MEMORY_FILE"
    fi
    echo "stable_memory:" >>${CANBENCH_YML}
    echo "  file: ${TMP_MEMORY_FILE}" >>${CANBENCH_YML}
fi

if [ $# -eq 0 ]; then
    # Runs the benchmark without updating the results file.
    ${CANBENCH_BIN} --no-runtime-integrity-check --runtime-path ${POCKET_IC_BIN} ${NOISE_THRESHOLD_ARG}
elif [ "$1" = "--update" ]; then
    # Runs the benchmark while updating the results file.
    ${CANBENCH_BIN} --no-runtime-integrity-check --runtime-path ${POCKET_IC_BIN} ${NOISE_THRESHOLD_ARG} --persist

    # Since we cannot specify an empty results file for the first time, we need to copy the default
    # results file to the desired location.
    if [ ! -s ${REPO_RESULTS_PATH} ]; then
        cp "${RUNFILES}/canbench_results.yml" "${REPO_RESULTS_PATH}"
    fi
elif [ "$1" = "--test" ]; then
    # Runs the benchmark test that fails if the diffs are new or above the threshold.
    ${CANBENCH_BIN} --no-runtime-integrity-check --runtime-path ${POCKET_IC_BIN} ${NOISE_THRESHOLD_ARG} >$CANBENCH_OUTPUT
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
elif [ "$1" = "--debug" ]; then
    ${CANBENCH_BIN} --no-runtime-integrity-check --runtime-path ${POCKET_IC_BIN} ${NOISE_THRESHOLD_ARG} --instruction-tracing
else
    echo "Unknown command: $1"
    exit 1
fi
