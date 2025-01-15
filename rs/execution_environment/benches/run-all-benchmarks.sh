#!/usr/bin/env bash
set -ue
##
## Top-level script to run all execution and embedder benchmarks.
## Usage:
##     ./rs/execution_environment/benches/run-all-benchmarks.sh | tee summary.txt
##
## The best (minimum) results are located in the `*.min`` files in the current directory.
## These should be manually copied to `rs/execution_environment/benches/baseline/`.
## A summary of the results is printed to the standard output.
##

printf "%-12s := %s\n" \
    "REPEAT" "${REPEAT:=3}" >&2

RUN_BENCHMARK="${0%/*}/run-benchmark.sh"
[ -x "${RUN_BENCHMARK}" ] || (echo "Error accessing script: ${RUN_BENCHMARK}" >&2 && exit 1)
SUMMARIZE_RESULTS="${0%/*}/summarize-results.sh"
[ -x "${SUMMARIZE_RESULTS}" ] || (echo "Error accessing script: ${SUMMARIZE_RESULTS}" >&2 && exit 1)

run() {
    local i="${1}"
    local name="${2}"
    local bench="${3}"
    # File with best (min) results.
    local min_file="${4}"
    local filter="${5:-}"

    # Counter file tracks the number of benchmark executions so far.
    counter_file="${min_file%.*}.counter"
    counter=$(cat "${counter_file}" 2>/dev/null || echo "0")
    [ -f "${min_file}" ] || counter="0"
    # Execute benchmark if needed.
    if [ "${counter}" -lt "${i}" ]; then
        echo "==> Running ${name} benchmarks ($((counter + 1)) of ${REPEAT})" >&2
        BENCH="${bench}" MIN_FILE="${min_file}" FILTER="${filter}" "${RUN_BENCHMARK}"
        echo "$((counter + 1))" >"${counter_file}"
    fi
    # Summarize results if the benchmark was executed or if it's the final iteration.
    if [ "${counter}" -lt "${i}" -o "${i}" = "${REPEAT}" ]; then
        echo "==> Summarizing ${name} results:" >&2
        set +e
        NAME="${name}" MIN_FILE="${min_file}" "${SUMMARIZE_RESULTS}"
        local ret="${?}"
        set -e
        # Stop repeating the benchmark if there are no changes.
        [ "${ret}" -eq 0 ] && echo "${REPEAT}" >"${counter_file}"
    fi
}

for i in $(seq 1 "${REPEAT}"); do
    run "${i}" "Embedders Compilation" \
        "//rs/embedders:compilation_bench" "EMBEDDERS_COMPILATION.min"
    run "${i}" "Embedders Heap" \
        "//rs/embedders:heap_bench" "EMBEDDERS_HEAP.min"
    run "${i}" "Embedders Stable Memory" \
        "//rs/embedders:stable_memory_bench" "EMBEDDERS_STABLE_MEMORY.min"
    run "${i}" "System API Inspect Message" \
        "//rs/execution_environment:execute_inspect_message_bench" "SYSTEM_API_INSPECT_MESSAGE.min"
    run "${i}" "System API Query" \
        "//rs/execution_environment:execute_query_bench" "SYSTEM_API_QUERY.min"
    run "${i}" "System API Update" \
        "//rs/execution_environment:execute_update_bench" "SYSTEM_API_UPDATE.min"
    run "${i}" "Wasm Instructions" \
        "//rs/execution_environment:wasm_instructions_bench" "WASM_INSTRUCTIONS.min"
done
