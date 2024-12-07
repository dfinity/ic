#!/bin/sh -eu
##
## Top-level script to run all execution and embedder benchmarks.
## Usage:
##     ./rs/execution_environment/benches/run-all-benchmarks.sh
##

printf "%-12s := %s\n" \
    "REPEAT" "${REPEAT:=9}"

RUN_BENCHMARK="${0%/*}/run-benchmark.sh"
[ -x "${RUN_BENCHMARK}" ] || (echo "Error accessing script: ${RUN_BENCHMARK}" && exit 1)
SUMMARIZE_RESULTS="${0%/*}/summarize-results.sh"
[ -x "${SUMMARIZE_RESULTS}" ] || (echo "Error accessing script: ${SUMMARIZE_RESULTS}" && exit 1)

run() {
    local i="${1}"
    local name="${2}"
    local bench="${3}"
    local min_file="${4}"
    local filter="${5:-}"

    repeated_file="${min_file%.*}.repeated"
    repeated=$(cat "${repeated_file}" 2>/dev/null || echo "-1")
    [ "${repeated}" -eq "-1" ] && quick="yes" || quick="no"
    [ -f "${min_file}" ] || repeated="-1"
    if [ "${repeated}" -lt "${i}" ]; then
        echo "==> Running ${name} benchmarks ($((repeated + 1)) of ${REPEAT})"
        QUICK="${quick}" BENCH="${bench}" MIN_FILE="${min_file}" FILTER="${filter}" \
            "${RUN_BENCHMARK}"
        echo "$((repeated + 1))" >"${repeated_file}"
    fi
    if [ "${repeated}" -lt "${i}" -o "${i}" = "${REPEAT}" ]; then
        echo "==> Summarizing ${name} results:"
        NAME="${name}" MIN_FILE="${min_file}" "${SUMMARIZE_RESULTS}"
    fi
}

for i in $(seq 0 ${REPEAT}); do
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
        "//rs/execution_environment:wasm_instructions_bench" "WASM_INSTRUCTIONS.min" \
        "confirmation"
done
