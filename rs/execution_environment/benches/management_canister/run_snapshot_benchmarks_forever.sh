#!/bin/sh -e
# Continuously run the defined BENCHMARK and store the minimum results.
#
# Usage: run_benchmarks_forever.sh

DEPENDENCIES="bazel rg sed"
if ! which ${DEPENDENCIES} >/dev/null; then
    echo "Error checking dependencies: ${DEPENDENCIES} are required"
    exit 1
fi

# Benchmark command to run to generate benchmark results.
DEF_BENCHMARK="bazel run //rs/execution_environment:management_canister_bench -- \
    canister_snapshot --warm-up-time 1 --sample-size 10 --output-format=bencher"
BENCHMARK="${BENCHMARK:-${DEF_BENCHMARK}}"
# `rg`-expression to extract benchmark results form the command run log.
BENCH_RG="${BENCH_RG:-^test .* bench:}"
# `sed`-expression to extract unique benchmark name from each result.
BENCH_NAME_SED="${BENCH_NAME_SED:-s/^test( .+ )\.\.\. .*/\1/}"
# `sed`-expression to extract benchmark result from each result.
BENCH_RESULT_SED="${BENCH_RESULT_SED:-s/.* ([0-9]+) ns.*/\1/}"
# File with the minimum benchmark results.
MIN_FILE="${MIN_FILE:-${0##*/}.min.txt}"
# Markdown file.
MD_FILE="${MD_FILE:-${0##*/}.md}"
# Command run log.
LOG_FILE="${LOG_FILE:-${0##*/}.log}"
# A temporary file to merge the results.
TMP_FILE="${TMP_FILE:-${0##*/}.tmp}"

for i in $(seq 1000); do
    echo "==> $(date '+%Y-%m-%d %H:%M:%S') Iteration #${i}"

    echo "    Re-running all the benchmarks in ${LOG_FILE}..."
    ${BENCHMARK} >"${LOG_FILE}" 2>&1

    if ! [ -s "${MIN_FILE}" ]; then
        echo "    Setting the baseline in ${MIN_FILE}..."
        cat "${LOG_FILE}" | rg "${BENCH_RG}" >"${MIN_FILE}"
    else
        echo "    Merging the ${LOG_FILE} into ${MIN_FILE}..."
        rm -f "${TMP_FILE}"
        cat "${LOG_FILE}" | rg "${BENCH_RG}" | while read new_bench; do
            name=$(echo "${new_bench}" | sed -E "${BENCH_NAME_SED}")
            new_result=$(echo "${new_bench}" | sed -E "${BENCH_RESULT_SED}")

            matches=$(rg -wF "${name}" "${MIN_FILE}" | wc -l)
            if [ "${matches}" -gt 1 ]; then
                echo "Error matching ${matches} times ${name} in ${MIN_FILE}"
                exit 1
            fi
            min_bench=$(rg -F "${name}" "${MIN_FILE}" | head -1 || true)
            min_result=$(echo "${min_bench}" | sed -E "${BENCH_RESULT_SED}")

            if [ -n "${min_result}" ]; then
                if [ -n "${new_result}" -a "${new_result}" -lt "${min_result}" ]; then
                    echo "        ${name} is improved from ${min_result} to ${new_result}"
                    min_bench="${new_bench}"
                fi
            else
                # There is no min result, so just take the new one.
                min_bench="${new_bench}"
            fi
            echo "${min_bench}" >>"${TMP_FILE}"
        done
        echo "    Updating the min results in ${MIN_FILE}..."
        mv -f "${TMP_FILE}" "${MIN_FILE}" || (echo "Error finding benchmark results" && exit 1)
    fi

    echo "    Generating ${MD_FILE}..."
    rm -f "${MD_FILE}"
    printf "| %-60s | %-10s |\n" "Benchmark" "Result" >>"${MD_FILE}"
    printf "| %-60s | %-10s |\n" "---" "---" >>"${MD_FILE}"
    cat "${MIN_FILE}" | while read bench; do
        name=$(echo "${bench}" | sed -E "${BENCH_NAME_SED}")
        result_ns=$(echo "${bench}" | sed -E "${BENCH_RESULT_SED}")
        result_ms=$(echo "scale=2; ${result_ns}/1000000" | bc -l)

        printf "| %-60s | %-10s |\n" "${name}" "${result_ms} ms" >>"${MD_FILE}"
    done
done
