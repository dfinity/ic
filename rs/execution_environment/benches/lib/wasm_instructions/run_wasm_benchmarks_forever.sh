#!/bin/sh -e
# Continuously improve `run_wasm_benchmarks_forever.md` file by running
# the `run_wasm_benchmarks.sh` and taking the minimum results. The produced
# file is a much more precise Wasm instructions costs report in Markdown format
# (see `WASM_BENCHMARKS.md`).
#
# Usage: run_wasm_benchmarks_forever.sh

if ! which bazel pee rg >/dev/null; then
    echo "Error checking dependencies: please ensure 'bazel', 'pee' and 'rg' are installed"
    exit 1
fi

# The file with final results.
#
# Example file content in Markdown format:
# | ibinop/i32.or | 2368404 | 1 | | BASELINE (1) |
MD_FILE="${0##*/}.md"

# The file with new benchmarks iteration results.
#
# Example file content in bencher format:
#   test wasm_instructions/i32_bin_op/i32.and ... bench:     3333486 ns/iter (+/- 78821)
NEW_RES_FILE="${MD_FILE%.md}.new.tmp"

# The file accumulating the minimum results of all benchmark iterations.
#
# Example file content in bencher format:
#   test wasm_instructions/i32_bin_op/i32.and ... bench:     3333486 ns/iter (+/- 78821)
MIN_RES_FILE="${MD_FILE%.md}.min.tmp"

# A temporary file to merge the current iteration with the accumulated minimum results.
MERGE_RES_FILE="${MD_FILE%.md}.merge.tmp"

# The scripts are expected to be in the same directory.
WASM_BENCHMARKS="${0%/*}/run_wasm_benchmarks.sh"

# The log file of the current benchmarks iteration.
WASM_BENCHMARKS_LOG_FILE="${0##*/}.log.tmp"

for i in $(seq 1000); do
    echo "==> $(date '+%Y-%m-%d %H:%M:%S') Iteration #${i}"

    echo "    Re-running all the benchmarks in ${WASM_BENCHMARKS_LOG_FILE}..."
    # Pass the `CACHE_FILE` so the new results will be stored there.
    CACHE_FILE="${NEW_RES_FILE}" "${WASM_BENCHMARKS}" -f >"${WASM_BENCHMARKS_LOG_FILE}" 2>&1

    if ! [ -s "${MIN_RES_FILE}" ]; then
        echo "    Setting the baseline in ${MIN_RES_FILE}..."
        mv "${NEW_RES_FILE}" "${MIN_RES_FILE}"
        continue
    fi

    echo "    Merging the ${NEW_RES_FILE} into ${MIN_RES_FILE}..."
    # Example `NEW_RES_FILE` and `MIN_RES_FILE` content in bencher format:
    #   test wasm_instructions/i32_bin_op/i32.and ... bench:     3333486 ns/iter (+/- 78821)
    rm -f "${MERGE_RES_FILE}"
    cat "${NEW_RES_FILE}" | while read test name ellipsis bench new_result rest; do
        min_result=$(rg -F " ${name} " "${MIN_RES_FILE}" | awk '{print $5}')
        if [ -n "${min_result}" ]; then
            if [ -n "${new_result}" -a "${new_result}" -lt "${min_result}" ]; then
                echo "        ${name#*/} is improved from ${min_result}ns to ${new_result}ns"
                min_result="${new_result}"
            fi
        else
            # There is no min result, so just take the new one.
            min_result="${new_result}"
        fi
        printf "${test} ${name} ${ellipsis} ${bench} ${min_result} ${rest}\n" >>"${MERGE_RES_FILE}"
    done

    echo "    Updating the results..."
    mv "${MERGE_RES_FILE}" "${MIN_RES_FILE}"

    echo "    Generating the new Markdown file..."
    # Pass the `CACHE_FILE` so the minimum results are used to generate the report.
    CACHE_FILE="${MIN_RES_FILE}" "${WASM_BENCHMARKS}" >"${MD_FILE}"
done
