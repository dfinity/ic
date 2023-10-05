#!/bin/sh -e
# Usage: run_wasm_benchmarks.sh [-f]
# Where:
#     -f force run benchmarks (do not use cache)

BAZEL_ARGS=${BAZEL_ARGS:=--warm-up-time 1 --sample-size 10 --measurement-time 1}
BAZEL_RUN_FILE="${0##*/}.bazel.run.tmp"
# Example content:
#   test wasm_instructions/i32_bin_op/i32.and ... bench:     3333486 ns/iter (+/- 78821)
RES_FILE="${0##*/}.res.tmp"
# Example content:
#   test wasm_instructions/i32_bin_op/i32.and/confirmation ... bench:     6553535 ns/iter (+/- 168333)
CONFIRMATION_RES_FILE="${0##*/}.confirmation.res.tmp"

# Run the benchmarks (or use the cached results).
[ -s "${BAZEL_RUN_FILE}" -a "${1}" != "-f" ] \
    || bazel run //rs/execution_environment:wasm_instructions_bench \
        -- --output-format bencher ${BAZEL_ARGS} | tee "${BAZEL_RUN_FILE}"

# Filter the results.
cat "${BAZEL_RUN_FILE}" | rg '^test wasm_' | rg -v '/confirmation' >"${RES_FILE}"
cat "${BAZEL_RUN_FILE}" | rg '^test wasm_' | rg '/confirmation' >"${CONFIRMATION_RES_FILE}"

# The "overhead" (0) is the smallest result.
overhead=$(cat "${RES_FILE}" | sort -nk 5 | head -1)
overhead_name=$(echo "${overhead}" | awk '{print $2}')
overhead_name="${overhead_name##*/}"
overhead_result=$(echo "${overhead}" | awk '{print $5}')

# The "baseline" (1) is the second smallest result.
baseline=$(cat "${RES_FILE}" | rg -Fv "${overhead_name}" | sort -nk 5 | head -1)
baseline_result=$(echo "${baseline}" | awk '{print $5}')

cat "${RES_FILE}" | while read _test name _ellipsis _bench result _rest; do
    short_name="${name#*/}"
    short_name="${short_name%-*}"

    K=$(((${result} - ${overhead_result}) / (${baseline_result} - ${overhead_result})))

    offset_name="${name#*-}"
    offset_name="${offset_name#${name}}"
    if [ -n "${offset_name}" ]; then
        offset_result=$(rg -wF "${offset_name}" ${RES_FILE} | head -1 | awk '{print $5}')
        # Use the diff only when $result is greater than $offset_result
        diff=$([ ${result} -gt ${offset_result} ] && echo "$((${result} - ${offset_result}))" || echo "0")
        COMMENT="= ${K} - ${offset_name}"
        K="$(((${diff}) / (${baseline_result} - ${overhead_result})))"
    else
        COMMENT=""
    fi

    confirmation_result=$(rg -wF "${name}" ${CONFIRMATION_RES_FILE} | awk '{print $5}')
    # If $confirmation_result is non-empty and $result is less than $confirmation_result*2/3 -> CONFIRMED
    COMMENT=$([ -n "${confirmation_result}" ] && [ "${result}" -lt "$((${confirmation_result} * 2 / 3))" ] && echo "${COMMENT}" || echo "OPTIMIZED?")
    # If $confirmation_result is empty -> UNCONFIRMED
    COMMENT=$([ -z "${confirmation_result}" ] && echo "UNCONFIRMED" || echo "${COMMENT}")
    # If $result equals $overhead_result -> OVERHEAD (0)
    COMMENT=$([ "${result}" = "${overhead_result}" ] && echo "OVERHEAD (0) ${COMMENT}" || echo "${COMMENT}")
    # If $result equals $baseline_result -> BASELINE (1)
    COMMENT=$([ "${result}" = "${baseline_result}" ] && echo "BASELINE (1) ${COMMENT}" || echo "${COMMENT}")
    printf "%-30s | %10s | %4s | | %s\n" "${short_name}" "${result}" "${K}" "${COMMENT}"
done
