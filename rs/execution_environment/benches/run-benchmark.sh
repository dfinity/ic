#!/usr/bin/env bash
set -ue
##
## Helper script to run the specified `BENCH`
## and store the best (minimum) results in the `MIN_FILE`.
##

DEPENDENCIES="awk bash bazel rg sed tail tee"
which ${DEPENDENCIES} >/dev/null || (echo "Error checking dependencies: ${DEPENDENCIES}" >&2 && exit 1)

printf "    %-12s := %s\n" \
    "BENCH" "${BENCH:?Usage: BENCH='//rs/embedders:heap_bench' ${0}}" \
    "BENCH_ARGS" "${BENCH_ARGS:=--warm-up-time=1 --measurement-time=1 --output-format=bencher}" \
    "FILTER" "${FILTER:=}" \
    "MIN_FILE" "${MIN_FILE:=${0##*/}.min}" \
    "LOG_FILE" "${LOG_FILE:=${MIN_FILE%.*}.log}" >&2

TMP_FILE="${TMP_FILE:-${MIN_FILE%.*}.tmp}"

# Run the benchmark and capture its output in the `LOG_FILE`.
bash -c "set -o pipefail; \
    bazel run '${BENCH}' -- ${FILTER} ${BENCH_ARGS} \
        2>&1 | tee '${LOG_FILE}' | rg '^(test .* )?bench:' --line-buffered \
        | sed -uEe 's/^test (.+) ... bench: +/> bench: \1 /'" \
    || (
        echo "Error running the benchmark:"
        tail -10 "${LOG_FILE}" | sed 's/^/! /'
        echo "For more details see: ${LOG_FILE}"
        exit 1
    ) >&2

if ! [ -s "${MIN_FILE}" ]; then
    echo "    Storing results in ${MIN_FILE}" >&2
    cat "${LOG_FILE}" | rg "^test .* bench:" >"${MIN_FILE}" \
        || echo "    No results found in ${LOG_FILE}" >&2
else
    echo "    Merging ${LOG_FILE} into ${MIN_FILE}" >&2
    rm -f "${TMP_FILE}"
    cat "${LOG_FILE}" | rg "^test .* bench:" | while read new_bench; do
        name="${new_bench#test }"
        name="${name% ... bench:*}"
        new_result_ns="${new_bench#* ... bench: }"
        new_result_ns="${new_result_ns% ns/iter*}"

        min_bench=$(rg -F "test ${name} ... bench:" "${MIN_FILE}" || true)
        min_result_ns="${min_bench#* ... bench: }"
        min_result_ns="${min_result_ns% ns/iter*}"

        if [ -z "${min_result_ns}" ] || [ "${new_result_ns}" -lt "${min_result_ns}" ]; then
            echo "^ improved: ${name} time: $((new_result_ns / 1000)) µs"
            min_bench="${new_bench}"
        fi
        echo "${min_bench}" >>"${TMP_FILE}"
    done
    echo "    Updating results in ${MIN_FILE}" >&2
    mv -f "${TMP_FILE}" "${MIN_FILE}" 2>/dev/null || echo "    No results to update" >&2
fi
rm -f "${LOG_FILE}"
