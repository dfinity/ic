#!/usr/bin/env bash
set -ue
##
## Helper script to run the specified `BENCH`
## and store the best (min) results in the `MIN_FILE`.
##

DEPENDENCIES="awk bash bazel rg sed tail tee"
which ${DEPENDENCIES} >/dev/null || (echo "Error checking dependencies: ${DEPENDENCIES}" && exit 1)

QUICK="${QUICK:-no}"
[ "${QUICK}" = "no" ] || BENCH_ARGS="--quick --output-format=bencher"

printf "    %-12s := %s\n" \
    "BENCH" "${BENCH:?Usage: BENCH='//rs/embedders:heap_bench' ${0}}" \
    "BENCH_ARGS" "${BENCH_ARGS:=--warm-up-time=1 --measurement-time=1 --output-format=bencher}" \
    "FILTER" "${FILTER:=}" \
    "MIN_FILE" "${MIN_FILE:=${0##*/}.min}" \
    "LOG_FILE" "${LOG_FILE:=${MIN_FILE%.*}.log}"

TMP_FILE="${TMP_FILE:-${MIN_FILE%.*}.tmp}"

bash -c "set -o pipefail; \
    bazel run '${BENCH}' -- ${FILTER} ${BENCH_ARGS} \
        2>&1 | tee '${LOG_FILE}' | rg '^(test .* )?bench:' --line-buffered \
        | sed -uEe 's/^test (.+) ... bench: +/    > bench: \1 /' -Ee 's/^bench: +/    > quick: /'" \
    || (
        echo "Error running the benchmark:"
        tail -10 "${LOG_FILE}" | sed 's/^/    ! /'
        echo "For more details see: ${LOG_FILE}"
        exit 1
    )

if ! [ -s "${MIN_FILE}" ]; then
    echo "    Storing results in ${MIN_FILE}"
    cat "${LOG_FILE}" | rg "^test .* bench:" >"${MIN_FILE}" || echo "    No results (quick run?)"
else
    echo "    Merging ${LOG_FILE} into ${MIN_FILE}"
    rm -f "${TMP_FILE}"
    cat "${LOG_FILE}" | rg "^test .* bench:" | while read new_bench; do
        name=$(echo "${new_bench}" | sed -E 's/^test (.+) ... bench:.*/\1/')
        new_result=$(echo "${new_bench}" | sed -E 's/.*bench: +([0-9]+) ns.*/\1/')

        min_bench=$(rg -F " ${name} " "${MIN_FILE}" || true)
        matches=$(echo "${min_bench}" | wc -l)
        [ "${matches}" -le 1 ] || (echo "Error matching ${name} times in ${MIN_FILE}" && exit 1)
        min_result=$(echo "${min_bench}" | sed -E 's/.*bench: +([0-9]+) ns.*/\1/')

        if [ -z "${min_result}" ] || [ "${new_result}" -lt "${min_result}" ]; then
            echo "    - improved ${name} time: $((new_result / 1000)) µs"
            min_bench="${new_bench}"
        fi
        echo "${min_bench}" >>"${TMP_FILE}"
    done
    echo "    Updating results in ${MIN_FILE}"
    mv -f "${TMP_FILE}" "${MIN_FILE}" 2>/dev/null || echo "    No results (quick run?)"
fi
rm -f "${LOG_FILE}"
