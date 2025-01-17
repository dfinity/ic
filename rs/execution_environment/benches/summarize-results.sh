#!/usr/bin/env bash
set -ue
##
## Helper script to summarize the results in the `MIN_FILE`
## comparing them to the `BASELINE_DIR` results.
##

DEPENDENCIES="awk rg sed"
which ${DEPENDENCIES} >/dev/null || (echo "Error checking dependencies: ${DEPENDENCIES}" >&2 && exit 1)

printf "    %-12s := %s\n" \
    "MIN_FILE" "${MIN_FILE:=${0##*/}.min}" \
    "BASELINE_DIR" "${BASELINE_DIR:=${0%/*}/baseline}" >&2

NAME="${NAME:-${MIN_FILE%.*}}"
TMP_FILE="${TMP_FILE:-${MIN_FILE%.*}.tmp}"

if [ ! -s "${MIN_FILE}" ]; then
    echo "    No results to summarize in ${MIN_FILE} (quick run?)" >&2 && exit 0
fi
BASELINE_FILE="${BASELINE_DIR}/${MIN_FILE##*/}"
if [ ! -s "${BASELINE_FILE}" ]; then
    echo "    No baseline found in ${BASELINE_FILE}" >&2 && exit 0
fi

echo_diff() {
    diff=$(((${2} - ${1}) * 100 * 10 / ${1}))
    awk "BEGIN { print (${diff})^2 <= (2 * 10)^2 ? 0 : ${diff} / 10 }"
}

# Compare the `MIN_FILE` to `BASELINE_FILE`.
total_baseline_ns="0"
total_new_ns="0"
rm -f "${TMP_FILE}"
# Example content:
#   test update/wasm64/baseline/empty loop ... bench:     2720243 ns/iter (+/- 48904)
while read min_bench; do
    name="${min_bench#test }"
    name="${name% ... bench:*}"
    new_result_ns="${min_bench#* ... bench: }"
    new_result_ns="${new_result_ns% ns/iter*}"

    baseline_bench=$(rg -F "test ${name} ... bench:" "${BASELINE_FILE}" || true)
    baseline_result_ns="${baseline_bench#* ... bench: }"
    baseline_result_ns="${baseline_result_ns% ns/iter*}"

    if [ -n "${new_result_ns}" -a -n "${baseline_result_ns}" ]; then
        total_baseline_ns=$((total_baseline_ns + baseline_result_ns))
        total_new_ns=$((total_new_ns + new_result_ns))
        echo "$(echo_diff "${baseline_result_ns}" "${new_result_ns}") ${name}" >>"${TMP_FILE}"
    fi
done <"${MIN_FILE}"

# Produce a summary.
baseline_commit=$(git rev-list --abbrev-commit -1 HEAD "${BASELINE_FILE}")
min_commit=$(git rev-list --abbrev-commit -1 HEAD)
total_diff=$(echo_diff "${total_baseline_ns}" "${total_new_ns}")
printf "= ${baseline_commit}..${min_commit}: ${NAME} total time: $((total_new_ns / 1000 / 1000)) ms "
case "${total_diff}" in
    0) echo "(no change)" ;;
    -*) echo "(improved by ${total_diff}%)" ;;
    *) echo "(regressed by ${total_diff}%)" ;;
esac

# Produce top regressed/improved details.
if [ "${total_diff}" != "0" ]; then
    cat "${TMP_FILE}" | sort -rn | rg '^[1-9]' | head -5 | while read diff name; do
        echo "  + ${name} time regressed by ${diff}%"
    done
    cat "${TMP_FILE}" | sort -n | rg '^-' | head -5 | while read diff name; do
        echo "  - ${name} time improved by ${diff}%"
    done
fi
rm -f "${TMP_FILE}"

# Return an error is there are changes, so the calling script might retry or report an error.
[ "${total_diff}" != "0" ]
