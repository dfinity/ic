#!/usr/bin/env bash
set -ue
##
## Helper script to summarize the results in the `MIN_FILE`
## comparing them to the `BASELINE_DIR` results.
##
## Please use the top-level `run-all-benchmarks.sh` to run all or just
## some benchmarks.
##

DEPENDENCIES="awk egrep fgrep sed"
which ${DEPENDENCIES} >/dev/null || (echo "Error checking dependencies: ${DEPENDENCIES}" >&2 && exit 1)

printf "    %-19s := %s\n" \
    "BASELINE_DIR" "${BASELINE_DIR:=${0%/*}/baseline}" \
    "MIN_FILE" "${MIN_FILE:=${0##*/}.min}" \
    "NOISE_THRESHOLD_PCT" "${NOISE_THRESHOLD_PCT:=2}" \
    "TOP_N" "${TOP_N:=10}" >&2

NAME="${NAME:-${MIN_FILE%.*}}"
TMP_FILE="${TMP_FILE:-${MIN_FILE%.*}.tmp}"

if [ ! -s "${MIN_FILE}" ]; then
    echo "    No results to summarize in ${MIN_FILE} (quick run?)" >&2 && exit 0
fi
# The min file name is expected to be in the format: `<name>.<host>@<commit_id>.min`
BASELINE_FILE="${BASELINE_DIR}/${MIN_FILE##*/}"
# Remove the commit id from the baseline file name, so we compare the min file name
# `<name>.<host>@<commit_id>.min` to the baseline file `<baseline_dir>/<name>.<host>.min`.
BASELINE_FILE="${BASELINE_FILE%@*.min}.min"
if [ ! -s "${BASELINE_FILE}" ]; then
    # Return an error, so the calling script can retry.
    echo "    No baseline found in ${BASELINE_FILE}" >&2 && exit 1
fi

echo_diff_ms_pct() {
    # The baseline file exists, but none of the benchmarks matched it.
    if [ "${1}" -gt "0" ]; then
        awk "BEGIN {
            diff_pct = (${2} - ${1}) * 100 / ${1}
            diff_ms = (${2} - ${1}) / 1000 / 1000
            if (diff_pct ^ 2 <= ${NOISE_THRESHOLD_PCT} ^ 2) {
                printf \"0 0\n\"
            } else {
                printf \"%.2f %.2f\n\", diff_ms, diff_pct
            };
        }"
    else
        echo "0 0"
    fi
}

total_ns="0"
# Compare the `MIN_FILE` to `BASELINE_FILE`.
total_baseline_ns="0"
total_new_ns="0"
rm -f "${TMP_FILE}"
touch "${TMP_FILE}"
# Example content:
#   test update/wasm64/baseline/empty loop ... bench:     2720243 ns/iter (+/- 48904)
while read min_bench; do
    name="${min_bench#test }"
    name="${name% ... bench:*}"
    new_result_ns="${min_bench#* ... bench: }"
    new_result_ns="${new_result_ns% ns/iter*}"
    total_ns=$((total_ns + new_result_ns))

    baseline_bench=$(fgrep "test ${name} ... bench:" "${BASELINE_FILE}" || true)
    baseline_result_ns="${baseline_bench#* ... bench: }"
    baseline_result_ns="${baseline_result_ns% ns/iter*}"

    if [ -n "${new_result_ns}" -a -n "${baseline_result_ns}" ]; then
        total_baseline_ns=$((total_baseline_ns + baseline_result_ns))
        total_new_ns=$((total_new_ns + new_result_ns))
        read baseline_ms new_ms < <(awk "BEGIN {
            printf \"%.2f %.2f\n\",
                ${baseline_result_ns} / 1000 / 1000, ${new_result_ns} / 1000 / 1000
        }")
        diff_ms_pct=$(echo_diff_ms_pct "${baseline_result_ns}" "${new_result_ns}")
        echo "${diff_ms_pct} ${baseline_ms} ${new_ms} ${name}" >>"${TMP_FILE}"
    fi
done <"${MIN_FILE}"

# Produce a summary.
baseline_commit=$(git rev-list --abbrev-commit -1 HEAD "${BASELINE_FILE}")
min_commit=$(git rev-list --abbrev-commit -1 HEAD)
read total_diff_ms total_diff_pct < <(echo_diff_ms_pct "${total_baseline_ns}" "${total_new_ns}")
printf "= ${baseline_commit}..${min_commit}: ${NAME} total time: $((total_ns / 1000 / 1000)) ms "
case "${total_diff_pct}/${total_baseline_ns}" in
    0/0) echo "(new)" ;;
    0*) echo "(no change)" ;;
    -*) echo "(improved by ${total_diff_ms} ms / ${total_diff_pct}%)" ;;
    *) echo "(regressed by ${total_diff_ms} ms / ${total_diff_pct}%)" ;;
esac

# Always produce top regressed/improved details.
echo "  Top ${TOP_N} by time:"
cat "${TMP_FILE}" | sort -rn | egrep '^[1-9]' | head -${TOP_N} \
    | while read diff_ms diff_pct baseline_ms new_ms name; do
        echo "  + ${name} time regressed by ${diff_ms} ms (${baseline_ms} -> ${new_ms} ms)"
    done
cat "${TMP_FILE}" | sort -n | egrep '^-' | head -${TOP_N} \
    | while read diff_ms diff_pct baseline_ms new_ms name; do
        echo "  - ${name} time improved by ${diff_ms} ms (${baseline_ms} -> ${new_ms} ms)"
    done
echo "  Top ${TOP_N} by percentage:"
cat "${TMP_FILE}" | sort -rnk 2 | egrep '^[1-9]' | head -${TOP_N} \
    | while read diff_ms diff_pct baseline_ms new_ms name; do
        echo "  + ${name} time regressed by ${diff_pct}% (${baseline_ms} -> ${new_ms} ms)"
    done
cat "${TMP_FILE}" | sort -nk 2 | egrep '^-' | head -${TOP_N} \
    | while read diff_ms diff_pct baseline_ms new_ms name; do
        echo "  - ${name} time improved by ${diff_pct}% (${baseline_ms} -> ${new_ms} ms)"
    done
rm -f "${TMP_FILE}"

# Return an error if there are changes or the is no baseline (new benchmarks),
# so the calling script might retry or report an error.
[ "${total_diff_pct}" == "0" -a "${total_baseline_ns}" != "0" ]
