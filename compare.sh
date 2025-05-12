#!/bin/bash

BASELINE_FILE="rs/execution_environment/benches/baseline/EMBEDDERS_HEAP.min"
MIN_FILE="EMBEDDERS_HEAP.min"
NOISE_THRESHOLD_PCT="2"

echo_diff_ms_pct() {
    # The baseline file exists, but none of the benchmarks matched it.
    if [ "${1}" -gt "0" ]; then
        awk "BEGIN {
            diff_pct = (${2} - ${1}) * 100 / ${1}
            diff_ms = (${2} - ${1}) / 1000 / 1000
            if (diff_pct ^ 2 <= ${NOISE_THRESHOLD_PCT} ^ 2) {
                printf \"0 0\n\"
            } else {
                printf \"%.1f %.1f\n\", diff_ms, diff_pct
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
# Example content:
#   test update/wasm64/baseline/empty loop ... bench:     2720243 ns/iter (+/- 48904)
while read min_bench; do
    name="${min_bench#test }"
    name="${name% ... bench:*}"
    new_result_ns="${min_bench#* ... bench: }"
    new_result_ns="${new_result_ns% ns/iter*}"
    total_ns=$((total_ns + new_result_ns))

    baseline_bench=$(rg -F "test ${name} ... bench:" "${BASELINE_FILE}" || true)
    baseline_result_ns="${baseline_bench#* ... bench: }"
    baseline_result_ns="${baseline_result_ns% ns/iter*}"

    if [ -n "${new_result_ns}" -a -n "${baseline_result_ns}" ]; then
        total_baseline_ns=$((total_baseline_ns + baseline_result_ns))
        total_new_ns=$((total_new_ns + new_result_ns))
        read diff_ms diff_pct < <(echo_diff_ms_pct "${baseline_result_ns}" "${new_result_ns}")
        baseline_result_ms=$((baseline_result_ns / 1000 / 1000))
        new_result_ms=$((new_result_ns / 1000 / 1000))
        name="${name#embedders:heap/}"
        case "${diff_ms}" in
            0/0) printf "?%7s%% ${name}\n" "${diff_pct}" ;;
            0*) printf "%7s%% ${name} (no change %s ns -> %s ns)\n" "${diff_pct}" \
                "${baseline_result_ns}" "${new_result_ns}" ;;
            -*) printf "%7s%% ${name} (improved %s ms -> %s ms)\n" \
                "${diff_pct}" \
                "${baseline_result_ms}" "${new_result_ms}" ;;
            *) printf "%7s%% ${name} (regressed %s ms -> %s ms)\n" \
                "+${diff_pct}" \
                "${baseline_result_ms}" "${new_result_ms}" ;;
        esac
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
