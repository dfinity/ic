#!/bin/sh -eu
##
## Helper script to summarize the results in the `MIN_FILE`
## comparing them to the `BASELINE_DIR` results.
##

DEPENDENCIES="awk rg sed"
which ${DEPENDENCIES} >/dev/null || (echo "Error checking dependencies: ${DEPENDENCIES}" && exit 1)

printf "    %-12s := %s\n" \
    "MIN_FILE" "${MIN_FILE:=${0##*/}.min}" \
    "BASELINE_DIR" "${BASELINE_DIR:=${0%/*}/baseline}"

NAME="${NAME:-${MIN_FILE%.*}}"

if [ ! -s "${MIN_FILE}" ]; then
    echo "    No results to summarize in ${MIN_FILE} (quick run?)" && exit 0
fi
[ -d "${BASELINE_DIR}" ] || (echo "Error accessing directory: ${BASELINE_DIR}" && exit 1)

BASELINE_FILE="${BASELINE_DIR}/${MIN_FILE##*/}"
if [ ! -s "${BASELINE_FILE}" ]; then
    echo "No baseline found: ${BASELINE_FILE}" && exit 0
fi

total_baseline="0"
total_new="0"
while read min_bench; do
    name=$(echo "${min_bench}" | sed -E 's/^test (.+) ... bench:.*/\1/')
    new_result=$(echo "${min_bench}" | sed -E 's/.*bench: +([0-9]+) ns.*/\1/')

    baseline_bench=$(rg -F " ${name} " "${BASELINE_FILE}" || true)
    matches=$(echo "${baseline_bench}" | wc -l)
    [ "${matches}" -le 1 ] || (echo "Error matching ${name} times in ${BASELINE_FILE}" && exit 1)
    baseline_result=$(echo "${baseline_bench}" | sed -E 's/.*bench: +([0-9]+) ns.*/\1/')

    if [ -n "${new_result}" -a -n "${baseline_result}" ]; then
        total_baseline=$((total_baseline + baseline_result))
        total_new=$((total_new + new_result))
    fi
done <"${MIN_FILE}"
baseline_commit=$(git rev-list --abbrev-commit -1 HEAD "${BASELINE_FILE}" | head -c 9)
min_commit=$(git rev-list --abbrev-commit -1 HEAD | head -c 9)
diff=$(echo "${total_min} ${total_baseline}" \
    | awk '{ diff = ($1 - $2) * 100 * 10 / $2; print diff^2 <= (2 * 10)^2 ? 0 : diff / 10 }')
total_min_s=$((total_min / 1000 / 1000))
printf "    = ${baseline_commit}..${min_commit}: ${NAME}: total time: ${total_min_s} s "
case "${diff}" in
    0) echo "(no change)" ;;
    -*) echo "(improved by ${diff}%)" ;;
    *) echo "(regressed by ${diff}%)" ;;
esac
