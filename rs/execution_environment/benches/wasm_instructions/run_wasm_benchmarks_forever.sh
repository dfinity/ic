#!/bin/sh
# Usage: run_wasm_benchmarks_forever.sh
#
# Continuously improve `run_wasm_benchmarks_forever.md` file by running
# the `run_wasm_benchmarks.sh` and taking the minimum results.

# Example content:
# | ibinop/i32.or             | 2368404              | 1              |         | BASELINE (1)     |
MD_FILE="${0##*/}.md"
WASM_BENCHMARKS="${0%/*}/run_wasm_benchmarks.sh"

for i in $(seq 1000); do
    echo "==> $(date '+%Y-%m-%d %H:%M:%S') Iteration #${i}"
    echo "    Re-running all the benchmarks..."
    "${WASM_BENCHMARKS}" -f >"${MD_FILE}.log.tmp" 2>&1
    echo "    Generating the new MD file..."
    "${WASM_BENCHMARKS}" >"${MD_FILE}.gen.tmp"
    if ! [ -s "${MD_FILE}" ]; then
        echo "    Setting the baseline..."
        mv "${MD_FILE}.gen.tmp" "${MD_FILE}"
        continue
    fi
    echo "    Merging the results..."
    rm -f "${MD_FILE}.merge.tmp"
    IFS="|"
    cat "${MD_FILE}" | while read name result k _empty comment; do
        # Trim the white spaces.
        name="$(echo ${name} | xargs)"
        result="$(echo ${result} | xargs)"
        k="$(echo ${k} | xargs)"
        comment="$(echo ${comment} | xargs)"
        new=$(rg -wF "${name}" "${MD_FILE}.gen.tmp")
        if [ -n "${new}" ]; then
            new_name=$(echo "${new}" | awk -F "|" '{print $1}' | xargs)
            new_result=$(echo "${new}" | awk -F "|" '{print $2}' | xargs)
            new_k=$(echo "${new}" | awk -F "|" '{print $3}' | xargs)
            new_comment=$(echo "${new}" | awk -F "|" '{print $5}' | xargs)
            if [ -n "${new_result}" -a "${new_result}" -lt "${result}" ]; then
                echo "        \"${name}\" result is improved"
                result="${new_result}"
                k="${new_k}"
                comment="${new_comment}"
            fi
        fi
        printf "%-30s | %10s | %4s | | %s\n" "${name}" "${result}" "${k}" "${comment}" \
            >>"${MD_FILE}.merge.tmp"
    done
    echo "    Updating the results..."
    mv "${MD_FILE}.merge.tmp" "${MD_FILE}"
done
