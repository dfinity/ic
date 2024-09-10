#!/usr/bin/env bash
set -e
##
## Compare performance of the Wasm64 vs Wasm32 System API calls.
##
##
## The final result is a Markdown formatted table:
##
##   | API Type / System API Call             | Wasm32 IPS | Wasm64 IPS | Speedup | Round Time |
##   | -------------------------------------- | ---------- | ---------- | ------- | ---------- |
##   | update/ic0_stable64_size()             |      1.30G |      1.25G |     -4% |      4.06s |
##   | update/ic0_canister_status()           |      1.27G |      1.34G |     +5% |      3.73s |
##   | inspect/ic0_msg_method_name_size()     |          - |      1.28G |       - |     23.92s |

## To quickly assess if there are any changes, run benchmarks just once.
if [ -n "${QUICK}" ]; then
    REPEAT="${REPEAT:=1}"
    WASM64_BENCH_ARGS="${WASM64_BENCH_ARGS:---warm-up-time 1  --measurement-time 1 --sample-size 10 --noplot}"
fi

echo "Global script configuration:"
echo
printf "%20s %s\n" \
    "WASM64_BENCH_ARGS :=" "${WASM64_BENCH_ARGS:=}" \
    "WASM32_BENCH_ARGS :=" "${WASM32_BENCH_ARGS:=${WASM64_BENCH_ARGS}}" \
    "" "" \
    "REPEAT :=" "${REPEAT:=9}" \
    "FILTER :=" "${FILTER:=}" \
    "QUICK :=" "${QUICK:=}" \
echo 

## Other (hidden) options
WORK_DIR=$PWD

## This function is called to run Wasm64 benchmarks
run_wasm64() {
    bazel run //rs/execution_environment:execute_inspect_message_bench_wasm64 -- ${FILTER} ${WASM64_BENCH_ARGS} \
        && bazel run //rs/execution_environment:execute_query_bench_wasm64 -- ${FILTER} ${WASM64_BENCH_ARGS} \
        && bazel run //rs/execution_environment:execute_update_bench_wasm64 -- ${FILTER} ${WASM64_BENCH_ARGS}
}

## This function is called to run Wasm32 benchmarks
run_wasm32() {
    (
        bazel run //rs/execution_environment:execute_inspect_message_bench -- ${FILTER} ${WASM32_BENCH_ARGS} \
            && bazel run //rs/execution_environment:execute_query_bench -- ${FILTER} ${WASM32_BENCH_ARGS} \
            && bazel run //rs/execution_environment:execute_update_bench -- ${FILTER} ${WASM32_BENCH_ARGS}
    )
}

########################################################################
## Analyze and print the results
########################################################################

print_md_header4() {
    printf "| %-42s | %-11s | %-11s | %-7s |\n" "$1" "$2" "$3" "$4" \
        "$(printf -- '-%.0s' $(seq 42))" "$(printf -- '-%.0s' $(seq 11))" \
        "$(printf -- '-%.0s' $(seq 11))" "$(printf -- '-%.0s' $(seq 7))"
}

print_md_header5() {
    printf "| %-42s | %-11s | %-11s | %-7s | %-10s |\n" "$1" "$2" "$3" "$4" "$5" \
        "$(printf -- '-%.0s' $(seq 42))" "$(printf -- '-%.0s' $(seq 11))" \
        "$(printf -- '-%.0s' $(seq 11))" "$(printf -- '-%.0s' $(seq 7))" \
        "$(printf -- '-%.0s' $(seq 10))"
}

cat_wasm64_benchmark_names() {
    cat "${WORK_DIR}/summary-wasm64.txt" | rg "Benchmarking .*: Analyzing" \
        | sed -Ee 's/^Benchmarking ([^:]*): Analyzing.*$/\1/'
}

## Print max throughput out of series of results
print_max_throughput() {
    local name="${1}"
    local file="${2}"
    ## Apply name transformations to match between wasm32 and wasm64 benchmarks
    ## ic0.call()/1B -> ic0.*call\(\).*1B
    match=$(echo "${name}" | sed -Ee 's#([^()0-9A-Za-z_]+)#.*#g' -e 's#[()]#\\&#g' -e 's#_#.#g')
    cat "${file}" | rg "${match}" --after-context 3 --max-count 1 | rg "thrpt:" \
        | sed -Ee 's#([.0-9]+ .?)elem/s#\n\1elem/s\n#g' | rg '^[0-9]' \
        | awk '
        BEGIN { max = ""; max_unit = "-"; }
        {
            v = $1; u = $2;
            if ((max == "") || (v > max && max_unit == u) || (v < max && max_unit != u)) {
                max = v; max_unit = u;
            }
        }
        END { printf "%s %s", max, max_unit}
    '
}

## Print min time out of series of results
print_min_time() {
    local name="${1}"
    local file="${2}"
    ## Apply name transformations to match between Wasm32 and Wasm64 benchmarks.
    ## ic0.call()/1B -> ic0.*call\(\).*1B
    match=$(echo "${name}" | sed -Ee 's#([^()0-9A-Za-z_]+)#.*#g' -e 's#[()]#\\&#g' -e 's#_#.#g')
    cat "${file}" | rg "${match}" --after-context 3 --max-count 1 | rg "time:" \
        | sed -Ee 's#([.0-9]+ .?)s#\n\1s\n#g' | rg '^[0-9]' \
        | awk '
            BEGIN { min = ""; min_unit = "-"; }
            {
                v = $1; u = $2;
                if ((min == "") || (v < min && min_unit == u) || (v > min && min_unit != u)) {
                    min = v; min_unit = u;
                }
            }
            END { printf "%s %s", min, min_unit}
        '
}

transform_elem_s() {
    ## Format transformations:
    ##   123.456 Kelem/s -> 123K
    ##   12.3456 Kelem/s -> 12.3K
    ##   1.23456 Kelem/s -> 1.23K
    ##   1.00K -> 1K
    sed -Ee 's#([0-9]{3,})\.[0-9]* (.)?elem/s#\1\2#g' \
        -e 's#([0-9]{2}\.[0-9])[0-9]* (.)?elem/s#\1\2#g' \
        -e 's#([0-9]{1}\.[0-9]{,2})[0-9]* (.)?elem/s#\1\2#g' \
        -e 's#([0-9]+)\.0+([A-Z])#\1\2#g'
}

transform_s() {
    ## Format transformations:
    ##   123.456 ms -> 123ms
    ##   12.3456 mss -> 12.3ms
    ##   1.23456 ms -> 1.23ms
    ##   1.00ms -> 1ms
    sed -Ee 's#([0-9]{3,})\.[0-9]* (.)?s#\1\2s#g' \
        -e 's#([0-9]{2}\.[0-9])[0-9]* (.)?s#\1\2s#g' \
        -e 's#([0-9]{1}\.[0-9]{,2})[0-9]* (.)?s#\1\2s#g' \
        -e 's#([0-9]+)\.0+([a-z])#\1\2#g'
}

transform_benchmark_name() {
    ## Format transformations:
    ##   _| or |_ -> |
    sed -Ee 's# +\||\| +#\|#g'
}

calculate_average_speedup() {
    local what="${1}"
    awk -F '|' '
    ## Covert a suffixed number to an integer: 123K -> 123000
    function convert(i) {
        switch (i) {
            case /K/: return i * 1000;
            case /M/: return i * 1000 * 1000;
            case /G/: return i * 1000 * 1000 * 1000;
            case /ms/: return i / 1000;
            case /us/: return i / 1000 / 1000;
            case /µs/: return i / 1000 / 1000;
            case /s/: return i / 1;
        }
    }
    {
        wasm32 = convert($3);
        wasm64 = convert($4);
        if (wasm32 == 0) {
            printf "| %-42s | %11s | %11s | %7s |", $2, $3, $4, "-";
        } else {
            speedup = int(wasm64/wasm32*100) - 100;
            sum += speedup;
            count++;
            printf "| %-42s | %11s | %11s | %+6d% |", $2, $3, $4, speedup;
        }
        # Print round time only for throughput
        # Throughput must be >= 100 elem/s, time must be < 100 s
        if (wasm64 < 100) {
            printf "\n";    # skip round time for time table
        } else {
            instructions_per_round = 7 * 1000 * 1000 * 1000;    # 7B
            round_time = instructions_per_round/wasm64;
            # Marked and complex calls have no tight loop
            if (round_time > 999 || $2 ~ /\*/) {
                printf " %10s |\n", "-";
            } else {
                printf " %9.2fs |\n", round_time;
            }
        }
    }
    END { if (count) printf "\nAverage speedup of the Wasm64: %+d%", sum/count }
    '
    echo "(${what})"
}

########################################################################
## Run all the benchmarks REPEAT times
########################################################################

for i in $(seq ${REPEAT}); do
    echo "==> Iteration ${i}: running Wasm64 benchmarks..."
    echo "    See full log: ${WORK_DIR}/wasm64-${i}.txt"
    set -o pipefail
    run_wasm64 2>&1 \
        | tee "${WORK_DIR}/wasm64-${i}.txt" \
        | rg --line-buffered "Benchmarking .*: Analyzing" --after-context 3 \
        | tee "${WORK_DIR}/wasm64-${i}-sum.txt" \
        | sed -e 's/^/    /' \
        || (
            echo "[...]"
            tail -20 "${WORK_DIR}/wasm64-${i}.txt"
            echo
            echo "Error running the Wasm64 benchmarks."
            echo "For more details see: ${WORK_DIR}/wasm64-${i}.txt"
            exit 1
        )
    set +o pipefail
    
    echo "==> Iteration ${i}: running Wasm32 benchmarks..."
    echo "    See full log: ${WORK_DIR}/wasm32-${i}.txt"
    set -o pipefail
    run_wasm32 2>&1 \
        | tee "${WORK_DIR}/wasm32-${i}.txt" \
        | rg --line-buffered "Benchmarking .*: Analyzing" --after-context 3 \
        | tee "${WORK_DIR}/wasm32-${i}-sum.txt" \
        | sed -e 's/^/    /' \
        || (
            echo "[...]"
            tail -20 ""${WORK_DIR}/wasm32-${i}.txt""
            echo
            echo "Error running the wasm32 benchmarks."
            echo "For more details see: "${WORK_DIR}/wasm32-${i}.txt""
            exit 1
        )
    set +o pipefail
    
    
done

########################################################################
## Get the best results for each benchmark
########################################################################
##
## The `*-sum.txt`` files look like this:
##
##   Benchmarking update/baseline/empty test: Analyzing
##   update/baseline/empty test
##                           time:   [273.07 us 275.46 us 278.14 us]
##                           thrpt:  [7.1905 Kelem/s 7.2605 Kelem/s 7.3242 Kelem/s]

## Paste the files together line by line
for i in $(seq ${REPEAT}); do
    echo "${WORK_DIR}/wasm64-${i}-sum.txt"
done | xargs paste >"${WORK_DIR}/summary-wasm64.txt"
for i in $(seq ${REPEAT}); do
    echo "${WORK_DIR}/wasm32-${i}-sum.txt"
done | xargs paste >"${WORK_DIR}/summary-wasm32.txt"


## Generate final report
(
    echo "System API Wasm32 vs. Wasm64 Performance Report"
    echo "============================="
    echo

    ## For each benchmark, print max Wasm32 and Wasm64 throughput
    print_md_header5 "API Type / System API Call" "Wasm32 IPS" "Wasm64 IPS" "Speedup" "Round Time"
    cat_wasm64_benchmark_names \
        | while read name; do
            printf "| ${name} | "
            print_max_throughput "${name}" "${WORK_DIR}/summary-wasm32.txt"
            printf " |"
            print_max_throughput "${name}" "${WORK_DIR}/summary-wasm64.txt"
            printf "|\n"
        done \
        | transform_elem_s | transform_benchmark_name \
        | calculate_average_speedup "throughput"

    echo

    ## For each benchmark, print min Wasm64 and Wasm32 time
    print_md_header4 "API Type / System API Call (1M Iterations)" "Wasm32 Time" "Wasm64 Time" "Speedup"
    cat_wasm64_benchmark_names \
        | while read name; do
            printf "| ${name} | "
            
            print_min_time "${name}" "${WORK_DIR}/summary-wasm32.txt"
            
            printf " | "
            print_min_time "      ${name}" "${WORK_DIR}/summary-wasm64.txt"
            printf " |\n"
        done \
        | transform_s | transform_benchmark_name \
        | calculate_average_speedup "time"

    echo

    ## Print footer
    echo "Note: marked calls have no loop, so those results should not be compared with other calls"
) | tee "${0##*/}-report.txt"
