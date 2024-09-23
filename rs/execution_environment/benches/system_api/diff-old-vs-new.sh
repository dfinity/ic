#!/usr/bin/env bash
set -ue
##
## Compare performance of the local (new) changes vs remote (old) IC repository.
##
## The script checks out an IC public repository branch and compares its
## performance vs the local (new) changes.
##
## By default, it checks out the `master` branch and repeats the benchmarks 9 times, taking
## the best result out of those 9 runs.
##
## The final result is a Markdown formatted table:
##
##   | API Type / System API Call             | Old IPS | New IPS | Speedup | Round Time |
##   | -------------------------------------- | ------- | ------- | ------- | ---------- |
##   | update/ic0_stable64_size()             |   1.30G |   1.25G |     -4% |      4.06s |
##   | update/ic0_canister_status()           |   1.27G |   1.34G |     +5% |      3.73s |
##   | inspect/ic0_msg_method_name_size()     |       - |   1.28G |       - |     23.92s |

## To quickly assess the new changes, run benchmarks just once
if [ -n "${QUICK}" ]; then
    REPEAT="${REPEAT:=1}"
    NEW_BENCH_ARGS="${NEW_BENCH_ARGS:---warm-up-time 1  --measurement-time 1 --sample-size 10 --noplot}"
fi

echo "Global script configuration:"
echo
printf "%20s %s\n" \
    "OLD_REPO :=" "${OLD_REPO:=git@github.com:dfinity/ic.git}" \
    "OLD_BRANCH :=" "${OLD_BRANCH:=master}" \
    "OLD_COMMIT :=" "${OLD_COMMIT:=}" \
    "" "" \
    "NEW_BENCH_ARGS :=" "${NEW_BENCH_ARGS:=}" \
    "NEW_NO_CACHE :=" "${NEW_NO_CACHE:=}" \
    "OLD_BENCH_ARGS :=" "${OLD_BENCH_ARGS:=${NEW_BENCH_ARGS}}" \
    "OLD_NO_CACHE :=" "${OLD_NO_CACHE:=}" \
    "" "" \
    "REPEAT :=" "${REPEAT:=9}" \
    "FILTER :=" "${FILTER:=}" \
    "QUICK :=" "${QUICK:=}" \
    "IGNORE_OLD_REPORT :=" "${IGNORE_OLD_REPORT:=}"
echo
echo "The configuration above could be overridden with environment variables, i.e.:"
echo "    QUICK=1 OLD_COMMIT=04f38ce0 ${0}"
echo

## Other (hidden) options
NEW_COMMIT=$(git rev-parse --short=9 HEAD)
CACHE_DIR="${CACHE_DIR:-${HOME}/.cache/${0##*/}/new-${NEW_COMMIT}/old-${OLD_BRANCH}-${OLD_COMMIT}}"
OLD_REPO_DIR="${OLD_REPO_DIR:-${CACHE_DIR}/ic}"
OLD_REPORT="${OLD_REPORT:-${OLD_REPO_DIR}/rs/execution_environment/benches/system_api/SYSTEM_API.md}"

mkdir -p "${CACHE_DIR}"

########################################################################
## Init and run benchmarks over the local (new) and remote (old) changes
########################################################################

## This function is called once to prepare local (new) changes
init_new() {
    echo "==> Building local (new) changes..."
}

## This function is called to run local (new) benchmarks
run_new() {
    bazel run //rs/execution_environment:execute_inspect_message_bench -- ${FILTER} ${NEW_BENCH_ARGS} \
        && bazel run //rs/execution_environment:execute_query_bench -- ${FILTER} ${NEW_BENCH_ARGS} \
        && bazel run //rs/execution_environment:execute_update_bench -- ${FILTER} ${NEW_BENCH_ARGS}
}

## This function is called once to prepare remote (old) repository
init_old() {
    echo "==> Cloning ${OLD_REPO}, branch ${OLD_BRANCH}..."
    if [ -d "${OLD_REPO_DIR}" -a -z "${OLD_NO_CACHE}" ]; then
        echo "    CACHED"
        echo "    Remote (old) directory already exist: ${OLD_REPO_DIR}"
        echo "    Pull the latest changes manually if needed."
    else
        git clone "${OLD_REPO}" --branch "${OLD_BRANCH}" --single-branch --no-tags \
            "${OLD_REPO_DIR}" 2>&1 | sed 's/^/    /'
        if [ -n "${OLD_COMMIT}" ]; then
            (
                cd "${OLD_REPO_DIR}"
                git checkout "${OLD_COMMIT}"
            )
        fi
    fi
    if [ -z "${IGNORE_OLD_REPORT}" ]; then
        echo "==> Using remote (old) report..."
        (
            if [ -s "${OLD_REPORT}" ]; then
                echo "    Found: ${OLD_REPORT}"
            else
                echo "Error accessing old report: ${OLD_REPORT}"
                echo "To override use:"
                echo "    OLD_REPORT=<path to SYSTEM_API.md> ${0}"
                exit 1
            fi
        )
    fi
}

## This function is called to run remote (old) benchmarks
run_old() {
    (
        cd "${OLD_REPO_DIR}"
        bazel run //rs/execution_environment:execute_inspect_message_bench -- ${FILTER} ${OLD_BENCH_ARGS} \
            && bazel run //rs/execution_environment:execute_query_bench -- ${FILTER} ${OLD_BENCH_ARGS} \
            && bazel run //rs/execution_environment:execute_update_bench -- ${FILTER} ${OLD_BENCH_ARGS}
    )
}

########################################################################
## Analyze and print the results
########################################################################

print_git_header() {
    printf "%s commit:%s branch:%s\n" \
        "Remote (old)" \
        "$(git -C ${OLD_REPO_DIR} rev-parse --short=9 HEAD)" \
        "$(git -C ${OLD_REPO_DIR} describe --always --all | sed -e 's#heads/##')" \
        "Local  (new)" \
        "$(git rev-parse --short=9 HEAD)" \
        "$(git describe --always --all | sed -e 's#heads/##')"
    echo
}

print_md_header4() {
    printf "| %-42s | %-8s | %-8s | %-7s |\n" "$1" "$2" "$3" "$4" \
        "$(printf -- '-%.0s' $(seq 42))" "$(printf -- '-%.0s' $(seq 8))" \
        "$(printf -- '-%.0s' $(seq 8))" "$(printf -- '-%.0s' $(seq 7))"
}

print_md_header5() {
    printf "| %-42s | %-8s | %-8s | %-7s | %-10s |\n" "$1" "$2" "$3" "$4" "$5" \
        "$(printf -- '-%.0s' $(seq 42))" "$(printf -- '-%.0s' $(seq 8))" \
        "$(printf -- '-%.0s' $(seq 8))" "$(printf -- '-%.0s' $(seq 7))" \
        "$(printf -- '-%.0s' $(seq 10))"
}

cat_new_benchmark_names() {
    cat "${CACHE_DIR}/summary-new.txt" | rg "Benchmarking .*: Analyzing" \
        | sed -Ee 's/^Benchmarking ([^:]*): Analyzing.*$/\1/'
}

## Print max throughput out of series of results
print_max_throughput() {
    local name="${1}"
    local file="${2}"
    ## Apply name transformations to match between local (new) and remote (old) benchmarks
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
    ## Apply name transformations to match between local (new) and remote (old) benchmarks
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

## Print a field from the remote (old) report
print_old_report_field() {
    local name="${1}"
    local line="${2}"
    local field="${3}"
    ## Apply name transformations to match between local (new) and remote (old) benchmarks
    ## ic0.call()/1B -> ic0.*call\(\).*1B
    match=$(echo "${name}" | sed -Ee 's#([^()0-9A-Za-z_]+)#.*#g' -Ee 's#[()]#\\&#g' -Ee 's#_#.#g')
    set -o pipefail
    cat "${OLD_REPORT}" | rg "${match}" | sed -Ee 's# +# #g' \
        | awk -F '|' "NR == ${line} {printf \$$((${field} + 1))} NR == 3 {exit 1}" \
        || printf "-"
    set +o pipefail
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
        old = convert($3);
        new = convert($4);
        if (old == 0) {
            printf "| %-42s | %8s | %8s | %7s |", $2, $3, $4, "-";
        } else {
            speedup = int(new/old*100) - 100;
            sum += speedup;
            count++;
            printf "| %-42s | %8s | %8s | %+6d% |", $2, $3, $4, speedup;
        }
        # Print round time only for throughput
        # Throughput must be >= 100 elem/s, time must be < 100 s
        if (new < 100) {
            printf "\n";    # skip round time for time table
        } else {
            instructions_per_round = 7 * 1000 * 1000 * 1000;    # 7B
            round_time = instructions_per_round/new;
            # Marked and complex calls have no tight loop
            if (round_time > 999 || $2 ~ /\*/) {
                printf " %10s |\n", "-";
            } else {
                printf " %9.2fs |\n", round_time;
            }
        }
    }
    END { if (count) printf "\nAverage speedup of the local (new) changes: %+d%", sum/count }
    '
    echo " (${what})"
}

########################################################################
## Init repositories
########################################################################

init_new
init_old

########################################################################
## Run all the benchmarks REPEAT times
########################################################################

for i in $(seq ${REPEAT}); do
    echo "==> Iteration ${i}: running local (new) benchmarks..."
    if [ -s "${CACHE_DIR}/new-${i}-sum.txt" -a -z "${NEW_NO_CACHE}" ]; then
        echo "    CACHED"
    else
        echo "    See full log: ${CACHE_DIR}/new-${i}.txt"
        set -o pipefail
        run_new 2>&1 \
            | tee "${CACHE_DIR}/new-${i}.txt" \
            | rg --line-buffered "Benchmarking .*: Analyzing" --after-context 3 \
            | tee "${CACHE_DIR}/new-${i}-sum.txt" \
            | sed -e 's/^/    /' \
            || (
                echo "[...]"
                tail -20 "${CACHE_DIR}/new-${i}.txt"
                echo
                echo "Error running the new benchmarks."
                echo "For more details see: ${CACHE_DIR}/new-${i}.txt"
                exit 1
            )
        set +o pipefail
    fi
    echo "==> Iteration ${i}: running remote (old) benchmarks..."
    if [ -n "${IGNORE_OLD_REPORT}" ]; then
        if [ -s "${CACHE_DIR}/old-${i}-sum.txt" -a -z "${OLD_NO_CACHE}" ]; then
            echo "    CACHED"
        else
            echo "    See full log: ${CACHE_DIR}/old-${i}.txt"
            set -o pipefail
            run_old 2>&1 \
                | tee "${CACHE_DIR}/old-${i}.txt" \
                | rg --line-buffered "Benchmarking .*: Analyzing" --after-context 3 \
                | tee "${CACHE_DIR}/old-${i}-sum.txt" \
                | sed -e 's/^/    /' \
                || (
                    echo "[...]"
                    tail -20 ""${CACHE_DIR}/old-${i}.txt""
                    echo
                    echo "Error running the old benchmarks."
                    echo "For more details see: "${CACHE_DIR}/old-${i}.txt""
                    exit 1
                )
            set +o pipefail
        fi
    else
        echo "    OLD REPORT"
    fi
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
    echo "${CACHE_DIR}/new-${i}-sum.txt"
done | xargs paste >"${CACHE_DIR}/summary-new.txt"
if [ -n "${IGNORE_OLD_REPORT}" ]; then
    for i in $(seq ${REPEAT}); do
        echo "${CACHE_DIR}/old-${i}-sum.txt"
    done | xargs paste >"${CACHE_DIR}/summary-old.txt"
fi

## Generate final report
(
    echo "System API Performance Report"
    echo "============================="
    echo
    print_git_header

    ## For each benchmark, print max remote (old) and local (new) throughput
    print_md_header5 "API Type / System API Call" "Old IPS" "New IPS" "Speedup" "Round Time"
    cat_new_benchmark_names \
        | while read name; do
            printf "| ${name} | "
            if [ -n "${IGNORE_OLD_REPORT}" ]; then
                print_max_throughput "${name}" "${CACHE_DIR}/summary-old.txt"
            else
                print_old_report_field "${name}" 1 3
            fi
            printf " | "
            print_max_throughput "${name}" "${CACHE_DIR}/summary-new.txt"
            printf " |\n"
        done \
        | transform_elem_s | transform_benchmark_name \
        | calculate_average_speedup "throughput"

    echo

    ## For each benchmark, print min remote (old) and local (new) time
    print_md_header4 "API Type / System API Call (1M Iterations)" "Old Time" "New Time" "Speedup"
    cat_new_benchmark_names \
        | while read name; do
            printf "| ${name} | "
            if [ -n "${IGNORE_OLD_REPORT}" ]; then
                print_min_time "${name}" "${CACHE_DIR}/summary-old.txt"
            else
                print_old_report_field "${name}" 2 3
            fi
            printf " | "
            print_min_time "${name}" "${CACHE_DIR}/summary-new.txt"
            printf " |\n"
        done \
        | transform_s | transform_benchmark_name \
        | calculate_average_speedup "time"

    echo

    ## Print footer
    echo "Note: marked calls have no loop, so those results should not be compared with other calls"
) | tee "${0##*/}-report.txt"
