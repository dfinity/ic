#!/bin/sh -e
##
## Compare performance of the local (new) changes vs remote (old) IC repository.
##
## The script checks out IC public repository master branch and compares its
## performance vs the local changes.
##
## By default, it checks out the `master` branch and repeats the benchmarks 9 times, taking
## the best result out of those 9 runs.
##
## The final result is a Markdown formatted table:
##
##   | API Type / System API Call             | Remote, IPS | Local, IPS  | Speedup |
##   | -------------------------------------- | ----------- | ----------- | ------- |
##   | update/ic0_stable64_size()             |       1.30G |       1.25G |     -4% |
##   | update/ic0_canister_status()           |       1.27G |       1.34G |     +5% |
##   | inspect/ic0_msg_method_name_size()     |             |       1.28G |       - |

## To quickly assess the local changes, run short local benchmarks just once
if [ -n "${QUICK}" ]; then
    REPEAT="${REPEAT:=1}"
    LOCAL_BENCH_ARGS="${LOCAL_BENCH_ARGS:---bench execute_* -- --warm-up-time 1  --measurement-time 1 --sample-size 10 --noplot}"
fi

echo "Global script configuration:"
echo
printf "%20s %s\n" \
    "LOCAL_REPO_DIR :=" "${LOCAL_REPO_DIR:=$(realpath ../../..)}" \
    "REMOTE_REPO :=" "${REMOTE_REPO:=git@gitlab.com:dfinity-lab/public/ic.git}" \
    "REMOTE_BRANCH :=" "${REMOTE_BRANCH:=master}" \
    "" "" \
    "LOCAL_PROFILE :=" "${LOCAL_PROFILE:=release-lto}" \
    "LOCAL_BENCH_ARGS :=" "${LOCAL_BENCH_ARGS:=--bench execute_*}" \
    "LOCAL_NO_CACHE :=" "${LOCAL_NO_CACHE:=}" \
    "REMOTE_PROFILE :=" "${REMOTE_PROFILE:=release-lto}" \
    "REMOTE_BENCH_ARGS :=" "${REMOTE_BENCH_ARGS:=${LOCAL_BENCH_ARGS}}" \
    "REMOTE_NO_CACHE :=" "${REMOTE_NO_CACHE:=}" \
    "" "" \
    "REPEAT :=" "${REPEAT:=9}" \
    "FILTER :=" "${FILTER:=}" \
    "QUICK :=" "${QUICK:=}"
echo
echo "The configuration above could be overridden with environment variables."
echo "Example: REMOTE_BRANCH=my_branch ${0}"
echo

## Other (hidden) options
BENCHMARK_DIR="${BENCHMARK_DIR:-execution_environment}"
CACHE_DIR="${CACHE_DIR:-${HOME}/.cache/${0##*/}}"
WORK_DIR="${WORK_DIR:-${LOCAL_REPO_DIR}/rs/target/${0##*/}}"

REMOTE_REPO_DIR="${REMOTE_REPO_DIR:-${WORK_DIR}/remote-${REMOTE_BRANCH}}"
LOCAL_BENCHMARK_DIR="${LOCAL_BENCHMARK_DIR:-${LOCAL_REPO_DIR}/rs/${BENCHMARK_DIR}}"
LOCAL_TARGET_DIR="${LOCAL_TARGET_DIR:-${LOCAL_REPO_DIR}/rs/target}"
REMOTE_BENCHMARK_DIR="${REMOTE_BENCHMARK_DIR:-${REMOTE_REPO_DIR}/rs/${BENCHMARK_DIR}}"
REMOTE_TARGET_DIR="${REMOTE_TARGET_DIR:-${REMOTE_REPO_DIR}/rs/target}"

mkdir -p "${WORK_DIR}" "${CACHE_DIR}"

########################################################################
## Init and run benchmarks over the local (new) and remote (old) changes
########################################################################

## This function is called once to prepare (build) local changes
init_local() {
    echo "==> Building local changes..."
    (
        cd "${LOCAL_REPO_DIR}/rs"
        cargo build --profile "${LOCAL_PROFILE}" --bin canister_sandbox --bin sandbox_launcher \
            || exit 1
    )
}

## This function is called to run remote benchmarks
run_local() {
    (
        cd "${LOCAL_BENCHMARK_DIR}"
        SANDBOX_BINARY="${LOCAL_TARGET_DIR}/${LOCAL_PROFILE}/canister_sandbox" \
            LAUNCHER_BINARY="${LOCAL_TARGET_DIR}/${LOCAL_PROFILE}/sandbox_launcher" \
            cargo bench ${FILTER} ${LOCAL_BENCH_ARGS} \
            || exit 1
    )
}

## This function is called once to prepare (clone and build) remote repository
init_remote() {
    echo "==> Cloning ${REMOTE_REPO}, branch ${REMOTE_BRANCH}..."
    if [ -d "${REMOTE_REPO_DIR}" -a -z "${REMOTE_NO_CACHE}" ]; then
        echo "    CACHED"
        echo "    Remote directory already exist: ${REMOTE_REPO_DIR}"
        echo "    Pull the latest changes manually if needed"
    else
        git clone "${REMOTE_REPO}" --branch "${REMOTE_BRANCH}" --single-branch --no-tags \
            "${REMOTE_REPO_DIR}" 2>&1 | sed 's/^/    /'
    fi
    echo "==> Building remote repo..."
    (
        cd "${REMOTE_REPO_DIR}/rs"
        cargo build --profile "${REMOTE_PROFILE}" --bin canister_sandbox --bin sandbox_launcher \
            || exit 1
    )
}

## This function is called to run remote benchmarks
run_remote() {
    (
        cd "${REMOTE_BENCHMARK_DIR}"
        SANDBOX_BINARY="${REMOTE_TARGET_DIR}/${REMOTE_PROFILE}/canister_sandbox" \
            LAUNCHER_BINARY="${REMOTE_TARGET_DIR}/${REMOTE_PROFILE}/sandbox_launcher" \
            cargo bench ${FILTER} ${REMOTE_BENCH_ARGS} \
            || exit 1
    )
}

########################################################################
## Analyze and print the results
########################################################################

print_git_header() {
    printf "%-6s profile: %-11s commit: %s %s\n" \
        "Local" \
        "${LOCAL_PROFILE}" \
        "$(git rev-parse --short=8 HEAD)" \
        "$(git describe --always --all | sed -e 's#heads/##')" \
        "Remote" \
        "${REMOTE_PROFILE}" \
        "$(git -C ${REMOTE_REPO_DIR} rev-parse --short=8 HEAD)" \
        "$(git -C ${REMOTE_REPO_DIR} describe --always --all | sed -e 's#heads/##')"
    echo
}

print_md_header() {
    printf "| %-42s | %-11s | %-11s | %-7s |\n" "$1" "$2" "$3" "$4" \
        "$(printf -- '-%.0s' $(seq 42))" "$(printf -- '-%.0s' $(seq 11))" \
        "$(printf -- '-%.0s' $(seq 11))" "$(printf -- '-%.0s' $(seq 7))"
}

cat_local_benchmark_names() {
    cat "${CACHE_DIR}/summary-local.txt" | rg "Benchmarking .*: Analyzing" \
        | sed -Ee 's/^Benchmarking ([^:]*): Analyzing.*$/\1/'
}

## Print max throughput out of series of results
print_max_throughput() {
    local name="${1}"
    local file="${2}"
    ## Apply name transformations to match between local and remote benchmarks
    ## ic0.call()/1B -> ic0.*call().*1B
    match="$(echo ${name} | sed -Ee 's#([^()0-9A-Za-z]+)#.*#g')"
    cat "${file}" | rg "${match}" -A 3 | rg "thrpt:" \
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
    ## Apply name transformations to match between local and remote benchmarks
    ## ic0.call()/1B -> ic0.*call().*1B
    match="$(echo ${name} | sed -Ee 's#([^()0-9A-Za-z]+)#.*#g')"
    cat "${file}" | rg "${match}" -A 3 | rg "time:" \
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
            case /us/: return i / 1000 * 1000;
            case /s/: return i * 1;
        }
    }
    {
        if (convert($3) != 0) {
            speedup = int(convert($4)/convert($3)*100) - 100;
            sum += speedup;
            count++;
            printf "| %-42s | %11s | %11s | %+6d% |\n", $2, $3, $4, speedup;
        } else {
            printf "| %-42s | %11s | %11s | %7s |\n", $2, $3, $4, "-";
        }
    }
    END { if (count) printf "\nAverage speedup of the local changes: %+d%", sum/count }
    '
    echo " (${what})"
}

########################################################################
## Init repositories
########################################################################

init_local
init_remote

########################################################################
## Run all the benchmarks 9 times
########################################################################

for i in $(seq ${REPEAT}); do
    echo "==> Iteration ${i}: running local benchmarks..."
    if [ -s "${CACHE_DIR}/local-${i}-sum.txt" -a -z "${LOCAL_NO_CACHE}" ]; then
        echo "    CACHED"
    else
        run_local \
            | tee "${CACHE_DIR}/local-${i}.txt" \
            | rg --line-buffered "Benchmarking .*: Analyzing" -A 3 \
            | tee "${CACHE_DIR}/local-${i}-sum.txt"
    fi
    echo "==> Iteration ${i}: running remote benchmarks..."
    if [ -s "${CACHE_DIR}/remote-${i}-sum.txt" -a -z "${REMOTE_NO_CACHE}" ]; then
        echo "    CACHED"
    else
        run_remote \
            | tee "${CACHE_DIR}/remote-${i}.txt" \
            | rg --line-buffered "Benchmarking .*: Analyzing" -A 3 \
            | tee "${CACHE_DIR}/remote-${i}-sum.txt"
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
    echo "${CACHE_DIR}/local-${i}-sum.txt"
done | xargs paste >"${CACHE_DIR}/summary-local.txt"
for i in $(seq ${REPEAT}); do
    echo "${CACHE_DIR}/remote-${i}-sum.txt"
done | xargs paste >"${CACHE_DIR}/summary-remote.txt"

## Generate final report
(
    echo "System API Performance Report"
    echo "============================="
    echo
    print_git_header

    ## For each benchmark, print max local and remote throughput
    print_md_header "API Type / System API Call" "Remote, IPS" "Local, IPS" "Speedup"
    cat_local_benchmark_names \
        | while read name; do
            printf "| ${name} | "
            print_max_throughput "${name}" "${CACHE_DIR}/summary-remote.txt"
            printf " | "
            print_max_throughput "${name}" "${CACHE_DIR}/summary-local.txt"
            printf " |\n"
        done \
        | transform_elem_s | transform_benchmark_name \
        | calculate_average_speedup "throughput"

    echo

    ## For each benchmark, print min local and remote time
    print_md_header "API Type / System API Call" "Remote Time" "Local Time" "Speedup"
    cat_local_benchmark_names \
        | while read name; do
            printf "| ${name} | "
            print_min_time "${name}" "${CACHE_DIR}/summary-remote.txt"
            printf " | "
            print_min_time "${name}" "${CACHE_DIR}/summary-local.txt"
            printf " |\n"
        done \
        | transform_s | transform_benchmark_name \
        | calculate_average_speedup "time"
    echo

    ## Print footer
    echo "Note: marked calls have no loop, so those results should not be compared vs other calls"
) | tee "${0##*/}-report.txt"
