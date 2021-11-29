#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]
Title:: Maximum capacity script for messages between different subnets
Goal:: Find maximum xnet messages per second that can be handled.
Runbook::
. set up the testnet (nns + subnet installation)
. install the xnet-test canister on each subnet
. call `start()` on each to have them send each other one request per round
. wait for `$runtime` seconds and call `stop()`
. collect canister-aggregated metrics regarding messages sent, requests received and latency
. if the metrics pass criterion, repeat the xnet_slo_test with higher rate. Otherwise, show the result of last successful run.

end::catalog[]
DOC

set -euo pipefail

function exit_usage() {
    echo >&2 "Wrong number of arguments, please provide values for <testnet_identifier> <subnets> <initial_rate> <rate_increment> <max_rounds> <payload_size> <subnet_type> <results_dir>:"
    echo >&2 "$0 cdslo 2 10 100 6 1024 [normal|single_node] /results/"
    exit 1
}

if (($# != 8)); then
    exit_usage
fi

runtime=600

testnet="$1"
subnets="$2"
initial_rate="$3"
rate_increment="$4"
max_rounds="$5"
payload_size="$6"
subnet_type="$7"
results_dir="$(
    mkdir -p "$8"
    realpath "$8"
)"
experiment_dir="$results_dir/${testnet}-rt_${runtime}-query-initial_rate_${initial_rate}-payload_${payload_size}-$(date +%s)"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

if [[ "$subnet_type" != "normal" ]] && [[ "$subnet_type" != "single_node" ]]; then
    echo >&2 "Invalid subnet type specified, choose between normal and single_node."
    exit_usage
fi

echo "Starting XNet test"
echo "On testnet with identifier $testnet with runtime $runtime (in seconds)."

# Helper function to convert times
dateFromEpoch() {
    date --date="@$1"
}

calltime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$calltime")"

# Preparatory work
hosts_file_path="$PROD_SRC/env/$testnet/hosts"
HOSTS_INI_ARGUMENTS=()
if [[ "$subnet_type" == "single_node" ]]; then
    # The test will run with a special hosts file creating many single-node app subnets.
    export HOSTS_INI_FILENAME=hosts_single_node_subnets.ini
    HOSTS_INI_ARGUMENTS+=(--hosts-ini "$HOSTS_INI_FILENAME")
fi

# Testnet NNS URL: the API endpoint of the first NNS replica.
if [[ -n "${TEST_NNS_URL-}" ]]; then
    nns_url="${TEST_NNS_URL}"
else

    deploy_with_timeout "$testnet" \
        --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}"

    nns_url=$(
        cd "$PROD_SRC"
        ansible-inventory -i "$hosts_file_path" --list \
            | jq -r -L"${PROD_SRC}/jq" 'import "ansible" as ansible;
            ._meta.hostvars |
            [
                with_entries(select(.value.subnet_index==0))[] |
                ansible::interpolate |
                .api_listen_url
            ] |
            first'
    )
fi

echo "Testnet deployment successful. Test starts now."

export XNET_TEST_CANISTER_WASM_PATH="$MEDIA_CANISTERS_PATH/xnet-test-canister.wasm"

starttime=""
endtime=""
finaltime=""
systemtest_endtime_file=""
systemtest_log=""

maximum_capacity_result_file="$experiment_dir/maximum_capacity"

show_maximum_capacity() {
    success_round=$(($1 - 1))
    if [[ $((success_round)) -eq 0 ]]; then
        echo "There were no successful xnet_slo_test runs."
    else
        rate=$((initial_rate + rate_increment * (success_round - 1)))
        echo "The last successful run of xnet_slo_test is with rate $rate and payload_size $payload_size."
        echo "$rate" >"$maximum_capacity_result_file"
    fi
}

set_variables() {
    experiment_subdir="$experiment_dir/$1"
    mkdir -p "$experiment_subdir"
    systemtest_endtime_file="$experiment_subdir/endtime"
    systemtest_log="$experiment_subdir/xnet-e2e.log"
}

set_start_time() {
    # Start time in seconds from epoch, to allow time arithmetic.
    starttime="$(date '+%s')"
    echo "Starting the round $1 of the xnet_slo_test."
    echo "Start time: $(dateFromEpoch "$starttime")"
    echo "$starttime" >"$experiment_subdir/starttime"
}

start_e2e_test_driver() {
    # Start the e2e system test in a subshell. This will allow us to have a better
    # control over when it finishes.
    cur_round="$1"
    rate=$((initial_rate + rate_increment * (cur_round - 1)))
    (
        {
            if ! e2e-test-driver \
                --nns_url "$nns_url" \
                --subnets "$subnets" \
                --runtime "$runtime" \
                --rate "$rate" \
                --payload_size "$payload_size" \
                --targeted_latency 40 \
                -- "4.3"; then
                echo "failed" >"$experiment_subdir/systemtest_failed"
            fi
        } | tee -a "$systemtest_log"
        date '+%s' >"$systemtest_endtime_file"
    ) &
    systemtest_pid=$!
    wait "$systemtest_pid"
    endtime="$(<"$systemtest_endtime_file")"
    echo "Ending system test *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

    duration=$((endtime - starttime))
    echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed in the round $cur_round of the xnet_slo_test."
}

check_e2e_test_driver_result() {
    if [[ -e "$experiment_subdir/systemtest_failed" ]]; then
        echo "System test failed, logs in '$systemtest_log'"
        return 1
    else
        echo "System test passed, continue with the next round"
        return 0
    fi
}

all_passed=true
for round in $(seq 1 "$max_rounds"); do
    set_variables "$round"

    set_start_time "$round"

    start_e2e_test_driver "$round"

    trap 'echo "SIGINT received, killing all jobs"; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1' INT

    if ! check_e2e_test_driver_result; then
        all_passed=false
        break
    fi

    #Sleep 2 minutes to avoid interfering the next run.
    sleep 120
done

if [[ "$all_passed" == true ]]; then
    show_maximum_capacity $((max_rounds + 1))
else
    show_maximum_capacity "$round"
fi

finaltime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$finaltime") (start time was $(dateFromEpoch "$calltime"))"

duration=$((finaltime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed in total in this test."
echo "The test was called with the following arguments"
echo "$@"
