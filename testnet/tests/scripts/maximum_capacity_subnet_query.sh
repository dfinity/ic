#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Maximum capacity script for subnet query workload test

Goal:: Find maximum query requests per second that can be handled.

Runbook::
. set up the testnet (nns + subnet installation)
. repeatedly runs subnet_query_workload_test until it fails
. start the workload generator
. send user-specified number of queries per second over a user-specified duration
. wait (configurable)
. collect metrics
. print results
. if the metrics pass criterion, repeats the subnet_query_workload_test with higher rate.
. otherwise, show the result of last successful run.

Success::
.. average finalization rate >= 0.3 (over all replicas in 60s windows), and
.. 95% of successful queries are completed within 600ms of their submission
   (measured on the node receiving the query) -- use 95% so that we allow for
   variability due to failing nodes and uniformity across scenario tests, and
.. <= 5% of requests issued by the workload generator fail.

end::catalog[]
DOC

set -euo pipefail

function exit_usage() {
    echo >&2 "Usage: <testnet_identifier> <exec_time_in_seconds> <initial_rate> <rate_increment> <max_iterations> <payload_size> <load_destination> <subnet_type> <results_dir>"
    echo >&2 "$0 p2p_15_28 1200 200 20 10 1k [dest_fe|dest_nodes] [normal|large|large_nns|56_nns] ./results/"
    echo >&2 ""
    echo >&2 "If the $TEST_LOADHOSTS enviroment variable is set when invoking this script:"
    echo >&2 " - Use host specified as a comma separated list of hostnames from $TEST_LOADHOSTS instead of a testnet"
    echo >&2 " - Do not boot anything, assume IC with specified hosts is already running"
    echo >&2 ""
    exit 1
}

if (($# != 9)); then
    exit_usage
fi

testnet="$1"
runtime="$2"
initial_rate="$3"
rate_increment="$4"
max_iterations="$5"
payload_size="$6"
# load_dest="$7"  # shellcheck: unused
subnet_type="$8"
results_dir="$(
    mkdir -p "$9"
    realpath "$9"
)"
experiment_dir="$results_dir/${testnet}-rt_${runtime}-query-initial_rate_${initial_rate}-payload_${payload_size}-$(date +%s)"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

SUBNET_TYPES=("normal" "large" "large_nns" "56_nns")
if [[ ! " ${SUBNET_TYPES[*]} " =~ ${subnet_type} ]]; then
    echo >&2 "Invalid subnet type specified, choose between normal, large, large_nns and 56_nns."
    exit_usage
fi

subnet_index=1

hosts_file_path="$PROD_SRC/env/$testnet/hosts"
HOSTS_INI_ARGUMENTS=()
if [[ "$subnet_type" == "large" ]]; then
    # The test will run with a special hosts file creating a large app subnet.
    export HOSTS_INI_FILENAME=hosts_large_subnet.ini
    HOSTS_INI_ARGUMENTS+=(--hosts-ini "$HOSTS_INI_FILENAME")
fi
if [[ "$subnet_type" == "large_nns" ]]; then
    # The test will run with a special hosts file creating a large nns subnet.
    export HOSTS_INI_FILENAME=hosts_large_nns.ini
    HOSTS_INI_ARGUMENTS+=(--hosts-ini "$HOSTS_INI_FILENAME")
    subnet_index=0
fi
if [[ "$subnet_type" == "56_nns" ]]; then
    # The test will run with a special hosts file creating a large nns subnet.
    export HOSTS_INI_FILENAME=hosts_56_nns.ini
    HOSTS_INI_ARGUMENTS+=(--hosts-ini "$HOSTS_INI_FILENAME")
    subnet_index=0
fi

exit_code=0

# Store the time at which the test was called, so we can compute how long everything takes.
calltime="$(date '+%s')"

# These are the hosts that the workload generator will target.
# We select the first node of the subnet.
if [[ -n "${TEST_LOADHOSTS-}" ]]; then
    loadhosts="$TEST_LOADHOSTS"
else
    loadhosts=$(
        cd "$PROD_SRC"
        ansible-inventory -i "$hosts_file_path" --list \
            | jq -L"${PROD_SRC}/jq" -r 'import "ansible" as ansible;
                ._meta.hostvars |
                [
                    with_entries(select(.value.subnet_index== '"$subnet_index"' ))[] |
                    ansible::interpolate |
                    .api_listen_url
                ][0]'
    )
fi
echo "Using loadhosts = $loadhosts"

# Store the time at which the test was called, so we can compute how long everything takes.
calltime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$calltime")"

# re-deploy the testnet
if [[ -n "${TEST_LOADHOSTS-}" ]]; then
    echo "Running against hosts ${TEST_LOADHOSTS}; not booting IC"
else
    deploy_with_timeout "$testnet" \
        --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}"
fi

echo "Testnet deployment successful. Test starts now."

echo "$loadhosts" >"$experiment_dir/loadhosts"

starttime=""
endtime=""
finaltime=""
wg_endtime_file=""
wg_log=""
wg_err_log=""
wg_status_file=""
wg_status=""
duration=""
experiment_subdir=""
maximum_capacity_result_file="$experiment_dir/maximum_capacity"

show_maximum_capacity() {
    success_iteration=$(($1 - 1))
    if [[ $((success_iteration)) -eq 0 ]]; then
        echo "There were no successful subnet_query_workload_test runs."
    else
        rate=$((initial_rate + rate_increment * (success_iteration - 1)))
        echo "The last successful run of subnet_query_workload_test is with rate $rate and payload_size $payload_size."
        echo "$rate" >"$maximum_capacity_result_file"
    fi
}

set_variables() {
    experiment_subdir="$experiment_dir/$1"
    mkdir -p "$experiment_subdir"
    wg_endtime_file="$experiment_subdir/endtime"
    wg_log="$experiment_subdir/workload-generator.log"
    wg_err_log="$experiment_subdir/workload-generator-err.log"
    wg_status_file="$experiment_subdir/wg_exit_status"

    mkdir -p "$experiment_subdir/data_to_upload"
    echo '
    {
     "FinalizationRate": finalization_rate
    }
    ' >>"$experiment_subdir/data_to_upload/FinalizationRate.json"

    mkdir -p "$experiment_subdir/data_to_upload"
    echo '
    {
     "FailedRequestsPercentage": failed_requests_percentage
    }
    ' >>"$experiment_subdir/data_to_upload/FailedRequestsPercentage.json"

    mkdir -p "$experiment_subdir/data_to_upload"
    echo '
    {
     "SlowRequestsPercentage": slow_requests_percentage
    }
    ' >>"$experiment_subdir/data_to_upload/SlowRequestsPercentage.json"
}

set_start_time() {
    # Store the test start time in epoch, so we could query Prometheus later.
    # Sleep for 60s for two reasons
    #  - metrics are already scraped after the testnet install
    #  - there are no residual metrics that we may aggregate
    sleep 60s
    starttime="$(date '+%s')"
    echo "Starting the iteration $1 of the subnet_query_workload_test."
    echo "Start time: $(dateFromEpoch "$starttime")"
    echo "$starttime" >"$experiment_subdir/starttime"
}

start_workload_generator() {
    loadhosts="$1"
    cur_iteration="$2"
    rate=$((initial_rate + rate_increment * (cur_iteration - 1)))
    (
        {
            local_wg_status=0
            # Leave enough extra time for the workload generator to report summary.
            # After a timeout make sure it's terminated, otherwise we may end up with stale processes
            # on the CI/CD which block the entire pipeline (other job invocations).
            timeout -k 300 $((runtime + 600)) ic-workload-generator \
                "$loadhosts" \
                -r "$rate" \
                --payload-size="$payload_size" \
                -n "$runtime" \
                --periodic-output \
                --summary-file "$experiment_subdir/workload-summary.json" 2>"$wg_err_log" \
                || local_wg_status=$?
            echo "$local_wg_status" >"$wg_status_file"
        } | tee -a "$wg_log"
        date '+%s' >"$wg_endtime_file"
    ) &
    wg_pid=$!
    wait "$wg_pid"
    endtime="$(<"$wg_endtime_file")"
    wg_status="$(<"$wg_status_file")"
    echo "Ending system test *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

    duration=$((endtime - starttime))
    echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed in the iteration $cur_iteration of the subnet_query_workload_test."
}

check_workload_generator_status() {
    if [[ $wg_status != 0 ]]; then
        failure "Workload generator didn't finish successfully. Exit code: $wg_status"
        # No point in doing further checks because other files may be missing.
        return 1
    else
        return 0
    fi
}

query_finalization_rate_and_request_duration() {
    # Produce the list of all nodes in the testnet, suitable for passing to the Prometheus query
    metricshosts="$(jq_subnet_load_urls_for_metrics $subnet_index)"

    # Extract the IC name from the testnet name (p2p_15_28 -> p2p)
    ic="${testnet%%_*}"

    mkdir -p "$experiment_subdir/metrics"
    common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts\""
    echo "Querying metrics for: $common_labels"

    metric="artifact_pool_consensus_height_stat"
    selector="$metric{$common_labels,type=\"finalization\",pool_type=\"validated\",stat=\"max\"}"
    # Calculate the averages over the large interval.
    # We split into smaller buckets, then apply avg_over_time. The outer avg it
    # to get an aggregate, instead of having values per replica.
    curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
        -o "$experiment_subdir/metrics/${metric}_avg_total.json" \
        -fsSL -m 30 --retry 10 --retry-connrefused \
        -H "Accept: application/json" \
        --data-urlencode "time=$endtime" \
        --data-urlencode "query=avg(rate(${selector}[${duration}s]))"

    # As the requirement calls for 90% of requests per minute to take less than 2s,
    # we compute p80 for each minute.
    # This code will SILENTLY return wrong values if replica_http_request_duration_seconds
    # metric does not have buckets above 2s, or does not have a bucket at 2s.
    # No buckets above 2s will definitely return wrong values, while no bucket at 2s
    # will yield interpolated results, which may not be accurate.
    # If in doubt, consult the definition of the metric in rs/http_handler/src/lib.rs.
    # Quantile formula from: https://prometheus.io/docs/practices/histograms/#quantiles
    metric=replica_http_request_duration_seconds
    selector="${metric}_bucket{$common_labels,request_type=\"query\"}"
    # prometheus query_range buckets are based on end time, we use 60s buckets below, so add 60
    offset_starttime="$((starttime + 60))"
    curl -G "http://prometheus.dfinity.systems:9090/api/v1/query_range" \
        -o "$experiment_subdir/metrics/${metric}.json" \
        -fsSL -m 30 --retry 10 --retry-connrefused \
        -H "Accept: application/json" \
        --data-urlencode "start=$offset_starttime" \
        --data-urlencode "end=$((endtime > offset_starttime ? endtime : offset_starttime))" \
        --data-urlencode "step=60s" \
        --data-urlencode "query=histogram_quantile(0.90, sum by (le) (rate(${selector}[60s])))"

    echo "Results stored in '$experiment_subdir/metrics'"

}

check_success_criterion() {
    finalization_rate="$(jq -r '.data.result[0].value[1]' <"$experiment_subdir/metrics/artifact_pool_consensus_height_stat_avg_total.json")"

    sed -i "s/finalization_rate/$finalization_rate/g" "$experiment_subdir/data_to_upload/FinalizationRate.json"

    expected_finalization=$(finalization_rate_threshold $subnet_index)
    if (($(bc <<<"$finalization_rate < $expected_finalization"))); then
        failure "Finalization rate $finalization_rate less than ${expected_finalization}, fail!"
    else
        success "Finalization rate $finalization_rate greater than ${expected_finalization}, great success!"
    fi

    # There are two important criteria to check:
    # 1. 90% of the requests in every minute take less than 2s: We get this from prometheus
    # 2. up to 1% of requests can fail: We get this from the workload generator

    # We have to check here if the value is nan, since that could be returned from Prometheus. Also,
    # an explicit call to `tonumber` is needed, since Prometheus returns strings, not numbers.
    max_ok="$(jq -r '.data.result[0].values | [.[][1] // 0 | tonumber | (isnan|not) and (. <= 2.0)] | min' <"$experiment_subdir/metrics/replica_http_request_duration_seconds.json")"

    slow_requests_percentage="$(jq -r '.data.result[0].values | [.[][1] // 0 | tonumber] | max' <"$experiment_subdir/metrics/replica_http_request_duration_seconds.json")"
    sed -i "s/slow_requests_percentage/$slow_requests_percentage/g" "$experiment_subdir/data_to_upload/SlowRequestsPercentage.json"

    if [[ $max_ok == "true" ]]; then
        success "90% of requests completed in under 2s"
    else
        failure "Fewer than 90% of requests completed in under 2s, check '$experiment_subdir/metrics/replica_http_request_duration_seconds.json'"
    fi

    # Use values from the workload generator to calculate the number of failures
    # 200 is the status of good message, everything else is a faulty one
    status_44_timeout="$(jq -r '.[0].status_counts."44" // 0' <"$experiment_subdir/workload-summary.json")"
    status_33_rejected="$(jq -r '.[0].status_counts."33" // 0' <"$experiment_subdir/workload-summary.json")"
    status_11_update_send_failed="$(jq -r '.[0].status_counts."11" // 0' <"$experiment_subdir/workload-summary.json")"
    status_0_not_sent="$(jq -r '.[0].status_counts."0" // 0' <"$experiment_subdir/workload-summary.json")"
    status_200_good="$(jq -r '.[0].status_counts."200" // 0' <"$experiment_subdir/workload-summary.json")"
    status_bad=$((status_44_timeout + status_33_rejected + status_11_update_send_failed + status_0_not_sent))

    if [[ $((status_200_good + status_bad)) != "0" ]]; then
        bad_percentage=$(((100 * (status_bad)) / (status_200_good + status_bad)))
    else
        bad_percentage=100
    fi

    # In addition, ensure we don't have any HTTP failures -- these are the signal
    # the experiment was bad. HTTP failures are detected when return codes are
    # different from timeout, rejected, not_sent, or good.
    has_http_failure="$(jq -r '.[0].status_counts | keys | inside(["0", "11", "33", "44", "200"]) | not' <"$experiment_subdir/workload-summary.json")"

    sed -i "s/failed_requests_percentage/$bad_percentage/g" "$experiment_subdir/data_to_upload/FailedRequestsPercentage.json"

    if [[ $has_http_failure == "true" ]]; then
        failure "There existed http failure, check '$experiment_subdir/workload-summary.json'"
    elif [[ $status_200_good == "0" ]]; then
        failure "There were no good requests, check '$experiment_subdir/workload-summary.json'"
    elif [[ $bad_percentage -le "5" ]]; then
        success "No more than 5% of requests failed."
    else
        failure "More than 5% of requests failed, check '$experiment_subdir/workload-summary.json'"
    fi

    echo "Max completion time ok $max_ok, failures happened $has_http_failure, bad percentage $bad_percentage"

}

all_passed=true
for iteration in $(seq 1 "$max_iterations"); do
    set_variables "$iteration"

    set_start_time "$iteration"

    start_workload_generator "$loadhosts" "$iteration"

    trap 'echo "SIGINT received, killing all jobs"; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1' INT

    if ! check_workload_generator_status; then
        all_passed=false
        break
    fi

    query_finalization_rate_and_request_duration

    check_success_criterion

    if [[ $((exit_code)) -ne 0 ]]; then
        all_passed=false
        break
    fi
done

if [[ "$all_passed" == true ]]; then
    show_maximum_capacity $((max_iterations + 1))
else
    show_maximum_capacity "$iteration"
fi

finaltime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$finaltime") (start time was $(dateFromEpoch "$calltime"))"

duration=$((finaltime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed in total in this test."
echo "The test was called with the following arguments"
echo "$@"
