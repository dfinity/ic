#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Subnet makes progress despite one third of the nodes being down

Runbook::
. set up the testnet (nns + subnet installation)
. start the workload generator against first third of the nodes
. add network delay, bandwidth restrictions, drops and node failures to a random nodes in the last third of the nodes
. stop the workload generator after the time expires
. collect metrics
. print results

Success::
.. Average finalization >= 0.3 (over all nodes NOT in last third, in 60s windows), and
.. p90 of successful counter update requests are completed within 15s of
      their submission (measured on the node receiving the update request) --
      use p90 so that we allow for variability due to failing nodes and
      uniformity, and
.. <= 5% of requests issued by the workload generator fail -- this is
     because no one has time to fix the workload generator, and it sometimes
     fails to deliver requests (increased to 20% for 56 node nns until a
     lower percentage is achievable).

end::catalog[]
DOC
export exit_code=0
set -euo pipefail
if (($# != 6)); then
    echo >&2 "Wrong number of arguments, please provide values for <testnet_identifier> <runtime_in_seconds> <rate> <payload_size> <topology> <results_dir>:"
    echo >&2 "$0 p2p_15 30 40 250b [normal|large|large_nns|56_nns] ./results/"
    exit 1
fi

testnet="$1"
runtime="$2"
rate="$3"
payload_size="$4"
subnet_type="$5"
results_dir="$(
    mkdir -p "$6"
    realpath "$6"
)"
experiment_dir="$results_dir/network_reliability_test_${testnet}-rt_${runtime}-rate_${rate}-payload_${payload_size}-$(date +%s)"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

SUBNET_TYPES=("normal" "large" "large_nns" "56_nns")
if [[ ! " ${SUBNET_TYPES[*]} " =~ ${subnet_type} ]]; then
    echo >&2 "Invalid subnet type specified, choose between normal, large, large_nns and 56_nns."
    exit_usage
fi

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
fi
if [[ "$subnet_type" == "56_nns" ]]; then
    # The test will run with a special hosts file creating a large nns subnet.
    export HOSTS_INI_FILENAME=hosts_56_nns.ini
    HOSTS_INI_ARGUMENTS+=(--hosts-ini "$HOSTS_INI_FILENAME")
fi

exit_code=0

# Store the time at which the test was called, so we can compute how long everything takes.
calltime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$calltime")"

mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "FinalizationRate": finalization_rate
}
' >>"$experiment_dir/data_to_upload/FinalizationRate.json"

echo '
{
 "SlowRequestsPercentage": slow_requests_percentage
}
' >>"$experiment_dir/data_to_upload/SlowRequestsPercentage.json"

# Deploy the testnet
deploy_with_timeout "$testnet" --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}"

echo "Testnet deployment successful. Test starts now."

# These are the hosts that the workload generator will target.
# The code picks the first 1/3 of the nodes, so it does not clash
# with the nodes that will be killed.
loadhosts_0=$(jq_subnet_nodes_urls_nth_third 0 0)
loadhosts_1=$(jq_subnet_nodes_urls_nth_third 1 0)
nodes_0=$(jq_subnet_nodes_nth_third 0 0)
nodes_1=$(jq_subnet_nodes_nth_third 1 0)
echo "$loadhosts_0" >"$experiment_dir/loadhosts_0"
echo "$loadhosts_1" >"$experiment_dir/loadhosts_1"
for node in ${nodes_0//,/ }; do # replace commas with spaces
    echo "subnet 0 load node $node"
done
for node in ${nodes_1//,/ }; do # replace commas with spaces
    echo "subnet 1 load node $node"
done

stress_nodes_0=$(jq_subnet_nodes_nth_third 0 2)
stress_nodes_1=$(jq_subnet_nodes_nth_third 1 2)
stress_nodes="${stress_nodes_0[*]}${stress_nodes_1[*]}"
for node in ${stress_nodes//,/ }; do # replace commas with spaces
    echo "stress node $node"
done

# Store the test start time in epoch, so we could query Prometheus later.
starttime="$(date '+%s')"

echo "Start time: $(dateFromEpoch "$starttime")"
echo "$starttime" >"$experiment_dir/starttime"

# As we start the workload generator in a subshell, the only way to pass the information back
# is via files.
# In this file, we store the end time, so we could query prometheus later.
wg_endtime_file="$experiment_dir/endtime"
wg_log="$experiment_dir/workload-generator.log"
wg_err_log="$experiment_dir/workload-generator-err.log"
wg_status_file="$experiment_dir/wg_exit_status"

run_workload_generator() {
    subnet=$1
    loadhosts=$2
    local_wg_status=0

    # Leave enough extra time for the workload generator to report summary.
    # After a timeout make sure it's terminated, otherwise we may end up with stale processes
    # on the CI/CD which block the entire pipeline (other job invocations).
    timeout -k 300 $((runtime + 300)) ic-workload-generator \
        "$loadhosts" -u \
        -r "$rate" \
        --payload-size="$payload_size" \
        -n "$runtime" \
        --periodic-output \
        --summary-file "$experiment_dir/${subnet}_workload-summary.json" 2>"$wg_err_log" \
        || local_wg_status=$?
    echo "$local_wg_status" >>"$wg_status_file"
    echo "finished workload generator for $loadhosts"
}
# Start the workload generator in a subshell. This will allow us to have a better
# control over when it finishes.
# Workload generator is run on NNS first and then on the app subnet.
(
    echo "Load nodes on subnet 0: $nodes_0"
    echo "Load nodes on subnet 1: $nodes_1"
    run_workload_generator 0 "$loadhosts_0" 2>&1 | tee -a "$wg_log" &
    # sleep to avoid race conditions
    echo "sleep before second wg call"
    sleep 3
    run_workload_generator 1 "$loadhosts_1" 2>&1 | tee -a "$wg_log" &
    wait
    date '+%s' >"$wg_endtime_file"
    echo "finished workload generation"
) &
wg_pid=$!

# We run the same scenario on every node designated for scenarios
scenario() {
    node=$1
    cd "$PROD_SRC/ansible"

    # when do we end the experiment
    end_at=$((starttime + runtime))

    while :; do
        # max time for all actions
        current_time="$(date '+%s')"
        if ((end_at <= current_time)); then
            echo "stress for node $node done"
            exit
        fi

        # Get the necessary parameters
        sleep_time=$((RANDOM % (end_at - current_time)))
        # Action time should be at least 10 minutes
        remaining=$((end_at - current_time - sleep_time - 10 * 60))
        if ((remaining < 0)); then
            remaining=1
        fi
        action_time=$((10 * 60 + RANDOM % remaining))
        # drop between 1 and 100% of packets
        drops_perc=$((1 + RANDOM % 99))
        # delay by 10 to 1000ms
        latency_ms=$((10 + RANDOM % 990))
        # restrict bandwidth to 10 to 100 mbit per second
        bandwidth_mbit=$((10 + RANDOM % 100))

        echo "stress for node $node: sleep_time: $sleep_time action_time: $action_time drops_perc: $drops_perc latency_ms: $latency_ms bandwidth_mbit: $bandwidth_mbit" >"$experiment_dir/action-log-$node"

        sleep "$sleep_time"
        ansible-playbook -i "../env/$testnet/hosts" icos_node_stress.yml \
            --limit "$node" -e ic_action=limit-bandwidth -e bandwidth_mbit="$bandwidth_mbit" -e latency_ms="$latency_ms" \
            -e drops_percentage="$drops_perc" 2>&1 | tee -a "$experiment_dir/ansible-action-${node}.log"

        sleep "$action_time"
        ansible-playbook -i "../env/$testnet/hosts" icos_node_stress.yml \
            --limit "$node" -e ic_action=reset 2>&1 | tee -a "$experiment_dir/ansible-action-${node}.log"

    done
}

for node in ${stress_nodes//,/ }; do # replace commas with spaces
    scenario "$node" &
done

# Wait on the workload generator to finish
wait "$wg_pid"

# Ensure we kill these on CTRL+C
trap 'echo "SIGINT received, killing all jobs"; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1' INT

# Wait on all subshells
wait

endtime="$(<"$wg_endtime_file")"

echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

duration=$((endtime - starttime))
offset_starttime="$((starttime + 60))"
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

# Get the report
# Produce the list of all unaffected nodes in the testnet, suitable for passing to the Prometheus query
metricshosts=$(join_array $'\n' "$(jq_subnet_load_third_nodes_urls_for_metrics 0)" "$(jq_subnet_load_third_nodes_urls_for_metrics 1)" | grep -v '^$' | tr '\n' '|' | sed 's/|$//')

# Extract the IC name from the testnet name (p2p_15_28 -> p2p)
ic="${testnet%%_*}"

# Get these metrics. We will go from the start time to the endtime, with 60s step.
# In each of the time windows (steps) we calculate the min, max, avg for the metric.
mkdir -p "$experiment_dir/metrics"
common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts\""
metric="artifact_pool_consensus_height_stat"
selector="$metric{$common_labels,type=\"finalization\",pool_type=\"validated\",stat=\"max\"}"
for op in min max avg; do
    curl -G "http://prometheus.dfinity.systems:9090/api/v1/query_range" \
        -fsSL -m 30 --retry 10 --retry-connrefused \
        -o "$experiment_dir/metrics/${metric}_${op}.json" \
        -H "Accept: application/json" \
        --data-urlencode "start=$offset_starttime" \
        --data-urlencode "end=$((endtime > offset_starttime ? endtime : offset_starttime))" \
        --data-urlencode "step=60s" \
        --data-urlencode "query=$op(rate(${selector}[60s]))"
done

# Calculate the averages over the large interval.
# We split into smaller buckets, then apply avg_over_time. The outer avg it
# to get an aggregate, instead of having values per replica.
curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
    -o "$experiment_dir/metrics/${metric}_avg_total.json" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -H "Accept: application/json" \
    --data-urlencode "time=$endtime" \
    --data-urlencode "query=avg(rate(${selector}[${duration}s]))"

# As the requirement calls for 90% of requests to take less than 2s,
# we compute p90.
# This code will SILENTLY return wrong values if replica_http_request_duration_seconds
# metric does not have buckets above 2s, or does not have a bucket at 2s.
# No buckets above 2s will definitely return wrong values, while no bucket at 2s
# will yield interpolated results, which may not be accurate.
# If in doubt, consult the definition of the metric in rs/http_handler/src/lib.rs.
# Quantile formula from: https://prometheus.io/docs/practices/histograms/#quantiles
metric=replica_http_request_duration_seconds
selector="${metric}_bucket{$common_labels,type=\"submit\",request_type=\"call\"}"
# prometheus query_range buckets are based on end time, we use 60s buckets below, so add 60
offset_starttime="$((starttime + 60))"
curl -G "http://prometheus.dfinity.systems:9090/api/v1/query_range" \
    -o "$experiment_dir/metrics/${metric}.json" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -H "Accept: application/json" \
    --data-urlencode "start=$offset_starttime" \
    --data-urlencode "end=$((endtime > offset_starttime ? endtime : offset_starttime))" \
    --data-urlencode "step=60s" \
    --data-urlencode "query=histogram_quantile(0.90, sum by (le) (rate(${selector}[60s])))"

echo "Results stored in '$experiment_dir/metrics'"

# Now, check if we were good

exit_code=0
endtime="$(<"$wg_endtime_file")"
finaltime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$finaltime") (start time was $(dateFromEpoch "$calltime"))"

duration=$((finaltime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

while read -r wg_status; do
    if [[ $wg_status != '0' ]]; then
        failure "Workload generator didn't finish successfully. Exit code: $wg_status"
        # No point in doing further checks because other files may be missing.
        exit "$exit_code"
    fi
done <"$wg_status_file"

# Finalization rate exceeding expected threshold
finalization_rate="$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")"

sed -i "s/finalization_rate/$finalization_rate/g" "$experiment_dir/data_to_upload/FinalizationRate.json"

# use expected finalization rate for NNS subnet (index 0)
expected_finalization=$(finalization_rate_threshold 0)
if (($(bc <<<"$finalization_rate < $expected_finalization"))); then
    failure "Finalization rate $finalization_rate less than ${expected_finalization}, fail!"
else
    success "Finalization rate $finalization_rate greater than ${expected_finalization}, great success!"
fi

# There are two important criteria to check:
# 1. 90% of requests take less than 2s: We get this from prometheus
# 2. up to 5% of requests can fail: We get this from the workload generator

# We have to check here if the value is nan, since that could be returned from Prometheus. Also,
# an explicit call to `tonumber` is needed, since Prometheus returns strings, not numbers.
max_ok="$(jq -r '.data.result[0].values | [.[][1] // 0 | tonumber | (isnan|not) and (. <= 2.0)] | min' <"$experiment_dir/metrics/replica_http_request_duration_seconds.json")"

slow_requests_percentage="$(jq -r '.data.result[0].values | [.[][1] // 0 | tonumber] | max' <"$experiment_dir/metrics/replica_http_request_duration_seconds.json")"
sed -i "s/slow_requests_percentage/$slow_requests_percentage/g" "$experiment_dir/data_to_upload/SlowRequestsPercentage.json"

if [[ $max_ok == "true" ]]; then
    success "90% of requests completed in under 2s"
else
    failure "Fewer than 90% of requests completed in under 2s, check '$experiment_dir/metrics/replica_http_request_duration_seconds.json'"
fi

# Use values from the workload generator to calculate the number of failures
# 202 is the status of good message, everything else is a faulty one
status_202_good_0="$(jq -r '.[0].status_counts."202" // 0' <"$experiment_dir/0_workload-summary.json")"
status_202_good_1="$(jq -r '.[0].status_counts."202" // 0' <"$experiment_dir/1_workload-summary.json")"
status_total_0="$(jq -r 'reduce (.[0].status_counts | to_entries[]) as {$key,$value} (0 ; . += $value)' <"$experiment_dir/0_workload-summary.json")"
status_total_1="$(jq -r 'reduce (.[0].status_counts | to_entries[]) as {$key,$value} (0 ; . += $value)' <"$experiment_dir/1_workload-summary.json")"

if [[ $((status_total_0 + status_total_1)) != "0" ]]; then
    bad_percentage=$((100 * (status_total_0 + status_total_1 - status_202_good_0 - status_202_good_1) / (status_total_0 + status_total_1)))
else
    bad_percentage=100
fi
echo "bad percentage $bad_percentage"

if [[ $bad_percentage -le "5" ]]; then
    success "No more than 5% of requests failed."
elif [[ "$subnet_type" == "56_nns" ]]; then
    if [[ $bad_percentage -le "20" ]]; then
        success "At most 20% of the requests failed."
    else
        failure "More than 20% of the requests failed, check '$experiment_dir/0_workload-summary.json and $experiment_dir/1_workload-summary.json'"
    fi
else
    failure "More than 5% of requests failed, check '$experiment_dir/0_workload-summary.json and $experiment_dir/1_workload-summary.json'"
fi

finaltime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$finaltime") (start time was $(dateFromEpoch "$calltime"))"

duration=$((finaltime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

echo "The test was called with the following arguments"
echo "$@"

exit $exit_code
