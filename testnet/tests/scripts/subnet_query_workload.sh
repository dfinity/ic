#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Subnet handles different query workloads

Goal:: Ensure IC responds to queries of a given size in a timely manner.

Runbook::
. set up the testnet (nns + subnet installation)
. start the workload generator
. send user-specified number of requests per second over a user-specified duration to one node
. wait (configurable)
. collect metrics
. print results

Success::
.. average finalization rate >= 0.3 (over all replicas in 60s windows), and
.. 95% of successful queries are completed within 600ms of their submission
   (measured on the node receiving the query) -- use 95% so that we allow for
   variability due to failing nodes and uniformity across scenario tests, and
.. all requests issued by the workload generator return status OK

end::catalog[]
DOC

set -exuo pipefail
export exit_code=0

function exit_usage() {
    echo >&2 "Usage: <testnet_identifier> <exec_time_in_seconds> <rate> <payload_size> <load_dest> <results_dir>"
    echo >&2 "$0 p2p_15_28 30 40 250b boundary_nodes ./results/"
    exit 1
}

if (($# != 6)); then
    exit_usage
fi

testnet="$1"
exec_time="$2"
rate="$3"
payload_size="$4"
load_dest="$5"
results_dir="$(
    mkdir -p "$6"
    realpath "$6"
)"

experiment_dir="$results_dir/subnet_query_workload_test_${testnet}-rt_${exec_time}-rate_${rate}-payload_${payload_size}-dest_${load_dest}-$(date +%s)"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

if ! printf '%s\n' "boundary_nodes" "replica_nodes" "dns" | grep -q "^$load_dest\$"; then
    echo >&2 "Invalid load destination specified, choose between 'boundary_nodes | replica_nodes | dns'"
    exit_usage
fi

# These are the hosts that the workload generator will target.
# We select the first of the subnet with index 1.
# (Note: the workload generator uses the IPv4 address of the host even if the host has an IPv6 address.
#  this is for the case when the machine that is running the test cannot connect to the host using IPv6)
install_endpoints=$(jq_hostvars 'map(select(.subnet_index==1) | .api_listen_url) | join(",")')

http2_only=false
if [[ "$load_dest" == "dns" ]]; then
    loadhosts="https://$testnet.dfinity.network/"
elif [[ "$load_dest" == "replica_nodes" ]]; then
    loadhosts=$install_endpoints
elif [[ "$load_dest" == "boundary_nodes" ]]; then
    http2_only=true
    loadhosts=$(jq_hostvars 'map(select(.subnet_index=="boundary") | .api_listen_url) | join(",")')
else
    exit_usage
fi
echo "Using loadhosts = ""$loadhosts"

# Results will be stored in $results_dir/$experiment_id -- this will allow us to collect all runs
# if ever needed.
# To make it discernable, use all the inputs, plus the current starttime
echo "Creating '$experiment_dir' to store all the data for this run."
mkdir -p "$experiment_dir"
echo "Populating '$experiment_dir' with git info and experiment params."
echo "'$testnet' '$exec_time' '$rate' '$payload_size' '$load_dest' '$results_dir'" >"$experiment_dir/params"

echo "Starting Testcase subnet_query_workload"
echo "On testnet with identifier $testnet with execution time $exec_time (in seconds)."

mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "FinalizationRate": finalization_rate
}
' >>"$experiment_dir/data_to_upload/FinalizationRate.json"
echo '
{
 "FailedRequestsPercentage": failed_requests_percentage
}
' >>"$experiment_dir/data_to_upload/FailedRequestsPercentage.json"
echo '
{
 "SlowRequestsPercentage": slow_requests_percentage
}
' >>"$experiment_dir/data_to_upload/SlowRequestsPercentage.json"

# Store the time at which the test was called, so we can compute how long everything takes.
calltime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$calltime")"

# re-deploy the testnet
deploy_with_timeout "$testnet" \
    --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}"
echo "$loadhosts" >"$experiment_dir/loadhosts"

echo "Testnet deployment successful. Test starts now."

# Sleep for 60s for two reasons
#  - metrics are already scraped after the testnet install
#  - there are no residual metrics that we may aggregate
sleep 60s
starttime="$(date '+%s')"

# Store the test start time in epoch, so we could query Prometheus later.
echo "Start time: $(dateFromEpoch "$starttime")"
echo "$starttime" >"$experiment_dir/starttime"

# As we start the workload generator in a subshell, the only way to pass the information back
# is via files.
# In this file, we store the end time, so we could query prometheus later.
wg_endtime_file="$experiment_dir/endtime"
wg_log="$experiment_dir/workload-generator.log"
wg_err_log="$experiment_dir/workload-generator-err.log"
wg_status_file="$experiment_dir/wg_exit_status"
# Start the workload generator in a subshell. This will allow us to have a better
# control over when it finishes.
(
    {
        local_wg_status=0
        # Leave enough extra time for the workload generator to report summary.
        # After a timeout make sure it's terminated, otherwise we may end up with stale processes
        # on the CI/CD which block the entire pipeline (other job invocations).
        timeout -k 300 $((exec_time + 600)) ic-workload-generator \
            "$loadhosts" \
            -r "$rate" \
            --payload-size="$payload_size" \
            -n "$exec_time" \
            --http2-only "$http2_only" \
            --periodic-output \
            --install-endpoint="$install_endpoints" \
            --host "ic0.app" \
            --summary-file "$experiment_dir/workload-summary.json" 2>"$wg_err_log" \
            || local_wg_status=$?
        echo "$local_wg_status" >"$wg_status_file"
    } | tee -a "$wg_log"
    date '+%s' >"$wg_endtime_file"
) &
wg_pid=$!

# Ensure we kill these on CTRL+C
trap 'echo "SIGINT received, killing all jobs"; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1' INT

# Wait on the workload generator to finish
wait "$wg_pid"

endtime="$(<"$wg_endtime_file")"
wg_status="$(<"$wg_status_file")"

echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

duration=$((endtime - starttime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

# Get the report
# Produce the list of all nodes in the testnet, suitable for passing to the Prometheus query
metricshosts="$(jq_subnet_load_urls_for_metrics 1)"

# Extract the IC name from the testnet name (p2p_15_28 -> p2p)
ic="${testnet%%_*}"

# Get these metrics. We will go from the start time to the endtime, with 60s step.
# In each of the time windows (steps) we calculate the min, max, avg for the metric.
mkdir -p "$experiment_dir/metrics"
common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts\""
echo "Querying metrics for: $common_labels"

metric="artifact_pool_consensus_height_stat"
selector="$metric{$common_labels,type=\"finalization\",pool_type=\"validated\",stat=\"max\"}"
for op in min max avg; do
    curl -G "http://prometheus.dfinity.systems:9090/api/v1/query_range" \
        -o "$experiment_dir/metrics/${metric}_${op}.json" \
        -fsSL -m 30 --retry 10 --retry-connrefused \
        -H "Accept: application/json" \
        --data-urlencode "start=$starttime" \
        --data-urlencode "end=$endtime" \
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
    -o "$experiment_dir/metrics/${metric}.json" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -H "Accept: application/json" \
    --data-urlencode "start=$offset_starttime" \
    --data-urlencode "end=$((endtime > offset_starttime ? endtime : offset_starttime))" \
    --data-urlencode "step=60s" \
    --data-urlencode "query=histogram_quantile(0.90, sum by (le) (rate(${selector}[60s])))"

echo "Results stored in '$experiment_dir/metrics'"

# Now, check if we were good
if [[ $wg_status != 0 ]]; then
    failure "Workload generator didn't finish successfully. Exit code: $wg_status"
    # No point in doing further checks because other files may be missing.
    exit $exit_code
fi

# Finalization rate > 0.3
finalization_rate="$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")"

sed -i "s/finalization_rate/$finalization_rate/g" "$experiment_dir/data_to_upload/FinalizationRate.json"

expected_finalization=$(finalization_rate_threshold 1)
if (($(bc <<<"$finalization_rate < $expected_finalization"))); then
    failure "Finalization rate $finalization_rate less than ${expected_finalization}, fail!"
else
    success "Finalization rate $finalization_rate greater than ${expected_finalization}, great success!"
fi

# There are two important criteria to check:
# 1. 80% of requests take less than 500ms: We get this from prometheus
# 2. up to 1% of requests can fail: We get this from the workload generator

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

echo "Max completion time ok $max_ok."

# Use values from the workload generator to calculate the number of failures

# 200 is the status of good message, everything else is a faulty one
status_200_good="$(jq -r '.[0].status_counts."200" // 0' <"$experiment_dir/workload-summary.json")"
# total number of messages
status_total="$(jq -r '.[0].status_counts | add' <"$experiment_dir/workload-summary.json")"

if [[ $status_200_good == "0" ]]; then
    failure "There were no good requests, check '$experiment_dir/workload-summary.json'"
elif [[ $status_total -eq $status_200_good ]]; then
    success "All requests returned status OK."
else
    failure "Not all requests returned Status OK, check '$experiment_dir/workload-summary.json'"
fi

finaltime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$finaltime") (start time was $(dateFromEpoch "$calltime"))"

duration=$((finaltime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

exit $exit_code

# Hints: These steps can give you graphs on the command line
# go get github.com/guptarohit/asciigraph
# go install github.com/guptarohit/asciigraph/cmd/asciigraph
# jq -r '.data.result[0].values[] | .[1]' </var/folders/1s/pj0fjsyd6qgb3j166jczwcjh0000gn/T/tmp.nKR1g4geSk/consensus_ingress_message_bytes_delivered_sum_avg.json | asciigraph -h 40
