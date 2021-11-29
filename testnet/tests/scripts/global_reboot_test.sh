#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Global reboot

Goal:: Ensure IC is healthy after rebooting all nodes

Runbook::
. set up the testnet (nns + subnet installation)
. start the workload generator (counter canister and xnet canister)
. wait (configurable)
. reboot all nodes roughly at the same time
. stop the workload generator after the predefined time (10min) since rebooting replicas
. collect metrics
. print results

Success::
.. average finalization rate >= 0.3 (over all replicas in 60s windows) in the last 5min, and
.. 90% of successful counter update requests are completed within 15s of
   their submission (measured on the node receiving the update request) -- use
   p90 so that we allow for variability due to failing nodes and uniformity
   across scenario tests, and
.. mean xnet request roundtrip latency is below 15s.

end::catalog[]
DOC

set -euo pipefail
export exit_code=0

if (($# != 8)); then
    echo >&2 "Wrong number of arguments, please provide values for <testnet_identifier> <runtime_in_seconds> <rate> <payload_size> <subnets> <xnet_rate> <xnet_payload_size> <results_dir>:"
    echo >&2 "$0 p2p_15 600 2 50k 2 10 1024 ./results/"
    exit 1
fi

testnet="$1"
waittime_to_kill="$2"
rate="$3"
payload_size="$4"
subnets="$5"
xnet_rate="$6"
xnet_payload_size="$7"
results_dir="$(
    mkdir -p "$8"
    realpath "$8"
)"
experiment_dir="$results_dir/${testnet}-power-outage-$(date +%s)"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "FinalizationRate": finalization_rate
}
' >>"$experiment_dir/data_to_upload/FinalizationRate.json"
echo '
{
 "BytesDeliveredRate": bytes_delivered_rate
}
' >>"$experiment_dir/data_to_upload/BytesDeliveredRate.json"
echo '
{
 "SlowRequestsPercentage": slow_requests_percentage
}
' >>"$experiment_dir/data_to_upload/SlowRequestsPercentage.json"

# Preparatory work
# Deploy the testnet
deploy_with_timeout "$testnet" --git-revision "$GIT_REVISION"

echo "Testnet deployment successful. Test starts now."

# Check acceptance of the test 25 min after the nodes have been killed
runtime=$((waittime_to_kill + 1500))

# The mean response latency of xnet requests should be less than 30 seconds.
# This targeted value has taken the rebooting time of nodes into consideration.
targeted_latency=30

# Store the time at which the test was called, so we can compute how long everything takes.
calltime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$calltime")"

export XNET_TEST_CANISTER_WASM_PATH="$MEDIA_CANISTERS_PATH/xnet-test-canister.wasm"

# These are the hosts that the workload generator will target
# (all hosts in this test)
load_urls=$(jq_hostvars 'map(select(.subnet_index==1) | .api_listen_url) | join(",")')
echo "$load_urls" >"$experiment_dir/load_urls"

# Store the test start time in epoch, so we could query Prometheus later.
starttime="$(date '+%s')"

echo "Start time: $(dateFromEpoch "$starttime")"
echo "$starttime" >"$experiment_dir/starttime"

xnet_endtime_file="$experiment_dir/xnet_endtime"
xnet_log="$experiment_dir/xnet-workload.log"
# Start the test driver.
(
    {
        # Testnet NNS URL: the API endpoint of the first NNS replica.
        nns_url=$(jq_hostvars 'map(select(.subnet_index==0) | .api_listen_url) | first')

        command -v e2e-test-driver
        e2e-test-driver \
            --nns_url "$nns_url" \
            --subnets "$subnets" \
            --runtime "$runtime" \
            --rate "$xnet_rate" \
            --payload_size "$xnet_payload_size" \
            --targeted_latency "$targeted_latency" \
            -- "4.3"
    } | tee -a "$xnet_log"
    date '+%s' >"$xnet_endtime_file"
) &
xnet_pid=$!

# As we start the workload generator in a subshell, the only way to pass the information back
# is via files.
# In this file, we store the end time, so we could query prometheus later.
wg_endtime_file="$experiment_dir/endtime"
wg_log="$experiment_dir/workload-generator.log"
wg_status_file="$experiment_dir/wg_exit_status"
(
    {
        local_wg_status=0
        # Leave enough extra time for the workload generator to report summary.
        # After a timeout make sure it's terminated, otherwise we may end up with stale processes
        # on the CI/CD which block the entire pipeline (other job invocations).
        timeout -k 300 $((runtime + 600)) ic-workload-generator \
            "$load_urls" -u \
            -r "$rate" \
            --payload-size="$payload_size" \
            -n "$runtime" \
            --periodic-output \
            --summary-file "$experiment_dir/workload-summary.json" \
            || local_wg_status=$?
        echo "$local_wg_status" >"$wg_status_file"
    } | tee -a "$wg_log"
    date '+%s' >"$wg_endtime_file"
) &
wg_pid=$!

# Start the scenario (essentially, the list of actions against the subnet) in a subshell.
# This will allow us to kill these steps if they take too long.
(
    cd "$PROD_SRC"

    sleep "$waittime_to_kill"

    # After the sleep time, just reboot all the nodes and expect them to come back
    ansible nodes -i "env/${testnet}/hosts" \
        --become -m shell -a 'reboot -ff' \
        | tee -a "$experiment_dir/scenario.log"
) &
scenario_pid=$!

# Ensure we kill all background processes on CTRL+C
trap 'echo "SIGINT received, killing all jobs"; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1' INT

# Wait on the xnet workload to finish
wait "$xnet_pid"
# Wait on the workload generator to finish
wait "$wg_pid"
# Then kill the scenario, if still running. If not, continue
kill -9 "$scenario_pid" || true

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

measure_time=$((endtime - 300))

# Get these metrics. We will go from the last 5 minutes to the endtime, with 60s step.
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
        --data-urlencode "start=$measure_time" \
        --data-urlencode "end=$endtime" \
        --data-urlencode "step=60s" \
        --data-urlencode "query=$op(rate(${selector}[60s]))"
done

# Calculate the averages over the large interval (last 5min).
# We split into smaller buckets, then apply avg_over_time. The outer avg it
# to get an aggregate, instead of having values per replica.
curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
    -o "$experiment_dir/metrics/${metric}_avg_total.json" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -H "Accept: application/json" \
    --data-urlencode "time=$endtime" \
    --data-urlencode "query=avg(rate(${selector}[300s]))"

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
finalization_rate="$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")"

if [[ $wg_status != 0 ]]; then
    failure "Workload generator didn't finish successfully. Exit code: $wg_status"
    # No point in doing further checks because other files may be missing.
    exit $exit_code
fi

sed -i "s/finalization_rate/$finalization_rate/g" "$experiment_dir/data_to_upload/FinalizationRate.json"

expected_finalization=$(finalization_rate_threshold 1)
if (($(bc <<<"$finalization_rate < $expected_finalization"))); then
    failure "Finalization rate $finalization_rate less than $expected_finalization, fail!"
else
    success "Finalization rate $finalization_rate greater or equal than $expected_finalization, great success!"
fi

# Check 90% of requests take less than 2s: We get this from prometheus
# We have to check here if the value is nan, since that could be returned from Prometheus. Also,
# an explicit call to `tonumber` is needed, since Prometheus returns strings, not numbers.
max_ok="$(jq -r '.data.result[0].values | [.[][1] // 0 | tonumber | (isnan|not) and (. <= 2.0)] | min' <"$experiment_dir/metrics/replica_http_request_duration_seconds.json")"

if [[ $max_ok == "true" ]]; then
    success "90% of requests completed in under 2s"
else
    failure "Fewer than 90% of requests completed in under 2s, check '$experiment_dir/metrics/replica_http_request_duration_seconds.json'"
fi

# Use values from the workload generator to calculate the number of failures
# 202 is the status of good message, everything else is a faulty one
status_44_timeout="$(jq -r '.[0].status_counts."44" // 0' <"$experiment_dir/workload-summary.json")"
status_33_rejected="$(jq -r '.[0].status_counts."33" // 0' <"$experiment_dir/workload-summary.json")"
status_0_not_sent="$(jq -r '.[0].status_counts."0" // 0' <"$experiment_dir/workload-summary.json")"
status_202_good="$(jq -r '.[0].status_counts."202" // 0' <"$experiment_dir/workload-summary.json")"
status_bad=$((status_44_timeout + status_33_rejected + status_0_not_sent))

if [[ $((status_202_good + status_bad)) != "0" ]]; then
    bad_percentage=$(((100 * (status_bad)) / (status_202_good + status_bad)))
else
    bad_percentage=100
fi

# In addition, ensure we don't have any HTTP failures -- these are the signal
# the experiment was bad. HTTP failures are detected when return codes are
# different from timeout, rejected, not_sent, or good.
has_http_failure="$(jq -r '.[0].status_counts | keys | inside(["0", "33", "44", "202"]) | not' <"$experiment_dir/workload-summary.json")"
echo "Max completion time ok $max_ok, failures happened $has_http_failure, bad percentage $bad_percentage"

finaltime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$finaltime") (start time was $(dateFromEpoch "$calltime"))"

duration=$((finaltime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

exit $exit_code

# Hints: These steps can give you graphs on the command line
# go get github.com/guptarohit/asciigraph
# go install github.com/guptarohit/asciigraph/cmd/asciigraph
# jq -r '.data.result[0].values[] | .[1]' </var/folders/1s/pj0fjsyd6qgb3j166jczwcjh0000gn/T/tmp.nKR1g4geSk/consensus_ingress_message_bytes_delivered_sum_avg.json | asciigraph -h 40
