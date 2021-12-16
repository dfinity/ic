#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Subnet handles update workloads

Goal:: Ensure IC responds to update calls of a given size in a timely manner.

Runbook::
. set up the testnet (nns + subnet installation)
. start the workload generator
. wait (configurable)
. stop the workload generator after the time expires
. collect metrics
. print results

Success::
.. average finalization rate >= 0.3 (over all replicas in 60s windows), and
.. no latency alerts are reported by Prometheus, and
.. <= 5% of requests issued by the workload generator fail.

end::catalog[]
DOC

set -euo pipefail
export exit_code=0

function exit_usage() {
    echo >&2 "Usage: <testnet_identifier> <exec_time_in_seconds> <rate> <payload_size> <subnet_type> <load_dest> <results_dir>"
    echo >&2 "$0 p2p_15_28 30 40 250b normal replica_nodes ./results/"
    exit 1
}

if (($# != 7)); then
    exit_usage
fi

testnet="$1"
exec_time="$2"
rate="$3"
payload_size="$4"
subnet_type="$5"
load_dest="$6"
results_dir="$(
    mkdir -p "$7"
    realpath "$7"
)"

experiment_dir="$results_dir/subnet_update_workload_test_${testnet}-rt_${exec_time}-rate_${rate}-payload_${payload_size}-subnet_${subnet_type}-dest_${load_dest}-$(date +%s)"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

SUBNET_TYPES=("normal" "large" "large_nns" "56_nns")
if [[ ! " ${SUBNET_TYPES[*]} " =~ ${subnet_type} ]]; then
    echo >&2 "Invalid subnet type specified, choose between normal, large, large_nns and 56_nns."
    exit_usage
fi
if ! printf '%s\n' "boundary_nodes" "replica_nodes" "dns" | grep -q "^$load_dest\$"; then
    echo >&2 "Invalid load destination specified, choose between 'boundary_nodes | replica_nodes | dns'"
    exit_usage
fi

exit_code=0
subnet_index=1
HOSTS_INI_ARGUMENTS=()
HOSTS_INI_FILENAME=hosts.ini

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

# These are the hosts that the workload generator will target.
# We select all of them.
install_endpoints=$(jq_hostvars 'map(select(.subnet_index=='"${subnet_index}"') | .api_listen_url) | join(",")')

STATUS_CHECK=""
http2_only=false
if [[ "$load_dest" == "dns" ]]; then
    loadhosts="https://$testnet.dfinity.network/"
elif [[ "$load_dest" == "replica_nodes" ]]; then
    loadhosts=$install_endpoints
elif [[ "$load_dest" == "boundary_nodes" ]]; then
    loadhosts=$(jq_hostvars 'map(select(.subnet_index=="boundary") | .api_listen_url) | join(",")')
    http2_only=true
    STATUS_CHECK="--no-status-check"
else
    exit_usage
fi
echo "Using loadhosts = $loadhosts"
echo "$loadhosts" >"$experiment_dir/loadhosts"

# Results will be stored in $results_dir/$experiment_id -- this will allow us to collect all runs
# if ever needed.
# To make it discernable, use all the inputs, plus the current starttime
echo "Creating '$experiment_dir' to store all the data for this run."
mkdir -p "$experiment_dir"
echo "Populating '$experiment_dir' with git info and experiment params."
echo "'$testnet' '$exec_time' '$rate' '$payload_size' '$subnet_type' '$load_dest' '$results_dir'" >"$experiment_dir/params"

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
            "$loadhosts" -u \
            -r "$rate" \
            --payload-size="$payload_size" \
            -n "$exec_time" \
            --periodic-output $STATUS_CHECK \
            --http2-only "$http2_only" \
            --install-endpoint="$install_endpoints" \
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

# Produce the list of all nodes in the testnet, suitable for passing to the Prometheus query
metricshosts="$(jq_subnet_load_urls_for_metrics $subnet_index)"

# Extract the IC name from the testnet name (p2p_15_28 -> p2p)
ic="${testnet%%_*}"

mkdir -p "$experiment_dir/metrics"
common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts\""
metric="artifact_pool_consensus_height_stat"
selector="$metric{$common_labels,type=\"finalization\",pool_type=\"validated\",stat=\"max\"}"
# Calculate the averages over the large interval.
# We split into smaller buckets, then apply avg_over_time. The outer avg it
# to get an aggregate, instead of having values per replica.
curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
    -o "$experiment_dir/metrics/${metric}_avg_total.json" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -H "Accept: application/json" \
    --data-urlencode "time=$endtime" \
    --data-urlencode "query=avg(rate(${selector}[${duration}s]))"

# Gather latency alerts from Prometheus
latency_alert="IC_Replica_CallRequests_ResponseTooSlow"
curl -G "http://prometheus.dfinity.systems:9090/api/v1/query_range" \
    -o "$experiment_dir/metrics/${latency_alert}.json" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -H "Accept: application/json" \
    --data-urlencode "start=$starttime" \
    --data-urlencode "end=$endtime" \
    --data-urlencode "step=60s" \
    --data-urlencode "query=ALERTS{ic=\"$ic\",job=\"replica\",alertname=\"$latency_alert\"}"

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

expected_finalization=$(finalization_rate_threshold $subnet_index)
if (($(bc <<<"$finalization_rate < $expected_finalization"))); then
    failure "Finalization rate $finalization_rate less than ${expected_finalization}, fail!"
else
    success "Finalization rate $finalization_rate greater than ${expected_finalization}, great success!"
fi

# There are two important criteria to check:
# 1. no latency alert: We get this from prometheus
# 2. up to 5% of requests can fail: We get this from the workload generator

no_latency_alert="$(jq -r '.data.result[0] | not' <"$experiment_dir/metrics/IC_Replica_CallRequests_ResponseTooSlow.json")"

if [[ $no_latency_alert == "true" ]]; then
    success "No latency alert, great success!"
else
    failure "Latency is more than expected (see: https://sourcegraph.dfinity.systems/search?q=+IC_Replica_CallRequests_ResponseTooSlow:.*yaml), fail!"
fi

# Use values from the workload generator to calculate the number of failures

# 202 is the status of good message, everything else is a faulty one
status_202_good="$(jq -r '.[0].status_counts."202" // 0' <"$experiment_dir/workload-summary.json")"
# total number of messages
status_total="$(jq -r '.[0].status_counts | add' <"$experiment_dir/workload-summary.json")"
# bad message are anything that is not good. This meansknown bad http codes and unknown ones
status_bad_and_unknown="$((status_total - status_202_good))"

if [[ $status_total != "0" ]]; then
    bad_percentage=$(((100 * status_bad_and_unknown) / status_total))
else
    bad_percentage=100
fi

# check if we had unexpected http errors.
# but we should not fail if there are unknown failures.
# we only care about the precentage of bad status compared to good ones.
has_http_failure="$(jq -r '.[0].status_counts | keys | inside(["0", "11", "33", "44", "202", "503"]) | not' <"$experiment_dir/workload-summary.json")"

sed -i "s/failed_requests_percentage/$bad_percentage/g" "$experiment_dir/data_to_upload/FailedRequestsPercentage.json"

if [[ $status_202_good == "0" ]]; then
    failure "There were no good requests, check '$experiment_dir/workload-summary.json'"
elif [[ $bad_percentage -le "5" ]]; then
    success "No more than 5% of requests failed."
else
    failure "More than 5% of requests failed, check '$experiment_dir/workload-summary.json'"
fi

echo "Other (HTTP) failures happened $has_http_failure, bad percentage $bad_percentage"

finaltime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$finaltime") (start time was $(dateFromEpoch "$calltime"))"

duration=$((finaltime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

exit $exit_code

# Hints: These steps can give you graphs on the command line
# go get github.com/guptarohit/asciigraph
# go install github.com/guptarohit/asciigraph/cmd/asciigraph
# jq -r '.data.result[0].values[] | .[1]' </var/folders/1s/pj0fjsyd6qgb3j166jczwcjh0000gn/T/tmp.nKR1g4geSk/consensus_ingress_message_bytes_delivered_sum_avg.json | asciigraph -h 40
