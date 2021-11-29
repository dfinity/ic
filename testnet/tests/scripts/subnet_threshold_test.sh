#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Subnet makes progress despite one third of the nodes being down

Runbook::
. set up the testnet (nns + subnet installation)
. start the workload generator against first third of the nodes
. wait (configurable)
. stop last third of the nodes
. stop the workload generator after the time expires
. collect metrics
. print results

Success::
.. alive nodes increased their finalization height 5 minutes after killing the nodes.

end::catalog[]
DOC

set -euo pipefail
export exit_code=0

function exit_usage() {
    echo >&2 "Usage: $0 <testnet> <runtime_in_seconds> <rate> <payload_size> <results_dir>"
    echo >&2 "$0 p2p_15 30 40 250b ./results/"
    exit 1
}

if (($# != 5)); then
    exit_usage
fi

testnet="$1"
waittime_to_kill="$2"
rate="$3"
payload_size="$4"
results_dir="$(
    mkdir -p "$5"
    realpath "$5"
)"
runtime=$((waittime_to_kill + 300))
experiment_dir="$results_dir/subnet_threshold_test_${testnet}-rt_${runtime}-rate_${rate}-payload_${payload_size}-$(date +%s)"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

# Store the time at which the test was called, so we can compute how long everything takes.
calltime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$calltime")"

mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "HeightStart": height_start
}
' >>"$experiment_dir/data_to_upload/HeightStart.json"

mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "HeightEnd": height_end
}
' >>"$experiment_dir/data_to_upload/HeightEnd.json"

# Preparatory work
# Deploy the testnet
deploy_with_timeout "$testnet" --git-revision "$GIT_REVISION"

echo "Testnet deployment successful. Test starts now."

# These are the hosts that the workload generator will target.
# The code picks the first 1/3 of the nodes, so it does not clash
# with the nodes that will be killed.
load_urls=$(jq_subnet_nodes_urls_nth_third 1 0)
echo "$load_urls" >"$experiment_dir/load_urls"

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
# Start the workload generator in a subshell. This will allow us to have a better
# control over when it finishes.
(
    {
        local_wg_status=0
        #  Leave enough extra time for the workload generator to report summary.
        #  After a timeout make sure it's terminated, otherwise we may end up with stale processes
        #  on the CI/CD which block the entire pipeline (other job invocations).
        timeout -k 300 $((runtime + 300)) ic-workload-generator \
            "$load_urls" -u \
            -r "$rate" \
            --payload-size="$payload_size" \
            -n "$runtime" \
            --periodic-output \
            --summary-file "$experiment_dir/workload-summary.json" 2>"$wg_err_log" \
            || local_wg_status=$?
        echo "$local_wg_status" >"$wg_status_file"
    } 2>&1 | tee -a "$wg_log"
    date '+%s' >"$wg_endtime_file"
) &
wg_pid=$!

# And now kill replicas while the workload generator is running and verify that
# the workload generator continues to run normally.
(
    # Stop nodes from 1st subnet, last third of the nodes
    stress_nodes=$(jq_subnet_nodes_nth_third 1 2)
    cd "$PROD_SRC/ansible"
    sleep "$waittime_to_kill"

    ansible-playbook -i "../env/$testnet/hosts" icos_node_stress.yml \
        --limit "$stress_nodes" -e ic_action=kill-replica 2>&1 | tee -a "$experiment_dir/scenario.log"
) &
scenario_pid=$!

# Ensure we kill all background processes on CTRL+C
trap 'echo "SIGINT received, killing all jobs"; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1' INT

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
# Produce the list of all unaffected nodes in the testnet, suitable for passing to the Prometheus query
metricshosts="$(jq_subnet_load_third_nodes_urls_for_metrics 1)"

# Extract the IC name from the testnet name (p2p_15_28 -> p2p)
ic="${testnet%%_*}"

measure_time=$((endtime - 300))

# Get these metrics. We will go from the last 5 min to the endtime, with 60s step.
# In each of the time windows (steps) we calculate the min for the metric.
# If min is increasing, we know the acceptance criteria is satisfied
mkdir -p "$experiment_dir/metrics"
common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts\""
metric="artifact_pool_consensus_height_stat"
selector="$metric{$common_labels,type=\"finalization\",pool_type=\"validated\",stat=\"max\"}"
curl -G "http://prometheus.dfinity.systems:9090/api/v1/query_range" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -o "$experiment_dir/metrics/${metric}_min.json" \
    -H "Accept: application/json" \
    --data-urlencode "start=$measure_time" \
    --data-urlencode "end=$endtime" \
    --data-urlencode "step=60s" \
    --data-urlencode "query=min($selector)"

echo "Results stored in '$experiment_dir/metrics'"

if [[ $wg_status != 0 ]]; then
    failure "Workload generator didn't finish successfully. Exit code: $wg_status"
    # No point in doing further checks because other files may be missing.
    exit $exit_code
fi

# There is a progress in the height
height_start="$(jq -r '.data.result[0].values | first | .[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_min.json")"
height_end="$(jq -r '.data.result[0].values | last | .[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_min.json")"
sed -i "s/height_start/$height_start/g" "$experiment_dir/data_to_upload/HeightStart.json"
sed -i "s/height_end/$height_end/g" "$experiment_dir/data_to_upload/HeightEnd.json"

if ((height_start >= height_end)); then
    failure "Some of the healthy nodes did not advance, fail!"
else
    success "All healthy nodes progressed, great success!"
fi

# Now, check if we were good
endtime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

duration=$((endtime - starttime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

exit $exit_code

# Hints: These steps can give you graphs on the command line
# go get github.com/guptarohit/asciigraph
# go install github.com/guptarohit/asciigraph/cmd/asciigraph
# jq -r '.data.result[0].values[] | .[1]' </var/folders/1s/pj0fjsyd6qgb3j166jczwcjh0000gn/T/tmp.nKR1g4geSk/consensus_ingress_message_bytes_delivered_sum_avg.json | asciigraph -h 40
