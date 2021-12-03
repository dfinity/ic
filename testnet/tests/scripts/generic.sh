#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Generic Example Test

Runbook::
. set up the testnet (nns + subnet installation)
. start the workload generator against first third of the nodes
. wait (configurable)
. stop a replica
. stop the workload generator after the time expires
. collect metrics
. print results

Success::
.. Finalization rate above a threshold value.

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
runtime="$2"
rate="$3"
payload_size="$4"
results_dir="$(
    mkdir -p "$5"
    realpath "$5"
)"
experiment_dir="$results_dir/${testnet}-rt_${runtime}-rate_${rate}-payload_${payload_size}-$(date +%s)"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

# Store the time at which the test was called, so we can compute how long everything takes (including the deployment time).
calltime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$calltime")"

# Preparatory work
# Deploy the testnet
deploy_with_timeout "$testnet" --git-revision "$GIT_REVISION"
echo "Testnet deployment successful. Test starts now."

# Store the test start time in epoch, so we can query Prometheus later.
starttime="$(date '+%s')"
echo "Start time: $(dateFromEpoch "$starttime")"
echo "$starttime" >"$experiment_dir/starttime"

mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "FinalizationRate": finalization_rate
}
' >>"$experiment_dir/data_to_upload/FinalizationRate.json"

# These are the hosts that the workload generator will target to install the counter canister
# [1:] selects all nodes except the first one, which is going to be killed
loadhosts=$(jq_hostvars 'map(select(.subnet_index==1) | .api_listen_url)[1:] | join(",")')
echo "load_ulrs: $loadhosts"
echo "$loadhosts" >"$experiment_dir/loadhosts"

# As we start the workload generator in a subshell, the only way to pass the information back
# is via files.
# In this file, we store the end time, so we could query prometheus later.
wg_endtime_file="$experiment_dir/endtime"
wg_log="$experiment_dir/workload-generator.log"
wg_status_file="$experiment_dir/wg_exit_status"
# Start the workload generator in a subshell. This will allow us to have a better
# control over when it finishes.
(
    {
        local_wg_status=0
        # Leave enough extra time for the workload generator to report summary.
        # After a timeout make sure it's terminated, otherwise we may end up with stale processes
        # on the CI/CD which block the entire pipeline (other job invocations).
        timeout -k 300 $((runtime + 600)) ic-workload-generator \
            "$loadhosts" -u \
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

# And then kill replica while the workload generator is running and verify that
# the workload generator continues to run normally.

# Start the scenario (essentially, the list of actions against the subnet) in a subshell.
# This will allow us to kill these steps if they take too long.
(
    # Run ansible playbook to stop a node and start it again after runtime seconds
    downtime=$((runtime / 2))
    cd "$PROD_SRC/ansible"
    script --quiet --return "$experiment_dir/scenario.log" --command "set -x;
        ansible-playbook -i '../env/$testnet/hosts' icos_node_stress.yml \
            --limit '$(jq_nth_subnet_node 1 0)' \
            -e ic_action=kill-replica -e downtime_seconds='$downtime'" >/dev/null 2>&1 &
) &
scenario_pid=$!

# Ensure we kill all background processes on CTRL+C
trap 'echo "SIGINT received, killing all jobs"; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1' INT

# Wait for the workload generator and scenario process to finish
wait "$wg_pid" "$scenario_pid"
cat "$experiment_dir/scenario.log" || true

endtime="$(<"$wg_endtime_file")"
wg_status="$(<"$wg_status_file")"

echo "Workload generator process is done *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

if [[ $wg_status != 0 ]]; then
    # No point in doing further checks because other files may be missing.
    failure "Workload generator didn't finish successfully. Exit code: $wg_status"
fi

# Get workload duration from workload_generator.log summary, which does not include
# canister deployment time, only the workload running time.
duration=$(grep "Summary .*:" "$experiment_dir/workload-generator.log" | sed -e 's/Summary \(.*\)\.\(.*\)s: success\(.*\)/\1/')
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

# Get the report
collect_metrics

# Now, check if we were good
finalization_rate="$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")"

sed -i "s/finalization_rate/$finalization_rate/g" "$experiment_dir/data_to_upload/FinalizationRate.json"

expected_finalization=$(finalization_rate_threshold 1)
# reduce to 3/4 of the value because 1 node is failing and in small subnets the finalization rate will therefore be rocky
expected_finalization=$(jq -n '('"${expected_finalization}"' | tonumber) * 3 / 4')
if (($(bc <<<"$finalization_rate < $expected_finalization"))); then
    failure "Finalization rate $finalization_rate less than ${expected_finalization}, fail!"
else
    success "Finalization rate $finalization_rate greater than ${expected_finalization}, great success!"
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
