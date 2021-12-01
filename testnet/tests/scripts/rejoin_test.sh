#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Nodes can rejoin a subnet under load

Runbook::
. set up the testnet (nns + subnet installation)
. install the `statesync-test` canister multiple times, updates the canisters state repeatedly
. wait for some time (configurable) and kill a replica before all update calls finish
. after all update calls finish, stop one third of the replicas, which are all in the same data center as the first one
. restart the first killed replica (now it needs to catch up for the network to make progress)
. wait 10min

Success::
.. if the network still makes progress with 2/3 of the nodes in last 5min, and
.. if statesync duration < CUP interval = DKG interval length / finalization

Note::
 When setting size_level to 1 ~ 8, the script runs the test under large state.
 The size_level is the the number of vectors to be initialized by update calls in the `statesync-test` canister.
 Each `statesync-test` canister's state size will be `size_level` * `VECTOR_LENGTH` bytes after all update calls.
 When setting size_level to 0, the script deploys the IC with DKG interval length 20 and runs the test with
 128MiB canister state and waits 30s instead of 10min (basic correctnessm no performance check).

end::catalog[]
DOC
set -eExuo pipefail
export exit_code=0
if (($# != 6)); then
    echo >&2 "Wrong number of arguments, please provide values for <testnet_identifier> <runtime_in_seconds> <num_canisters> <size_level> <subnet_type> <results_dir>:"
    echo >&2 "$0 messaging 300 2 0 [normal|large] ./results/"
    exit 1
fi

testnet="$1"
runtime="$2"
num_canisters="$3"
size_level="$4"
subnet_type="$5"
results_dir="$(
    mkdir -p "$6"
    realpath "$6"
)"
experiment_dir="$results_dir/rejoin_test_${testnet}-rt_${runtime}-$(date +%s)"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"
export STATESYNC_TEST_CANISTER_WASM_PATH="statesync-test-canister.wasm"

if [[ $((size_level)) -eq 0 ]] && [[ $((runtime)) -lt $((runtime / 8 + 30 * num_canisters)) ]]; then
    echo >&2 "Please set a higher runtime to make sure other replicas make more progress after killing the first one."
    exit 1
fi

if [[ $((size_level)) -gt 8 ]]; then
    echo >&2 "The size_level is no greater than 8. When setting size_level to 0, it runs the original test without large state."
    exit 1
fi

# Store the time at which the test was called, so we can compute how long everything takes.
calltime="$(date '+%s')"

mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "HeightStart": height_start
}
' >>"$experiment_dir/data_to_upload/HeightStart.json"
echo '
{
 "HeightEnd": height_end
}
' >>"$experiment_dir/data_to_upload/HeightEnd.json"
echo '
{
 "StatesyncDuration": statesync_duration
}
' >>"$experiment_dir/data_to_upload/StatesyncDuration.json"

HOSTS_INI_ARGUMENTS=()
HOSTS_INI_FILENAME=hosts.ini
if [[ "$subnet_type" == "large" ]]; then
    # The test will run with a special hosts file creating a large app subnet.
    export HOSTS_INI_FILENAME=hosts_large_subnet.ini
    HOSTS_INI_ARGUMENTS+=(--hosts-ini "$HOSTS_INI_FILENAME")
fi

echo "Starting Rejoin Test"
echo "On testnet with identifier $testnet with runtime $runtime (in seconds)."

# Get the list of all nodes in subnet 1.
# shellcheck disable=SC2046
mapfile -d " " -t all_nodes <<<$(jq_hostvars 'map(select(.subnet_index==1) | .node_index) | @sh')

num_all_nodes=${#all_nodes[@]}

if [[ $((num_all_nodes)) -lt 4 ]]; then
    echo >&2 "The rejoin_test requires at least 4 nodes."
    exit 1
fi

# Get the list of data centers in subnet 1.
# shellcheck disable=SC2046
mapfile -t data_centers <<<$(jq_hostvars 'map(select(.subnet_index==1) | .ic_host[:3]) | unique | .[]')

num_data_centers=${#data_centers[@]}

declare -A dc_nodes
# Get the list of nodes in each data center.
for i in $(seq 0 $((num_data_centers - 1))); do
    dc_nodes[${i}]=$(jq_hostvars "map(select(.subnet_index==1 and .ic_host[:3]==\"${data_centers[${i}]}\") | .node_index)")
done

if [[ $((num_data_centers)) -lt 2 ]]; then
    echo "Only one dc, we'll run the test anyways, but it won't tell us if statesync across dcs works well"
    dc_nodes[0]=$(jq_hostvars "map(select(.subnet_index==1 and .ic_host[:3]==\"${data_centers[0]}\") | .node_index) | unique | .[2:]")
    dc_nodes[1]=$(jq_hostvars "map(select(.subnet_index==1 and .ic_host[:3]==\"${data_centers[0]}\") | .node_index) | unique | .[:2]")
fi

group_0_nodes=[]
group_1_nodes=[]
# Assign nodes to group_0 and group_1.
if [[ $((num_data_centers)) -gt 2 ]]; then
    # Because there are 3 or more data centers, there must exist a data center called D with no more than f + 1 nodes.
    # Assign nodes in data center D to group_1 and add more nodes until group_1 has f + 1 nodes.
    # Assign the rest of nodes to group_0. Choose a node in data center D to do state sync.
    # During the state sync, all other f nodes in group_1 are killed, so the state sync only happens across data centers.
    f=$(((num_all_nodes - 1) / 3))
    group_1_size=$((f + 1))
    num=0

    for i in $(seq 0 $((num_data_centers - 1))); do
        num=$(echo "${dc_nodes[${i}]}" | jq length)
        if [[ $num -le $group_1_size ]]; then
            group_1_nodes=${dc_nodes[${i}]}
            break
        fi
    done

    to_be_added=$((group_1_size - num))
    for i in $(seq 0 $((num_all_nodes - 1))); do
        if [[ $(echo "$group_1_nodes" | jq "contains([${all_nodes[i]}])") == "true" ]]; then
            continue
        fi
        if [[ $to_be_added -gt 0 ]]; then
            group_1_nodes=$(echo "$group_1_nodes" | jq ". + [${all_nodes[i]}]")
            to_be_added=$((to_be_added - 1))
        else
            group_0_nodes=$(echo "$group_0_nodes" | jq ". + [${all_nodes[i]}]")
        fi
    done
else
    # When there are 2 data centers, both data centers may have more than (num_all_nodes - 1) / 3 + 1 nodes.
    # If so, it is necessary to truncate the two node groups to f + 1 and 2 * f nodes and modify the hosts file.

    dc0_nodes=${dc_nodes[0]}
    dc1_nodes=${dc_nodes[1]}
    # Swap if necessary to make data_center_0 the one with more nodes.
    if [[ $(echo "${dc_nodes[0]}" | jq length) -lt $(echo "${dc_nodes[1]}" | jq length) ]]; then
        dc0_nodes=${dc_nodes[1]}
        dc1_nodes=${dc_nodes[0]}
    fi
    num_0=$(echo "$dc0_nodes" | jq length)
    num_1=$(echo "$dc1_nodes" | jq length)

    if [[ $((num_1)) -lt 2 ]]; then
        echo >&2 "Each data center must have at least 2 nodes in subnet_1 to trigger the rejoin_test."
        exit 1
    fi

    # Pick 2 * f nodes from data_center_0 and f + 1 nodes from data_center_1.
    if [[ $((num_0 / 2)) -gt $((num_1 - 1)) ]]; then
        f=$((num_1 - 1))
    else
        f=$((num_0 / 2))
    fi
    group_0_size=$((2 * f))
    group_1_size=$((f + 1))

    # Deploy the testnet in a customized way.
    cp -d -r "$PROD_SRC/env/$testnet/" "$experiment_dir/env"
    chmod -R u+w "$experiment_dir/env"
    # Update the hosts_file_path to the copied one.
    hosts_file_path="$experiment_dir/env/$HOSTS_INI_FILENAME"

    # Skip the nodes which are not selected in subnet_1 when deploying the testnet.
    for node in $(echo "$dc0_nodes" | jq .[${group_0_size}:] | jq -r '@sh'); do
        node_name="${testnet}.1.$node"
        sed -i "s/$node_name/#$node_name/g" "$hosts_file_path"
    done

    for node in $(echo "$dc1_nodes" | jq .[${group_1_size}:] | jq -r '@sh'); do
        node_name="${testnet}.1.$node"
        sed -i "s/$node_name/#$node_name/g" "$hosts_file_path"
    done

    unlink "$experiment_dir/env/config/common"
    ln -s "$PROD_SRC/env/common" "$experiment_dir/env/config/common"
    cp "$hosts_file_path" "$PROD_SRC/env/$testnet/$HOSTS_INI_FILENAME"

    group_0_nodes=$(echo "$dc0_nodes" | jq .[:${group_0_size}])
    group_1_nodes=$(echo "$dc1_nodes" | jq .[:${group_1_size}])
fi

# Nodes has been assigned to group_0 and group_1, which are jq arrays.
# Transform the jq arrays to other formats to be used later.
group_0_nodes_list=$(echo "$group_0_nodes" | jq -r 'join(",")')
# group_1_remaining_nodes_list does not contain the node which performs state sync.
group_1_remaining_nodes_list=$(echo "$group_1_nodes" | jq .[1:${group_1_size}] | jq -r 'join(",")')

# shellcheck disable=SC2046
mapfile -d " " -t node_indices_0 <<<$(
    echo "$group_0_nodes" | jq -r '@sh'
)
# shellcheck disable=SC2046
mapfile -d " " -t node_indices_1 <<<$(
    echo "$group_1_nodes" | jq -r '@sh'
)

echo "${node_indices_0[@]}" >"$experiment_dir/node_indices_0"
echo "${node_indices_1[@]}" >"$experiment_dir/node_indices_1"

# Ansible commands need node keys as arguments for `--limit` when we kill and restart nodes.
statesync_node="${testnet}.1.${node_indices_1[0]}"
readarray -t group_1_remaining_keys < <(jq_hostvars "with_entries(select(.value.node_index | IN($group_1_remaining_nodes_list))) | keys[] ")

echo "Node $statesync_node is selected to do state sync with nodes in the other data center."

# Testnet NNS URL: the API endpoint of the first NNS replica.
nns_url=$(jq_hostvars '[._meta.hostvars[.nns.hosts[0]]]' 'map(.api_listen_url)[0]')

if [[ $((size_level)) -eq 0 ]]; then
    # Deploy to testnet DKG interval length 20
    deploy_with_timeout "$testnet" --dkg-interval-length 20 --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}"
else
    # Deploy to testnet
    deploy_with_timeout "$testnet" \
        --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}"
fi

echo "Testnet deployment successful. Test starts now."

# Unpack statesync-test-canister.wasm and let Project::cargo_bin() know about its location.
export STATESYNC_TEST_CANISTER_WASM_PATH="$MEDIA_CANISTERS_PATH/statesync-test-canister.wasm"

# Store the test start time in epoch, so we could query Prometheus later.
starttime="$(date '+%s')"

echo "Start time: $(dateFromEpoch "$starttime")"
echo "$starttime" >"$experiment_dir/starttime"

dkg_interval_length=$(ic-admin --nns-url "$nns_url" get-topology | jq -r ".topology.subnets | to_entries[1].value.records[0].value.dkg_interval_length")
echo "DKG interval lenght is $dkg_interval_length"

# As we start `e2e-test-driver` in a subshell, the only way to pass the information back
# is via files.
# In this file, we store the end time, so we could query prometheus later.
systemtest_endtime_file="$experiment_dir/endtime"
systemtest_log="$experiment_dir/statesync-e2e.log"

# Start the e2e system test in a subshell. This will allow us to have a better
# control over when it finishes.
(
    {
        echo "e2e part"
        command -v e2e-test-driver
        if ! e2e-test-driver \
            --nns_url "$nns_url" \
            --runtime "$runtime" \
            --num_canisters "$num_canisters" \
            --size_level "$size_level" \
            -- "5.2"; then
            echo "failed" >"$experiment_dir/systemtest_failed"
        fi
    } | tee -a "$systemtest_log"
    if [[ $((size_level)) -gt 0 ]]; then
        # Sleep 4 minutes to make the new checkpoint.
        sleep 240
    fi
    systemtest_endtime="$(date '+%s')"
    echo "$systemtest_endtime" >"$systemtest_endtime_file"
) &
systemtest_pid=$!

# Before stopping node 0, the subshell waits for 30s per canister if the size_level is 0
(
    # Run ansible playbook to stop the first node
    # after sleeping for some time to install the canisters and make a first call.
    # There is no precise control of how far the replica exactly goes when it is killed.
    # Usually, the earlier it gets killed, the larger the size of the state to sync will be.

    waittime_to_kill=$((30 * num_canisters))
    # For test with large state, the first node is killed at the very beginning so that the size of state sync
    # can be precisely controlled.

    if [[ $((size_level)) -eq 0 ]]; then
        sleep "$waittime_to_kill"
    fi
    cd "$PROD_SRC/ansible"
    ansible-playbook -i "../env/$testnet/hosts" icos_node_stress.yml \
        --limit "$statesync_node" \
        -e ic_action=kill-replica 2>&1 \
        | tee -a "$experiment_dir/scenario.log"

) &
scenario_pid=$!

# Ensure we kill these on CTRL+C
trap 'echo "SIGINT received, killing all jobs"; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1' INT

# Wait on the system test and scenario to finish
wait "$systemtest_pid" "$scenario_pid"
endtime="$(<"$systemtest_endtime_file")"
echo "Ending system test *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

duration=$((endtime - starttime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed in the first part of the test."

# TODO check result in a better way and print panic
if [[ -e "$experiment_dir/systemtest_failed" ]]; then
    echo "System test failed, logs in '$systemtest_log'"
    echo "The test was called with the following arguments"
    echo "$@"
    exit_code=1
    exit $exit_code
else
    echo "System test passed, continue with second part"
fi

# Start the second part of the scenario (essentially, the list of actions against the subnet) in a subshell.
# Kill the remaining f nodes in data_center_1.
# This will allow us to kill these steps if they take too long.
(
    cd "$PROD_SRC/ansible"
    stress_nodes="${group_1_remaining_keys[*]}"
    echo "stress_nodes $stress_nodes"
    ansible-playbook -i "../env/$testnet/hosts" icos_node_stress.yml \
        --limit "$stress_nodes" -e ic_action=kill-replica 2>&1 | tee -a "$experiment_dir/scenario.log"
) &
scenario_pid=$!

#Wait until scenario finishes
wait "$scenario_pid"

(
    # Run ansible playbook to reset the first node. The reset action will restart the replica.
    cd "$PROD_SRC/ansible"
    ansible-playbook -i "../env/$testnet/hosts" icos_node_stress.yml \
        --limit "$statesync_node" -e ic_action=reset | tee -a "$experiment_dir/scenario.log"
) &
scenario_pid=$!

wait "$scenario_pid"

# Sleep for 10min -- during this time, some nodes will be down.
# At the beginning of the sleeping time, the restarted replica will conduct state sync.
# Normally, state sync should finish within 5 minutes (which is roughly the CUP interval).
# The following 5 minutes is the time period for which we'll query the metrics.
# We need to ensure that progress is made even with partial membership.
# If the size level is 0 then we sleep for 30s only.
if [[ "$((size_level))" -eq "0" ]]; then
    echo "Sleep for 30s for statesync and querying (size level = 0)"
    sleep 30
else
    echo "Sleep for 10min for statesync and querying"
    sleep 600
fi

finaltime="$(date '+%s')"

echo "Final time: $(dateFromEpoch "$finaltime")"
echo "(Start time was $(dateFromEpoch "$starttime"))"

# Get the report
# Produce the list of all unaffected nodes in the testnet, suitable for passing to the Prometheus query
metricshosts=$(jq_load_filtered_urls_for_metrics ".node_index | IN($group_0_nodes_list)")
echo "metricshosts $metricshosts"

# Extract the IC name from the testnet name (p2p_15_28 -> p2p)
ic="${testnet%%_*}"

measure_time=$((finaltime - 300))

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
    --data-urlencode "end=$finaltime" \
    --data-urlencode "step=60s" \
    --data-urlencode "query=min($selector)"

# Get the finalization rate of unaffected nodes. We will go from the last 5 min to the endtime, with 60s step.
# Calculate the averages over the large interval.
# We split into smaller buckets, then apply avg_over_time. The outer avg it
# to get an aggregate, instead of having values per replica.
common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts\""
metric="artifact_pool_consensus_height_stat"
selector="$metric{$common_labels,type=\"finalization\",pool_type=\"validated\",stat=\"max\"}"

curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
    -o "$experiment_dir/metrics/${metric}_avg_total.json" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -H "Accept: application/json" \
    --data-urlencode "time=$endtime" \
    --data-urlencode "query=avg(rate(${selector}[300s]))"

# Get the state sync duration from the node which is first killed.
metricshosts=$(jq_load_filtered_urls_for_metrics ".node_index == ${node_indices_1[0]}")

# Get the metrics of state sync duration, summed up until $finaltime.
# Query the metrics from the first-killed node as it is the only one which conducts state sync.
# In this rejoin test, successful state sync only happens once.
# The value of state_sync_duration_seconds_sum at the final time should represent the state sync duration which just happened.
common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts\",status=\"ok\""
metric="state_sync_duration_seconds_sum"
selector="$metric{$common_labels}"
curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -o "$experiment_dir/metrics/${metric}.json" \
    -H "Accept: application/json" \
    --data-urlencode "time=$finaltime" \
    --data-urlencode "query=$selector"

echo "Results stored in '$experiment_dir/metrics'"

# Now, check if we were good

# There is a progress in the height
height_start="$(jq -r '.data.result[0].values | first | .[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_min.json")"
height_end="$(jq -r '.data.result[0].values | last | .[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_min.json")"
sed -i "s/height_start/$height_start/g" "$experiment_dir/data_to_upload/HeightStart.json"
sed -i "s/height_end/$height_end/g" "$experiment_dir/data_to_upload/HeightEnd.json"
finalization_rate="$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")"
statesync_duration="$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/state_sync_duration_seconds_sum.json")"
sed -i "s/statesync_duration/$statesync_duration/g" "$experiment_dir/data_to_upload/StatesyncDuration.json"

cup_interval_time=$(bc <<<"$dkg_interval_length/ ($finalization_rate + 0.000001)")

duration=$((finaltime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed in total in this test."
echo "The test was called with the following arguments"
echo "$@"

# State sync needs to finish within the CUP interval and has 30s left to recover the checkpoint.
if ((height_start >= height_end)); then
    failure "Some of the healthy nodes did not advance, fail!"
elif (($(bc <<<"$statesync_duration > $cup_interval_time - 30"))); then
    failure "State sync takes too much time and could not finish within the CUP interval."
else
    success "All healthy nodes progressed, great success!"
fi

endtime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

duration=$((endtime - starttime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

exit $exit_code
