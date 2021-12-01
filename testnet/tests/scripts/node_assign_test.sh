#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Node assignment test

Goal:: Ensure that nodes may be added to and removed from application subnets

Runbook::
. Deploy IC comprising 1 application subnet consisting of 1 node. In addition, there should be x unassigned nodes.
. Add these x nodes to the application subnet, making total number of nodes N=x+1.
. Assert that finalization rate is above the threshold_1.
. Kill f=floor(x/3) of the newly added nodes. This should NOT impede consensus from progressing. As the consensus rule N>=3f+1 holds.
. Assert that now finalization rate is above the threshold_2 (threshold_2 < threshold_1).
. Kill one more node. This should break the consensus, as the rule N>=3f+1 breaks.
. Assert that finalization rate is now zero.

Success::
.. Average finalization rate after adding x nodes > threshold_1 (measured for the first node in 60s window)
.. Average finalization rate after killing floor(x/3) nodes > threshold_2 (measured for the first node in 60s window)
.. Average finalization rate after killing one more node is zero (measured for the first node in 60s window)

end::catalog[]
DOC

if (($# != 2)); then
    echo >&2 "Wrong number of arguments, please provide values for <testnet_identifier> <results_dir>:"
    echo >&2 "$0 p2p_15 ./results/"
    exit 1
fi

testnet="$1"
results_dir="$(
    mkdir -p "$2"
    realpath "$2"
)"
experiment_dir="$results_dir/node_assign_test_${testnet}-$(date +%s)"

set -euo pipefail
export exit_code=0

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"
# Source helpers will have made the current directory $REPO_ROOT/testnet

# Store the time at which the test was called, so we can compute how long everything takes.
test_starttime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$test_starttime")"

# Add some additional data to the experiment_dir
mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "FinalizationRate": finalization_rate
}
' >>"$experiment_dir/data_to_upload/FinalizationRate.json"

export PROD_SRC
export TEST_MODULES="$PROD_SRC/tests/scripts/test_modules"

# Create directory for collecting logs
"$TEST_MODULES"/create_output_dir.sh "$results_dir"

export HOSTS="$PROD_SRC/env/$testnet/hosts"
export HOSTS_INI_FILENAME="hosts_unassigned.ini"
echo "Using host file name: $HOSTS_INI_FILENAME"
HOSTS_INI_ARGUMENTS=(--hosts-ini "$HOSTS_INI_FILENAME")

# Deploy the testnet with  --dkg-interval-length 19 for faster subnet changes
deploy_with_timeout "$testnet" \
    --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}" --dkg-interval-length 19

echo "Testnet deployment successful. Test starts now."

# This index corresponds to the first application subnet.
target_subnet_index=1
echo "Nodes will be added to the target subnet with index=${target_subnet_index}"

# Collect the list of unassigned nodes from the hosts file
mapfile -d " " -t unassigned_nodes <<<"$(ansible-inventory -i "${HOSTS}" --list | jq -r '.subnet_unassigned.hosts | @sh')"
echo "Unassigned nodes: ${unassigned_nodes[*]}"

parent_nns_url=$(jq_hostvars '[._meta.hostvars[.nns.hosts[0]]]' 'map(.api_listen_url)[0]')
export parent_nns_url
echo "parent_nns_url: $parent_nns_url"

mapfile -d " " -t node_ids <<<"$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r '.topology.unassigned_nodes | map_values(.node_id) | join(" ")')"
# Remove '\n' character (if exists) from the last node
node_ids[-1]="${node_ids[-1]//$'\n'/}"
echo "Unassigned node ids: ${node_ids[*]}"

unassigned_nodes_count="${#unassigned_nodes[@]}"
if [[ "${unassigned_nodes_count}" -lt "3" ]]; then
    failure "Initially there should at least 3 unassigned nodes."
fi

function add_node_to_subnet() {
    subnet_id=$1
    node_id=$2
    ic-admin --nns-url "$parent_nns_url" \
        propose-to-add-nodes-to-subnet \
        --test-neuron-proposer \
        --subnet-id "$subnet_id" "${node_id}"

    sleep 10

    unassigned=$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r ".topology.unassigned_nodes | map(select(.node_id==\"$node_id\")) | length")
    if [[ $unassigned != "0" ]]; then
        failure "Proposal to assign a node $node_id did not result in move from unassigned subnet"
    fi

    assigned=$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r ".topology.subnets | to_entries[$subnet_id].value.records[0].value.membership | map(select(.==\"$node_id\")) | length")
    if [[ $assigned != "1" ]]; then
        failure "Proposal to assign a node $node_id did not result in move to assigned subnet $subnet_id"
    fi
}

get_nodes_count_cmd="ic-admin --nns-url $parent_nns_url get-topology | jq -r '.topology.subnets | to_entries[${target_subnet_index}].value.records[0].value.membership | length'"
# Assert there is only one node in the application subnet
assigned_nodes_count=$(eval "$get_nodes_count_cmd")
echo "Originally the subnet contains ${assigned_nodes_count} node/s."
if [[ "${assigned_nodes_count}" -ne "1" ]]; then
    failure "Application subnet should contain only one node after deployment."
fi

# Now we extend the subnet to contain x+1 nodes in total (1 initial + x newly added).
node_idx=0
target_nodes_count=$((unassigned_nodes_count + 1))
until [[ "${assigned_nodes_count}" -eq "${target_nodes_count}" ]]; do
    echo "extending subnet with node_id=${node_ids[$node_idx]}"
    add_node_to_subnet "${target_subnet_index}" "${node_ids[$node_idx]}"
    node_idx=$((node_idx + 1))
    assigned_nodes_count=$(eval "$get_nodes_count_cmd")
done

echo "After adding the nodes there are ${assigned_nodes_count} nodes in the subnet."

echo "Waiting 80 secs after adding the nodes ..."
sleep 80 # sleep some time so the new nodes can catch up.
metrics_collection_time_sec=60
starttime="$(date '+%s')" # set start time of the metrics collection
export starttime
echo "Collecting metrics from the first node over ${metrics_collection_time_sec} secs ..."
sleep $metrics_collection_time_sec
endtime="$(date '+%s')" # set end time of the metrics collection
export endtime
# Get the report from the target subnet, where nodes where added.
collect_metrics "${target_subnet_index}"

# Extract the finalization rate
finalization_rate=$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")
echo "Collected finalization rate is ${finalization_rate}"

expected_finalization_threshold_1=$(finalization_rate_threshold "${target_subnet_index}")
if (($(bc <<<"$finalization_rate < $expected_finalization_threshold_1"))); then
    failure "Finalization rate $finalization_rate less than ${expected_finalization_threshold_1}, fail!"
else
    success "Finalization rate $finalization_rate greater than ${expected_finalization_threshold_1}, great success!"
fi

# Now we kill floor(x/3) nodes and measure metrics again, consensus should still take place.
cd "$PROD_SRC/ansible"
node_idx=0
max_kill_node_idx=$((unassigned_nodes_count / 3))
echo "We kill $((max_kill_node_idx - node_idx)) nodes. This should NOT impede consensus from progressing."
until [[ "${node_idx}" -eq "${max_kill_node_idx}" ]]; do
    removed_node="${unassigned_nodes[$node_idx]}"
    # this should remove quotes
    eval removed_node="${removed_node}"
    echo "Killing the node ${removed_node}."
    ansible-playbook -i "$HOSTS" icos_node_stress.yml --limit "${removed_node}" -e ic_action=kill-replica
    node_idx=$((node_idx + 1))
done

# Killing the nodes doesn't remove them from the registry, so we can assert the same node count.
assigned_nodes_count=$(eval "$get_nodes_count_cmd")
echo "After killing the nodes the subnet contains ${assigned_nodes_count} nodes (killing nodes doesn't remove them from the registry)."

echo "Waiting 80 secs after killing the nodes ..."
sleep 80 # sleep some time to make sure the nodes are dead.
starttime="$(date '+%s')"
echo "Collecting metrics from the first node over ${metrics_collection_time_sec} secs ..."
sleep $metrics_collection_time_sec
endtime="$(date '+%s')"
collect_metrics "${target_subnet_index}"

# Extract the finalization rate
finalization_rate=$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")
echo "Collected finalization rate is ${finalization_rate}"

expected_finalization_threshold_2=$(jq -n '('"${expected_finalization_threshold_1}"' | tonumber)  / (1 + '"${max_kill_node_idx}"')')
if (($(bc <<<"$finalization_rate < $expected_finalization_threshold_2"))); then
    failure "Finalization rate $finalization_rate less than ${expected_finalization_threshold_2}, fail!"
else
    success "Finalization rate $finalization_rate greater than ${expected_finalization_threshold_2}, great success!"
fi

# Kill one more node, this should break consensus, as the rule N>=3*f+1 doesn't hold.
removed_node="${unassigned_nodes[$node_idx]}"
# this should remove quotes
eval removed_node="${removed_node}"
echo "Killing node ${removed_node}."
ansible-playbook -i "$HOSTS" icos_node_stress.yml --limit "${removed_node}" -e ic_action=kill-replica

echo "Waiting 80 secs after killing the node ..."
sleep 80                  # sleep some time to make sure the node is dead.
starttime="$(date '+%s')" # from this moment the finalization rate should be zero, as only 14 out of 21 nodes are alive.
echo "Collecting metrics from the first node over ${metrics_collection_time_sec} secs ..."
sleep $metrics_collection_time_sec
endtime="$(date '+%s')"
collect_metrics "${target_subnet_index}"

# Extract the finalization rate
finalization_rate=$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")
echo "Collected finalization rate is ${finalization_rate}"

# Actually finalization rate should be exactly zero, as the consensus stopped.
expected_finalization_threshold_3=0.0001
if (($(bc <<<"$finalization_rate < $expected_finalization_threshold_3"))); then
    success "Finalization rate $finalization_rate is less than ${expected_finalization_threshold_3}, great success!"
else
    failure "Finalization rate $finalization_rate is greater than ${expected_finalization_threshold_3}, fail!"
fi

test_endtime="$(date '+%s')"
echo "$test_endtime" >"$experiment_dir/endtime"
echo "Ending tests *** $(dateFromEpoch "$test_endtime") (start time was $(dateFromEpoch "$test_starttime"))"

duration=$((test_endtime - test_starttime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

exit $exit_code
