#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Node assignment and removal test

Goal:: Ensure that nodes may be added to and removed from subnets and the IC

Runbook::
. sets up the nns subnet
. it creates a subnet which contains the first node in the hosts file
. it extends the subnet with additional nodes, one at a time
. it removes an unassigned node from the registry without having it join a subnet
. it assigns a node to a subnet, unassigns it, then removes it from the registry
. collects metrics:
  . make sure the finalization rate of the affected subnet works stays above a threshold
. prints results

Success::
.. average finalization rate >= 0.3 (over all replicas in 60s windows), and
.. all node assignments and removals are observed to succeed
.. consensus maintains liveness while nodes are being actively assigned, unassigned, and removed

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
experiment_dir="$results_dir/node_assign_remove_test_${testnet}-$(date +%s)"

set -euo pipefail
export exit_code=0

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"
# Source helpers will have made the current directory $REPO_ROOT/testnet

# Store the time at which the test was called, so we can compute how long everything takes (including the deployment time).
calltime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$calltime")"

# Add some additional data to the experiment_dir
mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "FinalizationRate": finalization_rate
}
' >>"$experiment_dir/data_to_upload/FinalizationRate.json"

export PROD_SRC
export TEST_MODULES="$PROD_SRC/tests/scripts/test_modules"

#  create directory for collecting logs
"$TEST_MODULES"/create_output_dir.sh "$results_dir"

export HOSTS="$PROD_SRC/env/$testnet/hosts"
export HOSTS_INI_FILENAME=hosts_unassigned.ini
HOSTS_INI_ARGUMENTS=(--hosts-ini "$HOSTS_INI_FILENAME")

# deploy the testnet with --dkg-interval-length 19 for faster subnet changes
deploy_with_timeout "$testnet" \
    --no-boundary-nodes \
    --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}" --dkg-interval-length 19

# Store the test start time in epoch, so we can query Prometheus later.
starttime="$(date '+%s')"
echo "Start time: $(dateFromEpoch "$starttime")"
echo "$starttime" >"$experiment_dir/starttime"

# collect nodes info

# find the first non-nns, non-unassigned subnet and make it our target
target_subnet=$(ansible-inventory -i "$HOSTS" --list | jq -r '.nodes.children | map(select(test("(nns|unassigned)") == false))[0]')
echo "target_subnet: $target_subnet"

# collect the list of unassigned nodes from the hosts file
mapfile -d " " -t initially_unassigned_nodes <<<"$(ansible-inventory -i "$HOSTS" --list | jq -r '.subnet_unassigned.hosts | @sh')"
echo "Unassigned nodes: " "${initially_unassigned_nodes[@]}"

parent_nns_url=$(jq_hostvars '[._meta.hostvars[.nns.hosts[0]]]' 'map(.api_listen_url)[0]')
export parent_nns_url
echo "parent_nns_url: $parent_nns_url"

mapfile -d " " -t node_ids <<<"$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r '.topology.unassigned_nodes | map_values(.node_id) | join(" ")')"

function add_node_to_subnet() {
    subnet_id=$1
    node_id=$2
    ic-admin --nns-url "$parent_nns_url" \
        propose-to-add-nodes-to-subnet \
        --test-neuron-proposer \
        --subnet-id "$subnet_id" "$node_id"

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

function remove_node_from_subnet() {
    subnet_id=$1
    node_id=$2
    ic-admin --nns-url "$parent_nns_url" \
        propose-to-remove-nodes-from-subnet \
        --test-neuron-proposer "$node_id"

    sleep 10

    unassigned=$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r ".topology.unassigned_nodes | map(select(.node_id==\"$node_id\")) | length")
    if [[ $unassigned != "1" ]]; then
        failure "Proposal to unassign a node $node_id did not result in move from assigned subnet"
    fi

    assigned=$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r ".topology.subnets | to_entries[$subnet_id].value.records[0].value.membership | map(select(.==\"$node_id\")) | length")
    if [[ $assigned != "0" ]]; then
        failure "Proposal to assign a node $node_id did not result in removal from subnet $subnet_id"
    fi
}

function remove_node_from_registry() {
    subnet_id=$1
    node_id=$2
    expected_to_succeed=$3
    ic-admin --nns-url "$parent_nns_url" \
        propose-to-remove-nodes \
        --test-neuron-proposer "$node_id"

    sleep 10

    unassigned=$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r ".topology.unassigned_nodes | map(select(.node_id==\"$node_id\")) | length")
    if [[ $unassigned != "0" ]]; then
        failure "Proposal to remove a node $node_id did not result in removal"
    fi

    assigned=$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r ".topology.subnets | to_entries[$subnet_id].value.records[0].value.membership | map(select(.==\"$node_id\")) | length")
    if [[ $assigned -ne "0" && $expected_to_succeed -eq "1" ]]; then
        failure "Proposal to remove a node $node_id somehow resulted in move to assigned subnet $subnet_id"
    fi
}

# Precondition: exactly one node already assigned to Subnet 1

initially_assigned=$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r ".topology.subnets | to_entries[1].value.records[0].value.membership | length")

# Add half of all unassigned_nodes to the subnet
current=0
len=$((${#initially_unassigned_nodes[@]} / 2))
while ((current < len)); do
    echo "extending subnet with ${initially_unassigned_nodes[$current]}"
    add_node_to_subnet 1 "${node_ids[$current]}"
    current=$((current + 1))
done

# Check that half of the unassigned nodes are now assigned
unassigned_check=$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r ".topology.unassigned_nodes | length")

if [[ $unassigned_check != $((${#initially_unassigned_nodes[@]} - len)) ]]; then
    failure "The number of unassigned nodes did not change as expected"
fi

# Remove all remaining unassigned nodes (except for the last one)
while [ $current -lt $((${#initially_unassigned_nodes[@]} - 1)) ]; do
    echo "removing ${initially_unassigned_nodes[$current]} from registry"
    remove_node_from_registry 1 "${node_ids[$current]}" 1
    current=$((current + 1))
done

# Check that there are no unassigned nodes left
unassigned_check=$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r ".topology.unassigned_nodes | length")
if [[ $unassigned_check != "1" ]]; then
    failure "Not all unassinged nodes were removed from the registry"
fi

# Try to remove all assigned nodes from the registry
current=0
while ((current < len)); do
    echo "trying to remove ${initially_unassigned_nodes[$current]} from registry"
    remove_node_from_registry 1 "${node_ids[$current]}" 0
    current=$((current + 1))
done

# Check that assigned nodes are still assigned
assigned_check=$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r ".topology.subnets | to_entries[1].value.records[0].value.membership | length")
if [[ $assigned_check != $((len + initially_assigned)) ]]; then
    failure "Assigned nodes were removed from registry"
fi

# Remove all assigned nodes from the subnet except for the first
current=0
while ((current < len)); do
    echo "removing ${initially_unassigned_nodes[$current]} from subnet"
    remove_node_from_subnet 1 "${node_ids[$current]}"
    current=$((current + 1))
done

# Check that there are no assigned nodes left
assigned_check=$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r ".topology.subnets | to_entries[1].value.records[0].value.membership | length")
if [[ $assigned_check != "1" ]]; then
    failure "Not all assigned nodes were removed from the subnet"
fi

# Remove all remaining unassigned nodes
current=0
while ((current < len)); do
    echo "removing ${initially_unassigned_nodes[$current]} from registry"
    remove_node_from_registry 1 "${node_ids[$current]}" 1
    current=$((current + 1))
done

# Check that there are no unassigned nodes left
unassigned_check=$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r ".topology.unassigned_nodes | length")
if [[ $unassigned_check != "1" ]]; then
    failure "Not all unassigned nodes were removed from the registry"
fi

# Check that there are still no assigned nodes left
assigned_check=$(ic-admin --nns-url "$parent_nns_url" get-topology | jq -r ".topology.subnets | to_entries[1].value.records[0].value.membership | length")
if [[ $assigned_check != "1" ]]; then
    failure "We somehow ended up with more assigned nodes"
fi

# wait for all commands
wait

sleep 30

# Get the report
collect_metrics

# Now, check if we were good
finalization_rate=$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")

sed -i "s/finalization_rate/$finalization_rate/g" "$experiment_dir/data_to_upload/FinalizationRate.json"

expected_finalization=$(finalization_rate_threshold 1)
# reduce to 3/4 of the value because some nodes fail and in small subnets the finalization rate will therefore be rocky
expected_finalization=$(jq -n '('"${expected_finalization}"' | tonumber) * 3 / 4')
if (($(bc <<<"$finalization_rate < $expected_finalization"))); then
    failure "Finalization rate $finalization_rate less than ${expected_finalization}, fail!"
else
    success "Finalization rate $finalization_rate greater than ${expected_finalization}, great success!"
fi

endtime="$(date '+%s')"
echo "$endtime" >"$experiment_dir/endtime"
echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

# duration covers the time we had 4 nodes running
duration=$((endtime - starttime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

exit $exit_code
