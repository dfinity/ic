#!/bin/bash

#### Functions for searching nodes and subnets

find_subnet_with_node() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    local NODE_ID=$2

    $IC_ADMIN --nns-url "$NNS_URL" \
        get-topology \
        | jq -r ".topology.subnets[] | select(.records[0].value.membership | contains([\"$NODE_ID\"])) | .records[].key" \
        | sed 's/subnet_record_//'
}

get_node_for_subnet() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    local SUBNET_ID=$2

    list_nodes_for_subnets "$NNS_URL" "$SUBNET_ID" | head -1
}

##: list_subnets
## Lists all subnet ids known by a given NNS
list_subnets() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1

    $IC_ADMIN --nns-url "$NNS_URL" \
        get-topology \
        | jq -r ".topology.subnets | keys | .[]"
}

# Usage: list_nodes_for_subnets <NNS_URL> <SUBNET_ID> (<SUBNET_ID>...)
list_nodes_for_subnets() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    shift

    local TOPOLOGY=$($IC_ADMIN --nns-url "$NNS_URL" get-topology)

    for SUBNET_ID in "$@"; do
        echo "$TOPOLOGY" | jq -r ".topology.subnets[\"$SUBNET_ID\"].records[0].value.membership[]"
    done
}

# Given a SUBNET_ID, find an IP of the first node
get_node_ip_for_subnet() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    local SUBNET_ID=$2

    NODE_ID=$(get_node_for_subnet "$NNS_URL" "$SUBNET_ID")

    node_ip_from_node_id "$NNS_URL" "$NODE_ID"
}

node_ip_from_node_id() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    local NODE_ID=$2

    $IC_ADMIN --nns-url "$NNS_URL" get-node "$NODE_ID" \
        | grep ip_addr \
        | cut -d '"' -f4
}

#### Functions to create and modify subnets

create_new_subnet() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1 # with protocol and port (http://...:8080)
    local NEURON_ID=$2
    local PEM=$3
    local REPLICA_VERSION=$4
    local SUBNET_TYPE=$5
    local UNASSIGNED_NODE_IDS=$6

    # shellcheck disable=SC2068
    $IC_ADMIN -s "$PEM" --nns-url "$NNS_URL" \
        propose-to-create-subnet \
        --summary "Creating a subnet" \
        --proposer "$NEURON_ID" \
        --subnet-type "$SUBNET_TYPE" \
        --replica-version-id "$REPLICA_VERSION" \
        ${UNASSIGNED_NODE_IDS[@]}
}
