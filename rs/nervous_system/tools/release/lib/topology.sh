#!/bin/bash

#### Functions for searching nodes and subnets

# Find the subnet that contains a given node id
# Returns just a subnet id, such as:
# pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae
find_subnet_with_node() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    local NODE_ID=$2

    $IC_ADMIN --nns-url "$NNS_URL" \
        get-topology \
        | jq -r ".subnets | to_entries[] | select(.value.nodes | keys | contains([\"$NODE_ID\"])) | .key"
}

# Returns first node in the subnet, with details. The output looks like this:
# {
#     "key": "ns7kv-kp2mu-mw7yi-krd4z-eqcvq-qeeej-mxtwb-c2ujq-xtq6x-orzoj-3qe",
#     "value": {
#         "ipv6": "2001:438:8000:10:6801:b7ff:fe12:e7e3",
#         "node_operator_id": "4lp6i-khv7q-lkgk3-hhrc6-ysjag-korh7-ysojw-7gv3h-glhdz-rpjrt-sqe",
#         "node_provider_id": "7at4h-nhtvt-a4s55-jigss-wr2ha-ysxkn-e6w7x-7ggnm-qd3d5-ry66r-cae",
#         "dc_id": "to2"
#     }
# }
get_first_node_details_for_subnet_id() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    local SUBNET_ID=$2

    list_nodes_with_details_for_subnet_id "$NNS_URL" "$SUBNET_ID" | jq -r "[to_entries[]] | first"
}

# Returns the node id of the first node in the subnet, such as:
# ns7kv-kp2mu-mw7yi-krd4z-eqcvq-qeeej-mxtwb-c2ujq-xtq6x-orzoj-3qe
get_node_for_subnet() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    local SUBNET_ID=$2

    get_first_node_details_for_subnet_id "$NNS_URL" "$SUBNET_ID" | jq -r ".key"
}

##: list_subnets
## Lists all subnet ids known by a given NNS
# Returns a list of subnets in the topology, such as:
# 2fq7c-slacv-26cgz-vzbx2-2jrcs-5edph-i5s2j-tck77-c3rlz-iobzx-mqe
# 3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe
# 4ecnw-byqwz-dtgss-ua2mh-pfvs7-c3lct-gtf4e-hnu75-j7eek-iifqm-sqe
# 4zbus-z2bmt-ilreg-xakz4-6tyre-hsqj4-slb4g-zjwqo-snjcc-iqphi-3qe
# 5kdm2-62fc6-fwnja-hutkz-ycsnm-4z33i-woh43-4cenu-ev7mi-gii6t-4ae
# [...]
list_subnets() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1

    $IC_ADMIN --nns-url "$NNS_URL" \
        get-topology \
        | jq -r ".subnets | keys | .[]"
}

# Returns a list of nodes with details for the given subnet id, such as:
list_nodes_with_details_for_subnet_id() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    shift

    local TOPOLOGY=$($IC_ADMIN --nns-url "$NNS_URL" get-topology)

    for SUBNET_ID in "$@"; do
        echo "$TOPOLOGY" | jq -r ".subnets[\"$SUBNET_ID\"].nodes"
    done
}

# Usage: list_nodes_for_subnets <NNS_URL> <SUBNET_ID> (<SUBNET_ID>...)
# Returns a list of node ids for the given subnets, such as:
# 2o33b-cheo6-ozp6n-sjrqc-cbro3-bslrm-kuhqz-wpncp-vlhji-jzeoj-6ae
# amjrq-m7xgs-bacs7-g54xa-t72h6-dszrv-7mj3i-6vcbx-3zzb2-6eean-xqe
# d7dyc-slisa-nrkkz-hrpee-2xbpi-xjido-shkjk-vrtob-cmfxd-6sevt-5qe
# [...]
list_nodes_for_subnets() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    shift

    local TOPOLOGY=$($IC_ADMIN --nns-url "$NNS_URL" get-topology)

    for SUBNET_ID in "$@"; do
        echo "$TOPOLOGY" | jq -r ".subnets[\"$SUBNET_ID\"].nodes | keys[]"
    done
}

# Given a SUBNET_ID, find an IP of the first node
# Example output:
# 2001:438:8000:10:6801:b7ff:fe12:e7e3
get_node_ip_for_subnet() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    local SUBNET_ID=$2

    get_first_node_details_for_subnet_id "$NNS_URL" "$SUBNET_ID" | jq -r ".value | .ipv6"
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
