#!/usr/bin/env bash
#set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

source "$SCRIPT_DIR/../lib.sh"

repo_root() {
    git rev-parse --show-toplevel
}

ensure_variable_set() {
    while [ $# -gt 0 ]; do
        if [ -v ${!1} ]; then
            echo "$1 was not set. Aborting"
            exit 1
        fi
        if [ -z "${!1}" ]; then
            echo "$1 was empty.  Aborting."
            exit 1
        fi
        shift
    done
}

download_canister_gz() {
    DOWNLOAD_NAME=$1
    GIT_HASH=$2

    OUTPUT_FILE="/tmp/$DOWNLOAD_NAME-$GIT_HASH.wasm.gz"

    curl --silent "https://download.dfinity.systems/ic/$GIT_HASH/canisters/$DOWNLOAD_NAME.wasm.gz" \
        --output "$OUTPUT_FILE"

    echo "$OUTPUT_FILE"
}

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

    $IC_ADMIN --nns-url "$NNS_URL" \
        get-topology \
        | jq -r ".topology.subnets[\"$SUBNET_ID\"].records[0].value.membership[0]"
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

ungzip() {
    FILE=$1

    UNZIPPED=$(echo "${FILE}" | sed 's/\.gz//')

    rm -f "$UNZIPPED"
    gzip -d "$FILE" >/dev/null

    if [ $? -gt 0 ]; then
        echo "Could not ungzip the file at $FILE"
        return 1
    fi

    echo "$UNZIPPED"
}

sha_256() {
    if $(which sha256sum >/dev/null); then
        SHA_CMD="sha256sum"
    else
        SHA_CMD="shasum -a 256"
    fi
    $SHA_CMD "$1" | cut -d' ' -f1
}

add_sns_wasms_allowed_principal() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1 # with protocol and port (http://...:8080)
    local NEURON_ID=$2
    local PEM=$3
    local PRINCIPAL_TO_ADD=$4

    $IC_ADMIN --nns-url "$NNS_URL" -s "$PEM" \
        propose-to-update-sns-deploy-whitelist \
        --proposer "$NEURON_ID" \
        --added-principals "$PRINCIPAL_TO_ADD"
}

set_sns_wasms_allowed_subnets() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1 # with protocol and port (http://...:8080)
    local NEURON_ID=$2
    local PEM=$3
    local SUBNET_TO_ADD=$4

    #  Remove all from current list
    #  and add new one

    CURRENT_SUBNETS=$(dfx canister --network "$NNS_URL" call qaa6y-5yaaa-aaaaa-aaafa-cai get_sns_subnet_ids '(record {})' \
        | grep principal \
        | sed 's/.*"\(.*\)";/\1/')

    cmd=($IC_ADMIN --nns-url $NNS_URL -s $PEM propose-to-update-sns-subnet-ids-in-sns-wasm)

    for current_subnet in $CURRENT_SUBNETS; do
        cmd+=(--sns-subnet-ids-to-remove $current_subnet)
    done

    cmd+=(--sns-subnet-ids-to-add $SUBNET_TO_ADD)

    cmd+=(--proposer $NEURON_ID)

    "${cmd[@]}"
}

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
        --proposer "$NEURON_ID" \
        --subnet-type "$SUBNET_TYPE" \
        --replica-version-id "$REPLICA_VERSION" \
        ${UNASSIGNED_NODE_IDS[@]}
}

set_default_subnets() {

    ensure_variable_set IC_ADMIN

    local NNS_URL=$1 # with protocol and port (http://...:8080)
    local NEURON_ID=$2
    local PEM=$3
    local SUBNET_ID=$4

    $IC_ADMIN -s "$PEM" --nns-url "$NNS_URL" \
        propose-to-set-authorized-subnetworks \
        --proposer "$NEURON_ID" \
        --subnets "$SUBNET_ID"
}

upload_canister_wasm_to_sns_wasm() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1 # with protocol and port (http://...:8080)
    local NEURON_ID=$2
    local PEM=$3
    local CANISTER_TYPE=$4
    local VERSION=$5

    WASM_GZ=$(download_canister_gz \
        $(canister_download_name_for_sns_canister_type "$CANISTER_TYPE") \
        "$VERSION")

    WASM=$(ungzip "$WASM_GZ")
    WASM_SHA=$(sha_256 "$WASM")

    local CANISTER_TYPE="$(echo "$CANISTER_TYPE" | sed 's/.*/\u&/')"

    SUMMARY_FILE=$(tempfile)
    echo "Proposal to add a WASM" >$SUMMARY_FILE

    $IC_ADMIN -s "$PEM" --nns-url "$NNS_URL" \
        propose-to-add-wasm-to-sns-wasm \
        --wasm-module-path "$WASM" \
        --wasm-module-sha256 "$WASM_SHA" \
        --canister-type "$CANISTER_TYPE" \
        --summary-file "$SUMMARY_FILE" \
        --proposer "$NEURON_ID"
}

deploy_new_sns() {
    ensure_variable_set SNS_CLI

    local NNS_URL=$1
    local WALLET_CANISTER=$2
    local CONFIG_FILE=$(3:-)

    if [ -z "$CONFIG_FILE" ]; then
        CONFIG_FILE=$SCRIPT_DIR/sns_default_test_init_params.yml
    fi

    $SNS_CLI deploy --network "$NNS_URL" \
        --wallet-canister-override "$WALLET_CANISTER" \
        --init-config-file "$CONFIG_FILE"
}

canister_download_name_for_sns_canister_type() {
    local CANISTER_TYPE=$1

    type__root="sns-root-canister"
    type__governance="sns-governance-canister"
    type__ledger="ic-icrc1-ledger"
    type__swap="sns-swap-canister"
    type__archive="ic-icrc1-archive"
    type__index="ic-icrc1-index"

    local INDEX=type__${CANISTER_TYPE}
    echo ${!INDEX}
}
