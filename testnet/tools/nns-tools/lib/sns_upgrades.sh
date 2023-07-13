#!/bin/bash

# We hold this in memory since it rarely changes (not during a script call)
MAINNET_CANISTER_WASM_HASH_VERSIONS=""
sns_mainnet_canister_wasm_hash_versions() {
    MAINNET_CANISTER_WASM_HASH_VERSIONS=${MAINNET_CANISTER_WASM_HASH_VERSIONS:-$(sns_w_list_upgrade_steps ic | $IDL2JSON | jq '.[] | last | .pretty_version[0]')}

    echo "$MAINNET_CANISTER_WASM_HASH_VERSIONS"
}

sns_mainnet_latest_wasm_hash() {
    local SNS_CANISTER_TYPE=$1
    sns_mainnet_canister_wasm_hash_versions \
        | jq -r ".${SNS_CANISTER_TYPE}_wasm_hash"
}

sns_wasm_hash_to_git_commit() {
    local HASH=$1
    cat "$NNS_TOOLS_DIR/sns_publish_log.txt" \
        | grep "$HASH" \
        | awk '{ print $3 }'
}

sns_mainnet_git_commit_id() {
    local SNS_CANISTER_TYPE=$1
    sns_wasm_hash_to_git_commit "$(sns_mainnet_latest_wasm_hash $SNS_CANISTER_TYPE)"
}

reset_sns_w_versions_to_mainnet() {
    ensure_variable_set IDL2JSON

    local NNS_URL=$1
    local NEURON_ID=$2

    upload_canister_git_version_to_sns_wasm \
        "$NNS_URL" "$NEURON_ID" \
        "$NNS_TOOLS_DIR"/test_user.pem \
        root $(sns_mainnet_git_commit_id root)

    upload_canister_git_version_to_sns_wasm \
        "$NNS_URL" "$NEURON_ID" \
        "$NNS_TOOLS_DIR"/test_user.pem \
        governance $(sns_mainnet_git_commit_id governance)

    upload_canister_git_version_to_sns_wasm \
        "$NNS_URL" "$NEURON_ID" \
        "$NNS_TOOLS_DIR"/test_user.pem \
        ledger $(sns_mainnet_git_commit_id ledger)

    upload_canister_git_version_to_sns_wasm \
        "$NNS_URL" "$NEURON_ID" \
        "$NNS_TOOLS_DIR"/test_user.pem \
        archive $(sns_mainnet_git_commit_id archive)

    upload_canister_git_version_to_sns_wasm \
        "$NNS_URL" "$NEURON_ID" \
        "$NNS_TOOLS_DIR"/test_user.pem \
        swap $(sns_mainnet_git_commit_id swap)

    upload_canister_git_version_to_sns_wasm \
        "$NNS_URL" "$NEURON_ID" \
        "$NNS_TOOLS_DIR"/test_user.pem \
        index $(sns_mainnet_git_commit_id index)
}

upload_canister_git_version_to_sns_wasm() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1 # with protocol and port (http://...:8080)
    local NEURON_ID=$2
    local PEM=$3
    local CANISTER_TYPE=$4
    local VERSION=$5

    WASM_GZ=$(download_sns_canister_wasm_gz_for_type "$CANISTER_TYPE" "$VERSION")

    upload_wasm_to_sns_wasm "$NNS_URL" "$NEURON_ID" \
        "$PEM" "$CANISTER_TYPE" "$WASM_GZ"
}

upload_wasm_to_sns_wasm() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1 # with protocol and port (http://...:8080)
    local NEURON_ID=$2
    local PEM=$3
    local CANISTER_TYPE=$4
    local WASM=$5

    WASM_SHA=$(sha_256 "$WASM")

    SUMMARY_FILE=$(mktemp)
    echo "Proposal to add a WASM" >$SUMMARY_FILE

    # We ignore most of the output here because it overwhelms the terminal
    $IC_ADMIN -s "$PEM" --nns-url "$NNS_URL" \
        propose-to-add-wasm-to-sns-wasm \
        --wasm-module-path "$WASM" \
        --wasm-module-sha256 "$WASM_SHA" \
        --canister-type "$CANISTER_TYPE" \
        --summary-file "$SUMMARY_FILE" \
        --proposer "$NEURON_ID" \
        | grep proposal
}

deploy_new_sns() {
    ensure_variable_set SNS_CLI

    local SUBNET_WITH_WALLET_URL=$1
    local WALLET_CANISTER=$2
    local CONFIG_FILE=${3:-}

    if [ -z "$CONFIG_FILE" ]; then
        CONFIG_FILE=$NNS_TOOLS_DIR/sns_default_test_init_params.yml
    fi

    set +e
    $SNS_CLI deploy --network "$SUBNET_WITH_WALLET_URL" \
        --wallet-canister-override "$WALLET_CANISTER" \
        --init-config-file "$CONFIG_FILE"
    set -e
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
        --added-principals "$PRINCIPAL_TO_ADD" \
        --summary "Updating deploy whitelist"
}

set_sns_wasms_allowed_subnets() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1 # with protocol and port (http://...:8080)
    local NEURON_ID=$2
    local PEM=$3
    local SUBNET_TO_ADD=$4

    #  Remove all from current list
    #  and add new one

    CURRENT_SUBNETS=$(dfx -q canister --network "$NNS_URL" call qaa6y-5yaaa-aaaaa-aaafa-cai get_sns_subnet_ids '(record {})' \
        | grep principal \
        | sed 's/.*"\(.*\)";/\1/')

    cmd=($IC_ADMIN --nns-url $NNS_URL -s $PEM propose-to-update-sns-subnet-ids-in-sns-wasm --summary "Updating SNS subnet ids in SNS-WASM")

    for current_subnet in $CURRENT_SUBNETS; do
        cmd+=(--sns-subnet-ids-to-remove $current_subnet)
    done

    cmd+=(--sns-subnet-ids-to-add $SUBNET_TO_ADD)

    cmd+=(--proposer $NEURON_ID)

    "${cmd[@]}"
}

wait_for_sns_canister_has_version() {
    local NETWORK=$1
    local CANISTER_ID=$2
    local SNS_CANISTER_TYPE=$3
    local VERSION=$4

    WASM=$(download_sns_canister_wasm_gz_for_type $SNS_CANISTER_TYPE $VERSION)
    wait_for_canister_has_file_contents "$NETWORK" "$CANISTER_ID" "$WASM"
}

wait_for_canister_has_file_contents() {
    local NETWORK=$1
    local CANISTER_ID=$2
    local WASM=$3

    for i in {1..20}; do
        echo "Testing if upgrade was successful..."
        if canister_has_file_contents_installed "$NETWORK" "$CANISTER_ID" "$WASM"; then
            print_green "Canister $CANISTER_ID successfully upgraded."
            return 0
        fi
        sleep 10
    done

    print_red "Canister $CANISTER_ID upgrade failed"
    return 1
}
