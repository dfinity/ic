#!/usr/bin/env bash
set -euo pipefail

if ! which jq >/dev/null; then
    echo >&2 "Tool \`jq\` not found.  Please install. \`brew install jq\` or check https://stedolan.github.io/jq/"
    exit 1
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

source "$SCRIPT_DIR/../lib.sh"

# Needed because otherwise we get conflicts between two users running scripts on same machine (tmp directory is shared)
MY_DOWNLOAD_DIR="/tmp/$(whoami)_deploy_scripts"
mkdir -p $MY_DOWNLOAD_DIR

is_variable_set() {
    set +u
    if [ -z "${!1}" ]; then
        set -u
        return 1
    fi
    set -u
    return 0
}

ensure_variable_set() {
    while [ $# -gt 0 ]; do
        if ! is_variable_set $1; then
            echo "\$$1 was empty or unset.  Aborting."
            exit 1
        fi
        shift
    done
}

### Functions for searching nodes and subnets

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

### End functions for searching nodes and subnets

### Upgrade canister related functions

sha_256() {
    if $(which sha256sum >/dev/null); then
        SHA_CMD="sha256sum"
    else
        SHA_CMD="shasum -a 256"
    fi
    $SHA_CMD "$1" | cut -d' ' -f1
}

##: propose_upgrade_canister_to_version_pem
## Upgrades an NNS canister by name using a neuron_id and a pem to a specified version on a given NNS
## Usage: $1 <NNS_URL> <NEURON_ID> <PEM> <CANISTER_NAME> <VERSION>
propose_upgrade_canister_to_version_pem() {
    local NNS_URL=$1
    local NEURON_ID=$2
    local PEM=$3
    local CANISTER_NAME=$4
    local VERSION=$5

    WASM_FILE=$(get_nns_canister_wasm_gz_for_type "$CANISTER_NAME" "$VERSION")

    propose_upgrade_canister_wasm_file_pem "$NNS_URL" "$NEURON_ID" "$PEM" "$CANISTER_NAME" "$WASM_FILE"
}

propose_upgrade_canister_wasm_file_pem() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    local NEURON_ID=$2
    local PEM=$3
    local CANISTER_NAME=$4
    local WASM_FILE=$5

    CANISTER_ID=$(nns_canister_id "$CANISTER_NAME")

    # See note at variable declaration
    PROPOSAL="$MY_DOWNLOAD_DIR"/testnet_upgrade_proposal.txt
    echo "Testnet $CANISTER_NAME upgrade" >$PROPOSAL

    local WASM_SHA=$(sha_256 "$WASM_FILE")

    $IC_ADMIN --nns-url "$NNS_URL" -s "$PEM" \
        propose-to-change-nns-canister --mode=upgrade \
        --canister-id "$CANISTER_ID" \
        --wasm-module-path "$WASM_FILE" \
        --wasm-module-sha256 "$WASM_SHA" \
        --summary-file $PROPOSAL \
        --proposer "$NEURON_ID"

    rm -rf $PROPOSAL
}

generate_nns_proposal_text() {

    local LAST_COMMIT=$1
    local NEXT_COMMIT=$2
    local CANISTER_NAME=$3
    local OUTPUT_FILE=${4:-}

    WASM_GZ=$(get_nns_canister_wasm_gz_for_type "$CANISTER_NAME" "$NEXT_COMMIT")
    WASM_SHA=$(sha_256 "$WASM_GZ")
    CAPITALIZED_CANISTER_NAME="$(tr '[:lower:]' '[:upper:]' <<<${CANISTER_NAME:0:1})${CANISTER_NAME:1}"
    LAST_WASM_HASH=$(canister_hash ic $CANISTER_NAME)

    IC_REPO=$(repo_root)

    CANISTER_CODE_LOCATION=$(get_nns_canister_code_location "$CANISTER_NAME")
    ESCAPED_IC_REPO=$(printf '%s\n' "$IC_REPO" | sed -e 's/[]\/$*.^[]/\\&/g')
    RELATIVE_CODE_LOCATION="$(echo "$CANISTER_CODE_LOCATION" | sed "s/$ESCAPED_IC_REPO/./g")"

    OUTPUT=$(
        cat <<EOF
## Proposal to Upgrade the $CAPITALIZED_CANISTER_NAME Canister
### Proposer: DFINITY Foundation
### Git Hash: $NEXT_COMMIT
### New Wasm Hash: $WASM_SHA
### Target canister: $(nns_canister_id "$CANISTER_NAME")
---
## Features
TODO ADD FEATURE NOTES
## Release Notes
\`\`\`
\$ git log --format="%C(auto) %h %s" $LAST_COMMIT..$NEXT_COMMIT --  $RELATIVE_CODE_LOCATION
$(git log --format="%C(auto) %h %s" "$LAST_COMMIT".."$NEXT_COMMIT" -- $CANISTER_CODE_LOCATION)
\`\`\`
## Wasm Verification
Verify that the hash of the gzipped WASM matches the proposed hash.
\`\`\`
git fetch
git checkout $NEXT_COMMIT
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/$(_canister_download_name_for_nns_canister_type "$CANISTER_NAME").wasm.gz
\`\`\`
## Current Version
- Current Git Hash: $LAST_COMMIT
- Current Wasm Hash: $LAST_WASM_HASH
EOF
    )

    if [ -z "$OUTPUT_FILE" ]; then
        echo "$OUTPUT"
    else
        echo "$OUTPUT" >"$OUTPUT_FILE"
        echo "File created at $OUTPUT_FILE"
    fi

}

generate_sns_bless_wasm_proposal_text() {

    local LAST_COMMIT=$1
    local NEXT_COMMIT=$2
    local CANISTER_TYPE=$3
    local OUTPUT_FILE=${4:-}

    WASM_GZ=$(get_sns_canister_wasm_gz_for_type "$CANISTER_TYPE" "$NEXT_COMMIT")
    WASM_SHA=$(sha_256 "$WASM_GZ")
    CAPITALIZED_CANISTER_TYPE="$(tr '[:lower:]' '[:upper:]' <<<${CANISTER_TYPE:0:1})${CANISTER_TYPE:1}"

    IC_REPO=$(repo_root)

    CANISTER_CODE_LOCATION=$(get_sns_canister_code_location "$CANISTER_TYPE")
    ESCAPED_IC_REPO=$(printf '%s\n' "$IC_REPO" | sed -e 's/[]\/$*.^[]/\\&/g')
    RELATIVE_CODE_LOCATION="$(echo "$CANISTER_CODE_LOCATION" | sed "s/$ESCAPED_IC_REPO/./g")"

    OUTPUT=$(
        cat <<EOF
## Proposal to Publish the SNS $CAPITALIZED_CANISTER_TYPE Canister WASM to SNS-W
### Proposer: DFINITY Foundation
### Canister Type: $CANISTER_TYPE
### Git Hash: $NEXT_COMMIT
### New Wasm Hash: $WASM_SHA
---
## Features
TODO ADD FEATURE NOTES
## Release Notes
\`\`\`
\$ git log --format="%C(auto) %h %s" $LAST_COMMIT..$NEXT_COMMIT --  $RELATIVE_CODE_LOCATION
$(git log --format="%C(auto) %h %s" "$LAST_COMMIT".."$NEXT_COMMIT" -- $CANISTER_CODE_LOCATION)
\`\`\`
## Wasm Verification
Verify that the hash of the gzipped WASM matches the proposed hash.
\`\`\`
git fetch
git checkout $NEXT_COMMIT
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/$(_canister_download_name_for_sns_canister_type "$CANISTER_TYPE").wasm.gz
\`\`\`
EOF
    )

    if [ -z "$OUTPUT_FILE" ]; then
        echo "$OUTPUT"
    else
        echo "$OUTPUT" >"$OUTPUT_FILE"
        echo "File created at $OUTPUT_FILE"
    fi

}

generate_insert_custom_upgrade_paths_proposal_text() {
    local SNS_GOVERNANCE_CANISTER_ID=$1
    shift
    VERSIONS=()
    for ((c = 1; c <= $#; c++)); do
        VERSIONS+=("${!c}")
    done

    DESCRIPTION=$([ "$SNS_GOVERNANCE_CANISTER_ID" == "" ] \
        && echo "All SNS upgrade paths (without their own overrides) will be affected by this proposal." \
        || echo "This will only affect the SNS that has the following governance Canister ID: $SNS_GOVERNANCE_CANISTER_ID.")
    DISPLAY_GOVERNANCE_ID=$([ "$SNS_GOVERNANCE_CANISTER_ID" == "" ] && echo "All" || echo "$SNS_GOVERNANCE_CANISTER_ID")
    GOVERNANCE_CANDID_ARG=$([ "$SNS_GOVERNANCE_CANISTER_ID" == "" ] \
        && echo "" \
        || echo "sns_governance_canister_id = opt principal \"$SNS_GOVERNANCE_CANISTER_ID\";")

    LAST_VERSION=""
    OUTPUT=$(
        cat <<EOF
## Proposal to TODO
### Proposer: DFINITY Foundation
### Target SNS Governance Canister: $DISPLAY_GOVERNANCE_ID
---
This proposal will change the upgrade path to use different WASMs, but WASMs that are already available on SNS-W.

$DESCRIPTION

## Rationale

TODO

## Useful background

To see what the upgrade path currently is, run:
\`\`\`
dfx canister --network ic call --candid ic/rs/nns/sns-wasm/canister/sns-wasm.did \\
    qaa6y-5yaaa-aaaaa-aaafa-cai list_upgrade_steps \\
    '(record {limit = 0: nat32; $GOVERNANCE_CANDID_ARG})'
\`\`\`
$(
            [ "$SNS_GOVERNANCE_CANISTER_ID" != "" ] && cat <<EO2

To see the current version the SNS reports to be running:
\`\`\`
dfx canister --network ic \\
        call --candid ic/rs/sns/governance/canister/governance.did \\
        "$SNS_GOVERNANCE_CANISTER_ID" get_running_sns_version "(record{})"
\`\`\`

EO2
        )
## Upgrade Path Changes

$(for VERSION in "${VERSIONS[@]}"; do
            if [ "$LAST_VERSION" != "" ]; then
                # Combine the upgrades to emulate the way this will work
                VERSION=$(echo "[$LAST_VERSION, $VERSION]" | jq -cS '.[0] * .[1]')
            else

                VERSION=$(echo $VERSION | jq -cS .)
            fi
            echo $VERSION | jq .
            echo
            LAST_VERSION=$VERSION
        done)

EOF
    )

    echo "$OUTPUT"
}

get_nns_canister_code_location() {
    CANISTER_NAME=$1

    IC_REPO=$(repo_root)
    RUST_DIR="$IC_REPO/rs"
    # Map of locations
    code_location__registry="$RUST_DIR/registry/canister"
    code_location__governance="$RUST_DIR/nns/governance"
    code_location__ledger="$RUST_DIR/rosetta-api/ledger_canister $RUST_DIR/rosetta-api/icp_ledger"
    code_location__root="$RUST_DIR/nns/handlers/root"
    code_location__cycles_minting="$RUST_DIR/nns/cmc"
    code_location__lifeline="$RUST_DIR/nns/handlers/lifeline"
    code_location__genesis_token="$RUST_DIR/nns/gtc"
    code_location__identity="$RUST_DIR/nns/identity"
    code_location__nns_ui="$RUST_DIR/nns/nns-ui"
    code_location__sns_wasm="$RUST_DIR/nns/sns-wasm"

    UNDERSCORED_CANISTER_NAME=$(echo "$CANISTER_NAME" | tr "-" "_")
    n=code_location__${UNDERSCORED_CANISTER_NAME}
    echo ${!n}
}

get_sns_canister_code_location() {
    CANISTER_NAME=$1

    IC_REPO=$(repo_root)
    RUST_DIR="$IC_REPO/rs"
    # Map of locations
    code_location__root="$RUST_DIR/sns/root"
    code_location__governance="$RUST_DIR/sns/governance"
    code_location__ledger="$RUST_DIR/rosetta-api/icrc1 $RUST_DIR/rosetta-api/ledger_core $RUST_DIR/rosetta-api/ledger_canister_core"
    code_location__swap="$RUST_DIR/sns/swap"
    code_location__archive="$RUST_DIR/rosetta-api/icrc1"
    code_location__index="$RUST_DIR/rosetta-api/icrc1"

    UNDERSCORED_CANISTER_NAME=$(echo "$CANISTER_NAME" | tr "-" "_")
    n=code_location__${UNDERSCORED_CANISTER_NAME}
    echo ${!n}
}

##: get_info
## Prints the info for a named NNS canister
## Usage: $1 <NETWORK> <CANISTER_NAME>
##      NETWORK: ic, or URL to an NNS subnet (including port)
##      CANISTER_NAME: human readable canister name (i.e. governance, registry, sns-wasm, etc...)
get_info() {
    local NETWORK=$1
    local CANISTER_NAME=$2

    dfx canister --network "$NETWORK" info $(nns_canister_id "$CANISTER_NAME")
}

canister_hash() {
    local NETWORK=$1
    local CANISTER_NAME=$2

    get_info $NETWORK $CANISTER_NAME \
        | grep "Module hash:" \
        | cut -d" " -f3 \
        | sed 's/^0x//'
}

nns_canister_git_version() {
    local NETWORK=$1
    local CANISTER_NAME=$2

    dfx canister --network $NETWORK metadata \
        $(nns_canister_id $CANISTER_NAME) git_commit_id
}

##: canister_has_version_installed
## Check if canister has the right version (git commit)
##      NETWORK: ic, or URL to an NNS subnet (including port)
##      CANISTER_NAME: human readable canister name (i.e. governance, registry, sns-wasm, etc...)
##      VERSION: Git hash of expected version
canister_has_version_installed() {
    local NETWORK=$1
    local CANISTER_NAME=$2
    local VERSION=$3

    WASM_GZ=$(get_nns_canister_wasm_gz_for_type "$CANISTER_NAME" "$VERSION")

    canister_has_file_contents_installed "$NETWORK" "$CANISTER_NAME" "$WASM_GZ"
}

canister_has_file_contents_installed() {
    local NETWORK=$1
    local CANISTER_NAME=$2
    local WASM_FILE=$3

    echo "Checking if canister $CANISTER_NAME is running $WASM_FILE..."

    WASM_HASH=$(sha_256 "$WASM_FILE")
    RUNNING_HASH=$(canister_hash "$NETWORK" "$CANISTER_NAME")

    if [ "$WASM_HASH" != "$RUNNING_HASH" ]; then
        echo >&2 "Canister has hash $RUNNING_HASH; expected $WASM_HASH"
        return 1
    fi

    echo >&2 "Canister is running with hash $WASM_HASH as expected"
    return 0
}

### End upgrade canister related functions

### Functions related to SNS deployments

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

    CURRENT_SUBNETS=$(dfx canister --network "$NNS_URL" call qaa6y-5yaaa-aaaaa-aaafa-cai get_sns_subnet_ids '(record {})' \
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

set_default_subnets() {

    ensure_variable_set IC_ADMIN

    local NNS_URL=$1 # with protocol and port (http://...:8080)
    local NEURON_ID=$2
    local PEM=$3
    local SUBNET_ID=$4

    $IC_ADMIN -s "$PEM" --nns-url "$NNS_URL" \
        propose-to-set-authorized-subnetworks \
        --proposer "$NEURON_ID" \
        --summary "Setting authorized subnetworks" \
        --subnets "$SUBNET_ID"
}

upload_canister_wasm_to_sns_wasm() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1 # with protocol and port (http://...:8080)
    local NEURON_ID=$2
    local PEM=$3
    local CANISTER_TYPE=$4
    local VERSION=$5

    WASM_GZ=$(get_sns_canister_wasm_gz_for_type "$CANISTER_TYPE" "$VERSION")

    WASM_SHA=$(sha_256 "$WASM_GZ")

    SUMMARY_FILE=$(mktemp)
    echo "Proposal to add a WASM" >$SUMMARY_FILE

    $IC_ADMIN -s "$PEM" --nns-url "$NNS_URL" \
        propose-to-add-wasm-to-sns-wasm \
        --wasm-module-path "$WASM_GZ" \
        --wasm-module-sha256 "$WASM_SHA" \
        --canister-type "$CANISTER_TYPE" \
        --summary-file "$SUMMARY_FILE" \
        --proposer "$NEURON_ID"
}

deploy_new_sns() {
    ensure_variable_set SNS_CLI

    local SUBNET_WITH_WALLET_URL=$1
    local WALLET_CANISTER=$2
    local CONFIG_FILE=${3:-}

    if [ -z "$CONFIG_FILE" ]; then
        CONFIG_FILE=$SCRIPT_DIR/sns_default_test_init_params.yml
    fi

    set +e
    $SNS_CLI deploy --network "$SUBNET_WITH_WALLET_URL" \
        --wallet-canister-override "$WALLET_CANISTER" \
        --init-config-file "$CONFIG_FILE"
    set -e
}

##: test_propose_to_open_sns_token_swap_pem
## Decentralize an SNS with test parameters
## Usage: $1 <NNS_URL> <NEURON_ID> <PEM> <SWAP_CANISTER_ID>
##      NNS_URL: The url to the subnet running the NNS in your testnet.
##      NEURON_ID: The neuron used to submit proposals (should have following to immediately pass)
##      PEM: path to the pem file of a neuron controller (hotkey or owner)
##      SWAP_CANISTER_ID: the id of the swap canister to decentralize
test_propose_to_open_sns_token_swap_pem() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1 # with protocol and port (http://...:8080)
    local NEURON_ID=$2
    local PEM=$3
    local SWAP_ID=$4

    NOW_PLUS_TWO_DAYS=$(($(date +%s) + 86400 + 86400))

    # Min ICP = 50, Max = 500
    # min per user 1 ICP, max 200
    # 3 users minimum
    $IC_ADMIN -s "$PEM" --nns-url "$NNS_URL" \
        propose-to-open-sns-token-swap \
        --min-participants 1 \
        --min-icp-e8s 1000000000 \
        --max-icp-e8s 3000000000000 \
        --min-participant-icp-e8s 1000000000 \
        --max-participant-icp-e8s 3000000000000 \
        --swap-due-timestamp-seconds $NOW_PLUS_TWO_DAYS \
        --sns-token-e8s 3000000000000 \
        --target-swap-canister-id "$SWAP_ID" \
        --neuron-basket-count 1 \
        --neuron-basket-dissolve-delay-interval-seconds 100 \
        --proposal-title "Decentralize this SNS" \
        --summary "Decentralize this SNS" \
        --proposer "$NEURON_ID"
}

configure_boundary_nodes_for_recovered_nns() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1 # with protocol and port (http://...:8080)
    local TESTNET=$2

    local ORIGINAL_NNS_ID="tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
    local NNS_ROOT_KEY=$(mktemp)

    # Get the new public key from recovered NNS
    $IC_ADMIN --nns-url "$NNS_URL" \
        get-subnet-public-key \
        "$ORIGINAL_NNS_ID" \
        $NNS_ROOT_KEY

    local NNS_CONF="nns_url=$NNS_URL"

    pushd "$(repo_root)/testnet/env/$TESTNET"
    BOUNDARY_NODES=$(HOSTS_INI_FILENAME=hosts_unassigned.ini ./hosts --nodes | grep boundary | cut -d' ' -f2)

    NNS_SUBNET_NODE=$(get_node_for_subnet "$NNS_URL" "$ORIGINAL_NNS_ID")

    local SSH_ARGS="-A -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

    for NODE in $BOUNDARY_NODES; do
        echo "Stopping ic-registry-replicator..."
        ssh $SSH_ARGS "admin@$NODE" "sudo systemctl stop ic-registry-replicator"
        echo "Updating configuration for boundary node..."
        scp -vvv -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "$NNS_ROOT_KEY" "admin@[$NODE]:/var/lib/admin/nns_public_key.pem"
        ssh $SSH_ARGS "admin@$NODE" "cat /var/lib/admin/nns_public_key.pem | sudo tee /boot/config/nns_public_key.pem"

        ssh $SSH_ARGS "admin@$NODE" "echo $NNS_CONF | sudo tee /boot/config/nns.conf"

        echo "Deleting current NNS store..."
        # Delete the store
        ssh $SSH_ARGS "admin@$NODE" "sudo rm -rf /var/opt/registry/store"

        echo "Reconfigure ic-registry-replicator..."
        ssh $SSH_ARGS "admin@$NODE" "sudo systemctl restart setup-ic-registry-replicator"
        echo "Restarting ic-registry-replicator..."
        ssh $SSH_ARGS "admin@$NODE" "sudo systemctl start ic-registry-replicator"

        echo "Updating nix configuration on boundary node to work with recovered NNS topology"
        # Update nginx config to not randomly choose where to get root key from (it uses recovered NNS topology some of which point to mainnet nodes)
        ssh $SSH_ARGS "admin@$NODE" "cat /etc/nginx/conf.d/001-mainnet-nginx.conf \
            | sed 's/\$random_route_subnet_id/$ORIGINAL_NNS_ID/g' \
            | sed 's/\$random_route_subnet_type/system/g' \
            | sed 's/\$random_route_node_id/$NNS_SUBNET_NODE/g' \
            | sudo tee /run/ic-node/001-mainnet-nginx.conf >/dev/null"

        ssh $SSH_ARGS "admin@$NODE" "sudo mount --bind /run/ic-node/001-mainnet-nginx.conf /etc/nginx/conf.d/001-mainnet-nginx.conf"
        ssh $SSH_ARGS "admin@$NODE" "sudo nginx -s reload"
        echo "Done configuring boundary node $NODE"
    done
}

##: nns_proposal_info
## Get the information for a proposal for a given ID
## Usage: $1 <NNS_URL> <PROPOSAL_ID>
##      NNS_URL: The url to the subnet running the NNS in your testnet.
##      PROPOSAL_ID: The ID of the proposal
nns_proposal_info() {
    local NNS_URL=$1
    local PROPOSAL_ID=$2

    local IC=$(repo_root)
    local GOV_DID="$IC/rs/nns/governance/canister/governance.did"

    dfx canister --network $NNS_URL \
        call --candid "$GOV_DID" \
        $(nns_canister_id governance) get_proposal_info "( $PROPOSAL_ID : nat64 )"
}

### End functions related to SNS deployments

### Functions to get WASMs

get_sns_canister_wasm_gz_for_type() {
    local CANISTER_TYPE=$1
    local VERSION=$2

    DOWNLOAD_NAME=$(_canister_download_name_for_sns_canister_type "$CANISTER_TYPE")
    WASM_GZ=$(_download_canister_gz "$DOWNLOAD_NAME" "$VERSION")
    echo "$WASM_GZ"
}

get_nns_canister_wasm_gz_for_type() {
    local CANISTER_TYPE=$1
    local VERSION=$2

    DOWNLOAD_NAME=$(_canister_download_name_for_nns_canister_type "$CANISTER_TYPE")
    WASM_GZ=$(_download_canister_gz "$DOWNLOAD_NAME" "$VERSION")
    echo "$WASM_GZ"
}

_download_canister_gz() {
    DOWNLOAD_NAME=$1
    GIT_HASH=$2

    # See note at variable declaration
    OUTPUT_FILE="$MY_DOWNLOAD_DIR/$DOWNLOAD_NAME-$GIT_HASH.wasm.gz"

    curl --silent "https://download.dfinity.systems/ic/$GIT_HASH/canisters/$DOWNLOAD_NAME.wasm.gz" \
        --output "$OUTPUT_FILE"

    echo "$OUTPUT_FILE"
}

_canister_download_name_for_sns_canister_type() {
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

_canister_download_name_for_nns_canister_type() {
    local CANISTER_TYPE=$1

    if [ "$CANISTER_TYPE" == "lifeline" ]; then
        echo "$CANISTER_TYPE"
    elif [ "$CANISTER_NAME" == "ledger" ]; then
        echo "ledger-canister_notify-method"
    else
        echo "$CANISTER_TYPE"-canister
    fi
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

# End Functions to get WASMs

nns_canister_id() {
    CANISTER_NAME=$1

    IC_REPO=$(repo_root)
    pushd "$IC_REPO/rs/nns" >/dev/null

    cat ./canister_ids.json \
        | jq -er ".[\"$CANISTER_NAME\"].mainnet" \
        | grep -v null

    FOUND=$?

    popd >/dev/null

    return $FOUND
}

# TODO deduplicate this from icos_deploy.sh by moving into lib.sh
disk_image_exists() {
    GIT_REVISION=$1
    curl --output /dev/null --silent --head --fail \
        "https://download.dfinity.systems/ic/${GIT_REVISION}/guest-os/disk-img-dev/disk-img.tar.gz" \
        || curl --output /dev/null --silent --head --fail \
            "https://download.dfinity.systems/ic/${GIT_REVISION}/guest-os/disk-img.tar.gz"
}

##: latest_commit_with_prebuilt_artifacts
## Gets the latest git commit with a prebuilt governance canister WASM and a disk image
latest_commit_with_prebuilt_artifacts() {

    IC_REPO=$(repo_root)
    pushd "$IC_REPO" >/dev/null

    RECENT_CHANGES=$(git log -n 100 --pretty=format:'%H')

    for HASH in $RECENT_CHANGES; do
        echo >&2 "Checking $HASH..."
        GZ=$(_download_canister_gz "governance-canister" "$HASH")

        if ungzip "$GZ" >/dev/null 2>&1; then
            if disk_image_exists "$HASH"; then
                echo "$HASH"
                return 0
            fi
        fi
    done

    popd >/dev/null

    echo >&2 "None found!"
    return 1
}

##: published_sns_canister_diff
## Gets the diff between the mainnet commits of various SNS canisters and IC master.
## Usage: $1
##
## In V1 of this function, the commits are sourced from commits.sh. In the future, these
## commits will be automatically parsed
published_sns_canister_diff() {
    IC_REPO=$(repo_root)
    git fetch origin master

    source "$SCRIPT_DIR/commits.sh"

    echo "rs/sns/governance changes since $SNS_GOVERNANCE_COMMIT"
    pretty_git_log "$SNS_GOVERNANCE_COMMIT" "rs/sns/governance"

    echo "rs/sns/root changes since $SNS_ROOT_COMMIT"
    pretty_git_log "$SNS_ROOT_COMMIT" "rs/sns/root"

    echo "rs/sns/swap changes since $SNS_SWAP_COMMIT"
    pretty_git_log "$SNS_SWAP_COMMIT" "rs/sns/swap"

    echo "rs/rosetta-api/icrc1/archive changes since $SNS_ARCHIVE_COMMIT"
    pretty_git_log "$SNS_ARCHIVE_COMMIT" "rs/rosetta-api/icrc1/archive"

    echo "rs/rosetta-api/icrc1/ledger changes since $SNS_LEDGER_COMMIT"
    pretty_git_log "$SNS_LEDGER_COMMIT" "rs/rosetta-api/icrc1/ledger"

    echo "rs/rosetta-api/icrc1/index changes since $SNS_INDEX_COMMIT"
    pretty_git_log "$SNS_INDEX_COMMIT" "rs/rosetta-api/icrc1/index"

    echo "rs/nns/sns-wasm since $SNS_WASM_COMMIT"
    pretty_git_log "$SNS_WASM_COMMIT" "rs/nns/sns-wasm"

    echo "rs/sns/init changes w.r.t. sns-wasm since $SNS_WASM_COMMIT"
    pretty_git_log "$SNS_WASM_COMMIT" "rs/sns/init"
    echo

    echo "------------------------------------------------------------------------------------------"
    echo "If you are publishing a new SNS Version based off of this script, please update commits.sh"
    echo "------------------------------------------------------------------------------------------"
}

pretty_git_log() {
    local COMMIT=$1
    local DIR=$2
    git --no-pager log master --pretty=format:"   %Cred%h%Creset %s" "$COMMIT"... -- "$IC_REPO/$DIR"
    echo
}

##: nns_neuron_info
## Get the information for a proposal for a given ID
## Usage: $1 <NNS_URL> <PROPOSAL_ID>
##      NNS_URL: The url to the subnet running the NNS in your testnet.
##      NEURON_ID: The ID of the neuron
nns_neuron_info() {
    local NNS_URL=$1
    local NEURON_ID=$2

    local IC=$(repo_root)
    local GOV_DID="$IC/rs/nns/governance/canister/governance.did"

    dfx canister --network $NNS_URL \
        call --candid "$GOV_DID" \
        $(nns_canister_id governance) get_neuron_info "( $NEURON_ID : nat64 )"
}

##: top_up_wallet
## Tops up the wallet from the current dfx user's ICP balance
top_up_wallet() {
    local SUBNET_URL=$1
    local WALLET_CANISTER=$2
    local AMOUNT=$3

    dfx ledger top-up --network "$SUBNET_URL" \
        --amount "$AMOUNT" "$WALLET_CANISTER"
}

# Note, this will be deprecated soon when get_state is deprecated from sale canister.
call_swap() {
    local NNS_URL=$1
    local SWAP_CANISTER_ID=$2
    local METHOD=$3

    local IC=$(repo_root)
    local SWAP_DID="$IC/rs/sns/swap/canister/swap.did"

    dfx canister --network $NNS_URL \
        call --candid $SWAP_DID \
        $SWAP_CANISTER_ID $METHOD '(record {})'
}

sns_quill_participate_in_sale() {
    ensure_variable_set SNS_QUILL

    # Please forgive me we need separate urls for these subnets until we get the boundary node in the script :(
    local NNS_URL=$1
    local SNS_URL=$2
    local PEM=$3
    local ROOT_CANISTER_ID=$4 # Needed to generate canister ids file
    local ICP=$5              # Not e8s

    TMP_ONE=$(mktemp)
    TMP_TWO=$(mktemp)
    CANISTER_IDS_FILE=$(mktemp)

    generate_canister_ids_file_for_sns_quill "$SNS_URL" "$ROOT_CANISTER_ID" >$CANISTER_IDS_FILE

    # We expect an error b/c the second command won't run
    set +e
    $SNS_QUILL --canister-ids-file $CANISTER_IDS_FILE --pem-file "$PEM" swap --amount "$ICP" --memo 4 >"$TMP_ONE"
    IC_URL=$NNS_URL $SNS_QUILL send --yes "$TMP_ONE"
    set -e

    $SNS_QUILL --canister-ids-file $CANISTER_IDS_FILE --pem-file "$PEM" swap --amount "$ICP" --memo 4 --notify-only >"$TMP_TWO"
    IC_URL=$SNS_URL $SNS_QUILL send --yes "$TMP_TWO"
}

generate_canister_ids_file_for_sns_quill() {
    ensure_variable_set IDL2JSON

    local SNS_URL=$1
    local SNS_ROOT_CANISTER_ID=$2

    sns_list_sns_canisters $SNS_URL $SNS_ROOT_CANISTER_ID \
        | $IDL2JSON \
        | jq ".root |= .[0] | .governance |= .[0] | .swap |= .[0] | .ledger |= .[0] | .index |= .[0]" \
        | jq 'with_entries(.key |= . + "_canister_id") | with_entries( if .key == "dapps_canister_id" then .key = "dapp_canister_id_list" else . end)'
}

sns_list_sns_canisters() {

    local SNS_URL=$1
    local SNS_ROOT_CANISTER_ID=$2

    local IC=$(repo_root)
    local ROOT_DID="$IC/rs/sns/root/canister/root.did"

    dfx canister --network "$SNS_URL" \
        call --candid "$ROOT_DID" \
        "$SNS_ROOT_CANISTER_ID" list_sns_canisters '(record {})'
}

sns_get_sns_canisters_summary() {

    local SNS_URL=$1
    local SNS_ROOT_CANISTER_ID=$2
    local IC=$(repo_root)
    local ROOT_DID="$IC/rs/sns/root/canister/root.did"

    dfx canister --network "$SNS_URL" \
        call --candid "$ROOT_DID" \
        "$SNS_ROOT_CANISTER_ID" get_sns_canisters_summary '(record {})'
}

sns_finalize_sale() {
    local SNS_URL=$1
    local SWAP_CANISTER_ID=$2

    local IC=$(repo_root)
    local SWAP_DID="$IC/rs/sns/swap/canister/swap.did"

    dfx canister --network "$SNS_URL" \
        call --candid "$SWAP_DID" \
        "$SWAP_CANISTER_ID" finalize_swap '(record {})'
}

##: sns_w_list_upgrade_steps
## List all the upgrade steps on the path
## Usage: $1 <NNS_URL> (<SNS_GOVERNANCE_CANISTER_ID>)
sns_w_list_upgrade_steps() {
    local NNS_URL=$1
    local SNS_GOVERNANCE_CANISTER_ID=${2:-}

    local IC=$(repo_root)
    local SNS_W_DID="$IC/rs/nns/sns-wasm/canister/sns-wasm.did"

    SNS_GOVERNANCE_CANISTER_ID=$([ "$SNS_GOVERNANCE_CANISTER_ID" == "" ] \
        && echo "null" \
        || echo "opt principal \"$SNS_GOVERNANCE_CANISTER_ID\"")

    dfx canister --network $NNS_URL \
        call --candid "$SNS_W_DID" \
        qaa6y-5yaaa-aaaaa-aaafa-cai list_upgrade_steps "(record {limit = 0: nat32; sns_governance_canister_id = $SNS_GOVERNANCE_CANISTER_ID})"
}

##: list_deployed_snses
## List all the SNSes that are deployed via SNS-W
## Usage: $1 <NNS_URL>
list_deployed_snses() {
    local NNS_URL=$1

    local IC=$(repo_root)
    local SNS_W_DID="$IC/rs/nns/sns-wasm/canister/sns-wasm.did"

    dfx canister --network $NNS_URL \
        call --candid "$SNS_W_DID" \
        qaa6y-5yaaa-aaaaa-aaafa-cai list_deployed_snses '(record {})'
}

sns_w_latest_version() {
    local NNS_URL=$1

    local IC=$(repo_root)
    local SNS_W_DID="$IC/rs/nns/sns-wasm/canister/sns-wasm.did"

    dfx canister --network $NNS_URL \
        call --candid "$SNS_W_DID" \
        qaa6y-5yaaa-aaaaa-aaafa-cai get_latest_sns_version_pretty '(null)'
}

install_sns_quill() {
    local DEST_FOLDER=$1
    log "Downloading sns-quill"

    local DEST=$DEST_FOLDER/sns-quill

    if [ $(uname -o) == "Darwin" ]; then
        if [ $(uname -p) == "arm" ]; then
            echo "Not supported (only 32 bit arm build available); Build locally and then set SNS_QUILL env variable"
            exit 1
        else
            curl -L -o $DEST https://github.com/dfinity/sns-quill/releases/download/v0.4.0/sns-quill-linux-x86_64
        fi
    else
        curl -L -o $DEST https://github.com/dfinity/sns-quill/releases/download/v0.4.0/sns-quill-linux-x86_64
    fi

    chmod +x $DEST
}

install_idl2json() {
    local DEST_FOLDER=$1
    log "Downloading sns-quill"
    set -x
    local DEST=$DEST_FOLDER/idl2json

    if [ "$(uname -op)" == "Darwin arm" ]; then
        #TODO test this path
        curl -L -o /tmp/idl2json.zip https://github.com/dfinity/idl2json/releases/download/v0.8.5/idl2json-macos-x86_64.zip
        unzip /tmp/idl2json.zip
    else
        curl -L -o /tmp/idl2json-linux-x86_64.tar.gz https://github.com/dfinity/idl2json/releases/download/v0.8.5/idl2json-linux-x86_64.tar.gz
        tar -zxvf /tmp/idl2json-linux-x86_64.tar.gz

    fi
    cp idl2json $DEST
    rm -f idl2json yaml2candid

    chmod +x $DEST

}
##: sns_list_my_neurons
## List the neurons
sns_list_my_neurons() {

    local SNS_URL=$1 # ususally SUBNET_URL
    local SNS_GOVERNANCE_CANISTER_ID=$2

    local IC=$(repo_root)
    local GOV_DID="$IC/rs/sns/governance/canister/governance.did"

    dfx canister --network $SNS_URL call \
        --candid $GOV_DID \
        $SNS_GOVERNANCE_CANISTER_ID list_neurons \
        "( record { of_principal = opt principal \"$(dfx identity get-principal)\"; limit = 100: nat32})"

}

hex2dec() {
    str=$(echo $@ | awk '{print toupper($0)}')
    echo "ibase=16; $str" | bc
}

# Outputs Javascript byte array
hash_to_idl_byte_array() {
    local INPUT=$1

    ARRAY=()
    for x in $(echo $INPUT | fold -w2); do
        ARRAY+=($(hex2dec $x))
    done

    OLDIFS=$IFS
    IFS=";"
    echo "{${ARRAY[*]}}"
    IFS=$OLDIFS
}

sns_w_get_next_sns_version() {
    local NNS_URL=$1
    local CURRENT_VERSION_CANDID=$2
    local SNS_GOVERNANCE_CANISTER_ID=${3:-}

    SNS_GOVERNANCE_CANISTER_ID=$([ "$SNS_GOVERNANCE_CANISTER_ID" == "" ] \
        && echo "null" \
        || echo "opt principal \"$SNS_GOVERNANCE_CANISTER_ID\"")

    local IC=$(repo_root)
    local SNS_W_DID="$IC/rs/nns/sns-wasm/canister/sns-wasm.did"

    dfx canister --network $NNS_URL call \
        --candid $SNS_W_DID \
        qaa6y-5yaaa-aaaaa-aaafa-cai get_next_sns_version \
        "(record {
                    governance_canister_id =  $SNS_GOVERNANCE_CANISTER_ID;
                    current_version = opt $CURRENT_VERSION_CANDID
                })"
}

sns_get_running_version() {

    local SNS_URL=$1
    local SNS_GOVERNANCE_CANISTER_ID=$2

    local IC=$(repo_root)
    local SNS_GOV_DID="$IC/rs/sns/governance/canister/governance.did"

    dfx canister --network "$SNS_URL" \
        call --candid $SNS_GOV_DID \
        "$SNS_GOVERNANCE_CANISTER_ID" get_running_sns_version "(record{})"
}

sns_upgrade_to_next_version() {
    ensure_variable_set SNS_QUILL

    local SNS_URL=$1
    local PEM=$2
    local SNS_GOVERNANCE_CANISTER_ID=$3
    local MEMO=$4

    SNS_DEV_NEURON_ID=$($SNS_QUILL public-ids --principal-id $(dfx identity get-principal) --memo $MEMO \
        | grep "SNS neuron id" \
        | cut -f2 -d: | awk '{$1=$1};1')

    BYTE_ARRAY_NEURON_ID=$(hash_to_idl_byte_array $SNS_DEV_NEURON_ID)

    PAYLOAD=$(
        cat <<EOF
(
  record {
    subaccount = vec $BYTE_ARRAY_NEURON_ID: vec nat8;
    command = opt variant {
      MakeProposal = record {
        url = "";
        title = "Upgrade an SNS canister";
        action = opt variant {
            UpgradeSnsToNextVersion = record {}
        };
        summary = "Upgrade I hope";
      }
    };
  },
)
EOF
    )
    dfx canister --network "$SNS_URL" call "$SNS_GOVERNANCE_CANISTER_ID" manage_neuron "$PAYLOAD"

}

sns_get_proposal() {
    local SNS_URL=$1
    local SNS_GOVERNANCE_CANISTER_ID=$2
    local PROPOSAL_ID=$3

    local IC=$(repo_root)
    local GOV_DID="$IC/rs/sns/governance/canister/governance.did"

    dfx canister --network $SNS_URL \
        call --candid "$GOV_DID" \
        $SNS_GOVERNANCE_CANISTER_ID get_proposal "( record { proposal_id = opt record { id = $PROPOSAL_ID : nat64 }})"
}
