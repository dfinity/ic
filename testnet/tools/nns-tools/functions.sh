#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

source "$SCRIPT_DIR/../lib.sh"

# Needed because otherwise we get conflicts between two users running scripts on same machine (tmp directory is shared)
MY_DOWNLOAD_DIR="/tmp/$(whoami)_deploy_scripts"
mkdir -p $MY_DOWNLOAD_DIR

repo_root() {
    git rev-parse --show-toplevel
}

is_variable_set() {
    if [ -z "${!1}" ]; then
        return 1
    fi
    return 0
}

ensure_variable_set() {
    set +u
    while [ $# -gt 0 ]; do
        if ! is_variable_set $1; then
            echo "\$$1 was empty or unset.  Aborting."
            exit 1
        fi
        shift
    done
    set -u
}

download_canister_gz() {
    DOWNLOAD_NAME=$1
    GIT_HASH=$2

    OUTPUT_FILE="/tmp/$DOWNLOAD_NAME-$GIT_HASH.wasm.gz"

    curl --silent "https://download.dfinity.systems/ic/$GIT_HASH/canisters/$DOWNLOAD_NAME.wasm.gz" \
        --output "$OUTPUT_FILE"

    echo "$OUTPUT_FILE"
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

### End functions for searching nodes and subnets

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

    WASM_FILE=$(get_nns_canister_wasm_for_type "$CANISTER_NAME" "$VERSION")

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
        --summary-file /tmp/testnet_upgrade_proposal.txt \
        --proposer "$NEURON_ID"

    rm -rf $PROPOSAL
}

generate_release_notes_template() {

    local LAST_COMMIT=$1
    local NEXT_COMMIT=$2
    local CANISTER_NAME=$3
    local OUTPUT_FILE=${4:-}

    WASM=$(get_nns_canister_wasm_for_type "$CANISTER_NAME" "$NEXT_COMMIT")
    WASM_SHA=$(sha_256 "$WASM")
    CAPITALIZED_CANISTER_NAME="$(tr '[:lower:]' '[:upper:]' <<<${CANISTER_NAME:0:1})${CANISTER_NAME:1}"

    IC_REPO=$(repo_root)

    CANISTER_CODE_LOCATION=$(get_canister_code_location "$CANISTER_NAME")
    ESCAPED_IC_REPO=$(printf '%s\n' "$IC_REPO" | sed -e 's/[]\/$*.^[]/\\&/g')
    RELATIVE_CODE_LOCATION=".$(echo "$CANISTER_CODE_LOCATION" | sed "s/$ESCAPED_IC_REPO//")"

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
$(git log --format="%C(auto) %h %s" "$LAST_COMMIT".."$NEXT_COMMIT" -- "$CANISTER_CODE_LOCATION")
\`\`\`
## Wasm Verification
\`\`\`
git fetch
git checkout $NEXT_COMMIT
./gitlab-ci/tools/docker-build-ic --artifacts="canisters"
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

get_canister_code_location() {
    CANISTER_NAME=$1

    IC_REPO=$(repo_root)
    RUST_DIR="$IC_REPO/rs"
    # Map of locations
    code_location__registry="$RUST_DIR/registry/canister"
    code_location__governance="$RUST_DIR/nns/governance"
    code_location__ledger="$RUST_DIR/rosetta-api/ledger_canister"
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

##: get_info
## Prints the info for a named NNS canister
## Usage: $1 <NETWORK> <CANISTER_NAME>
## NETWORK: ic, or URL to an NNS subnet (including port)
## CANISTER_NAME: human readable canister name (i.e. governance, registry, sns-wasm, etc...)
get_info() {
    NETWORK=$1
    CANISTER_NAME=$2

    dfx canister --network "$NETWORK" info $(nns_canister_id "$CANISTER_NAME")
}

# End upgrade canister related

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

    WASM=$(get_sns_canister_wasm_for_type "$CANISTER_TYPE" "$VERSION")

    WASM_SHA=$(sha_256 "$WASM")

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

    local SUBNET_WITH_WALLET_URL=$1
    local WALLET_CANISTER=$2
    local CONFIG_FILE=$(3:-)

    if [ -z "$CONFIG_FILE" ]; then
        CONFIG_FILE=$SCRIPT_DIR/sns_default_test_init_params.yml
    fi

    $SNS_CLI deploy --network "$SUBNET_WITH_WALLET_URL" \
        --wallet-canister-override "$WALLET_CANISTER" \
        --init-config-file "$CONFIG_FILE"
}

### Functions to get WASMs

get_sns_canister_wasm_for_type() {
    local CANISTER_TYPE=$1
    local VERSION=$2

    DOWNLOAD_NAME=$(_canister_download_name_for_sns_canister_type "$CANISTER_TYPE")
    WASM_GZ=$(_download_canister_gz "$DOWNLOAD_NAME" "$VERSION")
    ungzip "$WASM_GZ"
}

get_nns_canister_wasm_for_type() {
    local CANISTER_TYPE=$1
    local VERSION=$2

    DOWNLOAD_NAME=$(_canister_download_name_for_nns_canister_type "$CANISTER_TYPE")
    WASM_GZ=$(_download_canister_gz "$DOWNLOAD_NAME" "$VERSION")
    ungzip "$WASM_GZ"
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

    [ "$CANISTER_TYPE" != "lifeline" ] && echo "$CANISTER_TYPE"-canister || echo "$CANISTER_TYPE"
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
