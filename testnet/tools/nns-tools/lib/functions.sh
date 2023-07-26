#!/usr/bin/env bash
set -euo pipefail

if ! which jq >/dev/null; then
    echo >&2 "Tool \`jq\` not found.  Please install. \`brew install jq\` or check https://stedolan.github.io/jq/"
    exit 1
fi

### Upgrade canister related functions

##: propose_upgrade_canister_to_version_pem
## Upgrades an NNS canister by name using a neuron_id and a pem to a specified version on a given NNS
## Usage: $1 <NNS_URL> <NEURON_ID> <PEM> <CANISTER_NAME> <VERSION> (<ENCODED_ARGS_FILE>)
propose_upgrade_canister_to_version_pem() {
    local NNS_URL=$1
    local NEURON_ID=$2
    local PEM=$3
    local CANISTER_NAME=$4
    local VERSION=$5
    local ENCODED_ARGS_FILE=${6:-}

    WASM_FILE=$(get_nns_canister_wasm_gz_for_type "$CANISTER_NAME" "$VERSION")

    propose_upgrade_nns_canister_wasm_file_pem "$NNS_URL" "$NEURON_ID" "$PEM" "$CANISTER_NAME" "$WASM_FILE" "$ENCODED_ARGS_FILE"
}

build_canister_and_propose_upgrade_pem() {
    local NNS_URL=$1
    local NEURON_ID=$2
    local PEM=$3
    local CANISTER_NAME=$4
    local ENCODED_ARGS_FILE=${5:-}

    # TODO: Figure out a way to require that the result already be cached.
    bazel build "$(canister_bazel_label "${CANISTER_NAME}")"

    WASM_FILE="$(repo_root)/$(canister_bazel_artifact_path "${CANISTER_NAME}")"

    propose_upgrade_nns_canister_wasm_file_pem "$NNS_URL" "$NEURON_ID" "$PEM" "$CANISTER_NAME" "$WASM_FILE" "$ENCODED_ARGS_FILE"
}

canister_bazel_label() {
    local CANISTER_NAME=$1

    # A more authoritative place where these values are listed is the following:
    # https://sourcegraph.com/github.com/dfinity/ic@7f7f77e025ed16b58b4bae564eb27bc429d8063d/-/blob/publish/canisters/BUILD.bazel?L5&subtree=true
    case "$CANISTER_NAME" in
        "registry")
            echo "//rs/registry/canister:registry-canister"
            ;;
        "governance")
            echo "//rs/nns/governance:governance-canister"
            ;;
        "root")
            echo "//rs/nns/handlers/root/impl:root-canister"
            ;;
        "sns-wasm")
            echo "//rs/nns/sns-wasm:sns-wasm-canister"
            ;;
        "xrc-mock-canister")
            echo "//rs/rosetta-api/tvl/xrc_mock:xrc_mock_canister"
            ;;
        # TODO cycles-minting, genesis-token, identity, ledger, lifeline, nns-ui, registry
        *)
            echo "Sorry. I do not know how to build ${CANISTER_NAME}."
            exit 1
            ;;
    esac
}

canister_bazel_artifact_path() {
    local CANISTER_NAME=$1

    bazel cquery --output=files $(canister_bazel_label "$CANISTER_NAME") 2>/dev/null
}

propose_upgrade_nns_canister_wasm_file_pem() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    local NEURON_ID=$2
    local PEM=$3
    local CANISTER_NAME=$4
    local WASM_FILE=$5
    local ENCODED_ARGS_FILE=${6:-}

    CANISTER_ID=$(nns_canister_id "$CANISTER_NAME")

    propose_upgrade_canister_wasm_file_pem "$NNS_URL" "$NEURON_ID" "$PEM" "$CANISTER_ID" "$WASM_FILE" "$ENCODED_ARGS_FILE"
}

propose_upgrade_canister_wasm_file_pem() {
    ensure_variable_set IC_ADMIN

    local NNS_URL=$1
    local NEURON_ID=$2
    local PEM=$3
    local CANISTER_ID=$4
    local WASM_FILE=$5
    local ENCODED_ARGS_FILE=${6:-}

    # See note at variable declaration
    PROPOSAL="$MY_DOWNLOAD_DIR"/testnet_upgrade_proposal.txt
    echo "Testnet $CANISTER_ID upgrade" >$PROPOSAL

    local WASM_SHA=$(sha_256 "$WASM_FILE")

    $IC_ADMIN --nns-url "$NNS_URL" -s "$PEM" \
        propose-to-change-nns-canister --mode=upgrade \
        --canister-id "$CANISTER_ID" \
        --wasm-module-path "$WASM_FILE" \
        --wasm-module-sha256 "$WASM_SHA" \
        --summary-file $PROPOSAL \
        --proposer "$NEURON_ID" \
        $([ "${SKIP_STOPPING:-no}" == "yes" ] && echo "--skip-stopping-before-installing") \
        $([ -z "$ENCODED_ARGS_FILE" ] || echo "--arg $ENCODED_ARGS_FILE")

    rm -rf $PROPOSAL
}

get_nns_canister_code_location() {
    CANISTER_NAME=$1

    IC_REPO=$(repo_root)
    RUST_DIR="$IC_REPO/rs"
    LEDGER_COMMON="$RUST_DIR/rosetta-api/icp_ledger/src "
    LEDGER_COMMON+="$RUST_DIR/rosetta-api/ledger_core "
    LEDGER_COMMON+="$RUST_DIR/rosetta-api/ledger_canister_core "
    LEDGER_COMMON+="$IC_REPO/packages/icrc-ledger_types"
    # Map of locations
    code_location__registry="$RUST_DIR/registry/canister"
    code_location__governance="$RUST_DIR/nns/governance"
    code_location__ledger="$RUST_DIR/rosetta-api/ledger_canister/ledger $LEDGER_COMMON"
    code_location__icp_ledger_archive="$RUST_DIR/rosetta-api/icp_ledger/archive $LEDGER_COMMON"
    code_location__root="$RUST_DIR/nns/handlers/root/impl"
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

    dfx -q canister --network $NNS_URL \
        call --candid "$GOV_DID" \
        $(nns_canister_id governance) get_proposal_info "( $PROPOSAL_ID : nat64 )"
}

### End functions related to SNS deployments

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

    dfx -q canister --network $NNS_URL \
        call --candid "$GOV_DID" \
        $(nns_canister_id governance) get_neuron_info "( $NEURON_ID : nat64 )"
}

##: top_up_wallet
## Tops up the wallet from the current dfx user's ICP balance
top_up_wallet() {
    local SUBNET_URL=$1
    local WALLET_CANISTER=$2
    local AMOUNT=$3

    dfx -q ledger top-up --network "$SUBNET_URL" \
        --amount "$AMOUNT" "$WALLET_CANISTER"
}

# Note, this will be deprecated soon when get_state is deprecated from sale canister.
call_swap() {
    local NNS_URL=$1
    local SWAP_CANISTER_ID=$2
    local METHOD=$3

    local IC=$(repo_root)
    local SWAP_DID="$IC/rs/sns/swap/canister/swap.did"

    dfx -q canister --network $NNS_URL \
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

    dfx -q canister --network "$SNS_URL" \
        call --candid "$ROOT_DID" \
        "$SNS_ROOT_CANISTER_ID" list_sns_canisters '(record {})'
}

sns_get_sns_canisters_summary() {

    local SNS_URL=$1
    local SNS_ROOT_CANISTER_ID=$2
    local IC=$(repo_root)
    local ROOT_DID="$IC/rs/sns/root/canister/root.did"

    dfx -q canister --network "$SNS_URL" \
        call --candid "$ROOT_DID" \
        "$SNS_ROOT_CANISTER_ID" get_sns_canisters_summary '(record {})'
}

sns_finalize_sale() {
    local SNS_URL=$1
    local SWAP_CANISTER_ID=$2

    local IC=$(repo_root)
    local SWAP_DID="$IC/rs/sns/swap/canister/swap.did"

    dfx -q canister --network "$SNS_URL" \
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

    dfx -q canister --network "$NNS_URL" \
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

    dfx -q canister --network $NNS_URL \
        call --candid "$SNS_W_DID" \
        qaa6y-5yaaa-aaaaa-aaafa-cai list_deployed_snses '(record {})'
}

sns_w_latest_version() {
    local NNS_URL=$1

    local IC=$(repo_root)
    local SNS_W_DID="$IC/rs/nns/sns-wasm/canister/sns-wasm.did"

    dfx -q canister --network $NNS_URL \
        call --candid "$SNS_W_DID" \
        qaa6y-5yaaa-aaaaa-aaafa-cai get_latest_sns_version_pretty '(null)'
}

##: sns_list_my_neurons
## Usage: $1 <SUBNET_URL> <SNS_GOVERNANCE_CANISTER_ID>
## List the neurons owned by the current dfx identity
sns_list_my_neurons() {

    local SNS_URL=$1 # ususally SUBNET_URL
    local SNS_GOVERNANCE_CANISTER_ID=$2

    local IC=$(repo_root)
    local GOV_DID="$IC/rs/sns/governance/canister/governance.did"

    dfx -q canister --network $SNS_URL call \
        --candid $GOV_DID \
        $SNS_GOVERNANCE_CANISTER_ID list_neurons \
        "( record { of_principal = opt principal \"$(dfx -q identity get-principal)\"; limit = 100: nat32})"

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

    dfx -q canister --network $NNS_URL call \
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

    dfx -q canister --network "$SNS_URL" \
        call --candid $SNS_GOV_DID \
        "$SNS_GOVERNANCE_CANISTER_ID" get_running_sns_version "(record{})"
}

sns_upgrade_to_next_version() {
    ensure_variable_set SNS_QUILL

    local SNS_URL=$1
    local PEM=$2
    local SNS_GOVERNANCE_CANISTER_ID=$3
    local MEMO=$4

    SNS_DEV_NEURON_ID=$($SNS_QUILL public-ids --principal-id $(dfx -q identity get-principal) --memo $MEMO \
        | grep "SNS neuron id" \
        | cut -f2 -d: | awk '{$1=$1};1')

    BYTE_ARRAY_NEURON_ID=$(hex_to_idl_byte_array $SNS_DEV_NEURON_ID)

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
    dfx -q canister --network "$SNS_URL" call "$SNS_GOVERNANCE_CANISTER_ID" manage_neuron "$PAYLOAD"

}

##: sns_list_proposals
## Lists all proposals for an SNS with no filters
## Usage: $1 <SNS_URL> <SNS_GOVERNANCE_CANISTER_ID>
##   SNS_URL: URL of replica or boundary node that can send messages to SNS canisters
##   SNS_GOVERNANCE_CANISTER_ID: CanisterID of the SNS Governance canister
sns_list_proposals() {

    local SNS_URL=$1
    local SNS_GOVERNANCE_CANISTER_ID=$2

    local IC=$(repo_root)
    local GOV_DID="$IC/rs/sns/governance/canister/governance.did"

    dfx -q canister --network $SNS_URL \
        call --candid "$GOV_DID" \
        $SNS_GOVERNANCE_CANISTER_ID list_proposals "( record { include_reward_status = vec {}; limit = 0; exclude_type = vec {}; include_status = vec {}; })"
}

##: sns_get_proposal
## Usage: $1 <SNS_URL> <SNS_GOVERNANCE_CANISTER_ID> <PROPOSAL_ID>
sns_get_proposal() {
    local SNS_URL=$1
    local SNS_GOVERNANCE_CANISTER_ID=$2
    local PROPOSAL_ID=$3

    local IC=$(repo_root)
    local GOV_DID="$IC/rs/sns/governance/canister/governance.did"

    dfx -q canister --network $SNS_URL \
        call --candid "$GOV_DID" \
        "$SNS_GOVERNANCE_CANISTER_ID" get_proposal "( record { proposal_id = opt record { id = $PROPOSAL_ID : nat64 }})"
}
