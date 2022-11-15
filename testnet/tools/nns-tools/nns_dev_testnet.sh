#!/bin/bash

set -eo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$SCRIPT_DIR/functions.sh"
TESTNET_TOOLS="$(repo_root)/testnet/tools"
DEPLOYMENT_STEPS=${DEPLOYMENT_STEPS:-''}

help() {
    print_green "
Usage: $0 <TESTNET_NAME> <REPLICA_VERSION>
  TESTNET_NAME: The name of the testnet (a folder name in '<repo_root>/testnet/env').
    Note: Testnet must have a file called 'hosts_unassigned.ini' for this script to succeed.
  REPLICA_VERSION: The version of the replica to install on the testnet. Usually git id, or a build id for MR pipelines

  This script will recover a testnet to use mainnet backup in a state ready to launch SNSs and deploy canisters.
  It creates two subnets, one system subnet, and one application subnet.
"
}

if [ $# -lt 2 ]; then
    help
    echo
    print_red "Not enough arguments"
    exit 1
fi

TESTNET=$1
VERSION=$2

SSH_ARGS="-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

if ! which dfx >/dev/null; then
    echo "Please install DFX and add it to your local PATH variable."
    echo "See https://internetcomputer.org/docs/current/developer-docs/build/install-upgrade-remove/"
    exit 1
fi

PEM=$SCRIPT_DIR/nns_test_user_dfx_identity
dfx identity import --force --disable-encryption nns_test_user_dfx_identity $PEM
dfx identity use nns_test_user_dfx_identity
PRINCIPAL=$(dfx identity get-principal)

log "TESTNET=$TESTNET"
log "VERSION=$VERSION"
log "PEM=$PEM"
log "PRINCIPAL=$PRINCIPAL"

# We need to set DIR so that nns_state_deployment.sh doesn't delete the tmp folder after it runs
export DIR=${DIR:-$(mktemp -d)}
mkdir -p $DIR

if [ ! -f "$DIR/sns" ]; then
    install_binary sns "$VERSION" "$DIR"
fi

IC_ADMIN="$DIR/ic-admin"
SNS_CLI="$DIR/sns"

# First we just create the NNS State deployment using our special identity
# We use this to calculate variables from the next
NNS_STATE_DEPLOYMENT_RESULT=$DIR/nns_state_deployment_output
step 1 "Step 1: NNS State Deployment Script" || time (
    STEPS="$DEPLOYMENT_STEPS" $TESTNET_TOOLS/nns_state_deployment.sh "$TESTNET" "$VERSION" "$PRINCIPAL" "$PEM" | tee /dev/tty >$NNS_STATE_DEPLOYMENT_RESULT
)

#From the script result output, we need to obtain the list of Subnets
# so we can re-add them to the Registry topography
source "$DIR"/output_vars_nns_state_deployment.sh

step 2 "Step 2: Create subnet from the unassigned nodes" || (
    echo Creating subnet with unassigned nodes...

    create_new_subnet "$NNS_URL" "$NEURON_ID" "$PEM" "$VERSION" application "$UNASSIGNED_NODES"
    echo "Pausing for subnet to be created... @ $UNASSIGNED_NODES"
    sleep 30
    for NODE in $UNASSIGNED_NODES; do
        IP=$(node_ip_from_node_id "$NNS_URL" "$NODE")
        until ssh $SSH_ARGS "admin@${IP}" 'journalctl | grep -q "Ready for interaction"' &>/dev/null; do
            print_blue "Waiting for the subnet to be created..."
            sleep 2
        done
    done
)

NEW_SUBNET_ID=$(find_subnet_with_node "$NNS_URL" $UNASSIGNED_NODES)

step 3 "Set CMC default subnets to one on testnet" || (
    set_default_subnets "$NNS_URL" "$NEURON_ID" "$PEM" "$NEW_SUBNET_ID"
)

SUBNET_IP=$(get_node_ip_for_subnet "$NNS_URL" "$NEW_SUBNET_ID")
SUBNET_URL="http://[$SUBNET_IP]:8080"

step 4 "Create the cycles wallet for our test user" || time (
    WALLET_CANISTER=$(dfx ledger --network "$NNS_URL" create-canister "$PRINCIPAL" --amount 300 \
        | grep "Canister created" \
        | sed 's/.*"\(.*\)"/\1/') # get the CanisterId in quotes

    # Request to install must be made to here...
    dfx identity --network "$SUBNET_URL" deploy-wallet "$WALLET_CANISTER"
    dfx identity --network "$SUBNET_URL" set-wallet "$WALLET_CANISTER"

    # NOTE - to use deploy_new_sns you need to set the --network  to the SUBNET_URL not NNS_URL, b/c it has to go through your
    # wallet first....
    echo $WALLET_CANISTER >$DIR/wallet_canister
)

WALLET_CANISTER=$(cat $DIR/wallet_canister)
export WALLET_CANISTER

step 5 "Configure SNS-WASMs" || time (

    set_sns_wasms_allowed_subnets "$NNS_URL" "$NEURON_ID" "$PEM" "$NEW_SUBNET_ID"
    add_sns_wasms_allowed_principal "$NNS_URL" "$NEURON_ID" "$PEM" "$WALLET_CANISTER"

    echo "Wait a moment for proposal execution..."
    sleep 5

    echo "Currently allowed sns_subnet_ids?"
    dfx canister --network $NNS_URL call qaa6y-5yaaa-aaaaa-aaafa-cai get_sns_subnet_ids '(record {})'

    echo "Currently allowed principals?"
    dfx canister --network $NNS_URL call qaa6y-5yaaa-aaaaa-aaafa-cai get_allowed_principals '(record {})'

)

step --optional 6 "Upload WASMs to SNS-WASM" || time (
    LOG_FILE="$DIR/4_upload_wasms_to_sns_wasm.txt"
    for TYPE in ledger governance archive swap root index; do
        upload_canister_wasm_to_sns_wasm "$NNS_URL" "$NEURON_ID" "$PEM" $TYPE "$VERSION"
    done >"$LOG_FILE"
)

# Put all useful variables into a single place
VARS_FILE="$DIR/output_vars_nns_dev_testnet.sh"
echo "source $DIR/output_vars_nns_state_deployment.sh" >"$VARS_FILE"
echo "export SUBNET_URL=$SUBNET_URL" >>"$VARS_FILE"
echo "export WALLET_CANISTER=$WALLET_CANISTER" >>"$VARS_FILE"
echo "export IC_ADMIN=$IC_ADMIN" >>$VARS_FILE
echo "export SNS_CLI=$SNS_CLI" >>$VARS_FILE

echo "Variables from script stored at $VARS_FILE..."
