#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$SCRIPT_DIR/functions.sh"

help() {
    echo "
Usage: $0 <CANISTER_NAME> <VERSION> (<NNS_URL> <NEURON_ID>)
  CANISTER_NAME: Human readable canister name (from rs/nns/canister_ids.json)
  VERSION: Version to test (generally git hash, could be build id.  Green checkmarks on gitlab commit list have assets)
  NNS_URL: The url to the subnet running the NNS in your testnet.
  NEURON_ID: The neuron used to submit proposals (should have following to immediately pass)

  NOTE: Both NNS_URL and NEURON_ID can be passed in or set as environment variables.
    Using \"source \$YOUR_WORKING_DIRECTORY/output_vars_nns_state_deployment.sh\" will give you the needed
    variables in your shell.

  This script will upgrade a canister on a given testnet with a given neuron id.  If that neuron does not have sufficient
  voting power to pass the proposal, the proposal will still have to be voted in.
  "
    exit 1
}

if [ $# -lt 2 ]; then
    help
fi

CANISTER_NAME=$1
VERSION=$2
NNS_URL=${3:-$NNS_URL}
NEURON_ID=${4:-$NEURON_ID}

ensure_variable_set NNS_URL || help
ensure_variable_set NEURON_ID || help

# Allow overriding PEM file, but default to shared identity
export PEM=${PEM:-$SCRIPT_DIR/nns_test_user_dfx_identity}

propose_upgrade_canister_to_version_pem "$NNS_URL" "$NEURON_ID" "$PEM" "$CANISTER_NAME" "$VERSION"
