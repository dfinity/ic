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

for i in {1..20}; do
    echo "Testing if upgrade was successful..."
    if canister_has_version_installed $NNS_URL $CANISTER_NAME $VERSION; then
        print_green "First upgrade successful"
        break
    fi

    if [ $i -eq 20 ]; then
        print_red "First upgrade failed, aborting remainder of test"
        exit 1
    fi

    sleep 10
done

echo "Testing subsequent upgrade to ensure upgrade path continues to work"

# Download current version, and modify it,
WASM_GZ_FILE=$(get_nns_canister_wasm_gz_for_type "$CANISTER_NAME" "$VERSION")
ORIGINAL_HASH=$(sha_256 $WASM_GZ_FILE)

UNZIPPED=$(ungzip $WASM_GZ_FILE)

NEW_HASH=$(sha_256 "$UNZIPPED")

echo "Checking that hashes are in fact different..."
if [ "$NEW_HASH" == "$ORIGINAL_HASH" ]; then
    print_red "Hashes were the same, aborting rest of test..."
    exit 1
fi

# We upgrade to same version but with a different hash so that we can verify that second upgrade worked.
propose_upgrade_canister_wasm_file_pem "$NNS_URL" "$NEURON_ID" "$PEM" "$CANISTER_NAME" "$UNZIPPED"

for i in {1..20}; do
    echo "Testing if second upgrade was successful..."
    if canister_has_file_contents_installed "$NNS_URL" "$CANISTER_NAME" "$UNZIPPED"; then
        echo "Second upgrade successful..."
        print_green "Canister Upgrade test was successful!"
        exit 0
    fi
    sleep 10
done

print_red "Canister Upgrade test FAILED."
exit 1
