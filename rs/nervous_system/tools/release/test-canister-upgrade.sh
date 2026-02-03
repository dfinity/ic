#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <CANISTER_NAME> <VERSION> (<CANDID_ARGS> <NNS_URL> <NEURON_ID>)
  CANISTER_NAME: Human readable canister name (from rs/nns/canister_ids.json)
  VERSION: Version to test (generally git hash, could be build id.  Green checkmarks on GitHub commit list have assets)
  CANDID_ARGS: Candid args to encode to include in the request.  Use empty string
   to skip if manually passing NNS_URL and NEURON_ID
  NNS_URL: The url to the subnet running the NNS in your testnet.
  NEURON_ID: The neuron used to submit proposals (should have following to immediately pass)

  NOTE: If testing cycles-minting canister upgrade, you may have to set SKIP_STOPPING=yes in your environment before
    running this script, if your upgrade arguments reference canisters not running on this testnet.

  This script will upgrade a canister on a given testnet with a given neuron id.  If that neuron does not have sufficient
  voting power to pass the proposal, the proposal will still have to be voted in.
  "
    exit 1
}

if [ $# -lt 2 ]; then
    help
fi

set_testnet_env_variables

CANISTER_NAME=$1
VERSION=$2
CANDID_ARGS=${3:-$(empty_candid_upgrade_args "$CANISTER_NAME")}
NNS_URL=${4:-$NNS_URL}
NEURON_ID=${5:-$NEURON_ID}

ensure_variable_set NNS_URL || help
ensure_variable_set NEURON_ID || help

ENCODED_ARGS_FILE=""
if [ ! -z "$CANDID_ARGS" ]; then
    ENCODED_ARGS_FILE=$(encode_candid_args_in_file "$CANDID_ARGS")
fi

# When CMC is recovered from mainnet, it soon starts making calls to the Exchange Rate Canister (XRC), which is on a
# subnet that is not recovered.  These calls don't timeout and can't return.  That prevents CMC from ever being able to
# stop, which means we could never complete the upgrade. However, because they cannot return,
# it is safe to skip stopping when testing the upgrade of this canister, as replies cannot cause arbitrary code to execute
# when they return (which is the only reason for stopping in the first place).  The upgrade will still work, and
# the upgrade process will be exercised.
if [ "$CANISTER_NAME" == "cycles-minting" ]; then
    export SKIP_STOPPING=yes
fi

propose_upgrade_canister_to_version_pem "$NNS_URL" "$NEURON_ID" "$PEM" "$CANISTER_NAME" "$VERSION" "$ENCODED_ARGS_FILE"

if ! wait_for_nns_canister_has_version "$NNS_URL" "$CANISTER_NAME" "$VERSION"; then
    print_red "Aborting test"
    exit 1
fi

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
propose_upgrade_nns_canister_wasm_file_pem "$NNS_URL" "$NEURON_ID" "$PEM" "$CANISTER_NAME" "$UNZIPPED" "$ENCODED_ARGS_FILE"

if wait_for_nns_canister_has_file_contents "$NNS_URL" "$CANISTER_NAME" "$UNZIPPED"; then
    echo "Second upgrade successful..."
    print_green "Canister Upgrade test was successful!"
    exit 0
else
    print_red "Canister Upgrade test FAILED."
    exit 1
fi
