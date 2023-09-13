#!/bin/bash
set -Eeuo pipefail

source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"/../functions.sh

ensure_variable_set SNS_CLI IC_ADMIN SNS_QUILL IDL2JSON

PEM=$NNS_TOOLS_DIR/test_user.pem

# Upgrade SNS-W to the version we had when we did the original deploy (sns init parameters need to match)
propose_upgrade_canister_to_version_pem "$NNS_URL" "$NEURON_ID" "$PEM" "sns-wasm" "090276896af7c5eaa9d9dcbb9af45fe957d0a99b"

# Install all the wasms at the versions they were at to get our deploy latest-version to match
upload_canister_git_version_to_sns_wasm "$NNS_URL" "$NEURON_ID" "$PEM" root 1fc0208b9aeed0554b1be2711605e5b54ace9d6a
upload_canister_git_version_to_sns_wasm "$NNS_URL" "$NEURON_ID" "$PEM" governance 090276896af7c5eaa9d9dcbb9af45fe957d0a99b
upload_canister_git_version_to_sns_wasm "$NNS_URL" "$NEURON_ID" "$PEM" ledger 090276896af7c5eaa9d9dcbb9af45fe957d0a99b
upload_canister_git_version_to_sns_wasm "$NNS_URL" "$NEURON_ID" "$PEM" swap c9b2f9653afc2da47e5bd527c192090b860acbf0
upload_canister_git_version_to_sns_wasm "$NNS_URL" "$NEURON_ID" "$PEM" archive 1fc0208b9aeed0554b1be2711605e5b54ace9d6a
upload_canister_git_version_to_sns_wasm "$NNS_URL" "$NEURON_ID" "$PEM" index c9b2f9653afc2da47e5bd527c192090b860acbf0

echo "Trying to install the SNS (this could take some time...)"
# Install the new sns
DEPLOY_OUTPUT=$(deploy_new_sns $SUBNET_URL $WALLET_CANISTER $NNS_TOOLS_DIR/scenarios/sns_lots_of_airdrops.yml)
SWAP_CANISTER_ID=$(echo "$DEPLOY_OUTPUT" | grep 1_281_239_699 | sed 's/.*"\(.*\)";/\1/')
ROOT_CANISTER_ID=$(echo "$DEPLOY_OUTPUT" | grep 1_269_755_426 | sed 's/.*"\(.*\)";/\1/')
GOVERNANCE_CANISTER_ID=$(echo "$DEPLOY_OUTPUT" | grep 3_306_137_890 | sed 's/.*"\(.*\)";/\1/')
echo "$DEPLOY_OUTPUT"

echo "Trying to open"
# Should execute automatically
test_propose_to_open_sns_token_swap_pem "$NNS_URL" "$NEURON_ID" "$PEM" "$SWAP_CANISTER_ID"
echo "Opened sale"

echo "Trying to participate..."
# Participate with max amount to close the sale
sns_quill_participate_in_sale $NNS_URL $SUBNET_URL "$PEM" "$ROOT_CANISTER_ID" 30000
echo "Participated..."

echo "Trying to finalize..."
sns_finalize_sale $SUBNET_URL $SWAP_CANISTER_ID
echo "Finalize..."

upload_canister_git_version_to_sns_wasm "$NNS_URL" "$NEURON_ID" "$PEM" ledger efc4ad843489d21ec44659f115472056b811723d

#Use our developer neuron to upgrade (will fail)
sns_upgrade_to_next_version $SUBNET_URL $PEM $GOVERNANCE_CANISTER_ID 0

# Now we are in a broken state...
