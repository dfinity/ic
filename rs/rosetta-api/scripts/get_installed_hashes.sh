#!/usr/bin/env bash

set -euo pipefail

LEDGER_CANISTER_ID="ryjl3-tyaaa-aaaaa-aaaba-cai"
ARCHIVE_CANISTER_ID="qjdve-lqaaa-aaaaa-aaaeq-cai"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
TMP_DIR="$SCRIPT_DIR/tmp" # need a persistent directory from within dev container
INFO_FILE=$(find "$TMP_DIR" -iname "*.sourceme")

#shellcheck source=/dev/null
source "$INFO_FILE"

#shellcheck source=/dev/null
source "$SCRIPT_DIR/init_identity.sh"
init_identity # initialize the dfx identity

LEDGER_HASH=$(dfx canister --network "$NNS_URL" info "$LEDGER_CANISTER_ID" | grep hash | awk -Fx '{print $2}' | cut -c-10)
ARCHIVE_HASH=$(dfx canister --network "$NNS_URL" info "$ARCHIVE_CANISTER_ID" | grep hash | awk -Fx '{print $2}' | cut -c-10)

echo "ledger  $LEDGER_CANISTER_ID $LEDGER_HASH"
echo "archive $ARCHIVE_CANISTER_ID $ARCHIVE_HASH"
