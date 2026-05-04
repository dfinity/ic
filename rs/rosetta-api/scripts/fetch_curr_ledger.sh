#!/usr/bin/env bash

set -euo pipefail
set -x

COMMIT_ID=$(curl -s -f https://raw.githubusercontent.com/dfinity/ic/master/rs/ledger_suite/icp/UPGRADES.md \
    | grep "^|" | grep -v 'archive' | awk -F'|' '{print $4}' | sed 's/[` ]\+//g' | tail -n1)
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
TMP_DIR="$SCRIPT_DIR/tmp"
INFO_FILE=$(find "$TMP_DIR" -iname "*.sourceme")
COMMIT_DIR="$TMP_DIR/$COMMIT_ID"
LEDGER_FILE="$COMMIT_DIR/ledger-canister_notify-method.wasm.gz"
mkdir -p "$COMMIT_DIR"
if [ -f "$LEDGER_FILE" ]; then
    echo "Skipping download because the ledger file already exists at $LEDGER_FILE"
else
    curl -s -f "https://download.dfinity.systems/ic/$COMMIT_ID/canisters/ledger-canister_notify-method.wasm.gz" -o "$LEDGER_FILE"
fi
LEDGER_HASH=$(sha256sum "$LEDGER_FILE" | awk '{print $1}')
#shellcheck source=/dev/null
source "$INFO_FILE"
set +e
# A bit of a hack: we check if the ledger hash is in the dashboard
# regardless of the place.
HASH_IN_DASHBOARD=$(curl -s -f "$NNS_URL/_/dashboard" | grep "$LEDGER_HASH")
if [ -z "$HASH_IN_DASHBOARD" ]; then
    echo "Warning: the ledger downloaded at commit $COMMIT_ID has different sha256 than the one deployed (sha256 is $LEDGER_HASH)"
fi
