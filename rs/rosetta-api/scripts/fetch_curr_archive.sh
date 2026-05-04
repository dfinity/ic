#!/usr/bin/env bash

set -euo pipefail
set -x

COMMIT_ID=$(curl -s -f https://raw.githubusercontent.com/dfinity/ic/master/rs/ledger_suite/icp/UPGRADES.md \
    | grep "^|.*archive" | awk -F'|' '{print $4}' | sed 's/[` ]\+//g' | tail -n1)
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
TMP_DIR="$SCRIPT_DIR/tmp"
INFO_FILE=$(find "$TMP_DIR" -iname "*.sourceme")
COMMIT_DIR="$TMP_DIR/$COMMIT_ID"
ARCHIVE_FILE="$COMMIT_DIR/ledger-archive-node-canister.wasm.gz"
mkdir -p "$COMMIT_DIR"
if [ -f "$ARCHIVE_FILE" ]; then
    echo "Skipping download because the archive file already exists at $ARCHIVE_FILE"
else
    curl -s -f "https://download.dfinity.systems/ic/$COMMIT_ID/canisters/ledger-archive-node-canister.wasm.gz" -o "$ARCHIVE_FILE"
fi
ARCHIVE_HASH=$(sha256sum "$ARCHIVE_FILE" | awk '{print $1}')
# shellcheck source=/dev/null
source "$INFO_FILE"
set +e
# A bit of a hack: we check if the archive hash is in the dashboard
# regardless of the place.
HASH_IN_DASHBOARD=$(curl -s -f "$NNS_URL/_/dashboard" | grep "$ARCHIVE_HASH")
if [ -z "$HASH_IN_DASHBOARD" ]; then
    echo "Warning: the archive downloaded at commit $COMMIT_ID has different sha256 than the one deployed (sha256 is $ARCHIVE_HASH)"
fi
