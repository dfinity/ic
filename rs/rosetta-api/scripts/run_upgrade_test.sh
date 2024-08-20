#!/usr/bin/env bash

set -euo pipefail
set -x

function help {
    echo >&2 "Usage: $0 <commit_id> (icp-ledger-archive|icp-ledger-archive-1|ledger) <arg>?"
}

if (($# != 2)) && (($# != 3)); then
    help
    exit 1
fi

if [ "$2" != "icp-ledger-archive" ] && [ "$2" != "icp-ledger-archive-1" ] && [ "$2" != "ledger" ]; then
    help
    exit 2
fi

sudo apt update && sudo apt install sqlite3 containernetworking-plugins

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
COMMIT_ID="$1"
LEDGER_OR_ARCHIVE="$2"
ARG="${3:-}"

ROSETTA_DB_OLD=$("$SCRIPT_DIR/get_blocks.sh" | tail -n1)
if [ -z "$ARG" ]; then
    "$SCRIPT_DIR/../../../testnet/tools/nns-tools/test-canister-upgrade.sh" "$LEDGER_OR_ARCHIVE" "$COMMIT_ID"
else
    "$SCRIPT_DIR/../../../testnet/tools/nns-tools/test-canister-upgrade.sh" "$LEDGER_OR_ARCHIVE" "$COMMIT_ID" "$ARG"
fi
ROSETTA_DB_NEW=$("$SCRIPT_DIR/get_blocks.sh" | tail -n1)
"$SCRIPT_DIR/diff_rosetta_data.sh" "$ROSETTA_DB_OLD" "$ROSETTA_DB_NEW"
"$SCRIPT_DIR/test_transfers.sh"
"$SCRIPT_DIR/test_transfer_from.sh"
"$SCRIPT_DIR/test_approve.sh"
