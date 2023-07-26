#!/usr/bin/env bash

set -euo pipefail
set -x

function help {
    echo >&2 "Usage: $0 <test_net> <commit_id> (archive|ledger) <arg>?"
}

if (($# != 3)) && (($# != 4)); then
    help
    exit 1
fi

if [ "$3" != "archive" ] && [ "$3" != "ledger" ]; then
    help
    exit 2
fi

sudo apt update && sudo apt install sqlite3 xxd

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
TEST_NET="$1"
COMMIT_ID="$2"
LEDGER_OR_ARCHIVE="$3"
ARG="${4:-}"

"$SCRIPT_DIR/setup_testnet.sh" "$TEST_NET"
ROSETTA_DB_OLD=$("$SCRIPT_DIR/get_blocks.sh" | tail -n1)
if [ -z "$ARG" ]; then
    "$SCRIPT_DIR/submit_proposal.sh" "$COMMIT_ID" "$LEDGER_OR_ARCHIVE"
else
    "$SCRIPT_DIR/submit_proposal.sh" "$COMMIT_ID" "$LEDGER_OR_ARCHIVE" "$ARG"
fi
ROSETTA_DB_NEW=$("$SCRIPT_DIR/get_blocks.sh" | tail -n1)
"$SCRIPT_DIR/diff_rosetta_data.sh" "$ROSETTA_DB_OLD" "$ROSETTA_DB_NEW"
"$SCRIPT_DIR/test_transfers.sh"
