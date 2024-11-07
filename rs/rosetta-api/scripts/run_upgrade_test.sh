#!/usr/bin/env bash

set -euo pipefail
set -x

function help {
    echo >&2 "Usage: $0 <commit_id> (icp-ledger-archive|icp-ledger-archive-1|icp-ledger-archive-2|icp-index|ledger) <arg>?"
}

if (($# != 2)) && (($# != 3)); then
    help
    exit 1
fi

if [ "$2" != "icp-ledger-archive" ] \
    && [ "$2" != "icp-ledger-archive-1" ] \
    && [ "$2" != "icp-ledger-archive-2" ] \
    && [ "$2" != "icp-index" ] \
    && [ "$2" != "ledger" ]; then
    help
    exit 2
fi

function check_index() {
    set +e
    INDEX_CANISTER_ID="qhbym-qaaaa-aaaaa-aaafq-cai"
    CANISTER_STATUS=100
    for i in {1..20}; do
        DFX_DISABLE_QUERY_VERIFICATION=1 dfx canister call --network $NNS_URL \
            --candid "$SCRIPT_DIR/../../ledger_suite/icp/index/index.did" $INDEX_CANISTER_ID get_blocks \
            '(record { start=0; length=1; }, )'
        CANISTER_STATUS=$?
        if [ "$CANISTER_STATUS" == "0" ]; then
            break
        fi
        sleep 3
    done
    if [ "$CANISTER_STATUS" == "0" ]; then
        echo "Index canister is up and running"
    else
        echo "Index canister is not up and running"
        exit 1
    fi
    set -e
}

sudo apt update && sudo apt install -y sqlite3 containernetworking-plugins

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
COMMIT_ID="$1"
LEDGER_OR_ARCHIVE="$2"
ARG="${3:-}"
ROSETTA_DB_OLD=""

if [ "$LEDGER_OR_ARCHIVE" != "icp-index" ]; then
    ROSETTA_DB_OLD=$("$SCRIPT_DIR/get_blocks.sh" | tail -n1)
fi

check_index

if [ -z "$ARG" ]; then
    "$SCRIPT_DIR/../../../testnet/tools/nns-tools/test-canister-upgrade.sh" "$LEDGER_OR_ARCHIVE" "$COMMIT_ID"
else
    "$SCRIPT_DIR/../../../testnet/tools/nns-tools/test-canister-upgrade.sh" "$LEDGER_OR_ARCHIVE" "$COMMIT_ID" "$ARG"
fi

if [ "$LEDGER_OR_ARCHIVE" != "icp-index" ]; then
    ROSETTA_DB_NEW=$("$SCRIPT_DIR/get_blocks.sh" | tail -n1)
    "$SCRIPT_DIR/diff_rosetta_data.sh" "$ROSETTA_DB_OLD" "$ROSETTA_DB_NEW"
fi
"$SCRIPT_DIR/test_transfers.sh"
"$SCRIPT_DIR/test_transfer_from.sh"
"$SCRIPT_DIR/test_approve.sh"

check_index
