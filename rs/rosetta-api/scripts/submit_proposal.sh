#!/usr/bin/env bash

# Submit an upgrade proposal to the NNS.

set -euo pipefail
set -x

function help {
    echo >&2 "Usage: $0 <file_or_commit_id> (archive|ledger) <arg>?"
}

for arg in "$@"; do
    if [ "$arg" = '--help' ] || [ "$arg" = '-h' ]; then
        help
        exit 0
    fi
done

LEDGER_CANISTER_ID="ryjl3-tyaaa-aaaaa-aaaba-cai"
ARCHIVE_CANISTER_ID="qjdve-lqaaa-aaaaa-aaaeq-cai"

if [ "$2" != "archive" ] && [ "$2" != "ledger" ]; then
    help
    exit 2
elif [ "$2" == "archive" ]; then
    if (($# != 2)); then
        help
        exit 1
    fi
    CANISTER_ID="$ARCHIVE_CANISTER_ID"
else
    if (($# != 2)) && (($# != 3)); then
        help
        exit 1
    fi
    CANISTER_ID="$LEDGER_CANISTER_ID"
    ARG_OR_NULL="${3:-null}"
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
TMP_DIR="$SCRIPT_DIR/tmp" # need a persistent directory from within dev container
INFO_FILE=$(find "$TMP_DIR" -iname "*.sourceme")
LEDGER_DID="$SCRIPT_DIR/../icp_ledger/ledger.did"
EMPTY_FILE="$TMP_DIR/empty"
ARG_FILE="$TMP_DIR/arg"

#shellcheck source=/dev/null
source "$INFO_FILE"

source "$SCRIPT_DIR/init_identity.sh"
init_identity # initialize the dfx identity

if [ ! -f "$1" ]; then
    echo "No file found with name $1, I'm going to assume it's a commit id"
    COMMIT_ID=$(git rev-parse "$1")
    COMMIT_DIR="$TMP_DIR/$1"
    mkdir -p "$COMMIT_DIR"
    if [ "$2" == "archive" ]; then
        WASM_FILE="$COMMIT_DIR/ledger-archive-node-canister.wasm.gz"
        curl -s -f "https://download.dfinity.systems/ic/$COMMIT_ID/canisters/ledger-archive-node-canister.wasm.gz" -o "$WASM_FILE"
    else
        WASM_FILE="$COMMIT_DIR/ledger-canister_notify-method.wasm.gz"
        curl -s -f "https://download.dfinity.systems/ic/$COMMIT_ID/canisters/ledger-canister_notify-method.wasm.gz" -o "$WASM_FILE"
    fi
else
    echo "Found file with name $1"
    WASM_FILE="$1"
fi

arg_params=""
if [ "$2" = "ledger" ]; then
    if ! command -v didc &>/dev/null; then
        echo "didc not be found, downloading it"
        BIN_DIR="$TMP_DIR/bin"
        mkdir -p "$BIN_DIR"
        DIDC_BIN="$BIN_DIR/didc"
        curl -L -f "https://github.com/dfinity/candid/releases/download/2023-07-11/didc-linux64" -o "$DIDC_BIN"
        chmod +x "$DIDC_BIN"
        PATH="$BIN_DIR:$PATH"
    fi
    didc encode -d "$LEDGER_DID" -t '(opt LedgerCanisterPayload)' \
        "(opt variant { Upgrade=$ARG_OR_NULL },)" \
        | xxd -r -p >"$ARG_FILE"
    arg_params="--arg $ARG_FILE"
fi

WASM_HASH=$(sha256sum "$WASM_FILE" | awk '{print $1}')
touch "$EMPTY_FILE"
"$SCRIPT_DIR/../../../artifacts/guestos/$TEST_NET/$REPLICA_VERSION/bin/ic-admin" \
    --secret-key-pem "$HOME/.config/dfx/identity/$(dfx identity whoami)/identity.pem" \
    --nns-url "$NNS_URL" \
    propose-to-change-nns-canister \
    --proposer "$NEURON_ID" \
    --canister-id "$CANISTER_ID" \
    --mode upgrade \
    --wasm-module-path "$WASM_FILE" \
    --wasm-module-sha256 "$WASM_HASH" \
    --summary-file "$EMPTY_FILE" \
    $arg_params

sleep 5
max_attempts=23 # wait 115 (+ 5) seconds = 2 min
canister_hash=$(dfx canister --network "$NNS_URL" info "$CANISTER_ID" | grep hash | awk -Fx '{print $2}')
until [ "$canister_hash" = "$WASM_HASH" ]; do
    max_attempts=$(($max_attempts - 1))
    if [ $max_attempts -eq 0 ]; then
        echo >&2 "New hash for canister $CANISTER_ID not found (found '$canister_hash'). Did the proposal fail?"
        exit 3
    fi
    echo "New hash for canister $CANISTER_ID not found (found '$canister_hash'). Waiting 5s and checking again..."
    sleep 5
    canister_hash=$(dfx canister --network "$NNS_URL" info "$CANISTER_ID" | grep hash | awk -Fx '{print $2}')
done
echo "New hash for canister $CANISTER_ID found, upgrade succeeded."
