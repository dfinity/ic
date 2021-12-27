#!/usr/bin/env bash
#
# Functions for setting environment variables for canister Wasm binaries.

set -exuo pipefail

wasm_canister_list=(
    cycles-minting-canister
    genesis-token-canister
    governance-canister
    governance-mem-test-canister
    identity-canister
    inter_canister_error_handling
    json
    ledger-archive-node-canister
    ledger-canister
    ledger-canister_notify-method
    lifeline
    mem-utils-test-canister
    memory-test-canister
    nan_canonicalized
    nns-ui-canister
    panics
    pmap_canister
    registry-canister
    root-canister
    stable
    statesync-test-canister
    test-notified
    time
    upgrade-test-canister
    wasm
)

function export_wasm_canister_paths() {
    CANISTER_DIR=$1

    if [[ -z "${CANISTER_DIR}" || ! -d "${CANISTER_DIR}" ]]; then
        echo "Invalid canister binary directory provided: ${CANISTER_DIR}"
        exit 1
    fi

    ## The following runs something along the lines of
    # export REGISTRY_CANISTER_WASM_PATH=/wasm32-unknown-unknown/release/registry-canister.wasm
    ## for each target wasm canister
    for tgt in "${wasm_canister_list[@]}"; do
        tgt_uppercase=${tgt^^}                 # uppercase target (canister name)
        tgt_underscores=${tgt_uppercase//\-/_} # replace all occurences of '-' with '_'
        tgt_filename="$CANISTER_DIR/$tgt.wasm"
        if [[ -r "$tgt_filename.gz" ]]; then
            gunzip -f "$tgt_filename.gz"
        fi
        if [[ -r "$tgt_filename" ]]; then
            # exports the environment variable if the target canister was compiled
            export "${tgt_underscores}"_WASM_PATH="$tgt_filename"
        else
            echo "ERROR: target canister Wasm binary does not exist: ${tgt_filename}"
        fi
    done
}
