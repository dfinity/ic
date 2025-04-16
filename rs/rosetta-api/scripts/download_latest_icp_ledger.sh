#!/usr/bin/env bash

set -uo pipefail
#set -x

COMMITS=$(curl -sLf -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/dfinity/ic/commits?per_page=100" \
    | jq '.[].sha' | tr -d \")

if [ "$?" -ne "0" ]; then
    echo >&2 "Unable to fetch the commits from dfinity/ic. Please try again"
    exit 1
fi

for COMMIT in $COMMITS; do
    STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" -L --head \
        "https://download.dfinity.systems/ic/$COMMIT/canisters/ledger-canister_notify-method.wasm.gz")
    if (($STATUS_CODE >= 200)) && (($STATUS_CODE < 300)); then
        echo "Found artifacts for commit $COMMIT. Downloading icp_ledger.did and icp_ledger.wasm.gz"
        curl -sLf "https://raw.githubusercontent.com/dfinity/ic/$COMMIT/rs/ledger_suite/icrc1/ledger/ledger.did" \
            -o icp_ledger.did
        if [ "$?" -ne "0" ]; then
            echo >&2 "Unable to download the ledger did file. Please try again"
            exit 2
        fi
        curl -sLf "https://download.dfinity.systems/ic/$COMMIT/canisters/ledger-canister_notify-method.wasm.gz" \
            -o icp_ledger.wasm.gz
        if [ "$?" -ne "0" ]; then
            echo >&2 "Unable to download the ledger wasm file. Please try again"
            exit 3
        fi
        exit 0
    fi
done

echo "No commits with artifacts found"
exit 4
