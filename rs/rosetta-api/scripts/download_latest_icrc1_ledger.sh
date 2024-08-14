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
        "https://download.dfinity.systems/ic/$COMMIT/canisters/ic-icrc1-ledger.wasm.gz")
    if (($STATUS_CODE >= 200)) && (($STATUS_CODE < 300)); then
        echo "Found artifacts for commit $COMMIT. Downloading icrc1_ledger.did and icrc1_ledger.wasm.gz"
        curl -sLf "https://raw.githubusercontent.com/dfinity/ic/$COMMIT/rs/rosetta-api/icrc1/ledger/ledger.did" \
            -o icrc1_ledger.did
        if [ "$?" -ne "0" ]; then
            echo >&2 "Unable to download the icrc1 ledger did file. Please try again"
            exit 2
        fi
        curl -sLf "https://download.dfinity.systems/ic/$COMMIT/canisters/ic-icrc1-ledger.wasm.gz" \
            -o icrc1_ledger.wasm.gz
        if [ "$?" -ne "0" ]; then
            echo >&2 "Unable to download the icrc1 ledger wasm file. Please try again"
            exit 3
        fi
        exit 0
    fi
done

echo "No commits with artifacts found"
exit 4
