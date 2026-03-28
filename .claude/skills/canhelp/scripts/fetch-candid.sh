#!/bin/bash
set -euo pipefail

if ! command -v icp &>/dev/null; then
    echo "Error: 'icp' CLI not found. Install it from https://dfinity.github.io/icp-cli" >&2
    exit 1
fi

CANISTER_ID="${1:?Usage: fetch-candid.sh <canister-id>}"
OUT="/tmp/candid_${CANISTER_ID}.did"

icp canister metadata "$CANISTER_ID" candid:service --network ic >"$OUT"
echo "$OUT"
