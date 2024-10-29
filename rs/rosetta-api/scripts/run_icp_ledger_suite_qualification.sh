#!/bin/bash
set -euo pipefail
set -x

function help {
    echo >&2 "Usage: $0 <upgrade_commit_id> <downgrade_commit_id>"
}

if (($# != 2)); then
    help
    exit 1
fi

UPGRADE_COMMIT_ID="$1"
DOWNGRADE_COMMIT_ID="$2"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

export CANISTERS=("icp-index" "ledger" "icp-ledger-archive-2" "icp-ledger-archive-1" "icp-ledger-archive")
for canister in ${CANISTERS[@]}; do
    time "$SCRIPT_DIR/run_upgrade_test.sh" "$UPGRADE_COMMIT_ID" "$canister" '()'
done

for ((idx = ${#CANISTERS[@]} - 1; idx >= 0; idx--)); do
    time "$SCRIPT_DIR/run_upgrade_test.sh" "$DOWNGRADE_COMMIT_ID" "${CANISTERS[idx]}" '()'
done
