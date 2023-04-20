#!/usr/bin/env bash
set -euo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <NNS_CANISTER_NAME> (<NETWORK>)
    This script will give you a git diff between the latest version with assets available in S3 against the latest version
    deployed. It can be used to determine if an upgrade proposal should be created.

    NNS_CANISTER_NAME: The human readable canister name (governance, cycles-minting, ledger, root, sns-wasm, registry,
        lifeline, and genesis-token supported)
    NETWORK: The URL of the replica to hit, or 'ic'.  Defaults to 'ic'
    "
}

if [ $# -lt 1 ]; then
    help
    exit 1
fi

NNS_CANISTER_NAME=$1
NETWORK=${2:-ic}

LAST_DEPLOYED_COMMIT=$(nns_canister_git_version "$NETWORK" "$NNS_CANISTER_NAME")
echo >&2 "Deployed version: $LAST_DEPLOYED_COMMIT"

echo >&2 "Finding latest version with assets..."
NEXT_COMMIT_TO_DEPLOY=$(latest_commit_with_prebuilt_artifacts 2>/dev/null)
echo >&2 "Latest with assets: $NEXT_COMMIT_TO_DEPLOY"

CANISTER_CODE_LOCATION=$(get_nns_canister_code_location "$NNS_CANISTER_NAME")

echo >&2 "Commits that could be deployed: "
set -x
git log --format="%C(auto) %h %s" "$LAST_DEPLOYED_COMMIT".."$NEXT_COMMIT_TO_DEPLOY" -- $CANISTER_CODE_LOCATION
