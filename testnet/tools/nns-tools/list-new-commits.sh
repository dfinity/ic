#!/usr/bin/env bash
set -euo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0
  Prints unreleased canister git logs. This indicates which canisters should be
  released.

  TODO: Add support for SNS canisters.
"
    exit 1
}

if [ $# -ne 0 ]; then
    help
fi

# TODO: Let caller override this from the command line.
RELEASE_CANDIDATE_COMMIT_ID=$(latest_commit_with_prebuilt_artifacts 2>/dev/null)
echo "Tip of master:" "$RELEASE_CANDIDATE_COMMIT_ID"

# TODO: Some entries are commented out, because they are not in rs/nns/canister_ids.json.
NNS_CANISTERS=(
    cycles-minting
    governance
    genesis-token
    lifeline
    registry
    root
    sns-wasm
)

for canister_name in "${NNS_CANISTERS[@]}"; do
    echo
    echo Canister: "$canister_name"

    network=ic
    released_commit_id=$(nns_canister_git_version "$network" "$canister_name" 2>/dev/null)
    root=$(get_nns_canister_code_location "$canister_name")
    git log --format="%C(auto) %h %s" "$released_commit_id".."$RELEASE_CANDIDATE_COMMIT_ID" -- $root
done

SNS_CANISTERS=(
    swap
    root
    governance
    ledger
    index
    archive
)

for canister_name in "${SNS_CANISTERS[@]}"; do
    echo
    echo Canister: "$canister_name"

    network=ic
    released_commit_id=$(sns_mainnet_git_commit_id "$canister_name")
    root=$(get_sns_canister_code_location "$canister_name")
    git log --format="%C(auto) %h %s" "$released_commit_id".."$RELEASE_CANDIDATE_COMMIT_ID" -- $root
done
