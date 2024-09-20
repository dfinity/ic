#!/usr/bin/env bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 (<COMMIT_ID>)
    COMMIT_ID: The commit ID to compare to

    Prints unreleased canister git logs. This indicates which canisters should be
    released.

    If your system is missing some of the CLI tools that I need, you can install those via, e.g.,
    $ cargo install ic-wasm idl2json_cli ...

"
    exit 1
}

if [ $# -gt 1 ]; then
    help
fi

LATEST_ARTIFACTS_COMMIT=$(latest_commit_with_prebuilt_artifacts 2>/dev/null)

RELEASE_CANDIDATE_COMMIT_ID=${1:-$LATEST_ARTIFACTS_COMMIT}
echo "Listing commits from:" "$RELEASE_CANDIDATE_COMMIT_ID"

echo NNS
echo =====

for canister_name in "${NNS_CANISTERS[@]}"; do
    echo
    echo Canister: "$canister_name"

    network=ic
    released_commit_id=$(nns_canister_git_version "$network" "$canister_name" 2>/dev/null)
    root=$(get_nns_canister_code_location "$canister_name")
    git --no-pager log --format="%C(auto) %h %s" "$released_commit_id".."$RELEASE_CANDIDATE_COMMIT_ID" -- $root
done

echo
echo
echo SNS
echo =====

for canister_name in "${SNS_CANISTERS[@]}"; do
    echo
    echo Canister: "$canister_name"

    network=ic
    released_commit_id=$(sns_mainnet_git_commit_id "$canister_name")
    root=$(get_sns_canister_code_location "$canister_name")
    git --no-pager log --format="%C(auto) %h %s" "$released_commit_id".."$RELEASE_CANDIDATE_COMMIT_ID" -- $root
done
