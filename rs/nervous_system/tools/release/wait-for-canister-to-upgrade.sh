#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <CANISTER_NAME>
    CANISTER_NAME: E.g. governance, registry, sns-wasm, etc.

  Blocks until the WASM hash (as reported by dfx canister info) changes.
  Prints out the original and new WASM hashes.
  "
    exit 1
}

if [ $# -ne 1 ]; then
    help
fi

CANISTER_NAME=$1

wait_for_nns_canister_has_new_code ic "${CANISTER_NAME}"

# Print some additional information about the canister, which is helpful for confirming that the
# upgrade went well.

GIT_COMMIT_ID="$(nns_canister_git_version ic "${CANISTER_NAME}")"
echo "The git commit ID of the canister is now ${GIT_COMMIT_ID}"

CANISTER_ID="$(nns_canister_id "${CANISTER_NAME}")"
echo "You might want to look at the canister's page in the ICP Dashboard:"
echo "https://dashboard.internetcomputer.org/canister/${CANISTER_ID}"

echo
echo "🚀 Success!"
