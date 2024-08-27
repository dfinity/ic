#!/usr/bin/env bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <SNS_CANISTER_TYPE> <TARGET_VERSION> (<OUTPUT_FILE>)
  SNS_CANISTER_TYPE: Canister type to be published (root, governance, ledger, swap, archive, index)
  TARGET_VERSION: Git hash of new version to be published to production
  OUTPUT_FILE: File to write contents to (otherwise stdout is used)

  Environment Variables:
   LAST_PUBLISHED_VERSION: (optional) Git hash of last version published to
    production. If not provided, the script will attempt to read the last
    published version from the metadata of the canister.

  This script will output text for publishing the WASM to SNS-W for a given SNS
  canister. That text should be modified by hand to include any additional
  information that should be in the proposal.
  "
    exit 1
}

if [ $# -lt 2 ]; then
    help
fi

SNS_CANISTER_TYPE=$1
TARGET_VERSION=$2
OUTPUT_FILE=${3:-}
LAST_PUBLISHED_VERSION=${LAST_PUBLISHED_VERSION:-$(sns_mainnet_git_commit_id "$SNS_CANISTER_TYPE")}

IC_ROOT=$(repo_root)

current_branch_has_commit() {
    git branch $(git symbolic-ref --short HEAD) --contains $1 >/dev/null
}

current_branch_has_commit $LAST_PUBLISHED_VERSION || (
    echo "Current branch did not contain last deployed version: $LAST_PUBLISHED_VERSION. Aborting"
    exit 1
)

current_branch_has_commit $TARGET_VERSION || (
    echo "Current branch does not contain target version: $TARGET_VERSION.  Aborting."
    exit 1
)

generate_sns_bless_wasm_proposal_text "$LAST_PUBLISHED_VERSION" "$TARGET_VERSION" "$SNS_CANISTER_TYPE" "$OUTPUT_FILE"
