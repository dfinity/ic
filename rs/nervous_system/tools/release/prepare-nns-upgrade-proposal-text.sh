#!/usr/bin/env bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <CANISTER_NAME> <TARGET_VERSION> (<CANDID_ARGS> <OUTPUT_FILE>)
  CANISTER_NAME: Canister name to be deployed (from rs/nns/canister_ids.json)
  TARGET_VERSION: Git hash of version to be deployed to production
  CANDID_ARGS: Candid string to encode as as initial arguments for the canister. Empty string to ignore
  OUTPUT_FILE: File to write contents to (otherwise stdout is used)

  Environment_variables:
   PREVIOUS_COMMIT: (optional) Git hash of last deployed version for cases when the canister's git version is not
    available in the metadata, or needs to be overridden.

  This script will output text for a proposal to upgrade a given canister.  That text should be modified by hand
  to include any additional information that should be in the proposal.
  "
    exit 1
}

if [ $# -lt 2 ]; then
    help
fi

CANISTER_NAME=$1
NEXT=$2
LAST=${PREVIOUS_COMMIT:-$(nns_canister_git_version ic "$CANISTER_NAME")}
CANDID_ARGS=${3:-}
OUTPUT_FILE=${4:-}

IC_ROOT=$(repo_root)

current_branch_has_commit() {
    git branch $(git symbolic-ref --short HEAD) --contains $1 >/dev/null
}

current_branch_has_commit $LAST || (
    echo "Current branch did not contain last deployed version: $LAST. Aborting"
    exit 1
)

current_branch_has_commit $NEXT || (
    echo "Current branch does not contain target version: $NEXT.  Aborting."
    exit 1
)

if [ "$CANISTER_NAME" == "cycles-minting" -a -z "$CANDID_ARGS" ]; then
    echo "cycles-minting requires upgrade arguments. We recommend setting them to '()', i.e.:"
    echo "$0 $CANISTER_NAME $NEXT '()'"
    exit 1
fi

generate_nns_upgrade_proposal_text "$LAST" "$NEXT" "$CANISTER_NAME" "$CANDID_ARGS" "$OUTPUT_FILE"
