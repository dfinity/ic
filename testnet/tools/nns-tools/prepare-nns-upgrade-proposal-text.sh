#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$SCRIPT_DIR/functions.sh"

help() {
    print_green "
Usage: $0 <CANISTER_NAME> <TARGET_VERSION> (<OUTPUT_FILE>)
  CANISTER_NAME: Canister name to be deployed (from rs/nns/canister_ids.json)
  TARGET_VERSION: Git hash of version to be deployed to production
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
OUTPUT_FILE=${3:-}

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

generate_nns_proposal_text "$LAST" "$NEXT" "$CANISTER_NAME" "$OUTPUT_FILE"
