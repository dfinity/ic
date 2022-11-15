#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$SCRIPT_DIR/functions.sh"

help() {
    echo "
Usage: $0 <LAST_DEPLOYED_VERSION> <TARGET_VERSION> <CANISTER_NAME> (<OUTPUT_FILE>)
  LAST_DEPLOYED_VERSION: Git hash of last version deployed to production
  TARGET_VERSION: Git hash of version to be deployed to production
  CANISTER_NAME: Canister name to be deployed (from rs/nns/canister_ids.json)
  OUTPUT_FILE: File to write contents to (otherwise stdout is used)

  This script will output text for a proposal to upgrade a given canister.  That text should be modified by hand
  to include any additional information that should be in the proposal.
  "
    exit 1
}

if [ $# -lt 3 ]; then
    help
fi

LAST=$1
NEXT=$2
CANISTER_NAME=$3
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

generate_release_notes_template "$LAST" "$NEXT" "$CANISTER_NAME" "$OUTPUT_FILE"
