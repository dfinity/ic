#!/usr/bin/env bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <SNS_GOVERNANCE_CANISTER_ID> <VERSION> <VERSION_DIFF> (<VERSION_DIFF>)
  SNS_GOVERNANCE_CANISTER_ID: SNS Governancce Canister Id used to pinpoint a target SNS
  VERSION: JSON representation of a version ({\"governance_wasm_hash\": \"3b48f008fd8780c90f5061d623cdcbc67209ad89e63139152a255494c046f42b\" ... })
            that includes all 6 hashes.
  VERSION_DIFF: JSON representation like VERSION that only includes the hash that is different from the previous version.

  This script will output text for pushing the upgrade path to SNS-W, in the form of a proposal that can be executed with ./submit-mainnet-insert-upgrade-path-proposal.sh.
  "
    exit 1
}

if [ $# -lt 3 ]; then
    help
fi

IC_ROOT=$(repo_root)

generate_insert_custom_upgrade_paths_proposal_text "${@}"
