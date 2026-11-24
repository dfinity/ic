#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <PROPOSAL_FILE>...
    PROPOSAL_FILE: One or more files with proposals created by
     ./prepare-nns-upgrade-proposal-text.sh or
     ./prepare-publish-sns-wasm-proposal-text.sh (or formatted in that way).
     Each is submitted by submit-mainnet-nns-upgrade-proposal.sh or
     submit-mainnet-publish-sns-wasm-proposal.sh, depending on its title.

  Environment Variables:
   DRY_RUN: If set to true, no proposals will be created, but other than that,
    this script will do as much as it would otherwise.
   NEURON_ID: Your mainnet neuron ID, associated with your HSM. If not set,
    this script asks for it.

  This script first asks for your neuron ID. Then, it shows the proposals, and a
  summary: which commit, and which canisters the proposals are for. If that
  seems right, you enter your HSM PIN (once); otherwise, press Ctrl+C. Then, it
  submits the proposals in the order given, printing one line per proposal. At
  the end, it lists the new proposals.

  All proposals must be for the same commit. If submitting one of the proposals
  fails, the rest are not submitted.
  "
    exit 1
}

if [ $# -lt 1 ]; then
    help
fi

PROPOSAL_FILES=("$@")

NNS_UPGRADE_TITLE_PATTERN='^# Upgrade the (.+) Canister to Commit '
SNS_PUBLISH_TITLE_PATTERN='^# Publish SNS (.+) WASM Built at Commit '

# Step 1: Read and validate all proposal files, before asking for anything.

PROPOSAL_KINDS=()
CANISTER_NAMES=()
VERSIONS=()
DEFECTS=()
for PROPOSAL_FILE in "${PROPOSAL_FILES[@]}"; do
    if [ ! -f "$PROPOSAL_FILE" ]; then
        DEFECTS+=("$PROPOSAL_FILE: file not found.")
        PROPOSAL_KINDS+=("")
        CANISTER_NAMES+=("")
        VERSIONS+=("")
        continue
    fi

    TITLE=$(grep '.' "$PROPOSAL_FILE" | head -n 1 || true)
    if [[ "$TITLE" =~ $NNS_UPGRADE_TITLE_PATTERN ]]; then
        PROPOSAL_KINDS+=("NNS")
        CANISTER_NAMES+=("${BASH_REMATCH[1]}")
    elif [[ "$TITLE" =~ $SNS_PUBLISH_TITLE_PATTERN ]]; then
        PROPOSAL_KINDS+=("SNS")
        CANISTER_NAMES+=("${BASH_REMATCH[1]}")
    else
        DEFECTS+=("$PROPOSAL_FILE: title is neither an NNS canister upgrade nor an SNS WASM publication: $TITLE")
        PROPOSAL_KINDS+=("")
        CANISTER_NAMES+=("")
    fi

    PROPOSAL_VERSION=$(grep '__Source code__: ' "$PROPOSAL_FILE" | sed -E 's~.*\[(.{40})\].*~\1~' || true)
    if [ -z "$PROPOSAL_VERSION" ]; then
        DEFECTS+=("$PROPOSAL_FILE: no commit found (expected a line like '__Source code__: [<commit>]...').")
    fi
    VERSIONS+=("$PROPOSAL_VERSION")

    if grep -q -i TODO "$PROPOSAL_FILE"; then
        DEFECTS+=("$PROPOSAL_FILE: contains TODO.")
    fi
done

# All proposals must be for the same commit. Compare against the first commit
# found (files without one were reported above).
VERSION=""
VERSION_SOURCE_FILE=""
for i in "${!PROPOSAL_FILES[@]}"; do
    if [ -z "${VERSIONS[$i]}" ]; then
        continue
    fi
    if [ -z "$VERSION" ]; then
        VERSION="${VERSIONS[$i]}"
        VERSION_SOURCE_FILE="${PROPOSAL_FILES[$i]}"
        continue
    fi
    if [ "${VERSIONS[$i]}" != "$VERSION" ]; then
        DEFECTS+=("${PROPOSAL_FILES[$i]}: commit ${VERSIONS[$i]} differs from the commit of $VERSION_SOURCE_FILE ($VERSION).")
    fi
done

if [ ${#DEFECTS[@]} -gt 0 ]; then
    print_red "Not submitting anything, because of the following problems:"
    for DEFECT in "${DEFECTS[@]}"; do
        echo "  - $DEFECT"
    done
    exit 1
fi

# Step 2: Get the neuron ID.

NEURON_ID="${NEURON_ID:-}"
if [ -z "$NEURON_ID" ]; then
    prompt "Enter your neuron ID:"
    read -r NEURON_ID
fi
if [[ ! "$NEURON_ID" =~ ^[0-9]+$ ]]; then
    print_red "Neuron ID must be a number, but got '$NEURON_ID'."
    exit 1
fi
echo

# Step 3: Show what is about to be submitted. The user confirms by entering
# their HSM PIN.

list_canisters_of_kind() {
    local KIND=$1
    local IS_ANY_FOUND=false
    for i in "${!PROPOSAL_FILES[@]}"; do
        if [ "${PROPOSAL_KINDS[$i]}" = "$KIND" ]; then
            echo "    ${CANISTER_NAMES[$i]}"
            IS_ANY_FOUND=true
        fi
    done
    if [ "$IS_ANY_FOUND" = false ]; then
        echo "    (none)"
    fi
}

for PROPOSAL_FILE in "${PROPOSAL_FILES[@]}"; do
    echo_line
    echo "$PROPOSAL_FILE"
    echo_line
    cat "$PROPOSAL_FILE"
    echo
done

echo_line
echo "Submitting ${#PROPOSAL_FILES[@]} proposal(s) as neuron $NEURON_ID."
echo
echo "Commit: $VERSION"
echo
echo "NNS canisters to upgrade:"
list_canisters_of_kind NNS
echo
echo "SNS canisters to publish:"
list_canisters_of_kind SNS
echo_line
echo

confirm_by_entering_dfx_hsm_pin
echo

# Step 4: Submit the proposals, one at a time.
#
# Each proposal gets one line of progress. The full output of submitting it
# (synopsis, downloads, ic-admin's messages) is saved to a file, which is only
# shown if submitting fails.

PROPOSAL_IDS=()
for i in "${!PROPOSAL_FILES[@]}"; do
    PROPOSAL_FILE="${PROPOSAL_FILES[$i]}"
    if [ "${PROPOSAL_KINDS[$i]}" = NNS ]; then
        SUBMIT_SCRIPT="$NNS_TOOLS_DIR/submit-mainnet-nns-upgrade-proposal.sh"
    else
        SUBMIT_SCRIPT="$NNS_TOOLS_DIR/submit-mainnet-publish-sns-wasm-proposal.sh"
    fi

    echo -n "($((i + 1))/${#PROPOSAL_FILES[@]}) ${PROPOSAL_KINDS[$i]} ${CANISTER_NAMES[$i]}... "

    SUBMIT_OUTPUT_FILE=$(mktemp -t submit-proposal-output.XXXXXX)
    if ! SKIP_CONFIRMATION=true "$SUBMIT_SCRIPT" "$PROPOSAL_FILE" "$NEURON_ID" >"$SUBMIT_OUTPUT_FILE" 2>&1; then
        print_red "FAILED"
        echo
        cat "$SUBMIT_OUTPUT_FILE"
        echo
        print_red "Not submitting the remaining proposals."
        if [ ${#PROPOSAL_IDS[@]} -gt 0 ]; then
            echo "Proposals already submitted:"
            for j in "${!PROPOSAL_IDS[@]}"; do
                echo "    ${PROPOSAL_KINDS[$j]} ${CANISTER_NAMES[$j]}: https://dashboard.internetcomputer.org/proposal/${PROPOSAL_IDS[$j]}"
            done
        fi
        exit 1
    fi

    PROPOSAL_ID=$(sed -n -E 's|^https://dashboard\.internetcomputer\.org/proposal/([0-9]+)$|\1|p' "$SUBMIT_OUTPUT_FILE" | tail -n 1)
    PROPOSAL_IDS+=("$PROPOSAL_ID")
    if [ "${DRY_RUN:-false}" = true ]; then
        echo "ok (dry run)"
    elif [ -n "$PROPOSAL_ID" ]; then
        echo "proposal $PROPOSAL_ID"
    else
        print_yellow "submitted, but its ID was not found in the output. See $SUBMIT_OUTPUT_FILE"
    fi
done
echo

# Step 5: Summarize.

echo_line
if [ "${DRY_RUN:-false}" = true ]; then
    print_yellow "This was just a dry run. No proposals were created."
    exit 0
fi

echo "Submitted proposals:"
for i in "${!PROPOSAL_FILES[@]}"; do
    PROPOSAL_ID="${PROPOSAL_IDS[$i]}"
    if [ -z "$PROPOSAL_ID" ]; then
        PROPOSAL_ID="(unknown; see the output above)"
    else
        PROPOSAL_ID="https://dashboard.internetcomputer.org/proposal/$PROPOSAL_ID"
    fi
    echo "    ${PROPOSAL_KINDS[$i]} ${CANISTER_NAMES[$i]}: $PROPOSAL_ID"
done
