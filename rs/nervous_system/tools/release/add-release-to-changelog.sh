#!/usr/bin/env bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <PROPOSAL_ID>
    PROPOSAL_ID: The ID of a recently proposed Governance backend canister upgrade proposal.

    Moves the pending new changelog entry from unreleased_changelog.md to CHANGELOG.md.

    The commit that the proposal is baded on MUST be currently check out.
    Otherwise, this script will do nothing, and terminate with a nonzero exit
    status.

" >&2
    exit 1
}

PROPOSAL_ID="${1}"

cd "$(repo_root)"
PWD="$(pwd)"

# Fetch the proposal.
#
# --update is used (even though get_proposal_info is a query method) so that
# the reply is certified by the NNS subnet, rather than being the word of
# whichever single replica happens to answer a query. The title of the reply
# determines which files this script rewrites.
print_cyan "⏳ Fetching proposal ${PROPOSAL_ID}..." >&2
PROPOSAL_INFO=$(
    __dfx --quiet \
        canister call \
        --ic \
        --update \
        --candid rs/nns/governance/canister/governance.did \
        $(nns_canister_id governance) \
        get_proposal_info "(${PROPOSAL_ID})" \
        | idl2json
)
# Unwrap.
LEN=$(echo "${PROPOSAL_INFO}" | jq '. | length')
if [[ "${LEN}" -ne 1 ]]; then
    print_red "💀 Unexpected result from the get_proposal_info method:" >&2
    print_red "Should have one element, but has ${LEN}" >&2
    exit 1
fi
PROPOSAL_INFO=$(echo "${PROPOSAL_INFO}" | jq '.[0]')

# Get proposal creation timestamp.
# It's under proposal_creation_timestamp_seconds on SNS, and proposal_timestamp_seconds on NNS
PROPOSED_TIMESTAMP_SECONDS=$(echo "${PROPOSAL_INFO}" | jq '.proposal_creation_timestamp_seconds // .proposal_timestamp_seconds | tonumber')
if [[ "${PROPOSED_TIMESTAMP_SECONDS}" -eq 0 ]]; then
    print_red "💀 Proposal ${PROPOSAL_ID} exists, but had no proposal_creation_timestamp_seconds." >&2
    exit 1
fi

# Extract which canister was upgraded, and to what commit.
TITLE=$(echo "${PROPOSAL_INFO}" | jq -r '.proposal[0].title[0]')
if grep 'Upgrade the .* Canister to Commit .*' <<<"${TITLE}" &>/dev/null; then
    GOVERNANCE_TYPE='NNS'
    CANISTER_NAME=$(
        echo "${TITLE}" \
            | sed 's/Upgrade the //' | sed 's/ Canister to Commit .*//' \
            | tr '[:upper:]' '[:lower:]'
    )
    DESTINATION_COMMIT_ID=$(echo "${TITLE}" | sed 's/Upgrade the .* Canister to Commit //')
elif grep 'Publish SNS .* WASM Built at Commit .*' <<<"${TITLE}" &>/dev/null; then
    GOVERNANCE_TYPE='SNS'
    CANISTER_NAME=$(
        echo "${TITLE}" \
            | sed 's/Publish SNS //' | sed 's/ WASM Built at Commit .*//' \
            | tr '[:upper:]' '[:lower:]'
    )
    DESTINATION_COMMIT_ID=$(echo "${TITLE}" | sed 's/Publish SNS .* WASM Built at Commit //')
else
    # The title is printed with printf %q, not print_red, because it is
    # untrusted, and print_red uses `echo -e`, which would turn escape
    # sequences in it into terminal control characters.
    print_red "💀 Unable to parse proposal title:" >&2
    printf '%q\n' "${TITLE}" >&2
    print_red "(In particular, unable to determine which canister and commit.)" >&2
    exit 1
fi

# Fail if what was extracted from the (untrusted) title is malformed. This
# must happen before either value is printed with print_* (see above for why);
# offending values are printed with printf %q instead.
#
# Proposal titles contain an abbreviated (7 character) commit ID, but a full
# one is also accepted.
if [[ ! "${CANISTER_NAME}" =~ ^[a-z0-9_-]+$ ]]; then
    print_red "💀 Malformed canister name in proposal title:" >&2
    printf '%q\n' "${CANISTER_NAME}" >&2
    exit 1
fi
if [[ ! "${DESTINATION_COMMIT_ID}" =~ ^[0-9a-f]{7,40}$ ]]; then
    print_red "💀 Malformed commit ID in proposal title:" >&2
    printf '%q\n' "${DESTINATION_COMMIT_ID}" >&2
    exit 1
fi

SECONDS_AGO=$(($(gdate +%s) - ${PROPOSED_TIMESTAMP_SECONDS}))
PROPOSED_ON=$(
    gdate --utc \
        --date=@"${PROPOSED_TIMESTAMP_SECONDS}" \
        --iso-8601
)
print_cyan "🏃 ${GOVERNANCE_TYPE} ${CANISTER_NAME} proposal was submitted ${SECONDS_AGO} seconds ago." >&2

# Fail if the proposal's commit is not checked out. The commit ID is quoted so
# that it is compared literally (as a prefix), not as a glob pattern.
if [[ $(git rev-parse HEAD) != "${DESTINATION_COMMIT_ID}"* ]]; then
    print_red "💀 You currently have $(git rev-parse HEAD)" >&2
    print_red "checked out, but this command only supports being run when" >&2
    print_red "the proposal's commit (${DESTINATION_COMMIT_ID}) is checked out." >&2
    exit 1
fi

# cd to the canister's primary code path.
CANISTER_CODE_PATH=$(
    get_"$(echo "${GOVERNANCE_TYPE}" | tr '[:upper:]' '[:lower:]')"_canister_code_location \
        "${CANISTER_NAME}" \
        | sed "s^${PWD}^.^g" \
        | cut -d' ' -f1
)
cd "${CANISTER_CODE_PATH}"

# Assert that there is a CHANGELOG.md file.
if [[ ! -e CHANGELOG.md ]]; then
    print_red "💀 ${GOVERNANCE_TYPE} ${CANISTER_NAME} has no CHANGELOG.md file." >&2
    exit 1
fi
# TODO: Also verify that unreleased_changelog.md exists.
# TODO: Verify that there are no uncommited changes in this dir, the canister's primary code path.

# Construct new entry for CHANGELOG.md
NEW_FEATURES_AND_FIXES=$(
    sed '1,/^# Next Upgrade Proposal$/d' \
        unreleased_changelog.md \
        | filter_out_empty_markdown_sections
)
if [[ -z "${NEW_FEATURES_AND_FIXES}" ]]; then
    print_red "💀 ${GOVERNANCE_TYPE} ${CANISTER_NAME}'s unreleased_changelog.md is EMPTY." >&2
    exit 1
fi
NEW_ENTRY="# ${PROPOSED_ON}: Proposal ${PROPOSAL_ID}

http://dashboard.internetcomputer.org/proposal/${PROPOSAL_ID}

${NEW_FEATURES_AND_FIXES}
"

CHANGELOG_INTRODUCTION=$(sed -n '/^INSERT NEW RELEASES HERE$/q;p' CHANGELOG.md)
CHANGELOG_EARLIER_RELEASES=$(sed '1,/^INSERT NEW RELEASES HERE$/d' CHANGELOG.md)

# Insert new entry into CHANGELOG.md.
echo -n "${CHANGELOG_INTRODUCTION}


INSERT NEW RELEASES HERE


${NEW_ENTRY}${CHANGELOG_EARLIER_RELEASES}
" \
    >CHANGELOG.md

UNRELEASED_CHANGELOG_INTRODUCTION=$(sed -n '/^# Next Upgrade Proposal$/q;p' unreleased_changelog.md)
echo -n "${UNRELEASED_CHANGELOG_INTRODUCTION}


# Next Upgrade Proposal

## Added

## Changed

## Deprecated

## Removed

## Fixed

## Security
""" \
    >unreleased_changelog.md

print_green '🎉 Success! Added new entry to CHANGELOG.md.' >&2
print_cyan '💡 Run `git diff` to see the changes. If you are pleased, commit,' >&2
print_cyan 'push, request review, and merge them into master, per usual.' >&2
