#!/usr/bin/env bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <COMMIT_ID>
    COMMIT_ID: The commit ID to compare to

    Prints unreleased canister git logs. This indicates which canisters should be
    released.

    If your system is missing some of the CLI tools that I need, you can install those via, e.g.,
    $ cargo install ic-wasm idl2json_cli ...

"
    exit 1
}

RELEASE_CANDIDATE_COMMIT_ID="${1:-GARBAGE}"

if [[ "${RELEASE_CANDIDATE_COMMIT_ID}" == 'GARBAGE' ]]; then
    LATEST_COMMIT_WITH_PREBUILT_ARTIFACTS=$(latest_commit_with_prebuilt_artifacts 2>/dev/null)
    echo
    print_yellow "The latest commit with prebuilt artifacts: ${LATEST_COMMIT_WITH_PREBUILT_ARTIFACTS}"
    help
fi

NETWORK=ic

list_new_canister_commits() {
    CANISTER_NAME="${1}"
    CODE_DIRECTORIES="${2}"
    LATEST_RELEASED_COMMIT_ID="${3}"

    RANGE="${LATEST_RELEASED_COMMIT_ID}..${RELEASE_CANDIDATE_COMMIT_ID}"
    NEW_COMMITS=$(
        git \
            --no-pager \
            log \
            --format="%C(auto) %h %s" \
            "${RANGE}" \
            -- \
            "${CODE_DIRECTORIES}"
    )

    INTERESTING_COMMITS=$(
        grep -v -E ' .{10} (chore|refactor|test)\b' <<< "$NEW_COMMITS" \
        || true
    )

    COMMIT_COUNT=$(grep . <<< "$NEW_COMMITS" | wc -l || true)
    INTERESTING_COMMIT_COUNT=$(grep . <<< "$INTERESTING_COMMITS" | wc -l || true)

    # Compose heading for canister.
    HEADING=$(printf "%-14s" "${CANISTER_NAME}") # Add space padding on right of canister name.
    HEADING="${HEADING} ${COMMIT_COUNT} new commits"
    if [[ "${COMMIT_COUNT}" -gt 0 ]]; then
        if [[ "${INTERESTING_COMMIT_COUNT}" -eq 0 ]]; then
            INTERESTING=NONE
        else
            INTERESTING="${INTERESTING_COMMIT_COUNT}"
        fi
        HEADING="${HEADING}, ${INTERESTING} interesting"
    fi

    # Print heading.
    echo
    if [[ "${INTERESTING_COMMIT_COUNT}" -gt 0 || "${COMMIT_COUNT}" -ge 5 ]]; then
        print_green "${HEADING}"
    else
        print_cyan "${HEADING}"
    fi

    # Print commits.
    if [[ "${INTERESTING_COMMITS}" != "" ]] ; then
        echo "${INTERESTING_COMMITS}"
    fi
}

echo
print_purple NNS
print_purple =====

for CANISTER_NAME in "${NNS_CANISTERS[@]}"; do
    LATEST_RELEASED_COMMIT_ID=$(nns_canister_git_version "${NETWORK}" "${CANISTER_NAME}" 2>/dev/null)
    CODE_DIRECTORIES=$(get_nns_canister_code_location "${CANISTER_NAME}")

    list_new_canister_commits "${CANISTER_NAME}" "${CODE_DIRECTORIES}" "${LATEST_RELEASED_COMMIT_ID}"
done

echo
echo
print_purple SNS
print_purple =====

for CANISTER_NAME in "${SNS_CANISTERS[@]}"; do
    LATEST_RELEASED_COMMIT_ID=$(sns_mainnet_git_commit_id "${CANISTER_NAME}")
    CODE_DIRECTORIES=$(get_sns_canister_code_location "${CANISTER_NAME}")

    list_new_canister_commits "${CANISTER_NAME}" "${CODE_DIRECTORIES}" "${LATEST_RELEASED_COMMIT_ID}"
done
