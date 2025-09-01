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

AUTO_COMMIT_ID=false
if [[ "${RELEASE_CANDIDATE_COMMIT_ID}" == 'GARBAGE' ]]; then
    RELEASE_CANDIDATE_COMMIT_ID=$(latest_commit_with_prebuilt_artifacts 2>/dev/null)
    AUTO_COMMIT_ID=true

    COMMIT_DESCRIPTION=$(git show -s --format="%h (%cd)" --date=relative "${RELEASE_CANDIDATE_COMMIT_ID}")
    echo
    print_yellow "⚠️  Using the latest commit with prebuilt artifacts: ${COMMIT_DESCRIPTION}"
fi

NETWORK=ic

list_new_canister_commits() {
    CANISTER_NAME="${1}"
    # Notice plural. Multiple values are separated by space. Because bash.
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
            ${CODE_DIRECTORIES} # No quote here is necessary, because plural.
    )

    INTERESTING_COMMITS=$(
        grep -v -E ' [0-9a-z]{10,12} (chore|refactor|test|docs)\b' <<<"$NEW_COMMITS" \
            || true
    )

    COMMIT_COUNT=$(grep . <<<"$NEW_COMMITS" | wc -l || true)
    INTERESTING_COMMIT_COUNT=$(grep . <<<"$INTERESTING_COMMITS" | wc -l || true)

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
        print_light_gray "${HEADING}"
    fi

    while IFS= read -r COMMIT_MESSAGE; do
        if echo "$COMMIT_MESSAGE" | grep -v -E ' [0-9a-z]{10,12} (chore|refactor|test|docs)\b' >/dev/null; then
            print_green "${COMMIT_MESSAGE}"
        else
            print_light_gray "${COMMIT_MESSAGE}"
        fi
    done <<<"${NEW_COMMITS}"

}

# Begin main.

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

if [[ "${AUTO_COMMIT_ID}" == true ]]; then
    echo
    echo
    print_yellow "⚠️  Used the latest commit with prebuilt artifacts: ${RELEASE_CANDIDATE_COMMIT_ID}"
fi
