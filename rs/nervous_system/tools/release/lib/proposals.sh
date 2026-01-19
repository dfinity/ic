#!/bin/bash

#### Proposal generators

generate_swap_canister_upgrade_proposal_text() {
    local LAST_COMMIT=$1
    local NEXT_COMMIT=$2
    local CANISTER_ID=$3
    local OUTPUT_FILE=${4:-}

    PROPOSER=$(git config user.email | sed 's/@/ at /')

    WASM_GZ=$(download_sns_canister_wasm_gz_for_type "swap" "$NEXT_COMMIT")
    WASM_SHA=$(sha_256 "$WASM_GZ")
    SHORT_NEXT_COMMIT="${NEXT_COMMIT:0:7}"
    CANISTER_TYPE="swap"
    CAPITALIZED_CANISTER_TYPE="Swap"
    LAST_WASM_HASH=$(canister_hash ic $CANISTER_ID)

    IC_REPO=$(repo_root)

    CANISTER_CODE_LOCATION=$(get_sns_canister_code_location swap)
    ESCAPED_IC_REPO=$(printf '%s\n' "$IC_REPO" | sed -e 's/[]\/$*.^[]/\\&/g')
    RELATIVE_CODE_LOCATION=$(echo "$CANISTER_CODE_LOCATION" | sed "s/$ESCAPED_IC_REPO/./g")

    ROOT_CANISTER_ID=$(
        dfx \
            --identity default \
            canister --network ic \
            call ${CANISTER_ID} get_init '(record {})' \
            | idl2json \
            | jq -r ".init[0].sns_root_canister_id"
    )
    SNS_PROJECT_NAME=$(curl -s "https://sns-api.internetcomputer.org/api/v1/snses/$ROOT_CANISTER_ID" | jq -r ".name")

    OUTPUT=$(
        cat <<++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Upgrade the $SNS_PROJECT_NAME $CAPITALIZED_CANISTER_TYPE Canister to Commit $SHORT_NEXT_COMMIT

__Proposer__: ${PROPOSER}

__Source code__: [$NEXT_COMMIT][new-commit]

__New wasm hash__: $WASM_SHA

__Target canister__: [$CANISTER_ID](https://dashboard.internetcomputer.org/canister/$CANISTER_ID)

[new-commit]: https://github.com/dfinity/ic/tree/$NEXT_COMMIT

## Summary

TODO add a summary of changes

## New Commits

\`\`\`
\$ git log --format="%C(auto) %h %s" $LAST_COMMIT..$NEXT_COMMIT --  $RELATIVE_CODE_LOCATION
$(git log --format="%C(auto) %h %s" "$LAST_COMMIT".."$NEXT_COMMIT" -- $CANISTER_CODE_LOCATION)
\`\`\`

## Current Version

__Current git hash__: $LAST_COMMIT

__Current wasm hash__: $LAST_WASM_HASH

## Verification

See the general instructions on [how to verify] proposals like this. A "quick
start" guide is provided here.

[how to verify]: https://github.com/dfinity/ic/tree/${NEXT_COMMIT}/rs/nervous_system/docs/proposal_verification.md

### WASM Verification

See ["Building the code"][prereqs] for prerequisites.

[prereqs]: https://github.com/dfinity/ic/tree/${NEXT_COMMIT}/README.adoc#building-the-code

\`\`\`
# 1. Get a copy of the code.
git clone git@github.com:dfinity/ic.git
cd ic
# Or, if you already have a copy of the ic repo,
git fetch
git checkout $NEXT_COMMIT

# 2. Build canisters.
./ci/container/build-ic.sh -c

# 3. Fingerprint the result.
sha256sum ./artifacts/canisters/$(_canister_download_name_for_sns_canister_type "$CANISTER_TYPE").wasm.gz
\`\`\`

This should match \`wasm_module_hash\` field of this proposal.
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    )

    if [ -z "$OUTPUT_FILE" ]; then
        echo "$OUTPUT"
    else
        echo "$OUTPUT" >"$OUTPUT_FILE"
        echo "File created at $OUTPUT_FILE"
    fi

}

generate_nns_upgrade_proposal_text() {

    local LAST_COMMIT=$1
    local NEXT_COMMIT=$2
    local CANISTER_NAME=$3
    local CANDID_ARGS=${4:-}
    local OUTPUT_FILE=${5:-}

    assert_that_a_prebuilt_nns_wasm_is_available "$CANISTER_NAME" "$NEXT_COMMIT"

    PROPOSER=$(git config user.email | sed 's/@/ at /')

    SHORT_NEXT_COMMIT="${NEXT_COMMIT:0:7}"
    CAPITALIZED_CANISTER_NAME="$(tr '[:lower:]' '[:upper:]' <<<${CANISTER_NAME:0:1})${CANISTER_NAME:1}"

    LAST_WASM_HASH=$(nns_canister_hash ic "$CANISTER_NAME")

    IC_REPO=$(repo_root)

    CANISTER_CODE_LOCATION=$(get_nns_canister_code_location "$CANISTER_NAME")
    ESCAPED_IC_REPO=$(printf '%s\n' "$IC_REPO" | sed -e 's/[]\/$*.^[]/\\&/g')
    RELATIVE_CODE_LOCATION="$(echo "$CANISTER_CODE_LOCATION" | sed "s/$ESCAPED_IC_REPO/./g")"

    # If the canister has an unrelease_changelog.md file, use that to populate
    # the "Features & Fixes" section of the upgrade proposal.
    FEATURES_AND_FIXES="TODO Hand-craft this section."
    PRIMARY_CANISTER_RELATIVE_CODE_LOCATION=$(echo "${RELATIVE_CODE_LOCATION}" | cut -d' ' -f1)
    UNRELEASED_CHANGELOG_RELATIVE_PATH="${PRIMARY_CANISTER_RELATIVE_CODE_LOCATION}/unreleased_changelog.md"
    if [[ -e "${UNRELEASED_CHANGELOG_RELATIVE_PATH}" ]]; then
        FEATURES_AND_FIXES=$(
            git show "${NEXT_COMMIT}:${UNRELEASED_CHANGELOG_RELATIVE_PATH}" \
                | sed -n '/# Next Upgrade Proposal/,$p' \
                | tail -n +3 \
                | filter_out_empty_markdown_sections \
                | increment_markdown_heading_levels
        )
        if [[ -z "${FEATURES_AND_FIXES}" ]]; then
            print_yellow "The unreleased_changelog.md has nothing interesting in it." >&2
            print_yellow 'Therefore, Some hand crafting of "Features & Fixes" will be required.' >&2
            FEATURES_AND_FIXES='TODO Hand-craft this section. unreleased_changelog.md was empty. It might be
that this is just a "maintenance" release; i.e. we are not trying to ship
any behavior changes. Instead, we just want the build in production to not
get too old. One reason to run recent builds is so that the next release
does not have a huge amount of changes in it.'
        fi
    else
        print_yellow "No unreleased_changelog.md found at ${UNRELEASED_CHANGELOG_RELATIVE_PATH} for ${CANISTER_NAME} " >&2
        print_yellow 'The "Features & Fixes" section will need to be written by hand.' >&2
    fi

    ARGS_HASH=""
    if [ ! -z "$CANDID_ARGS" ]; then
        FILE=$(encode_candid_args_in_file "$CANDID_ARGS")
        ARGS_HASH=$(sha_256 "$FILE")
    fi

    OUTPUT=$(
        cat <<++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Upgrade the $CAPITALIZED_CANISTER_NAME Canister to Commit $SHORT_NEXT_COMMIT

__Proposer__: ${PROPOSER}

__Source code__: [$NEXT_COMMIT][new-commit]

[new-commit]: https://github.com/dfinity/ic/tree/$NEXT_COMMIT


## Features & Fixes

TODO: Review this section. In particular, make sure that it matches the "New
Commits" section, and does not contain anything extraneous from previous
proposals. If it seems alright, simply delete this TODO.

$FEATURES_AND_FIXES


## New Commits

\`\`\`
\$ git log --format="%C(auto) %h %s" $LAST_COMMIT..$NEXT_COMMIT --  $RELATIVE_CODE_LOCATION
$(git log --format="%C(auto) %h %s" "$LAST_COMMIT".."$NEXT_COMMIT" -- $CANISTER_CODE_LOCATION)
\`\`\`$(if [ ! -z "$CANDID_ARGS" ]; then
            echo "


## Upgrade Arguments

\`\`\`candid
$CANDID_ARGS
\`\`\`
"
        fi)


## Current Version

__Current git hash__: $LAST_COMMIT

__Current wasm hash__: $LAST_WASM_HASH


## Verification

See the general instructions on [how to verify] proposals like this. A "quick
start" guide is provided here.

[how to verify]: https://github.com/dfinity/ic/tree/${NEXT_COMMIT}/rs/nervous_system/docs/proposal_verification.md


### WASM Verification

See ["Building the code"][prereqs] for prerequisites.

[prereqs]: https://github.com/dfinity/ic/tree/${NEXT_COMMIT}/README.adoc#building-the-code

\`\`\`
# 1. Get a copy of the code.
git clone git@github.com:dfinity/ic.git
cd ic
# Or, if you already have a copy of the ic repo,
git fetch
git checkout $NEXT_COMMIT

# 2. Build canisters.
./ci/container/build-ic.sh -c

# 3. Fingerprint the result.
sha256sum ./artifacts/canisters/$(_canister_download_name_for_nns_canister_type "$CANISTER_NAME").wasm.gz
\`\`\`

This should match \`wasm_module_hash\` field of this proposal.$(if [ ! -z "$CANDID_ARGS" ]; then
            echo "


### Upgrade Arguments Verification

[\`didc\`][latest-didc] is required.

[latest-didc]: https://github.com/dfinity/candid/releases/latest

\`\`\`
didc encode '$CANDID_ARGS' | xxd -r -p | sha256sum

\`\`\`

This should match the \`arg_hash\` field of this proposal.
"
        fi)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    )

    if [ -z "$OUTPUT_FILE" ]; then
        echo "$OUTPUT"
    else
        echo "$OUTPUT" >"$OUTPUT_FILE"
        echo "File created at $OUTPUT_FILE"
    fi

}

generate_sns_bless_wasm_proposal_text() {

    local LAST_COMMIT=$1
    local NEXT_COMMIT=$2
    local CANISTER_TYPE=$3
    local OUTPUT_FILE=${4:-}

    assert_that_a_prebuilt_sns_wasm_is_available "$CANISTER_TYPE" "$NEXT_COMMIT"

    PROPOSER=$(git config user.email | sed 's/@/ at /')

    SHORT_NEXT_COMMIT="${NEXT_COMMIT:0:7}"
    CAPITALIZED_CANISTER_TYPE="$(tr '[:lower:]' '[:upper:]' <<<${CANISTER_TYPE:0:1})${CANISTER_TYPE:1}"

    IC_REPO=$(repo_root)

    CANISTER_CODE_LOCATION=$(get_sns_canister_code_location "$CANISTER_TYPE")
    ESCAPED_IC_REPO=$(printf '%s\n' "$IC_REPO" | sed -e 's/[]\/$*.^[]/\\&/g')
    RELATIVE_CODE_LOCATION="$(echo "$CANISTER_CODE_LOCATION" | sed "s/$ESCAPED_IC_REPO/./g")"

    # If the canister has an unrelease_changelog.md file, use that to populate
    # the "Features & Fixes" section of the proposal.
    FEATURES_AND_FIXES="TODO Hand-craft this section."
    PRIMARY_CANISTER_RELATIVE_CODE_LOCATION=$(echo "${RELATIVE_CODE_LOCATION}" | cut -d' ' -f1)
    UNRELEASED_CHANGELOG_RELATIVE_PATH="${PRIMARY_CANISTER_RELATIVE_CODE_LOCATION}/unreleased_changelog.md"
    if [[ -e "${UNRELEASED_CHANGELOG_RELATIVE_PATH}" ]]; then
        FEATURES_AND_FIXES=$(
            git show "${NEXT_COMMIT}:${UNRELEASED_CHANGELOG_RELATIVE_PATH}" \
                | sed -n '/# Next Upgrade Proposal/,$p' \
                | tail -n +3 \
                | filter_out_empty_markdown_sections \
                | increment_markdown_heading_levels
        )
        if [[ -z "${FEATURES_AND_FIXES}" ]]; then
            print_yellow "The unreleased_changelog.md has nothing interesting in it." >&2
            print_yellow 'Therefore, Some hand crafting of "Features & Fixes" will be required.' >&2
            FEATURES_AND_FIXES='TODO Hand-craft this section. unreleased_changelog.md was empty. It might be
that this is just a "maintenance" release; i.e. we are not trying to ship
any behavior changes. Instead, we just want the build in production to not
get too old. One reason to run recent builds is so that the next release
does not have a huge amount of changes in it.'
        fi
    else
        print_yellow "No unreleased_changelog.md file at ${UNRELEASED_CHANGELOG_RELATIVE_PATH} for ${CANISTER_NAME}." >&2
        print_yellow 'The "Features & Fixes" section will need to be written by hand.' >&2
    fi

    OUTPUT=$(
        cat <<++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Publish SNS $CAPITALIZED_CANISTER_TYPE WASM Built at Commit $SHORT_NEXT_COMMIT

__Proposer__: $PROPOSER

__Source code__: [$NEXT_COMMIT][new-commit]

[new-commit]: https://github.com/dfinity/ic/tree/$NEXT_COMMIT

## Features & Fixes

TODO: Review this section. In particular, make sure that it matches the "New
Commits" section, and does not contain anything extraneous from previous
proposals. If it seems alright, simply delete this TODO.

$FEATURES_AND_FIXES


## New Commits

\`\`\`
\$ git log --format="%C(auto) %h %s" $LAST_COMMIT..$NEXT_COMMIT --  $RELATIVE_CODE_LOCATION
$(git log --format="%C(auto) %h %s" "$LAST_COMMIT".."$NEXT_COMMIT" -- $CANISTER_CODE_LOCATION)
\`\`\`


## Wasm Verification

See the general instructions on [how to verify] proposals like this. A "quick
start" guide is provided here.

[how to verify]: https://github.com/dfinity/ic/tree/${NEXT_COMMIT}/rs/nervous_system/docs/proposal_verification.md

See ["Building the code"][prereqs] for prerequisites.

[prereqs]: https://github.com/dfinity/ic/tree/${NEXT_COMMIT}/README.adoc#building-the-code

\`\`\`
# 1. Get a copy of the code.
git clone git@github.com:dfinity/ic.git
cd ic
# Or, if you already have a copy of the ic repo,
git fetch
git checkout $NEXT_COMMIT

# 2. Build canisters.
./ci/container/build-ic.sh -c

# 3. Fingerprint the result.
sha256sum ./artifacts/canisters/$(_canister_download_name_for_sns_canister_type "$CANISTER_TYPE").wasm.gz
\`\`\`

This should match \`wasm\` field of this proposal.
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    )

    if [ -z "$OUTPUT_FILE" ]; then
        echo "$OUTPUT"
    else
        echo "$OUTPUT" >"$OUTPUT_FILE"
        echo "File created at $OUTPUT_FILE"
    fi

}

generate_versions_from_initial_and_diffs() {
    VERSIONS=()
    for ((c = 1; c <= $#; c++)); do
        VERSIONS+=("${!c}")
    done

    LAST_VERSION=""
    for VERSION in "${VERSIONS[@]}"; do
        if [ "$LAST_VERSION" != "" ]; then
            # Combine the upgrades to emulate the way this will work
            VERSION=$(echo "[$LAST_VERSION, $VERSION]" | jq -cS '.[0] * .[1]')
        else

            VERSION=$(echo $VERSION | jq -cS .)
        fi
        echo $VERSION | jq -c .
        LAST_VERSION=$VERSION
    done
}

generate_insert_custom_upgrade_paths_proposal_text() {
    local SNS_GOVERNANCE_CANISTER_ID=$1
    shift
    VERSIONS=$(generate_versions_from_initial_and_diffs "${@}")

    DESCRIPTION=$([ "$SNS_GOVERNANCE_CANISTER_ID" == "" ] \
        && echo "All SNS upgrade paths (without their own overrides) will be affected by this proposal." \
        || echo "This will only affect the SNS that has the following governance Canister ID: $SNS_GOVERNANCE_CANISTER_ID.")
    DISPLAY_GOVERNANCE_ID=$([ "$SNS_GOVERNANCE_CANISTER_ID" == "" ] && echo "All" || echo "$SNS_GOVERNANCE_CANISTER_ID")
    GOVERNANCE_CANDID_ARG=$([ "$SNS_GOVERNANCE_CANISTER_ID" == "" ] \
        && echo "" \
        || echo "sns_governance_canister_id = opt principal \"$SNS_GOVERNANCE_CANISTER_ID\";")

    LAST_VERSION=""
    OUTPUT=$(
        cat <<EOF
## Proposal to Insert Custom Upgrade Path to SNS-W
### Proposer: DFINITY Foundation
### Target SNS Governance Canister(s): $DISPLAY_GOVERNANCE_ID
---
This proposal will change the upgrade path to use different WASMs that are already available on SNS-W.

$DESCRIPTION

## Rationale

TODO

## Useful background

To see what the upgrade path currently is, run:
\`\`\`
dfx canister --network ic call --candid ic/rs/nns/sns-wasm/canister/sns-wasm.did \\
    qaa6y-5yaaa-aaaaa-aaafa-cai list_upgrade_steps \\
    '(record {limit = 0: nat32; $GOVERNANCE_CANDID_ARG})'
\`\`\`
$(
            [ "$SNS_GOVERNANCE_CANISTER_ID" != "" ] && cat <<EO2

To see the current version the SNS reports to be running:
\`\`\`
dfx canister --network ic \\
        call --candid ic/rs/sns/governance/canister/governance.did \\
        "$SNS_GOVERNANCE_CANISTER_ID" get_running_sns_version "(record{})"
\`\`\`

EO2
        )
## Upgrade Path Changes

$(for VERSION in ${VERSIONS}; do
            echo $VERSION | jq .
            echo
        done)

EOF
    )

    echo "$OUTPUT"
}

##: generate_forum_post_nns_upgrades
## Usage: $1 <proposal_file> (<proposal_file>...)
## Example: $1 directory_with_new_proposals/*
## Example: $1 proposal_1.md proposal_2.md
generate_forum_post_nns_upgrades() {
    if [ $# -eq 0 ]; then
        echo "No proposal files provided"
        exit 1
    fi

    PROPOSAL_FILES=$(ls "$@")

    THIS_FRIDAY=$(date -d "next Friday" +'%Y-%m-%d' 2>/dev/null || date -v+Fri +%Y-%m-%d)

    OUTPUT=$(
        cat <<EOF
The NNS Team submitted the following proposals.  DFINITY plans to vote on these proposals the following Monday.

TODO proposal links

## Additional Notes / Breaking Changes

TODO - delete if nothing relevant

## Proposals to be Submitted

$(for file in $PROPOSAL_FILES; do
            echo "### $(nns_upgrade_proposal_canister_raw_name $file)"
            echo '````'
            cat $file
            echo '````'
            echo
        done)
EOF
    )

    echo "$OUTPUT"
}

##: generate_forum_post_sns_wasm_publish
## Usage: $1 <proposal_file> (<proposal_file>...)
## Example: $1 directory_with_new_proposals/*
## Example: $1 proposal_1.md proposal_2.md
generate_forum_post_sns_wasm_publish() {
    if [ $# -eq 0 ]; then
        echo "No proposal files provided"
        exit 1
    fi

    PROPOSAL_FILES=$(ls "$@")

    THIS_FRIDAY=$(date -d "next Friday" +'%Y-%m-%d' 2>/dev/null || date -v+Fri +%Y-%m-%d)

    OUTPUT=$(
        cat <<EOF
The NNS Team submitted the following proposals to publish new versions of SNS canisters to SNS-WASM.  DFINITY plans to vote on these proposals the following Monday.

TODO proposal links

## Additional Notes / Breaking Changes

TODO - delete if nothing relevant

## Proposals to be Submitted

$(for file in $PROPOSAL_FILES; do
            echo "### $(sns_wasm_publish_proposal_canister_raw_name $file)"
            echo '````'
            cat $file
            echo '````'
            echo
        done)
EOF
    )

    echo "$OUTPUT"
}

#### Helper functions
encode_candid_args_in_file() {
    ARGS=$1
    ENCODED_ARGS_FILE=$(mktemp) || {
        echo "Failed to create temp file" >&2
        return 1
    }

    if ! didc encode "$ARGS" | xxd -r -p >"$ENCODED_ARGS_FILE"; then
        echo "Error: Failed to encode arguments. Do you have didc on your PATH?" >&2
        rm -f "$ENCODED_ARGS_FILE"
        return 1
    fi

    echo "$ENCODED_ARGS_FILE"
}

# Return the candid args when none are passed.
# Usually returns empty string to say "no args passed", but
# In cases where upgrade args are needed, even as a "None", a value must
# be encoded
empty_candid_upgrade_args() {
    CANISTER_NAME=$1

    if [ "$CANISTER_NAME" == "cycles-minting" ]; then
        echo "()"
    fi
    # Empty string means do nothing
    echo ""
}

#### Proposal value extractors (based on common format of proposal elements)

# Extracts "LAST_COMMIT" from string like "git log $LAST_COMMIT..$NEXT_COMMIT" where commits are git commit ids
# Usage extract_previous_version <PROPOSAL_FILE>
extract_previous_version() {
    local FILE=$1
    cat $FILE | grep "git log" | sed 's/.*\([0-9a-f]\{40\}\)\.\.[0-9a-f]\{40\}.*/\1/'
}

# Get the candid args in the proposal, or supply the empty argument to be passed.
extract_candid_upgrade_args() {
    local FILE=$1
    local EXTRACTED=$(cat "$FILE" | sed -n '/```candid/,/```/p' | grep -v '^```')

    if [ -z "$EXTRACTED" ]; then
        empty_candid_upgrade_args "$CANISTER_NAME"
    else
        echo "$EXTRACTED"
    fi
}

# Extracts a proposal header field value if the field title is given.
# Example:
#   For file with line like: "### Some Field: foo"
#   the value of foo can be extracted with "old_proposal_header_field_value <FILE> 'Some Field:'"
# Usage: old_proposal_header_field_value <FILE> <FIELD_NAME>
#
# Deprecated; please use `proposal_canister_id_value` instead.
old_proposal_header_field_value() {
    local FILE=$1
    local FIELD=$2
    cat $FILE | grep "### $FIELD" | sed "s/.*$FIELD[[:space:]]*//"
}

# If the input starts with `[...`, tries to extract the markdown link's display name.
# Otherwise, returns the full input string as-is.
#
# Example 1:
# ```
# extract_first_markdown_link_display_name "[abc](https://dashboard.internetcomputer.org/canister/abc)"
# abc
# ```
#
# Example 2:
# extract_first_markdown_link_display_name "user at dfinity.org"
# user at dfinity.org
# ```
extract_first_markdown_link_display_name() {
    local STRING_POTENTIALLY_WITH_MARKDOWN_LINKS=$1
    FIRST_MARKDOWN_LINK_DISPLAY_NAME=$(printf "$STRING_POTENTIALLY_WITH_MARKDOWN_LINKS" | sed -nre 's/\[([^]]+)\].*/\1/p')
    if [ -z "$FIRST_MARKDOWN_LINK_DISPLAY_NAME" ]; then
        printf "$STRING_POTENTIALLY_WITH_MARKDOWN_LINKS"
    else
        printf "$FIRST_MARKDOWN_LINK_DISPLAY_NAME"
    fi
}

# Extracts a proposal header field value if the field title is given.
# Example:
#   For file with line like: "__Some Field__: foo"
#   the value of foo can be extracted with "proposal_field_value <FILE> 'Some Field:'"
# Usage: proposal_field_value <FILE> <FIELD_NAME>
proposal_field_value() {
    local FILE=$1
    local FIELD=$2
    VALUE=$(cat $FILE | grep "__${FIELD}__" | sed "s/.*__${FIELD}__:[[:space:]]*//")
    if [ -z "$VALUE" ]; then
        echo >&2 "WARNING: Cannot find field '$FIELD' in '$FILE'."
    fi
    extract_first_markdown_link_display_name "$VALUE"
}

nns_upgrade_proposal_canister_raw_name() {
    local FILE=$1
    cat "$FILE" | grep "# Upgrade the" | cut -d' ' -f4
}

sns_wasm_publish_proposal_canister_raw_name() {
    local FILE=$1
    cat "$FILE" | grep "# Publish SNS" | cut -d' ' -f4
}
#### Proposal text validators

validate_no_todos() {
    local PROPOSAL_FILE=$1

    if grep -q -i TODO "$PROPOSAL_FILE"; then
        echo >&2 "Cannot submit proposal with 'TODO' items in text"
        exit 1
    fi
}

validate_nns_canister_id() {
    local CANISTER_NAME=$1
    local EXPECTED_CANISTER_ID=$2

    local CALCULATED_CANISTER_ID=$(nns_canister_id "$CANISTER_NAME")

    if [ "$EXPECTED_CANISTER_ID" != "$CALCULATED_CANISTER_ID" ]; then
        echo "Target canister does not match expected value for named canister in proposal"
        return 1
    fi
}

validate_nns_version_wasm_sha() {
    local CANISTER_TYPE=$1 # Same as CANISTER_NAME for nns canisters
    local VERSION=$2
    local EXPECTED_SHA=$3

    _base_validate_version_wasm_sha \
        $(get_nns_canister_wasm_gz_for_type "$CANISTER_TYPE" "$VERSION") \
        "$EXPECTED_SHA"
}

validate_sns_version_wasm_sha() {
    local CANISTER_TYPE=$1
    local VERSION=$2
    local EXPECTED_SHA=$3

    _base_validate_version_wasm_sha \
        $(download_sns_canister_wasm_gz_for_type "$CANISTER_TYPE" "$VERSION") \
        "$EXPECTED_SHA"
}

_base_validate_version_wasm_sha() {
    local WASM_GZ=$1
    local EXPECTED_SHA=$2

    WASM_SHA=$(sha_256 "$WASM_GZ")

    if [ "$WASM_SHA" != "$EXPECTED_SHA" ]; then
        echo "SHA256 hash for WASM at proposed version does not match hash stated in proposal"
        exit 1
    fi
}

#### User interaction helper for proposals

confirm_submit_proposal_command() {
    print_green "Would you like to run the following command?"
    echo

    # Preview the command.
    first=true
    for arg in "$@"; do
        # Indent, except the first line.
        if [ "$first" == false ]; then
            echo -n '    '
        fi
        first=false

        # Quote arguments (in case there is a space).
        printf '%q \\\n' "$arg" \
            | sed 's~pin=.*~pin=******~'
    done
    echo

    confirm
}
