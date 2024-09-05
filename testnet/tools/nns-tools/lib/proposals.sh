#!/bin/bash

#### Proposal generators

generate_sale_canister_upgrade_proposal_text() {
    local LAST_COMMIT=$1
    local NEXT_COMMIT=$2
    local CANISTER_ID=$3
    local OUTPUT_FILE=${4:-}

    WASM_GZ=$(download_sns_canister_wasm_gz_for_type "swap" "$NEXT_COMMIT")
    WASM_SHA=$(sha_256 "$WASM_GZ")
    CAPITALIZED_CANISTER_NAME="Swap"
    LAST_WASM_HASH=$(canister_hash ic $CANISTER_ID)

    IC_REPO=$(repo_root)

    CANISTER_CODE_LOCATION=$(get_sns_canister_code_location swap)
    ESCAPED_IC_REPO=$(printf '%s\n' "$IC_REPO" | sed -e 's/[]\/$*.^[]/\\&/g')
    RELATIVE_CODE_LOCATION=$(echo "$CANISTER_CODE_LOCATION" | sed "s/$ESCAPED_IC_REPO/./g")

    OUTPUT=$(
        cat <<EOF
## Proposal to Upgrade the Sale Canister for TODO
### Proposer: DFINITY Foundation
### Git Hash: $NEXT_COMMIT
### New Wasm Hash: $WASM_SHA
### Target canister: $CANISTER_ID
---
## Features
TODO ADD FEATURE NOTES
## Release Notes
\`\`\`
\$ git log --format="%C(auto) %h %s" $LAST_COMMIT..$NEXT_COMMIT --  $RELATIVE_CODE_LOCATION
$(git log --format="%C(auto) %h %s" "$LAST_COMMIT".."$NEXT_COMMIT" -- "$CANISTER_CODE_LOCATION")
\`\`\`
## Wasm Verification
Verify that the hash of the gzipped WASM matches the proposed hash.
\`\`\`
git fetch
git checkout $NEXT_COMMIT
./gitlab-ci/container/build-ic.sh -c
sha256sum ./artifacts/canisters/$(_canister_download_name_for_sns_canister_type swap).wasm.gz
\`\`\`
## Current Version
- Current Git Hash: $LAST_COMMIT
- Current Wasm Hash: $LAST_WASM_HASH
EOF
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

    ARGS_HASH=""
    if [ ! -z "$CANDID_ARGS" ]; then
        FILE=$(encode_candid_args_in_file "$CANDID_ARGS")
        ARGS_HASH=$(sha_256 "$FILE")
    fi

    OUTPUT=$(
        cat <<++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Upgrade the $CAPITALIZED_CANISTER_NAME Canister to Commit $SHORT_NEXT_COMMIT

__Proposer__: ${PROPOSER}\\
__Source Code__: [$NEXT_COMMIT][new-commit]

[new-commit]: https://github.com/dfinity/ic/tree/$NEXT_COMMIT


## Features, Fixes, and Optimizations

TODO TO BE FILLED OUT BY THE PROPOSER


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

- Current Git Hash: $LAST_COMMIT
- Current Wasm Hash: $LAST_WASM_HASH


## WASM Verification

See ["Building the code"][prereqs] for prerequisites.

[prereqs]: https://github.com/dfinity/ic?tab=readme-ov-file#building-the-code

\`\`\`
# 1. Get a copy of the code.
git clone git@github.com:dfinity/ic.git
cd ic
# Or, if you already have a copy of the ic repo,
git fetch
git checkout $NEXT_COMMIT

# 2. Build canisters.
./gitlab-ci/container/build-ic.sh -c

# 3. Fingerprint the result.
sha256sum ./artifacts/canisters/$(_canister_download_name_for_nns_canister_type "$CANISTER_NAME").wasm.gz
\`\`\`

This should match \`wasm_module_hash\` field of this proposal.$(if [ ! -z "$CANDID_ARGS" ]; then
            echo "


## Upgrade Arguments Verification

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

    OUTPUT=$(
        cat <<++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Publish SNS $CAPITALIZED_CANISTER_TYPE WASM Built at Commit $SHORT_NEXT_COMMIT

__Proposer__: $PROPOSER\\
__Source Code__: [$NEXT_COMMIT][new-commit]

[new-commit]: https://github.com/dfinity/ic/tree/$NEXT_COMMIT


## Features, Fixes, and Optimizations

TODO TO BE FILLED OUT BY THE PROPOSER


## New Commits

\`\`\`
\$ git log --format="%C(auto) %h %s" $LAST_COMMIT..$NEXT_COMMIT --  $RELATIVE_CODE_LOCATION
$(git log --format="%C(auto) %h %s" "$LAST_COMMIT".."$NEXT_COMMIT" -- $CANISTER_CODE_LOCATION)
\`\`\`


## Wasm Verification

See ["Building the code"][prereqs] for prerequisites.

[prereqs]: https://github.com/dfinity/ic?tab=readme-ov-file#building-the-code

\`\`\`
# 1. Get a copy of the code.
git clone git@github.com:dfinity/ic.git
cd ic
# Or, if you already have a copy of the ic repo,
git fetch
git checkout $NEXT_COMMIT

# 2. Build canisters.
./gitlab-ci/container/build-ic.sh -c

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
    PROPOSAL_FILES=$(ls "$@")

    THIS_FRIDAY=$(date -d "next Friday" +'%Y-%m-%d' 2>/dev/null || date -v+Fri +%Y-%m-%d)

    OUTPUT=$(
        cat <<EOF
The NNS Team will be submitting the following upgrade proposals this Friday, $THIS_FRIDAY.  DFINITY plans to vote on these proposals the following Monday.

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
    PROPOSAL_FILES=$(ls "$@")

    THIS_FRIDAY=$(date -d "next Friday" +'%Y-%m-%d' 2>/dev/null || date -v+Fri +%Y-%m-%d)

    OUTPUT=$(
        cat <<EOF
The NNS Team will be submitting the following proposals to publish new versions of SNS canisters to SNS-WASM this Friday, $THIS_FRIDAY.  DFINITY plans to vote on these proposals the following Monday.

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
    ENCODED_ARGS_FILE=$(mktemp)
    didc encode \
        "$ARGS" \
        | xxd -r -p >"$ENCODED_ARGS_FILE"

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
#   the value of foo can be extracted with "proposal_header_field_value <FILE> 'Some Field:'"
# Usage: proposal_header_field_value <FILE> <FIELD_NAME>
proposal_header_field_value() {
    local FILE=$1
    local FIELD=$2
    cat $FILE | grep "### $FIELD" | sed "s/.*$FIELD[[:space:]]*//"
}

nns_upgrade_proposal_canister_raw_name() {
    local FILE=$1
    cat "$FILE" | grep "## Proposal to Upgrade the" | cut -d' ' -f6
}

sns_wasm_publish_proposal_canister_raw_name() {
    local FILE=$1
    cat "$FILE" | grep "## Proposal to Publish the SNS" | cut -d' ' -f7
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
