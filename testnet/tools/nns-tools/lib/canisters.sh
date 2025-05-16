#!/bin/bash

##: nns_get_info
## Prints the info for a named NNS canister
## Usage: $1 <NETWORK> <CANISTER_NAME>
##      NETWORK: ic, or URL to an NNS subnet (including port)
##      CANISTER_NAME: human readable canister name (i.e. governance, registry, sns-wasm, etc...)
nns_get_info() {
    local NETWORK=$1
    local CANISTER_NAME=$2

    get_info "$NETWORK" $(nns_canister_id "$CANISTER_NAME")
}

get_info() {
    local NETWORK=$1
    local CANISTER_ID=$2

    __dfx -q canister --network "$NETWORK" info "$CANISTER_ID"
}

nns_canister_hash() {
    local NETWORK=$1
    local CANISTER_NAME=$2

    canister_hash "$NETWORK" $(nns_canister_id "$CANISTER_NAME")
}

canister_hash() {
    local NETWORK=$1
    local CANISTER_ID=$2

    get_info "$NETWORK" "$CANISTER_ID" \
        | grep "Module hash:" \
        | cut -d" " -f3 \
        | sed 's/^0x//'
}

##: nns_canister_git_version
## Gets the git_commit_id from an NNS  canister's metadata if set, looked up by human-friendly name
## Usage: $1 <NETWORK> <CANISTER_NAME>
##      NETWORK: ic, or URL to an NNS subnet (including port)
##      CANISTER_NAME: human readable canister name (i.e. governance, registry, sns-wasm, etc...)
nns_canister_git_version() {
    local NETWORK=$1
    local CANISTER_NAME=$2

    canister_git_version "$NETWORK" $(nns_canister_id "$CANISTER_NAME")
}

##: canister_git_version
## Gets the git_commit_id from the canister's metadata if set
## Usage: $1 <NETWORK> <CANISTER_ID>
##      NETWORK: ic, or URL to an NNS subnet (including port)
##      CANISTER_ID: CanisterId for the canister (a Canister principal)
canister_git_version() {
    local NETWORK=$1
    local CANISTER_ID=$2

    GIT_COMMIT_ID_FROM_METADATA=$(
        __dfx -q canister --network "$NETWORK" metadata "$CANISTER_ID" git_commit_id
    )
    if [ "${GIT_COMMIT_ID_FROM_METADATA}" = "0000000000000000000000000000000000000000" ]; then
        echo >&2 "Looks like the canister ${CANISTER_ID} was built from the tip of this branch."
        GIT_COMMIT_ID=$(git rev-parse HEAD)
        echo >&2 "Taking Git commit ID from the tip of this branch: ${GIT_COMMIT_ID}"
    else
        GIT_COMMIT_ID="${GIT_COMMIT_ID_FROM_METADATA}"
    fi
    echo -n "${GIT_COMMIT_ID}"
}

nns_canister_id() {
    CANISTER_NAME=$1

    IC_REPO=$(repo_root)
    pushd "$IC_REPO/rs/nns" >/dev/null

    cat ./canister_ids.json \
        | jq -er ".[\"$CANISTER_NAME\"].mainnet" \
        | grep -v null

    FOUND=$?

    popd >/dev/null

    return $FOUND
}

##: nns_canister_has_version_installed
## Check if canister has the right version (git commit)
##      NETWORK: ic, or URL to an NNS subnet (including port)
##      CANISTER_NAME: human readable canister name (i.e. governance, registry, sns-wasm, etc...)
##      VERSION: Git hash of expected version
nns_canister_has_version_installed() {
    local NETWORK=$1
    local CANISTER_NAME=$2
    local VERSION=$3

    WASM_GZ=$(get_nns_canister_wasm_gz_for_type "$CANISTER_NAME" "$VERSION")

    nns_canister_has_file_contents_installed "$NETWORK" "$CANISTER_NAME" "$WASM_GZ"
}

canister_has_file_contents_installed() {
    local NETWORK=$1
    local CANISTER_ID=$2
    local WASM_FILE=$3

    echo "Checking if canister $CANISTER_ID is running $WASM_FILE..."

    WASM_HASH=$(sha_256 "$WASM_FILE")
    RUNNING_HASH=$(canister_hash "$NETWORK" "$CANISTER_ID")

    if [ "$WASM_HASH" != "$RUNNING_HASH" ]; then
        echo >&2 "Canister has hash $RUNNING_HASH; expected $WASM_HASH"
        return 1
    fi

    echo >&2 "Canister is running with hash $WASM_HASH as expected"
    return 0
}

canister_has_hash_installed() {
    local NETWORK=$1
    local CANISTER_ID=$2
    local HASH=$3

    echo "Checking if canister $CANISTER_ID is running $HASH..."

    RUNNING_HASH=$(canister_hash "$NETWORK" "$CANISTER_ID")

    if [ "$HASH" != "$RUNNING_HASH" ]; then
        echo >&2 "Canister has hash $RUNNING_HASH; expected $HASH"
        return 1
    fi

    echo >&2 "Canister is running with hash $HASH as expected"
    return 0
}

nns_canister_has_file_contents_installed() {
    local NETWORK=$1
    local CANISTER_NAME=$2
    local WASM_FILE=$3

    echo "Checking if canister $CANISTER_NAME is running $WASM_FILE..."

    WASM_HASH=$(sha_256 "$WASM_FILE")
    RUNNING_HASH=$(nns_canister_hash "$NETWORK" "$CANISTER_NAME")

    if [ "$WASM_HASH" != "$RUNNING_HASH" ]; then
        echo >&2 "Canister has hash $RUNNING_HASH; expected $WASM_HASH"
        return 1
    fi

    echo >&2 "Canister is running with hash $WASM_HASH as expected"
    return 0
}

wait_for_nns_canister_has_version() {
    local NNS_URL=$1
    local CANISTER_NAME=$2
    local VERSION=$3
    WASM_GZ=$(get_nns_canister_wasm_gz_for_type "$CANISTER_NAME" "$VERSION")

    wait_for_nns_canister_has_file_contents "$NNS_URL" "$CANISTER_NAME" "$WASM_GZ"
}

wait_for_nns_canister_has_file_contents() {
    local NNS_URL=$1
    local CANISTER_NAME=$2
    local WASM=$3

    for i in {1..20}; do
        echo "Testing if upgrade was successful..."
        if nns_canister_has_file_contents_installed "$NNS_URL" "$CANISTER_NAME" "$WASM"; then
            print_green "Canister $CANISTER_NAME successfully upgraded."
            return 0
        fi
        sleep 10
    done

    print_red "Canister $CANISTER_NAME upgrade failed"
    return 1
}

wait_for_nns_canister_has_new_code() {
    local NETWORK=$1
    local CANISTER_NAME=$2

    # These might not be consistent, but that is highly unlikely.
    ORIGINAL_WASM_HASH="$(nns_canister_hash ic "${CANISTER_NAME}")"
    OLD_GIT_COMMIT_ID="$(dfx canister --ic metadata "$(nns_canister_id "${CANISTER_NAME}")" git_commit_id)"

    echo "The original WASM hash is"
    echo "  ${ORIGINAL_WASM_HASH}"
    echo "The canister now (self-reports that it is) running code built from git commit ID"
    echo "  ${OLD_GIT_COMMIT_ID}"
    echo "We will now poll until it changes. Please, stand by..."
    echo

    for i in {1..600}; do
        sleep 6
        LATEST_WASM_HASH="$(nns_canister_hash ic "${CANISTER_NAME}")"

        if [[ "${LATEST_WASM_HASH}" != "${ORIGINAL_WASM_HASH}" ]]; then
            echo
            echo "The WASM hash for ${CANISTER_NAME} has changed to"
            echo "  ${LATEST_WASM_HASH}"
            NEW_GIT_COMMIT_ID="$(dfx canister --ic metadata "$(nns_canister_id "${CANISTER_NAME}")" git_commit_id)"
            echo "The canister now (self-reports that it is) running code built from git commit ID"
            echo "  ${NEW_GIT_COMMIT_ID}"
            return
        fi

        echo "No change yet..."
    done

    echo
    echo "Giving up. The canister's WASM hash has not changed after 1 hour."
    return 1
}

reset_nns_canister_version_to_mainnet() {
    local NNS_URL=$1
    local NEURON_ID=$2
    local PEM=$3
    local CANISTER_NAME=$4
    local ENCODED_ARGS_FILE=${5:-}

    VERSION=$(nns_canister_git_version "ic" "${CANISTER_NAME}")
    propose_upgrade_canister_to_version_pem "${NNS_URL}" "${NEURON_ID}" "${PEM}" "${CANISTER_NAME}" "${VERSION}" "${ENCODED_ARGS_FILE}"

    wait_for_nns_canister_has_version "${NNS_URL}" "${CANISTER_NAME}" "${VERSION}"
}
