#!/bin/bash

download_sns_canister_wasm_gz_for_type() {
    local CANISTER_TYPE=$1
    local VERSION=$2

    DOWNLOAD_NAME=$(_canister_download_name_for_sns_canister_type "$CANISTER_TYPE")
    WASM_GZ=$(_download_canister_gz "$DOWNLOAD_NAME" "$VERSION")
    echo "$WASM_GZ"
}

get_nns_canister_wasm_gz_for_type() {
    local CANISTER_TYPE=$1
    local VERSION=$2

    DOWNLOAD_NAME=$(_canister_download_name_for_nns_canister_type "$CANISTER_TYPE")
    WASM_GZ=$(_download_canister_gz "$DOWNLOAD_NAME" "$VERSION")
    echo "$WASM_GZ"
}

_download_canister_gz() {
    DOWNLOAD_NAME=$1
    GIT_HASH=$2

    DOWNLOAD_URL="https://download.dfinity.systems/ic/${GIT_HASH}/canisters/${DOWNLOAD_NAME}.wasm.gz"
    OUTPUT_FILE="$MY_DOWNLOAD_DIR/$DOWNLOAD_NAME-$GIT_HASH.wasm.gz"

    curl \
        "${DOWNLOAD_URL}" \
        --output "${OUTPUT_FILE}" \
        --fail \
        --silent

    echo "${OUTPUT_FILE}"
}

_canister_download_name_for_sns_canister_type() {
    local CANISTER_TYPE=$1

    type__root="sns-root-canister"
    type__governance="sns-governance-canister"
    type__ledger="ic-icrc1-ledger"
    type__swap="sns-swap-canister"
    type__archive="ic-icrc1-archive"
    type__index="ic-icrc1-index-ng"

    local INDEX=type__${CANISTER_TYPE}
    echo ${!INDEX}
}

_canister_download_name_for_nns_canister_type() {
    local CANISTER_TYPE=$1

    if [ "$CANISTER_TYPE" == "lifeline" ]; then
        echo "$CANISTER_TYPE"_canister
    elif [ "$CANISTER_TYPE" == "ledger" ]; then
        echo "ledger-canister_notify-method"
    elif [ "$CANISTER_TYPE" == "icp-ledger-archive" ] || [ "$CANISTER_TYPE" == "icp-ledger-archive-1" ]; then
        echo "ledger-archive-node-canister"
    elif [ "$CANISTER_TYPE" == "icp-index" ]; then
        echo "ic-icp-index-canister"
    else
        echo "$CANISTER_TYPE"-canister
    fi
}

ungzip() {
    FILE=$1

    UNZIPPED=$(echo "${FILE}" | sed 's/\.gz//')

    rm -f "$UNZIPPED"
    gzip -d "$FILE" >/dev/null

    if [ $? -gt 0 ]; then
        echo "Could not ungzip the file at $FILE"
        return 1
    fi

    echo "$UNZIPPED"
}
