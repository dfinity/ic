#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

help() {
    print_green "
Usage: $0 <VERSION> <SNS_CANISTER_TYPE> (<SNS_CANISTER_TYPE>...)
  VERSION: Version to test (generally git hash, could be build id.  Green checkmarks on GitHub commit list have assets)
  SNS_CANISTER_TYPE: Human readable SNS canister name (root, governance, ledger, swap, archive, index)

  This script will test upgrading the canisters to a particular version, and will test doing so
    in all possible permutations of the upgrades.
  "
    exit 1
}

if [ $# -lt 2 ]; then
    help
fi
VERSION=$1
shift
CANISTERS="${@}"

set_testnet_env_variables

ensure_variable_set IDL2JSON
ensure_variable_set SNS_QUILL
ensure_variable_set IC_ADMIN

ensure_variable_set NNS_URL
ensure_variable_set NEURON_ID
ensure_variable_set WALLET_CANISTER
ensure_variable_set PEM

# Install the sns binary corresponding to the latest NNS Governance canister
SNS_CLI_VERSION=$(nns_canister_git_version "${NNS_URL}" "governance")
install_binary sns "$SNS_CLI_VERSION" "$MY_DOWNLOAD_DIR"

PERMUTATIONS=$(python3 \
    -c 'import itertools,sys;print(*[" ".join(p) for p in itertools.permutations(sys.argv[1:])],sep="\n")' \
    $CANISTERS)

LOG_FILE=$(mktemp)
echo "Log file is $LOG_FILE"

upgrade_nns_governance_to_test_version "${NNS_URL}" "${NEURON_ID}" "${PEM}"

echo "$PERMUTATIONS" | while read -r ORDERING; do

    # Deploy an SNS for upgrade testing with the latest in mainnet
    create_sns_for_upgrade_test $NNS_URL $NEURON_ID $PEM -1

    GOV_CANISTER_ID=$(sns_canister_id_for_sns_canister_type governance)
    SWAP_CANISTER_ID=$(sns_canister_id_for_sns_canister_type swap)

    # Archive is not going to be available for testing in this way because it is spawned after a certain
    # threshold of activity

    for CANISTER in $ORDERING; do
        echo "Uploading $CANISTER WASM to SNS-W" | tee -a $LOG_FILE
        upload_canister_git_version_to_sns_wasm "$NNS_URL" "$NEURON_ID" \
            "$PEM" "$CANISTER" "$VERSION"

        upgrade_sns "$NNS_URL" "$NEURON_ID" "$PEM" \
            "$CANISTER" "$VERSION" "$LOG_FILE" "$SWAP_CANISTER_ID" "$GOV_CANISTER_ID"

        echo "Waiting for upgrade..." | tee -a $LOG_FILE
        if ! wait_for_sns_canister_has_version "$NNS_URL" \
            $(sns_canister_id_for_sns_canister_type $CANISTER) "$CANISTER" "$VERSION"; then
            print_red "Failed upgrade for '$ORDERING' on step upgrading '$CANISTER'" | tee -a $LOG_FILE
            break
        fi

    done

    for CANISTER in $ORDERING; do

        WASM_GZ_FILE=$(download_sns_canister_wasm_gz_for_type "$CANISTER" "$VERSION")

        ORIGINAL_HASH=$(sha_256 "$WASM_GZ_FILE")

        # Re-gzip the WASM to generate an equivalent, file that nevertheless has a different SHA256.
        UNZIPPED=$(ungzip "$WASM_GZ_FILE")
        # This changes the modification time of the file, which is enough to cause re-gzipping to
        # generate a different (but still equivalent) result.
        touch "${UNZIPPED}"
        # gzip explodes when the destination location is already taken. Here, we assume that in such
        # cases, it is just seeing the result of a previous gzip run, and there is no cause for
        # alarm. Hence the ` || true` at the end of this line.
        gzip -S .regz "${UNZIPPED}" || true
        REZIPPED="${UNZIPPED}".regz
        NEW_HASH=$(sha_256 "${REZIPPED}")

        # Verify that re-gzipping had the intended effect. To wit, a different hash.
        if [ "$NEW_HASH" == "$ORIGINAL_HASH" ]; then
            print_red "Hashes were the same, aborting rest of test..."
            break
        fi

        echo "Uploading re-gzipped $CANISTER WASM to SNS-W" | tee -a $LOG_FILE
        upload_wasm_to_sns_wasm "$NNS_URL" "$NEURON_ID" \
            "$PEM" "$CANISTER" "${REZIPPED}"

        upgrade_sns "$NNS_URL" "$NEURON_ID" "$PEM" \
            "$CANISTER" "${REZIPPED}" "$LOG_FILE" "$SWAP_CANISTER_ID" "$GOV_CANISTER_ID"

        if ! wait_for_canister_has_file_contents "$NNS_URL" \
            $(sns_canister_id_for_sns_canister_type $CANISTER) "${REZIPPED}"; then
            print_red "Subsequent upgrade failed."
            print_red "Failed upgrade for '$ORDERING' on step upgrading '$CANISTER'" | tee -a $LOG_FILE
            break
        fi
    done

    print_green "Finished testing 'Upgrade Order: $ORDERING' but check for failures" | tee -a $LOG_FILE
    # Log finished with ordering

done

print_green Testing finished.
echo Test logs recorded in: "$LOG_FILE"
