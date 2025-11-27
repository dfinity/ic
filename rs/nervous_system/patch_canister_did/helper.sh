#!/bin/bash

# Helper script for editing the patch file for a candid file of a test canister. In most cases, the
# _test.did.patch file can be edited directly. However, in some cases, editing the patch file
# manually might be less straightforward, especially if the main .did file has some changes around
# the diff. In those cases, this script makes it easier to edit the patch file, by generating the
# _test.did file (`--generate-test-did`), allowing the user to edit the _test.did file, and then
# allow the user to update the patch file based on the new _test.did file (`--update-patch`).

set -eEuo pipefail

REPO_PATH="$(git rev-parse --show-toplevel)"
DID="$1"
PATCH="$2"
TEST_DID="${DID/.did/_test.did}"
DID_PATH="${REPO_PATH}/${DID}"
PATCH_PATH="${REPO_PATH}/${PATCH}"
TEST_DID_PATH="${REPO_PATH}/${TEST_DID}"
TEST_DID_TEMP_PATH="${REPO_PATH}/${TEST_DID}.tmp"

if [ "$3" == "--generate-test-did" ]; then
    DID_TEMP_FILE=$(mktemp -t did.XXXXXX)
    PATCH_TEMP_FILE=$(mktemp -t patch.XXXXXX)
    trap "rm -f $DID_TEMP_FILE $PATCH_TEMP_FILE" EXIT
    GIT_BASE=${GIT_BASE:-master}
    echo "Using GIT_BASE=$GIT_BASE for generating $TEST_DID_TEMP_PATH"
    if ! git show $GIT_BASE:$DID >$DID_TEMP_FILE; then
        echo "Error: $DID does not exist in $GIT_BASE. Check your candid_test_did configuration."
        exit 1
    fi
    if ! git show $GIT_BASE:$PATCH >$PATCH_TEMP_FILE; then
        echo "Error: $PATCH does not exist in $GIT_BASE. Consider use a different GIT_BASE."
        exit 1
    fi

    if ! patch "$DID_TEMP_FILE" -i "$PATCH_TEMP_FILE" -o "$TEST_DID_TEMP_PATH"; then
        echo "Error: Failed to patch $DID_TEMP_FILE with $PATCH_TEMP_FILE Consider use a different GIT_BASE."
        exit 1
    fi
    echo "Generated $TEST_DID_TEMP_PATH, please edit and run again with \`bazel run ${TARGET_BASE_NAME}_update_patch\`"
elif [ "$3" == "--update-patch" ]; then
    if [ ! -f $DID_PATH ]; then
        echo "Error: $DID_PATH does not exist. Check your candid_test_did configuration."
        exit 1
    fi
    if [ ! -f "$TEST_DID_TEMP_PATH" ]; then
        echo "Error: $TEST_DID_TEMP_PATH does not exist, please run again with \`bazel run ${TARGET_BASE_NAME}_generate_test_did\`"
        exit 1
    fi

    # The `diff` exit code is 1 if the files are different, and we want to ignore that.
    diff -u "$DID_PATH" "$TEST_DID_TEMP_PATH" --label "$DID" --label "$TEST_DID" >"$PATCH_PATH" || true
    echo "Updated $PATCH_PATH, removing the temporary file $TEST_DID_TEMP_PATH"
    rm "$TEST_DID_TEMP_PATH"
else
    echo "Invalid argument: $3"
    exit 1
fi
