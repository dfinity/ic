set -eEuo pipefail

DID="$1"
PATCH="$2"
TEST_DID="${DID/.did/_test.did}"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
DID_PATH="${REPO_PATH}/$DID"
PATCH_PATH="${REPO_PATH}/$PATCH"
TEST_DID_TMP_PATH="${DID_PATH/.did/_test.did.tmp}"

echo "DID_PATH: $DID_PATH"
echo "PATCH_PATH: $PATCH_PATH"
echo "TEST_DID_TMP_PATH: $TEST_DID_TMP_PATH"
diff -u "$DID_PATH" "$TEST_DID_TMP_PATH" --label "$DID" --label "$TEST_DID" >"$PATCH_PATH"
rm "$TEST_DID_TMP_PATH"
