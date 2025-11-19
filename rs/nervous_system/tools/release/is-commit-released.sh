#!/usr/bin/env bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

CANISTER_NAME=$1
QUERY_COMMIT_ID=$2

CANISTER_ID=$(nns_canister_id "$CANISTER_NAME")
echo "Fetching git_commit_id from $CANISTER_NAME ($CANISTER_ID)..."

CURRENT_COMMIT_ID=$(dfx canister --ic metadata "$CANISTER_ID" 'git_commit_id')
echo "$CANISTER_NAME reports itself to be on commit $CURRENT_COMMIT_ID."

# This is in case the commit is not yet in our local repo. This assumes that if
# the commit was released, it is in the GitHub repo. That might not be true in
# the case of hotfixes though.
git fetch origin "$CURRENT_COMMIT_ID"

echo
if git merge-base --is-ancestor "$QUERY_COMMIT_ID" "$CURRENT_COMMIT_ID"; then
    echo "🎉 ${QUERY_COMMIT_ID} is included in the code that $CANISTER_NAME is currently running."
    exit 0
else
    echo "🙅 ${QUERY_COMMIT_ID} is not (yet?) being run by $CANISTER_NAME."
    exit 1
fi
