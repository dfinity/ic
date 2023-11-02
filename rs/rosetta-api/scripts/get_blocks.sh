#!/usr/bin/env bash

# Submit an upgrade proposal to the NNS.

set -euo pipefail
set -x

if (($# != 0)); then
    echo >&2 "Usage: $0"
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$SCRIPT_DIR/constants.sh"

ROSETTA_DATA_DIR_PARENT="$TMP_DIR/rosetta_data"

# the directory used to store the ledger blocks is
# the hash of the ledger and the archive nodes
# concatenated

LEDGER_HASH=$(dfx canister --network "$NNS_URL" info "$LEDGER_CANISTER_ID" | grep hash | awk -Fx '{print $2}' | cut -c-10)
ARCHIVE_HASH=$(dfx canister --network "$NNS_URL" info "$ARCHIVE_CANISTER_ID" | grep hash | awk -Fx '{print $2}' | cut -c-10)
ROSETTA_DATA_DIR="$ROSETTA_DATA_DIR_PARENT/${LEDGER_HASH}_$ARCHIVE_HASH"

rm -rf "$ROSETTA_DATA_DIR"
mkdir -p "$ROSETTA_DATA_DIR"
chmod go+wrx -R "$ROSETTA_DATA_DIR"

docker run \
    --mount type=bind,source="$ROSETTA_DATA_DIR",target=/data \
    --tty \
    --publish 8080:8080 \
    --rm \
    docker.io/dfinity/rosetta-api:latest \
    --exit-on-sync \
    --ic-url "$NNS_URL"

echo "$ROSETTA_DATA_DIR/db.sqlite"
