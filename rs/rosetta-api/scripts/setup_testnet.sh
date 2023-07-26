#!/usr/bin/env bash

# Setup a testnet with the current version and state
# of nns and ledger. Uses your current dfx identity.
#
# Usage: setup_testnet.sh <testnet>
#
# See https://www.notion.so/dfinityorg/How-to-upgrade-the-ICP-ledger-on-a-testnet-798eb588363f46a080ea1110e34772d9?pvs=4

set -euo pipefail
#set -x

if (($# != 1)); then
    echo >&2 "Usage: $0 <test_net>"
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
TEST_NET="$1"
PAGE='http://[2001:1900:2100:2827:6801:e7ff:feeb:50ec]:8080/_/dashboard'
TEMP_DIR="$SCRIPT_DIR/tmp" # need a persistent directory from within dev container
INFO_FILE="$TEMP_DIR/$TEST_NET.sourceme"

mkdir -p "$TEMP_DIR"
rm -rf "$INFO_FILE"
#shellcheck source=/dev/null
source "$SCRIPT_DIR/init_identity.sh"
init_identity # initialize the dfx identity
principal="$(dfx identity get-principal)"
pem_file="$HOME/.config/dfx/identity/$(dfx identity whoami)/identity.pem"
replica_version=$(curl "$PAGE" | tr -d '\n' | sed -nE 's#.*Replica Version<[^<]*<[^>]*>([^<]+).*#\1#gp')
echo "replica_version: $replica_version"
echo "export REPLICA_VERSION=$replica_version" >>"$INFO_FILE"
echo "export TEST_NET=$TEST_NET" >>"$INFO_FILE"
"$SCRIPT_DIR/../../../testnet/tools/nns_state_deployment.sh" "$TEST_NET" "$replica_version" "$principal" "$pem_file" | tee >(grep "^export" >>"$INFO_FILE")
