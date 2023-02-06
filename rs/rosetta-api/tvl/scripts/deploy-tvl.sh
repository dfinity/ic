#!/usr/bin/env bash

set -euo pipefail

NETWORK=local

echo "=== Setting up TVL environment ==="

## The default canister id of governance on NNS.
#CANISTER_ID_GOVERNANCE=rrkah-fqaaa-aaaaa-aaaaq-cai
dfx nns import
CANISTER_ID_GOVERNANCE=$(dfx canister id nns-governance)

echo "Deploying XRC canister..."
dfx deploy xrc
CANISTER_ID_XRC=$(dfx canister id xrc)
echo "Deployed XRC canister at: $CANISTER_ID_XRC"

echo "Deploying TVL canister..."
# TIP: update_period below 60 is useless since XRC canister min period is 60 seconds.
dfx deploy tvl --network $NETWORK --with-cycles 10000000000000 --argument "(record {
    governance_id = principal \"$CANISTER_ID_GOVERNANCE\";
    xrc_id = principal \"$CANISTER_ID_XRC\";
    update_period = 60;
})"
CANISTER_ID_TVL=$(dfx canister id tvl)
echo "Deployed TVL canister at: $CANISTER_ID_TVL"

echo "=== Testing TVL usage ==="

./call.sh
