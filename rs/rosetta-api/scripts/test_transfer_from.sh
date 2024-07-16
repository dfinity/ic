#!/usr/bin/env bash

# Submit an upgrade proposal to the NNS.

set -euo pipefail
#set -x

if (($# != 0)); then
    echo >&2 "Usage: $0"
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$SCRIPT_DIR/constants.sh"

NUM_OF_BATCHES=50
NUM_OF_TRANSFERS_PER_BATCH=20 # 100 fails for some reason related to the testnet setup
AMOUNT_PER_TRANSFER="1:nat"
AMOUNT_PER_APPROVAL="1000000000:nat"
export DFX_DISABLE_QUERY_VERIFICATION=1 # Query verification fails on dynamic testnets with recovered mainnet NNS state, so disable query verification

dfx identity use "$NNS_TEST_ID"
NNS_TEST_PRINCIPAL=$(dfx identity get-principal)

query_blocks_res=$(dfx canister --network $NNS_URL call --candid "$LEDGER_DID" --query "$LEDGER_CANISTER_ID" query_blocks '(record {start=0:nat64;length=1:nat64})')
BEFORE_CHAIN_LENGTH=$(echo $query_blocks_res | sed -n 's/.*chain_length *= *\([^ ]\+\).*/\1/p' | tr -d '_')
BEFORE_FIRST_BLOCK_INDEX=$(echo $query_blocks_res | sed -n 's/.*first_block_index *= *\([^ ]\+\).*/\1/p' | tr -d '_')

SPENDER_ID="spender_id"
SPENDER_ID_HOME_DIR="$DFX_HOME/.config/dfx/identity/$SPENDER_ID"

if [ -d "$SPENDER_ID_HOME_DIR" ]; then
    echo "Found $SPENDER_ID identity in $SPENDER_ID_HOME_DIR"
else
    echo "No identity directory found, I'm going to create a new $SPENDER_ID identity and persist it"
    dfx identity new "$SPENDER_ID" --disable-encryption
fi
dfx identity use "$SPENDER_ID"
SPENDER_PRINCIPAL=$(dfx identity get-principal)

dfx identity use "$NNS_TEST_ID"
dfx canister call --candid "$LEDGER_DID" --network "$NNS_URL" "$LEDGER_CANISTER_ID" icrc2_approve "(record {spender=record {owner=principal \"$SPENDER_PRINCIPAL\"}; amount=$AMOUNT_PER_APPROVAL},)"

dfx identity use "$SPENDER_ID"

for ((batch = 0; batch < $NUM_OF_BATCHES; batch++)); do
    echo "start sending batch $((batch + 1))/$NUM_OF_BATCHES of $NUM_OF_TRANSFERS_PER_BATCH txs"
    for ((t = 0; t < $NUM_OF_TRANSFERS_PER_BATCH; t++)); do
        dfx canister call --candid "$LEDGER_DID" --network "$NNS_URL" "$LEDGER_CANISTER_ID" icrc2_transfer_from "(record {from=record {owner=principal \"$NNS_TEST_PRINCIPAL\"}; to=record {owner=principal \"$SPENDER_PRINCIPAL\"}; amount=$AMOUNT_PER_TRANSFER},)" &
    done
    wait
    echo "done sending batch $((batch + 1))/$NUM_OF_BATCHES of $NUM_OF_TRANSFERS_PER_BATCH txs"
done

query_blocks_res=$(dfx canister --network $NNS_URL call --candid "$LEDGER_DID" --query "$LEDGER_CANISTER_ID" query_blocks '(record {start=0:nat64;length=1:nat64})')
AFTER_CHAIN_LENGTH=$(echo $query_blocks_res | sed -n 's/.*chain_length *= *\([^ ]\+\).*/\1/p' | tr -d '_')
AFTER_FIRST_BLOCK_INDEX=$(echo $query_blocks_res | sed -n 's/.*first_block_index *= *\([^ ]\+\).*/\1/p' | tr -d '_')

DELTA=$(($NUM_OF_BATCHES * $NUM_OF_TRANSFERS_PER_BATCH + 1))
EXPECTED_AFTER_CHAIN_LENGTH=$(($BEFORE_CHAIN_LENGTH + $DELTA))
if (($AFTER_CHAIN_LENGTH < $EXPECTED_AFTER_CHAIN_LENGTH)); then
    echo >&2 "The chain_length should have increased of $DELTA transactions but it is not. before:$BEFORE_CHAIN_LENGTH after:$AFTER_CHAIN_LENGTH"
    exit 2
fi

if [ $BEFORE_FIRST_BLOCK_INDEX -eq $AFTER_FIRST_BLOCK_INDEX ]; then
    echo "Warning: no archival happened"
fi

echo "Transfers from test completed successfully!"
