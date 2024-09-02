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
export DFX_DISABLE_QUERY_VERIFICATION=1 # Query verification fails on dynamic testnets with recovered mainnet NNS state, so disable query verification

dfx identity use "$NNS_TEST_ID"

query_blocks_res=$(dfx canister --network $NNS_URL call --candid "$LEDGER_DID" --query "$LEDGER_CANISTER_ID" query_blocks '(record {start=0:nat64;length=1:nat64})')
BEFORE_CHAIN_LENGTH=$(echo $query_blocks_res | sed -n 's/.*chain_length *= *\([^ ]\+\).*/\1/p' | tr -d '_')
BEFORE_FIRST_BLOCK_INDEX=$(echo $query_blocks_res | sed -n 's/.*first_block_index *= *\([^ ]\+\).*/\1/p' | tr -d '_')

for ((batch = 0; batch < $NUM_OF_BATCHES; batch++)); do
    echo "start sending batch $((batch + 1))/$NUM_OF_BATCHES of $NUM_OF_TRANSFERS_PER_BATCH txs"
    for ((t = 0; t < $NUM_OF_TRANSFERS_PER_BATCH; t++)); do
        dfx canister call --candid "$LEDGER_DID" --network "$NNS_URL" "$LEDGER_CANISTER_ID" icrc1_transfer "(record {to=record {owner=principal \"$LEDGER_CANISTER_ID\"}; amount=$AMOUNT_PER_TRANSFER},)" &
    done
    wait
    echo "done sending batch $((batch + 1))/$NUM_OF_BATCHES of $NUM_OF_TRANSFERS_PER_BATCH txs"
done

query_blocks_res=$(dfx canister --network $NNS_URL call --candid "$LEDGER_DID" --query "$LEDGER_CANISTER_ID" query_blocks '(record {start=0:nat64;length=1:nat64})')
AFTER_CHAIN_LENGTH=$(echo $query_blocks_res | sed -n 's/.*chain_length *= *\([^ ]\+\).*/\1/p' | tr -d '_')
AFTER_FIRST_BLOCK_INDEX=$(echo $query_blocks_res | sed -n 's/.*first_block_index *= *\([^ ]\+\).*/\1/p' | tr -d '_')

DELTA=$(($NUM_OF_BATCHES * $NUM_OF_TRANSFERS_PER_BATCH))
EXPECTED_AFTER_CHAIN_LENGTH=$(($BEFORE_CHAIN_LENGTH + $DELTA))
if (($AFTER_CHAIN_LENGTH < $EXPECTED_AFTER_CHAIN_LENGTH)); then
    echo >&2 "The chain_length should have increased of $DELTA transactions but it is not. before:$BEFORE_CHAIN_LENGTH after:$AFTER_CHAIN_LENGTH"
    exit 2
fi

if [ $BEFORE_FIRST_BLOCK_INDEX -eq $AFTER_FIRST_BLOCK_INDEX ]; then
    echo "Warning: no archival happened"
fi

echo "Transfers test completed successfully!"
