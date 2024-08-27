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
NUM_OF_APPROVALS_PER_BATCH=21           # 100 fails for some reason related to the testnet setup
export DFX_DISABLE_QUERY_VERIFICATION=1 # Query verification fails on dynamic testnets with recovered mainnet NNS state, so disable query verification

dfx identity use "$NNS_TEST_ID"

SPENDER_1_PRINCIPAL="pcwbg-y26mf-k62dw-7xo2m-jfv2n-un56b-pjkp7-oirek-obdjm-bklck-2ae"
SPENDER_2_PRINCIPAL="tcpbp-bppbk-ac6zu-smi7p-opmky-qjuez-ugxzv-v33ci-vod7y-kpktd-kae"
SPENDER_3_PRINCIPAL="xnrq6-gadm3-6ious-kx6kn-utuqf-iphoq-vrag4-rlfvt-5z7n7-52n4q-vae"

query_blocks_res=$(dfx canister --network $NNS_URL call --candid "$LEDGER_DID" --query "$LEDGER_CANISTER_ID" query_blocks '(record {start=0:nat64;length=1:nat64})')
BEFORE_CHAIN_LENGTH=$(echo $query_blocks_res | sed -n 's/.*chain_length *= *\([^ ]\+\).*/\1/p' | tr -d '_')
BEFORE_FIRST_BLOCK_INDEX=$(echo $query_blocks_res | sed -n 's/.*first_block_index *= *\([^ ]\+\).*/\1/p' | tr -d '_')

dfx canister call --candid "$LEDGER_DID" --network "$NNS_URL" "$LEDGER_CANISTER_ID" icrc2_approve "(record {spender=record {owner=principal \"$SPENDER_2_PRINCIPAL\"}; amount=200:nat},)"

EXPIRATION=2993656999000000000 # expiration far in the future

for ((batch = 0; batch < $NUM_OF_BATCHES; batch++)); do
    echo "start sending batch $((batch + 1))/$NUM_OF_BATCHES of $NUM_OF_APPROVALS_PER_BATCH txs"
    for ((t = 0; t < $NUM_OF_APPROVALS_PER_BATCH; t++)); do
        case $(($t % 3)) in

            0)
                dfx canister call --candid "$LEDGER_DID" --network "$NNS_URL" "$LEDGER_CANISTER_ID" icrc2_approve "(record {spender=record {owner=principal \"$SPENDER_1_PRINCIPAL\"}; amount=100:nat},)" &
                ;;

            1)
                dfx canister call --candid "$LEDGER_DID" --network "$NNS_URL" "$LEDGER_CANISTER_ID" icrc2_approve "(record {spender=record {owner=principal \"$SPENDER_2_PRINCIPAL\"}; amount=200:nat; expected_allowance=opt 200},)" &
                ;;

            2)
                dfx canister call --candid "$LEDGER_DID" --network "$NNS_URL" "$LEDGER_CANISTER_ID" icrc2_approve "(record {spender=record {owner=principal \"$SPENDER_3_PRINCIPAL\"}; amount=300:nat; expires_at=opt $EXPIRATION},)" &
                let "EXPIRATION += 1"
                ;;

        esac
    done
    wait
    echo "done sending batch $((batch + 1))/$NUM_OF_BATCHES of $NUM_OF_APPROVALS_PER_BATCH txs"
done

query_blocks_res=$(dfx canister --network $NNS_URL call --candid "$LEDGER_DID" --query "$LEDGER_CANISTER_ID" query_blocks '(record {start=0:nat64;length=1:nat64})')
AFTER_CHAIN_LENGTH=$(echo $query_blocks_res | sed -n 's/.*chain_length *= *\([^ ]\+\).*/\1/p' | tr -d '_')
AFTER_FIRST_BLOCK_INDEX=$(echo $query_blocks_res | sed -n 's/.*first_block_index *= *\([^ ]\+\).*/\1/p' | tr -d '_')

DELTA=$(($NUM_OF_BATCHES * $NUM_OF_APPROVALS_PER_BATCH + 1))
EXPECTED_AFTER_CHAIN_LENGTH=$(($BEFORE_CHAIN_LENGTH + $DELTA))
if (($AFTER_CHAIN_LENGTH < $EXPECTED_AFTER_CHAIN_LENGTH)); then
    echo >&2 "The chain_length should have increased of $DELTA transactions but it is not. before:$BEFORE_CHAIN_LENGTH after:$AFTER_CHAIN_LENGTH"
    exit 2
fi

if [ $BEFORE_FIRST_BLOCK_INDEX -eq $AFTER_FIRST_BLOCK_INDEX ]; then
    echo "Warning: no archival happened"
fi

echo "Approval test completed successfully!"
