#!/usr/bin/env bash

set -euo pipefail

# Set the principal running the experiment.
PRINCIPAL=$(dfx identity get-principal)

NETWORK=local

echo "=== Setting up ICRC1 Index canister benchmark environment ==="

echo "Step 1: creating icrc1-ledger canister..."
# Setting the threshold to a large value to avoid archiving.
dfx deploy icrc1-ledger --network $NETWORK --argument "(variant {
  Init = record {
    token_symbol = \"TEX\";
    token_name = \"Token example\";
    minting_account = record { owner = principal \"$PRINCIPAL\" };
    transfer_fee = 10_000;
    metadata = vec {};
    initial_balances = vec {};
    archive_options = record {
        num_blocks_to_archive = 20_000;
        trigger_threshold = 5_000_000;
        controller_id = principal \"$PRINCIPAL\";
        cycles_for_archive_creation = opt 4_000_000_000_000;
    };
  }
})"
CANISTER_ID_LEDGER=$(dfx canister id icrc1-ledger)
echo "Canister id of ledger is $CANISTER_ID_LEDGER"

echo "Step 2: creating icrc1-index-old canister..."
dfx deploy icrc1-index-old --network $NETWORK --argument "(record {
      ledger_id = principal \"$CANISTER_ID_LEDGER\"
    }
)"
CANISTER_ID_INDEX=$(dfx canister id icrc1-index-old)
echo "Canister id of index is $CANISTER_ID_INDEX"

echo "Step 3: creating icrc1-benchmark-generator canister..."
dfx deploy icrc1-benchmark-generator --network $NETWORK --argument "(record {
      ledger_id = principal \"$CANISTER_ID_LEDGER\";
      index_id = principal \"$CANISTER_ID_INDEX\";
    }
)"
CANISTER_ID_BENCHMARK=$(dfx canister id icrc1-benchmark-generator)
echo "Canister id of benchmark is $CANISTER_ID_BENCHMARK"
echo "Setting benchmark canister as a controller of the index canister..." # required for upgrades.
dfx canister update-settings --add-controller "$CANISTER_ID_BENCHMARK" icrc1-index-old

echo "Step 4: deploy sample worker (for test)"
dfx deploy icrc1-benchmark-worker --network $NETWORK --argument "(record {
      ledger_id = principal \"$CANISTER_ID_LEDGER\";
      rand_seed = 1234;
    }
)"
echo "Generate worker wasm blob"
od -An -tx1 -v .dfx/local/canisters/icrc1-benchmark-worker/icrc1-benchmark-worker.wasm | sed -E "s/[[:space:]]+/\\\/g" | tr -d "\n" | sed '$ s/\\$//' >icrc1-benchmark-worker.wasmblob
echo "Generate worker argument file"
echo -n "(blob \"" >argument-worker.txt
cat icrc1-benchmark-worker.wasmblob >>argument-worker.txt
echo "\")" >>argument-worker.txt
echo "Upload worker canister wasm"
dfx canister call --argument-file argument-worker.txt icrc1-benchmark-generator upload_worker_wasm

echo "Step 5: fabricating cycles for all canisters..."
dfx ledger fabricate-cycles --t 500000 --canister icrc1-ledger
dfx ledger fabricate-cycles --t 500000 --canister icrc1-index-old
dfx ledger fabricate-cycles --t 500000 --canister icrc1-benchmark-generator
dfx ledger fabricate-cycles --t 500000 --canister icrc1-benchmark-worker

echo "Step 6: transferring tokens to benchmark canister..."
dfx canister call icrc1-ledger icrc1_transfer "(record {
    to = record {
        owner = principal \"$CANISTER_ID_BENCHMARK\"
    };
    amount = 500_000_000_0000_0000;
})"

echo "Benchmark environment ready! Launching benchmark..."
dfx canister call icrc1-benchmark-generator run_scenario '(variant {IndexPerf})'
