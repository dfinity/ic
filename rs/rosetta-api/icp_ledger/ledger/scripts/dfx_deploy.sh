#!/bin/bash

# This script is supposed to be run only through Bazel: bazel run //rs/rosetta-api/icp_ledger/ledger/scripts:dfx_deploy
# It deploys the icp_ledger_canister canister with the specified arguments

# Check if necessary environment variables are set
if [[ -z "$MINTER_ACCOUNT_ID" ]]; then
    echo "Error: MINTER_ACCOUNT_ID environment variable is not set"
    exit 1
fi

if [[ -z "$DEFAULT_ACCOUNT_ID" ]]; then
    echo "Error: DEFAULT_ACCOUNT_ID environment variable is not set"
    exit 1
fi

# Check if dfx is installed
if ! command -v dfx &>/dev/null; then
    echo "Error: dfx is not installed"
    exit 1
fi

# Check if a local replica is running
if ! dfx ping &>/dev/null; then
    echo "Error: Local replica is not running"
    exit 1
fi

base_dir=$(pwd)
dir="$base_dir/rs/rosetta-api/icp_ledger/ledger"

cd $dir

# Force-delete file .dfx/local/canisters/icp_ledger_canister/icp_ledger_canister.wasm.gz if it exists.
# At the moment this file is somehow immutable (no write permissions) and can't be overwritten by dfx deploy.
rm -f .dfx/local/canisters/icp_ledger_canister/icp_ledger_canister.wasm.gz

canister_id="ryjl3-tyaaa-aaaaa-aaaba-cai"

# Check if canister is already installed. If so, stop and delete it.
if dfx canister status $canister_id &>/dev/null; then
    echo "Canister icp_ledger_canister is already installed. Stopping and deleting..."
    dfx canister stop $canister_id
    dfx canister delete --no-withdrawal $canister_id
fi

echo "Deploying icp_ledger_canister with the following arguments:"
echo "  MINTER_ACCOUNT_ID: $MINTER_ACCOUNT_ID"
echo "  DEFAULT_ACCOUNT_ID: $DEFAULT_ACCOUNT_ID"
echo "In directory: $dir $RUNFILES_DIR"

command="dfx --verbose deploy --mode auto --specified-id ryjl3-tyaaa-aaaaa-aaaba-cai icp_ledger_canister --argument \"
    (variant {
        Init = record {
            minting_account = \\\"$MINTER_ACCOUNT_ID\\\";
            initial_values = vec {
                record {
                    \\\"$DEFAULT_ACCOUNT_ID\\\";
                    record {
                        e8s = 10_000_000_000 : nat64;
                    };
                };
            };
            send_whitelist = vec {};
            transfer_fee = opt record {
                e8s = 10_000 : nat64;
            };
            token_symbol = opt \\\"LICP\\\";
            token_name = opt \\\"Local ICP\\\";
        }
    })
\""

echo "Command: $command"
eval $command

cd $base_dir
