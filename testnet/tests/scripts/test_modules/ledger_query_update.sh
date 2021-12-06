#!/usr/bin/env bash

# scenario test script module.
# Name: ledger_query_update
# Args: <testnet_identifier> <duration> <tps> <experiment_dir> <test_account_id>
# Roughly speaking, this script:
# - queries the balances on the ledger canister installed on the nns subnet
# - updates the balances on the ledger canister
# Passing criteria:
# - this script uses single source account to transfer e8s to 10 different target accounts
# - script queries source account balance at the beginning, keeps it in initial_source_account_balance
#   and queries source account balance at the end, keeps it in post_source_account_balance
# - script keeps track of all transfers being made and aggregate them to an expected_delta for verification
# - script calculates actual_delta of source account before and after all transfer transactions, and
#   compares it with expected_delta to verify that the difference is within 0.1%

set -eEuo pipefail

if (($# != 5)); then
    echo >&2 "ERROR: Wrong number of arguments, please provide values for <testnet_identifier> <duration> <tps> <experiment_dir> <test_account_id>"
    exit 1
fi

testnet="$1"
duration="$2"
tps="$3"
experiment_dir="$4"
test_account_id="$5"

REPO_ROOT="$(git rev-parse --show-toplevel)"
PROD_SRC=${PROD_SRC:-$REPO_ROOT/testnet}
TEST_MODULES=${TEST_MODULES:-$PROD_SRC/tests/scripts/test_modules}
hosts_file_path="$PROD_SRC/env/$testnet/hosts"

# ledger canister_id on the testnet
ledger="ryjl3-tyaaa-aaaaa-aaaba-cai"

# Introduce a number of Account IDs
AccountIDs=("1d0a7a837ab90e2a26557f0fe96e5e24e033dcdecf9c9be3bd690bacef1c80ed"
    "a6b3c860b5d9e5c7260130c1ba7b6ab14102b8a7e3a343618a1083eb94741218"
    "634fc6a7f7082f0c5ee1fc1bb334d19599579583b79a450e09a63f43671baa64"
    "2136812f84cd1014e07ea6302f1705fcc58814502bd022a4e28782f7d90b3ae7"
    "57f49278b96afe9b16bcbe1f43b96922f0c9be5e7e387357f1ae130f71fa1c47"
    "18d3f841c42b614f6fd8b7ec9a14e5a6f30eba7009706b62f522c0d0a71f71e6"
    "975f9f6884b82ac57373e9d0b537e4c73a5a6451031c7093dc05b8d6df87f3e7"
    "52ad9bb3748098e5357d1146f014b17bc4d901995ad682ee4d0df2f6a0ea02c3"
    "1b44b4325b2c867527212137c0938539d9195308d78ea33a6a0839b4fd6f1e78"
    "357f9dd1d4f36852c312fe576398755b7c9305d486bfece561253a5c2e984ea6")

# Copy ledger_canister into experiment_dir
cp -rp "$TEST_MODULES"/ledger_canister "$experiment_dir/"
chmod +w -R "$experiment_dir"/ledger_canister

# These are the hosts to which we will send transfer update calls and balance query calls
nns_hosts=$(
    cd "$PROD_SRC" || exit 1
    ansible-inventory -i "$hosts_file_path" \
        --list | jq -L./jq -r \
        "import \"ansible\" as ansible; . as \$o | .nns.hosts[0] | \$o._meta.hostvars[.] | ansible::interpolate | .api_listen_url"
)

echo "NNS hosts: $nns_hosts"
nns_ip=${nns_hosts##*/}
echo "NNS_IP: $nns_ip"
# Update dfx.json with testnet info
pushd "$experiment_dir/ledger_canister" || exit 1
sed -i "s/nnstestnet/$testnet/g" dfx.json
sed -i "s/dcs-nns-8.dfinity.systems:8080/$nns_ip/g" dfx.json

echo "dfx version: $(dfx --version)"

# Testnet has ledger canister initialized with test_principal_id.
# Assume test identity so that ledger transfers can be made from test account
{
    echo "****************************"
    # This command is just to make sure that a default identity is created on the test runner if not already present. This is required so that "$HOME"/.config/dfx/identity/ folder exists to create test_identity.
    dfx identity list
    # Create an identity using the provided test identity
    cp -r "$TEST_MODULES"/test_identity "$HOME"/.config/dfx/identity/
    # Use this identity instead of default
    dfx identity use test_identity
    # Verify that test_principal_id is used
    test_pid=$(dfx identity get-principal 2>&1)
    echo "Principal ID: $test_pid"
    echo "****************************"
}

# Check source account initial balance
initial_source_account_balance=$(dfx canister --no-wallet --network="$testnet" call "$ledger" account_balance_dfx "(record { account = \"$test_account_id\"; } )" 2>&1)
echo "initial_source_account_balance is $initial_source_account_balance"
initial_source_account_balance=$(echo "$initial_source_account_balance" | cut -d '=' -f 2 | cut -d ':' -f 1 | tr -dc '0-9')
echo "initial_source_account_balance is $initial_source_account_balance"

# Helper function to convert times
dateFromEpoch() {
    date --date="@$1"
}

# For every principal_id, query account_balance, transfer a variant amount e8s and query account balance again
# If the balance does not reflect, report error and break out of the loop
execute_tps() {
    batch=$1
    amount_base=$2
    batch_starttime="$(date '+%s')"
    for ((p = 0; p < tps; p++)); do
        (
            test_receiver_account_id=${AccountIDs[p % 10]}

            # Transfer dynamic amount of e8s to the account, so transaction will not be considered duplicate
            dynamic_amount=$((amount_base + p))
            result=$(dfx canister --no-wallet --network="$testnet" call "$ledger" send_dfx "(record { memo = $dynamic_amount:nat64; amount = record { e8s = $dynamic_amount:nat64 }; fee = record { e8s = 10000:nat64 }; to = \"$test_receiver_account_id\" } )" 2>&1)
            echo "$result" >>"$experiment_dir/ledger_log"
            echo "$((dynamic_amount + 10000))" >>"$experiment_dir/expected_delta"
        ) &
        to_wait+=($!)
    done
    wait "${to_wait[@]}"
    batch_endtime="$(date '+%s')"
    batch_duration=$((batch_endtime - batch_starttime))
    echo "Batch $batch of $tps transfers took $batch_duration seconds" | tee -a "$experiment_dir/ledger_success"
}

# Every second start a batch of tps transactions in a subshell,
# If a batch takes more than batch_execution_time, report error and break out of the loop
# Since we are starting the subshell, it's not guaranteed that the exact tps will be run, but a close approximation of it.
amount_base=0
for ((i = 0; i < duration; i++)); do
    (
        execute_tps "$i" "$amount_base"
    ) &
    sleep 1
    amount_base=$((amount_base + tps))
done

wait

# Check source account post balance
post_source_account_balance=$(dfx canister --no-wallet --network="$testnet" call "$ledger" account_balance_dfx "(record { account = \"$test_account_id\"; } )" 2>&1)
post_source_account_balance=$(echo "$post_source_account_balance" | cut -d '=' -f 2 | cut -d ':' -f 1 | tr -dc '0-9')

# Calculate total expected_delta from all subshell transfers
expected_delta=0
while read -r -a line; do
    expected_delta=$((expected_delta + line))
done <"$experiment_dir/expected_delta"
echo "expected_delta is $expected_delta"

echo "initial_source_account_balance is $initial_source_account_balance"
echo "post_source_account_balance is $post_source_account_balance"
actual_delta=$((initial_source_account_balance - post_source_account_balance))
echo "actual_delta is: $actual_delta"

# Consider failure if failed to transfer more than 0.1% of expected amounts
delta=$((expected_delta - actual_delta))
if (($(bc -l <<<"$delta / $expected_delta > 0.001") || $(bc -l <<<"$delta / $expected_delta < -0.001"))); then
    echo "Failed to transfer $delta e8s." >>"$experiment_dir/ledger_error"
fi

exit 0
