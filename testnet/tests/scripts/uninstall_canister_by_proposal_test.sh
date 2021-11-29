#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Uninstall Canister by a Proposal

Goal:: Ensure that canisters can be uninstalled by a NNS proposal and queries and update calls
 are not answered anymore afterwards


Runbook::
. deploy canister
. make call to canister
. submit proposal to uninstall canister
. wait
. make call to canister

Success::
.. calls to canister succeed before proposal submission and fail afterwards

end::catalog[]
DOC

if (($# != 2)); then
    echo >&2 "Wrong number of arguments, please provide values for <testnet_identifier> <results_dir>:"
    echo >&2 "$0 medium02 ./results/"
    exit 1
fi

testnet="$1"
results_dir="$(
    mkdir -p "$2"
    realpath "$2"
)"
experiment_dir="$results_dir/uninstall_canister_by_proposal_test_${testnet}-$(date +%s)"

set -euo pipefail
export exit_code=0

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"
# Source helpers will have made the current directory $REPO_ROOT/testnet

# Store the time at which the test was called, so we can compute how long everything takes.
starttime="$(date '+%s')"
echo "Testcase call time: $(dateFromEpoch "$starttime")"

export PROD_SRC
export TEST_MODULES="$PROD_SRC/tests/scripts/test_modules"
export HOSTS="$PROD_SRC/env/$testnet/hosts"

# Deploy the testnet
deploy_with_timeout "$testnet" --git-revision "$GIT_REVISION"

echo "Testnet deployment successful. Test starts now."

# obtain URL of a node in the NNS to send an ic-admin call to
nns_url=$(jq_hostvars 'map(select(.subnet_index==0) | .api_listen_url)[0]')
export nns_url
echo "nns_url: $nns_url"

# deploy a hello world canister on the testnet with dfx
pushd "$experiment_dir" || exit 1
loadhosts=$(jq_subnet_nodes_urls_nth_third 1 1)
IFS=',' read -ra hosts <<<"$loadhosts"
echo "hosts: ${hosts[*]}"
ic_ip="${hosts:8}"
echo "ic_ip: $ic_ip"
echo "creating test_canister"
dfx new "test_canister" --frontend=false
cd test_canister || exit 1
sed -i'.original' -e "s/local/$testnet/g" dfx.json
sed -i'.original' -e "s/bind/providers/g" dfx.json
sed -i'.original' -e "s/\"127.0.0.1:8000\"/\[\"http:\/\/[$ic_ip\"\]/g" dfx.json
sed -i'.original' -e 's/ephemeral/persistent/g' dfx.json
echo "deploying test_canister"
dfx deploy --no-wallet --network "$testnet"

# make a call to the canister, expect it to return successfully
result=$(dfx canister --network "$testnet" call test_canister greet everyone 2>&1)
echo "$result"
if [[ $result == *"error"* ]]; then
    failure "Calling the canister failed"
else
    echo "First call executed successfully!"
fi

# obtain the canister id (called twice to avoid parsing problems where
# previous output is included)
canister_id=$(dfx canister --network "$testnet" id test_canister)
canister_id=$(dfx canister --network "$testnet" id test_canister)

# make a proposal to uninstall the canister with an ic-admin call
echo "creating proposal to uninstall canister with id $canister_id"
ic-admin --nns-url "$nns_url" \
    propose-to-uninstall-code \
    --test-neuron-proposer \
    --canister-id "$canister_id" \
    --proposal-url "https://www.proposal.dfinity.org" \
    --summary "Uninstall test canister"
echo "submitted proposal"

# sleep while hopefully uninstallation takes place
sleep 8

# make another call to the canister, expect it to fail
result=$(dfx canister --network "$testnet" call test_canister greet everyone 2>&1 || true)
echo "$result"
if [[ $result == *"rror"* ]]; then
    echo "error found"
    success "Calling the canister failed after deinstallation"
else
    failure "Second call succeeded despite deinstallation"
fi

endtime="$(date '+%s')"
echo "$endtime" >"$experiment_dir/endtime"

echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

# duration covers the time we had 4 nodes running
duration=$((endtime - starttime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

exit $exit_code
