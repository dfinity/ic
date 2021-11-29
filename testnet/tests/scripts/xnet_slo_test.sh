#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: XNet messaging functions within SLO

Goal:: Ensure IC routes XNet traffic in a timely manner

Runbook::
. Instantiate an IC with at least two applications subnets
. Install the xnet-testing canister in each subnet
. Initiate them with the IDs of all canisters and their subnet IDs and let them send messages to each other for a while
. Collect canister-aggregated metrics regarding messages sent, requests received and latency

Success::
.. Pass if for each subnet: There were no failed calls or sequence errors, and
.. Send/finalization rate is above threshold, and
.. Mean request roundtrip is below threshold, and
.. All requests sent more than threshold time get responses.

end::catalog[]
DOC

set -euo pipefail
export exit_code=0

function exit_usage() {
    echo >&2 "Usage: <testnet_identifier> <subnets> <runtime_in_seconds> <rate> <payload_size> <subnet_type> <results_dir>:"
    echo >&2 "$0 p2p58 3 60 40 250b [normal|single_node] /results/"
    exit 1
}

if (($# != 7)); then
    exit_usage
fi

testnet="$1"
subnets="$2"
runtime="$3"
rate="$4"
payload_size="$5"
subnet_type="$6"
results_dir="$(
    mkdir -p "$7"
    realpath "$7"
)"
experiment_dir="$results_dir/${testnet}-xnet-slo-rt_${runtime}-rate_${rate}-payload_${payload_size}-$(date +%s)"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

# Store the time at which the test was called, so we can compute how long everything takes.
calltime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$calltime")"

if [[ "$subnet_type" != "normal" ]] && [[ "$subnet_type" != "single_node" ]]; then
    echo >&2 "Invalid subnet type specified, choose between normal and single_node."
    exit_usage
fi

hosts_file_path="$PROD_SRC/env/$testnet/hosts"
HOSTS_INI_ARGUMENTS=()

if [[ "$subnet_type" == "single_node" ]]; then
    # The test will run with a special hosts file creating many single-node app subnets.
    export HOSTS_INI_FILENAME=hosts_single_node_subnets.ini
    HOSTS_INI_ARGUMENTS+=(--hosts-ini "$HOSTS_INI_FILENAME")
fi

# Deploy the testnet
deploy_with_timeout "$testnet" \
    --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}"

# Testnet NNS URL: the API endpoint of the first NNS replica.
nns_url=$(
    cd "$PROD_SRC"
    ansible-inventory -i "$hosts_file_path" --list \
        | jq -r -L"${PROD_SRC}/jq" 'import "ansible" as ansible;
            ._meta.hostvars |
            [
                with_entries(select(.value.subnet_index==0))[] |
                ansible::interpolate |
                .api_listen_url
            ] |
            first'
)

echo "Testnet deployment successful. Test starts now."

export XNET_TEST_CANISTER_WASM_PATH="$MEDIA_CANISTERS_PATH/xnet-test-canister.wasm"

# Store the test start time in epoch, so we could query Prometheus later.
starttime="$(date '+%s')"

echo "Start time: $(dateFromEpoch "$starttime")"
echo "$starttime" >"$experiment_dir/starttime"

xnet_endtime_file="$experiment_dir/xnet_endtime"
xnet_log="$experiment_dir/xnet-workload.log"

# Start the test driver.
{
    command -v e2e-test-driver
    e2e-test-driver \
        --nns_url "$nns_url" \
        --subnets "$subnets" \
        --runtime "$runtime" \
        --rate "$rate" \
        --payload_size "$payload_size" \
        -- "4.3"
} | tee -a "$xnet_log"

date '+%s' >"$xnet_endtime_file"
endtime="$(<"$xnet_endtime_file")"

echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$calltime"))"

duration=$((endtime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

exit $exit_code
