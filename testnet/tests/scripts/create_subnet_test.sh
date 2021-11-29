#!/usr/bin/env bash
# We use subshells to isolate code.  Shellcheck is concerned that changes are meant to be global.
# shellcheck disable=SC2030,SC2031,SC2154
# We use sed a lot, but shellcheck is worried about '$' not expanding to a variable.
# shellcheck disable=SC2016
# We use client-side variable expansion
# shellcheck disable=SC2029,SC2087
# We want arrays to expand into multiple arguments
# shellcheck disable=SC2068

: End shellcheck global rules

: <<'DOC'
tag::catalog[]

Title:: Create Subnet test

Goal:: Ensure that a subnet can be created from un-assigned nodes

Runbook::
. sets up the nns subnet
. it creates a subnet from the list of un-assigned nodes
. collects metrics:
. prints results

Success::
.. average finalization rate >= 0.3 (over all replicas in 60s windows), and

end::catalog[]
DOC

if (($# != 2)); then
    echo >&2 "Wrong number of arguments, please provide values for <testnet_identifier> <results_dir>:"
    echo >&2 "$0 p2p_15 30 40 250b 1 0 10 ./results/"
    exit 1
fi

testnet="$1"
results_dir="$(
    mkdir -p "$2"
    realpath "$2"
)"
experiment_dir="$results_dir/create_subnet_test_${testnet}-$(date +%s)"

set -euo pipefail
export exit_code=0

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"
# Source helpers will have made the current directory $REPO_ROOT/testnet

# Store the time at which the test was called, so we can compute how long everything takes.
calltime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$calltime")"

# Add some additional data to the experiment_dir
mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "FinalizationRate": finalization_rate
}
' >>"$experiment_dir/data_to_upload/FinalizationRate.json"

export PROD_SRC
export TEST_MODULES="$PROD_SRC/tests/scripts/test_modules"

#  create directory for collecting logs
"$TEST_MODULES"/create_output_dir.sh "$results_dir"

export HOSTS="$PROD_SRC/env/$testnet/hosts"
export HOSTS_INI_FILENAME="hosts_unassigned.ini"
echo "using host file name: $HOSTS_INI_FILENAME"
HOSTS_INI_ARGUMENTS=(--hosts-ini "$HOSTS_INI_FILENAME")

# deploy the testnet with  --dkg-interval-length 19 for fast subnet creation
deploy_with_timeout "$testnet" \
    --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}" --dkg-interval-length 19

echo "Testnet deployment successful. Test starts now."

nns_url=$(jq_hostvars 'map(select(.subnet_index==0) | .api_listen_url)[0]')
echo "nns_url: $nns_url"

mapfile -d " " -t node_ids <<<"$(ic-admin --nns-url "$nns_url" get-topology | jq -r '.topology.unassigned_nodes | map_values(.node_id) | join(" ")')"
echo "Unassigned node ids: ${node_ids[*]}"

get_subnets_num_cmd="ic-admin --nns-url ${nns_url} get-subnet-list | jq '. | length'"
init_subnets_num=$(eval "$get_subnets_num_cmd")
echo "After deployment, there are ${init_subnets_num} subnets on testnet ${testnet}"

replica_version_id=$(ic-admin --nns-url "$nns_url" get-subnet 0 | jq '.records[0].value.replica_version_id' -r)
echo "Replica version id=${replica_version_id}"

echo "Proposal submission to create a subnet"

ic-admin \
    --nns-url "$nns_url" \
    propose-to-create-subnet \
    --test-neuron-proposer \
    --ingress-bytes-per-block-soft-cap 2097152 \
    --max-ingress-bytes-per-message 2097152 \
    --max-block-payload-size 0 \
    --max-ingress-messages-per-block 1000 \
    --unit-delay-millis 1000 \
    --replica-version-id "$replica_version_id" \
    --initial-notary-delay-millis 600 \
    --dkg-interval-length 19 \
    --gossip-max-artifact-streams-per-peer 20 \
    --gossip-max-chunk-wait-ms 15000 \
    --gossip-max-duplicity 1 \
    --gossip-max-chunk-size 4096 \
    --gossip-receive-check-cache-size 5000 \
    --gossip-pfn-evaluation-period-ms 3000 \
    --gossip-registry-poll-period-ms 3000 \
    --gossip-retransmission-request-ms 60000 \
    --subnet-type application ${node_ids[@]}

target_subnets_num="$((init_subnets_num + 1))" # one more subnet should be created after deployment
current_subnets_num=$(eval "$get_subnets_num_cmd")
echo "Waiting till the number of subnets becomes ${target_subnets_num}"
sleep_time_sec=30
until [[ "${current_subnets_num}" -eq "${target_subnets_num}" ]]; do
    echo "Current number of subnets is ${current_subnets_num} vs target number of ${target_subnets_num}"
    echo "Waiting another ${sleep_time_sec} seconds for subnet to be created"
    current_subnets_num=$(eval "$get_subnets_num_cmd")
    sleep $sleep_time_sec
done

echo "After propose-to-create-subnet call, there are $(eval "$get_subnets_num_cmd") subnets on testnet ${testnet}"

starttime="$(date '+%s')"
echo "Start time for finalization rate measurement: $(dateFromEpoch "$starttime")"

# sleep enough time to gather metrics
sleep_time_sec=100
echo "Waiting ${sleep_time_sec} seconds to gather metrics"
sleep $sleep_time_sec

collect_metrics '"x"'

# Now, check if we were good
finalization_rate=$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")
echo "Finalization rate is ${finalization_rate}"

sed -i "s/finalization_rate/$finalization_rate/g" "$experiment_dir/data_to_upload/FinalizationRate.json"

inspected_subnet_index="$((current_subnets_num - 1))"
expected_finalization=$(finalization_rate_threshold "${inspected_subnet_index}")
if (($(bc <<<"$finalization_rate < $expected_finalization"))); then
    failure "Finalization rate $finalization_rate less than ${expected_finalization}, fail!"
else
    success "Finalization rate $finalization_rate greater than ${expected_finalization}, great success!"
fi

endtime="$(date '+%s')"
echo "$endtime" >"$experiment_dir/endtime"

echo "Ending tests *** $(dateFromEpoch "$endtime") (the test was triggered at $(dateFromEpoch "$calltime"))"

# duration covers the time we had 4 nodes running
duration=$((endtime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

exit $exit_code
