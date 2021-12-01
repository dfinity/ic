#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Change registry periodically via subnet record proposals

Goal:: Ensure the NNS subnet finalization rate stays the same.

Runbook::
. set up the testnet (nns + subnet installation)
. measure finalization rate without proposals for a given duration
. measure finalization rate with a user-specified number of proposals submitted during the same duration (each proposal changes the registry entry of the first subnet record)

Success::
.. average finalization rate without proposals only 10% higher than with

end::catalog[]
DOC

set -euo pipefail
export exit_code=0

# Ensure we kill all background processes on CTRL+C
# shellcheck disable=SC2064
trap "echo 'SIGINT received, killing all jobs'; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1" INT

if (($# != 5)); then
    echo >&2 "Wrong number of arguments, please provide values for <testnet_identifier> <duration> <num_proposals> <subnet_type> <results_dir>:"
    echo >&2 "$0 consensus3 600 5 [normal|large_nns|56_nns] ./results/"
    exit 1
fi

testnet="$1"
duration="$2"
num_proposals="$3"
subnet_type="$4"
results_dir="$(
    mkdir -p "$5"
    realpath "$5"
)"
# Results will be stored in $results_dir/$experiment_id -- this will allow us to collect all runs
# if ever needed.
# To make it discernable, use all the inputs, plus the current starttime
experiment_dir="$results_dir/testcase_registry_changes_${testnet}-$(date +%s)"

SUBNET_TYPES=("normal" "large" "large_nns" "56_nns")
if [[ ! " ${SUBNET_TYPES[*]} " =~ ${subnet_type} ]]; then
    echo >&2 "Invalid subnet type specified, choose between normal, large, large_nns and 56_nns."
    exit_usage
fi

HOSTS_INI_ARGUMENTS=()
if [[ "$subnet_type" == "large" ]]; then
    # The test will run with a special hosts file creating a large app subnet.
    export HOSTS_INI_FILENAME=hosts_large_subnet.ini
    HOSTS_INI_ARGUMENTS+=(--hosts-ini "$HOSTS_INI_FILENAME")
fi
if [[ "$subnet_type" == "large_nns" ]]; then
    # The test will run with a special hosts file creating a large nns subnet.
    export HOSTS_INI_FILENAME=hosts_large_nns.ini
    HOSTS_INI_ARGUMENTS+=(--hosts-ini "$HOSTS_INI_FILENAME")
fi
if [[ "$subnet_type" == "56_nns" ]]; then
    # The test will run with a special hosts file creating a large nns subnet.
    export HOSTS_INI_FILENAME=hosts_56_nns.ini
    HOSTS_INI_ARGUMENTS+=(--hosts-ini "$HOSTS_INI_FILENAME")
fi

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"
TEST_MODULES=${TEST_MODULES:-$PROD_SRC/tests/scripts/test_modules}

# Store the time at which the test was called, so we can compute how long everything takes.
calltime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$calltime")"

# Deploy testnet
deploy_with_timeout "$testnet" \
    --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}"

echo "Testnet deployment successful. Test starts now."

echo "Starting Testcase Registry Changes"
echo "On testnet with identifier $testnet with $num_proposals num_proposals spread over $duration seconds"

starttime="$(date '+%s')"

echo "Start time: $(dateFromEpoch "$starttime")"
echo "$starttime" >"$experiment_dir/starttime"

# Sleep for 60s for two reasons
#  - metrics are already scraped after the testnet install
#  - there are no residual metrics that we may aggregate
sleep 60s

#Store the test start time in epoch, so we could query Prometheus later.
starttime="$(date '+%s')"
echo "Sleep for $duration to measure finalization_rate without proposals"
sleep "$duration"

# Produce the list of all nodes in the testnet, suitable for passing to the Prometheus query
metricshosts="$(jq_subnet_load_urls_for_metrics 1)"

# compute average without load

# Extract the IC name from the testnet name (p2p_15_28 -> p2p)
ic="${testnet%%_*}"

endtime="$(date '+%s')"

# Get these metrics. We will go from the start time to the endtime, with 60s step.
# In each of the time windows (steps) we calculate the min, max, avg for the metric.
mkdir -p "$experiment_dir/metrics"
common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts\""
metric="artifact_pool_consensus_height_stat"
selector="$metric{$common_labels,type=\"finalization\",pool_type=\"validated\",stat=\"max\"}"
for op in min max avg; do
    curl -G "http://prometheus.dfinity.systems:9090/api/v1/query_range" \
        -fsSL -m 30 --retry 10 --retry-connrefused \
        -o "$experiment_dir/metrics/no_load_${metric}_${op}.json" \
        -H "Accept: application/json" \
        --data-urlencode "start=$starttime" \
        --data-urlencode "end=$endtime" \
        --data-urlencode "step=60s" \
        --data-urlencode "query=$op(rate(${selector}[60s]))"
done

# Calculate the averages over the large interval.
# We split into smaller buckets, then apply avg_over_time. The outer avg it
# to get an aggregate, instead of having values per replica.
curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
    -o "$experiment_dir/metrics/no_load_${metric}_avg_total.json" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -H "Accept: application/json" \
    --data-urlencode "time=$endtime" \
    --data-urlencode "query=avg(rate(${selector}[${duration}s]))"

echo "Results stored in '$experiment_dir/metrics'"

# Now, check if we were good

no_load_finalization_rate="$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/no_load_artifact_pool_consensus_height_stat_avg_total.json")"

mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "FinalizationRate": no_load_finalization_rate
}
' >>"$experiment_dir/data_to_upload/FinalizationRate.json"
sed -i "s/no_load_finalization_rate/$no_load_finalization_rate/g" "$experiment_dir/data_to_upload/FinalizationRate.json"

starttime="$(date '+%s')"

echo "Start time of part with NNS load (registry changes): $(dateFromEpoch "$starttime")"
echo "$starttime" >"$experiment_dir/starttime"

NNS_URL=$(jq_hostvars '[._meta.hostvars[.nns.hosts[0]]]' 'map(.api_listen_url)[0]')

subnet_index=1
base=2097152
interval=$((duration / num_proposals))
initial_registry_version=$(ic-admin --nns-url "$NNS_URL" get-topology | jq -r ".topology.subnets | to_entries[$subnet_index].value.records[0].version")
for ((p = 0; p < num_proposals; p++)); do
    (
        proposal_starttime="$(date '+%s')"
        bytes_per_message=$((base + p))
        registry_version=$(ic-admin --nns-url "$NNS_URL" get-topology | jq -r ".topology.subnets | to_entries[$subnet_index].value.records[0].version")
        echo "Proposal submission $p, bytes_per_message $bytes_per_message at $(dateFromEpoch "$proposal_starttime"), registry version $registry_version"

        result=$(ic-admin --nns-url="$NNS_URL" propose-to-update-subnet \
            --test-neuron-proposer \
            --subnet-id $subnet_index \
            --ingress-bytes-per-block-soft-cap 2097152 \
            --max-ingress-bytes-per-message "$bytes_per_message" \
            --unit-delay-millis 1000 \
            --initial-notary-delay-millis 600 \
            --dkg-interval-length 499 \
            --gossip-max-artifact-streams-per-peer 20 \
            --gossip-max-chunk-wait-ms 15000 \
            --gossip-max-duplicity 1 \
            --gossip-max-chunk-size 4096 \
            --gossip-receive-check-cache-size 5000 \
            --gossip-pfn-evaluation-period-ms 3000 \
            --gossip-registry-poll-period-ms 3000 \
            --gossip-retransmission-request-ms 60000)
        proposal_endtime="$(date '+%s')"
        registry_version=$(ic-admin --nns-url "$NNS_URL" get-topology | jq -r ".topology.subnets | to_entries[$subnet_index].value.records[0].version")
        echo "Proposal submission result $result at $(dateFromEpoch "$proposal_endtime"), registry version $registry_version"
    ) &
    to_wait+=($!)
    sleep "$interval"
done
echo "finished sending proposals"

wait "${to_wait[@]}"
endtime="$(date '+%s')"
echo "last proposal processed at $endtime"
end_registry_version=$(ic-admin --nns-url "$NNS_URL" get-topology | jq -r ".topology.subnets | to_entries[$subnet_index].value.records[0].version")

# Get these metrics. We will go from the start time to the endtime, with 60s step.
# In each of the time windows (steps) we calculate the min, max, avg for the metric.
mkdir -p "$experiment_dir/metrics"
common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts\""
metric="artifact_pool_consensus_height_stat"
selector="$metric{$common_labels,type=\"finalization\",pool_type=\"validated\",stat=\"max\"}"
for op in min max avg; do
    curl -G "http://prometheus.dfinity.systems:9090/api/v1/query_range" \
        -fsSL -m 30 --retry 10 --retry-connrefused \
        -o "$experiment_dir/metrics/${metric}_${op}.json" \
        -H "Accept: application/json" \
        --data-urlencode "start=$starttime" \
        --data-urlencode "end=$endtime" \
        --data-urlencode "step=60s" \
        --data-urlencode "query=$op(rate(${selector}[60s]))"
done

# Calculate the averages over the large interval.
# We split into smaller buckets, then apply avg_over_time. The outer avg it
# to get an aggregate, instead of having values per replica.
curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
    -o "$experiment_dir/metrics/${metric}_avg_total.json" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -H "Accept: application/json" \
    --data-urlencode "time=$endtime" \
    --data-urlencode "query=avg(rate(${selector}[${duration}s]))"

echo "Results stored in '$experiment_dir/metrics'"

# Now, check if we were good

finalization_rate="$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")"

mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "FinalizationRate": finalization_rate
}
' >>"$experiment_dir/data_to_upload/FinalizationRate.json"
sed -i "s/finalization_rate/$finalization_rate/g" "$experiment_dir/data_to_upload/FinalizationRate.json"

expected_finalization=$(finalization_rate_threshold $subnet_index)
if (($(bc <<<"$no_load_finalization_rate < $expected_finalization"))); then
    failure "Finalization rate without registry changes $no_load_finalization_rate less than $expected_finalization, fail!"
else
    success "Finalization rate wihtout registry changes $no_load_finalization_rate greater or equal than $expected_finalization, great success!"
fi

if (($(bc <<<"$finalization_rate < $expected_finalization"))); then
    failure "Finalization rate with registry changes $finalization_rate less than $expected_finalization, fail!"
else
    success "Finalization rate with registry changes $finalization_rate greater or equal than $expected_finalization, great success!"
fi

if (($(echo "100 * $no_load_finalization_rate > 110 * $finalization_rate" | bc -l))); then
    failure "Finalization rate without proposals is more than 10% higher than with, fail!"
else
    success "Finalization rate difference is less than 10%, great success!"
fi

if (($(echo "$end_registry_version > $initial_registry_version + $num_proposals" | bc -l))); then
    echo "Initial registry version $initial_registry_version"
    echo "Last registry version $end_registry_version"
    failure "Registry version did not increase with number of proposals, fail!"
else
    success "Registry version did increase sufficiently, great success!"
fi

duration=$((endtime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

exit $exit_code
