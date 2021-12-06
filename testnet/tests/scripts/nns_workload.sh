#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: NNS subnet processes proposals, votes, ledger transfers and queries

Goal:: Ensure the NNS subnet responds to typical workload, and rejoined node participates into consensus.
This script verifies 2 things:
. NNS subnet responds to typical workload in timely manner, even when a node goes down.
. After the node is full restored, it successfully participates into consensus through the observation that
  another 1/3 of nodes going down, and the network is maintained at bare minimum threshold with the 
  rejoined node.

Runbook::
. set up the testnet (nns + subnet installation)
. at t1=0: start workload for duration d
.. create ledger transfers and queries
.. create proposals and submit votes
. at t2=d/4: stop first node, and restart it at t3=3d/4
. at t4 >= min(d, t3+5min): collect metrics for finalization rate from time 0 to t4
. at t5 = t4 + 5min: stop 1/3 of the nodes
. at t6 = t4 + 10min: collect metrics for statesync of first node since time 0
. collect metrics for height from time t5 to time t6

Success criteria:

. all ledger transfers complete in < 60s
. all proposals submitted successfully
. finalization rate from time 0 to t4 > 0.3
. statesync duration < DKG interval - 30s (for checkpointing)
. height increased between t5 and t6

Details::
In this test we deploy the NNS network and execute consecutive batches of
parallel proposals for creating of empty subnets # with subsequent votings
for these proposals.
Moreover, we run a batch of the specified number of transactions (tps) on the deployed ledger canister every second for the given duration:
 - transfer ICPTs from the minting account to a new/existing account - update call
 - query the account balance of a new/existing account - query call
Furthermore, if the NNS subnet has more than 4 nodes we stop one node after a quarter of the total duration for half of the
duration, then we let it restart. Ideally, this period is greater than 3 DKG intervals,
(~3 x 5min) so the node needs to catch up from the CUP.

end::catalog[]
DOC

set -euo pipefail
export exit_code=0
# Ensure we kill all background processes on CTRL+C
# shellcheck disable=SC2064
trap "echo 'SIGINT received, killing all jobs'; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1" INT

if (($# != 7)); then
    echo >&2 "Wrong number of arguments, please provide values for <testnet_identifier> <duration> <transfers_per_sec> <batch_size> <subnet_type> <expected_finalization> <results_dir>:"
    echo >&2 "$0 consensus3 600 50 10 [normal|large_nns|56_nns] 0.30 ./results/"
    exit 1
fi

# principal for test_modules/test_identity/identity.pem, used for ledger transfers
test_principal_id="b3gus-edhie-77egn-fejju-pt4xd-zz2pt-7v22l-rrts4-a3ebi-fcm4d-wae"
test_account_id="a1d3966cc6f4103b296330d36c659194addf928d7c9bafef220194a45b8c2692"

testnet="$1"
duration="$2"
tps="$3"
batch_size="$4"
subnet_type="$5"
expected_finalization="$6"
results_dir="$(
    mkdir -p "$7"
    realpath "$7"
)"

# Results will be stored in $results_dir/$experiment_id -- this will allow us to collect all runs
# if ever needed.
# To make it discernable, use all the inputs, plus the current starttime
experiment_dir="$results_dir/testcase_nns_workload_${testnet}-$(date +%s)"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"
TEST_MODULES=${TEST_MODULES:-$PROD_SRC/tests/scripts/test_modules}

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

#Store the test start time in epoch, so we could query Prometheus later.
starttime="$(date '+%s')"

echo "Start time: $(dateFromEpoch "$starttime")"
echo "$starttime" >"$experiment_dir/starttime"

# Preparatory work
# Deploy testnet with the test_ledger_account. This will initialize ledger canister with an account for test_principal_id
deploy_with_timeout "$testnet" \
    --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}" \
    --ansible-args "-e {\"test_ledger_accounts\":[\"$test_principal_id\"]}"

echo "Testnet deployment successful. Test starts now."

echo "Starting Testcase nns_workload"
echo "On testnet with identifier $testnet with proposal_batches of size $batch_size and $duration duration"

# Get the list of all node_indices, so we can use that in scenarios
# shellcheck disable=SC2046
mapfile -d " " -t node_indices <<<$(jq_hostvars 'map(select(.subnet_index==0) | .node_index) | @sh')
echo "${node_indices[@]}" >"$experiment_dir/node_indices"

# Prepare metric-collection related variables for later use.
# Produce the list of all nodes in the testnet, suitable for passing to the Prometheus query
metricshosts="$(jq_subnet_load_third_nodes_urls_for_metrics 0)"

# Extract the IC name from the testnet name (p2p_15_28 -> p2p)
ic="${testnet%%_*}"

NNS_URL=$(jq_hostvars '[._meta.hostvars[.nns.hosts[0]]]' 'map(.api_listen_url)[0]')
echo "Set NNS url to $NNS_URL"

# start ledger transfer as asynchronous process
(
    ledger_starttime="$(date '+%s')"
    echo "$ledger_starttime" >"$experiment_dir/ledger_starttime"
    echo "Starting ledger transfers at $ledger_starttime"
    "$TEST_MODULES"/ledger_query_update.sh "$testnet" "$duration" "$tps" "$experiment_dir" "$test_account_id"
    ledger_endtime="$(date '+%s')"
    echo "Ledger workload finished at $ledger_endtime"
    echo "$ledger_endtime" >"$experiment_dir/ledger_endtime"
) &
ledger_pid=$!

# Run batches with `batch_size` proposals in each batch, for the duration of `duration`
# Note, the proposals within one batch are created and being voted for in parallel.
(
    # Pick a random self-authenticating ID (not clear how it is being used, but without it the test doesn't run)
    some_id="cmcjw-6c5ve-4zjnt-lipnl-2lp43-oh5wk-ewciz-xyvnv-m2rz5-hkm6a-hqe"
    batch_starttime="$(date '+%s')"
    echo "$batch_starttime" >"$experiment_dir/batch_starttime"
    echo "Starting proposal batches at $batch_starttime"
    current_batch_starttime="$(date '+%s')"
    p=0
    while (((current_batch_starttime - batch_starttime) < duration)); do
        current_batch_starttime="$(date '+%s')"
        p=$((p + 1))
        to_wait=()
        for ((q = 0; q < batch_size; q++)); do
            (
                msg="Proposal submission batch $p, proposal $q"
                echo "$msg"
                result=$(ic-admin --nns-url="$NNS_URL" propose-to-create-subnet \
                    "$some_id" \
                    --test-neuron-proposer \
                    --ingress-bytes-per-block-soft-cap 2097152 \
                    --max-ingress-bytes-per-message 2097152 \
                    --max-ingress-messages-per-block 1000 \
                    --max-block-payload-size 5000000 \
                    --unit-delay-millis 2000 \
                    --initial-notary-delay-millis 2500 \
                    --dkg-interval-length 99 \
                    --gossip-max-artifact-streams-per-peer 20 \
                    --gossip-max-chunk-wait-ms 15000 \
                    --gossip-max-duplicity 1 \
                    --gossip-max-chunk-size 4096 \
                    --gossip-receive-check-cache-size 5000 \
                    --gossip-pfn-evaluation-period-ms 3000 \
                    --gossip-registry-poll-period-ms 3000 \
                    --gossip-retransmission-request-ms 60000 \
                    --subnet-type "application")
                echo "$msg result $result"
            ) &
            to_wait+=($!)
        done
        wait "${to_wait[@]}"
        current_batch_endtime="$(date '+%s')"
        current_batch_duration=$((current_batch_endtime - current_batch_starttime))
        echo "Batch $p took $current_batch_duration seconds."
    done
    batch_endtime="$(date '+%s')"
    echo "last batch execute at $batch_endtime"
    echo "$batch_endtime" >"$experiment_dir/batch_endtime"
) &
proposals_pid=$!

run_simulation=true
if [ ${#node_indices[@]} -le 3 ]; then
    echo "NNS contains less than or equal to 3 nodes, so do not run failure simulation and proposals"
    run_simulation=false
fi

# start node failure simulation as asynchronous process
(
    # skipping failure simulation if small NNS subnet
    if [ "$run_simulation" = false ]; then
        exit 0
    fi

    sleep $((duration / 4))

    node="$(jq_nth_subnet_node 0 1)"
    downtime=$((duration / 4))
    echo "Failure simulation: stopping node $node for $downtime seconds."
    single_node_failure_starttime="$(date '+%s')"
    echo "$single_node_failure_starttime" >"$experiment_dir/single_node_failure_starttime"

    # Kills a node, and restarts after `downtime` seconds
    cd "$PROD_SRC/ansible"
    ansible-playbook -i "../env/$testnet/hosts" icos_node_stress.yml \
        --limit "$node" \
        -e ic_action=kill-replica -e downtime_seconds="$downtime" 2>&1 \
        | tee -a "$experiment_dir/single_failure_scenario.log"

    single_node_failure_endtime="$(date '+%s')"
    echo "Node restart finished at $single_node_failure_endtime"
    echo "$single_node_failure_endtime" >"$experiment_dir/single_node_failure_endtime"
) &
node_rejoin_pid=$!

# Wait for node rejoin to finish to start collecting consensus metrics throughout the period
wait "$node_rejoin_pid"
single_node_failure_starttime=$(cat "$experiment_dir/single_node_failure_starttime")
finalization_analysis_time="$(date '+%s')"
failure_simulation_duration=$((finalization_analysis_time - single_node_failure_starttime))

# Calculate the averages over the large interval.
# We split into smaller buckets, then apply avg_over_time. The outer avg it
# to get an aggregate, instead of having values per replica.
mkdir -p "$experiment_dir/metrics"
common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts\""
metric="artifact_pool_consensus_height_stat"
selector="$metric{$common_labels,type=\"finalization\",pool_type=\"validated\",stat=\"max\"}"
curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
    -o "$experiment_dir/metrics/${metric}_avg_total.json" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -H "Accept: application/json" \
    --data-urlencode "time=$finalization_analysis_time" \
    --data-urlencode "query=avg(rate(${selector}[${failure_simulation_duration}s]))"

finalization_rate="$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")"

echo "Putting finalization_rate result to file."
echo '
{
 "FinalizationRate": finalization_rate
}
' >>"$experiment_dir/FinalizationRate.json"
sed -i "s/finalization_rate/$finalization_rate/g" "$experiment_dir/FinalizationRate.json"

echo "Finalization metrics stored in '$experiment_dir/metrics'"

if (($(bc <<<"$finalization_rate < $expected_finalization"))); then
    failure "Finalization rate $finalization_rate less than $expected_finalization, fail!"
else
    success "Finalization rate $finalization_rate greater or equal than $expected_finalization, great success!"
fi

nns_reduce_to_threshold_time="$(date '+%s')"
echo "$nns_reduce_to_threshold_time" >"$experiment_dir/nns_reduce_to_threshold_time"

# Kill one third of nodes (making sure none of the newly killds nodes is the previous restored node)
(
    # skipping failure simulation if small NNS subnet
    if [ "$run_simulation" = false ]; then
        exit 0
    fi

    one_third_nodes="$(jq_subnet_nodes_nth_third 0 2)"

    one_thirds_failure_starttime="$(date '+%s')"
    echo "$one_thirds_failure_starttime" >"$experiment_dir/one_thirds_failure_starttime"

    # Kills a node, and restarts after `downtime` seconds
    cd "$PROD_SRC/ansible"
    ansible-playbook -i "../env/$testnet/hosts" icos_node_stress.yml \
        --limit "$one_third_nodes" \
        -e ic_action=kill-replica 2>&1 \
        | tee -a "$experiment_dir/one_third_failure_scenario.log"
    sleep 60

    one_thirds_failure_endtime="$(date '+%s')"
    echo "One thirds failure trigger finished at $one_thirds_failure_endtime"
    echo "$one_thirds_failure_endtime" >"$experiment_dir/one_thirds_failure_endtime"
) &
one_third_going_down_pid=$!

echo "waiting for ledger transfer and subnet creation proposal submission processes to finish before collecting final metrics."
for p in "$one_third_going_down_pid" "$ledger_pid" "$proposals_pid"; do
    wait "$p"
done
# Wait for any other background jobs to terminate
wait

endtime="$(date '+%s')"
echo "$endtime"
echo "$endtime" >"$experiment_dir/endtime"

# Get these metrics.
# We will go from when 1/3 nodes went down to the endtime, with 60s step.
# In each of the time windows (steps) we calculate the min for the metric.
# If min is increasing, we know the acceptance criteria is satisfied
common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts\""
metric="artifact_pool_consensus_height_stat"
selector="$metric{$common_labels,type=\"finalization\",pool_type=\"validated\",stat=\"max\"}"
curl -G "http://prometheus.dfinity.systems:9090/api/v1/query_range" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -o "$experiment_dir/metrics/${metric}_min.json" \
    -H "Accept: application/json" \
    --data-urlencode "start=$nns_reduce_to_threshold_time" \
    --data-urlencode "end=$endtime" \
    --data-urlencode "step=10s" \
    --data-urlencode "query=min($selector)"
height_start="$(jq -r '.data.result[0].values | first | .[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_min.json")"
height_end="$(jq -r '.data.result[0].values | last | .[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_min.json")"

# Get the metrics of state sync duration, summed up until $endtime.
# Query the metrics from the first-killed node as it is the only one which conducts state sync.
# In this test, successful state sync only happens once.
# The value of state_sync_duration_seconds_sum at the final time should represent the state sync duration which just happened.
# Get the report
# Produce the list of all unaffected nodes in the testnet, suitable for passing to the Prometheus query
common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts\",status=\"ok\""
metric="state_sync_duration_seconds_sum"
selector="$metric{$common_labels}"
curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
    -fsSL -m 30 --retry 10 --retry-connrefused \
    -o "$experiment_dir/metrics/${metric}.json" \
    -H "Accept: application/json" \
    --data-urlencode "start=$starttime" \
    --data-urlencode "end=$endtime" \
    --data-urlencode "query=$selector"

echo "Results stored in '$experiment_dir/metrics'"

# State sync needs to finish within the CUP interval and has 30s left to recover the checkpoint.
if ((height_start >= height_end)); then
    failure "Some of the healthy nodes did not advance, fail!"
else
    success "All healthy nodes progressed, great success!"
fi

if [[ -f "$experiment_dir/ledger_error" ]]; then
    failure "Ledger canister could not perform $tps transfers in $duration seconds, fail!"
else
    success "Ledger canister performed $tps transfers in $duration, great success!"
fi

if [ "$run_simulation" = true ]; then
    sfs=$(cat "$experiment_dir/single_node_failure_starttime")
    sfe=$(cat "$experiment_dir/single_node_failure_endtime")
    otf=$(cat "$experiment_dir/one_thirds_failure_starttime")
    bs=$(cat "$experiment_dir/batch_starttime")
    be=$(cat "$experiment_dir/batch_endtime")
    echo "Node restart started at $(dateFromEpoch "$sfs")"
    echo "Node restart finished at $(dateFromEpoch "$sfe")"
    echo "One third nodes failure at $(dateFromEpoch "$otf")"
    echo "Proposals started at $(dateFromEpoch "$bs")"
    echo "Proposals finished at $(dateFromEpoch "$be")"
else
    echo "Did not run simulation and proposal since only four nodes in NNS"
fi

ls=$(cat "$experiment_dir/ledger_starttime")
le=$(cat "$experiment_dir/ledger_endtime")
echo "Ledger transfers started at $(dateFromEpoch "$ls")"
echo "Ledger transfers finished at $(dateFromEpoch "$le")"

endtime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

echo "$(((endtime - starttime) / 60)) minutes and $(((endtime - starttime) % 60)) seconds elapsed."

exit $exit_code
