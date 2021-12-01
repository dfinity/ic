#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Maximum capacity script for rejoin test

Goal:: Find maximum state size that can be synced within CUP interval.


Runbook::
. set up the testnet (nns + subnet installation)
. install the `statesync-test` canister multiple times, updates the canisters state repeatedly
. wait for some time (configurable) and kill a replica before all update calls finish
. after all update calls finish, stop one third of the replicas, which are all in the same data center as the first one
. restart the first killed replica (now it needs to catch up for the network to make progress)
. wait 10min
. if the metrics pass criterion, restarts the killed group and repeats the rejoin_test with increased state size
. otherwise, show the result of last successful run

Success::
.. if the network still makes progress with 2/3 of the nodes in last 5min, and
.. if statesync duration < CUP interval = DKG interval length / finalization

end::catalog[]
DOC
set -euo pipefail
export exit_code=0
if (($# != 7)); then
    echo >&2 "Wrong number of arguments, please provide values for <testnet_identifier> <num_canisters_for_copy> <initial_num_canisters> <incremental_num_canisters> <max_iterations> <subnet_type> <results_dir>:"
    echo >&2 "$0 p2p58 3 10 5 2 [normal|large] ./results/"
    exit 1
fi

testnet="$1"
num_canisters_for_copy="$2"
initial_num_canisters="$3"
incremental_num_canisters="$4"
max_iterations="$5"
subnet_type="$6"
results_dir="$(
    mkdir -p "$7"
    realpath "$7"
)"
experiment_dir="$results_dir/maximum_rejoin_test_${testnet}-initial_size_${initial_num_canisters}-incremental_size_${incremental_num_canisters}-$(date +%s)"

size_level=8
runtime=60
random_seed=0

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"
export STATESYNC_TEST_CANISTER_WASM_PATH="$MEDIA_CANISTERS_PATH/statesync-test-canister.wasm"
export exit_code=0

if [[ $((size_level)) -eq 0 ]] && [[ $((runtime)) -lt $((runtime / 8 + 30 * num_canisters)) ]]; then
    echo >&2 "Please set a higher runtime to make sure other replicas make more progress after killing the first one."
    exit 1
fi

if [[ $((size_level)) -gt 8 ]]; then
    echo >&2 "The size_level is no greater than 8. When setting size_level to 0, it runs the original test without large state."
    exit 1
fi

# Store the time at which the test was called, so we can compute how long everything takes.
calltime="$(date '+%s')"

HOSTS_INI_ARGUMENTS=()
export HOSTS_INI_FILENAME=hosts.ini
if [[ "$subnet_type" == "large" ]]; then
    # The test will run with a special hosts file creating a large app subnet.
    export HOSTS_INI_FILENAME=hosts_large_subnet.ini
    HOSTS_INI_ARGUMENTS+=(--hosts-ini "$HOSTS_INI_FILENAME")
fi

echo "Starting Rejoin Test"
echo "On testnet with identifier $testnet with runtime $runtime (in seconds)."

# Testnet NNS URL: the API endpoint of the first NNS replica.
nns_url=$(jq_hostvars '[._meta.hostvars[.nns.hosts[0]]]' 'map(.api_listen_url)[0]')

# Get the list of all node_indices, so we can use that in scenarios
# shellcheck disable=SC2046
mapfile -d " " -t node_indices <<<$(jq_hostvars 'map(select(.subnet_index==1) | .node_index) | @sh')

echo "${node_indices[@]}" >"$experiment_dir/node_indices"

statesync_node=$(jq_hostvars "with_entries(select(.value.node_index==${node_indices[0]})) | keys[]")

statesync_node_ipv6=$(jq_hostvars "map(select(.node_index==${node_indices[0]}) | .ipv6)[0]")

echo "Node $statesync_node with ipv6 $statesync_node_ipv6 is selected to do state sync."

# Unpack statesync-test-canister.wasm and let Project::cargo_bin() know about its location.
export STATESYNC_TEST_CANISTER_WASM_PATH="$MEDIA_CANISTERS_PATH/statesync-test-canister.wasm"

# Deploy to testnet
deploy_with_timeout "$testnet" \
    --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}"

echo "Testnet deployment successful. Test starts now."

starttime=""
endtime=""
finaltime=""
systemtest_endtime_file=""
systemtest_log=""
maximum_capacity_result_file="$experiment_dir/maximum_capacity"

show_maximum_capacity() {
    success_iteration=$(($1 - 1))
    if [[ $((success_iteration)) -eq 0 ]]; then
        echo "There were no successful rejoin_test runs."
    else
        num_canisters=$((initial_num_canisters + incremental_num_canisters * (success_iteration - 1)))
        echo "The last successful run of rejoin_test is iteration $success_iteration with $num_canisters canisters of 1 GiB size."
        metrics_dir="$experiment_dir/$success_iteration/metrics"
        statesync_fetch_size="$(jq -r '.data.result[0].value[1]' <"$metrics_dir/state_sync_size_bytes_total.json")"
        statesync_duration="$(jq -r '.data.result[0].value[1]' <"$metrics_dir/state_sync_duration_seconds_sum.json")"
        echo "The last successful state sync took $statesync_duration seconds and fetched $statesync_fetch_size bytes remotely."
        echo "$statesync_fetch_size" >"$maximum_capacity_result_file"
    fi
}

set_variables() {
    experiment_subdir="$experiment_dir/$1"
    mkdir -p "$experiment_subdir"
    systemtest_endtime_file="$experiment_subdir/endtime"
    systemtest_log="$experiment_subdir/workload-generator.log"

    mkdir -p "$experiment_subdir/data_to_upload"
    echo '
    {
     "HeightStart": height_start
    }
    ' >>"$experiment_subdir/data_to_upload/HeightStart.json"
    echo '
    {
     "HeightEnd": height_end
    }
    ' >>"$experiment_subdir/data_to_upload/HeightEnd.json"
    echo '
    {
     "StatesyncDuration": statesync_duration
    }
    ' >>"$experiment_subdir/data_to_upload/StatesyncDuration.json"
}

set_start_time() {
    # Store the test start time in epoch, so we could query Prometheus later.
    starttime="$(date '+%s')"
    echo "Starting the iteration $1 of the rejoin_test."
    echo "Start time: $(dateFromEpoch "$starttime")"
    echo "$starttime" >"$experiment_subdir/starttime"
}

kill_the_first_replica() {
    (
        cd "$PROD_SRC/ansible"
        ansible-playbook -i "../env/$testnet/hosts" icos_node_stress.yml \
            --limit "$statesync_node" \
            -e ic_action=kill-replica 2>&1 \
            | tee -a "$experiment_subdir/scenario.log"

        # Purge its checkpoints folder to control the size of transferred chunks during state sync.
        ansible-playbook -i "../env/$testnet/hosts" icos_node_recover_base_checkpoint.yml \
            --limit "$statesync_node" 2>&1 | tee -a "$experiment_subdir/scenario.log"
    ) &
    scenario_pid=$!
    wait "$scenario_pid"
}

start_e2e_test_driver() {
    # Start the e2e system test in a subshell. This will allow us to have a better
    # control over when it finishes.
    cur_iteration="$1"
    num_canisters="$incremental_num_canisters"
    if [[ $((cur_iteration)) -eq 0 ]]; then
        num_canisters="$num_canisters_for_copy"
    elif [[ $((cur_iteration)) -eq 1 ]]; then
        num_canisters="$initial_num_canisters"
    fi
    (
        {
            echo "e2e part"
            command -v e2e-test-driver
            if ! e2e-test-driver \
                --nns_url "$nns_url" \
                --runtime "$runtime" \
                --num_canisters "$num_canisters" \
                --size_level "$size_level" \
                --random_seed "$random_seed" \
                -- "5.2"; then
                echo "failed" >"$experiment_subdir/systemtest_failed"
            fi
        } | tee -a "$systemtest_log"
        # Sleep 4 minutes to make the new checkpoint.
        sleep 240
        date '+%s' >"$systemtest_endtime_file"
    ) &
    systemtest_pid=$!
    wait "$systemtest_pid"
    endtime="$(<"$systemtest_endtime_file")"
    echo "Ending system test *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"
    random_seed=$((random_seed + size_level * num_canisters))
    duration=$((endtime - starttime))
    echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed in the first part of the test."
}

check_e2e_test_driver_result() {
    if [[ -e "$experiment_subdir/systemtest_failed" ]]; then
        echo "System test failed, logs in '$systemtest_log'"
        return 1
    else
        echo "System test passed, continue with the next iteration"
        return 0
    fi
}

kill_the_last_group() {
    (
        # Stop nodes from 1st subnet, last third of the nodes
        stress_nodes=$(jq_subnet_nodes_nth_third 1 2)
        cd "$PROD_SRC/ansible"
        ansible-playbook -i "../env/$testnet/hosts" icos_node_stress.yml \
            --limit "$stress_nodes" -e ic_action=kill-replica 2>&1 | tee -a "$experiment_subdir/scenario.log"
    ) &
    scenario_pid=$!
    wait "$scenario_pid"
}

restart_the_first_replica() {
    (
        cd "$PROD_SRC/ansible"
        ansible-playbook -i "../env/$testnet/hosts" icos_node_stress.yml \
            --limit "$statesync_node" \
            -e ic_action=reset 2>&1 \
            | tee -a "$experiment_subdir/scenario.log"
    ) &
    scenario_pid=$!
    wait "$scenario_pid"
}

restart_the_last_group() {
    (
        # Stop nodes from 1st subnet, last third of the nodes
        stress_nodes=$(jq_subnet_nodes_nth_third 1 2)
        cd "$PROD_SRC/ansible"
        ansible-playbook -i "../env/$testnet/hosts" icos_node_stress.yml \
            --limit "$stress_nodes" -e ic_action=reset 2>&1 | tee -a "$experiment_subdir/scenario.log"
        echo "Sleep for 2min for recovery of the last group."
        sleep 120
    ) &
    scenario_pid=$!
    wait "$scenario_pid"
}

wait_for_state_sync() {
    # Sleep for 10min -- during this time, some nodes will be down.
    # At the beginning of the sleeping time, the restarted replica will conduct state sync.
    # Normally, state sync should finish within 5 minutes (which is roughly the CUP interval).
    # The following 5 minutes is the time period for which we'll query the metrics.
    # We need to ensure that progress is made even with partial membership.
    echo "Sleep for 10min while subshell runs scenario for second part"
    sleep 600

    finaltime="$(date '+%s')"

    echo "Final time: $(dateFromEpoch "$finaltime")"
    echo "(Start time was $(dateFromEpoch "$starttime"))"
}

query_finalization_height_and_rate() {
    # Get the report
    # Produce the list of all unaffected nodes in the testnet, suitable for passing to the Prometheus query
    metricshosts_of_unaffected_nodes="$(jq_subnet_load_third_nodes_urls_for_metrics 1)"

    # Extract the IC name from the testnet name (p2p_15_28 -> p2p)
    ic="${testnet%%_*}"

    measure_time=$((finaltime - 300))

    # Get these metrics. We will go from the last 5 min to the endtime, with 60s step.
    # In each of the time windows (steps) we calculate the min for the metric.
    # If min is increasing, we know the acceptance criteria is satisfied
    mkdir -p "$experiment_subdir/metrics"
    common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts_of_unaffected_nodes\""
    metric="artifact_pool_consensus_height_stat"
    selector="$metric{$common_labels,type=\"finalization\",pool_type=\"validated\",stat=\"max\"}"
    curl -G "http://prometheus.dfinity.systems:9090/api/v1/query_range" \
        -fsSL -m 30 --retry 10 --retry-connrefused \
        -o "$experiment_subdir/metrics/${metric}_min.json" \
        -H "Accept: application/json" \
        --data-urlencode "start=$measure_time" \
        --data-urlencode "end=$finaltime" \
        --data-urlencode "step=60s" \
        --data-urlencode "query=min($selector)"

    # Get the finalization rate of unaffected nodes. We will go from the last 5 min to the endtime, with 60s step.
    # Calculate the averages over the large interval.
    # We split into smaller buckets, then apply avg_over_time. The outer avg it
    # to get an aggregate, instead of having values per replica.
    common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts_of_unaffected_nodes\""
    metric="artifact_pool_consensus_height_stat"
    selector="$metric{$common_labels,type=\"finalization\",pool_type=\"validated\",stat=\"max\"}"

    curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
        -o "$experiment_subdir/metrics/${metric}_avg_total.json" \
        -fsSL -m 30 --retry 10 --retry-connrefused \
        -H "Accept: application/json" \
        --data-urlencode "time=$endtime" \
        --data-urlencode "query=avg(rate(${selector}[300s]))"
}

query_state_sync_duration_and_fetch_size() {
    # Get the state sync duration from the node which is first killed.
    metricshosts_of_the_first_node=$(jq_hostvars "map(select(.node_index==${node_indices[0]}) | .metrics_listen_addr)[0]" | escapebracket)

    # Get the metrics of state sync duration, summed up until $finaltime.
    # Query the metrics from the first-killed node as it is the only one which conducts state sync.
    # In this rejoin test, successful state sync only happens once.
    # The value of state_sync_duration_seconds_sum at the final time should represent the state sync duration which just happened.
    common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts_of_the_first_node\",status=\"ok\""
    metric="state_sync_duration_seconds_sum"
    selector="$metric{$common_labels}"
    curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
        -fsSL -m 30 --retry 10 --retry-connrefused \
        -o "$experiment_subdir/metrics/${metric}.json" \
        -H "Accept: application/json" \
        --data-urlencode "time=$finaltime" \
        --data-urlencode "query=$selector"

    # Get the metrics of state sync size, summed up until $finaltime.
    common_labels="ic=\"$ic\",job=\"replica\",instance=~\"$metricshosts_of_the_first_node\",op=\"fetch\""
    metric="state_sync_size_bytes_total"
    selector="$metric{$common_labels}"
    curl -G "http://prometheus.dfinity.systems:9090/api/v1/query" \
        -fsSL -m 30 --retry 10 --retry-connrefused \
        -o "$experiment_subdir/metrics/${metric}.json" \
        -H "Accept: application/json" \
        --data-urlencode "time=$finaltime" \
        --data-urlencode "query=$selector"

    echo "Results stored in '$experiment_subdir/metrics'"
}

check_state_sync() {
    # There is a progress in the height
    height_start="$(jq -r '.data.result[0].values | first | .[1]' <"$experiment_subdir/metrics/artifact_pool_consensus_height_stat_min.json")"
    height_end="$(jq -r '.data.result[0].values | last | .[1]' <"$experiment_subdir/metrics/artifact_pool_consensus_height_stat_min.json")"
    sed -i "s/height_start/$height_start/g" "$experiment_subdir/data_to_upload/HeightStart.json"
    sed -i "s/height_end/$height_end/g" "$experiment_subdir/data_to_upload/HeightEnd.json"
    finalization_rate="$(jq -r '.data.result[0].value[1]' <"$experiment_subdir/metrics/artifact_pool_consensus_height_stat_avg_total.json")"
    statesync_duration="$(jq -r '.data.result[0].value[1]' <"$experiment_subdir/metrics/state_sync_duration_seconds_sum.json")"
    sed -i "s/statesync_duration/$statesync_duration/g" "$experiment_subdir/data_to_upload/StatesyncDuration.json"
    dkg_interval_length=$(ic-admin --nns-url "$nns_url" get-topology | jq -r ".topology.subnets | to_entries[1].value.records[0].value.dkg_interval_length")
    cup_interval_time=$(bc <<<"$dkg_interval_length/ ($finalization_rate + 0.000001)")

    # State sync needs to finish within the CUP interval and has 30s left to recover the checkpoint.
    if ((height_start >= height_end)); then
        failure "Some of the healthy nodes did not advance, fail!"
    elif (($(bc <<<"$statesync_duration > $cup_interval_time - 30"))); then
        failure "State sync takes too much time and could not finish within the CUP interval."
    else
        success "All healthy nodes progressed, great success!"
    fi
}

prepare_base_checkpoint_for_copy() {
    set_variables 0
    set_start_time 0
    start_e2e_test_driver 0
    trap 'echo "SIGINT received, killing all jobs"; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1' INT
    if ! check_e2e_test_driver_result; then
        failure "Preparation for base checkpoint fails! There were no successful rejoin_test runs."
        exit $exit_code
    fi
    cd "$PROD_SRC/ansible"
    ansible-playbook -i "../env/$testnet/hosts" icos_node_stress.yml \
        --limit "$statesync_node" \
        -e ic_action=kill-replica 2>&1 \
        | tee -a "$experiment_subdir/scenario.log"

    # Move base checkpoint to backup directory.
    ansible-playbook -i "../env/$testnet/hosts" icos_node_backup_base_checkpoint.yml \
        --limit "$statesync_node" 2>&1 | tee -a "$experiment_subdir/scenario.log"
}

prepare_base_checkpoint_for_copy

all_passed=true
for iteration in $(seq 1 "$max_iterations"); do
    set_variables "$iteration"

    set_start_time "$iteration"

    kill_the_first_replica

    start_e2e_test_driver "$iteration"

    trap 'echo "SIGINT received, killing all jobs"; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1' INT

    if ! check_e2e_test_driver_result; then
        all_passed=false
        break
    fi

    kill_the_last_group

    restart_the_first_replica

    wait_for_state_sync

    query_finalization_height_and_rate

    query_state_sync_duration_and_fetch_size

    check_state_sync "$iteration"

    if [[ $((exit_code)) -ne 0 ]]; then
        all_passed=false
        break
    fi

    restart_the_last_group
done

if [[ "$all_passed" == true ]]; then
    show_maximum_capacity $((max_iterations + 1))
else
    show_maximum_capacity "$iteration"
fi

finaltime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$finaltime") (start time was $(dateFromEpoch "$calltime"))"
duration=$((finaltime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed in total in this test."
echo "The test was called with the following arguments"
echo "$@"
