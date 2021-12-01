#!/usr/bin/env bash
# We use subshells to isolate code.  Shellcheck is concerned that changes are meant to be global.
# shellcheck disable=SC2030,SC2031,SC2154
# We prefer to use sed
# shellcheck disable=SC2001

: <<'DOC'
tag::catalog[]

Title:: Recover From The Deployment of a No-Op application subnet

Goal:: Demonstrate that recovery CUP can be written to registry and triggers
upgrade in node manager

Runbook::
. Start ic with at least one application subnet with counter canister and
  light load
. Upgrade subnet to version that does not produce blocks
. Change registry with recovery CUP and subnet record to run test version again
. Observe that subnet restarts

Success::
- counter always increases (NOT IMPLEMENTED YET)
- finalization rate > threshold at most 1min after recovery proposal has been executed
end::catalog[]

S3 artifacts from MR 2067 https://gitlab.com/dfinity-lab/public/ic/-/merge_requests/2067
are used in step 2. For this test to pass, that MR's branch must be backwards
compatible with the version under test. In case of a breaking change (or two
non-breaking changes that violate backwards compatibility together), it is
thus necessary to merge master into branch 'broken-blockmaker' 
DOC

set -euo pipefail
export exit_code=0

if (($# != 2)); then
    echo >&2 "Wrong number of arguments, please provide values for <testnet> <results_dir>"
    exit 1
fi

SSH_OPTIONS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
testnet="$1"
results_dir="$(
    mkdir -p "$2"
    realpath "$2"
)"
subnet_index=1
experiment_dir="$results_dir/disaster_recovery_basic_test-${testnet}-$(date +%s)"
mkdir -p "$experiment_dir"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

calltime="$(date '+%s')"
echo "Testcase call time: $(dateFromEpoch "$calltime")"

STEPS_PATTERN="^(${STEPS:-.*})([.].*|$)"
ENV_FILE="${results_dir}/env_vars"
BIN_DIR="${results_dir}/bin"

export PATH="$BIN_DIR:$PATH"
mkdir -p "$BIN_DIR"
echo "ENV_FILE=$ENV_FILE"
NUM_STEPS_MATCHED=0
step() {
    # Runs a named step if the name matches the env var STEPS.
    # Optional steps are skipped unless STEPS matches the step name exactly.
    if [[ "$1" == "--optional" ]]; then
        local optional="1"
        shift 1
    else
        local optional=""
    fi
    STEP="$1"
    if [[ "$STEP" =~ $STEPS_PATTERN ]]; then
        ((NUM_STEPS_MATCHED++))
        test -n "${DRY_RUN:-}" || printf "\n\n"
        echo "#$(echo "$1" | tr -cd '.' | tr . '#')${optional:+ (Optional)} $*"
        test -e "$ENV_FILE" || touch "$ENV_FILE"
        # shellcheck disable=SC1090
        source "$ENV_FILE"
        # Nothing more to do if:
        #    this is a dry run
        # OR the step is optional and doesn't match the filter exactly.
        if test -n "${DRY_RUN:-}" || { test -n "${optional:-}" && [[ "$STEP" != "${STEPS:-}" ]]; }; then
            : Skipping step "$STEP"
        else
            echo "Start: $(date -u)"
            echo "$STEP	$(date -u)" >>"$results_dir/step_log"

            false
        fi
    else
        true
    fi
}

# Function to preserve vars to be used over multiple steps, so that they are still there if the shell is killed.
setvar() {
    printf 'export %s="%s"\n' "$1" "$2" >>"$ENV_FILE"
}

set_verbosity() {
    test -z "${VERBOSE:-}" || set -x
}

# Utility function for downloading pre-built artifacts (binaries)
function download_executable() {
    "${REPO_ROOT}"/gitlab-ci/src/artifacts/rclone_download.py \
        --git-rev "$GIT_REVISION" --remote-path=release --out="${BIN_DIR}" \
        --unpack --mark-executable
}

# Submit proposal to bless replica version and wait until the proposal is executed.
function bless_replica_version() {
    local version=$1
    local sha256=$2
    local proposal_id
    proposal_id=$(ic-admin --nns-url "$NNS_URL" \
        propose-to-bless-replica-version-flexible \
        --test-neuron-proposer "$version" ignore ignore ignore ignore \
        "https://download.dfinity.systems/ic/$version/guest-os/update-img/update-img.tar.gz" \
        "$sha256" | grep -i proposal | grep -oE "[0-9]*")

    wait_for_proposal_execution "$testnet" "$proposal_id"
}

# Submit proposal to update subnet replica version and wait until the subnet has
# switched to this replica version.
function update_subnet_replica_version() {
    local subnet_id=$1
    local version=$2
    local proposal_id
    proposal_id=$(ic-admin --nns-url "$NNS_URL" \
        propose-to-update-subnet-replica-version \
        --test-neuron-proposer "$subnet_id" "$version" | grep -i proposal | grep -oE "[0-9]*")

    wait_for_proposal_execution "$testnet" "$proposal_id"
}

set_verbosity

################################################################################
# 0. Download tools & binaries
################################################################################
step 0 "Download requisite binaries" || time (
    download_agent_rs_binaries "$BIN_DIR"
    download_executable
    echo OK
)

################################################################################
# 1. Start ic with at least one application subnet
################################################################################
step 1 Create IC on "$testnet" || true

step 1.A Deploy IC || time (
    HOSTS_INI_FILENAME="hosts_unassigned.ini"
    test -f "$PROD_SRC/env/$testnet/$HOSTS_INI_FILENAME" || (echo "Missing $HOSTS_INI_FILENAME for testnet $testnet, abort!" && exit 1)
    setvar HOSTS_INI_FILENAME "$HOSTS_INI_FILENAME"
    "$PROD_SRC/tools/icos_deploy.sh" --no-boundary-nodes \
        --dkg-interval-length 19 --git-revision "$GIT_REVISION" --hosts-ini "$HOSTS_INI_FILENAME" "$testnet"
)

step 1.B Get NNS_URL || time (

    NNS_URL=$(
        cd "$PROD_SRC" \
            && "env/$testnet/hosts" --list | jq -L./jq -r \
                "import \"ansible\" as ansible; . as \$o | .nns.hosts[0] | \$o._meta.hostvars[.] * \$o.nodes.vars | ansible::interpolate | .api_listen_url"
    )
    echo "Set NNS_URL to $NNS_URL"

    TARGET_SUBNET=$(ic-admin --nns-url="$NNS_URL" get-subnet "$subnet_index" | jq -r .records[0].key | sed 's/subnet_record_//')

    echo "Target subnet is $TARGET_SUBNET"

    setvar NNS_URL "$NNS_URL"
    setvar TARGET_SUBNET "$TARGET_SUBNET"
)

step 1.C Calculate membership || time (
    TOPOLOGY=$(ic-admin --nns-url "$NNS_URL" get-topology)
    SUBNET_INFO=$(echo "$TOPOLOGY" | jq ".topology.subnets[\"$TARGET_SUBNET\"]")
    INITIAL_MEMBERS=$(echo "$SUBNET_INFO" | jq .records[0].value.membership[] | sed -e 's/"//g' | xargs)
    FAILOVER_MEMBERS=$(echo "$TOPOLOGY" | jq '.topology.unassigned_nodes|map(.node_id)|.[]' | sed -e 's/"//g' | xargs)
    echo "INITIAL_MEMBERS: $INITIAL_MEMBERS"
    echo "FAILOVER_MEMBERS: $FAILOVER_MEMBERS"

    # shellcheck disable=SC2068
    INITIAL_MEMBER_IPS=$(for node_id in $INITIAL_MEMBERS; do ic-admin --nns-url "$NNS_URL" get-node "$node_id" | tail -n1 | sed -e 's/^.* ip_addr: "\([^"]*\)".*$/\1/'; done | xargs)
    # shellcheck disable=SC2068
    FAILOVER_MEMBER_IPS=$(for node_id in $FAILOVER_MEMBERS; do ic-admin --nns-url "$NNS_URL" get-node "$node_id" | tail -n1 | sed -e 's/^.* ip_addr: "\([^"]*\)".*$/\1/'; done | xargs)
    echo "INITIAL_MEMBER_IPS: $INITIAL_MEMBER_IPS"
    echo "FAILOVER_MEMBER_IPS: $FAILOVER_MEMBER_IPS"
    setvar INITIAL_MEMBERS "$INITIAL_MEMBERS"
    setvar FAILOVER_MEMBERS "$FAILOVER_MEMBERS"
    setvar INITIAL_MEMBER_IPS "$INITIAL_MEMBER_IPS"
    setvar FAILOVER_MEMBER_IPS "$FAILOVER_MEMBER_IPS"
)

################################################################################
# 2. Upgrade subnet to version that does not produce blocks
################################################################################

step 2 Upgrade subnet "$subnet_index" to \"broken blockmaker\" || true

step 2.A Compute checksum of the ICOS image of \"broken blockmaker\" branch || time (
    ic_version_broken_blockmaker=$(cd "$PROD_SRC" && ../gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh origin/broken-blockmaker 1 | tail -n1)
    test -z "$ic_version_broken_blockmaker" && echo "Failed to retrieve a revision in broken-blockmaker branch that disk image" && exit 1
    setvar ic_version_broken_blockmaker "$ic_version_broken_blockmaker"
    setvar \
        ic_version_broken_blockmaker_sha256 \
        "$(curl -s "https://download.dfinity.systems/ic/$ic_version_broken_blockmaker/guest-os/update-img/update-img.tar.gz" | sha256sum | cut -d' ' -f1)"
)

step 2.B Upgrade subnet replica version to \"broken blockmaker\" || time (
    bless_replica_version "$ic_version_broken_blockmaker" "$ic_version_broken_blockmaker_sha256"
    update_subnet_replica_version "$TARGET_SUBNET" "$ic_version_broken_blockmaker"
)

step 2.C Wait for the subnet to stop || time (
    HOST_URL=$(
        cd "$PROD_SRC" \
            && "env/$testnet/hosts" --list | jq -L./jq -r \
                "import \"ansible\" as ansible; . as \$o | .subnet_1.hosts[0] | \$o._meta.hostvars[.] * \$o.nodes.vars | ansible::interpolate | .api_listen_url"
    )
    n=0
    while true; do
        curl -k --silent "$HOST_URL/api/v2/status" 2>&1 | grep "$ic_version_broken_blockmaker" && break
        sleep 5
        n=$((n + 1))
        test "$n" -gt 100 && echo "Failed to detect replica version $ic_version_broken_blockmaker on subnet" && exit 1
    done
    wait_for_subnet_to_stop
)

################################################################################
# 3. Change registry with recovery CUP and subnet record to run test
#    version again
################################################################################

step 3 Change recovery CUP and subnet record to a working version again. || true

# Get a working version by looking up HEAD revision.
step 3.A Compute checksum of the ICOS image of a working revision || time (
    # Try to choose a working revision from master branch (excluding the GIT_REVISION)
    ic_version_working=$(cd "$PROD_SRC" && ../gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh origin/master 2 \
        | grep -v "$GIT_REVISION" | head -n1)
    test -z "$ic_version_working" && echo "Failed to retrieve a working revision that already has ICOS disk image" && exit 1
    setvar ic_version_working "$ic_version_working"
    setvar \
        ic_version_working_sha256 \
        "$(curl -s "https://download.dfinity.systems/ic/$ic_version_working/guest-os/update-img/update-img.tar.gz" | sha256sum | cut -d' ' -f1)"
)

step 3.B Upgrade replica version to a working version || time (
    # Update the replica version on this subnet to a working version.
    # Note that since it is already stuck, it will not actually upgrade.
    # The subnet record in registry, however, will be updated nevertheless.
    bless_replica_version "$ic_version_working" "$ic_version_working_sha256"
    update_subnet_replica_version "$TARGET_SUBNET" "$ic_version_working"
)

step 3.C Calculate recovery height and state hash. || time (
    echo ic-cup-explorer "$NNS_URL" "$TARGET_SUBNET"
    OUTPUT=$(ic-cup-explorer "$NNS_URL" "$TARGET_SUBNET")
    echo "ic-cup-explorer output: $OUTPUT"
    HEIGHT=$(echo "$OUTPUT" | grep 'HEIGHT:' | grep -oE "[0-9]*")
    STATE_HASH=$(echo "$OUTPUT" | grep 'HASH:' | sed 's/HASH://' | xargs)
    RECOVERY_HEIGHT=$((HEIGHT + 100))
    setvar STATE_HASH "$STATE_HASH"
    setvar LAST_HEIGHT_IN_HEX "$(printf "%016x" "$HEIGHT")"
    setvar RECOVERY_HEIGHT "$RECOVERY_HEIGHT"
)

step 3.D Keep only state of recovery height on one of the nodes. || time (
    node_ip=$(echo "$INITIAL_MEMBER_IPS" | xargs -n1 | tail -n1)
    #shellcheck disable=SC2029,SC2086,SC2087
    ssh $SSH_OPTIONS "admin@$node_ip" <<EOF
cd /var/lib/ic/data/ic_state/checkpoints
echo rm -rf \$(ls|grep -v $LAST_HEIGHT_IN_HEX)
sudo rm -rf \$(ls|grep -v $LAST_HEIGHT_IN_HEX)
EOF
)

step 3.E Propose to update recovery cup || time (
    # We don't have to specify the version to update here because it will use
    # the latest replica version already specified in the registry
    echo "Making recovery cup at height $RECOVERY_HEIGHT with state hash $STATE_HASH"

    # shellcheck disable=SC2068,SC2128,SC2086
    PROPOSAL_ID=$(
        ic-admin --nns-url="$NNS_URL" propose-to-update-recovery-cup \
            --test-neuron-proposer \
            --subnet-index "$subnet_index" \
            --height "$RECOVERY_HEIGHT" \
            --time-ns "$(date +%s%N)" \
            --state-hash "$STATE_HASH" \
            --replacement-nodes $INITIAL_MEMBERS | grep -i proposal | grep -oE "[0-9]*"
    )

    echo "proposed recovery cup setting initial members"
    wait_for_proposal_execution "$testnet" "$PROPOSAL_ID"
)

step 3.E Wait for subnet to resume || time (
    wait_for_subnet_to_resume
)

step 4 Install and run workload generator || time (
    # As we start the workload generator in a subshell, the only way to pass the information back
    # is via files.
    # In this file, we store the end time, so we could query prometheus later.
    wg_log="$experiment_dir/workload-generator.log"
    wg_err_log="$experiment_dir/workload-generator-err.log"
    wg_status_file="$experiment_dir/wg_exit_status"

    # Start the workload generator in a subshell. This will allow us to have a better
    # control over when it finishes.
    (
        loadhosts=$(for ip in $INITIAL_MEMBER_IPS; do echo "http://[$ip]:8080"; done | xargs | sed -e 's/ /,/g')
        {
            local_wg_status=0
            rate=30
            # Leave enough extra time for the workload generator to report summary.
            # After a timeout make sure it's terminated, otherwise we may end up with stale processes
            # on the CI/CD which block the entire pipeline (other job invocations).
            timeout -k 120 100 ic-workload-generator \
                "$loadhosts" -u \
                -r "$rate" \
                -n 30 \
                --periodic-output \
                --summary-file "$experiment_dir/workload-summary.json" 2>"$wg_err_log" \
                || local_wg_status=$?
            echo "$local_wg_status" >"$wg_status_file"
        } | tee -a "$wg_log"
    )
    wg_status="$(<"$wg_status_file")"
    test "$wg_status" -eq 0 || (echo "Workload testing failed with exit code $wg_status" && exit "$wg_status")
)

################################################################################
# 5. Stall the network and recover it again using failover nodes
################################################################################

step 5 Stall the network and recover it again using failover nodes || true

step 5.A Halt the subnet || time (
    PROPOSAL_OUTPUT=$(ic-admin --nns-url="$NNS_URL" propose-to-update-subnet \
        --test-neuron-proposer --is-halted true --subnet 1)
    PROPOSAL_ID=$(echo "$PROPOSAL_OUTPUT" | grep -i proposal | grep -oE "[0-9]*")
    wait_for_proposal_execution "$testnet" "$PROPOSAL_ID"
    wait_for_subnet_to_stop
)

step 5.B propose to update subnet replica verison to working version again || time (
    # Since the subnet is stopped, it will not be able to update to working version.
    # But we have to make the proposal anyway in order for 5.D to succeed.
    update_subnet_replica_version "$TARGET_SUBNET" "$ic_version_working"
    echo "Going back to everything working"
)

step 5.C Copy state to one of the failover nodes || time (
    src_ip=$(echo "${INITIAL_MEMBER_IPS}" | sed -e 's/ .*$//')
    echo Copying state checkpoint from "$src_ip"
    rsync -e "ssh $SSH_OPTIONS" -a admin@"[${src_ip}]":/var/lib/ic/data/ic_state/checkpoints "$experiment_dir/"
    #shellcheck disable=SC2012
    checkpoint=$(ls -tr "$experiment_dir/checkpoints" | tail -n1)
    echo Latest checkpoint is "$checkpoint"

    dst_ip=$(echo "${FAILOVER_MEMBER_IPS}" | sed -e 's/ .*$//')
    echo Copying state checkpoint to "$dst_ip"
    echo rsync -a --delete "$experiment_dir/checkpoints/$checkpoint" admin@"[${dst_ip}]":/tmp/
    rsync -e "ssh $SSH_OPTIONS" -a --delete "$experiment_dir/checkpoints/$checkpoint" admin@"[${dst_ip}]":/tmp/
    #shellcheck disable=SC2029,SC2086
    ssh $SSH_OPTIONS admin@"${dst_ip}" "sudo rsync -a --delete /tmp/$checkpoint /var/lib/ic/data/ic_state/checkpoints/"
    #shellcheck disable=SC2029,SC2086
    ssh $SSH_OPTIONS admin@"${dst_ip}" "sudo chown ic-replica:nonconfidential /var/lib/ic/data/ic_state/checkpoints/$checkpoint"

    FAILOVER_STATE_HASH=$(state-tool manifest --state "$experiment_dir/checkpoints/$checkpoint" | tail -n1 | sed -e 's/ROOT HASH: //')
    echo Recovery state root hash: "$FAILOVER_STATE_HASH"

    FAILOVER_RECOVERY_HEIGHT=$(printf "%d" $((16#$checkpoint)))
    echo Recovery height: "$FAILOVER_RECOVERY_HEIGHT"

    setvar FAILOVER_STATE_HASH "$FAILOVER_STATE_HASH"
    setvar FAILOVER_RECOVERY_HEIGHT "$FAILOVER_RECOVERY_HEIGHT"
)

step 5.D propose to update recovery CUP || time (
    # shellcheck disable=SC2068,SC2128,SC2086
    PROPOSAL_ID=$(
        ic-admin --nns-url="$NNS_URL" propose-to-update-recovery-cup \
            --test-neuron-proposer \
            --subnet-index "$subnet_index" \
            --height "$FAILOVER_RECOVERY_HEIGHT" \
            --time-ns "$(date +%s%N)" \
            --state-hash "$FAILOVER_STATE_HASH" \
            --replacement-nodes ${FAILOVER_MEMBERS} | grep -i proposal | grep -oE "[0-9]*"
    )

    echo "proposed recovery cup with failover members"

    wait_for_proposal_execution "$testnet" "$PROPOSAL_ID"
)

step 6 Propose to unhalt the subnet || time (
    PROPOSAL_OUTPUT=$(ic-admin --nns-url="$NNS_URL" propose-to-update-subnet \
        --test-neuron-proposer --is-halted false --subnet 1)
    PROPOSAL_ID=$(echo "$PROPOSAL_OUTPUT" | grep -i proposal | grep -oE "[0-9]*")
    wait_for_proposal_execution "$testnet" "$PROPOSAL_ID"
    wait_for_subnet_to_resume '"x"'
)

success "Subnet started again successfully, passing last step of the test"

endtime="$(date '+%s')"
echo "$endtime" >"$experiment_dir/endtime"

echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$calltime"))"

# duration covers the time we had 4 nodes running
duration=$((endtime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

exit $exit_code
