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

Title:: Recover From NNS Failure

Goal:: Demonstrate how a temporary IC can be used to create a new subnet which starts with the state of a broken NNS subnet

Runbook::
1. Start IC with at least one application subnet ("original NNS").
2. "Break" the NNS-subnet, and persist registry canister state (backup).
3. Start recovery IC with a "parent NNS" and an application subnet ("child NNS"), stop "child NNS"
4. Prepare local registry state (for "child NNS") consistent with NNS recovery CUP
5. Prepare and host tarball of the registry state that should be used at startup
6. Prepare NNS recovery CUP (for "child NNS") from the persisted "original NNS" state and from
7. Observe that "child NNS" restarts properly, and has the original NNS subnet state.

Success::
- "child NNS" runs as a NNS subnet
- finalization rate > threshold at most 1min after recovery proposal has been executed

end::catalog[]

DOC

set -euo pipefail

function exit_usage() {
    echo >&2 "Usage: $0 <testnet> <results_dir>"
    echo >&2 "$0 p2p_15 ./results/"
    exit 1
}

if (($# != 2)); then
    exit_usage
fi

testnet="$1"
results_dir="$(
    mkdir -p "$2"
    realpath "$2"
)"
experiment_subdir="${experiment_subdir-${testnet}_nns_subnet-recovery_$(date +%s)}"
experiment_dir="$results_dir/$experiment_subdir"

ORIGINAL_NNS_DATA="${ORIGINAL_NNS_DATA:-$experiment_dir/original_nns_data}"
NEW_REGISTRY_LOCAL_STORE="${NEW_REGISTRY_LOCAL_STORE:-$experiment_dir/new_registry_local_store}"
SCRATCH="$experiment_dir/scratch"

mkdir -p "$ORIGINAL_NNS_DATA" "$NEW_REGISTRY_LOCAL_STORE" "$SCRATCH"

# save stdout and stderr to file
# descriptors 3 and 4,
# then redirect them to "foo"
exec 3>&1 4>&2 2>&1 >"$experiment_dir/test_output.txt"
exec 1>&3 2>&4

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

mkdir -p "$experiment_dir/data_to_upload"
echo '
{
 "FinalizationRate": finalization_rate
}
' >>"$experiment_dir/data_to_upload/FinalizationRate.json"

# Store the time at which the test was called, so we can compute how long everything takes.
calltime="$(date '+%s')"
echo "Testcase Start time: $(dateFromEpoch "$calltime")"

################################################################################
###  Actual test steps (cf. Runbook above) start here.

SSH_ARGS=(-o "StrictHostKeyChecking=no" -o "NumberOfPasswordPrompts=0" -A)
RSYNC_ARGS="-e ssh ${SSH_ARGS[*]}"

export BIN_PATH="${REPO_ROOT}/artifacts/bin"
# Utility function for downloading pre-built artifacts (binaries)
function download_executable() {
    rclone --config="${REPO_ROOT}/.rclone-anon.conf" --progress --stats-one-line copyto \
        "public-s3:dfinity-download-public/ic/$GIT_REVISION/release/$1.gz" "$BIN_PATH/$1.gz"
    gunzip -k -f "$BIN_PATH/$1.gz"
    chmod +x "$BIN_PATH/$1"
}

IC_REPLAY="$REPO_ROOT/artifacts/bin/ic-replay"
IC_ADMIN="$REPO_ROOT/artifacts/bin/ic-admin"
IC_REGEDIT="$REPO_ROOT/artifacts/bin/ic-regedit"

set_verbosity

step 0 "Download requisite binaries" || time (
    download_executable "ic-replay"
    download_executable "ic-admin"
    download_executable "ic-regedit"

    echo OK
)

step 1 Create original IC on "${testnet}" || true

export HOSTS_INI_FILENAME=hosts_unassigned.ini
HOSTS_INI_ARGUMENTS=(--hosts-ini "$HOSTS_INI_FILENAME")
export HOSTS="$PROD_SRC/env/$testnet/hosts"

NNS_HOST="$(jq_hostvars 'map(select(.subnet_index==0) | .ansible_host)[0]')"
CHILD_NNS_HOST=$(jq_hostvars 'map(select(.subnet_index=="x") | .ansible_host)[0]')
NNS_URL=$(jq_hostvars '[._meta.hostvars[.nns.hosts[0]]]' 'map(.api_listen_url)[0]')
AUX_HOST=$(jq_hostvars 'map(select(.subnet_index=="aux") | .ansible_host)[0]')

step 1.A Deploy the original IC || time (
    deploy_with_timeout "$testnet" \
        --no-boundary-nodes \
        --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}" --dkg-interval-length 19
)

echo "Testnet deployment successful. Test starts now."

step 2 "Stop the NNS-subnet on [${testnet}], and persist the directory containing state and registry store." || true

NNS_TEMP_DIR="/tmp/nns-recovery-XXXXXXXXXXX/"

step 2.A "Break (Stop) NNS-subnet and save its state and registry data somewhere." || time (
    # shellcheck disable=SC2016
    echo "Saving DATA to $ORIGINAL_NNS_DATA"
    # The code below directly manipulates the ic replica service -- this is
    # brittle, we need a way to transition a node from/to "subnet recovery
    # mode" without referring to implementation details.
    ssh ${SSH_ARGS[@]} admin@"$NNS_HOST" <<EOF
sudo systemctl stop ic-replica
sudo rsync --delete -a /var/lib/ic/data $NNS_TEMP_DIR
sudo chown -R \$(whoami) $NNS_TEMP_DIR
EOF
    rsync -a admin@"[$NNS_HOST]:$NNS_TEMP_DIR" "$ORIGINAL_NNS_DATA" "$RSYNC_ARGS"
    cp -r "$ORIGINAL_NNS_DATA" "${ORIGINAL_NNS_DATA}_backup"
)

step 3 "Create parent IC on [${testnet}], and stop child NNS subnet" || true

step 3.A.1 "Deploy the parent IC" || time (
    deploy_with_timeout "$testnet" \
        --no-boundary-nodes \
        --dkg-interval-length 19 \
        --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}" \
        --ansible-args '-e ic_disk_gb=300'
)

step 3.A.2 "Increase the block rate" || time (
    set -x
    SUBNET_ID=$("$IC_ADMIN" --nns-url="$NNS_URL" get-subnet 0 | jq '.records[0].key' | sed "s/subnet_record_//" | xargs echo)
    "$IC_ADMIN" --nns-url "$NNS_URL" propose-to-update-subnet --subnet "$SUBNET_ID" --initial-notary-delay-millis 400 --test-neuron-proposer
)

ORIGINAL_NNS_ID=$("$IC_REGEDIT" snapshot "$ORIGINAL_NNS_DATA/data/ic_registry_local_store" | jq -r .nns_subnet_id.principal_id.raw | cut -d')' -f2-)

step 3.B "Create the new child nns subnet" || time (
    echo "Original nns id is: $ORIGINAL_NNS_ID"

    mapfile -d " " -t node_ids <<<"$($IC_ADMIN --nns-url "$NNS_URL" get-topology | jq -r '.topology.unassigned_nodes | map_values(.node_id) | join(" ")')"

    replica_version_id=$("$IC_ADMIN" --nns-url "$NNS_URL" get-subnet 0 | jq '.records[0].value.replica_version_id' -r)

    "$IC_ADMIN" \
        --nns-url "$NNS_URL" \
        propose-to-create-subnet \
        --test-neuron-proposer \
        --unit-delay-millis 2000 \
        --subnet-handler-id "unused" \
        --replica-version-id "$replica_version_id" \
        --subnet-id-override "$ORIGINAL_NNS_ID" \
        --dkg-interval-length 19 \
        --is-halted \
        --subnet-type system ${node_ids[@]} # We want node_ids to expand to multiple arguments
    until "$IC_ADMIN" --nns-url "$NNS_URL" get-subnet "$ORIGINAL_NNS_ID" 2>/dev/null >/dev/null; do
        echo "Waiting for subnet to be created"
        sleep 5
    done
)

step 4 "Prepare recovery CUP and local registry state" || true

function sync_registry_store() {
    rsync -a admin@"[$NNS_HOST]:/var/lib/ic/data/ic_registry_local_store/" "$NEW_REGISTRY_LOCAL_STORE" -a --delete "$RSYNC_ARGS"
}

step 4.A "Copy the new registry local store" || time (
    sync_registry_store

    while ! grep -q "$ORIGINAL_NNS_ID" <("$IC_REGEDIT" snapshot "$NEW_REGISTRY_LOCAL_STORE"); do
        # The registry data that we fetched was too old and did not include the just
        # added subnet
        echo "Registry data did not include the original subnet. Waiting for registry data to appear."
        sleep 5
        sync_registry_store
    done
)

IC_JSON="$SCRATCH/ic5.json"
step 4.B "Run ic-replay" || time (
    sed -e "s|PATH_TO_REPLACE|$ORIGINAL_NNS_DATA|g" <"$PROD_SRC/tests/scripts/ic.json5" >"$IC_JSON"

    echo "Running ic-replay"
    "$IC_REPLAY" --subnet-id "$ORIGINAL_NNS_ID" --canister-caller-id r7inp-6aaaa-aaaaa-aaabq-cai "$IC_JSON" add-registry-content "$NEW_REGISTRY_LOCAL_STORE" --verbose >"$SCRATCH/ic-replay-0.log"
    "$IC_REPLAY" --subnet-id "$ORIGINAL_NNS_ID" "$IC_JSON" update-registry-local-store >"$SCRATCH/ic-replay-1.log"
)

step 5 "Make registry store tarball and serve it over http" || true

step 5.A "Make the tarball" || time (
    tar -czvf "$SCRATCH/registry_store.tar.gz" -C "$ORIGINAL_NNS_DATA/data/ic_registry_local_store" .
)

step 5.B "Copy registry tarball to auxiliary http server host" || time (
    ssh ${SSH_ARGS[@]} admin@"$AUX_HOST" "mkdir -p /tmp/subnet_recovery_test/"
    rsync --delete -a "$SCRATCH/registry_store.tar.gz" admin@"[$AUX_HOST]":'/tmp/subnet_recovery_test/registry_store.tar.gz' "$RSYNC_ARGS"
)

step 5.C "Install daemonize and python on auxiliary http server host" || time (
    ssh ${SSH_ARGS[@]} admin@"$AUX_HOST" 'sudo apt update && sudo apt -y install daemonize python3'
)

step 5.D "Host the tarball using python" || time (
    ssh ${SSH_ARGS[@]} admin@"$AUX_HOST" 'daemonize $(which python3) -m http.server --bind :: 8081'
)

step 6 "Propose and execute recovery CUP" || true

REGISTRY_STORE_URI="http://[$AUX_HOST]:8081/tmp/subnet_recovery_test/registry_store.tar.gz"

function get_state_hash() {
    local state_hash
    state_hash=$(grep 'state hash' "$1" | tail -1 | cut -d':' -f2- | xargs)
    echo "$state_hash"
}

function get_registry_version() {
    local registry_version
    registry_version=$(grep 'Latest registry version' "$1" | tail -1 | cut -d':' -f2- | xargs)
    echo "$registry_version"
}

function get_checkpoint_height() {
    local checkpoint_height
    checkpoint_height=$(grep 'Latest checkpoint' "$1" | tail -1 | cut -d':' -f2- | xargs)
    echo "$checkpoint_height"
}

step 6.A "Propose recovery CUP" || time (
    TARBALL_HASH=$(sha256sum "$SCRATCH/registry_store.tar.gz" | cut -d ' ' -f 1)
    CHECKPOINT_HEIGHT=$(get_checkpoint_height "$SCRATCH/ic-replay-1.log")
    REGISTRY_VERSION=$(get_registry_version "$SCRATCH/ic-replay-1.log")
    STATE_HASH=$(get_state_hash "$SCRATCH/ic-replay-1.log")

    # While recovering the state from a backup pod, ic-replay performs fewer steps in step 4.B
    # In this scenario, the checkpoint height and the state hash are printed only into ic-replay-0.log
    # (and not ic-replay-1.log), hence the two lines below.
    CHECKPOINT_HEIGHT=${CHECKPOINT_HEIGHT:-$(get_checkpoint_height "$SCRATCH/ic-replay-0.log")}
    STATE_HASH=${STATE_HASH:-$(get_state_hash "$SCRATCH/ic-replay-0.log")}

    echo "Proposing cup with state hash: $STATE_HASH, TARBALL_HASH: $TARBALL_HASH, REGISTRY_VERSION: $REGISTRY_VERSION"
    "$IC_ADMIN" --nns-url="$NNS_URL" propose-to-update-recovery-cup \
        --subnet "$ORIGINAL_NNS_ID" --height $((CHECKPOINT_HEIGHT + 100)) --time-ns "$(date +%s%N)" \
        --state-hash "$STATE_HASH" --test-neuron-proposer \
        --registry-store-uri "$REGISTRY_STORE_URI" \
        --registry-store-hash "$TARBALL_HASH" \
        --registry-version "$REGISTRY_VERSION"
)

step 6.B "Restart node with new state" || time (
    echo "child host: $CHILD_NNS_HOST"
    # The code below directly manipulates the ic replica service -- this is
    # brittle, we need a way to transition a node from/to "subnet recovery
    # mode" without referring to implementation details.
    ssh ${SSH_ARGS[@]} admin@"$CHILD_NNS_HOST" <<EOF
	sudo mkdir /var/lib/ic/data/new_ic_state
	sudo chown -R admin /var/lib/ic/data/new_ic_state
EOF
    rsync --delete -a "$ORIGINAL_NNS_DATA/data/ic_state/" admin@"[$CHILD_NNS_HOST]":/var/lib/ic/data/new_ic_state "$RSYNC_ARGS"
    ssh ${SSH_ARGS[@]} admin@"$CHILD_NNS_HOST" <<EOF
    sudo systemctl stop ic-replica
	sudo chmod -R --reference=/var/lib/ic/data/ic_state /var/lib/ic/data/new_ic_state
	sudo chown -R --reference=/var/lib/ic/data/ic_state /var/lib/ic/data/new_ic_state
	sudo rm -r /var/lib/ic/data/ic_state
	sudo mv /var/lib/ic/data/new_ic_state /var/lib/ic/data/ic_state
    sudo systemctl start ic-replica
EOF
)

# Check finalization rate
step 7 "Check finalization rate" || time (
    wait_for_subnet_to_resume '"x"'
)

# Print the IPv6 that can be used with DFX
step 8 "Get child NNS host IPv6" || time (
    echo "CHILD_NNS_HOST is $CHILD_NNS_HOST"
)

success "Test completed successfully"

endtime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$endtime") (call time was $(dateFromEpoch "$calltime"))"
duration=$((endtime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."
