#!/usr/bin/env bash
# We use subshells to isolate code.  Shellcheck is concerned that changes are meant to be global.
# shellcheck disable=SC2030,SC2031,SC2154
# We prefer to use sed
# shellcheck disable=SC2001

: <<'DOC'
tag::catalog[]

Title:: Recover From The Deployment of a No-Op NNS subnet by loading a new CatchUpPackage.

Goal:: Demonstrate that NNS can be recovered without changing node membership when keys are still intact.

Runbook::
. Start ic with NNS.
. Upgrade nns to a version that does not produce blocks.
. Use ic-replay to update registry to include a new replica version, and produce a new CUP.
. Load the new CUP (together with registry local store and canister states) manually on all NNS nodes.
. Observe that NNS subnet restarts and continues functioning.

Success::
- finalization rate > threshold at most 1min after recovery proposal has been executed
end::catalog[]

S3 artifacts from MR 2067 https://gitlab.com/dfinity-lab/public/ic/-/merge_requests/2067
are used in step 2. For this test to pass, that MR's branch must be backwards
compatible with the version under test. In case of a breaking change (or two
non-breaking changes that violate backwards compatibility together), it is
thus necessary to merge master into branch 'broken-blockmaker' This is a
temporary solution.
DOC

set -euo pipefail
export exit_code=0

if (($# != 2)); then
    echo >&2 "Wrong number of arguments, please provide values for <testnet> <results_dir>"
    exit 1
fi

SSH_OPTIONS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
RSYNC_ARGS="-e ssh $SSH_OPTIONS"
testnet="$1"
results_dir="$(
    mkdir -p "$2"
    realpath "$2"
)"
nns_subnet_index=0
experiment_dir="${EXPERIMENT_DIR:-$results_dir/disaster_recovery_basic_test-${testnet}-$(date +%s)}"
mkdir -p "$experiment_dir"

ORIGINAL_NNS_DATA="${ORIGINAL_NNS_DATA:-$experiment_dir/original_nns_data}"
NEW_REGISTRY_LOCAL_STORE="${NEW_REGISTRY_LOCAL_STORE:-$experiment_dir/new_registry_local_store}"

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

calltime="$(date '+%s')"
echo "Testcase call time: $(dateFromEpoch "$calltime")"

BIN_DIR="${results_dir}/bin"
export PATH="$PATH:$BIN_DIR"
mkdir -p "$BIN_DIR"

# Utility function for downloading pre-built artifacts (binaries)
function download_executable() {
    download_agent_rs_binaries "$BIN_DIR"
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
        --test-neuron-proposer "$version" \
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

function wait_for_subnet_to_stop() {
    local subnet=${1:-1}
    while true; do
        endtime="$(date '+%s')"
        duration=60
        collect_metrics "$subnet"
        finalization_rate="$(jq -r '.data.result[0].value[1]' <"$experiment_dir/metrics/artifact_pool_consensus_height_stat_avg_total.json")"
        echo "Finalization rate = $finalization_rate"
        test "$finalization_rate" = "0" && break
        sleep 5
    done
}

set_verbosity

################################################################################
# 0. Download tools & binaries
################################################################################
step 0 "Download requisite binaries" || time (
    download_executable
    echo OK
)

################################################################################
# 1. Start ic with at least one application subnet
################################################################################
step 1 Create IC on "$testnet" || true

step 1.A Deploy IC || time (
    HOSTS_INI_FILENAME="${HOSTS_INI_FILENAME:-hosts.ini}"
    test -f "$PROD_SRC/env/$testnet/$HOSTS_INI_FILENAME" || (echo "Missing $HOSTS_INI_FILENAME for testnet $testnet, abort!" && exit 1)
    setvar HOSTS_INI_FILENAME "$HOSTS_INI_FILENAME"
    "$PROD_SRC/tools/icos_deploy.sh" --no-boundary-nodes --dkg-interval-length 19 --git-revision "$GIT_REVISION" --hosts-ini "$HOSTS_INI_FILENAME" "$testnet"
)

step 1.B Get NNS_URL || time (

    NNS_URL=$(
        cd "$PROD_SRC" \
            && "env/$testnet/hosts" --list | jq -L./jq -r \
                "import \"ansible\" as ansible; . as \$o | .nns.hosts[0] | \$o._meta.hostvars[.] * \$o.nodes.vars | ansible::interpolate | .api_listen_url"
    )
    echo "Set NNS_URL to $NNS_URL"

    TARGET_SUBNET=$(ic-admin --nns-url="$NNS_URL" get-subnet "$nns_subnet_index" | jq -r .records[0].key | sed 's/subnet_record_//')

    echo "Target NNS subnet is $TARGET_SUBNET"

    setvar NNS_URL "$NNS_URL"
    setvar TARGET_SUBNET "$TARGET_SUBNET"
)

step 1.C Calculate membership || time (
    TOPOLOGY=$(ic-admin --nns-url "$NNS_URL" get-topology)
    SUBNET_INFO=$(echo "$TOPOLOGY" | jq ".topology.subnets[\"$TARGET_SUBNET\"]")
    MEMBERS=$(echo "$SUBNET_INFO" | jq .records[0].value.membership[] | sed -e 's/"//g' | xargs)
    echo "MEMBERS: $MEMBERS"

    # shellcheck disable=SC2068
    MEMBER_IPS=$(for node_id in $MEMBERS; do ic-admin --nns-url "$NNS_URL" get-node "$node_id" | tail -n1 | sed -e 's/^.* ip_addr: "\([^"]*\)".*$/\1/'; done | xargs)
    # shellcheck disable=SC2068
    echo "MEMBER_IPS: $MEMBER_IPS"
    setvar MEMBERS "$MEMBERS"
    setvar MEMBER_IPS "$MEMBER_IPS"
)

################################################################################
# 2. Upgrade subnet to version that does not produce blocks
################################################################################

step 2 Upgrade NNS to \"broken blockmaker\" || true

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
                "import \"ansible\" as ansible; . as \$o | .nns.hosts[0] | \$o._meta.hostvars[.] * \$o.nodes.vars | ansible::interpolate | .api_listen_url"
    )
    n=0
    while true; do
        curl -k --silent "$HOST_URL/api/v2/status" 2>&1 | grep "$ic_version_broken_blockmaker" && break
        sleep 5
        n=$((n + 1))
        test "$n" -gt 100 && echo "Failed to detect replica version $ic_version_broken_blockmaker on subnet" && exit 1
    done
    wait_for_subnet_to_stop "$nns_subnet_index"
)

step 3 "Make recovery CUP and registry local store" || true

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

step 3.B Copy state to localhost || time (
    NNS_HOST="$(echo "$MEMBER_IPS" | cut -d' ' -f1)"
    NNS_TEMP_DIR="/tmp/nns-recovery-XXXXXXXXXXX/"
    echo "Saving DATA to $ORIGINAL_NNS_DATA"
    #shellcheck disable=SC2086,SC2087
    ssh ${SSH_OPTIONS} admin@"$NNS_HOST" <<EOF
sudo systemctl stop ic-replica
sudo rsync --delete --exclude=images -a /var/lib/ic/data $NNS_TEMP_DIR
sudo chown -R \$(whoami) $NNS_TEMP_DIR
cp /run/ic-node/config/ic.json5 $NNS_TEMP_DIR
EOF
    rsync -a --delete admin@"[$NNS_HOST]:$NNS_TEMP_DIR" "$ORIGINAL_NNS_DATA" "$RSYNC_ARGS"
)

step 3.C "Run ic-replay" || time (
    IC_JSON=$(mktemp "$ORIGINAL_NNS_DATA/ic.json5-XXXXX")
    sed -e 's|/var/lib/ic/|.\/|' <"$ORIGINAL_NNS_DATA/ic.json5" >"$IC_JSON"
    cd "$ORIGINAL_NNS_DATA"
    replica_version_record=$(
        cat <<END
{ "release_package_url": "https://download.dfinity.systems/ic/$ic_version_working/guest-os/update-img/update-img.tar.gz",
  "release_package_sha256_hex": "$ic_version_working_sha256"
}
END
    )
    ic-replay --subnet-id "$TARGET_SUBNET" "$IC_JSON" add-and-bless-replica-version --update-subnet-record "$ic_version_working" "$replica_version_record" >"$experiment_dir/ic-replay-0.log"
    STATE_HASH=$(grep 'state hash' "$experiment_dir/ic-replay-0.log" | tail -n1 | cut -d':' -f2- | xargs)
    HEIGHT=$(grep 'Latest checkpoint at height:' "$experiment_dir/ic-replay-0.log" | tail -n1 | cut -d':' -f2- | xargs)
    setvar IC_JSON "$IC_JSON"
    setvar STATE_HASH "$STATE_HASH"
    setvar HEIGHT "$HEIGHT"
)

step 3.D "Create registry local store and state tarballs" || time (
    # This won't change state hash
    cd "$ORIGINAL_NNS_DATA"
    ic-replay --subnet-id "$TARGET_SUBNET" "$IC_JSON" update-registry-local-store >"$experiment_dir/ic-replay-1.log"
    tar -C "$ORIGINAL_NNS_DATA/data" -zcf "$experiment_dir/ic_registry_local_store.tar.gz" ic_registry_local_store
    tar -C "$ORIGINAL_NNS_DATA/data" -zcf "$experiment_dir/ic_state.tar.gz" ic_state
)

step 3.E "Create CUP" || time (
    # The state after the following ic-replay command will be disregarded, since we don't
    # need the recovery CUP to be in the registry canister or local store. Only the CUP
    # file is important.
    cd "$ORIGINAL_NNS_DATA"
    NNS_HOST="$(echo "$MEMBER_IPS" | cut -d' ' -f1)"
    ic-replay --subnet-id "$TARGET_SUBNET" "$IC_JSON" set-recovery-cup "$STATE_HASH" "$HEIGHT" >"$experiment_dir/ic-replay-2.log"
    ic-replay --subnet-id "$TARGET_SUBNET" "$IC_JSON" update-registry-local-store >"$experiment_dir/ic-replay-3.log"
    ic-admin --nns-url "$NNS_URL" get-recovery-cup "$TARGET_SUBNET" --registry-local-store "$ORIGINAL_NNS_DATA/data/ic_registry_local_store" --output-file "$experiment_dir/cup.proto" >/dev/null
)

step 4 "Copy CUP, state and registry local store to NNS nodes and restart" || time (
    TMP_DIR=/tmp/disaster_recovery_test
    for node_ip in $MEMBER_IPS; do
        echo Copying data and restarting dfinity service on "$node_ip"
        #shellcheck disable=SC2086,SC2029
        ssh $SSH_OPTIONS "admin@$node_ip" "sudo rm -rf $TMP_DIR && mkdir $TMP_DIR"
        #shellcheck disable=SC2086,SC2029
        scp $SSH_OPTIONS \
            "$experiment_dir/cup.proto" \
            "$experiment_dir/ic_registry_local_store.tar.gz" \
            "$experiment_dir/ic_state.tar.gz" "admin@[$node_ip]:$TMP_DIR/"
        #shellcheck disable=SC2086,SC2029,SC2087
        ssh $SSH_OPTIONS "admin@$node_ip" <<EOF
cd $TMP_DIR
OWNER_UID=\$(sudo stat -c '%u' /var/lib/ic/data/ic_registry_local_store)
GROUP_UID=\$(sudo stat -c '%g' /var/lib/ic/data/ic_registry_local_store)
tar zxf ic_registry_local_store.tar.gz
sudo chown -R "\$OWNER_UID:\$GROUP_UID"  ic_registry_local_store

OWNER_UID=\$(sudo stat -c '%u' /var/lib/ic/data/ic_state)
GROUP_UID=\$(sudo stat -c '%g' /var/lib/ic/data/ic_state)
tar zxf ic_state.tar.gz
sudo chown -R "\$OWNER_UID:\$GROUP_UID"  ic_state

OWNER_UID=\$(sudo stat -c '%u' /var/lib/ic/data/cups)
GROUP_UID=\$(sudo stat -c '%g' /var/lib/ic/data/cups)
sudo chown -R "\$OWNER_UID:\$GROUP_UID" cup.proto

sudo systemctl stop ic-replica
sudo rsync -a --delete ic_registry_local_store/ /var/lib/ic/data/ic_registry_local_store/
sudo rsync -a --delete ic_state/ /var/lib/ic/data/ic_state/
sudo cp cup.proto /var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb
sudo cp cup.proto /var/lib/ic/data/cups/cup_${TARGET_SUBNET}.types.v1.CatchUpPackage.pb
sudo systemctl start ic-replica
EOF
    done
)

step 5 "Check if NNS has resumed" || time (
    wait_for_subnet_to_resume "$nns_subnet_index"
)

success "Subnet started again successfully, passing last step of the test"

endtime="$(date '+%s')"
echo "$endtime" >"$experiment_dir/endtime"

echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$calltime"))"

# duration covers the time we had 4 nodes running
duration=$((endtime - calltime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."

exit $exit_code
