#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: NNS Backup

Goal:: Ensure NNS backup and replay tools work

Description::
In this test we deploy a one node NNS network and trigger an upgrade (we do this
to obtain a "cut" in the backup, so that we can not only test the recovery from
the backup created by a single version, but also across multiple versions.
After the upgrade, we pull the backed up artifacts and run the replay tool on them.

Runbook::
. set up the testnet (nns + subnet installation)
. trigger an upgrade of the nns subnet
. pull backed up artifacts and run replay tool on them

Success::
. the replay tool was able to restore the state from all pulled backup artifacts, including those created after the upgrade.

end::catalog[]
DOC

set -euo pipefail

function exit_usage() {
    echo >&2 "Usage: $0 <testnet>  <results_dir>"
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
experiment_dir="$results_dir/${testnet}-$(date +%s)"
export experiment_dir

# shellcheck disable=SC1090
source "${HELPERS:-$(dirname "${BASH_SOURCE[0]}")/include/helpers.sh}"

starttime="$(date '+%s')"
echo "Start time: $(dateFromEpoch "$starttime")"

# Determine the URL of the NNS
HOSTS_INI_ARGUMENTS=()

if [[ -n "${TEST_NNS_URL-}" ]]; then
    nns_url="${TEST_NNS_URL}"
else
    # Deploy the testnet
    deploy_with_timeout "$testnet" \
        --no-boundary-nodes \
        --with-testnet-keys \
        --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}"

    nns_url=$(jq_hostvars '[._meta.hostvars[.nns.hosts[0]]]' 'map(.api_listen_url)[0]')
fi

echo "Testnet deployment successful. Test starts now."

set -x

# First we speed up the NNS, so that we do not need to wait for CUP height for too long.
SUBNET=0 # NNS
SUBNET_ID=$(ic-admin --nns-url="$nns_url" get-subnet "$SUBNET" | jq '.records[0].key' | sed "s/subnet_record_//" | xargs echo)

echo "➡️  Increase the block rate"
(
    set -x

    ic-admin --nns-url "$nns_url" propose-to-update-subnet --subnet "$SUBNET_ID" --initial-notary-delay-millis 400 --test-neuron-proposer
)

# Because this a self-upgrade test, we need to download the guest-os for this version
UPGRADE_URL="https://download.dfinity.systems/ic/${GIT_REVISION}/guest-os/update-img/update-img-test.tar.gz"
UPGRADE_IMG="update-img-${GIT_REVISION}.tar.gz"

if [[ ! -r "${UPGRADE_IMG}" ]]; then
    curl "$UPGRADE_URL" --output "$UPGRADE_IMG"
fi

echo "Upgrade image is at: ${UPGRADE_IMG}"

PRE_UPGRADE_VERSION="${GIT_REVISION}"
VERSION="${GIT_REVISION}-test"

# Generate upgrade image and apply upgrade
echo "➡️  Triggering upgrade"
(
    set -x

    LOG_BLESSING=$(mktemp)

    SHA256=$(sha256sum "$UPGRADE_IMG" | awk '{ print $1}')
    echo "Checksum is: ${SHA256}"

    ic-admin --nns-url "$nns_url" propose-to-bless-replica-version-flexible \
        --test-neuron-proposer "$VERSION" foo foo foo foo \
        "$UPGRADE_URL" "$SHA256" 2>&1 | tee "$LOG_BLESSING"

    until ic-admin --nns-url "$nns_url" get-blessed-replica-versions | grep -q "$VERSION"; do
        echo "Waiting for the blessed replica version to appear..."
        sleep 5
    done

    ic-admin --nns-url="$nns_url" propose-to-update-subnet-replica-version \
        --test-neuron-proposer "$SUBNET" "$VERSION"
)

NUM=0
echo "➡️  Waiting for version endpoint to change at: ${nns_url}/api/v2/status (takes up to 5 mins)"
echo -n "State: "
while ! curl -s "${nns_url}/api/v2/status" --output - | grep "impl_version.*$VERSION" -a; do
    NUM=$((NUM + 1))

    if [[ $NUM -gt 200 ]]; then
        echo ""
        echo "❌ Giving up - upgrade failed"
        exit 1
    fi
    echo -n "."
    sleep 5
done

# Ensure we kill all background processes on CTRL+C
# shellcheck disable=SC2064
trap "echo 'SIGINT received, killing all jobs'; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1" INT

nns_ip=${nns_url/http:\/\/[/}
nns_ip=${nns_ip/]:8080/}

# Retrieve all data required for the backup recovery.
ssh-keygen -R "$nns_ip"
scp -o StrictHostKeyChecking=no -r "admin@[${nns_ip}]:/run/ic-node/config/ic.json5" "${results_dir}"
set +e
rsync -az "backup@[${nns_ip}]:/var/lib/ic/backup/" "${results_dir}/backup/"
rsync -az "admin@[${nns_ip}]:/var/lib/ic/data/ic_registry_local_store/" "${results_dir}/ic_registry_local_store/"
set -e

sed -i "s#/var/lib/ic/#$results_dir/restored/var/lib/ic/#" "$results_dir/ic.json5"
mkdir -p "$results_dir/restored/var/lib/ic/data/"

# shellcheck disable=SC2012
POST_UPGRADE_HEIGHT=$(ls -1v "$results_dir/backup/$SUBNET_ID/$VERSION/0/" | head -1)

# Recover the state from the artifacts created by the version before the upgrade.
echo y | ic-replay "$results_dir/ic.json5" --subnet-id "$SUBNET_ID" restore-from-backup "$results_dir/ic_registry_local_store/" "$results_dir/backup" "$PRE_UPGRADE_VERSION" 0 &>"$results_dir/backup.log"

# Check that the replay correctly recognized an upgrade.
if ! grep -q "continue backup recovery from height" "$results_dir/backup.log"; then
    echo "❌ Backup recovery failed."
    exit 1
fi

SUCCESS=0
retries=25
for ((c = 1; c <= retries; c++)); do
    # Sync the backup again
    set +e
    rsync -az "backup@[${nns_ip}]:/var/lib/ic/backup/" "${results_dir}/backup/"
    set -e
    # Recover the state from the artifacts created by the version after the upgrade.
    ic-replay "$results_dir/ic.json5" --subnet-id "$SUBNET_ID" restore-from-backup "$results_dir/ic_registry_local_store/" "$results_dir/backup" "$VERSION" "$POST_UPGRADE_HEIGHT" &>>"$results_dir/backup_post_upgrade.log"
    # Ensure we were able to find at least one CUP
    if grep -q "Found a CUP" "$results_dir/backup_post_upgrade.log"; then
        SUCCESS=1
        break
    fi
    echo "No CUP was produced yet; retrying... ($c/$retries)"
    sleep 5
done

# Ensure the state computation did not diverge on a CUP.
if grep -q "does not correspond" "$results_dir/backup_post_upgrade.log"; then
    echo "❌ State computation diverged."
    exit 1
fi

if test $SUCCESS = "1"; then
    echo "✅ Backup recovery succeeded."
else
    echo "❌ Backup recovery failed on post-upgrade artifacts."
    exit 1
fi

endtime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

duration=$((endtime - starttime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."
