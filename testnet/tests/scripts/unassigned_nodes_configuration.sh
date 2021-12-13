#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Unassigned Nodes configuration

Goal:: Ensure we can set SSH readonly keys and upgrade the unassigned nodes.

Description::
We deploy an IC with a set of unassigned nodes. Then we make a proposal and add an 
SSH key for the read-only access and set the replica version for unassigned nodes.
Then we make sure that unassgined nodes eventually upgrade to that version by
leveraging the SSH access.

Runbook::
. Deploy an IC with unassgined nodes
. Deploy a config for unassgined nodes with one SSH key and a replica version.
. ssh into one of the unassgined nodes and read the version file.

Success::
. At least one unassgined node has SSH enabled and runs the expected version.

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

if [[ -n "${TEST_NNS_URL-}" ]]; then
    nns_url="${TEST_NNS_URL}"
else
    HOSTS_INI_FILENAME="hosts_unassigned.ini"
    test -f "$PROD_SRC/env/$testnet/$HOSTS_INI_FILENAME" || (echo "Missing $HOSTS_INI_FILENAME for testnet $testnet, abort!" && exit 1)
    # Deploy the testnet
    deploy_with_timeout "$testnet" \
        --dkg-interval-length 19 --no-boundary-nodes --with-testnet-keys \
        --git-revision "$GIT_REVISION" --hosts-ini "$HOSTS_INI_FILENAME"

    nns_url=$(jq_hostvars '[._meta.hostvars[.nns.hosts[0]]]' 'map(.api_listen_url)[0]')
fi

echo "Testnet deployment successful. Test starts now."

set -x

UPGRADE_URL="https://download.dfinity.systems/ic/${GIT_REVISION}/guest-os/update-img/update-img-test.tar.gz"
UPGRADE_IMG="update-img-${GIT_REVISION}.tar.gz"

if [[ ! -r "${UPGRADE_IMG}" ]]; then
    curl "$UPGRADE_URL" --output "$UPGRADE_IMG"
fi

echo "Upgrade image is at: ${UPGRADE_IMG}"

VERSION="${GIT_REVISION}-test"

# Generate upgrade image and apply upgrade
echo "➡️  Triggering upgrade of unassigned nodes and adding of ssh keys"
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

    ic-admin --nns-url="$nns_url" propose-to-update-unassigned-nodes-config \
        --test-neuron-proposer --replica-version-id "$VERSION" \
        --ssh-readonly-access "$(
            ssh-add &>/dev/null
            ssh-add -L | tail -1
        )"
)

UNASSIGNED_NODE_ID="$(ic-admin --nns-url "$nns_url" get-topology | jq -r '.topology.unassigned_nodes[0].node_id')"
UNASSIGNED_NODE_IP="$(ic-admin --nns-url "$nns_url" get-node "$UNASSIGNED_NODE_ID" | sed -n 's/.*ip_addr: "\([^"]*\)".*/\1/p')"

SSH_OPTIONS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

n=0
while true; do
    DETECTED_VERSION="$(ssh "$SSH_OPTIONS" "readonly@$UNASSIGNED_NODE_IP" 'cat /opt/ic/share/version.txt')"
    if [[ "$DETECTED_VERSION" == "$VERSION" ]]; then
        echo "✅ SUCCESS! Unassigned node $UNASSIGNED_NODE_IP has the ssh readonly access enabled and is runnig version $VERSION."
        break
    else
        sleep 15
        n=$((n + 1))
        test "$n" -gt 100 && echo "Failed to detect replica version $VERSION on unassigned node $UNASSIGNED_NODE_IP" && exit 1
    fi
done

endtime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"
duration=$((endtime - starttime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."
