#!/usr/bin/env bash

: <<'DOC'
tag::catalog[]

Title:: Upgrade Reject on a Hash Mismatch

Goal:: Ensure a subnet does not upgrade if the hash of the release package does not match.

Description::

Runbook::
. set up the testnet
. trigger an upgrade of the nns subnet with a broken hash
. make sure the replicas log an error

Success::
. Replicas log failures about hash mismatch

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
hosts_file_path="$PROD_SRC/env/$testnet/hosts"
HOSTS_INI_ARGUMENTS=()

if [[ -n "${TEST_NNS_URL-}" ]]; then
    nns_url="${TEST_NNS_URL}"
else
    # Deploy the testnet
    deploy_with_timeout "$testnet" \
        --dkg-interval-length 19 \
        --git-revision "$GIT_REVISION" "${HOSTS_INI_ARGUMENTS[@]}"

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
fi

echo "Testnet deployment successful. Test starts now."

# First we speed up the NNS, so that we do not need to wait for CUP height for too long.
SUBNET=0 # NNS

# Because this a self-upgrade test, we need to download the guest-os for this version
UPGRADE_URL="https://download.dfinity.systems/ic/${GIT_REVISION}/guest-os/update-img/update-img-test.tar.gz"
UPGRADE_IMG="update-img-${GIT_REVISION}.tar.gz"

if [[ ! -r "${UPGRADE_IMG}" ]]; then
    curl "$UPGRADE_URL" --output "$UPGRADE_IMG"
fi

echo "Upgrade image is at: ${UPGRADE_IMG}"

VERSION="${GIT_REVISION}-test"

# Generate upgrade image and submit a proposal with a broken hash
echo "➡️  Triggering upgrade"
(
    LOG_BLESSING=$(mktemp)

    # This hash is a hardcoded value of "0", which should differ from the hash of the new image.
    SHA256="9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa"
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

# Ensure we kill all background processes on CTRL+C
# shellcheck disable=SC2064
trap "echo 'SIGINT received, killing all jobs'; jobs -p | xargs -rn1 pkill -P >/dev/null 2>&1; exit 1" INT

nns_ip=${nns_url/http:\/\/[/}
nns_ip=${nns_ip/]:8080/}

SSH_ARGS=(-o "StrictHostKeyChecking=no" -o "NumberOfPasswordPrompts=0" -A)
NUM=0
until ssh "${SSH_ARGS[@]}" "readonly@$nns_ip" 'journalctl -u ic-replica --since "30m ago" |grep -qi FileHashMismatchError'; do
    NUM=$((NUM + 1))

    echo "Waiting for a replica to report a hash mismatch..."
    if [[ $NUM -gt 200 ]]; then
        echo ""
        echo "❌ Giving up"
        exit 1
    fi
    echo -n "."
    sleep 5
done

echo "SUCCESS!"

# Clean up the testnet by freeing up resources used by replicas
"$REPO_ROOT/testnet/tools/icos_destroy.sh" "$testnet"
echo "Cleaning up testnet finished."

endtime="$(date '+%s')"
echo "Ending tests *** $(dateFromEpoch "$endtime") (start time was $(dateFromEpoch "$starttime"))"

duration=$((endtime - starttime))
echo "$((duration / 60)) minutes and $((duration % 60)) seconds elapsed."
