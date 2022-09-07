#!/bin/bash

set -e

source $(dirname "${BASH_SOURCE[0]}")/artifact-utils.sh

HTTP_PID=
HOST_IP_ADDR=

LOG_NNS=$(mktemp)
LOG_UPGRADE=$(mktemp)
SUBNET_IDX=0

for argument in "${@}"; do
    case ${argument} in
        -d | --debug)
            DEBUG=1
            ;;
        -h | --help)
            echo 'Usage:

Arguments:
  --origin-ip=          specify IP address from which we expect requests
  --nns-url=            specify NNS URL
  --subnet-url=         specify URL of machine in subnet to upgrade. Defaults to NNS URL.
  --upgrade-image=      Build the image to upgrade
  --ic-admin-bin=       ic-admin binary path
  --subnet=             Index of the subnetwork to upgrade, defaults to 0
'
            exit 1
            ;;
        --origin-ip=*)
            ORIGIN_IP_ADDR="${argument#*=}"
            # Perform a route lookup towards the given address (the IC node).
            # This will yield the local address used in order to communicate
            # with the IC nodes. This ensures that the address is usable as
            # http endpoint address for the update fetching.
            HOST_IP_ADDR=$(ip route get "${ORIGIN_IP_ADDR}" | sed -e 's/.*src \([^ ]*\).*/\1/' -e t -e d)
            shift
            ;;
        --nns-url=*)
            NNS_URL="${argument#*=}"
            shift
            ;;
        --subnet-url=*)
            SUBNET_URL="${argument#*=}"
            shift
            ;;
        --upgrade-image=*)
            UPGRADE_IMAGE="${argument#*=}"
            shift
            ;;
        --ic-admin-bin=*)
            IC_ADMIN_BIN="${argument#*=}"
            shift
            ;;
        --subnet=*)
            SUBNET="${argument#*=}"
            shift
            ;;
        --no-httpd)
            START_HTTPD=0
            shift
            ;;
        *)
            echo 'Error: Argument is not supported.'
            exit 1
            ;;
    esac
done

echo "Assuming HTTP server serving upgrades is comming up at $HOST_IP_ADDR"

SUBNET_URL="${SUBNET_URL:=$NNS_URL}"
SUBNET="${SUBNET:=0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "➡️  Testing Registry call"
retry_command 5 "$IC_ADMIN_BIN" --nns-url "${NNS_URL}" get-subnet $SUBNET | grep "replica_version"

echo "➡️  Looking up version number in upgrade tar"
VERSION=$(version_from_upgrade_image "${UPGRADE_IMAGE}")

echo "➡️  Upgrade subnetwork $SUBNET to $VERSION"
(
    # Print state in the registry before we propose to updated.
    # Do *NOT* fail the test if this goes wrong
    $IC_ADMIN_BIN --nns-url=$NNS_URL get-replica-version $VERSION || true
    $IC_ADMIN_BIN --nns-url=$NNS_URL get-subnet $SUBNET | grep replica_version || true

    retry_command 5 $IC_ADMIN_BIN --nns-url=$NNS_URL propose-to-update-subnet-replica-version \
        --test-neuron-proposer $SUBNET $VERSION | tee "$LOG_UPGRADE"

    sleep 5

    # This is just a sanity check. Don't fail test if it fails.
    $IC_ADMIN_BIN --nns-url=$NNS_URL get-subnet $SUBNET | grep replica_version || true

    rm "$LOG_UPGRADE"
)

NUM=0
echo "➡️  Waiting for version endpoint to change at: ${SUBNET_URL}/api/v2/status (takes up to 5 mins) "
date
echo -n "State: "
while ! curl -s ${SUBNET_URL}/api/v2/status --output - | egrep "impl_version..?$VERSION" -a; do
    NUM=$(($NUM + 1))

    if [[ $NUM -gt 200 ]]; then
        echo ""
        date

        echo "❌ Giving up"

        IPADDR=${SUBNET_URL/http:\/\/[/}
        IPADDR=${IPADDR/]:8080/}
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveCountMax=3 -o ServerAliveInterval=1 -o PasswordAuthentication=false "root@${IPADDR}" "journalctl -u ic-replica -r"

        echo "Terminating"
        exit 1

    fi

    echo -n "."
    sleep 5
done

echo ""
date
echo "✅ Upgrade success (to $VERSION)"

exit 0
