#!/bin/bash

set -e

source $(dirname "${BASH_SOURCE[0]}")/artifact-utils.sh

HTTP_PID=
HOST_IP_ADDR=

LOG_NNS=$(mktemp)
LOG_UPGRADE=$(mktemp)
SUBNET_IDX=0
SECOND_UPGRADE=0

set -x

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
  --upgrade-image=      Build the image to upgrade
  --ic-admin-bin=       ic-admin binary path
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
        --upgrade-image=*)
            UPGRADE_IMAGE="${argument#*=}"
            shift
            ;;
        --ic-admin-bin=*)
            IC_ADMIN_BIN="${argument#*=}"
            shift
            ;;
        *)
            echo 'Error: Argument is not supported.'
            exit 1
            ;;
    esac
done

[ -n "$HOST_IP_ADDR" ] || {
    echo "Missing --origin-ip address, aborting"
    exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "Assuming HTTP server serving upgrades is comming up at $HOST_IP_ADDR"

SUBNET_URL="${SUBNET_URL:=$NNS_URL}"
SUBNET="${SUBNET:=0}"

echo "➡️  Testing Registry call"
retry_command 5 "$IC_ADMIN_BIN" --nns-url "${NNS_URL}" get-subnet $SUBNET | grep "replica_version"

echo "➡️  Starting HTTP server to serve upgrade $UPGRADE_IMAGE"
(
    cd "$(dirname $UPGRADE_IMAGE)"
    kill $(ss -plant | grep ':\<8000\>' | grep pid=[0-9]* -o | awk -F= '{ print $2 }') || true
    python3 -m http.server 8000 --bind ::
) &
HTTP_PID=$!

echo "➡️  Looking up version number for $UPGRADE_IMAGE"
VERSION=$(version_from_upgrade_image "${UPGRADE_IMAGE}")

# Checks if the given IP contains any ":" characters that might be
# confused for the "port" separator. If that is the case, enclose
# the address using [] to disambiguate.
function quote_ip() {
    echo "$1" | sed -e 's/\(.*:.*\)/[\1]/'
}

echo "➡️  Bless upgrade $VERSION"
(
    UPGRADE="$UPGRADE_IMAGE"
    UPGRADE_IMAGE_NAME=$(basename "$UPGRADE_IMAGE")
    UPGRADE_URL="http://$(quote_ip "${HOST_IP_ADDR}"):8000/${UPGRADE_IMAGE_NAME}"

    SHA256=$(sha256sum "$UPGRADE" | awk '{ print $1}')
    echo "Checksum is: ${SHA256}"
    echo -n "Checksum downloading via URL: "
    curl "$UPGRADE_URL" | sha256sum || {
        echo "Failed to download upgrade image, aborting"
        exit 1
    }

    LOG_BLESSING=$(mktemp)
    retry_command 5 $IC_ADMIN_BIN --nns-url $NNS_URL propose-to-bless-replica-version-flexible \
        --test-neuron-proposer $VERSION foo foo foo foo \
        $UPGRADE_URL $SHA256 2>&1 | tee "$LOG_BLESSING"
)

echo "✅ Proposal success (for $VERSION) (time: $(date))"
exit 0
