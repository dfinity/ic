#!/bin/bash

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")
source $BASE_DIR/scripts/helpers.sh

# Early draft of a script to trigger upgrades.
# This has to customized, as it currently is tailored for Stefan's setup.
function error() {
    echo $1
    exit 1
}

# --------------------------------------------------
# CONFIGURATION

# Note, the script assumes that there is a webserver running serving the
# upgrade image at http://$IP:8000/upgrade-image.tar.

# Can do:
# (cd /tmp/upgrade-image; python -m http.server 8000 --bind ::)
# to start one
# Get keyword arguments

UPGRADE_IMAGE=${UPGRADE_IMAGE:-}

for argument in "${@}"; do
    case ${argument} in
        -d | --debug)
            DEBUG=1
            ;;
        -h | --help)
            echo 'Usage:

   ____  _____ ___ _   _ ___ _______   __
  |  _ \|  ___|_ _| \ | |_ _|_   _\ \ / /
  | | | | |_   | ||  \| || |  | |  \ V /
  | |_| |  _|  | || |\  || |  | |   | |
  |____/|_|   |___|_| \_|___| |_|   |_|

    Internet Computer Operating System
              Upgrade tool

Arguments:
  -v,  --version        specify new guest OS version ID (Default: Timestamp Unix Epoch)
  --nns-url=            specify NNS URL
  --upgrade-url=        specify URL where the upgrade base URL is available
  --upgrade-image=      Build the image to upgrade
'
            exit 1
            ;;
        --nns-url=*)
            NNS_URL="${argument#*=}"
            shift
            ;;
        --upgrade-url=*)
            UPGRADE_URL="${argument#*=}"
            shift
            ;;
        --upgrade-image=*)
            UPGRADE_IMAGE="${argument#*=}"
            shift
            ;;
        -v=* | --version=*)
            VERSION="${argument#*=}"
            shift
            ;;
        *)
            echo 'Error: Argument is not supported.'
            exit 1
            ;;
    esac
done

[ -n "$UPGRADE_URL" ] || error "Need to provide upgrade url as argument --upgrade-url"
[ -n "$NNS_URL" ] || error "Need to provide NNS url as argument --nns-url"

# --------------------------------------------------

# Below this lie shouldn't need any changes

set -x
set -e
#set -u

DEFAULT_VERSION=$(date +%s)
VERSION="${VERSION:=$DEFAULT_VERSION}"

if [[ -n "$UPGRADE_IMAGE" ]]; then
    UPGRADE="$UPGRADE_IMAGE"
else
    UPGRADEDIR="/tmp/upgrade-image/"
    UPGRADE="$UPGRADEDIR/upgrade-image.tar"

    [ -d "$UPGRADEDIR" ] || mkdir "$UPGRADEDIR"
    rm -f "${UPGRADEDIR}/*"

    echo -n $VERSION >rootfs/opt/ic/share/version.txt
    scripts/build-ubuntu.sh -o "$UPGRADE"
fi

SHA256=$(sha256sum "$UPGRADE" | awk '{ print $1}')
echo "Checksum is: ${SHA256}"

if [[ -z "$UPGRADE_IMAGE" ]]; then
    echo "Waiting for image to be deployed. Hit any key then"
    read -r -n 1
fi

export TMP=$(mktemp -d)
download_binaries

$TMP/ic-admin --nns-url $NNS_URL propose-to-bless-replica-version-flexible \
    --test-neuron-proposer $VERSION \
    $UPGRADE_URL $SHA256 2>&1 | tee $TMP/blessing.log

export PROPOSAL_ID=$(grep '^proposal' $TMP/blessing.log | awk '{print $2}')
echo "Assuming proposal ID is $PROPOSAL_ID"
sleep 5

$TMP/ic-admin --nns-url=$NNS_URL forward-test-neuron-vote ${PROPOSAL_ID}
$TMP/ic-admin --nns-url=$NNS_URL execute-eligible-proposals

echo "Waiting 30 seconds, just to be sure"
sleep 30

$TMP/ic-admin --nns-url=$NNS_URL get-replica-version $VERSION
$TMP/ic-admin --nns-url=$NNS_URL get-subnet 0 | grep replica_version

$TMP/ic-admin --nns-url=$NNS_URL propose-to-update-subnet-replica-version \
    --test-neuron-proposer 0 $VERSION | tee $TMP/blessing.log

export PROPOSAL_ID=$(grep '^proposal' $TMP/blessing.log | awk '{print $2}')
echo "Assuming proposal ID is $PROPOSAL_ID"
sleep 5

$TMP/ic-admin --nns-url=$NNS_URL forward-test-neuron-vote ${PROPOSAL_ID}
$TMP/ic-admin --nns-url=$NNS_URL execute-eligible-proposals

$TMP/ic-admin --nns-url=$NNS_URL get-subnet 0 | grep replica_version

rm -rf $TMP
