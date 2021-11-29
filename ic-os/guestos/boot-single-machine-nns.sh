#!/bin/bash

# Inspired by: ic_nns_install.yml

BASE_DIR=$(dirname "${BASH_SOURCE[0]}")
# shellcheck source=scripts/helpers.sh
source "${BASE_DIR}"/scripts/helpers.sh

function error() {
    echo "$1"
    exit 1
}

VPN_IP6=::1

[[ -n "$VPN_IP6" ]] || error "Please specify IPv6 address as third argument"

if [[ -n "$1" ]]; then
    TMP="$1"
    if [[ ! -d "$1" ]]; then
        mkdir "$TMP"
    fi
else
    TMP=$(mktemp -d)
fi

if [[ -n "$2" ]]; then
    STATE_SRC=$2
fi

# We are deploying the NNS subnetwork
SUBNET_IDX=0

download_binaries

(
    source scripts/fetch-dfinity-binaries.sh
    get_dfinity_binaries
    REPLICA_HASH=$(sha256sum rootfs/opt/ic/bin/replica | cut -d " " -f 1)
    NM_HASH=$(sha256sum rootfs/opt/ic/bin/nodemanager | cut -d " " -f 1)
    # Generate key material
    # See subnet_crypto_install, line 5

    if [[ ! -f "$TMP/subnet_list.pb" ]]; then

        "$TMP/ic-prep" \
            "--working-dir" "$TMP" \
            "--replica-download-url" "file:///opt/ic/bin/replica" \
            "--replica-hash" "$REPLICA_HASH" \
            "--nodemanager-download-url" "file:///opt/ic/bin/nodemanager" \
            "--nodemanager-hash" "$NM_HASH" \
            "--nns-subnet-index" "0" \
            "--dkg-interval-length" "5" \
            "--p2p-flows" "1234-1" \
            "--nodes" "0-${SUBNET_IDX}-[${VPN_IP6}]:4100-[${VPN_IP6}]:2497-0-[${VPN_IP6}]:8080"
    fi
) || error "Failed to run ic-prep"
# Not sure if 0 as the node_index works here - let's see

ls "${TMP}"
echo "--------------------------------------------------"
ls "${TMP}/node-0"

DERIVED_NODE_ID=$(cat "${TMP}/node-0/derived_node_id")
echo "Derived node ID is ${DERIVED_NODE_ID}"

# Generate tarball
# --------------------------------------------------

TARBALL_TMP=$(mktemp -d)

mkdir -p ${TARBALL_TMP}/node/replica_config

# Not sure where the gatway address comes from.
# Got it from QEMU after doing dhclient.
"${BASE_DIR}"/scripts/build-bootstrap-config-image.sh ./vm.img \
    --ipv6_address fd00:2:1:1:1::51/64 \
    --ic_crypto ${TMP}/node-0/crypto/ \
    --ic_registry_local_store ${TMP}/ic_registry_local_store \
    --nns_public_key ${TMP}/nns_public_key.pem \
    || error "Failed to run build bootstrap config"

# Forwarding of http port in the other direction.

# Fetch binaries
# --------------------------------------------------

# debugfs

# Debugging stuff
# --------------------------------------------------
# cat rootfs/etc/dfinity/ic_crypto/crypto/public_keys.pb | protoc --decode_raw

echo "Once booted (e.g. in qemu), resume booting by calling: scripts/install-nns.sh ${TMP}"
