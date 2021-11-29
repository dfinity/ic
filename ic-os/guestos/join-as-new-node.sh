#!/bin/bash

# Inspired by: node_crypto_install.yml
BASE_DIR=$(dirname "${BASH_SOURCE[0]}")

function error() {
    echo $1
    exit 1
}

NNS_HOSTNAME=$1
SUBNET_IDX=$2
VPN_IP=$3
VPN_IP6=$4

[[ -n "$NNS_HOSTNAME" ]] || error "Please set NNS hostname as argument, e.g. dcs-replica-1.dfinity.systems"
[[ -n "$SUBNET_IDX" ]] || error "Please set subnet index as second argument, e.g. \"1\" if the new node should join the first subnetwork"
[[ -n "$VPN_IP" ]] || error "Please specify IPv4 address as third argument"
[[ -n "$VPN_IP6" ]] || error "Please specify IPv6 address as third argument"

NNS_URL="http://${NNS_HOSTNAME}:8080"

if [[ -n "$5" ]]; then
    TMP="$5"
    if [[ ! -d "$5" ]]; then
        mkdir "$TMP"
    fi
else
    TMP=$(mktemp -d)
fi

function download_binaries() {
    # Download helper tools

    "${BASE_DIR}"/../../gitlab-ci/src/artifacts/rclone_download.py \
        --git-rev "$GIT_REVISION" --remote-path=release --out="$TARGET_DIR" \
        --include "{ic-admin,ic-prep}.gz"

    for f in ic-admin ic-prep; do
        gunzip -f "$TARGET_DIR/$f"
        chmod +x "$TARGET_DIR/$f"
    done
}

if [[ ! -e "$TMP/ic-prep" ]]; then

    download_binaries

    # Determine subnet ID to join
    SUBNET_ID=$($TMP/ic-admin --nns-url ${NNS_URL} get-subnet 1 | grep subnet_record_[^\"]* --color=never -o | sed -e 's/subnet_record_//')

    echo "Determined IP on DFINITY VPN is: v4 ${VPN_IP} and v6 ${VPN_IP6}"
    (
        set -x
        # Generate key material
        "$TMP/ic-prep" \
            "--working-dir" "$TMP" \
            "--replica-download-url" "http://example.com" \
            "--replica-hash" "deadbeef" \
            "--dkg-interval-length" "99" \
            "--p2p-flows" "1234-1" \
            "--nns-subnet-index" "${SUBNET_IDX}" \
            "--nodes" "0-${SUBNET_IDX}-[${VPN_IP6}]:4100-${VPN_IP}:2497-0-${VPN_IP}:8080"
    ) || error "Failed to run ic-prep"
    # Not sure if 0 as the node_index works here - let's see
fi

# Determine subnet ID to join
SUBNET_ID=$($TMP/ic-admin --nns-url ${NNS_URL} get-subnet 1 | grep subnet_record_[^\"]* --color=never -o | sed -e 's/subnet_record_//')

ls ${TMP}
echo "--------------------------------------------------"
ls ${TMP}/node-0

DERIVED_NODE_ID=$(cat ${TMP}/node-0/derived_node_id)
echo "Derived node ID is ${DERIVED_NODE_ID}"

# Delete old generated content in rootfs
rm -rf rootfs/etc/dfinity/
# Generate folder structure
mkdir -p rootfs/etc/dfinity/node/replica_config
mkdir -p rootfs/etc/dfinity/ic_crypto/

# Setup rootfs with generated content
# --------------------------------------------------

echo "Node configuration"
IC_JSON_TARGET=rootfs/etc/dfinity/node/replica_config/ic.json5
sed -e 's/{{ node_index }}/"'$DERIVED_NODE_ID'"/' \
    -e 's/{{ p2p_listen_ip }}/'${VPN_IP6}'/' \
    -e 's/{{ ip_address }}/'${VPN_IP}'/' \
    -e 's@{{ nns_url }}@'${NNS_URL}'@' \
    config/ic.json5 >$IC_JSON_TARGET

# Update crypto setup
cp -r ${TMP}/node-0/crypto/ rootfs/etc/dfinity/ic_crypto/

# Fetch the NNS public key from the NNS machine
scp ${NNS_HOSTNAME}:/etc/dfinity/node/nns_public_key.pem rootfs/etc/dfinity/node/

# Mutate registry to add the node to the given subnetwork
# --------------------------------------------------

# Upload crypto stuff
# - Public key of node
# - TLS certificates
ANSIBLE_TMP=$(mktemp -d)
cp ${TMP}/node-0/crypto_* ${ANSIBLE_TMP}
$TMP/ic-admin \
    --nns-url ${NNS_URL} \
    add-all-pb-files-in-path \
    -n ${ANSIBLE_TMP} || error "Failed to install crypto keys"
rm -rf ${ANSIBLE_TMP}

# Add node record to the NNS registry and add node-id to the membership list of the subnet.
set -x
$TMP/ic-admin \
    --nns-url ${NNS_URL} \
    add-node ${DERIVED_NODE_ID} ${SUBNET_ID} \
    pb_file ${TMP}/node-0/node_record_*.pb

# Fetch replica and node manager binaries
(
    export NNS_REPLICA=$NNS_HOSTNAME
    source "${BASE_DIR}"/scripts/fetch-dfinity-binaries.sh
    get_dfinity_binaries
)
ls -R rootfs/opt/ic/bin/

# Debugging stuff
# --------------------------------------------------
# cat rootfs/etc/dfinity/ic_crypto/crypto/public_keys.pb | protoc --decode_raw

# Cleanup
# --------------------------------------------------

if [[ -z "$4" ]]; then
    rm -rf ${TMP}
fi
