#!/usr/bin/env bash

# Create configuration for k8s testnet VMs

set -eEuo pipefail

if (($# < 4)); then
    echo "Usage: k8s_config.sh <replica_version> <nns_ip> <app_ip> <out>"
    echo "  <replica_version>: The version deployed."
    echo "  <nns_ip>: IP of the pod hosting the NNS node."
    echo "  <app_ip>: IP of the pod hosting the app node."
    echo "  <ip_prefix>: IP prefix to whitelist in the initial firewall."
    echo "  <out>: Folder to contain all script outputs."
    exit 1
fi

REPLICA_VERSION=$1
NNS_IP=$2
APP_IP=$3
IP_PREFIX=$4
OUT=$5

REPO_ROOT="$(git rev-parse --show-toplevel)"
TEMPDIR=$(mktemp -d /tmp/k8s_deploy.sh.XXXXXXXXXX)
trap "rm -rf ${TEMPDIR}" exit

##############################################################################
echo "Building out folder structure..."
##############################################################################
rm -rf "${OUT}"
mkdir -p "${OUT}"
NNS_CONFIG_DIR="${TEMPDIR}/nns"
APP_CONFIG_DIR="${TEMPDIR}/app"
IC_PREP_DIR="${TEMPDIR}/prep"
BIN_DIR="${TEMPDIR}/bin"
INIT_DIR="${OUT}/init"
NNS_OUT_DIR="${OUT}/nns"
APP_OUT_DIR="${OUT}/app"

mkdir ${NNS_CONFIG_DIR}
mkdir ${APP_CONFIG_DIR}
mkdir ${IC_PREP_DIR}
mkdir ${BIN_DIR}
mkdir ${INIT_DIR}
mkdir ${NNS_OUT_DIR}
mkdir ${APP_OUT_DIR}

##############################################################################
echo "Downloading tools..."
##############################################################################
rclone --config="${REPO_ROOT}"/.rclone-anon.conf copy "public-s3:dfinity-download-public/ic/${REPLICA_VERSION}/release/ic-prep.gz" "${BIN_DIR}"
rclone --config="${REPO_ROOT}"/.rclone-anon.conf copy "public-s3:dfinity-download-public/ic/${REPLICA_VERSION}/release/ic-nns-init.gz" "${BIN_DIR}"

find "${BIN_DIR}/" -name "*.gz" -print0 | xargs -P100 -0I{} bash -c "gunzip -f {} && basename {} .gz | xargs -I[] chmod +x ${BIN_DIR}/[]"

##############################################################################
echo "Running ic-prep..."
##############################################################################
SSH="${REPO_ROOT}/testnet/tools/k8s/ssh_authorized_keys"
WHITELIST_FILE="${REPO_ROOT}/testnet/tools/k8s/provisional_whitelist.json"
# The principal id below is the one corresponding to the hardcoded key in
# ic_test_utilities::identity::TEST_IDENTITY_KEYPAIR. We do not have access to it
# in this script, so hardcode the corresponding principal instead.
#
# It is used for both the node operator and its corresponding provider.
NODE_OPERATOR_ID="5o66h-77qch-43oup-7aaui-kz5ty-tww4j-t2wmx-e3lym-cbtct-l3gpw-wae"
"${BIN_DIR}/ic-prep" \
    "--working-dir" "${IC_PREP_DIR}" \
    "--replica-version" "${REPLICA_VERSION}" \
    "--nns-subnet-index" "0" \
    "--p2p-flows" "1234-1" \
    "--node" "idx:0,subnet_idx:0,p2p_addr:\"org.internetcomputer.p2p1://[${NNS_IP}]:4100\",xnet_api:\"http://[${NNS_IP}]:2497\",public_api:\"http://[${NNS_IP}]:8080\"" \
    "--node" "idx:1,subnet_idx:1,p2p_addr:\"org.internetcomputer.p2p1://[${APP_IP}]:4100\",xnet_api:\"http://[${APP_IP}]:2497\",public_api:\"http://[${APP_IP}]:8080\"" \
    "--provisional-whitelist" "${WHITELIST_FILE}" \
    "--initial-node-operator" "${NODE_OPERATOR_ID}" \
    "--initial-node-provider" "${NODE_OPERATOR_ID}" \
    "--whitelisted-prefixes" "${IP_PREFIX}"

##############################################################################
echo "Building config folders..."
##############################################################################
NNS_URL=("http://[${NNS_IP}]:8080")

# Build NNS Node config
# -------------------------------------------------------------------------

# Copy registry to NNS node
cp -r "${IC_PREP_DIR}/ic_registry_local_store" "${NNS_CONFIG_DIR}"

# Copy crypto material
cp -r "${IC_PREP_DIR}/node-0/crypto/" "${NNS_CONFIG_DIR}/ic_crypto/"
cp "${IC_PREP_DIR}/nns_public_key.pem" "${NNS_CONFIG_DIR}/nns_public_key.pem"
echo "nns_url=${NNS_URL}" >"${NNS_CONFIG_DIR}/nns.conf"

# Generate Network config
echo "hostname=testnet-1" >"${NNS_CONFIG_DIR}/network.conf"
echo "name_servers_fallback=2606:4700:4700::1111 2606:4700:4700::1001" >>"${NNS_CONFIG_DIR}/network.conf"

# Generate Journalbeat config
echo "journalbeat_hosts=elasticsearch-node-0.testnet.dfinity.systems:443 elasticsearch-node-1.testnet.dfinity.systems:443 elasticsearch-node-2.testnet.dfinity.systems:443" >"${NNS_CONFIG_DIR}/journalbeat.conf"

# Copy SSH Keys
cp -Lr "${SSH}" "${NNS_CONFIG_DIR}/accounts_ssh_authorized_keys"

# Build App Node config
# -------------------------------------------------------------------------

# Copy crypto material
cp -r "${IC_PREP_DIR}/node-1/crypto/" "${APP_CONFIG_DIR}/ic_crypto/"
cp "${IC_PREP_DIR}/nns_public_key.pem" "${APP_CONFIG_DIR}/nns_public_key.pem"
echo "nns_url=${NNS_URL}" >"${APP_CONFIG_DIR}/nns.conf"

# Generate Network config
echo "hostname=testnet-2" >"${APP_CONFIG_DIR}/network.conf"
echo "name_servers_fallback=2606:4700:4700::1111 2606:4700:4700::1001" >>"${APP_CONFIG_DIR}/network.conf"

# Generate Journalbeat config
echo "journalbeat_hosts=elasticsearch-node-0.testnet.dfinity.systems:443 elasticsearch-node-1.testnet.dfinity.systems:443 elasticsearch-node-2.testnet.dfinity.systems:443" >"${APP_CONFIG_DIR}/journalbeat.conf"

# Copy SSH Keys
cp -Lr "${SSH}" "${APP_CONFIG_DIR}/accounts_ssh_authorized_keys"

##############################################################################
echo "Assembling config images..."
##############################################################################

tar cf "${NNS_OUT_DIR}/ic-bootstrap.tar" -C "${NNS_CONFIG_DIR}" .
tar cf "${APP_OUT_DIR}/ic-bootstrap.tar" -C "${APP_CONFIG_DIR}" .

truncate --size 4M "${NNS_OUT_DIR}/bootstrap.img"
mkfs.vfat -n CONFIG "${NNS_OUT_DIR}/bootstrap.img"
mcopy -i "${NNS_OUT_DIR}/bootstrap.img" -o -s "${NNS_OUT_DIR}/ic-bootstrap.tar" ::
truncate --size 4M "${APP_OUT_DIR}/bootstrap.img"
mkfs.vfat -n CONFIG "${APP_OUT_DIR}/bootstrap.img"
mcopy -i "${APP_OUT_DIR}/bootstrap.img" -o -s "${APP_OUT_DIR}/ic-bootstrap.tar" ::

# NOTE: We produce "raw" config, as well as virtual disk. Which will be used
# will depend on upload method.

##############################################################################
echo "Packing all other outputs..."
##############################################################################
# Set up canisters, nns-init, registry state
rclone --config="${REPO_ROOT}"/.rclone-anon.conf --include '*' copyto "public-s3:dfinity-download-public/ic/${REPLICA_VERSION}/canisters" "${INIT_DIR}/canisters"

find "${INIT_DIR}/canisters/" -name "*.gz" -print0 | xargs -P100 -0I{} bash -c "gunzip -f {}"

cp "${BIN_DIR}/ic-nns-init" "${INIT_DIR}"
cp -r "${IC_PREP_DIR}/ic_registry_local_store" "${INIT_DIR}"

echo
echo "To start the NNS, run:"
echo "ic-nns-init --url 'http://[${NNS_IP}]:8080' --registry-local-store-dir ic_registry_local_store --wasm-dir canisters"
