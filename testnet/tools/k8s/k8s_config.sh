#!/usr/bin/env bash

# Create configuration for k8s testnet VMs

set -eEuo pipefail

if (($# < 4)); then
    echo "Usage: k8s_config.sh <replica_version> <nns_ip> <app_ip> <out>"
    echo "  <replica_version>: The version deployed."
    echo "  <nns_ips>: IPs of pods hosting NNS nodes. (Separated by spaces)"
    echo "  <app_ips>: IPs of pods hosting app nodes. (Separated by spaces)"
    echo "  <ip_prefix>: IP prefix to whitelist in the initial firewall."
    echo "  <out>: Folder to contain all script outputs."
    exit 1
fi

REPLICA_VERSION=$1
NNS_IPS=$2
APP_IPS=$3
IP_PREFIX=$4
OUT=$5

REPO_ROOT="$(git rev-parse --show-toplevel)"
TEMPDIR=$(mktemp -d /tmp/k8s_deploy.sh.XXXXXXXXXX)
trap "rm -rf ${TEMPDIR}" exit
IC_PREP_DIR="${TEMPDIR}/prep"
BIN_DIR="${TEMPDIR}/bin"

function create_directories() {
    ##############################################################################
    echo "Building out directory structure..."
    ##############################################################################
    rm -rf "${OUT}"
    mkdir -p "${OUT}"
    mkdir ${IC_PREP_DIR}
    mkdir ${BIN_DIR}
}

function download_tools() {
    ##############################################################################
    echo "Downloading tools..."
    ##############################################################################

    rclone --config="${REPO_ROOT}"/.rclone-anon.conf copy "public-s3:dfinity-download-public/ic/${REPLICA_VERSION}/release/ic-prep.gz" "${BIN_DIR}"
    gunzip -f "${BIN_DIR}/ic-prep.gz"
    chmod +x "${BIN_DIR}/ic-prep"
}

function ic_prep() {
    ##############################################################################
    echo "Running ic-prep..."
    ##############################################################################

    local nns_ips=(${NNS_IPS})
    local app_ips=(${APP_IPS})

    local node_definitions=()
    local node_index=0
    for ip in "${nns_ips[@]}"; do
        node_definitions+=("--node")
        node_definitions+=("idx:$((node_index++)),subnet_idx:0,p2p_addr:\"org.internetcomputer.p2p1://[${ip}]:4100\",xnet_api:\"http://[${ip}]:2497\",public_api:\"http://[${ip}]:8080\"")
    done

    for ip in "${app_ips[@]}"; do
        node_definitions+=("--node")
        node_definitions+=("idx:$((node_index++)),subnet_idx:1,p2p_addr:\"org.internetcomputer.p2p1://[${ip}]:4100\",xnet_api:\"http://[${ip}]:2497\",public_api:\"http://[${ip}]:8080\"")
    done

    # Allow any principal to create canisters on any subnet
    local whitelist_file="${REPO_ROOT}/testnet/tools/k8s/provisional_whitelist.json"

    # The principal id below is the one corresponding to the hardcoded key in
    # ic_test_utilities::identity::TEST_IDENTITY_KEYPAIR. We do not have access to it
    # in this script, so hardcode the corresponding principal instead.
    #
    # It is used for both the node operator and its corresponding provider.
    NODE_OPERATOR_ID="5o66h-77qch-43oup-7aaui-kz5ty-tww4j-t2wmx-e3lym-cbtct-l3gpw-wae"
    "${BIN_DIR}/ic-prep" \
        "--working-dir" "${IC_PREP_DIR}" \
        "--replica-version" "${REPLICA_VERSION}" \
        "${node_definitions[@]}" \
        "--p2p-flows" "1234-1" \
        "--provisional-whitelist" "${whitelist_file}" \
        "--initial-node-operator" "${NODE_OPERATOR_ID}" \
        "--initial-node-provider" "${NODE_OPERATOR_ID}" \
        "--whitelisted-prefixes" "${IP_PREFIX}"

    cp -r "${IC_PREP_DIR}/ic_registry_local_store" "${OUT}"
}

function build_config() {
    ##############################################################################
    echo "Building config folders..."
    ##############################################################################

    local nns_ips=(${NNS_IPS})
    local app_ips=(${APP_IPS})

    local nns_urls=()
    for ip in "${nns_ips[@]}"; do
        nns_urls+=("http://[${ip}]:8080")
    done

    local ssh="${REPO_ROOT}/testnet/tools/k8s/ssh_authorized_keys"

    local node_index=0
    for ip in "${nns_ips[@]}"; do
        "${REPO_ROOT}/ic-os/scripts/build-bootstrap-config-image.sh" \
            "${OUT}/bootstrap-${node_index}.img" \
            "--ic_registry_local_store" "${IC_PREP_DIR}/ic_registry_local_store" \
            "--ic_crypto" "${IC_PREP_DIR}/node-${node_index}/crypto" \
            "--nns_public_key" "${IC_PREP_DIR}/nns_public_key.pem" \
            "--nns_url" "${nns_urls[*]}" \
            "--hostname" "testnet-$((node_index++))" \
            "--journalbeat_hosts" "elasticsearch.testnet.dfinity.network:443" \
            "--accounts_ssh_authorized_keys" "${ssh}"
    done

    for ip in "${app_ips[@]}"; do
        "${REPO_ROOT}/ic-os/scripts/build-bootstrap-config-image.sh" \
            "${OUT}/bootstrap-${node_index}.img" \
            "--ic_crypto" "${IC_PREP_DIR}/node-${node_index}/crypto" \
            "--nns_public_key" "${IC_PREP_DIR}/nns_public_key.pem" \
            "--nns_url" "${nns_urls[*]}" \
            "--hostname" "testnet-$((node_index++))" \
            "--journalbeat_hosts" "elasticsearch.testnet.dfinity.network:443" \
            "--accounts_ssh_authorized_keys" "${ssh}"
    done
}

create_directories
download_tools
ic_prep
build_config
