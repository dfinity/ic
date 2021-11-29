#!/usr/bin/env bash

# Build subnet based on subnet.json and transform it into removable media.

# Build Requirements:
# - Operating System: Ubuntu 20.04
# - Packages: coreutils, jq, mtools, tar, util-linux, wget, rclone

set -o errexit
set -o pipefail

BASE_DIR="$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT=$(git rev-parse --show-toplevel)

# Set argument defaults
DEBUG=0

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            echo 'Usage:

   ____  _____ ___ _   _ ___ _______   __
  |  _ \|  ___|_ _| \ | |_ _|_   _\ \ / /
  | | | | |_   | ||  \| || |  | |  \ V /
  | |_| |  _|  | || |\  || |  | |   | |
  |____/|_|   |___|_| \_|___| |_|   |_|

    Internet Computer Operating System
         Removable Media Builder

Arguments:
  -h,  --help                 show this help message and exit
  -i=, --input=               JSON formatted input file (Default: ./subnet.json)
  -o=, --output=              removable media output directory (Default: ./build-out/)
  -s=, --ssh=                 specify directory holding SSH authorized_key files (Default: ../../testnet/config/ssh_authorized_keys)
       --git-revision=        git revision for which to prepare the media
       --whitelist=           path to provisional whitelist that allows canister creation
       --dkg-interval-length= number of consensus rounds between DKG (-1 if not provided explicitly, which means - default will be used)
  -x,  --debug                enable verbose console output
'
            exit 1
            ;;
        -i=* | --input=*)
            INPUT="${argument#*=}"
            shift
            ;;
        -o=* | --output=*)
            OUTPUT="${argument#*=}"
            shift
            ;;
        -s=* | --ssh=*)
            SSH="${argument#*=}"
            shift
            ;;
        --git-revision=*)
            GIT_REVISION="${argument#*=}"
            shift
            ;;
        --whitelist=*)
            WHITELIST="${argument#*=}"
            shift
            ;;
        --dkg-interval-length=*)
            DKG_INTERVAL_LENGTH="${argument#*=}"
            shift
            ;;
        -x | --debug)
            DEBUG=1
            ;;
        *)
            echo 'Error: Argument is not supported.'
            exit 1
            ;;
    esac
done

# Set arguments if undefined
INPUT="${INPUT:=${BASE_DIR}/subnet.json}"
OUTPUT="${OUTPUT:=${BASE_DIR}/build-out}"
SSH="${SSH:=${BASE_DIR}/../../testnet/config/ssh_authorized_keys}"
GIT_REVISION="${GIT_REVISION:=}"
WHITELIST="${WHITELIST:=}"
# Negative DKG value means unset (default will be used)
DKG_INTERVAL_LENGTH="${DKG_INTERVAL_LENGTH:=-1}"

if [[ -z "$GIT_REVISION" ]]; then
    echo "Please provide the GIT_REVISION as env. variable or the command line with --git-revision=<value>"
    exit 1
fi

if [[ -z "$WHITELIST" ]]; then
    echo "Please provide the WHITELIST as env. variable or the command line with --whitelist=<value>"
    exit 1
fi

# Load INPUT
CONFIG="$(cat ${INPUT})"

DEPLOYMENT=$(echo ${CONFIG} | jq -r -c '.deployment')
NAME_SERVERS=$(echo ${CONFIG} | jq -r -c '.name_servers | join(" ")')
NAME_SERVERS_FALLBACK=$(echo ${CONFIG} | jq -r -c '.name_servers_fallback | join(" ")')
JOURNALBEAT_HOSTS=$(echo ${CONFIG} | jq -r -c '.journalbeat_hosts | join(" ")')

function prepare_build_directories() {
    IC_PREP_DIR="$(mktemp -d)"
    CONFIG_DIR="$(mktemp -d)"
    TARBALL_DIR="$(mktemp -d)"

    if [ ! -d "${OUTPUT}" ]; then
        mkdir -p "${OUTPUT}"
    fi
}

function cleanup_rootfs() {
    rm -rf ${BASE_DIR}/rootfs/opt/ic/bin/nodemanager*
    rm -rf ${BASE_DIR}/rootfs/opt/ic/bin/replica*
}

function download_registry_canisters() {
    "${REPO_ROOT}"/gitlab-ci/src/artifacts/rclone_download.py \
        --git-rev "$GIT_REVISION" --remote-path=canisters --out="${IC_PREP_DIR}/canisters"

    for f in "${IC_PREP_DIR}"/canisters/*.gz; do
        gunzip -f "$f"
    done
    rsync -a --delete "${IC_PREP_DIR}/canisters/" "$OUTPUT/canisters/"
}

function download_binaries() {
    "${REPO_ROOT}"/gitlab-ci/src/artifacts/rclone_download.py \
        --git-rev "$GIT_REVISION" --remote-path=release --out="${IC_PREP_DIR}/bin"

    for f in "${IC_PREP_DIR}"/bin/*.gz; do
        gunzip -f "$f"
        chmod +x "${IC_PREP_DIR}/bin/$(basename $f .gz)"
    done
    mkdir -p "$OUTPUT/bin"
    rsync -a --delete "${IC_PREP_DIR}/bin/" "$OUTPUT/bin/"
}

function generate_subnet_config() {
    cp -a ${IC_PREP_DIR}/bin/replica "$REPO_ROOT/ic-os/guestos/rootfs/opt/ic/bin/replica"
    cp -a ${IC_PREP_DIR}/bin/nodemanager "$REPO_ROOT/ic-os/guestos/rootfs/opt/ic/bin/nodemanager"
    cp -a ${IC_PREP_DIR}/bin/boundary-node-control-plane "$REPO_ROOT/ic-os/generic-guestos/rootfs/opt/dfinity/boundary-node-control-plane"
    REPLICA_HASH=$(sha256sum "$REPO_ROOT/ic-os/guestos/rootfs/opt/ic/bin/replica" | cut -d " " -f 1)
    NM_HASH=$(sha256sum "$REPO_ROOT/ic-os/guestos/rootfs/opt/ic/bin/nodemanager" | cut -d " " -f 1)

    NODES_NNS=()
    NODES_APP=()
    # Query and list all NNS node addresses in subnet
    for datacenter in $(echo ${CONFIG} | jq -c '.datacenters[]'); do
        local ipv6_prefix=$(echo ${datacenter} | jq -r '.ipv6_prefix')
        for nodes in $(echo ${datacenter} | jq -c '.nodes[]'); do
            for nns_node in $(echo ${nodes} | jq -c 'select(.subnet_type|test("root_subnet"))'); do
                local ipv6_address=$(echo "${nns_node}" | jq -r '.ipv6_address')
                local subnet_idx=$(echo ${nns_node} | jq -r '.subnet_idx')
                local node_idx=$(echo ${nns_node} | jq -r '.node_idx')

                NODES_NNS+=("$node_idx-$subnet_idx-[${ipv6_address}]:4100-[${ipv6_address}]:2497-0-[${ipv6_address}]:8080")
            done

        done
    done

    # Query and list all APP node addresses in subnet
    for datacenter in $(echo ${CONFIG} | jq -c '.datacenters[]'); do
        local ipv6_prefix=$(echo ${datacenters} | jq -r '.ipv6_prefix')
        for nodes in $(echo ${datacenter} | jq -c '.nodes[]'); do
            for app_node in $(echo ${nodes} | jq -c 'select(.subnet_type|test("app_subnet"))'); do
                local ipv6_address=$(echo "${app_node}" | jq -r '.ipv6_address')
                local subnet_idx=$(echo ${app_node} | jq -r '.subnet_idx')
                local node_idx=$(echo ${app_node} | jq -r '.node_idx')

                if [[ "$subnet_idx" == "x" ]]; then
                    # Unassigned nodes (nodes not assigned to any subnet) have an empty subnet_idx
                    # in the line submitted to ic-prep.
                    subnet_idx=""
                fi
                NODES_APP+=("$node_idx-$subnet_idx-[${ipv6_address}]:4100-[${ipv6_address}]:2497-0-[${ipv6_address}]:8080")
            done
        done
    done

    # The principal id below is the one corresponding to the hardcoded key in
    # ic_test_utilities::identity::TEST_IDENTITY_KEYPAIR. We do not have access to it
    # in this script, so hardcode the corresponding principal instead.
    #
    # It is used for both the node operator and its corresponding provider.
    NODE_OPERATOR_ID="5o66h-77qch-43oup-7aaui-kz5ty-tww4j-t2wmx-e3lym-cbtct-l3gpw-wae"

    set -x
    # Generate key material for assigned nodes
    # See subnet_crypto_install, line 5
    "${IC_PREP_DIR}/bin/ic-prep" \
        "--working-dir" "${IC_PREP_DIR}" \
        "--replica-download-url" "file:///opt/ic/bin/replica" \
        "--replica-hash" "${REPLICA_HASH}" \
        "--replica-version" "${GIT_REVISION}" \
        "--nodemanager-download-url" "file:///opt/ic/bin/nodemanager" \
        "--nodemanager-hash" "${NM_HASH}" \
        "--nns-subnet-index" "0" \
        "--dkg-interval-length" "${DKG_INTERVAL_LENGTH}" \
        "--p2p-flows" "1234-1" \
        "--nodes" ${NODES_NNS[*]} ${NODES_APP[*]} \
        "--provisional-whitelist" "${WHITELIST}" \
        "--initial-node-operator" "${NODE_OPERATOR_ID}" \
        "--initial-node-provider" "${NODE_OPERATOR_ID}"
    set +x
}

function create_tarball_structure() {
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        echo ${datacenters} | jq -c '[.nodes[],.boundary_nodes[],.aux_nodes[]][]' | while read nodes; do
            local subnet_idx=$(echo ${nodes} | jq -r '.subnet_idx')
            local node_idx=$(echo ${nodes} | jq -r '.node_idx')
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            mkdir -p "${CONFIG_DIR}/$NODE_PREFIX/node/replica_config"
        done
    done
}

function generate_journalbeat_config() {
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        echo ${datacenters} | jq -c '[.nodes[],.boundary_nodes[],.aux_nodes[]][]' | while read nodes; do

            local hostname=$(echo ${nodes} | jq -r '.hostname')
            local subnet_idx=$(echo ${nodes} | jq -r '.subnet_idx')
            local node_idx=$(echo ${nodes} | jq -r '.node_idx')

            # Define hostname
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx

            if [ "${JOURNALBEAT_HOSTS}" != "" ]; then
                echo "journalbeat_hosts=${JOURNALBEAT_HOSTS}" >"${CONFIG_DIR}/$NODE_PREFIX/journalbeat.conf"
            fi
        done
    done
}

function generate_node_config() {
    # Query and list all NNS nodes in subnet
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        local ipv6_prefix=$(echo ${datacenters} | jq -r '.ipv6_prefix')
        echo ${datacenters} | jq -c '.nodes[]' | while read nodes; do
            NNS_DC_URL=$(echo ${nodes} | jq -c 'select(.subnet_type|test("root_subnet"))' | while read nns_node; do
                local ipv6_address=$(echo "${nns_node}" | jq -r '.ipv6_address')
                echo -n "http://[${ipv6_address}]:8080"
            done)
            echo ${NNS_DC_URL} >>"${IC_PREP_DIR}/NNS_URL"
        done
    done
    NNS_URL="$(cat ${IC_PREP_DIR}/NNS_URL | awk '$1=$1' ORS=',' | sed 's@,$@@g')"
    rm -f "${IC_PREP_DIR}/NNS_URL)"

    # Populate NNS specific configuration
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        echo ${datacenters} | jq -c '.nodes[]' | while read nodes; do

            local subnet_idx=$(echo ${nodes} | jq -r '.subnet_idx')
            local node_idx=$(echo ${nodes} | jq -r '.node_idx')
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx

            echo ${nodes} | jq -c 'select(.subnet_type|test("root_subnet"))' | while read nns_node; do
                # Copy initial NNS
                cp -r "${IC_PREP_DIR}/ic_registry_local_store" "${CONFIG_DIR}/$NODE_PREFIX/"
            done
        done
    done

    # Populate generic configuration
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        local ipv6_prefix=$(echo ${datacenters} | jq -r '.ipv6_prefix')
        echo ${datacenters} | jq -c '.nodes[]' | while read nodes; do

            local subnet_idx=$(echo ${nodes} | jq -r '.subnet_idx')
            local node_idx=$(echo ${nodes} | jq -r '.node_idx')
            local use_hsm=$(echo ${nodes} | jq -r '.use_hsm')
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx

            if ! [[ "${use_hsm}" == "true" || "${use_hsm}" == "1" ]]; then
                # Update crypto setup
                cp -r "${IC_PREP_DIR}/node-$node_idx/crypto/" "${CONFIG_DIR}/$NODE_PREFIX/ic_crypto/"
            fi

            # Copy the NNS public key in the correct place
            cp "${IC_PREP_DIR}/nns_public_key.pem" "${CONFIG_DIR}/$NODE_PREFIX/nns_public_key.pem"
            echo "nns_url=${NNS_URL}" >"${CONFIG_DIR}/$NODE_PREFIX/nns.conf"
        done
    done

    # nns config for boundary nodes
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        local ipv6_prefix=$(echo ${datacenters} | jq -r '.ipv6_prefix')
        echo ${datacenters} | jq -c '.boundary_nodes[]' | while read nodes; do
            local subnet_idx=$(echo ${nodes} | jq -r '.subnet_idx')
            local node_idx=$(echo ${nodes} | jq -r '.node_idx')
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            # Copy the NNS public key in the correct place
            cp "${IC_PREP_DIR}/nns_public_key.pem" "${CONFIG_DIR}/$NODE_PREFIX/nns_public_key.pem"
            echo "nns_url=${NNS_URL}" >"${CONFIG_DIR}/$NODE_PREFIX/nns.conf"
        done
    done
}

function generate_network_config() {
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        local ipv6_prefix=$(echo ${datacenters} | jq -r '.ipv6_prefix')
        local ipv6_subnet=$(echo ${datacenters} | jq -r '.ipv6_subnet')
        local ipv6_gateway="${ipv6_prefix}"::1
        echo ${datacenters} | jq -c '[.nodes[],.boundary_nodes[],.aux_nodes[]][]' | while read nodes; do

            local hostname=$(echo ${nodes} | jq -r '.hostname')
            local subnet_idx=$(echo ${nodes} | jq -r '.subnet_idx')
            local node_idx=$(echo ${nodes} | jq -r '.node_idx')

            # Define hostname
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            echo "hostname=${hostname}" >"${CONFIG_DIR}/$NODE_PREFIX/network.conf"

            # Set name servers
            echo "name_servers=${NAME_SERVERS}" >>"${CONFIG_DIR}/$NODE_PREFIX/network.conf"
            echo "name_servers_fallback=${NAME_SERVERS_FALLBACK}" >>"${CONFIG_DIR}/$NODE_PREFIX/network.conf"

            # IPv6 network configuration is obtained from the Router Advertisement.
        done
    done
}

function copy_ssh_keys() {
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        echo ${datacenters} | jq -c '[.nodes[],.boundary_nodes[],.aux_nodes[]][]' | while read nodes; do
            local subnet_idx=$(echo ${nodes} | jq -r '.subnet_idx')
            local node_idx=$(echo ${nodes} | jq -r '.node_idx')
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx

            # Copy the contents of the directory, but make sure that we do not
            # copy/create symlinks (but rather dereference file contents).
            # Symlinks must be refused by the config injection script (they
            # can lead to confusion and side effects when overwriting one
            # file changes another).
            cp -Lr "${SSH}" "${CONFIG_DIR}/$NODE_PREFIX/accounts_ssh_authorized_keys"
        done
    done
}

function build_tarball() {
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        echo ${datacenters} | jq -c '[.nodes[],.boundary_nodes[],.aux_nodes[]][]' | while read nodes; do

            local subnet_idx=$(echo ${nodes} | jq -r '.subnet_idx')
            local node_idx=$(echo ${nodes} | jq -r '.node_idx')

            # Create temporary tarball directory per node
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            mkdir -p "${TARBALL_DIR}/$NODE_PREFIX"
            (
                cd "${CONFIG_DIR}/$NODE_PREFIX"
                tar c .
            ) >${TARBALL_DIR}/$NODE_PREFIX/ic-bootstrap.tar
        done
    done
    tar czf "${OUTPUT}/config.tgz" -C "${CONFIG_DIR}" .
}

function build_removable_media() {
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        echo ${datacenters} | jq -c '[.nodes[],.boundary_nodes[],.aux_nodes[]][]' | while read nodes; do
            local subnet_idx=$(echo ${nodes} | jq -r '.subnet_idx')
            local node_idx=$(echo ${nodes} | jq -r '.node_idx')

            #echo "${DEPLOYMENT}.$subnet_idx.$node_idx"
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            truncate --size 4M "${OUTPUT}/$NODE_PREFIX.img"
            mkfs.vfat "${OUTPUT}/$NODE_PREFIX.img"
            mcopy -i "${OUTPUT}/$NODE_PREFIX.img" -o -s ${TARBALL_DIR}/$NODE_PREFIX/ic-bootstrap.tar ::
        done
    done
}

function remove_temporary_directories() {
    rm -rf ${IC_PREP_DIR}
    rm -rf ${CONFIG_DIR}
    rm -rf ${TARBALL_DIR}
}

# See how we were called
if [ ${DEBUG} -eq 1 ]; then
    cleanup_rootfs
    prepare_build_directories
    download_binaries
    download_registry_canisters
    generate_subnet_config
    create_tarball_structure
    generate_journalbeat_config
    generate_node_config
    generate_network_config
    copy_ssh_keys
    build_tarball
    build_removable_media
    remove_temporary_directories
    cleanup_rootfs
else
    cleanup_rootfs >/dev/null 2>&1
    prepare_build_directories >/dev/null 2>&1
    download_binaries >/dev/null 2>&1
    download_registry_canisters >/dev/null 2>&1
    generate_subnet_config >/dev/null 2>&1
    create_tarball_structure >/dev/null 2>&1
    generate_journalbeat_config >/dev/null 2>&1
    generate_node_config >/dev/null 2>&1
    generate_network_config >/dev/null 2>&1
    copy_ssh_keys >/dev/null 2>&1
    build_tarball >/dev/null 2>&1
    build_removable_media >/dev/null 2>&1
    remove_temporary_directories >/dev/null 2>&1
    cleanup_rootfs >/dev/null 2>&1
fi
