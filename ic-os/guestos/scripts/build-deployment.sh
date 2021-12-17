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
TESTNET_KEYS=""

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
       --with-testnet-keys    Initialize the registry with readonly and backup keys from testnet/config/ssh_authorized_keys.
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
        --with-testnet-keys)
            TESTNET_KEYS="${REPO_ROOT}/testnet/config/ssh_authorized_keys/admin"
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

# Read all the top-level values out in one swoop
VALUES=$(echo ${CONFIG} | jq -r -c '[
    .deployment,
    (.name_servers | join(" ")),
    (.name_servers_fallback | join(" ")),
    (.journalbeat_hosts | join(" ")),
    (.journalbeat_tags | join(" "))
] | join("\u0001")')
IFS=$'\1' read -r DEPLOYMENT NAME_SERVERS NAME_SERVERS_FALLBACK JOURNALBEAT_HOSTS JOURNALBEAT_TAGS < <(echo $VALUES)

# Read all the node info out in one swoop
NODES=0
VALUES=$(echo ${CONFIG} \
    | jq -r -c '.datacenters[]
| .aux_nodes[] += { "type": "aux" } | .boundary_nodes[] += {"type": "boundary"} | .nodes[] += { "type": "replica" }
| [.aux_nodes[], .boundary_nodes[], .nodes[]][] + { "ipv6_prefix": .ipv6_prefix, "ipv6_subnet": .ipv6_subnet } | [
    .ipv6_prefix,
    .ipv6_subnet,
    .ipv6_address,
    .hostname,
    .subnet_type,
    .subnet_idx,
    .node_idx,
    .use_hsm,
    .type
] | join("\u0001")')
while IFS=$'\1' read -r ipv6_prefix ipv6_subnet ipv6_address hostname subnet_type subnet_idx node_idx use_hsm type; do
    eval "declare -A __RAW_NODE_$NODES=(
        ['ipv6_prefix']=$ipv6_prefix
        ['ipv6_subnet']=$ipv6_subnet
        ['ipv6_address']=$ipv6_address
        ['subnet_type']=$subnet_type
        ['hostname']=$hostname
        ['subnet_idx']=$subnet_idx
        ['node_idx']=$node_idx
        ['use_hsm']=$use_hsm
        ['type']=$type
    )"
    NODES=$((NODES + 1))
done < <(printf "%s\n" "${VALUES[@]}")
NODES=${!__RAW_NODE_@}

function prepare_build_directories() {
    TEMPDIR=$(mktemp -d /tmp/build-deployment.sh.XXXXXXXXXX)

    IC_PREP_DIR="$TEMPDIR/IC_PREP"
    CONFIG_DIR="$TEMPDIR/CONFIG"
    TARBALL_DIR="$TEMPDIR/TARBALL"

    mkdir -p "${IC_PREP_DIR}"
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${TARBALL_DIR}"

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

    find "${IC_PREP_DIR}/canisters/" -name "*.gz" -print0 | xargs -P100 -0I{} bash -c "gunzip -f {}"

    rsync -a --delete "${IC_PREP_DIR}/canisters/" "$OUTPUT/canisters/"
}

function download_binaries() {
    "${REPO_ROOT}"/gitlab-ci/src/artifacts/rclone_download.py \
        --git-rev "$GIT_REVISION" --remote-path=release --out="${IC_PREP_DIR}/bin"

    find "${IC_PREP_DIR}/bin/" -name "*.gz" -print0 | xargs -P100 -0I{} bash -c "gunzip -f {} && basename {} .gz | xargs -I[] chmod +x ${IC_PREP_DIR}/bin/[]"

    mkdir -p "$OUTPUT/bin"
    rsync -a --delete "${IC_PREP_DIR}/bin/" "$OUTPUT/bin/"
}

function generate_subnet_config() {
    # Start hashing in the background
    mkfifo "$TEMPDIR/REPLICA_HASH"
    mkfifo "$TEMPDIR/NM_HASH"
    sha256sum "${IC_PREP_DIR}/bin/replica" | cut -d " " -f 1 >"$TEMPDIR/REPLICA_HASH" &
    sha256sum "${IC_PREP_DIR}/bin/nodemanager" | cut -d " " -f 1 >"$TEMPDIR/NM_HASH" &

    cp -a ${IC_PREP_DIR}/bin/replica "$REPO_ROOT/ic-os/guestos/rootfs/opt/ic/bin/replica"
    cp -a ${IC_PREP_DIR}/bin/nodemanager "$REPO_ROOT/ic-os/guestos/rootfs/opt/ic/bin/nodemanager"
    cp -a ${IC_PREP_DIR}/bin/boundary-node-control-plane "$REPO_ROOT/ic-os/generic-guestos/rootfs/opt/dfinity/boundary-node-control-plane"

    NODES_NNS=()
    NODES_APP=()
    # Query and list all NNS and APP node addresses in subnet
    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" -ne "replica" ]]; then
            continue
        fi
        local ipv6_address=${NODE["ipv6_address"]}
        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}
        local subnet_type=${NODE["subnet_type"]}

        if [[ "$subnet_type" == "root_subnet" ]]; then
            NODES_NNS+=("$node_idx-$subnet_idx-[${ipv6_address}]:4100-[${ipv6_address}]:2497-0-[${ipv6_address}]:8080")
        elif [[ "$subnet_type" == "app_subnet" ]]; then
            if [[ "$subnet_idx" == "x" ]]; then
                # Unassigned nodes (nodes not assigned to any subnet) have an empty subnet_idx
                # in the line submitted to ic-prep.
                subnet_idx=""
            fi
            NODES_APP+=("$node_idx-$subnet_idx-[${ipv6_address}]:4100-[${ipv6_address}]:2497-0-[${ipv6_address}]:8080")
        fi
    done

    # The principal id below is the one corresponding to the hardcoded key in
    # ic_test_utilities::identity::TEST_IDENTITY_KEYPAIR. We do not have access to it
    # in this script, so hardcode the corresponding principal instead.
    #
    # It is used for both the node operator and its corresponding provider.
    NODE_OPERATOR_ID="5o66h-77qch-43oup-7aaui-kz5ty-tww4j-t2wmx-e3lym-cbtct-l3gpw-wae"

    # Get the hash results
    REPLICA_HASH=$(cat "$TEMPDIR/REPLICA_HASH")
    NM_HASH=$(cat "$TEMPDIR/NM_HASH")

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
        "--initial-node-provider" "${NODE_OPERATOR_ID}" \
        "--ssh-readonly-access-file" "${TESTNET_KEYS}" \
        "--ssh-backup-access-file" "${TESTNET_KEYS}"
    set +x
}

function create_tarball_structure() {
    for n in $NODES; do
        declare -n NODE=$n
        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}
        NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
        mkdir -p "${CONFIG_DIR}/$NODE_PREFIX/node/replica_config"
    done
}

function generate_journalbeat_config() {
    for n in $NODES; do
        declare -n NODE=$n
        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}

        # Define hostname
        NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx

        if [ "${JOURNALBEAT_HOSTS}" != "" ]; then
            echo "journalbeat_hosts=${JOURNALBEAT_HOSTS}" >"${CONFIG_DIR}/$NODE_PREFIX/journalbeat.conf"
        fi
        if [ "${JOURNALBEAT_TAGS}" != "" ]; then
            echo "journalbeat_tags=${JOURNALBEAT_TAGS}" >>"${CONFIG_DIR}/$NODE_PREFIX/journalbeat.conf"
        fi
    done
}

function generate_node_config() {
    # Query and list all NNS nodes in subnet
    # Populate NNS specific configuration
    NNS_URL=()
    for n in $NODES; do
        declare -n NODE=$n

        local ipv6_address=${NODE["ipv6_address"]}
        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}
        local subnet_type=${NODE["subnet_type"]}

        if [[ "${NODE["type"]}" -ne "replica" ]]; then
            continue
        fi
        if [[ "$subnet_type" -ne "root_subnet" ]]; then
            continue
        fi

        # Copy initial NNS
        NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
        cp -r "${IC_PREP_DIR}/ic_registry_local_store" "${CONFIG_DIR}/$NODE_PREFIX/"

        NNS_URL+=("http://[${ipv6_address}]:8080")
    done
    NNS_URL=$(
        IFS=,
        echo "${NNS_URL[*]}"
    )

    # Populate generic configuration
    for n in $NODES; do
        declare -n NODE=$n
        local ipv6_address=${NODE["ipv6_address"]}
        local subnet_type=${NODE["subnet_type"]}
        local type=${NODE["type"]}
        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}
        NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx

        if [[ "$type" == "replica" ]]; then
            local use_hsm=${NODE["use_hsm"]}

            # Update crypto setup
            if ! [[ "${use_hsm}" == "true" || "${use_hsm}" == "1" ]]; then
                cp -r "${IC_PREP_DIR}/node-$node_idx/crypto/" "${CONFIG_DIR}/$NODE_PREFIX/ic_crypto/"
            fi

            # Copy the NNS public key in the correct place
            cp "${IC_PREP_DIR}/nns_public_key.pem" "${CONFIG_DIR}/$NODE_PREFIX/nns_public_key.pem"
            echo "nns_url=${NNS_URL}" >"${CONFIG_DIR}/$NODE_PREFIX/nns.conf"

        elif [[ "$type" == "boundary" ]]; then
            # Copy the NNS public key in the correct place
            cp "${IC_PREP_DIR}/nns_public_key.pem" "${CONFIG_DIR}/$NODE_PREFIX/nns_public_key.pem"
            echo "nns_url=${NNS_URL}" >"${CONFIG_DIR}/$NODE_PREFIX/nns.conf"
        fi
    done
}

function generate_network_config() {
    for n in $NODES; do
        declare -n NODE=$n
        local hostname=${NODE["hostname"]}
        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}

        # Define hostname
        NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
        echo "hostname=${hostname}" >"${CONFIG_DIR}/$NODE_PREFIX/network.conf"

        # Set name servers
        echo "name_servers=${NAME_SERVERS}" >>"${CONFIG_DIR}/$NODE_PREFIX/network.conf"
        echo "name_servers_fallback=${NAME_SERVERS_FALLBACK}" >>"${CONFIG_DIR}/$NODE_PREFIX/network.conf"

        # IPv6 network configuration is obtained from the Router Advertisement.
    done
}

function copy_ssh_keys() {
    for n in $NODES; do
        declare -n NODE=$n
        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}

        NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx

        # Copy the contents of the directory, but make sure that we do not
        # copy/create symlinks (but rather dereference file contents).
        # Symlinks must be refused by the config injection script (they
        # can lead to confusion and side effects when overwriting one
        # file changes another).
        cp -Lr "${SSH}" "${CONFIG_DIR}/$NODE_PREFIX/accounts_ssh_authorized_keys"
    done
}

function build_tarball() {
    for n in $NODES; do
        declare -n NODE=$n
        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}

        # Create temporary tarball directory per node
        NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
        mkdir -p "${TARBALL_DIR}/$NODE_PREFIX"
        (
            cd "${CONFIG_DIR}/$NODE_PREFIX"
            tar c .
        ) >${TARBALL_DIR}/$NODE_PREFIX/ic-bootstrap.tar
    done
    tar czf "${OUTPUT}/config.tgz" -C "${CONFIG_DIR}" .
}

function build_removable_media() {
    for n in $NODES; do
        declare -n NODE=$n
        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}

        #echo "${DEPLOYMENT}.$subnet_idx.$node_idx"
        NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
        truncate --size 4M "${OUTPUT}/$NODE_PREFIX.img"
        mkfs.vfat "${OUTPUT}/$NODE_PREFIX.img"
        mcopy -i "${OUTPUT}/$NODE_PREFIX.img" -o -s ${TARBALL_DIR}/$NODE_PREFIX/ic-bootstrap.tar ::
    done
}

function remove_temporary_directories() {
    rm -rf ${TEMPDIR}
}

# See how we were called
if [ ${DEBUG} -eq 1 ]; then
    cleanup_rootfs
    prepare_build_directories
    download_binaries &
    DOWNLOAD_PID=$!
    download_registry_canisters
    wait $DOWNLOAD_PID
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
    download_binaries >/dev/null 2>&1 &
    DOWNLOAD_PID=$!
    download_registry_canisters >/dev/null 2>&1
    wait $DOWNLOAD_PID
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
