#!/usr/bin/env bash

# Build subnet based on subnet.json and transform it into removable media.

# Build Requirements:
# - Operating System: Ubuntu 20.04
# - Packages: coreutils, jq, mtools, tar, util-linux, wget, rclone

set -o errexit
set -o pipefail

REPO_ROOT=${REPO_ROOT:-$(git rev-parse --show-toplevel)}

# Set argument defaults
DEBUG=0
TESTNET_KEYS=""

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            echo 'Usage:

    Internet Computer Operating System
         Removable Media Builder

Arguments:
  -h,  --help                           show this help message and exit
  -i=, --input=                         JSON formatted input file
  -o=, --output=                        removable media output directory
       --output-nns-public-key=         An optional path to output nns_public_key.pem if desired
  -s=, --ssh=                           specify directory holding SSH authorized_key files (Default: <repo_root>/testnet/config/ssh_authorized_keys)
       --node-operator-private-key=     specify the node provider private key
       --git-revision=                  git revision for which to prepare the media
       --whitelist=                     path to provisional whitelist that allows canister creation
       --dkg-interval-length=           number of consensus rounds between DKG (-1 if not provided explicitly, which means - default will be used)
       --max-ingress-bytes-per-message= maximum size of ingress message allowed in bytes
  -x,  --debug                          enable verbose console output
       --with-testnet-keys              Initialize the registry with readonly and backup keys from testnet/config/ssh_authorized_keys.
       --allow-specified-ids            Allow installing canisters at specified IDs
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
        --output-nns-public-key=*)
            OUTPUT_NNS_PUBLIC_KEY="${argument#*=}"
            shift
            ;;
        -s=* | --ssh=*)
            SSH="${argument#*=}"
            shift
            ;;
        --node-operator-private-key=*)
            NODE_OPERATOR_PRIVATE_KEY="${argument#*=}"
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
        --max-ingress-bytes-per-message=*)
            MAX_INGRESS_BYTES_PER_MESSAGE="${argument#*=}"
            shift
            ;;
        -x | --debug)
            DEBUG=1
            ;;
        --with-testnet-keys)
            TESTNET_KEYS="${REPO_ROOT}/testnet/config/ssh_authorized_keys/admin"
            ;;
        --allow-specified-ids)
            ALLOW_SPECIFIED_IDS="--use-specified-ids-allocation-range"
            ;;
        *)
            echo 'Error: Argument is not supported.'
            exit 1
            ;;
    esac
done

# Set arguments if undefined
INPUT="${INPUT:=}"
OUTPUT="${OUTPUT:=}"
SSH="${SSH:=${REPO_ROOT}/testnet/config/ssh_authorized_keys}"
NODE_OPERATOR_PRIVATE_KEY="${NODE_OPERATOR_PRIVATE_KEY:=}"
GIT_REVISION="${GIT_REVISION:=}"
WHITELIST="${WHITELIST:=}"
# Negative DKG value means unset (default will be used)
DKG_INTERVAL_LENGTH="${DKG_INTERVAL_LENGTH:=-1}"
# Negative value means unset (default will be used)
MAX_INGRESS_BYTES_PER_MESSAGE="${MAX_INGRESS_BYTES_PER_MESSAGE:=-1}"

if [[ -z "${GIT_REVISION}" ]]; then
    echo "Please provide the GIT_REVISION as env. variable or the command line with --git-revision=<value>"
    exit 1
fi

if [[ -z "${INPUT}" ]]; then
    echo "Please provide INPUT as env. variable or on the command line with --input=<value>"
    exit 1
fi

if [[ -z "${OUTPUT}" ]]; then
    echo "Please provide OUTPUT as env. variable or on the command line with --output=<value>"
    exit 1
fi

if [[ -z "${WHITELIST}" ]]; then
    echo "Please provide the WHITELIST as env. variable or the command line with --whitelist=<value>"
    exit 1
fi

# Load INPUT
CONFIG="$(cat ${INPUT})"

# Read all the top-level values out in one swoop
VALUES=$(echo ${CONFIG} | jq -r -c '[
    .deployment,
    (.elasticsearch_hosts | join(" ")),
    (.elasticsearch_tags | join(" "))
] | join("\u0001")')
IFS=$'\1' read -r DEPLOYMENT ELASTICSEARCH_HOSTS ELASTICSEARCH_TAGS < <(echo $VALUES)

# Read all the node info out in one swoop
NODES=0
VALUES=$(echo ${CONFIG} \
    | jq -r -c '.datacenters[]
| .aux_nodes[] += { "type": "aux" } | .boundary_nodes[] += {"type": "boundary"} | .nodes[] += { "type": "replica" }
| [.aux_nodes[], .boundary_nodes[], .nodes[]][] + { "ipv6_prefix": .ipv6_prefix } | [
    .ipv6_prefix,
    .ipv6_address,
    .hostname,
    .subnet_type,
    .subnet_idx,
    .node_idx,
    .use_hsm,
    .type
] | join("\u0001")')
while IFS=$'\1' read -r ipv6_prefix ipv6_address hostname subnet_type subnet_idx node_idx use_hsm type; do
    eval "declare -A __RAW_NODE_${NODES}=(
        ['ipv6_prefix']=${ipv6_prefix}
        ['ipv6_address']=${ipv6_address}
        ['hostname']=${hostname}
        ['subnet_type']=${subnet_type}
        ['subnet_idx']=${subnet_idx}
        ['node_idx']=${node_idx}
        ['use_hsm']=${use_hsm}
        ['type']=${type}
    )"
    NODES=$((NODES + 1))
done < <(printf "%s\n" "${VALUES[@]}")
NODES=${!__RAW_NODE_@}

function prepare_build_directories() {
    TEMPDIR=$(mktemp -d /tmp/build-guestos-configs.sh.XXXXXXXXXX)
    trap "rm -rf ${TEMPDIR}" exit

    IC_PREP_DIR="${TEMPDIR}/IC_PREP"
    mkdir -p "${IC_PREP_DIR}"

    if [ ! -d "${OUTPUT}" ]; then
        mkdir -p "${OUTPUT}"
    fi
}

function download_registry_canisters() {
    "${REPO_ROOT}"/ci/src/artifacts/rclone_download.py \
        --git-rev "${GIT_REVISION}" --remote-path=canisters --out="${IC_PREP_DIR}/canisters"

    rsync -a --delete "${IC_PREP_DIR}/canisters/" "${OUTPUT}/canisters/"
}

function download_binaries() {
    "${REPO_ROOT}"/ci/src/artifacts/rclone_download.py \
        --git-rev "${GIT_REVISION}" --remote-path=release --out="${IC_PREP_DIR}/bin"

    find "${IC_PREP_DIR}/bin/" -name "*.gz" -print0 | xargs -P100 -0I{} bash -c "gunzip -f {} && basename {} .gz | xargs -I[] chmod +x ${IC_PREP_DIR}/bin/[]"

    mkdir -p "${OUTPUT}/bin"
    rsync -a --delete "${IC_PREP_DIR}/bin/" "${OUTPUT}/bin/"
}

function generate_prep_material() {
    NODES_NNS=()
    NODES_APP=()
    # Query and list all NNS and APP node addresses in subnet
    for n in ${NODES}; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" != "replica" ]]; then
            continue
        fi
        local ipv6_address=${NODE["ipv6_address"]}
        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}
        local subnet_type=${NODE["subnet_type"]}

        if [[ "${subnet_type}" == "root_subnet" ]]; then
            NODES_NNS+=("--node")
            NODES_NNS+=("idx:${node_idx},subnet_idx:${subnet_idx},xnet_api:\"[${ipv6_address}]:2497\",public_api:\"[${ipv6_address}]:8080\"")
            OLD_NODES_NNS+=("${node_idx}-${subnet_idx}-[${ipv6_address}]:4100-[${ipv6_address}]:2497-0-[${ipv6_address}]:8080")
        elif [[ "${subnet_type}" == "app_subnet" ]]; then
            if [[ "${subnet_idx}" == "x" ]]; then
                # Unassigned nodes (nodes not assigned to any subnet) have an empty subnet_idx
                # in the line submitted to ic-prep.
                subnet_idx=""
            fi
            NODES_APP+=("--node")
            NODES_APP+=("idx:${node_idx},subnet_idx:${subnet_idx},xnet_api:\"[${ipv6_address}]:2497\",public_api:\"[${ipv6_address}]:8080\"")
            OLD_NODES_APP+=("${node_idx}-${subnet_idx}-[${ipv6_address}]:4100-[${ipv6_address}]:2497-0-[${ipv6_address}]:8080")
        fi
    done

    # The principal id below is the one corresponding to the hardcoded key in
    # ic_test_utilities::identity::TEST_IDENTITY_KEYPAIR. We do not have access to it
    # in this script, so hardcode the corresponding principal instead.
    #
    # It is used for both the node operator and its corresponding provider.
    NODE_OPERATOR_ID="5o66h-77qch-43oup-7aaui-kz5ty-tww4j-t2wmx-e3lym-cbtct-l3gpw-wae"

    set -x
    # Fix backward compatibility of removed ic-prep argument
    if ${IC_PREP_DIR}/bin/ic-prep --help | grep -q 'p2p-flows'; then
        P2P_FLOWS=""--p2p-flows" "1234-1""
    fi

    # Fix backward compatibility of removed nodes argument
    if ${IC_PREP_DIR}/bin/ic-prep --help | grep -q -- '--nodes'; then
        NODE_FLAG=("--nodes")
        NODE_FLAG+=(${OLD_NODES_NNS[*]})
        NODE_FLAG+=(${OLD_NODES_APP[*]})
    else
        NODE_FLAG=(${NODES_NNS[*]})
        NODE_FLAG+=(${NODES_APP[*]})
    fi

    # Generate key material for assigned nodes
    # See subnet_crypto_install, line 5
    "${IC_PREP_DIR}/bin/ic-prep" \
        "--working-dir" "${IC_PREP_DIR}" \
        "--replica-version" "${GIT_REVISION}" \
        "--nns-subnet-index" "0" \
        "--dkg-interval-length" "${DKG_INTERVAL_LENGTH}" \
        "--max-ingress-bytes-per-message" "${MAX_INGRESS_BYTES_PER_MESSAGE}" \
        ${P2P_FLOWS:-} \
        ${NODE_FLAG[*]} \
        "--provisional-whitelist" "${WHITELIST}" \
        "--initial-node-operator" "${NODE_OPERATOR_ID}" \
        "--initial-node-provider" "${NODE_OPERATOR_ID}" \
        "--ssh-readonly-access-file" "${TESTNET_KEYS}" \
        "--ssh-backup-access-file" "${TESTNET_KEYS}" \
        ${ALLOW_SPECIFIED_IDS:-}
    set +x

    cp -r "${IC_PREP_DIR}/ic_registry_local_store" "${OUTPUT}/ic_registry_local_store"
}

function build_bootstrap_images() {
    # Collect NNS URLs
    NNS_URL=()
    for n in ${NODES}; do
        declare -n NODE=$n
        local ipv6_address=${NODE["ipv6_address"]}
        if [[ "${NODE["type"]}" != "replica" ]]; then
            continue
        fi
        if [[ "${NODE["subnet_type"]}" != "root_subnet" ]]; then
            continue
        fi

        NNS_URL+=("http://[${ipv6_address}]:8080")
    done
    NNS_URL=$(
        IFS=,
        echo "${NNS_URL[*]}"
    )

    for n in ${NODES}; do
        declare -n NODE=${n}
        local hostname=${NODE["hostname"]}
        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}
        NODE_PREFIX=${DEPLOYMENT}.${subnet_idx}.${node_idx}

        if [[ "${NODE["type"]}" != "replica" ]]; then
            continue
        fi

        # Only include local store in the root subnet
        local root_subnet=""
        if [[ "${NODE["subnet_type"]}" == "root_subnet" ]]; then
            root_subnet="true"
        fi

        # Use crypto material only if `use_hsm` is not specified
        local use_crypto=""
        local use_hsm=${NODE["use_hsm"]}
        if ! [[ "${use_hsm}" == "true" || "${use_hsm}" == "1" ]]; then
            use_crypto="true"
        fi

        set -x
        "${REPO_ROOT}"/ic-os/components/hostos-scripts/build-bootstrap-config-image.sh \
            "${OUTPUT}/${NODE_PREFIX}.img" \
            ${root_subnet:+"--ic_registry_local_store"} ${root_subnet:+"${IC_PREP_DIR}/ic_registry_local_store"} \
            ${use_crypto:+"--ic_crypto"} ${use_crypto:+"${IC_PREP_DIR}/node-${node_idx}/crypto/"} \
            "--nns_url" "${NNS_URL}" \
            "--nns_public_key" "${IC_PREP_DIR}/nns_public_key.pem" \
            "--hostname" "${hostname}" \
            "--accounts_ssh_authorized_keys" "${SSH}" \
            ${ELASTICSEARCH_HOSTS:+"--elasticsearch_hosts"} ${ELASTICSEARCH_HOSTS:+"${ELASTICSEARCH_HOSTS}"} \
            ${ELASTICSEARCH_TAGS:+"--elasticsearch_tags"} ${ELASTICSEARCH_TAGS:+"${ELASTICSEARCH_TAGS}"} \
            ${NODE_OPERATOR_PRIVATE_KEY:+"--node_operator_private_key"} ${NODE_OPERATOR_PRIVATE_KEY:+"${NODE_OPERATOR_PRIVATE_KEY}"} \
            "--socks_proxy" "socks5://socks5.testnet.dfinity.network:1080"
        set +x
    done

    # Output NNS key to specified location
    if [[ -n "${OUTPUT_NNS_PUBLIC_KEY:-}" ]]; then
        cp "${IC_PREP_DIR}/nns_public_key.pem" "${OUTPUT_NNS_PUBLIC_KEY}"
    fi
}

function build_universal_media() {
    for n in ${NODES}; do
        declare -n NODE=${n}
        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}
        NODE_PREFIX=${DEPLOYMENT}.${subnet_idx}.${node_idx}

        if [[ "${NODE["type"]}" != "aux" ]]; then
            continue
        fi

        truncate --size 4M "${OUTPUT}/${NODE_PREFIX}.img"
        mkfs.vfat -n CONFIG "${OUTPUT}/${NODE_PREFIX}.img"
        mcopy -i "${OUTPUT}/${NODE_PREFIX}.img" -o -s ${SSH} ::ssh-authorized-keys
    done
}

function main() {
    prepare_build_directories
    download_binaries &
    DOWNLOAD_PID=$!
    download_registry_canisters
    wait $DOWNLOAD_PID
    generate_prep_material
    build_bootstrap_images

    build_universal_media
}

# See how we were called
if [ ${DEBUG} -eq 1 ]; then
    main
else
    main >/dev/null 2>&1
fi
