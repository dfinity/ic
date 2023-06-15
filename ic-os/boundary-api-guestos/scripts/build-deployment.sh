#!/usr/bin/env bash

# Build subnet based on subnet.json and transform it into removable media.

# Build Requirements:
# - Bash 4+
#
# - Operating System: Ubuntu 20.04
# - >sudo apt install coreutils jq mtools tar util-linux wget rclone
#
# - Operating System: MacOS 12.5
# - >brew install coreutil bash jq rclone dosfstools wget mtools gnu-tar
# - /usr/local/sbin/ must be in your path (for dosfstools)

set -euo pipefail

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

if [[ "${BASH_VERSINFO:-0}" -lt 4 ]]; then
    err "Bash 4+ is required"
    exit 1
fi

BASE_DIR="$(dirname "${BASH_SOURCE[0]}")/.."
GIT_REVISION=$(git rev-parse --verify HEAD)

function exit_usage() {
    echo 'Usage:

Removable Media Builder for API Boundary Node VMs


Arguments:
  -h,  --help                           show this help message and exit
  -i=, --input=                         JSON formatted input file (Default: ./subnet.json)
  -o=, --output=                        removable media output directory (Default: ./build-out/)
       --env=                           specify deployment environment (dev/prod/test)
       --ssh=                           specify directory holding SSH authorized_key files (Default: ../../testnet/config/ssh_authorized_keys)
       --certdir=                       specify directory holding TLS certificates for hosted domain (Default: None i.e. snakeoil/self certified certificate will be used)
       --nns_public_key=                specify NNS public key pem file
       --nns_urls=                      specify a file that lists on each line a nns url of the form `http://[ip]:port` this file will override nns urls derived from input json file
       --replicas-ipv6=                 specify a file that lists on each line an ipv6 firewall rule to allow replicas of the form `ipv6-addr/prefix-length` (# comments and trailing whitespace will be stripped)
       --ip-hash-salt                   specify a salt for hashing ip values
       --logging-url                    specify an endpoint for our logging backend
       --logging-user                   specify a user for our logging backend
       --logging-password               specify a password for our logging backend
       --logging-2xx-sample-rate        specify a sampling rate for logging 2XX requests (1 / N)
  -x,  --debug                          enable verbose console output
'
    exit 1
}

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            exit_usage
            ;;
        -i=* | --input=*)
            INPUT="${argument#*=}"
            shift
            ;;
        -o=* | --output=*)
            OUTPUT="${argument#*=}"
            shift
            ;;
        --env=*)
            ENV="${argument#*=}"
            shift
            ;;
        --ssh=*)
            SSH="${argument#*=}"
            shift
            ;;
        --certdir=*)
            CERT_DIR="${argument#*=}"
            shift
            ;;
        --nns_url=*)
            NNS_URL_OVERRIDE="${argument#*=}"
            shift
            ;;
        --nns_public_key=*)
            NNS_PUBLIC_KEY="${argument#*=}"
            shift
            ;;
        --replicas-ipv6=*)
            REPLICA_IPV6_OVERRIDE="${argument#*=}"
            shift
            ;;
        --ip-hash-salt=*)
            IP_HASH_SALT="${argument#*=}"
            ;;
        --logging-url=*)
            LOGGING_URL="${argument#*=}"
            ;;
        --logging-user=*)
            LOGGING_USER="${argument#*=}"
            ;;
        --logging-password=*)
            LOGGING_PASSWORD="${argument#*=}"
            ;;
        --logging-2xx-sample-rate=*)
            LOGGING_2XX_SAMPLE_RATE="${argument#*=}"
            ;;
        *)
            echo "Error: Argument \"${argument#}\" is not supported for $0"
            exit 1
            ;;
    esac
done

# Set arguments if undefined
INPUT="${INPUT:=${BASE_DIR}/subnet.json}"
OUTPUT="${OUTPUT:=${BASE_DIR}/build-out}"
SSH="${SSH:=${BASE_DIR}/../../testnet/config/ssh_authorized_keys}"
CERT_DIR="${CERT_DIR:-}"
if [ -z ${NNS_PUBLIC_KEY+x} ]; then
    err "--nns_public_key not set"
    exit 1
elif [ ! -f "${NNS_PUBLIC_KEY}" ]; then
    err "nns_public_key '${NNS_PUBLIC_KEY}' not found"
    exit 1
fi

if [ -z ${ENV+x} ]; then
    err "--env not set"
    exit 1
elif [[ ! "${ENV}" =~ ^(dev|prod|test)$ ]]; then
    err "--env should be set to one of: dev/prod/test"
    exit 1
fi

# Load INPUT
CONFIG="$(cat ${INPUT})"

# Read all the BN vars
BN_VARS=$(
    echo ${CONFIG} | jq -r '.bn_vars | to_entries | map(
        .key as $key | (                   # Save the key
            [.value] |                     # Force value to be an array
            flatten |                      # Flatten so we can create pairs
            map( [$key, (. | tostring)] )  # Create pairs
        )
    )[][] | join("=")'
)

# Add `env` variable on top
BN_VARS="env=${ENV}"$'\n'"${BN_VARS}"

# Read all the top-level values out in one swoop
VALUES=$(echo ${CONFIG} | jq -r -c '[
    .deployment,
    (.name_servers | join(" ")),
    (.name_servers_fallback | join(" ")),
    (.ipv4_name_servers | join(" "))
] | join("\u0001")')
IFS=$'\1' read -r DEPLOYMENT IPV6_NAME_SERVERS IPV6_NAME_SERVERS_FALLBACK IPV4_NAME_SERVERS < <(echo $VALUES)

# Read all the node info out in one swoop
NODES=0
VALUES=$(echo ${CONFIG} \
    | jq -r -c '.datacenters[]
| .api_nodes[] += { "type": "api" } | .aux_nodes[] += { "type": "aux" } | .boundary_nodes[] += {"type": "boundary"} | .nodes[] += { "type": "replica" }
| [.api_nodes[], .aux_nodes[], .boundary_nodes[], .nodes[]][] | [
    .ipv6_address,
    .ipv6_gateway,
    .ipv4_gateway,
    .ipv4_address,
    .hostname,
    .subnet_type,
    .subnet_idx,
    .node_idx,
    .type
] | join("\u0001")')
while IFS=$'\1' read -r ipv6_address ipv6_gateway ipv4_gateway ipv4_address hostname subnet_type subnet_idx node_idx type; do
    eval "declare -A __RAW_NODE_$NODES=(
        ['ipv6_address']=$ipv6_address
        ['ipv6_gateway']=$ipv6_gateway
	    ['ipv4_gateway']=$ipv4_gateway
        ['ipv4_address']=$ipv4_address
        ['hostname']=$hostname
        ['subnet_type']=$subnet_type
        ['subnet_idx']=$subnet_idx
        ['node_idx']=$node_idx
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

    mkdir -p "${IC_PREP_DIR}/bin"
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${TARBALL_DIR}"

    if [ ! -d "${OUTPUT}" ]; then
        mkdir -p "${OUTPUT}"
    fi
}

function create_tarball_structure() {
    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" = "api" ]]; then
            local subnet_idx=${NODE["subnet_idx"]}
            local node_idx=${NODE["node_idx"]}
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            mkdir -p "${CONFIG_DIR}/${NODE_PREFIX}/node/replica_config"
        fi
    done
}

function generate_api_node_config() {
    local NNS_URL=
    if [ -z ${NNS_URL_OVERRIDE+x} ]; then
        # Query and list all NNS nodes in subnet
        for n in $NODES; do
            declare -n NODE=$n

            local ipv6_address=${NODE["ipv6_address"]}

            if [[ "${NODE["type"]}" != "replica" || "${NODE["subnet_type"]}" != "root_subnet" ]]; then
                continue
            fi

            NNS_URL+="http://[${ipv6_address}]:8080,"
        done
    else
        NNS_URL=$(cat ${NNS_URL_OVERRIDE} | awk '$1=$1' ORS=',')
    fi
    NNS_URL=$(echo ${NNS_URL} | sed 's/,$//g')
    #echo "nns_url=${NNS_URL}"

    # nns config for api nodes
    for n in $NODES; do
        declare -n NODE=$n

        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}

        NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx

        if [[ "${NODE["type"]}" != "api" ]]; then
            continue
        fi

        cp "${NNS_PUBLIC_KEY}" "${CONFIG_DIR}/${NODE_PREFIX}/nns_public_key.pem"

        echo "nns_url=${NNS_URL}" >"${CONFIG_DIR}/${NODE_PREFIX}/nns.conf"
        mkdir -p "${CONFIG_DIR}/${NODE_PREFIX}/buildinfo"
        cat >"${CONFIG_DIR}/${NODE_PREFIX}/buildinfo/version.prom" <<EOF
# HELP api_version_info version information for the api node
# TYPE api_version_info counter
api_version_info{git_revision="${GIT_REVISION}"} 1
EOF

        # Copy vars listing from environment's Ansible inventory
        # to the BN's /boot/config directory
        echo "$BN_VARS" >"${CONFIG_DIR}/${NODE_PREFIX}/bn_vars.conf"
    done
}

function generate_network_config() {
    local REPLICAS_IPV6=
    if [ -z ${REPLICA_IPS_OVERRIDE+x} ]; then
        # Query and list all NNS nodes in subnet
        for n in $NODES; do
            declare -n NODE=$n

            local ipv6_address=${NODE["ipv6_address"]}

            if [[ "${NODE["type"]}" != "replica" ]]; then
                continue
            fi

            REPLICAS_IPV6+="${ipv6_address}/64,"
        done
    else
        # Remove comments and comma separate
        REPLICAS_IPV6=$(cat ${REPLICA_IPV6_OVERRIDE} | sed 's/[[:blank:]]*#.*//' | awk '$1=$1' ORS=',')
    fi
    REPLICAS_IPV6=$(echo ${REPLICAS_IPV6} | sed 's/,$//g')

    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" == "api" ]]; then
            local hostname=${NODE["hostname"]}
            local subnet_idx=${NODE["subnet_idx"]}
            local node_idx=${NODE["node_idx"]}
            local ipv6_address=${NODE["ipv6_address"]}
            local ipv6_gateway=${NODE["ipv6_gateway"]}
            local ipv4_address=${NODE["ipv4_address"]}
            local ipv4_gateway=${NODE["ipv4_gateway"]}

            # Define hostname
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            echo "hostname=${hostname}" >"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"

            # Set name servers
            echo "ipv6_name_servers=${IPV6_NAME_SERVERS}" >>"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"
            echo "ipv6_name_servers_fallback=${IPV6_NAME_SERVERS_FALLBACK}" >>"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"
            echo "ipv4_name_servers=${IPV4_NAME_SERVERS}" >>"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"

            # ipv6
            if [ -z ${ipv6_address:-} ]; then echo "ipv6_address is unset"; else
                echo "ipv6_address=${ipv6_address}" >>"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"
            fi
            if [ -z ${ipv6_gateway:-} ]; then echo "ipv6_gateway is unset"; else
                echo "ipv6_gateway=${ipv6_gateway}" >>"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"
            fi

            # ipv4
            if [ -z ${ipv4_address:-} ]; then echo "ipv4_address is unset"; else
                echo "ipv4_address=${ipv4_address}" >>"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"
            fi
            if [ -z ${ipv4_gateway:-} ]; then echo "ipv4_gateway is unset"; else
                echo "ipv4_gateway=${ipv4_gateway}" >>"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"
            fi

            # Set ipv6 replicas
            echo "ipv6_replica_ips=${REPLICAS_IPV6}" >>"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"

            cat "${CONFIG_DIR}/${NODE_PREFIX}/network.conf"
            # IPv6 network configuration is obtained from the Router Advertisement.
        fi
    done
}

function copy_ssh_keys() {
    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" == "api" ]]; then
            local subnet_idx=${NODE["subnet_idx"]}
            local node_idx=${NODE["node_idx"]}

            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx

            # Copy the contents of the directory, but make sure that we do not
            # copy/create symlinks (but rather dereference file contents).
            # Symlinks must be refused by the config injection script (they
            # can lead to confusion and side effects when overwriting one
            # file changes another).
            cp -Lr "${SSH}" "${CONFIG_DIR}/${NODE_PREFIX}/accounts_ssh_authorized_keys"
        fi
    done
}

function copy_certs() {
    if [[ -f "${CERT_DIR}/fullchain.pem" && -f "${CERT_DIR}/privkey.pem" && -f "${CERT_DIR}/chain.pem" ]]; then
        echo "Using certificates ${CERT_DIR}/fullchain.pem ${CERT_DIR}/privkey.pem ${CERT_DIR}/chain.pem"
        for n in $NODES; do
            declare -n NODE=$n
            if [[ "${NODE["type"]}" == "api" ]]; then
                local subnet_idx=${NODE["subnet_idx"]}
                local node_idx=${NODE["node_idx"]}

                NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
                mkdir -p "${CONFIG_DIR}/${NODE_PREFIX}/certs"
                cp "${CERT_DIR}/fullchain.pem" "${CONFIG_DIR}/${NODE_PREFIX}/certs"
                cp "${CERT_DIR}/privkey.pem" "${CONFIG_DIR}/${NODE_PREFIX}/certs"
                cp "${CERT_DIR}/chain.pem" "${CONFIG_DIR}/${NODE_PREFIX}/certs"
            fi
        done
    else
        echo "Not copying certificates"
    fi
}

function copy_ip_hash_salt() {
    if [[ -z "${IP_HASH_SALT:-}" ]]; then
        err "ip hashing salt has not been provided, proceeding without copying it"
        return
    fi

    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" != "api" ]]; then
            continue
        fi

        local SUBNET_IDX="${NODE["subnet_idx"]}"
        local NODE_IDX="${NODE["node_idx"]}"
        local NODE_PREFIX="${DEPLOYMENT}.${SUBNET_IDX}.${NODE_IDX}"

        echo "ip_hash_salt=${IP_HASH_SALT}" >>"${CONFIG_DIR}/${NODE_PREFIX}/bn_vars.conf"
    done
}

function copy_logging_credentials() {
    if [[ -z "${LOGGING_URL:-}" || -z "${LOGGING_USER:-}" || -z "${LOGGING_PASSWORD:-}" ]]; then
        err "logging credentials have not been provided, continuing without configuring logging"
        return
    fi

    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" != "api" ]]; then
            continue
        fi

        local SUBNET_IDX="${NODE["subnet_idx"]}"
        local NODE_IDX="${NODE["node_idx"]}"
        local NODE_PREFIX="${DEPLOYMENT}.${SUBNET_IDX}.${NODE_IDX}"

        # Default values
        LOGGING_2XX_SAMPLE_RATE=${LOGGING_2XX_SAMPLE_RATE:-1}

        echo "logging_url=${LOGGING_URL}" >>"${CONFIG_DIR}/${NODE_PREFIX}/bn_vars.conf"
        echo "logging_user=${LOGGING_USER}" >>"${CONFIG_DIR}/${NODE_PREFIX}/bn_vars.conf"
        echo "logging_password=${LOGGING_PASSWORD}" >>"${CONFIG_DIR}/${NODE_PREFIX}/bn_vars.conf"
        echo "logging_2xx_sample_rate=${LOGGING_2XX_SAMPLE_RATE}" >>"${CONFIG_DIR}/${NODE_PREFIX}/bn_vars.conf"
    done
}

function build_tarball() {
    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" == "api" ]]; then
            local subnet_idx=${NODE["subnet_idx"]}
            local node_idx=${NODE["node_idx"]}

            # Create temporary tarball directory per node
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            mkdir -p "${TARBALL_DIR}/${NODE_PREFIX}"
            (
                cd "${CONFIG_DIR}/${NODE_PREFIX}"
                tar c .
            ) >"${TARBALL_DIR}/${NODE_PREFIX}/ic-bootstrap.tar"
        fi
    done
    tar czf "${OUTPUT}/config.tgz" -C "${CONFIG_DIR}" .
}

function build_removable_media() {
    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" == "api" ]]; then
            local subnet_idx=${NODE["subnet_idx"]}
            local node_idx=${NODE["node_idx"]}

            #echo "${DEPLOYMENT}.$subnet_idx.$node_idx"
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            truncate --size 100M "${OUTPUT}/${NODE_PREFIX}.img"
            mkfs.vfat "${OUTPUT}/${NODE_PREFIX}.img"
            mcopy -i "${OUTPUT}/${NODE_PREFIX}.img" -o -s ${TARBALL_DIR}/${NODE_PREFIX}/ic-bootstrap.tar ::
        fi
    done
}

function remove_temporary_directories() {
    rm -rf ${TEMPDIR}
}

function main() {
    # Establish run order
    prepare_build_directories
    create_tarball_structure
    generate_api_node_config
    generate_network_config
    copy_ssh_keys
    copy_certs
    copy_ip_hash_salt
    copy_logging_credentials
    build_tarball
    build_removable_media
    remove_temporary_directories
}

main
