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

set -o errexit
set -o pipefail

err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

if [[ "${BASH_VERSINFO:-0}" -lt 4 ]]; then
    err "Bash 4+ is required"
    exit 1
fi

BASE_DIR="$(dirname "${BASH_SOURCE[0]}")/.."
GIT_REVISION=$(git rev-parse --verify HEAD)

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            echo 'Usage:

Removable Media Builder for Boundary Node VMs


Arguments:
  -h,  --help                           show this help message and exit
  -i=, --input=                         JSON formatted input file (Default: ./subnet.json)
  -o=, --output=                        removable media output directory (Default: ./build-out/)
  -s=, --ssh=                           specify directory holding SSH authorized_key files (Default: ../../testnet/config/ssh_authorized_keys)
  -c=, --certdir=                       specify directory holding TLS certificates for hosted domain (Default: None i.e. snakeoil/self certified certificate will be used)
  -n=, --nns_urls=                      specify a file that lists on each line a nns url of the form http://[ip]:port this file will override nns urls derived from input json file
  -b=, --denylist=                      a deny list of canisters
       --prober-identity=               specify an identity file for the prober
       --geolite2-country-db=           specify path to GeoLite2 Country Database
       --geolite2-city-db=              specify path to GeoLite2 City Database
       --git-revision=                  git revision for which to prepare the media
  -x,  --debug                          enable verbose console output
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
        -c=* | --certdir=*)
            CERT_DIR="${argument#*=}"
            shift
            ;;
        -n=* | --nns_url=*)
            NNS_URL_OVERRIDE="${argument#*=}"
            shift
            ;;
        --replicas-ipv6=*)
            REPLICA_IPV6_OVERRIDE="${argument#*=}"
            shift
            ;;
        --denylist=*)
            DENY_LIST="${argument#*=}"
            ;;
        --prober-identity=*)
            PROBER_IDENTITY="${argument#*=}"
            ;;
        --geolite2-country-db=*)
            GEOLITE2_COUNTRY_DB="${argument#*=}"
            ;;
        --geolite2-city-db=*)
            GEOLITE2_CITY_DB="${argument#*=}"
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
CERT_DIR="${CERT_DIR:-}"

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
| [.aux_nodes[], .boundary_nodes[], .nodes[]][] | [
    .ipv6_address,
    .ipv4_gateway,
    .ipv4_address,
    .prober,
    .hostname,
    .subnet_type,
    .subnet_idx,
    .node_idx,
    .type
] | join("\u0001")')
while IFS=$'\1' read -r ipv6_address ipv4_gateway ipv4_address prober hostname subnet_type subnet_idx node_idx type; do
    eval "declare -A __RAW_NODE_$NODES=(
        ['ipv6_address']=$ipv6_address
	    ['ipv4_gateway']=$ipv4_gateway
        ['ipv4_address']=$ipv4_address
        ['prober']=$prober
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
        if [[ "${NODE["type"]}" = "boundary" ]]; then
            local subnet_idx=${NODE["subnet_idx"]}
            local node_idx=${NODE["node_idx"]}
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            mkdir -p "${CONFIG_DIR}/${NODE_PREFIX}/node/replica_config"
        fi
    done
}

function generate_logging_config() {
    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" == "boundary" ]]; then
            local subnet_idx=${NODE["subnet_idx"]}
            local node_idx=${NODE["node_idx"]}

            # Define hostname
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx

            if [ "${JOURNALBEAT_HOSTS}" != "" ]; then
                echo "journalbeat_hosts=${JOURNALBEAT_HOSTS}" >"${CONFIG_DIR}/${NODE_PREFIX}/journalbeat.conf"
            fi
            if [ "${JOURNALBEAT_TAGS}" != "" ]; then
                echo "journalbeat_tags=${JOURNALBEAT_TAGS}" >>"${CONFIG_DIR}/${NODE_PREFIX}/journalbeat.conf"
            fi
        fi
    done
}

function generate_boundary_node_config() {
    local NNS_URL=
    if [ -z ${NNS_URL_OVERRIDE+x} ]; then
        # Query and list all NNS nodes in subnet
        for n in $NODES; do
            declare -n NODE=$n

            local ipv6_address=${NODE["ipv6_address"]}

            if [[ "${NODE["type"]}" != "replica" ]] || [[ "${NODE["subnet_type"]}" != "root_subnet" ]]; then
                continue
            fi

            NNS_URL+="http://[${ipv6_address}]:8080,"
        done
    else
        NNS_URL=$(cat ${NNS_URL_OVERRIDE} | awk '$1=$1' ORS=',')
    fi
    NNS_URL=$(echo ${NNS_URL} | sed 's/,$//g')
    #echo "nns_url=${NNS_URL}"

    # nns config for boundary nodes
    for n in $NODES; do
        declare -n NODE=$n

        local subnet_idx=${NODE["subnet_idx"]}
        local node_idx=${NODE["node_idx"]}

        NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx

        if [[ "${NODE["type"]}" != "boundary" ]]; then
            continue
        fi

        if [ -f "${IC_PREP_DIR}/nns_public_key.pem" ]; then
            cp "${IC_PREP_DIR}/nns_public_key.pem" "${CONFIG_DIR}/${NODE_PREFIX}/nns_public_key.pem"
        fi

        echo "nns_url=${NNS_URL}" >"${CONFIG_DIR}/${NODE_PREFIX}/nns.conf"
        mkdir -p "${CONFIG_DIR}/${NODE_PREFIX}/buildinfo"
        cat >"${CONFIG_DIR}/${NODE_PREFIX}/buildinfo/version.prom" <<EOF
# HELP bn_version_info version information for the boundary node
# TYPE bn_version_info counter
bn_version_info{git_revision="${GIT_REVISION}"} 1
EOF

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
        REPLICAS_IPV6=$(cat ${REPLICA_IPV6_OVERRIDE} | awk '$1=$1' ORS=',')
    fi
    REPLICAS_IPV6=$(echo ${REPLICAS_IPV6} | sed 's/,$//g')

    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" == "boundary" ]]; then
            local hostname=${NODE["hostname"]}
            local subnet_idx=${NODE["subnet_idx"]}
            local node_idx=${NODE["node_idx"]}
            local ipv4_address=${NODE["ipv4_address"]}
            local ipv4_gateway=${NODE["ipv4_gateway"]}

            # Define hostname
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            echo "hostname=${hostname}" >"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"

            # Set name servers
            echo "name_servers=${NAME_SERVERS}" >>"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"
            echo "name_servers_fallback=${NAME_SERVERS_FALLBACK}" >>"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"

            # Set ipv4 address
            if [ -z ${ipv4_address:-} ]; then
                echo "ipv4_address is unset"
            else
                echo "ipv4_address=${ipv4_address}" >>"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"
            fi

            # Set ipv4 gateway
            if [ -z ${ipv4_gateway:-} ]; then
                echo "ipv4_gateway is unset"
            else
                echo "ipv4_gateway=${ipv4_gateway}" >>"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"
            fi

            # Set ipv6 replicas
            echo "ipv6_replica_ips=${REPLICAS_IPV6}" >>"${CONFIG_DIR}/${NODE_PREFIX}/network.conf"

            cat "${CONFIG_DIR}/${NODE_PREFIX}/network.conf"
            # IPv6 network configuration is obtained from the Router Advertisement.
        fi
    done
}

function generate_prober_config() {
    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" == "boundary" ]]; then
            local hostname=${NODE["hostname"]}
            local subnet_idx=${NODE["subnet_idx"]}
            local node_idx=${NODE["node_idx"]}
            local prober=${NODE["prober"]}

            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx

            mkdir -p "${CONFIG_DIR}/${NODE_PREFIX}/prober"

            # copy_prober_identity
            if [[ -f "${PROBER_IDENTITY}" ]]; then
                echo "Using prober identity ${PROBER_IDENTITY}"
                cp "${PROBER_IDENTITY}" "${CONFIG_DIR}/${NODE_PREFIX}/prober/identity.pem"
            fi

            # enable/disable prober
            if [ -z ${prober:-} ]; then
                echo "Disabling prober"
                touch "${CONFIG_DIR}/${NODE_PREFIX}/prober/prober.disabled"
            fi
        fi
    done
}

function copy_deny_list() {
    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" == "boundary" ]]; then
            local subnet_idx=${NODE["subnet_idx"]}
            local node_idx=${NODE["node_idx"]}

            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            if [[ -f "${DENY_LIST:-}" ]]; then
                echo "Using deny list ${DENY_LIST}"
                cp "${DENY_LIST}" "${CONFIG_DIR}/${NODE_PREFIX}/denylist.map"
            else
                echo "Using empty denylist"
                touch "${CONFIG_DIR}/${NODE_PREFIX}/denylist.map"
            fi
        fi
    done
}

function copy_ssh_keys() {
    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" == "boundary" ]]; then
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
    if [[ -f "${CERT_DIR}/fullchain.pem" ]] && [[ -f "${CERT_DIR}/privkey.pem" ]] && [[ -f "${CERT_DIR}/chain.pem" ]]; then
        echo "Using certificates ${CERT_DIR}/fullchain.pem ${CERT_DIR}/privkey.pem ${CERT_DIR}/chain.pem"
        for n in $NODES; do
            declare -n NODE=$n
            if [[ "${NODE["type"]}" == "boundary" ]]; then
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

function copy_geolite2_dbs() {
    if [[ -z "${GEOLITE2_COUNTRY_DB}" || -z "${GEOLITE2_CITY_DB}" ]]; then
        err "please provide both country and city geolite2 dbs"
        return
    fi

    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" != "boundary" ]]; then
            continue
        fi

        local SUBNET_IDX="${NODE["subnet_idx"]}"
        local NODE_IDX="${NODE["node_idx"]}"
        local NODE_PREFIX="${DEPLOYMENT}.${SUBNET_IDX}.${NODE_IDX}"

        mkdir -p "${CONFIG_DIR}/${NODE_PREFIX}/geolite2_dbs"
        cp "${GEOLITE2_COUNTRY_DB}" "${CONFIG_DIR}/${NODE_PREFIX}/geolite2_dbs/"
        cp "${GEOLITE2_CITY_DB}" "${CONFIG_DIR}/${NODE_PREFIX}/geolite2_dbs/"
    done
}

function build_tarball() {
    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" == "boundary" ]]; then
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
        if [[ "${NODE["type"]}" == "boundary" ]]; then
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
    generate_boundary_node_config
    generate_logging_config
    generate_network_config
    generate_prober_config
    copy_ssh_keys
    copy_certs
    copy_deny_list
    copy_geolite2_dbs
    build_tarball
    build_removable_media
    remove_temporary_directories
}

main
