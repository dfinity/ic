#!/usr/bin/env bash

# Build subnet based on subnet.json and transform it into removable media.

# Build Requirements:
# - Operating System: Ubuntu 20.04
# - Packages: coreutils, jq, mtools, tar, util-linux, wget, rclone

set -o errexit
set -o pipefail

BASE_DIR="$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT=$(git rev-parse --show-toplevel)

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
  -d=, --nginx-domainname=              domain name hosted by nginx ic0.dev or ic0.app
  -b=, --denylist=                      a deny list of canisters
       --git-revision=                  git revision for which to prepare the media
       --deployment-type={prod|dev}        production or development deployment type
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
        -c=* | --certdir=*)
            CERT_DIR="${argument#*=}"
            shift
            ;;
        -n=* | --nns_url=*)
            NNS_URL_OVERRIDE="${argument#*=}"
            shift
            ;;
        --git-revision=*)
            GIT_REVISION="${argument#*=}"
            shift
            ;;
        -d=* | --nginx-domainname=*)
            NGINX_DOMAIN_NAME="${argument#*=}"
            ;;
        -b=* | --denylist=*)
            DENY_LIST="${argument#*=}"
            ;;
        --deployment-type=*)
            DEPLOYMENT_TYPE="${argument#*=}"
            shift
            # mark the deployment as a dev/prod
            if [ ${DEPLOYMENT_TYPE} != "prod" ] && [ ${DEPLOYMENT_TYPE} != "dev" ]; then
                echo "only prod or dev deployment types supported"
                exit 1
            fi
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
CERT_DIR="${CERT_DIR:=""}"
DENY_LIST="${DENY_LIST:=""}"
GIT_REVISION="${GIT_REVISION:=}"
DEPLOYMENT_TYPE="${DEPLOYMENT_TYPE:="prod"}"
NGINX_DOMAIN_NAME="${NGINX_DOMAIN_NAME:="ic0.app"}"

if ! echo $NGINX_DOMAIN_NAME | grep -q ".*\..*"; then
    echo "malformed domain name $NGINX_DOMAIN_NAME"
    NGINX_DOMAIN_NAME="ic0.app"
fi

echo "Using domain name $NGINX_DOMAIN_NAME"
NGINX_DOMAIN=${NGINX_DOMAIN_NAME%.*}
NGINX_TLD=${NGINX_DOMAIN_NAME#*.}
if [[ $NGINX_DOMAIN == "" ]] || [[ $NGINX_TLD == "" ]]; then
    echo "Malformed nginx domain $NGINX_DOMAIN_NAME using defaults"
    NGINX_DOMAIN="${NGINX_DOMAIN:="ic0"}"
    NGINX_TLD="${NGINX_TLD:="app"}"
fi

if [[ -z "$GIT_REVISION" ]]; then
    echo "Please provide the GIT_REVISION as env. variable or the command line with --git-revision=<value>"
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
    .ipv4_gateway,
    .ipv4_address,
    .hostname,
    .subnet_type,
    .subnet_idx,
    .node_idx,
    .use_hsm,
    .type
] | join("\u0001")')
while IFS=$'\1' read -r ipv6_prefix ipv6_subnet ipv6_address ipv4_gateway ipv4_address hostname subnet_type subnet_idx node_idx use_hsm type; do
    eval "declare -A __RAW_NODE_$NODES=(
        ['ipv6_prefix']=$ipv6_prefix
        ['ipv6_subnet']=$ipv6_subnet
        ['ipv6_address']=$ipv6_address
	['ipv4_gateway']=$ipv4_gateway
        ['ipv4_address']=$ipv4_address
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

    mkdir -p "${IC_PREP_DIR}/bin"
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${TARBALL_DIR}"

    if [ ! -d "${OUTPUT}" ]; then
        mkdir -p "${OUTPUT}"
    fi
}

function download_binaries() {
    for filename in "boundary-node-control-plane.gz" "boundary-node-prober.gz"; do
        "${REPO_ROOT}"/gitlab-ci/src/artifacts/rclone_download.py \
            --git-rev "$GIT_REVISION" --remote-path=release --include ${filename} --out="${IC_PREP_DIR}/bin/"
    done

    find "${IC_PREP_DIR}/bin/" -name "*.gz" -print0 | xargs -P100 -0I{} bash -c "gunzip -f {} && basename {} .gz | xargs -I[] chmod +x ${IC_PREP_DIR}/bin/[]"

    mkdir -p "$OUTPUT/bin"
    rsync -a --delete "${IC_PREP_DIR}/bin/" "$OUTPUT/bin/"
}

function place_control_plane() {
    cp -a "${IC_PREP_DIR}/bin/boundary-node-control-plane" "$REPO_ROOT/ic-os/boundary-guestos/rootfs/opt/ic/bin/boundary-node-control-plane"
    cp -a "${IC_PREP_DIR}/bin/boundary-node-prober" "$REPO_ROOT/ic-os/boundary-guestos/rootfs/opt/ic/bin/boundary-node-prober"
}

function create_tarball_structure() {
    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" = "boundary" ]]; then
            local subnet_idx=${NODE["subnet_idx"]}
            local node_idx=${NODE["node_idx"]}
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            mkdir -p "${CONFIG_DIR}/$NODE_PREFIX/node/replica_config"
        fi
    done
}

function generate_journalbeat_config() {
    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" == "boundary" ]]; then
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
        fi
    done
}

function generate_boundary_node_config() {
    rm -rf ${IC_PREP_DIR}/NNS_URL
    if [ -z ${NNS_URL_OVERRIDE+x} ]; then
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
        NNS_URL_FILE=${IC_PREP_DIR}/NNS_URL
    else
        NNS_URL_FILE=${NNS_URL_OVERRIDE}
    fi
    NNS_URL="$(cat ${NNS_URL_FILE} | awk '$1=$1' ORS=',' | sed 's@,$@@g')"
    #echo ${NNS_URL}

    # nns config for boundary nodes
    echo ${CONFIG} | jq -c '.datacenters[]' | while read datacenters; do
        echo ${datacenters} | jq -c '[.boundary_nodes[]][]' | while read nodes; do
            local subnet_idx=$(echo ${nodes} | jq -r '.subnet_idx')
            local node_idx=$(echo ${nodes} | jq -r '.node_idx')
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            if [ -f "${IC_PREP_DIR}/nns_public_key.pem" ]; then
                cp "${IC_PREP_DIR}/nns_public_key.pem" "${CONFIG_DIR}/$NODE_PREFIX/nns_public_key.pem"
            fi
            echo "nns_url=${NNS_URL}" >"${CONFIG_DIR}/$NODE_PREFIX/nns.conf"
            echo ${DEPLOYMENT_TYPE:="prod"} >"${CONFIG_DIR}/$NODE_PREFIX"/deployment_type
            echo DOMAIN=${NGINX_DOMAIN} >"${CONFIG_DIR}/$NODE_PREFIX"/nginxdomain.conf
            echo TLD=${NGINX_TLD} >>"${CONFIG_DIR}/$NODE_PREFIX"/nginxdomain.conf
        done
    done
}

function generate_network_config() {
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
            echo "hostname=${hostname}" >"${CONFIG_DIR}/$NODE_PREFIX/network.conf"

            # Set name servers
            echo "name_servers=${NAME_SERVERS}" >>"${CONFIG_DIR}/$NODE_PREFIX/network.conf"
            echo "name_servers_fallback=${NAME_SERVERS_FALLBACK}" >>"${CONFIG_DIR}/$NODE_PREFIX/network.conf"

            # Set ipv4 address
            if [ -z ${ipv4_address:-} ]; then
                echo "ipv4_address is unset"
            else
                echo "ipv4_address=${ipv4_address}" >>"${CONFIG_DIR}/$NODE_PREFIX/network.conf"
            fi

            # Set ipv4 gateway
            if [ -z ${ipv4_gateway:-} ]; then
                echo "ipv4_gateway is unset"
            else
                echo "ipv4_gateway=${ipv4_gateway}" >>"${CONFIG_DIR}/$NODE_PREFIX/network.conf"
            fi

            cat "${CONFIG_DIR}/$NODE_PREFIX/network.conf"
            # IPv6 network configuration is obtained from the Router Advertisement.
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
            cp -Lr "${SSH}" "${CONFIG_DIR}/$NODE_PREFIX/accounts_ssh_authorized_keys"
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
            if [[ -f ${DENY_LIST} ]]; then
                echo "Using deny list ${DENY_LIST}"
                cp ${DENY_LIST} ${CONFIG_DIR}/$NODE_PREFIX/denylist.map
            else
                echo "Using empty denylist"
                touch ${CONFIG_DIR}/$NODE_PREFIX/denylist.map
            fi
        fi
    done
}

function copy_certs() {
    if [[ -f ${CERT_DIR}/fullchain.pem ]] && [[ -f ${CERT_DIR}/privkey.pem ]] && [[ -f ${CERT_DIR}/chain.pem ]]; then
        echo "Using certificates ${CERT_DIR}/fullchain.pem ${CERT_DIR}/privkey.pem ${CERT_DIR}/chain.pem"
        for n in $NODES; do
            declare -n NODE=$n
            if [[ "${NODE["type"]}" == "boundary" ]]; then
                local subnet_idx=${NODE["subnet_idx"]}
                local node_idx=${NODE["node_idx"]}

                NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
                mkdir -p ${CONFIG_DIR}/$NODE_PREFIX/certs
                cp ${CERT_DIR}/fullchain.pem ${CONFIG_DIR}/$NODE_PREFIX/certs
                cp ${CERT_DIR}/privkey.pem ${CONFIG_DIR}/$NODE_PREFIX/certs
                cp ${CERT_DIR}/chain.pem ${CONFIG_DIR}/$NODE_PREFIX/certs
            fi
        done
    else
        echo "Not copying certificates"
    fi
}

function build_tarball() {
    for n in $NODES; do
        declare -n NODE=$n
        if [[ "${NODE["type"]}" == "boundary" ]]; then
            local subnet_idx=${NODE["subnet_idx"]}
            local node_idx=${NODE["node_idx"]}

            # Create temporary tarball directory per node
            NODE_PREFIX=${DEPLOYMENT}.$subnet_idx.$node_idx
            mkdir -p "${TARBALL_DIR}/$NODE_PREFIX"
            (
                cd "${CONFIG_DIR}/$NODE_PREFIX"
                tar c .
            ) >${TARBALL_DIR}/$NODE_PREFIX/ic-bootstrap.tar
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
            truncate --size 4M "${OUTPUT}/$NODE_PREFIX.img"
            mkfs.vfat "${OUTPUT}/$NODE_PREFIX.img"
            mcopy -i "${OUTPUT}/$NODE_PREFIX.img" -o -s ${TARBALL_DIR}/$NODE_PREFIX/ic-bootstrap.tar ::
        fi
    done
}

function remove_temporary_directories() {
    rm -rf ${TEMPDIR}
}

function main() {
    # Establish run order
    prepare_build_directories
    download_binaries
    place_control_plane
    create_tarball_structure
    generate_boundary_node_config
    generate_journalbeat_config
    generate_network_config
    copy_ssh_keys
    copy_certs
    copy_deny_list
    build_tarball
    build_removable_media
    # remove_temporary_directories
}

main
