#!/usr/bin/env bash

set -e

function usage() {
    cat >&2 <<EOF
build-bootstrap-config-image.sh [-t] out_file [parameters]

Build the configuration image injected into the guest OS
during bootstrap.

The first argument may optionally be "-t" to instruct the script to just build
the tar file that contains the config information. Otherwise, it will build the
disk image that will be injected as removable media into the bootstrap process.

The output file needs to be given next. The script will either write a
disk image or tar file as output file (see above).

Following that are the options specifying the configuration to write. Each of
option takes a value given as next argument, and any number of the following
options may be specified:

  --ipv6_address a:b::c/n
    The IPv6 address to assign. Must include netmask in bits (e.g.
    dead:beef::1/64)

  --ipv6_gateway a:b::c
    Default IPv6 gateway.

  --ipv4_address a.b.c.d

  --ipv4_gateway a.b.c.d
    Default IPv4 gateway.

  --hostname name
    Name to assign to the host. Will be used in logging.

  --name_servers servers
    DNS servers to use. Can be multiple servers separated by space (make sure
    to quote the argument string so it appears as a single argument to the
    script, e.g. --name_servers "8.8.8.8 1.1.1.1").

  --journalbeat_hosts hosts
    Logging hosts to use. Can be multiple hosts separated by space (make sure
    to quote the argument string so it appears as a single argument to the
    script, e.g. --journalbeat_hosts "h1.domain.tld:9220 h2.domain.tld:9230").

  --journalbeat_tags tags
    Tags to be used by Journalbeat. Can be multiple tags separated by space
    (make sure to quote the argument string so it appears as a single argument
    to the script, e.g. --journalbeat_tags "testnet1 slo")

  --nns_url url
    URL of NNS nodes for sign up or registry access. Can be multiple nodes
    separated by commas (make sure to quote the argument string in that
    case).

  --nns_public_key path
    NNS public key file.

  --accounts_ssh_authorized_keys path
    Should point to a directory with files containing the authorized ssh
    keys for specific user accounts on the machine. The name of the
    key designates the name of the account (so, if there is a file
    "PATH/admin" then it is transferred to "~admin/.ssh/authorized_keys" on
    the target). The presently recognized accounts are: backup, readonly,
    admin and root (the latter one for testing purposes only!)

  --deployment-type [prod|dev]
    Creates a file named ./deployment_type with contents 'dev|prod' on the
    config image.  The boundary vm consults this file to perform any runtime
    change required for enabling a development mode. The default deployment type
    is 'prod'.

  --nginx-domainname
    domain name hosted by nginx ic0.dev or ic0.app
EOF
}

# Arguments:
# - $1 the tar file to build
# - all remaining arguments: parameters to encode into the bootstrap
function build_ic_bootstrap_tar() {
    local OUT_FILE="$1"
    shift

    local IPV6_ADDRESS IPV6_GATEWAY NAME_SERVERS HOSTNAME
    local IPV4_ADDRESS IPV4_GATEWAY NAME_SERVERS HOSTNAME
    local NNS_URL NNS_PUBLIC_KEY
    local JOURNALBEAT_HOSTS JOURNALBEAT_TAGS
    local ACCOUNTS_SSH_AUTHORIZED_KEYS
    while true; do
        if [ $# == 0 ]; then
            break
        fi
        case "$1" in
            --ipv6_address)
                IPV6_ADDRESS="$2"
                ;;
            --ipv6_gateway)
                IPV6_GATEWAY="$2"
                ;;
            --ipv4_address)
                IPV4_ADDRESS="$2"
                ;;
            --ipv4_gateway)
                IPV4_GATEWAY="$2"
                ;;
            --hostname)
                HOSTNAME="$2"
                ;;
            --name_servers)
                NAME_SERVERS="$2"
                ;;
            --journalbeat_hosts)
                JOURNALBEAT_HOSTS="$2"
                ;;
            --journalbeat_tags)
                JOURNALBEAT_TAGS="$2"
                ;;
            --nns_url)
                NNS_URL="$2"
                ;;
            --nns_public_key)
                NNS_PUBLIC_KEY="$2"
                ;;
            --accounts_ssh_authorized_keys)
                ACCOUNTS_SSH_AUTHORIZED_KEYS="$2"
                ;;
            --denylist)
                DENY_LIST="$2"
                ;;
            --deployment-type)
                DEPLOYMENT_TYPE="$2"
                if [ ${DEPLOYMENT_TYPE} != "prod" ] && [ ${DEPLOYMENT_TYPE} != "dev" ]; then
                    echo "only prod or dev deployment types supported"
                    usage
                    exit 1
                fi
                ;;
            --nginx-domainname)
                NGINX_DOMAIN_NAME="$2"
                ;;
            *)
                echo "Unrecognized option: $1"
                usage
                exit 1
                break
                ;;
        esac
        shift 2
    done

    [[ "$HOSTNAME" == "" ]] || [[ "$HOSTNAME" == [a-zA-Z]*([a-zA-Z0-9])*(-+([a-zA-Z0-9])) ]] || {
        echo "Invalid hostname: '$HOSTNAME'" >&2
        exit 1
    }

    NGINX_DOMAIN_NAME="${NGINX_DOMAIN_NAME:="ic0.app"}"
    DENY_LIST="${DENY_LIST:=""}"

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

    local BOOTSTRAP_TMPDIR=$(mktemp -d)

    cat >"${BOOTSTRAP_TMPDIR}/network.conf" <<EOF
ipv6_address=$IPV6_ADDRESS
ipv6_gateway=$IPV6_GATEWAY
ipv4_address=$IPV4_ADDRESS
ipv4_gateway=$IPV4_GATEWAY
name_servers=$NAME_SERVERS
hostname=$HOSTNAME
EOF
    if [ "${JOURNALBEAT_HOSTS}" != "" ]; then
        echo "journalbeat_hosts=$JOURNALBEAT_HOSTS" >"${BOOTSTRAP_TMPDIR}/journalbeat.conf"
    fi

    if [ "${JOURNALBEAT_TAGS}" != "" ]; then
        echo "journalbeat_tags=$JOURNALBEAT_TAGS" >>"${BOOTSTRAP_TMPDIR}/journalbeat.conf"
    fi

    if [ "${NNS_PUBLIC_KEY}" != "" ]; then
        cp "${NNS_PUBLIC_KEY}" "${BOOTSTRAP_TMPDIR}/nns_public_key.pem"
    fi

    # list of NNS ipv6 addresses
    if [ "${NNS_URL}" != "" ]; then
        echo "nns_url=${NNS_URL}" >"${BOOTSTRAP_TMPDIR}/nns.conf"
    fi

    # ssh access
    if [ "${ACCOUNTS_SSH_AUTHORIZED_KEYS}" != "" ]; then
        cp -r "${ACCOUNTS_SSH_AUTHORIZED_KEYS}" "${BOOTSTRAP_TMPDIR}/accounts_ssh_authorized_keys"
    fi

    # set the deployment type
    echo ${DEPLOYMENT_TYPE:="prod"} >"${BOOTSTRAP_TMPDIR}/deployment_type"

    # Set the domain name
    echo DOMAIN=${NGINX_DOMAIN} >"${BOOTSTRAP_TMPDIR}/nginxdomain.conf"
    echo TLD=${NGINX_TLD} >>"${BOOTSTRAP_TMPDIR}/nginxdomain.conf"

    # setup the deny list
    if [[ -f ${DENY_LIST} ]]; then
        echo "Using deny list ${DENY_LIST}"
        cp ${DENY_LIST} ${BOOTSTRAP_TMPDIR}/denylist.map
    else
        echo "Using empty denylist"
        touch ${BOOTSTRAP_TMPDIR}/denylist.map
    fi

    tar cf "${OUT_FILE}" -C "${BOOTSTRAP_TMPDIR}" .
    rm -rf "${BOOTSTRAP_TMPDIR}"
}

# Arguments:
# - $1 the disk image to be built
# - all remaining arguments: parameters to encode into the bootstrap

function build_ic_bootstrap_diskimage() {
    local OUT_FILE="$1"
    shift

    local TMPDIR=$(mktemp -d)
    build_ic_bootstrap_tar "${TMPDIR}/ic-bootstrap.tar" "$@"

    truncate -s 10M "${OUT_FILE}"
    mkfs.vfat "${OUT_FILE}"
    mcopy -i "${OUT_FILE}" -o "${TMPDIR}/ic-bootstrap.tar" ::

    rm -rf "${TMPDIR}"
}

BUILD_TAR_ONLY=0
if [ "$1" == "-t" -o "$1" == "--tar" ]; then
    BUILD_TAR_ONLY=1
    shift
fi

if [ "$#" -lt 2 ]; then
    usage
    exit 1
fi

if [ "${BUILD_TAR_ONLY}" == 0 ]; then
    build_ic_bootstrap_diskimage "$@"
else
    build_ic_bootstrap_tar "$@"
fi
