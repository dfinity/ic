#!/usr/bin/env bash

set -euo pipefail

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

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

  --elasticsearch_url url
    Logging url to use.

  --elasticsearch_tags tags
    Tags to apply

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

  --denylist path
    Specify an initial denylist of canisters for the Boundary Nodes

  --denylist_url url
    Specify the url for the denylist updater 

  --prober-identity path
    specify an identity file for the prober

  --system-domains
    comma-delimited list of domains serving system canisters (e.g. ic0.dev or ic0.app)

  --application-domains
    comma-delimited list of domains serving application canisters (e.g. ic0.dev or ic0.app)

  --ipv4_http_ips
    the ipv4 blocks (e.g. "1.2.3.4/5") to be whitelisted for inbound http(s)
    traffic. Multiple block may be specified separated by commas.

  --ipv6_http_ips)
    the ipv6 blocks (e.g. "1:2:3:4::/64") to be whitelisted for inbound http(s)
    traffic. Multiple block may be specified separated by commas.

  --ipv6_debug_ips)
    the ipv6 blocks (e.g. "1:2:3:4::/64") to be whitelisted for inbound debug
    (e.g. ssh) traffic. Multiple block may be specified separated by commas.

  --ipv6_monitoring_ips)
    the ipv6 blocks (e.g. "1:2:3:4::/64") to be whitelisted for inbound
    monitoring (e.g. prometheus) traffic. Multiple block may be specified separated by
    commas.

EOF
}

# Arguments:
# - $1 the comma seperated list of IPv4 addresses/prefixes
function check_ipv4_prefixes() {
    local ipv4_prefixes="$1"
    local fail=0
    for ipv4_prefix in ${ipv4_prefixes//,/ }; do
        IFS=/ read -r ipv4_address ipv4_length <<<${ipv4_prefix}

        if [[ ! ${ipv4_address} =~ ^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$ ]]; then
            echo "Incorrectly formatted IPv4 address: ${ipv4_address}"
            fail=1
        fi

        if [[ ! -z "${ipv4_length:-}" ]] && ((ipv4_length < 0 || ipv4_length > 32)); then
            echo "IPv4 prefix length out of bounds: ${ipv4_length}"
            fail=1
        fi
    done
    return ${fail}
}

# Arguments:
# - $1 the comma seperated list of IPv6 addresses/prefixes
function check_ipv6_prefixes() {
    local ipv6_prefixes="$1"
    local fail=0
    for ipv6_prefix in ${ipv6_prefixes//,/ }; do
        IFS=/ read -r ipv6_address ipv6_length <<<${ipv6_prefix}
        if [[ ! ${ipv6_address} =~ ^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$ ]]; then
            err "Incorrectly formatted IPv6 address: ${ipv6_address}"
            fail=1
        fi
        if [[ ! -z "${ipv6_length:-}" ]] && ((ipv6_length < 0 || ipv6_length > 128)); then
            err "IPv6 prefix length out of bounds: ${ipv6_length}"
            fail=1
        fi
    done
    return ${fail}
}

# Arguments:
# - $1 the tar file to build
# - all remaining arguments: parameters to encode into the bootstrap
function build_ic_bootstrap_tar() {
    local OUT_FILE="$1"
    shift

    local IPV4_HTTP_IPS IPV6_HTTP_IPS IPV6_DEBUG_IPS IPV6_MONITORING_IPS REQUIRE_SEO_CERTIFICATION REQUIRE_UNDERSCORE_CERTIFICATION
    while true; do
        if [ $# == 0 ]; then
            break
        fi
        case "$1" in
            --ipv6_address)
                local IPV6_ADDRESS="$2"
                ;;
            --ipv6_gateway)
                local IPV6_GATEWAY="$2"
                ;;
            --ipv4_address)
                local IPV4_ADDRESS="$2"
                ;;
            --ipv4_gateway)
                local IPV4_GATEWAY="$2"
                ;;
            --hostname)
                local HOSTNAME="$2"
                ;;
            --name_servers)
                local NAME_SERVERS="$2"
                ;;
            --elasticsearch_url)
                local ELASTICSEARCH_URL="$2"
                ;;
            --elasticsearch_tags)
                local ELASTICSEARCH_TAGS="$2"
                ;;
            --nns_url)
                local NNS_URL="$2"
                ;;
            --nns_public_key)
                local NNS_PUBLIC_KEY="$2"
                ;;
            --accounts_ssh_authorized_keys)
                local ACCOUNTS_SSH_AUTHORIZED_KEYS="$2"
                ;;
            --denylist)
                local DENYLIST="$2"
                ;;
            --denylist_url)
                local DENYLIST_URL="$2"
                ;;
            --prober-identity)
                local PROBER_IDENTITY="$2"
                ;;
            --system-domains)
                local SYSTEM_DOMAINS="$2"
                ;;
            --application-domains)
                local APPLICATION_DOMAINS="$2"
                ;;
            --ipv6_replica_ips)
                local IPV6_REPLICA_IPS="$2"
                ;;
            --ipv4_http_ips)
                IPV4_HTTP_IPS="$2"
                ;;
            --ipv6_http_ips)
                IPV6_HTTP_IPS="$2"
                ;;
            --ipv6_debug_ips)
                IPV6_DEBUG_IPS="$2"
                ;;
            --ipv6_monitoring_ips)
                IPV6_MONITORING_IPS="$2"
                ;;
            --require_seo_certification)
                REQUIRE_SEO_CERTIFICATION="$2"
                ;;
            --require_underscore_certification)
                REQUIRE_UNDERSCORE_CERTIFICATION="$2"
                ;;
            *)
                err "Unrecognized option: $1"
                usage
                exit 1
                break
                ;;
        esac
        shift 2
    done

    local fail=0
    if [[ -z "${HOSTNAME:-}" ]]; then
        err "missing hostname"
        fail=1
    elif [[ ! "${HOSTNAME}" =~ ^[a-zA-Z]+([a-zA-Z0-9])*(-+[a-zA-Z0-9]*)*$ ]]; then
        err "Invalid hostname: '${HOSTNAME}'"
        fail=1
    fi

    if [[ -z "${NNS_PUBLIC_KEY:-}" ]]; then
        err "missing nns_public_key"
        fail=1
    fi

    if [[ -z "${SYSTEM_DOMAINS:-}" ]]; then
        SYSTEM_DOMAINS=ic0.app
    fi

    IFS="," read -a SYSTEM_DOMAINS <<<$SYSTEM_DOMAINS

    for DOMAIN in "${SYSTEM_DOMAINS[@]}"; do
        if [[ ! "${DOMAIN}" =~ ^.*\..*$ ]]; then
            err "malformed domain name: '${DOMAIN}'"
            fail=1
        fi
    done

    if [[ -z "${APPLICATION_DOMAINS:-}" ]]; then
        APPLICATION_DOMAINS=ic0.app
    fi

    IFS="," read -a APPLICATION_DOMAINS <<<$APPLICATION_DOMAINS

    for DOMAIN in "${APPLICATION_DOMAINS[@]}"; do
        if [[ ! "${DOMAIN}" =~ ^.*\..*$ ]]; then
            err "malformed domain name: '${DOMAIN}'"
            fail=1
        fi
    done

    if [[ -z "${ELASTICSEARCH_URL:-}" ]]; then
        err "missing elasticsearch_url"
        fail=1
    fi

    if [ -z "${NNS_URL:-}" ]; then
        err "missing nns_url"
        fail=1
    fi

    check_ipv4_prefixes ${IPV4_HTTP_IPS:=""} || fail=1
    check_ipv6_prefixes ${IPV6_REPLICA_IPS:=""} || fail=1
    check_ipv6_prefixes ${IPV6_HTTP_IPS:=""} || fail=1
    check_ipv6_prefixes ${IPV6_DEBUG_IPS:=""} || fail=1
    check_ipv6_prefixes ${IPV6_MONITORING_IPS:=""} || fail=1

    if [[ "${fail}" == 1 ]]; then
        exit 1
    fi

    local BOOTSTRAP_TMPDIR=$(mktemp -d)

    cat >"${BOOTSTRAP_TMPDIR}/network.conf" <<EOF
ipv6_address=${IPV6_ADDRESS:-}
ipv6_gateway=${IPV6_GATEWAY:-}
ipv4_address=${IPV4_ADDRESS:-}
ipv4_gateway=${IPV4_GATEWAY:-}
name_servers=${NAME_SERVERS:-}
hostname=${HOSTNAME}
ipv6_replica_ips=${IPV6_REPLICA_IPS}
EOF

    cp "${NNS_PUBLIC_KEY}" "${BOOTSTRAP_TMPDIR}/nns_public_key.pem"

    # list of NNS ipv6 addresses
    echo "nns_url=${NNS_URL}" >"${BOOTSTRAP_TMPDIR}/nns.conf"

    # ssh access
    if [ -n "${ACCOUNTS_SSH_AUTHORIZED_KEYS:-}" ]; then
        cp -r "${ACCOUNTS_SSH_AUTHORIZED_KEYS}" "${BOOTSTRAP_TMPDIR}/accounts_ssh_authorized_keys"
    fi

    # setup the deny list
    if [[ -n "${DENYLIST:-}" ]]; then
        echo "Using deny list ${DENYLIST}"
        cp "${DENYLIST}" "${BOOTSTRAP_TMPDIR}/denylist.map"
    else
        echo "Using empty denylist"
        touch "${BOOTSTRAP_TMPDIR}/denylist.map"
    fi

    # setup the bn_vars
    BN_VARS_PATH="${BOOTSTRAP_TMPDIR}/bn_vars.conf"

    cat >"${BN_VARS_PATH}" <<EOF
$(printf "system_domains=%s\n" "${SYSTEM_DOMAINS[@]}")
$(printf "application_domains=%s\n" "${APPLICATION_DOMAINS[@]}")
denylist_url=${DENYLIST_URL:-}
elasticsearch_url=${ELASTICSEARCH_URL}
elasticsearch_tags=${ELASTICSEARCH_TAGS:-}
ipv4_http_ips=${IPV4_HTTP_IPS}
ipv6_http_ips=${IPV6_HTTP_IPS}
ipv6_debug_ips=${IPV6_DEBUG_IPS}
ipv6_monitoring_ips=${IPV6_MONITORING_IPS}
require_seo_certification=${REQUIRE_SEO_CERTIFICATION:-}
require_underscore_certification=${REQUIRE_UNDERSCORE_CERTIFICATION:-}
EOF

    # setup the prober identity
    if [[ -n "${PROBER_IDENTITY:-}" ]]; then
        echo "Using prober identity ${PROBER_IDENTITY}"
        cp "${PROBER_IDENTITY}" "${BOOTSTRAP_TMPDIR}/prober_identity.pem"
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
