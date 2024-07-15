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

  --ipv4_name_servers servers
    DNS servers to use. Can be multiple servers separated by space (make sure
    to quote the argument string so it appears as a single argument to the
    script, e.g., --name_servers "8.8.8.8 1.1.1.1").

  --ipv6_name_servers servers
    DNS servers to use. Can be multiple servers separated by space (make sure
    to quote the argument string so it appears as a single argument to the
    script, e.g., --name_servers "2606:4700:4700::1111 2606:4700:4700::1001").

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
    comma-delimited list of domains serving system canisters (e.g., ic0.dev or ic0.app)

  --application-domains
    comma-delimited list of domains serving application canisters (e.g., ic0.dev or ic0.app)

  --certdir
    specify the directory holding TLS certificates for the hosted domain
    (default: None i.e., snakeoil/self certified certificate will be used)

  --ipv4_http_ips
    the ipv4 blocks (e.g., "1.2.3.4/5") to be whitelisted for inbound http(s)
    traffic. Multiple block may be specified separated by commas.

  --ipv6_http_ips
    the ipv6 blocks (e.g., "1:2:3:4::/64") to be whitelisted for inbound http(s)
    traffic. Multiple block may be specified separated by commas.

  --ipv6_debug_ips
    the ipv6 blocks (e.g., "1:2:3:4::/64") to be whitelisted for inbound debug
    (e.g., ssh) traffic. Multiple block may be specified separated by commas.

  --ipv6_monitoring_ips
    the ipv6 blocks (e.g., "1:2:3:4::/64") to be whitelisted for inbound
    monitoring (e.g., prometheus) traffic. Multiple block may be specified separated by
    commas.

  --canary-proxy-port
    the portnumber to run the canary proxy on. Canary proxy disabled if not provided

  --certificate_orchestrator_uri
    the API domain to reach the certificate orchestrator canister (e.g., https://ic0.app/).

  --certificate_orchestrator_canister_id
    the canister ID of the certificate orchestrator.

  --certificate_issuer_delegation_domain
    the delegation domain, which is used for the DNS-01 ACME challenges.

  --certificate_issuer_name_servers
    name servers used for verifying custom-domains DNS configuration

  --certificate_issuer_name_servers_port
    port used for communicating with name servers

  --certificate_issuer_acme_provider_url
    URL of the ACME provider (e.g., https://acme-v02.api.letsencrypt.org for Let's Encrypt).

  --certificate_issuer_cloudflare_api_url
    the URL of the DNS provider that controls the delegation domain.

  --certificate_issuer_cloudflare_api_key
    the API key that controls the delegation domain.

  --certificate_issuer_identity
    path to the file containing an allowlisted identity in the certificate orchestrator.

  --certificate_issuer_encryption_key
    path to the file containing the symmetric encryption key to encrypt the certificates
    (and the corresponding private keys) before uploading them to the certificate
    orchestrator canister.

  --certificate_issuer_task_delay_sec
    delay in seconds that is added to the processing deadline for any task that
    the certificate issuer submits to the certificate orchestrator.

  --certificate_issuer_task_error_delay_sec
    delay in seconds that is added to the processing deadline for any task that
    failed while processing in the certificate issuer.

  --certificate_issuer_peek_sleep_sec
    time between peeks by the certificate issuer to fetch a new task from the
    certificate orchestrator.

  --certificate_syncer_polling_interval_sec
    time between polling the certificate issuer for custom domain updates (i.e.,
    newly registered, modified, or removed custom domains).

  --ic_registry_local_store
    path to a local registry store to be used instead of the one provided by the
    registry replicator.

  --env
    deployment environment (dev/prod/test)

EOF
}

# Arguments:
# - $1 the comma separated list of IPv4 addresses/prefixes
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
# - $1 the comma separated list of IPv6 addresses/prefixes
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

# check variables ensures that either ALL or NONE
# of the given variable names are set
#
# Arguments:
# - $@ space separated list of variable names
function check_variables() {
    declare -a REQUIRED_VARIABLES=($@)

    COUNT=0
    if [[ "${#REQUIRED_VARIABLES[@]}" -gt 0 ]]; then
        for VAR in "${REQUIRED_VARIABLES[@]}"; do
            if [[ -v "${VAR}" && ! -z "${!VAR}" ]]; then
                ((COUNT++))
            fi
        done
    fi

    if ! [[ "${COUNT}" == 0 || "${COUNT}" == "${#REQUIRED_VARIABLES[@]}" ]]; then
        return 1
    fi

    return 0
}

# Arguments:
# - $1 the tar file to build
# - all remaining arguments: parameters to encode into the bootstrap
function build_ic_bootstrap_tar() {
    local OUT_FILE="$1"
    shift

    # Firewall
    local IPV4_HTTP_IPS IPV6_HTTP_IPS IPV6_DEBUG_IPS IPV6_MONITORING_IPS
    # Canary Proxy
    local CANARY_PROXY_PORT
    # Custom domains
    local CERTIFICATE_ORCHESTRATOR_URI CERTIFICATE_ORCHESTRATOR_CANISTER_ID CERTIFICATE_ISSUER_DELEGATION_DOMAIN
    local CERTIFICATE_ISSUER_ACME_PROVIDER_URL CERTIFICATE_ISSUER_CLOUDFLARE_API_URL CERTIFICATE_ISSUER_CLOUDFLARE_API_KEY
    local CERTIFICATE_ISSUER_NAME_SERVERS CERTIFICATE_ISSUER_NAME_SERVERS_PORT CERTIFICATE_ISSUER_IDENTITY CERTIFICATE_ISSUER_ENCRYPTION_KEY
    local CERTIFICATE_ISSUER_TASK_DELAY_SEC CERTIFICATE_ISSUER_TASK_ERROR_DELAY_SEC CERTIFICATE_ISSUER_PEEK_SLEEP_SEC

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
            --ipv4_name_servers)
                local IPV4_NAME_SERVERS="$2"
                ;;
            --ipv6_name_servers)
                local IPV6_NAME_SERVERS="$2"
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
            --certdir)
                local CERT_DIR="$2"
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
            --canary-proxy-port)
                CANARY_PROXY_PORT="$2"
                ;;
            --certificate_orchestrator_uri)
                CERTIFICATE_ORCHESTRATOR_URI="$2"
                ;;
            --certificate_orchestrator_canister_id)
                CERTIFICATE_ORCHESTRATOR_CANISTER_ID="$2"
                ;;
            --certificate_issuer_delegation_domain)
                CERTIFICATE_ISSUER_DELEGATION_DOMAIN="$2"
                ;;
            --certificate_issuer_name_servers)
                CERTIFICATE_ISSUER_NAME_SERVERS="$2"
                ;;
            --certificate_issuer_name_servers_port)
                CERTIFICATE_ISSUER_NAME_SERVERS_PORT="$2"
                ;;
            --certificate_issuer_acme_provider_url)
                CERTIFICATE_ISSUER_ACME_PROVIDER_URL="$2"
                ;;
            --certificate_issuer_cloudflare_api_url)
                CERTIFICATE_ISSUER_CLOUDFLARE_API_URL="$2"
                ;;
            --certificate_issuer_cloudflare_api_key)
                CERTIFICATE_ISSUER_CLOUDFLARE_API_KEY="$2"
                ;;
            --certificate_issuer_identity)
                CERTIFICATE_ISSUER_IDENTITY="$2"
                ;;
            --certificate_issuer_encryption_key)
                CERTIFICATE_ISSUER_ENCRYPTION_KEY="$2"
                ;;
            --certificate_issuer_task_delay_sec)
                CERTIFICATE_ISSUER_TASK_DELAY_SEC="$2"
                ;;
            --certificate_issuer_task_error_delay_sec)
                CERTIFICATE_ISSUER_TASK_ERROR_DELAY_SEC="$2"
                ;;
            --certificate_issuer_peek_sleep_sec)
                CERTIFICATE_ISSUER_PEEK_SLEEP_SEC="$2"
                ;;
            --certificate_syncer_polling_interval_sec)
                CERTIFICATE_SYNCER_POLLING_INTERVAL_SEC="$2"
                ;;
            --ic_registry_local_store)
                IC_REGISTRY_LOCAL_STORE="$2"
                ;;
            --env)
                ENV="$2"
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

    if [ -z ${ENV+x} ]; then
        err "--env not set"
        fail=1
    elif [[ ! "${ENV}" =~ ^(dev|prod|test)$ ]]; then
        err "--env should be set to one of: dev/prod/test"
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
        if [[ ! "${DOMAIN}" =~ ^.*\..*$ && ! "${DOMAIN}" =~ ^\[[0-9a-f:]*\]$ ]]; then
            err "malformed domain name: '${DOMAIN}'"
            fail=1
        fi
    done

    if [[ -z "${APPLICATION_DOMAINS:-}" ]]; then
        APPLICATION_DOMAINS=ic0.app
    fi

    IFS="," read -a APPLICATION_DOMAINS <<<$APPLICATION_DOMAINS

    for DOMAIN in "${APPLICATION_DOMAINS[@]}"; do
        if [[ ! "${DOMAIN}" =~ ^.*\..*$ && ! "${DOMAIN}" =~ ^\[[0-9a-f:]*\]$ ]]; then
            err "malformed domain name: '${DOMAIN}'"
            fail=1
        fi
    done

    CERT_DIR="${CERT_DIR:-}"

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

    # Verify Configuration for Custom-Domains
    CUSTOM_DOMAINS_VARIABLES=(
        CERTIFICATE_ORCHESTRATOR_URI
        CERTIFICATE_ORCHESTRATOR_CANISTER_ID
        CERTIFICATE_ISSUER_DELEGATION_DOMAIN
        CERTIFICATE_ISSUER_NAME_SERVERS
        CERTIFICATE_ISSUER_NAME_SERVERS_PORT
        CERTIFICATE_ISSUER_ACME_PROVIDER_URL
        CERTIFICATE_ISSUER_CLOUDFLARE_API_URL
        CERTIFICATE_ISSUER_CLOUDFLARE_API_KEY
        CERTIFICATE_ISSUER_IDENTITY
        CERTIFICATE_ISSUER_ENCRYPTION_KEY
    )

    if ! check_variables "${CUSTOM_DOMAINS_VARIABLES[@]}"; then
        err "some of the certificate issuance options are not set. Either all or none have to be set"
        fail=1
    fi

    if [[ "${fail}" == 1 ]]; then
        exit 1
    fi

    local BOOTSTRAP_TMPDIR=$(mktemp -d)

    cat >"${BOOTSTRAP_TMPDIR}/network.conf" <<EOF
ipv6_address=${IPV6_ADDRESS:-}
ipv6_gateway=${IPV6_GATEWAY:-}
ipv4_address=${IPV4_ADDRESS:-}
ipv4_gateway=${IPV4_GATEWAY:-}
ipv4_name_servers=${IPV4_NAME_SERVERS:-}
ipv6_name_servers=${IPV6_NAME_SERVERS:-}
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
        cp "${DENYLIST}" "${BOOTSTRAP_TMPDIR}/denylist.json"
    else
        echo "Using empty denylist"
        echo '{"canisters":{}}' >"${BOOTSTRAP_TMPDIR}/denylist.json"
    fi

    # setup the bn_vars
    BN_VARS_PATH="${BOOTSTRAP_TMPDIR}/bn_vars.conf"

    cat >"${BN_VARS_PATH}" <<EOF
$(printf "system_domains=%s\n" "${SYSTEM_DOMAINS[@]}")
$(printf "application_domains=%s\n" "${APPLICATION_DOMAINS[@]}")
canary_proxy_port=${CANARY_PROXY_PORT:-}
denylist_url=${DENYLIST_URL:-}
env=${ENV:-}
elasticsearch_url=${ELASTICSEARCH_URL}
elasticsearch_tags=${ELASTICSEARCH_TAGS:-}
ipv4_http_ips=${IPV4_HTTP_IPS}
ipv6_http_ips=${IPV6_HTTP_IPS}
ipv6_debug_ips=${IPV6_DEBUG_IPS}
ipv6_monitoring_ips=${IPV6_MONITORING_IPS}
logging_url=${LOGGING_URL:-"http://127.0.0.1:12345"}
logging_user=${LOGGING_USER:-"undefined"}
logging_password=${LOGGING_PASSWORD:-"undefined"}
EOF

    # setup the prober identity
    if [[ -n "${PROBER_IDENTITY:-}" ]]; then
        echo "Using prober identity ${PROBER_IDENTITY}"
        cp "${PROBER_IDENTITY}" "${BOOTSTRAP_TMPDIR}/prober_identity.pem"
    fi

    # setup the certificates
    if [[ -n "${CERT_DIR:-}" && -f "${CERT_DIR}/fullchain.pem" && -f "${CERT_DIR}/privkey.pem" && -f "${CERT_DIR}/chain.pem" ]]; then
        echo "Using certificates ${CERT_DIR}/fullchain.pem ${CERT_DIR}/privkey.pem ${CERT_DIR}/chain.pem"
        mkdir -p "${BOOTSTRAP_TMPDIR}/certs"
        cp "${CERT_DIR}/fullchain.pem" "${BOOTSTRAP_TMPDIR}/certs"
        cp "${CERT_DIR}/privkey.pem" "${BOOTSTRAP_TMPDIR}/certs"
        cp "${CERT_DIR}/chain.pem" "${BOOTSTRAP_TMPDIR}/certs"
    fi

    # setup custom domains
    if [[ ! -z "${CERTIFICATE_ORCHESTRATOR_URI:-}" ]]; then
        cp "${CERTIFICATE_ISSUER_IDENTITY}" "${BOOTSTRAP_TMPDIR}/certificate_issuer_identity.pem"
        cp "${CERTIFICATE_ISSUER_ENCRYPTION_KEY}" "${BOOTSTRAP_TMPDIR}/certificate_issuer_enc_key.pem"

        cat >"${BOOTSTRAP_TMPDIR}/certificate_issuer.conf" <<EOF
certificate_orchestrator_uri=${CERTIFICATE_ORCHESTRATOR_URI}
certificate_orchestrator_canister_id=${CERTIFICATE_ORCHESTRATOR_CANISTER_ID}
certificate_issuer_delegation_domain=${CERTIFICATE_ISSUER_DELEGATION_DOMAIN}
certificate_issuer_name_servers=${CERTIFICATE_ISSUER_NAME_SERVERS}
certificate_issuer_name_servers_port=${CERTIFICATE_ISSUER_NAME_SERVERS_PORT}
certificate_issuer_acme_provider_url=${CERTIFICATE_ISSUER_ACME_PROVIDER_URL}
certificate_issuer_cloudflare_api_url=${CERTIFICATE_ISSUER_CLOUDFLARE_API_URL}
certificate_issuer_cloudflare_api_key=${CERTIFICATE_ISSUER_CLOUDFLARE_API_KEY}
${CERTIFICATE_ISSUER_TASK_DELAY_SEC:+certificate_issuer_task_delay_sec=${CERTIFICATE_ISSUER_TASK_DELAY_SEC}}
${CERTIFICATE_ISSUER_TASK_ERROR_DELAY_SEC:+certificate_issuer_task_error_delay_sec=${CERTIFICATE_ISSUER_TASK_ERROR_DELAY_SEC}}
${CERTIFICATE_ISSUER_PEEK_SLEEP_SEC:+certificate_issuer_peek_sleep_sec=${CERTIFICATE_ISSUER_PEEK_SLEEP_SEC}}
EOF
    fi

    if [[ ! -z "${CERTIFICATE_SYNCER_POLLING_INTERVAL_SEC:-}" ]]; then
        cat >"${BOOTSTRAP_TMPDIR}/certificate_syncer.conf" <<EOF
certificate_syncer_polling_interval_sec=${CERTIFICATE_SYNCER_POLLING_INTERVAL_SEC}
EOF
    fi

    # use the registry local store
    if [[ -n "${IC_REGISTRY_LOCAL_STORE:-}" ]]; then
        echo "Using the registry local store at ${IC_REGISTRY_LOCAL_STORE}"
        cp -r "${IC_REGISTRY_LOCAL_STORE}" "${BOOTSTRAP_TMPDIR}/ic_registry_local_store"
    fi

    tar cf "${OUT_FILE}" \
        --sort=name \
        --owner=root:0 \
        --group=root:0 \
        --mtime="UTC 1970-01-01 00:00:00" \
        -C "${BOOTSTRAP_TMPDIR}" .
    rm -rf "${BOOTSTRAP_TMPDIR}"
}

# Arguments:
# - $1 the disk image to be built
# - all remaining arguments: parameters to encode into the bootstrap

function build_ic_bootstrap_diskimage() {
    local OUT_FILE="$1"
    shift

    local TMPDIR=$(mktemp -d)
    local TAR="${TMPDIR}/ic-bootstrap.tar"
    build_ic_bootstrap_tar "${TAR}" "$@"

    size=$(du --bytes "${TAR}" | awk '{print $1}')
    size=$((2 * size + 1048576))
    echo "image size: $size"
    truncate -s $size "${OUT_FILE}"
    mkfs.vfat -n CONFIG "${OUT_FILE}"
    mcopy -i "${OUT_FILE}" -o "${TAR}" ::

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
