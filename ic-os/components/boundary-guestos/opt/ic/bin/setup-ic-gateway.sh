#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly BN_CONFIG="${BOOT_DIR}/bn_vars.conf"
readonly IC_BOUNDARY_CONFIG="${BOOT_DIR}/ic_boundary.conf"

readonly RUN_DIR='/run/ic-node/etc/ic-gateway'
readonly ENV_FILE="${RUN_DIR}/env"
readonly ROOT_KEY="${RUN_DIR}/root_key.der"

API_DOMAINS=()
SYSTEM_DOMAINS=()
APPLICATION_DOMAINS=()

function join_by {
    local d=${1-} f=${2-}
    if shift 2; then
        printf %s "$f" "${@/#/$d}"
    fi
}

# Read the config variables. The files must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
function read_variables() {
    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing node configuration directory: ${BOOT_DIR}"
        exit 1
    fi

    if [ ! -f "${BN_CONFIG}" ]; then
        err "missing domain configuration: ${BN_CONFIG}"
        exit 1
    fi

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "env") ENV="${value}" ;;
            "system_domains") SYSTEM_DOMAINS+=("${value}") ;;
            "application_domains") APPLICATION_DOMAINS+=("${value}") ;;
            "api_domains") API_DOMAINS+=("${value}") ;;
            "denylist_url") DENYLIST_URL="${value}" ;;
            "logging_url") LOGGING_URL="${value}" ;;
            "logging_user") LOGGING_USER="${value}" ;;
            "logging_password") LOGGING_PASSWORD="${value}" ;;
        esac
    done <"${BN_CONFIG}"

    if [[ "${#SYSTEM_DOMAINS[@]}" -eq 0 ]]; then
        err "SYSTEM_DOMAINS variable not set. ic-gateway won't be configured."
        exit 1
    fi

    if [[ "${#APPLICATION_DOMAINS[@]}" -eq 0 ]]; then
        err "APPLICATION_DOMAINS variable not set. ic-gateway won't be configured."
        exit 1
    fi

    API_DOMAINS+=("rosetta.dfinity.network")

    # TODO move this later to bn_vars or somewhere else
    MAX_CONCURRENCY=""
    SHED_EWMA_PARAM=""
    if [ -f "${IC_BOUNDARY_CONFIG}" ]; then
        while IFS="=" read -r key value; do
            case "${key}" in
                "max_concurrency") MAX_CONCURRENCY="${value}" ;;
                "shed_ewma_param") SHED_EWMA_PARAM="${value}" ;;
            esac
        done <"${IC_BOUNDARY_CONFIG}"
    fi

    check_nns_pem
}

function setup_geoip_db() {
    local -r BOOT_DBS="${BOOT_DIR}/geolite2_dbs"
    local -r EMPTY_DBS='/etc/geoip'

    if [[ ! -d "${BOOT_DBS}" ]]; then
        err "missing geolite2 dbs dir '${BOOT_DBS}', defaulting to empty dbs '${EMPTY_DBS}'"
        local -r DBS_SRC="${EMPTY_DBS}"
    else
        local -r DBS_SRC="${BOOT_DBS}"
    fi

    cp "${DBS_SRC}/GeoLite2-Country.mmdb" "${RUN_DIR}"
}

function copy_deny_list() {
    local -r DENY_LIST_SRC="${BOOT_DIR}/denylist.json"
    local -r DENY_LIST_DST="${RUN_DIR}/denylist.json"

    if [[ -f "${DENY_LIST_DST}" ]]; then
        echo "${DENY_LIST_DST} already present, skipping"
        return
    fi

    if [[ ! -f "${DENY_LIST_SRC}" ]]; then
        echo '{"canisters":{}}' >"${DENY_LIST_DST}"
    else
        cp "${DENY_LIST_SRC}" "${DENY_LIST_DST}"
    fi
}

function generate_config() {
    # Setup network key
    get_nns_der >"${ROOT_KEY}"

    local DOMAINS_APP=$(join_by , ${APPLICATION_DOMAINS[@]})
    local DOMAINS_SYSTEM=$(join_by , ${SYSTEM_DOMAINS[@]})
    local DOMAINS_API=$(join_by , ${API_DOMAINS[@]})

    # Allow denylist canister
    cat >"${RUN_DIR}/allowlist.txt" <<EOF
z2rt2-eaaaa-aaaal-abcva-cai
EOF

    cat >"${ENV_FILE}" <<EOF
ENV="${ENV}"
DOMAIN_APP="${DOMAINS_APP}"
DOMAIN_SYSTEM="${DOMAINS_SYSTEM}"
DOMAIN_API="${DOMAINS_API}"
LISTEN_PLAIN="[::]:80"
LISTEN_TLS="[::]:443"
DNS_PROTOCOL="https"
METRICS_LISTEN="[::]:9314"
POLICY_PRE_ISOLATION_CANISTERS="${RUN_DIR}/pre_isolation_canisters.txt"
POLICY_DENYLIST_ALLOWLIST="${RUN_DIR}/allowlist.txt"
POLICY_DENYLIST_SEED="${RUN_DIR}/denylist.json"
DOMAIN_CANISTER_ALIAS="identity:rdmx6-jaaaa-aaaaa-aaadq-cai,nns:qoctq-giaaa-aaaaa-aaaea-cai"
GEOIP_DB="${RUN_DIR}/GeoLite2-Country.mmdb"
IC_URL="http://127.0.0.1:9000"
IC_ROOT_KEY="${ROOT_KEY}"
CERT_PROVIDER_DIR="${RUN_DIR}/certs"
CERT_PROVIDER_ISSUER_URL="http://127.0.0.1:3000"
CERT_DEFAULT="icp0.io"
LOG_STDOUT="true"
CACHE_SIZE="2GB"
CACHE_MAX_ITEM_SIZE="20MB"
CACHE_TTL="10s"
CACHE_LOCK_TIMEOUT="10s"
CACHE_XFETCH_BETA="3.0"
SHED_SYSTEM_EWMA="0.9"
SHED_SYSTEM_CPU="0.95"
SHED_SYSTEM_MEMORY="0.95"
SHED_SHARDED_EWMA="0.6"
SHED_SHARDED_PASSTHROUGH="20000"
SHED_SHARDED_LATENCY="query:2s,call:2s,sync_call:13s,read_state:2s,read_state_subnet:2s,status:100ms,health:100ms,registrations:5s,http:5s"
EOF

    if [ ! -z "${DENYLIST_URL:-}" ]; then
        echo "POLICY_DENYLIST_URL=\"${DENYLIST_URL}\"" >>"${ENV_FILE}"
    fi

    if [ ! -z "${LOGGING_URL:-}" ]; then
        echo "LOG_VECTOR_URL=\"${LOGGING_URL}\"" >>"${ENV_FILE}"
        echo "LOG_VECTOR_USER=\"${LOGGING_USER}\"" >>"${ENV_FILE}"
        echo "LOG_VECTOR_PASS=\"${LOGGING_PASSWORD}\"" >>"${ENV_FILE}"
    fi

    if [ ! -z "${MAX_CONCURRENCY:-}" ]; then
        echo "LOAD_MAX_CONCURRENCY=\"${MAX_CONCURRENCY}\"" >>"${ENV_FILE}"
    fi

    if [ ! -z "${SHED_EWMA_PARAM:-}" ]; then
        echo "LOAD_SHED_EWMA_PARAM=\"${SHED_EWMA_PARAM}\"" >>"${ENV_FILE}"
    fi
}

function setup_pre_isolation_canisters() {
    local -r SRC_CANISTERS_PATH="${BOOT_DIR}/pre_isolation_canisters.txt"
    local -r DST_CANISTERS_PATH="${RUN_DIR}/pre_isolation_canisters.txt"

    if [[ ! -f "${SRC_CANISTERS_PATH}" ]]; then
        touch "${DST_CANISTERS_PATH}"
    else
        cp "${SRC_CANISTERS_PATH}" "${DST_CANISTERS_PATH}"
    fi
}

function setup_certs() {
    mkdir -p "${RUN_DIR}/certs"

    if [ -f "${BOOT_DIR}/certs/fullchain.pem" ]; then
        cp "${BOOT_DIR}/certs/fullchain.pem" "${RUN_DIR}/certs/cert.pem"
    else
        cp "/etc/ssl/certs/ssl-cert-snakeoil.pem" "${RUN_DIR}/certs/cert.pem"
    fi

    if [ -f "${BOOT_DIR}/certs/privkey.pem" ]; then
        cp "${BOOT_DIR}/certs/privkey.pem" "${RUN_DIR}/certs/cert.key"
    else
        cp "/etc/ssl/private/ssl-cert-snakeoil.key" "${RUN_DIR}/certs/cert.key"
    fi
}

function main() {
    mkdir -p "${RUN_DIR}"

    read_variables
    setup_pre_isolation_canisters
    setup_geoip_db
    copy_deny_list
    setup_certs
    generate_config
}

main "$@"
