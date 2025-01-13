#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly SERVICE_NAME='ic-boundary'

readonly IC_BOUNDARY_RATELIMITS="${BOOT_DIR}/canister-ratelimit.yml"

readonly NNS_CONFIG="${BOOT_DIR}/nns.conf"
readonly NNS_PEM="${BOOT_DIR}/nns_public_key.pem"

readonly CFG_DIR='/run/ic-node/etc/ic-boundary'
readonly RUN_DIR='/run/ic-node/etc/default'
readonly ENV_FILE="${RUN_DIR}/${SERVICE_NAME}"

function read_variables() {
    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing node configuration directory: ${BOOT_DIR}"
        exit 1
    fi

    if [ ! -f "${NNS_CONFIG}" ]; then
        err "missing nns configuration: ${NNS_CONFIG}"
        exit 1
    fi

    if [ ! -f "${NNS_PEM}" ]; then
        err "missing nns public key: ${NNS_PEM}"
        exit 1
    fi

    while IFS="=" read -r key value; do
        case "${key}" in
            "nns_url") NNS_URL="${value}" ;;
        esac
    done <"${NNS_CONFIG}"

    if [[ -z "${NNS_URL:-}" ]]; then
        err "missing NNS configuration value(s): $(cat "${NNS_CONFIG}")"
        exit 1
    fi
}

function generate_config() {
    mkdir -p "${RUN_DIR}"

    # Copy NNS Public Key
    cp -a "${NNS_PEM}" "${RUN_DIR}/"

    # Generate Configuration
    cat >"${ENV_FILE}" <<EOF
LISTEN_HTTP_PORT="9000"
NETWORK_HTTP_CLIENT_COUNT="2"
OBS_METRICS_ADDR="[::]:9324"
OBS_LOG_STDOUT="true"
OBS_LOG_FAILED_REQUESTS_ONLY="true"
HTTP_CLIENT_TIMEOUT_CONNECT="3s"
NFTABLES_SYSTEM_REPLICAS_PATH="/run/ic-node/etc/nftables/system_replicas.ruleset"
RETRY_UPDATE_CALL="true"
RATE_LIMIT_PER_SECOND_PER_SUBNET="1000"
RATE_LIMIT_GENERIC_FILE="/run/ic-node/etc/ic-boundary/canister-ratelimit.yml"
REGISTRY_NNS_URLS="${NNS_URL}"
REGISTRY_NNS_PUB_KEY_PEM="/run/ic-node/etc/default/nns_public_key.pem"
REGISTRY_LOCAL_STORE_PATH="/var/opt/registry/store"
CACHE_SIZE="1GB"
CACHE_MAX_ITEM_SIZE="10MB"
CACHE_TTL="1s"
EOF
}

function setup_geolite2_dbs() {
    local -r BOOT_DBS="${BOOT_DIR}/geolite2_dbs"
    local -r EMPTY_DBS='/etc/geoip'

    if [[ ! -d "${BOOT_DBS}" ]]; then
        err "missing geolite2 dbs dir '${BOOT_DBS}', defaulting to empty dbs '${EMPTY_DBS}'"
        local -r DBS_SRC="${EMPTY_DBS}"
    else
        local -r DBS_SRC="${BOOT_DBS}"
    fi

    mkdir -p "${CFG_DIR}"
    cp "${DBS_SRC}/GeoLite2-Country.mmdb" "${CFG_DIR}"
}

function setup_ratelimits() {
    if [ -f "${IC_BOUNDARY_RATELIMITS}" ]; then
        mkdir -p "${CFG_DIR}"
        cp "${IC_BOUNDARY_RATELIMITS}" "${CFG_DIR}"
    fi
}

function main() {
    read_variables
    generate_config
    setup_geolite2_dbs
    setup_ratelimits
    mkdir -p /var/opt/registry/store
}

main "$@"
