#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly SERVICE_NAME='ic-boundary'

readonly IC_BOUNDARY_CONFIG="${BOOT_DIR}/ic_boundary.conf"
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

    if [ -f "${IC_BOUNDARY_CONFIG}" ]; then
        while IFS="=" read -r key value; do
            case "${key}" in
                "max_concurrency") MAX_CONCURRENCY+=("${value}") ;;
                "shed_ewma_param") SHED_EWMA_PARAM+=("${value}") ;;
            esac
        done <"${IC_BOUNDARY_CONFIG}"
    fi
}

function generate_config() {
    mkdir -p "${RUN_DIR}"

    # Copy NNS Public Key
    cp -a "${NNS_PEM}" "${RUN_DIR}/"

    # Generate Configuration
    cat >"${ENV_FILE}" <<EOF
NNS_URL=${NNS_URL}
CACHE_SIZE=1073741824
CACHE_ITEM_MAX_SIZE=10485760
CACHE_TTL=1
MAX_CONCURRENCY=${MAX_CONCURRENCY:-}
SHED_EWMA_PARAM=${SHED_EWMA_PARAM:-}
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
