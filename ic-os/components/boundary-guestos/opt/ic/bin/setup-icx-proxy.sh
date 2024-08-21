#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly BN_CONFIG="${BOOT_DIR}/bn_vars.conf"

readonly RUN_DIR='/run/ic-node/etc/icx-proxy'
readonly ENV_FILE="${RUN_DIR}/env"
readonly ROOT_KEY="${RUN_DIR}/root_key.der"

SYSTEM_DOMAINS=()
APPLICATION_DOMAINS=()

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
            "system_domains") SYSTEM_DOMAINS+=("${value}") ;;
            "application_domains") APPLICATION_DOMAINS+=("${value}") ;;
            "denylist_url") DENYLIST_URL="${value}" ;;
        esac
    done <"${BN_CONFIG}"

    if [[ "${#SYSTEM_DOMAINS[@]}" -eq 0 ]]; then
        err "SYSTEM_DOMAINS variable not set. icx-proxy won't be configured."
        exit 1
    fi

    if [[ "${#APPLICATION_DOMAINS[@]}" -eq 0 ]]; then
        err "APPLICATION_DOMAINS variable not set. icx-proxy won't be configured."
        exit 1
    fi

    check_nns_pem
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

function generate_icx_proxy_config() {
    local -r DOMAINS=(
        "${SYSTEM_DOMAINS[@]}"
        "${APPLICATION_DOMAINS[@]}"
    )

    local -A UNIQUE_DOMAINS

    for DOMAIN in "${DOMAINS[@]}"; do
        UNIQUE_DOMAINS[$DOMAIN]=0
    done

    for DOMAIN in "${!UNIQUE_DOMAINS[@]}"; do
        ARG_DOMAINS+=("--domain ${DOMAIN}")
    done

    for DOMAIN in "${SYSTEM_DOMAINS[@]}"; do
        local DOMAIN_ESCAPED=${DOMAIN//\./\\.}
        ARG_DOMAINS_SYSTEM+=("--domain-system-regex '^([^.]+\.)?(raw\.)?${DOMAIN_ESCAPED}$'")
    done

    for DOMAIN in "${APPLICATION_DOMAINS[@]}"; do
        local DOMAIN_ESCAPED=${DOMAIN//\./\\.}
        ARG_DOMAINS_APPLICATION+=("--domain-app-regex '^([^.]+\.)?(raw\.)?${DOMAIN_ESCAPED}$'")
    done

    mkdir -p "${RUN_DIR}"

    # Setup network key
    get_nns_der >"${ROOT_KEY}"

    cat >"${ENV_FILE}" <<EOF
DOMAINS=${ARG_DOMAINS[@]}
DOMAINS_SYSTEM=${ARG_DOMAINS_SYSTEM[@]}
DOMAINS_APPLICATION=${ARG_DOMAINS_APPLICATION[@]}
DENYLIST_URL=${DENYLIST_URL:-}
EOF

    # Denylist canister
    cat >"${RUN_DIR}/allowlist.txt" <<EOF
z2rt2-eaaaa-aaaal-abcva-cai
EOF
}

function setup_pre_isolation_canisters() {
    local -r SRC_CANISTERS_PATH="${BOOT_DIR}/pre_isolation_canisters.txt"
    local -r DST_CANISTERS_PATH="${RUN_DIR}/pre_isolation_canisters.txt"

    mkdir -p "${RUN_DIR}"

    if [[ ! -f "${SRC_CANISTERS_PATH}" ]]; then
        touch "${DST_CANISTERS_PATH}"
    else
        cp "${SRC_CANISTERS_PATH}" "${DST_CANISTERS_PATH}"
    fi
}

function main() {
    read_variables
    setup_pre_isolation_canisters
    setup_geolite2_dbs
    copy_deny_list
    generate_icx_proxy_config
}

main "$@"
