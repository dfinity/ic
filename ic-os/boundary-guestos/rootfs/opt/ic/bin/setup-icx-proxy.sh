#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly BN_CONFIG="${BOOT_DIR}/bn_vars.conf"
readonly CERT_DIR="${BOOT_DIR}/certs"
readonly CERTS=("fullchain.pem" "privkey.pem" "chain.pem")

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

    # Disable SSL checking if we don't have real certs
    for CERT in "${CERTS[@]}"; do
        if [[ ! -f "${CERT_DIR}/${CERT}" ]]; then
            echo "missing cert ${CERT_DIR}/${CERT}, disabling ssl"
            SSL_OPTIONS="--danger-accept-invalid-ssl"
        fi
    done

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "system_domains") SYSTEM_DOMAINS+=("${value}") ;;
            "application_domains") APPLICATION_DOMAINS+=("${value}") ;;
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

function generate_icx_proxy_config() {
    local -r DOMAINS=(
        "${SYSTEM_DOMAINS[@]}"
        "${APPLICATION_DOMAINS[@]}"
    )

    local -A UNIQUE_DOMAINS

    for DOMAIN in "${DOMAINS[@]}"; do
        UNIQUE_DOMAINS[$DOMAIN]=0
    done

    for DOMAIN in "${SYSTEM_DOMAINS[@]}"; do
        ARG_REPLICA_DOMAIN_ADDRS+=("--replicas ${DOMAIN}|127.0.0.1:443")
    done

    for DOMAIN in "${!UNIQUE_DOMAINS[@]}"; do
        ARG_DOMAINS+=("--domain ${DOMAIN}")
    done

    mkdir -p "${RUN_DIR}"

    # Setup network key
    get_nns_der >"${ROOT_KEY}"

    cat >"${ENV_FILE}" <<EOF
REPLICA_DOMAIN_ADDRS=${ARG_REPLICA_DOMAIN_ADDRS[@]}
DOMAINS=${ARG_DOMAINS[@]}
SSL_OPTIONS=${SSL_OPTIONS:-}
EOF
}

function main() {
    read_variables
    generate_icx_proxy_config
}

main "$@"
