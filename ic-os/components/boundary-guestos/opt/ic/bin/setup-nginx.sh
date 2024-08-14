#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly RUN_DIR='/run/ic-node/etc/nginx'

SYSTEM_DOMAINS=()
APPLICATION_DOMAINS=()
API_DOMAINS=()

function read_variables() {
    local -r BN_CONFIG="${BOOT_DIR}/bn_vars.conf"

    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing prober configuration directory: ${BOOT_DIR}"
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
            "api_domains") API_DOMAINS+=("${value}") ;;
        esac
    done <"${BN_CONFIG}"

    if [[ "${#SYSTEM_DOMAINS[@]}" -eq 0 ]]; then
        err "SYSTEM_DOMAINS variable not set. Nginx won't be configured."
        exit 1
    fi

    if [[ "${#APPLICATION_DOMAINS[@]}" -eq 0 ]]; then
        err "APPLICATION_DOMAINS variables not set. Nginx won't be configured."
        exit 1
    fi

    if [[ "${#API_DOMAINS[@]}" -eq 0 ]]; then
        err "API_DOMAINS variables not set but are not required. Proceeding without them."
    fi
}

function copy_certs() {
    local -r SNAKEOIL_PEM='/etc/ssl/certs/ssl-cert-snakeoil.pem'
    local -r CERT_SRC="${BOOT_DIR}/certs"
    local -r CERT_DST="${RUN_DIR}/certs"
    local -r CERTS=("fullchain.pem" "chain.pem")
    mkdir -p "${CERT_DST}"
    for CERT in "${CERTS[@]}"; do
        if [[ -f "${CERT_SRC}/${CERT}" ]]; then
            echo "Using certificate ${CERT_SRC}/${CERT}"
            cp "${CERT_SRC}/${CERT}" "${CERT_DST}/${CERT}"
        else
            echo "Using snakeoil for ${CERT}"
            cp "${SNAKEOIL_PEM}" "${CERT_DST}/${CERT}"
        fi
    done

    local -r SNAKEOIL_KEY='/etc/ssl/private/ssl-cert-snakeoil.key'
    local -r KEYS_SRC="${CERT_SRC}"
    local -r KEYS_DST="${RUN_DIR}/keys"
    local -r KEYS=("privkey.pem")
    mkdir -p "${KEYS_DST}"
    for KEY in "${KEYS[@]}"; do
        if [[ -f "${KEYS_SRC}/${KEY}" ]]; then
            echo "Using certificate ${KEYS_SRC}/${KEY}"
            cp "${KEYS_SRC}/${KEY}" "${KEYS_DST}/${KEY}"
        else
            echo "Using snakeoil for ${KEY}"
            cp "${SNAKEOIL_KEY}" "${KEYS_DST}/${KEY}"
        fi
    done
}

function setup_domains() {
    local -r DOMAIN_DIR="${RUN_DIR}/conf.d"
    mkdir -p "${DOMAIN_DIR}"

    # Configure a fallback api-domain in case an api-domain is not specified (e.g in the case of the testnets)
    local -r FALLBACK_API_DOMAIN="api.${SYSTEM_DOMAINS[0]}"
    if [[ -z "${API_DOMAINS[@]}" ]]; then
        API_DOMAINS+=("${FALLBACK_API_DOMAIN}")
    fi

    # primary domains
    echo "map nop \$primary_application_domain { default ${APPLICATION_DOMAINS[0]}; }" >"${DOMAIN_DIR}/set_primary_application_domain.conf"
    echo "map nop \$primary_api_domain { default ${API_DOMAINS[0]}; }" >"${DOMAIN_DIR}/set_primary_api_domain.conf"

    local -r DOMAINS=(
        "${SYSTEM_DOMAINS[@]}"
        "${APPLICATION_DOMAINS[@]}"
    )

    local -A UNIQUE_DOMAINS

    for DOMAIN in "${DOMAINS[@]}"; do
        UNIQUE_DOMAINS[$DOMAIN]=0
    done

    # server names
    for DOMAIN in "${!UNIQUE_DOMAINS[@]}"; do
        local DOMAIN_ESCAPED=${DOMAIN//\./\\.}

        echo "server_name .rosetta-exchanges.${DOMAIN};" >>"${DOMAIN_DIR}/server_rosetta_domain.conf"
        echo "server_name ~^([^.]+\.${DOMAIN_ESCAPED})$;" >>"${DOMAIN_DIR}/server_domain_escaped.conf"
        echo "server_name ~^([^.]+\.raw\.${DOMAIN_ESCAPED})$;" >>"${DOMAIN_DIR}/server_raw_domain_escaped.conf"
        echo "server_name ${DOMAIN};" >>"${DOMAIN_DIR}/server_domain.conf"
        echo "server_name raw.${DOMAIN};" >>"${DOMAIN_DIR}/server_raw_domain.conf"
    done

    # api domains
    for DOMAIN in "${API_DOMAINS[@]}"; do
        echo "server_name ${DOMAIN};" >>"${DOMAIN_DIR}/api_domain.conf"
    done
}

function setup_custom_domains() {
    local -r SERVER_BLOCKS='/var/opt/nginx/domains.conf'
    mkdir -p "$(dirname ${SERVER_BLOCKS})"

    if [[ ! -f "${SERVER_BLOCKS}" ]]; then
        touch "${SERVER_BLOCKS}"
    fi
}

function main() {
    read_variables
    copy_certs
    setup_domains
    setup_custom_domains
}

main "$@"
