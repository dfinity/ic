#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly BOOT_DIR='/boot/config'

readonly RUN_DIR='/run/ic-node/etc/nginx'

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
            "domain") DOMAIN="${value}" ;;
        esac
    done <"${BN_CONFIG}"

    if [[ -z "${DOMAIN:-}" ]]; then
        err '${DOMAIN} variable not set. nginx will not be configured.'
        exit 1
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

function copy_deny_list() {
    local -r DENY_LIST_SRC="${BOOT_DIR}/denylist.map"
    local -r DENY_LIST_DST="/var/opt/nginx/denylist/denylist.map"

    if [[ -f "${DENY_LIST_DST}" ]]; then
        echo "${DENY_LIST_DST} already present, skipping"
        return
    fi

    if [[ ! -f "${DENY_LIST_SRC}" ]]; then
        touch "${DENY_LIST_DST}"
    else
        cp "${DENY_LIST_SRC}" "${DENY_LIST_DST}"
    fi
}

function setup_domain_name() {
    local -r DOMAIN_DIR="${RUN_DIR}/conf.d"
    local -r DOMAIN_ESCAPED=${DOMAIN//\./\\.}

    mkdir -p "${DOMAIN_DIR}"
    echo "map nop \$domain { default ${DOMAIN}; }" >"${DOMAIN_DIR}/domain_set.conf"
    echo "server_name ~^([^.]+\.${DOMAIN_ESCAPED})$;" >"${DOMAIN_DIR}/server_domain_escaped.conf"
    echo "server_name ${DOMAIN};" >"${DOMAIN_DIR}/server_domain.conf"
    echo "server_name ~^([^.]+\.raw\.${DOMAIN_ESCAPED})$;" >"${DOMAIN_DIR}/server_raw_domain_escaped.conf"
    echo "server_name raw.${DOMAIN};" >"${DOMAIN_DIR}/server_raw_domain.conf"
    echo "server_name .rosetta-exchanges.${DOMAIN};" >"${DOMAIN_DIR}/server_rosetta_domain.conf"
}

function setup_geolite2_dbs() {
    local -r BOOT_DBS="${BOOT_DIR}/geolite2_dbs"
    local -r EMPTY_DBS='/etc/nginx/geoip'
    local -r DBS_DST="${RUN_DIR}/geoip"
    local -r DB_NAMES=(
        GeoLite2-Country.mmdb
        GeoLite2-City.mmdb
    )

    mkdir -p "${DBS_DST}"

    if [[ ! -d "${BOOT_DBS}" ]]; then
        err "missing geolite2 dbs dir '${BOOT_DBS}', defaulting to empty dbs '${EMPTY_DBS}'"
        local -r DBS_SRC="${EMPTY_DBS}"
    else
        local -r DBS_SRC="${BOOT_DBS}"
    fi

    # Copy databases
    for DB_NAME in "${DB_NAMES[@]}"; do
        if [[ ! -f "${DBS_SRC}/${DB_NAME}" ]]; then
            err "missing geolite2 db: ${DBS_SRC}/${DB_NAME}"
            exit 1
        fi

        cp \
            "${DBS_SRC}/${DB_NAME}" \
            "${DBS_DST}/${DB_NAME}"
    done
}

function setup_ic_router() {
    local -r SNAKEOIL_PEM='/etc/ssl/certs/ssl-cert-snakeoil.pem'
    local -r IC_ROUTING='/var/opt/nginx/ic'
    local -r TRUSTED_CERTS="${IC_ROUTING}/trusted_certs.pem"
    local -r NGINX_TABLE="${IC_ROUTING}/nginx_table.conf"
    local -r IC_ROUTER_TABLE="${IC_ROUTING}/ic_router_table.js"

    # Place to store the generated routing tables
    mkdir -p "${IC_ROUTING}"

    # trusted_cert.pem contains all certificates for the upstream replica. This file
    # is periodically updated by the proxy+watcher service. To bootstrap the process
    # we initially place a dummy trusted cert. This dummy is the copy of the
    # snakeoil cert. This allows the nginx service to start, but upstream routing
    # will only happen once the control plane pulls the initial set of routes
    if [[ ! -f "${TRUSTED_CERTS}" ]]; then
        cp "${SNAKEOIL_PEM}" "${TRUSTED_CERTS}"
    fi

    if [[ ! -f "${NGINX_TABLE}" ]]; then
        cat >"${NGINX_TABLE}" <<EOF
# MAINTAINED BY ic_router_control_plane.py DO NOT EDIT BY HAND
# END MAINTAINED BY ic_router_control_plane.py DO NOT EDIT BY HAND
EOF
    fi

    if [[ ! -f "${IC_ROUTER_TABLE}" ]]; then
        cat >"${IC_ROUTER_TABLE}" <<EOF
let subnet_table = {
// MAINTAINED BY ic_router_control_plane.py DO NOT EDIT BY HAND
// END MAINTAINED BY ic_router_control_plane.py DO NOT EDIT BY HAND
};
export default subnet_table;
EOF
    fi
}

function main() {
    read_variables
    copy_certs
    copy_deny_list
    setup_domain_name
    setup_geolite2_dbs
    setup_ic_router
}

main "$@"
