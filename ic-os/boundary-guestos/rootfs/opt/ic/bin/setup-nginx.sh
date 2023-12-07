#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly RUN_DIR='/run/ic-node/etc/nginx'
readonly EMPTY_NJS_EXPORTS='let v = {}; export default v; // PLACEHOLDER'

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
            "require_seo_certification") REQUIRE_SEO_CERTIFICATION="${value}" ;;
            "require_underscore_certification") REQUIRE_UNDERSCORE_CERTIFICATION="${value}" ;;
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

    # Prepend certificate hash to the Service Worker as a comment.
    # This should force browsers to re-download it whenever the certificate is re-issued.
    #
    # See for details:
    # - https://github.com/w3c/ServiceWorker/issues/1523
    # - https://bugs.chromium.org/p/chromium/issues/detail?id=1103551
    # - https://web.dev/service-worker-lifecycle/#updates
    #
    # TODO: remove when the bugs are fixed
    local -r SW="/var/www/html/sw.js"
    local -r CERT_HASH=$(sha256sum "${CERT_DST}/fullchain.pem" | awk '{print $1}')
    echo "/* ${CERT_HASH} */" >"${SW}.prefix"
    cat "${SW}.prefix" "${SW}" >"${SW}.new"
    mv -f "${SW}.new" "${SW}"
    rm -f "${SW}.prefix"

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

function setup_domains() {
    local -r SYSTEM_DOMAINS_PATH="${RUN_DIR}/conf.d/system_domains.conf"
    for DOMAIN in "${SYSTEM_DOMAINS[@]}"; do
        local DOMAIN_ESCAPED=${DOMAIN//\./\\.}
        echo "~^([^.]+\.)?(raw\.)?${DOMAIN_ESCAPED}$ 1;" >>"${SYSTEM_DOMAINS_PATH}"
    done

    local -r APPLICATION_DOMAINS_PATH="${RUN_DIR}/conf.d/application_domains.conf"
    for DOMAIN in "${APPLICATION_DOMAINS[@]}"; do
        local DOMAIN_ESCAPED=${DOMAIN//\./\\.}
        echo "~^([^.]+\.)?(raw\.)?${DOMAIN_ESCAPED}$ 1;" >>"${APPLICATION_DOMAINS_PATH}"
    done

    local -r DOMAIN_DIR="${RUN_DIR}/conf.d"
    mkdir -p "${DOMAIN_DIR}"

    # Configure a fallback api-domain in case an api-domain is not specified (e.g in the case of the testnets)
    local -r FALLBACK_API_DOMAIN="api.${SYSTEM_DOMAINS[0]}"
    if [[ -z "${API_DOMAINS[@]}" ]]; then
        API_DOMAINS+=("${FALLBACK_API_DOMAIN}")
    fi

    # primary domains
    echo "map nop \$primary_system_domain { default ${SYSTEM_DOMAINS[0]}; }" >"${DOMAIN_DIR}/set_primary_system_domain.conf"
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
    local -r IC_LEGACY_ROUTING='/var/cache/ic_routes'
    local -r TRUSTED_CERTS="${IC_ROUTING}/trusted_certs.pem"
    local -r NGINX_TABLE="${IC_ROUTING}/ic_upstreams.conf"
    local -r IC_ROUTER_TABLE="${IC_ROUTING}/ic_routes.js"

    # Place to store the generated routing tables
    mkdir -p "${IC_ROUTING}" "${IC_LEGACY_ROUTING}"

    # trusted_cert.pem contains all certificates for the upstream replica. This file
    # is periodically updated by the proxy+watcher service. To bootstrap the process
    # we initially place a dummy trusted cert. This dummy is the copy of the
    # snakeoil cert. This allows the nginx service to start, but upstream routing
    # will only happen once the control plane pulls the initial set of routes
    if [[ ! -f "${TRUSTED_CERTS}" ]]; then
        cp "${SNAKEOIL_PEM}" "${TRUSTED_CERTS}"
    fi

    if [[ ! -f "${NGINX_TABLE}" ]]; then
        echo '# PLACEHOLDER' >"${NGINX_TABLE}"
    fi

    if [[ ! -f "${IC_ROUTER_TABLE}" ]]; then
        echo "${EMPTY_NJS_EXPORTS}" >"${IC_ROUTER_TABLE}"
    fi
}

function setup_custom_domains() {
    local -r SERVER_BLOCKS='/var/opt/nginx/domains.conf'
    mkdir -p "$(dirname ${SERVER_BLOCKS})"

    if [[ ! -f "${SERVER_BLOCKS}" ]]; then
        touch "${SERVER_BLOCKS}"
    fi

    local -r DOMAIN_MAPPINGS="/var/opt/nginx/domain_canister_mappings.js"
    mkdir -p "$(dirname ${DOMAIN_MAPPINGS})"

    if [[ ! -f "${DOMAIN_MAPPINGS}" ]]; then
        echo "${EMPTY_NJS_EXPORTS}" >"${DOMAIN_MAPPINGS}"
    fi
}

function setup_pre_isolation_canisters() {
    local -r SRC_CANISTERS_PATH="${BOOT_DIR}/pre_isolation_canisters.txt"
    local -r DST_CANISTERS_PATH="/run/ic-node/etc/nginx/conf.d/pre_isolation_canisters.conf"

    # Make sure the file exists
    touch "${DST_CANISTERS_PATH}"

    if [[ ! -f "${SRC_CANISTERS_PATH}" ]]; then
        err "missing pre_isolation_canisters.txt file: ${SRC_CANISTERS_PATH}; continuing with an empty one"
        return
    fi

    # Check that ID matches the regex for a canister ID
    # And write to nginx config
    while read id; do
        echo "${id} 1;" >>"${DST_CANISTERS_PATH}"
    done < <(cat "${SRC_CANISTERS_PATH}" | grep -E '^[a-z0-9-]{27}$')
}

function setup_canister_id_alises() {
    local -r CANISTER_ID_ALIASES_DIR="/var/opt/nginx/canister_aliases"
    local -r CANISTER_ID_ALIASES_PATH="${CANISTER_ID_ALIASES_DIR}/canister_id_aliases.js"

    mkdir -p "${CANISTER_ID_ALIASES_DIR}"
    cat >"${CANISTER_ID_ALIASES_PATH}" <<EOF
let CANISTER_ID_ALIASES = {
  dscvr: "h5aet-waaaa-aaaab-qaamq-cai",
  identity: "rdmx6-jaaaa-aaaaa-aaadq-cai",
  nns: "qoctq-giaaa-aaaaa-aaaea-cai",
  personhood: "g3wsl-eqaaa-aaaan-aaaaa-cai",
};

export default CANISTER_ID_ALIASES;
EOF
}

function setup_cgi() {
    cat >"/run/ic-node/etc/nginx/conf.d/cgi.conf" <<EOF
# Setup server for the cgi
server {
  listen 80;
  listen [::]:80;
  # Fast cgi support from fcgiwrap
  include /etc/nginx/fcgiwrap.conf;
}
EOF
}

function main() {
    read_variables
    copy_certs
    copy_deny_list
    setup_domains
    setup_geolite2_dbs
    setup_ic_router
    setup_custom_domains
    setup_pre_isolation_canisters
    setup_canister_id_alises
    setup_cgi
}

main "$@"
