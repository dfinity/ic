#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'
source '/opt/ic/bin/exec_condition.shlib'

readonly IDENTITY_PEM="${BOOT_DIR}/certificate_issuer_identity.pem"
readonly ENC_KEY_PEM="${BOOT_DIR}/certificate_issuer_enc_key.pem"

readonly RUN_DIR='/run/ic-node/etc/default'
readonly ENV_FILE="${RUN_DIR}/certificate-issuer"
readonly CFG_DIR='/run/ic-node/etc/certificate-issuer'

# Read the config variables. The files must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
function read_variables() {
    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing node configuration directory: ${BOOT_DIR}"
        exit 1
    fi

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "certificate_orchestrator_uri") ORCHESTRATOR_URI="${value}" ;;
            "certificate_orchestrator_canister_id") ORCHESTRATOR_CANISTER_ID="${value}" ;;
            "certificate_issuer_name_servers") NAME_SERVERS="${value}" ;;
            "certificate_issuer_name_servers_port") NAME_SERVERS_PORT="${value}" ;;
            "certificate_issuer_delegation_domain") DELEGATION_DOMAIN="${value}" ;;
            "certificate_issuer_acme_provider_url") ACME_PROVIDER_URL="${value}" ;;
            "certificate_issuer_acme_id") ACME_ACCOUNT_ID="${value}" ;;
            "certificate_issuer_acme_key") ACME_ACCOUNT_KEY="${value}" ;;
            "certificate_issuer_cloudflare_api_url") CLOUDFLARE_API_URL="${value}" ;;
            "certificate_issuer_cloudflare_api_key") CLOUDFLARE_API_KEY="${value}" ;;
            "certificate_issuer_task_delay_sec") TASK_DELAY_SEC="${value}" ;;
            "certificate_issuer_task_error_delay_sec") TASK_ERROR_DELAY_SEC="${value}" ;;
            "certificate_issuer_peek_sleep_sec") PEEK_SLEEP_SEC="${value}" ;;
            "certificate_issuer_important_domains") IMPORTANT_DOMAINS="${value}" ;;
        esac
    done <"${BOOT_DIR}/certificate_issuer.conf"
}

function copy_files() {
    mkdir -p "${CFG_DIR}"
    cp "${IDENTITY_PEM}" "${CFG_DIR}/identity.pem"
    cp "${ENC_KEY_PEM}" "${CFG_DIR}/enc_key.pem"
    get_nns_der >"${CFG_DIR}/root_key.der"
    echo -n "${CLOUDFLARE_API_KEY}" >"${CFG_DIR}/cloudflare_api_key.txt"

    if ! [ -z ${ACME_ACCOUNT_KEY:-} ]; then
        echo -n "${ACME_ACCOUNT_KEY:-}" >"${CFG_DIR}/acme_account_key.txt"
    fi
}

function generate_config() {
    mkdir -p $(dirname "${ENV_FILE}")
    cat >"${ENV_FILE}" <<EOF
IDENTITY_PATH=${CFG_DIR}/identity.pem
NNS_KEY_PATH="${CFG_DIR}/root_key.der"
KEY_PATH=${CFG_DIR}/enc_key.pem
ORCHESTRATOR_URI=${ORCHESTRATOR_URI}
ORCHESTRATOR_CANISTER_ID=${ORCHESTRATOR_CANISTER_ID}
NAME_SERVERS=${NAME_SERVERS:-}
NAME_SERVERS_PORT=${NAME_SERVERS_PORT:-}
DELEGATION_DOMAIN=${DELEGATION_DOMAIN}
ACME_PROVIDER_URL=${ACME_PROVIDER_URL:-}
ACME_ACCOUNT_ID=${ACME_ACCOUNT_ID:-}
ACME_ACCOUNT_KEY_PATH=${ACME_ACCOUNT_KEY:+"${CFG_DIR}"/acme_account_key.txt}
CLOUDFLARE_API_URL=${CLOUDFLARE_API_URL:-}
CLOUDFLARE_API_KEY_PATH=${CFG_DIR}/cloudflare_api_key.txt
TASK_DELAY_SEC=${TASK_DELAY_SEC:-}
TASK_ERROR_DELAY_SEC=${TASK_ERROR_DELAY_SEC:-}
PEEK_SLEEP_SEC=${PEEK_SLEEP_SEC:-}
IMPORTANT_DOMAINS=${IMPORTANT_DOMAINS:-}
EOF
}

function main() {
    if [ ! -f "${IDENTITY_PEM}" ]; then
        echo "missing certificate-issuer identity: ${IDENTITY_PEM}, disabling certificate-issuer"
        disable
        return
    fi

    read_variables
    copy_files
    generate_config
}

main "$@"
