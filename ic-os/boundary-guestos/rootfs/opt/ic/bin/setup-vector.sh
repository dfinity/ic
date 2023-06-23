#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly BN_CONFIG="${BOOT_DIR}/bn_vars.conf"

readonly RUN_DIR='/run/ic-node/etc/default'
readonly ENV_FILE="${RUN_DIR}/vector"

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
            "elasticsearch_url") ELASTICSEARCH_URL="${value}" ;;
            "elasticsearch_tags") ELASTICSEARCH_TAGS="${value}" ;;
            "ip_hash_salt") IP_HASH_SALT="${value}" ;;
            "logging_url") LOGGING_URL="${value}" ;;
            "logging_user") LOGGING_USER="${value}" ;;
            "logging_password") LOGGING_PASSWORD="${value}" ;;
            "logging_2xx_sample_rate") LOGGING_2XX_SAMPLE_RATE="${value}" ;;
        esac
    done <"${BN_CONFIG}"

    if [[ -z "${ELASTICSEARCH_URL:-}" ]]; then
        err "missing vector configuration value(s): $(cat "${BN_CONFIG}")"
        exit 1
    fi

    # Default to 1% sampling rate (value is 1/N)
    LOGGING_2XX_SAMPLE_RATE=${LOGGING_2XX_SAMPLE_RATE:-100}
}

function generate_vector_config() {
    mkdir -p "${RUN_DIR}"
    cat >"${ENV_FILE}" <<EOF
ENV=${ENV}
ELASTICSEARCH_URL=${ELASTICSEARCH_URL}
ELASTICSEARCH_TAGS=${ELASTICSEARCH_TAGS:-}
IP_HASH_SALT=${IP_HASH_SALT:-}
CLICKHOUSE_URL=${LOGGING_URL:-}
CLICKHOUSE_USER=${LOGGING_USER:-}
CLICKHOUSE_PASSWORD=${LOGGING_PASSWORD:-}
CLICKHOUSE_2XX_SAMPLE_RATE=${LOGGING_2XX_SAMPLE_RATE:-}
EOF
}

function main() {
    read_variables
    generate_vector_config
}

main "$@"
