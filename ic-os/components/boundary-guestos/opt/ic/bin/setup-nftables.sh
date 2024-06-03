#!/bin/bash
# Generate the network configuration from the information set in the
# configuration store.

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly BN_CONFIG="${BOOT_DIR}/bn_vars.conf"
readonly NETWORK_CONFIG="${BOOT_DIR}/network.conf"

readonly RUN_DIR='/run/ic-node/etc/nftables'
readonly SYSTEM_REPLICAS_FILE="${RUN_DIR}/system_replicas.ruleset"
readonly RULESET_FILE="${RUN_DIR}/defs.ruleset"

ipv6_replica_ips=("::/128")
ipv4_http_ips=("0.0.0.0/32")
ipv6_http_ips=("::/128")
ipv6_debug_ips=("::/128")
ipv6_monitoring_ips=("::/128")

function csv() {
    local -r arr=("$@")
    IFS=,
    echo "${arr[*]}"
}

# Read the network config variables from file. The file must be of the form
# "key=value" for each line with a specific set of keys permissible (see code
# below).
function read_variables() {
    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing node configuration directory: ${BOOT_DIR}"
        exit 1
    fi
    if [ ! -f "${BN_CONFIG}" ]; then
        err "missing bn_vars configuration: ${BN_CONFIG}"
        exit 1
    fi
    if [ ! -f "${NETWORK_CONFIG}" ]; then
        err "missing network configuration: ${NETWORK_CONFIG}"
        exit 1
    fi

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "ipv4_http_ips") ipv4_http_ips+=("${value}") ;;
            "ipv6_http_ips") ipv6_http_ips+=("${value}") ;;
            "ipv6_debug_ips") ipv6_debug_ips+=("${value}") ;;
            "ipv6_monitoring_ips") ipv6_monitoring_ips+=("${value}") ;;
            "canary_proxy_port") canary_proxy_port="${value}" ;;
        esac
    done <"${BN_CONFIG}"

    while IFS="=" read -r key value; do
        case "$key" in
            "ipv6_replica_ips") ipv6_replica_ips+=("${value}") ;;
        esac
    done <"${NETWORK_CONFIG}"
}

# Add extra rules to nftables to limit access.
function generate_nftables_config() {
    mkdir -p "${RUN_DIR}"

    cat >"${RULESET_FILE}" <<EOF
define ipv6_replica_ips    = { $(csv "${ipv6_replica_ips[@]}")    }
define ipv4_http_ips       = { $(csv "${ipv4_http_ips[@]}")       }
define ipv6_http_ips       = { $(csv "${ipv6_http_ips[@]}")       }
define ipv6_debug_ips      = { $(csv "${ipv6_debug_ips[@]}")      }
define ipv6_monitoring_ips = { $(csv "${ipv6_monitoring_ips[@]}") }
define canary_proxy_port   = ${canary_proxy_port:-0}
EOF

    cat >"${SYSTEM_REPLICAS_FILE}" <<EOF
define ipv6_system_replica_ips = { ::/128 }
EOF
}

function main() {
    read_variables
    generate_nftables_config
}

main "$@"
