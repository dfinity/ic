#!/bin/bash
# Generate the network configuration from the information set in the
# configuration store.

set -euox pipefail

readonly BOOT_CONFIG='/boot/config'
readonly RUN_DIR='/run/ic-node/etc/nftables'

ipv6_replica_ips=()
ipv4_http_ips=()
ipv6_http_ips=()
ipv6_debug_ips=()
ipv6_monitoring_ips=()

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

function csv() {
    local -r arr=("$@")
    IFS=,
    echo "${arr[*]}"
}

# Read the network config variables from file. The file must be of the form
# "key=value" for each line with a specific set of keys permissible (see code
# below).
function read_variables() {
    if [[ ! -d "${BOOT_CONFIG}" ]]; then
        err "missing node configuration directory: ${BOOT_CONFIG}"
        exit 1
    fi
    if [ ! -f "${BOOT_CONFIG}/bn_vars.conf" ]; then
        err "missing bn_vars configuration: ${BOOT_CONFIG}/bn_vars.conf"
        exit 1
    fi
    if [ ! -f "${BOOT_CONFIG}/network.conf" ]; then
        err "missing network configuration: ${BOOT_CONFIG}/network.conf"
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
        esac
    done <"${BOOT_CONFIG}/bn_vars.conf"

    while IFS="=" read -r key value; do
        case "$key" in
            "ipv6_replica_ips") ipv6_replica_ips+="${value}" ;;
        esac
    done <"${BOOT_CONFIG}/network.conf"
}

# Add extra rules to nftables to limit access.
function generate_nftables_config() {
    mkdir -p "${RUN_DIR}"

    cat >"${RUN_DIR}/defs.ruleset" <<EOF
define ipv6_replica_ips = { $(csv "${ipv6_replica_ips[@]}") }

define ipv4_http_ips = { $(csv "${ipv4_http_ips[@]}") }

define ipv6_http_ips = { $(csv "${ipv6_http_ips[@]}") }

define ipv6_debug_ips = { $(csv "${ipv6_debug_ips[@]}") }

define ipv6_monitoring_ips = { $(csv "${ipv6_monitoring_ips[@]}") }
EOF
}

function main() {
    read_variables
    generate_nftables_config
}

main "$@"
