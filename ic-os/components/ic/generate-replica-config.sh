#!/bin/bash

# Substitute correct configuration parameters into ic.json5. Will take IP addresses
# from configuration file or from network interfaces.

source /opt/ic/bin/config.sh

function usage() {
    cat <<EOF
Usage:
  generate-replica-config -i ic.json5.template -o ic.json5

  Generate replica config from template file.

  -m malicious_behavior.conf: Optional, malicious behavior parameters

  -i infile: input ic.json5.template file
  -o outfile: output ic.json5 file
EOF
}

function read_config_variables() {
    NNS_URLS=$(get_config_value '.icos_settings.nns_urls | join(",")')
    NODE_INDEX=$(get_config_value '.icos_settings.hostname')
    BACKUP_RETENTION_TIME_SECS=$(get_config_value '.guestos_settings.guestos_dev_settings.backup_spool.backup_retention_time_seconds')
    BACKUP_PURGING_INTERVAL_SECS=$(get_config_value '.guestos_settings.guestos_dev_settings.backup_spool.backup_purging_interval_seconds')
    QUERY_STATS_EPOCH_LENGTH=$(get_config_value '.guestos_settings.guestos_dev_settings.query_stats_epoch_length')
    JAEGER_ADDR=$(get_config_value '.guestos_settings.guestos_dev_settings.jaeger_addr')

    # todo:
    # "malicious_behavior") malicious_behavior="${value}" ;;
}

function configure_ipv6() {
    ipv6_config_type=$(get_config_value '.network_settings.ipv6_config | keys[]')
    case "$ipv6_config_type" in
        "Deterministic")
            echo "GuestOS IPv6 configuration should not be 'Deterministic'."
            exit 1
            ;;
        "Fixed")
            IPV6_ADDRESS=$(get_config_value '.network_settings.ipv6_config.Fixed.address')
            ;;
        "RouterAdvertisement")
            interface=($(find /sys/class/net -type l -not -lname '*virtual*' -exec basename '{}' ';'))
            IPV6_ADDRESS="$(get_if_address_retries 6 ${interface} 12)"
            ;;
        *)
            echo "ERROR: Unknown IPv6 configuration type."
            exit 1
            ;;
    esac

    if [ "${IPV6_ADDRESS}" == "" ]; then
        echo "Cannot determine an IPv6 address, aborting"
        exit 1
    fi
}

function configure_ipv4() {
    IPV4_ADDRESS="" IPV4_GATEWAY="" DOMAIN=""
    ipv4_config_present=$(get_config_value '.network_settings.ipv4_config != null')
    if [ "$ipv4_config_present" = "true" ]; then
        ipv4_address=$(get_config_value '.network_settings.ipv4_config.address')
        ipv4_prefix_length=$(get_config_value '.network_settings.ipv4_config.prefix_length')
        IPV4_ADDRESS="${ipv4_address}/${ipv4_prefix_length}"
        IPV4_GATEWAY=$(get_config_value '.network_settings.ipv4_config.gateway')
        DOMAIN=$(get_config_value '.network_settings.ipv4_config.domain')
    fi
}

# Get address of interface
#
# Arguments:
# - $1: address family (4 or 6 for IPv4 or IPv6)
# - $2: interface name
function get_if_address() {
    local FAMILY=-"$1"
    local INTERFACE="$2"
    ip -o "${FAMILY}" addr show up primary scope global "${INTERFACE}" | while read -r num dev family addr options; do
        echo ${addr%/*}
        break
    done
}

# Get address of interface, retrying for a while
#
# Arguments:
# - $1: address family (4 or 6 for IPv4 or IPv6)
# - $2: interface name
# - $3: number of retries, trying every second
function get_if_address_retries() {
    local FAMILY=-"$1"
    local INTERFACE="$2"
    local RETRIES="$3"
    local ADDR=""
    while [ "${RETRIES}" != 0 -a "$ADDR" == "" ]; do
        ADDR=$(get_if_address "${FAMILY}" "${INTERFACE}")
        if [ "${ADDR}" != "" ]; then
            echo "${ADDR}"
            break
        fi
        RETRIES=$(("${RETRIES}" - 1))
        echo "Retrying ${RETRIES} ..." 1>&2
        sleep 10
    done
}

function set_default_config_values() {
    [ "${NNS_URLS}" = "null" ] && NNS_URLS="http://[::1]:8080"
    [ "${NODE_INDEX}" = "null" ] && NODE_INDEX="0"
    [ "${BACKUP_RETENTION_TIME_SECS}" = "null" ] && BACKUP_RETENTION_TIME_SECS="86400"  # Default value is 24h
    [ "${BACKUP_PURGING_INTERVAL_SECS}" = "null" ] && BACKUP_PURGING_INTERVAL_SECS="3600"  # Default value is 1h
    [ "${QUERY_STATS_EPOCH_LENGTH}" = "null" ] && QUERY_STATS_EPOCH_LENGTH="600"  # Default is 600 blocks (around 10min)

    # TODO: If the Jaeger address is not specified the config file will contain Some(""). This needs to be fixed.
    [ "${JAEGER_ADDR}" = "null" ] && JAEGER_ADDR=""
}

# Read malicious behavior config variables from file. The file must be of the
# form "key=value" for each line with a specific set of keys permissible (see
# code below).
#
# Arguments:
# - $1: Name of the file to be read.
function read_malicious_behavior_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "malicious_behavior") malicious_behavior="${value}" ;;
        esac
    done <"$1"
}

while getopts "m:i:o:" OPT; do
    case "${OPT}" in
        m)
            MALICIOUS_BEHAVIOR_CONFIG_FILE="${OPTARG}"
            ;;
        i)
            IN_FILE="${OPTARG}"
            ;;
        o)
            OUT_FILE="${OPTARG}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

if [ "${IN_FILE}" == "" -o "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

configure_ipv6
configure_ipv4

if [ "${MALICIOUS_BEHAVIOR_CONFIG_FILE}" != "" -a -e "${MALICIOUS_BEHAVIOR_CONFIG_FILE}" ]; then
    read_malicious_behavior_variables "${MALICIOUS_BEHAVIOR_CONFIG_FILE}"
fi

read_config_variables
set_default_config_values

sed -e "s@{{ ipv6_address }}@${IPV6_ADDRESS}@" \
    -e "s@{{ ipv4_address }}@${IPV4_ADDRESS}@" \
    -e "s@{{ ipv4_gateway }}@${IPV4_GATEWAY}@" \
    -e "s@{{ domain }}@${DOMAIN}@" \
    -e "s@{{ nns_urls }}@${NNS_URLS}@" \
    -e "s@{{ node_index }}@${NODE_INDEX}@" \
    -e "s@{{ backup_retention_time_secs }}@${BACKUP_RETENTION_TIME_SECS}@" \
    -e "s@{{ backup_purging_interval_secs }}@${BACKUP_PURGING_INTERVAL_SECS}@" \
    -e "s@{{ malicious_behavior }}@${MALICIOUS_BEHAVIOR}@" \
    -e "s@{{ query_stats_epoch_length }}@${QUERY_STATS_EPOCH_LENGTH}@" \
    -e "s@{{ jaeger_addr }}@${JAEGER_ADDR}@" \
    "${IN_FILE}" >"${OUT_FILE}"

# umask for service is set to be restricted, but this file needs to be
# world-readable
chmod 644 "${OUT_FILE}"
