#!/bin/bash

# Substitute correct configuration parameters into ic.json5. Will take IP addresses
# from configuration file or from network interfaces.

source /opt/ic/bin/config.sh

function usage() {
    cat <<EOF
Usage:
  generate-replica-config -c config.json -i ic.json5.template -o ic.json5

  Generate replica config from template file.

  -c config.json: config object
  -n network.conf: Optional, network configuration description file
  -m malicious_behavior.conf: Optional, malicious behavior parameters

  -i infile: input ic.json5.template file
  -o outfile: output ic.json5 file
EOF
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

function read_config_variables() {
    ipv6_gateway=$(get_config_value '.network_settings.ipv6_config.Deterministic.gateway')
    ipv4_address=$(get_config_value '.network_settings.ipv4_config.address')
    ipv4_prefix_length=$(get_config_value '.network_settings.ipv4_config.prefix_length')
    ipv4_gateway=$(get_config_value '.network_settings.ipv4_config.gateway')
    domain=$(get_config_value '.network_settings.ipv4_config.domain')
    nns_urls=$(get_config_value '.icos_settings.nns_urls | join(",")')
    hostname=$(get_config_value '.icos_settings.hostname')
    backup_retention_time_secs=$(get_config_value '.guestos_settings.guestos_dev_settings.backup_spool.backup_retention_time_seconds')
    backup_purging_interval_secs=$(get_config_value '.guestos_settings.guestos_dev_settings.backup_spool.backup_purging_interval_seconds')
    jaeger_addr=$(get_config_value '.guestos_settings.guestos_dev_settings.jaeger_addr')
    query_stats_epoch_length=$(get_config_value '.guestos_settings.guestos_dev_settings.query_stats_epoch_length')

    # todo:
    # "ipv6_address") ipv6_address="${value}" ;;
    # "malicious_behavior") malicious_behavior="${value}" ;;
}

# XXX: the following function is duplicate with generate-network-config.sh
# -- consolidate
#
# Read the network config variables from file. The file must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
#
# Arguments:
# - $1: Name of the file to be read.
function read_network_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "ipv6_address") ipv6_address="${value}" ;;
        esac
    done <"$1"
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

while getopts "m:n:c:i:o:" OPT; do
    case "${OPT}" in
        n)
            NETWORK_CONFIG_FILE="${OPTARG}"
            ;;
        m)
            MALICIOUS_BEHAVIOR_CONFIG_FILE="${OPTARG}"
            ;;
        c)
            CONFIG_FILE="${OPTARG}"
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

if [ "${CONFIG_FILE}" == "" -o "${IN_FILE}" == "" -o "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

if [ "${NETWORK_CONFIG_FILE}" != "" -a -e "${NETWORK_CONFIG_FILE}" ]; then
    read_network_variables "${NETWORK_CONFIG_FILE}"
fi
if [ "${MALICIOUS_BEHAVIOR_CONFIG_FILE}" != "" -a -e "${MALICIOUS_BEHAVIOR_CONFIG_FILE}" ]; then
    read_malicious_behavior_variables "${MALICIOUS_BEHAVIOR_CONFIG_FILE}"
fi
if [ "${CONFIG_FILE}" != "" -a -e "${CONFIG_FILE}" ]; then
    read_config_variables "${CONFIG_FILE}"
fi



INTERFACE=($(find /sys/class/net -type l -not -lname '*virtual*' -exec basename '{}' ';'))
IPV6_ADDRESS="${ipv6_address%/*}"
IPV6_ADDRESS="${IPV6_ADDRESS:-$(get_if_address_retries 6 ${INTERFACE} 12)}"
if [[ -n "$ipv4_address" && "$ipv4_address" != "null" && -n "$ipv4_prefix_length" && "$ipv4_prefix_length" != "null" ]]; then
  IPV4_ADDRESS="${ipv4_address}/${ipv4_prefix_length}"
else
  IPV4_ADDRESS=""
fi
IPV4_GATEWAY="${ipv4_gateway:-}"
DOMAIN="${domain:-}"
NNS_URLS="${nns_urls:-http://[::1]:8080}"
NODE_INDEX="${node_index:-0}"
# Default value is 24h
BACKUP_RETENTION_TIME_SECS="${backup_retention_time_secs:-86400}"
[ "${backup_retention_time_secs}" = "null" ] && BACKUP_RETENTION_TIME_SECS="86400"
# Default value is 1h
BACKUP_PURGING_INTERVAL_SECS="${backup_purging_interval_secs:-3600}"
[ "${backup_purging_interval_secs}" = "null" ] && BACKUP_PURGING_INTERVAL_SECS="3600"
# Default is null (None)
MALICIOUS_BEHAVIOR="${malicious_behavior:-null}"
# Default is 600 blocks i.e. around 10min
QUERY_STATS_EPOCH_LENGTH="${query_stats_epoch_length:-600}"
[ "${query_stats_epoch_length}" = "null" ] && QUERY_STATS_EPOCH_LENGTH="600"
# TODO: If the Jaeger address is not specified the config file will contain Some(""). This needs to be fixed.
JAEGER_ADDR="${jaeger_addr:-}"
[ "${jaeger_addr}" = "null" ] && JAEGER_ADDR=""

if [ "${IPV6_ADDRESS}" == "" ]; then
    echo "Cannot determine an IPv6 address, aborting"
    exit 1
fi

sed -e "s@{{ ipv6_address }}@${IPV6_ADDRESS}@" \
    -e "s@{{ ipv4_address }}@${IPV4_ADDRESS}@" \
    -e "s@{{ ipv4_gateway }}@${IPV4_GATEWAY}@" \
    -e "s@{{ domain }}@${DOMAIN}@" \
    -e "s@{{ nns_urls }}@${NNS_URLS}@" \
    -e "s@{{ node_index }}@${NODE_INDEX}@" \
    -e "s@{{ backup_retention_time_secs }}@${BACKUP_RETENTION_TIME_SECS}@" \
    -e "s@{{ backup_purging_interval_secs }}@${BACKUP_PURGING_INTERVAL_SECS}@" \
    -e "s@{{ malicious_behavior }}@${MALICIOUS_BEHAVIOR}@" \
    -e "s@{{ query_stats_aggregation }}@\"Enabled\"@" \
    -e "s@{{ query_stats_epoch_length }}@${QUERY_STATS_EPOCH_LENGTH}@" \
    -e "s@{{ jaeger_addr }}@${JAEGER_ADDR}@" \
    "${IN_FILE}" >"${OUT_FILE}"

# umask for service is set to be restricted, but this file needs to be
# world-readable
chmod 644 "${OUT_FILE}"
