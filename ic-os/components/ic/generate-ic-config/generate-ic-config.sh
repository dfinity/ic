#!/bin/bash

# Substitute correct configuration parameters into ic.json5. Will take IP addresses
# from configuration file or from network interfaces.

function usage() {
    cat <<EOF
Usage:
  generate-ic-config [-n network.conf] [-c nns.conf] [-b backup.conf] [-m malicious_behavior.conf] [-q query_stats.conf] [ -r reward.conf ] -i ic.json5.template -o ic.json5

  Generate replica config from template file.

  -n network.conf: Optional, network configuration description file
  -c nns.conf: Optional, address of nns to contact
  -b backup.conf: Optional, parameters of the artifact backup
  -m malicious_behavior.conf: Optional, malicious behavior parameters
  -q query_stats.conf: Optional, query statistics epoch length configuration
  -r reward.conf: Optional, node reward type configuration
  -t jaeger_addr.conf: Optional, Jaeger address
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
            "hostname") hostname="${value}" ;;
            "ipv6_address") ipv6_address="${value}" ;;
            "ipv6_gateway") ipv6_gateway="${value}" ;;
            "ipv4_address") ipv4_address="${value}" ;;
            "ipv4_gateway") ipv4_gateway="${value}" ;;
            "domain") domain="${value}" ;;
        esac
    done <"$1"
}

# Read nns config variables. The file must be of the form "key=value" for each line with a
# specific set of keys permissible (see code below).
#
# Arguments:
# - $1: Name of the file to be read.
function read_nns_variables() {
    while IFS="=" read -r key value; do
        case "$key" in
            "nns_url") nns_urls="${value}" ;;
        esac
    done <"$1"
}

# Read the backup config variables from file. The file must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
#
# Arguments:
# - $1: Name of the file to be read.
function read_backup_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "backup_retention_time_secs") backup_retention_time_secs="${value}" ;;
            "backup_puging_interval_secs") backup_purging_interval_secs="${value}" ;;
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

# Read query stats config variables from file. The file contains a single value which is the epoch length in seconds.
function read_query_stats_variables() {
    while IFS="=" read -r key value; do
        case "$key" in
            "query_stats_epoch_length")
                query_stats_epoch_length="${value}"
                ;;
        esac
    done <"$1"
}

# Read node reward type config variables from file. The file contains a single value which is the node reward type.
function read_node_reward_type_variable() {
    while IFS="=" read -r key value; do
        case "$key" in
            "node_reward_type") node_reward_type="${value}" ;;
        esac
    done <"$1"
}

# Read Jaeger address variable from file. The file contains a single value Jaeger node address used in system tests.
function read_jaeger_addr_variable() {
    while IFS="=" read -r key value; do
        case "$key" in
            "jaeger_addr") jaeger_addr="${value}" ;;
        esac
    done <"$1"
}

while getopts "l:m:q:r:n:c:t:i:o:b:" OPT; do
    case "${OPT}" in
        n)
            NETWORK_CONFIG_FILE="${OPTARG}"
            ;;
        c)
            NNS_CONFIG_FILE="${OPTARG}"
            ;;
        b)
            BACKUP_CONFIG_FILE="${OPTARG}"
            ;;
        m)
            MALICIOUS_BEHAVIOR_CONFIG_FILE="${OPTARG}"
            ;;
        q)
            QUERY_STATS_CONFIG_FILE="${OPTARG}"
            ;;
        r)
            NODE_REWARD_TYPE="${OPTARG}"
            ;;
        t)
            JAEGER_ADDR_FILE="${OPTARG}"
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

if [ "${NETWORK_CONFIG_FILE}" != "" -a -e "${NETWORK_CONFIG_FILE}" ]; then
    read_network_variables "${NETWORK_CONFIG_FILE}"
fi

if [ "${BACKUP_CONFIG_FILE}" != "" -a -e "${BACKUP_CONFIG_FILE}" ]; then
    read_backup_variables "${BACKUP_CONFIG_FILE}"
fi

if [ "${NNS_CONFIG_FILE}" != "" -a -e "${NNS_CONFIG_FILE}" ]; then
    read_nns_variables "${NNS_CONFIG_FILE}"
fi

if [ "${MALICIOUS_BEHAVIOR_CONFIG_FILE}" != "" -a -e "${MALICIOUS_BEHAVIOR_CONFIG_FILE}" ]; then
    read_malicious_behavior_variables "${MALICIOUS_BEHAVIOR_CONFIG_FILE}"
fi

if [ "${QUERY_STATS_CONFIG_FILE}" != "" -a -e "${QUERY_STATS_CONFIG_FILE}" ]; then
    read_query_stats_variables "${QUERY_STATS_CONFIG_FILE}"
fi

if [ "${NODE_REWARD_TYPE}" != "" -a -e "${NODE_REWARD_TYPE}" ]; then
    read_node_reward_type_variable "${NODE_REWARD_TYPE}"
fi

if [ "${JAEGER_ADDR_FILE}" != "" -a -e "${JAEGER_ADDR_FILE}" ]; then
    read_jaeger_addr_variable "${JAEGER_ADDR_FILE}"
fi

INTERFACE=($(find /sys/class/net -type l -not -lname '*virtual*' -exec basename '{}' ';'))
IPV6_ADDRESS="${ipv6_address%/*}"
IPV6_ADDRESS="${IPV6_ADDRESS:-$(get_if_address_retries 6 ${INTERFACE} 12)}"
IPV4_ADDRESS="${ipv4_address:-}"
IPV4_GATEWAY="${ipv4_gateway:-}"
DOMAIN="${domain:-}"
NNS_URLS="${nns_urls:-http://[::1]:8080}"
# Default value is 24h
BACKUP_RETENTION_TIME_SECS="${backup_retention_time_secs:-86400}"
# Default value is 1h
BACKUP_PURGING_INTERVAL_SECS="${backup_purging_interval_secs:-3600}"
# Default is null (None)
MALICIOUS_BEHAVIOR="${malicious_behavior:-null}"
# Default is 600 blocks i.e. around 10min
QUERY_STATS_EPOCH_LENGTH="${query_stats_epoch_length:-600}"
# TODO: If the Jaeger address is not specified the config file will contain Some(""). This needs to be fixed.
JAEGER_ADDR="${jaeger_addr:-}"

# TODO: Should pass prefix directly
if ! IPV6_PREFIX=$(echo "${IPV6_ADDRESS}" | sed -E -e 's/:/#/4' -e '/#/!q1' -e 's/#.*/::\/64/'); then
    # If address does not substitute correctly, fallback to loopback for easy templating
    IPV6_PREFIX="::1/128"
fi

if [ "${IPV6_ADDRESS}" == "" ]; then
    echo "Cannot determine an IPv6 address, aborting"
    exit 1
fi

sed -e "s@{{ ipv6_address }}@${IPV6_ADDRESS}@" \
    -e "s@{{ ipv6_prefix }}@${IPV6_PREFIX}@" \
    -e "s@{{ ipv4_address }}@${IPV4_ADDRESS}@" \
    -e "s@{{ ipv4_gateway }}@${IPV4_GATEWAY}@" \
    -e "s@{{ domain }}@${DOMAIN}@" \
    -e "s@{{ nns_urls }}@${NNS_URLS}@" \
    -e "s@{{ backup_retention_time_secs }}@${BACKUP_RETENTION_TIME_SECS}@" \
    -e "s@{{ backup_purging_interval_secs }}@${BACKUP_PURGING_INTERVAL_SECS}@" \
    -e "s@{{ malicious_behavior }}@${MALICIOUS_BEHAVIOR}@" \
    -e "s@{{ query_stats_epoch_length }}@${QUERY_STATS_EPOCH_LENGTH}@" \
    -e "s@{{ node_reward_type }}@${NODE_REWARD_TYPE}@" \
    -e "s@{{ jaeger_addr }}@${JAEGER_ADDR}@" \
    "${IN_FILE}" >"${OUT_FILE}"

# umask for service is set to be restricted, but this file needs to be
# world-readable
chmod 644 "${OUT_FILE}"
