#!/bin/bash

# Substitute correct configuration parameters into ic.json5. Will take IP addresses
# from configuration file or from network interfaces.

function usage() {
    cat <<EOF
Usage:
  generate-replica-config [-n network.conf] [-c nns.conf] [-b backup.conf] [-l log.conf] [-m malicious_behavior.conf] -i ic.json5.template -o ic.json5

  Generate replica config from template file.

  -n network.conf: Optional, network configuration description file
  -c nns.conf: Optional, address of nns to contact
  -b backup.conf: Optional, parameters of the artifact backup
  -l log.conf: Optional, logging parameters of the node software
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
            "name_servers") name_servers="${value}" ;;
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
            "nns_url") nns_url="${value}" ;;
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

# Read log config variables from file. The file must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
#
# Arguments:
# - $1: Name of the file to be read.
function read_log_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "log_debug_overrides") log_debug_overrides="${value}" ;;
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

while getopts "l:m:n:c:i:o:b:" OPT; do
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
        l)
            LOG_CONFIG_FILE="${OPTARG}"
            ;;
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

if [ "${NETWORK_CONFIG_FILE}" != "" -a -e "${NETWORK_CONFIG_FILE}" ]; then
    read_network_variables "${NETWORK_CONFIG_FILE}"
fi

if [ "${BACKUP_CONFIG_FILE}" != "" -a -e "${BACKUP_CONFIG_FILE}" ]; then
    read_backup_variables "${BACKUP_CONFIG_FILE}"
fi

if [ "${NNS_CONFIG_FILE}" != "" -a -e "${NNS_CONFIG_FILE}" ]; then
    read_nns_variables "${NNS_CONFIG_FILE}"
fi

if [ "${LOG_CONFIG_FILE}" != "" -a -e "${LOG_CONFIG_FILE}" ]; then
    read_log_variables "${LOG_CONFIG_FILE}"
fi

if [ "${MALICIOUS_BEHAVIOR_CONFIG_FILE}" != "" -a -e "${MALICIOUS_BEHAVIOR_CONFIG_FILE}" ]; then
    read_malicious_behavior_variables "${MALICIOUS_BEHAVIOR_CONFIG_FILE}"
fi

IPV6_ADDRESS="${ipv6_address%/*}"
IPV6_ADDRESS="${IPV6_ADDRESS:-$(get_if_address_retries 6 enp1s0 12)}"
NNS_URL="${nns_url:-http://[::1]:8080}"
NODE_INDEX="${node_index:-0}"
# Default value is 24h
BACKUP_RETENTION_TIME_SECS="${backup_retention_time_secs:-86400}"
# Default vlaue is 1h
BACKUP_PURGING_INTERVAL_SECS="${backup_purging_interval_secs:-3600}"
# Default is an empty list
LOG_DEBUG_OVERRIDES="${log_debug_overrides:-[]}"
# Default is null (None)
MALICIOUS_BEHAVIOR="${malicious_behavior:-null}"

if [ "${IPV6_ADDRESS}" == "" ]; then
    echo "Cannot determine an IPv6 address, aborting"
    exit 1
fi

# HACK: host names set on mercury deployment are invalid. Fix this up
# by resetting the host name to be derived from IPv6 address.
if [ "${hostname}" == "" ]; then
    if [ -e "${NETWORK_CONFIG_FILE}" ]; then
        # Derive new hostname.
        # Hostname must start with a letter, not have two consecutive hyphens and end with an alphanumeric.
        NEW_HOST_NAME=ip6$(echo "${IPV6_ADDRESS}" | sed -e 's/::/x/g;s/:/-/g')
        echo "Set new hostname: ${NEW_HOST_NAME}"
        # Substitute hostname in master config file so it persists
        # across reboots and upgrades.
        sed -i "${NETWORK_CONFIG_FILE}" -e "s/hostname=.*/hostname=$NEW_HOST_NAME/"
        # Force set current hostname from master config file.
        /opt/ic/bin/setup-hostname.sh
    fi
fi

sed -e "s@{{ ipv6_address }}@${IPV6_ADDRESS}@" \
    -e "s@{{ nns_url }}@${NNS_URL}@" \
    -e "s@{{ node_index }}@${NODE_INDEX}@" \
    -e "s@{{ backup_retention_time_secs }}@${BACKUP_RETENTION_TIME_SECS}@" \
    -e "s@{{ backup_purging_interval_secs }}@${BACKUP_PURGING_INTERVAL_SECS}@" \
    -e "s@{{ log_debug_overrides }}@${LOG_DEBUG_OVERRIDES}@" \
    -e "s@{{ malicious_behavior }}@${MALICIOUS_BEHAVIOR}@" \
    "${IN_FILE}" >"${OUT_FILE}"

# umask for service is set to be restricted, but this file needs to be
# world-readable
chmod 644 "${OUT_FILE}"
