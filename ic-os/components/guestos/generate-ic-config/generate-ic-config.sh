#!/bin/bash

# Substitute correct configuration parameters into ic.json5. Will take IP addresses
# from configuration file or from network interfaces.

source /opt/ic/bin/config.sh

function usage() {
    cat <<EOF
Usage:
  generate-ic-config -i ic.json5.template -o ic.json5

  Generate replica config from template file.

  -i infile: input ic.json5.template file
  -o outfile: output ic.json5 file
EOF
}

function configure_ipv6() {
    ipv6_config_type=$(get_config_value '.network_settings.ipv6_config | if type=="object" then keys[] else . end')
    case "$ipv6_config_type" in
        "Deterministic")
            echo "GuestOS IPv6 configuration should not be 'Deterministic'."
            exit 1
            ;;
        "Fixed")
            IPV6_ADDRESS=$(get_config_value '.network_settings.ipv6_config.Fixed.address')
            # Remove the subnet part from the IPv6 address
            IPV6_ADDRESS="${IPV6_ADDRESS%%/*}"
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

    if [ -z "${IPV6_ADDRESS}" ]; then
        echo "Cannot determine an IPv6 address, aborting"
        exit 1
    fi

    # TODO: Should pass prefix directly
    if ! IPV6_PREFIX=$(echo "${IPV6_ADDRESS}" | sed -E -e 's/:/#/4' -e '/#/!q1' -e 's/#.*/::\/64/'); then
        # If address does not substitute correctly, fallback to loopback for easy templating
        IPV6_PREFIX="::1/128"
    fi
}

function configure_ipv4() {
    IPV4_ADDRESS="" IPV4_GATEWAY=""
    ipv4_config_present=$(get_config_value '.network_settings.ipv4_config != null')
    if [ "$ipv4_config_present" = "true" ]; then
        ipv4_address=$(get_config_value '.network_settings.ipv4_config.address')
        ipv4_prefix_length=$(get_config_value '.network_settings.ipv4_config.prefix_length')
        IPV4_ADDRESS="${ipv4_address}/${ipv4_prefix_length}"
        IPV4_GATEWAY=$(get_config_value '.network_settings.ipv4_config.gateway')
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

function read_config_variables() {
    NNS_URLS=$(get_config_value '.icos_settings.nns_urls | join(",")')
    BACKUP_RETENTION_TIME_SECS=$(get_config_value '.guestos_settings.guestos_dev_settings.backup_spool.backup_retention_time_seconds')
    BACKUP_PURGING_INTERVAL_SECS=$(get_config_value '.guestos_settings.guestos_dev_settings.backup_spool.backup_purging_interval_seconds')
    QUERY_STATS_EPOCH_LENGTH=$(get_config_value '.guestos_settings.guestos_dev_settings.query_stats_epoch_length')
    JAEGER_ADDR=$(get_config_value '.guestos_settings.guestos_dev_settings.jaeger_addr')
    DOMAIN_NAME=$(get_config_value '.network_settings.domain_name')
    NODE_REWARD_TYPE=$(get_config_value '.icos_settings.node_reward_type')

    # Compact the JSON and escape special characters
    MALICIOUS_BEHAVIOR=$(get_config_value '.guestos_settings.guestos_dev_settings.malicious_behavior' | jq -c '.' | sed 's/[&\/]/\\&/g')

    GENERATE_IC_BOUNDARY_TLS_CERT=$(get_config_value '.guestos_settings.guestos_dev_settings.generate_ic_boundary_tls_cert')
}

function set_default_config_values() {
    [ "${NNS_URLS}" = "null" -o -z "${NNS_URLS}" ] && NNS_URLS="http://[::1]:8080"
    [ "${BACKUP_RETENTION_TIME_SECS}" = "null" -o -z "${BACKUP_RETENTION_TIME_SECS}" ] && BACKUP_RETENTION_TIME_SECS="86400"      # Default is 24h
    [ "${BACKUP_PURGING_INTERVAL_SECS}" = "null" -o -z "${BACKUP_PURGING_INTERVAL_SECS}" ] && BACKUP_PURGING_INTERVAL_SECS="3600" # Default is 1h
    [ "${QUERY_STATS_EPOCH_LENGTH}" = "null" -o -z "${QUERY_STATS_EPOCH_LENGTH}" ] && QUERY_STATS_EPOCH_LENGTH="600"              # Default is 600 blocks (around 10min)
    [ "${JAEGER_ADDR}" = "null" -o -z "${JAEGER_ADDR}" ] && JAEGER_ADDR=""
    [ "${DOMAIN_NAME}" = "null" -o -z "${DOMAIN_NAME}" ] && DOMAIN_NAME=""
    [ "${NODE_REWARD_TYPE}" = "null" -o -z "${NODE_REWARD_TYPE}" ] && NODE_REWARD_TYPE=""
    [ "${MALICIOUS_BEHAVIOR}" = "null" -o -z "${MALICIOUS_BEHAVIOR}" ] && MALICIOUS_BEHAVIOR="null" # Default is null
}

while getopts "i:o:" OPT; do
    case "${OPT}" in
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

read_config_variables
set_default_config_values

sed -e "s@{{ ipv6_address }}@${IPV6_ADDRESS}@" \
    -e "s@{{ ipv6_prefix }}@${IPV6_PREFIX}@" \
    -e "s@{{ ipv4_address }}@${IPV4_ADDRESS}@" \
    -e "s@{{ ipv4_gateway }}@${IPV4_GATEWAY}@" \
    -e "s@{{ domain_name }}@${DOMAIN_NAME}@" \
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

# Generate and inject a self-signed TLS certificate and key for ic-boundary
# for the given domain name. To be used in system tests only.
if [[ -n "${GENERATE_IC_BOUNDARY_TLS_CERT}" ]] && [ "${GENERATE_IC_BOUNDARY_TLS_CERT}" != "null" ]; then
    TLS_KEY_PATH="/var/lib/ic/data/ic-boundary-tls.key"
    TLS_CERT_PATH="/var/lib/ic/data/ic-boundary-tls.crt"

    openssl req -x509 -newkey rsa:2048 \
        -keyout "${TLS_KEY_PATH}" \
        -out "${TLS_CERT_PATH}" -sha256 -days 3650 -nodes \
        -subj /C=CH/ST=Zurich/L=Zurich/O=InternetComputer/OU=ApiBoundaryNodes/CN=${GENERATE_IC_BOUNDARY_TLS_CERT}
    chown ic-replica:nogroup "${TLS_KEY_PATH}" "${TLS_CERT_PATH}"
    chmod 644 "${TLS_KEY_PATH}" "${TLS_CERT_PATH}"
fi
