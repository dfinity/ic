#!/usr/bin/env bash

set -o nounset
set -o pipefail

source /opt/ic/bin/config.sh

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function read_config_variables() {
    ipv6_prefix=$(get_config_value '.network_settings.ipv6_prefix')
    ipv6_gateway=$(get_config_value '.network_settings.ipv6_gateway')
    ipv4_address=$(get_config_value '.network_settings.ipv4_address')
    ipv4_prefix_length=$(get_config_value '.network_settings.ipv4_prefix_length')
    ipv4_gateway=$(get_config_value '.network_settings.ipv4_gateway')
    domain=$(get_config_value '.network_settings.domain')
}

# WARNING: Uses 'eval' for command execution.
# Ensure 'command' is a trusted, fixed string.
function eval_command_with_retries() {
    local command="${1}"
    local error_message="${2}"
    local result=""
    local attempt_count=0

    while [ -z "${result}" ] && [ ${attempt_count} -lt 3 ]; do
        result=$(eval "${command}")
        ((attempt_count++))

        if [ -z "${result}" ] && [ ${attempt_count} -lt 3 ]; then
            sleep 1
        fi
    done

    if [ -z "${result}" ]; then
        log_and_halt_installation_on_error "1" "${error_message}"
    fi

    echo "${result}"
}

function get_network_settings() {
    ipv6_capable_interfaces=$(eval_command_with_retries \
        "ip -6 addr show | awk '/^[0-9]+: / {print \$2}' | sed 's/://g' | grep -v '^lo$'" \
        "Failed to get system's network interfaces.")

    if [ -z "${ipv6_capable_interfaces}" ]; then
        log_and_halt_installation_on_error "1" "No network interfaces with IPv6 addresses found."
    else
        echo "IPv6-capable interfaces found:"
        echo "${ipv6_capable_interfaces}"
    fi

    # Full IPv6 address
    ipv6_address_system_full=$(eval_command_with_retries \
        "ip -6 addr show | awk '(/inet6/) && (!/fe80|::1/) { print \$2 }'" \
        "Failed to get system's network configuration.")

    if [ -z "${ipv6_address_system_full}" ]; then
        log_and_halt_installation_on_error "1" "No IPv6 addresses found."
    fi

    ipv6_prefix_system=$(eval_command_with_retries \
        "echo ${ipv6_address_system_full} | cut -d: -f1-4" \
        "Failed to get system's IPv6 prefix.")

    ipv6_subnet_system=$(eval_command_with_retries \
        "echo ${ipv6_address_system_full} | awk -F '/' '{ print \"/\" \$2 }'" \
        "Failed to get system's IPv6 subnet.")

    ipv6_gateway_system=$(eval_command_with_retries \
        "ip -6 route show | awk '(/^default/) { print \$3 }'" \
        "Failed to get system's IPv6 gateway.")

    ipv6_address_system=$(eval_command_with_retries \
        "echo ${ipv6_address_system_full} | awk -F '/' '{ print \$1 }'" \
        "Failed to get system's IPv6 address.")

    HOSTOS_IPV6_ADDRESS=$(/opt/ic/bin/setupos_tool generate-ipv6-address --node-type HostOS)
    GUESTOS_IPV6_ADDRESS=$(/opt/ic/bin/setupos_tool generate-ipv6-address --node-type GuestOS)
}

function print_network_settings() {
    echo "* Printing user defined network settings..."
    echo "  IPv6 Prefix : ${ipv6_prefix}"
    echo "  IPv6 Gateway: ${ipv6_gateway}"
    if [[ -n ${ipv4_address} && -n ${ipv4_prefix_length} && -n ${ipv4_gateway} && -n ${domain} ]]; then
        echo "  IPv4 Address: ${ipv4_address}"
        echo "  IPv4 Prefix Length: ${ipv4_prefix_length}"
        echo "  IPv4 Gateway: ${ipv4_gateway}"
        echo "  Domain name : ${domain}"
    fi
    echo " "

    echo "* Printing system's network settings..."
    echo "  IPv6 Prefix : ${ipv6_prefix_system}"
    echo "  IPv6 Subnet : ${ipv6_subnet_system}"
    echo "  IPv6 Gateway: ${ipv6_gateway_system}"
    echo " "

    echo "* Printing IPv6 addresses..."
    echo "  SetupOS: ${ipv6_address_system_full}"
    echo "  HostOS : ${HOSTOS_IPV6_ADDRESS}"
    echo "  GuestOS: ${GUESTOS_IPV6_ADDRESS}"
    echo " "
}

function validate_domain_name() {
    local domain_part
    local -a domain_parts

    IFS='.' read -ra domain_parts <<<"${domain}"

    if [ ${#domain_parts[@]} -lt 2 ]; then
        log_and_halt_installation_on_error 1 "Domain validation error: less than two domain parts in domain"
    fi

    for domain_part in "${domain_parts[@]}"; do
        if [ -z "$domain_part" ] || [ ${#domain_part} -gt 63 ]; then
            log_and_halt_installation_on_error 1 "Domain validation error: domain part length violation"
        fi

        if [[ $domain_part == -* ]] || [[ $domain_part == *- ]]; then
            log_and_halt_installation_on_error 1 "Domain validation error: domain part starts or ends with a hyphen"
        fi

        if ! [[ $domain_part =~ ^[a-zA-Z0-9-]+$ ]]; then
            log_and_halt_installation_on_error 1 "Domain validation error: invalid characters in domain part"
        fi
    done
}

function setup_ipv4_network() {
    echo "* Setting up IPv4 network..."

    ip addr add ${ipv4_address}/${ipv4_prefix_length} dev 'br6'
    log_and_halt_installation_on_error "${?}" "Unable to add IPv4 address to interface."

    ip route add default via ${ipv4_gateway}
    log_and_halt_installation_on_error "${?}" "Unable to set default route in IPv4 network configuration."
}

function ping_ipv4_gateway() {
    echo "* Pinging IPv4 gateway..."
    # wait 20 seconds maximum for any network changes to settle.
    ping4 -c 2 -w 20 ${ipv4_gateway} >/dev/null 2>&1
    log_and_halt_installation_on_error "${?}" "Unable to ping IPv4 gateway."

    echo "  success"
}

function ping_ipv6_gateway() {
    echo "* Pinging IPv6 gateway..."

    ping6 -c 4 ${ipv6_gateway_system} >/dev/null 2>&1
    log_and_halt_installation_on_error "${?}" "Unable to ping IPv6 gateway."

    echo "  success"
    echo " "
}

function assemble_nns_nodes_list() {
    nns_url_string=$(get_config_value '.icos_settings.nns_url')
    nns_url_list=$(echo $nns_url_string | sed 's@,@ @g')
}

function query_nns_nodes() {
    echo "* Querying NNS nodes..."

    i=0
    success=0
    nodes=$(echo ${nns_url_list} | wc -w)
    # At least one of the provided URLs needs to work.
    verify=1
    for url in $(echo $nns_url_list); do
        # When running against testnets, we need to ignore self signed certs
        # with `--insecure`. This check is only meant to confirm from SetupOS
        # that NNS urls are reachable, so we do not mind that it is "weak".
        curl --insecure --head --connect-timeout 3 --silent ${url} >/dev/null 2>&1
        if [ "${?}" -ne 0 ]; then
            echo "  fail: ${url}"
        else
            echo "  okay: ${url}"
            success=$((${success} + 1))
        fi
        i=$((${i} + 1))
        if [ ${success} -ge ${verify} ]; then
            echo "  success"
            break
        elif [ ${i} -eq ${nodes} ]; then
            log_and_halt_installation_on_error "1" "Unable to query enough healthy NNS nodes."
        fi
    done
}

# Establish run order
main() {
    source /opt/ic/bin/functions.sh
    log_start "$(basename $0)"
    read__config_variables
    get_network_settings
    print_network_settings

    if [[ -n ${ipv4_address} && -n ${ipv4_prefix_length} && -n ${ipv4_gateway} ]]; then
        validate_domain_name
        setup_ipv4_network
        ping_ipv4_gateway
    fi

    ping_ipv6_gateway
    assemble_nns_nodes_list
    query_nns_nodes
    log_end "$(basename $0)"
}

main
