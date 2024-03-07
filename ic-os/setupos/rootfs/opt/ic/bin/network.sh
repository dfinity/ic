#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

CONFIG="${CONFIG:=/var/ic/config/config.ini}"
DEPLOYMENT="${DEPLOYMENT:=/data/deployment.json}"

function read_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "ipv6_prefix") ipv6_prefix="${value}" ;;
            "ipv6_gateway") ipv6_gateway="${value}" ;;
            "ipv4_address") ipv4_address="${value}" ;;
            "ipv4_prefix_length") ipv4_prefix_length="${value}" ;;
            "ipv4_gateway") ipv4_gateway="${value}" ;;
            "domain") domain="${value}" ;;
        esac
    done <"${CONFIG}"
}

function get_network_settings() {
    # Full IPv6 address
    retry=0

    ipv6_address_system_full=$(ip -6 a s | awk '(/inet6/) && (! / fe80| ::1/) { print $2 }')
    log_and_halt_installation_on_error "${?}" "System network configuration failed."

    while [ -z "${ipv6_address_system_full}" ]; do
        let retry=retry+1
        if [ ${retry} -ge 3 ]; then
            log_and_halt_installation_on_error "1" "System network configuration failed."
            break
        else
            sleep 1
            ipv6_address_system_full=$(ip -6 a s | awk '(/inet6/) && (! /fe80|::1/) { print $2 }')
            log_and_halt_installation_on_error "${?}" "System network configuration failed."
        fi
    done

    # IPv6 prefix
    retry=0

    ipv6_prefix_system=$(echo ${ipv6_address_system_full} | cut -d: -f1-4)
    log_and_halt_installation_on_error "${?}" "Unable to get system's IPv6 prefix."

    while [ -z "${ipv6_prefix_system}" ]; do
        let retry=retry+1
        if [ ${retry} -ge 3 ]; then
            log_and_halt_installation_on_error "1" "Unable to get system's IPv6 prefix."
            break
        else
            sleep 1
            ipv6_prefix_system=$(echo ${ipv6_address_system_full} | cut -d: -f1-4)
            log_and_halt_installation_on_error "${?}" "Unable to get system's IPv6 prefix."
        fi
    done

    # IPv6 subnet
    retry=0

    ipv6_subnet_system=$(echo ${ipv6_address_system_full} | awk -F '/' '{ print "/" $2 }')
    log_and_halt_installation_on_error "${?}" "Unable to get system's IPv6 subnet."

    while [ -z "${ipv6_subnet_system}" ]; do
        let retry=retry+1
        if [ ${retry} -ge 3 ]; then
            log_and_halt_installation_on_error "1" "Unable to get system's IPv6 subnet."
            break
        else
            sleep 1
            ipv6_subnet_system=$(echo ${ipv6_address_system_full} | awk -F '/' '{ print "/" $2 }')
            log_and_halt_installation_on_error "${?}" "Unable to get system's IPv6 subnet."
        fi
    done

    # IPv6 gateway
    retry=0

    ipv6_gateway_system=$(ip -6 r s | awk '(/^default/) { print $3 }')
    log_and_halt_installation_on_error "${?}" "Unable to get system's IPv6 gateway."

    while [ -z "${ipv6_gateway_system}" ]; do
        let retry=retry+1
        if [ ${retry} -ge 3 ]; then
            log_and_halt_installation_on_error "1" "Unable to get system's IPv6 gateway."
            break
        else
            sleep 1
            ipv6_gateway_system=$(ip -6 r s | awk '(/^default/) { print $3 }')
            log_and_halt_installation_on_error "${?}" "Unable to get system's IPv6 gateway."
        fi
    done

    # IPv6 address
    retry=0

    ipv6_address_system=$(echo ${ipv6_address_system_full} | awk -F '/' '{ print $1 }')
    log_and_halt_installation_on_error "${?}" "Unable to get system's IPv6 subnet."

    while [ -z "${ipv6_address_system}" ]; do
        let retry=retry+1
        if [ ${retry} -ge 3 ]; then
            log_and_halt_installation_on_error "1" "Unable to get system's IPv6 subnet."
            break
        else
            sleep 1
            ipv6_address_system=$(echo ${ipv6_address_system_full} | awk -F '/' '{ print $1 }')
            log_and_halt_installation_on_error "${?}" "Unable to get system's IPv6 subnet."
        fi
    done

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
    NNS_URL_STRING=$(/opt/ic/bin/fetch-property.sh --key=.nns.url --config=${DEPLOYMENT})
    NNS_URL_LIST=$(echo $NNS_URL_STRING | sed 's@,@ @g')
}

function query_nns_nodes() {
    echo "* Querying NNS nodes..."

    i=0
    success=0
    nodes=$(echo ${NNS_URL_LIST} | wc -w)
    # At least one of the provided URLs needs to work.
    verify=1
    for url in $(echo $NNS_URL_LIST); do
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
    read_variables
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
