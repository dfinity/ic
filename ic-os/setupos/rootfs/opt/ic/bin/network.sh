#!/usr/bin/env bash

set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

CONFIG="${CONFIG:=/config/tmp/config.ini}"
DEPLOYMENT="${DEPLOYMENT:=/data/deployment.json}"

function read_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "ipv6_prefix") ipv6_prefix="${value}" ;;
            "ipv6_subnet") ipv6_subnet="${value}" ;;
            "ipv6_gateway") ipv6_gateway="${value}" ;;
        esac
    done <"${CONFIG}"
}

function get_network_settings() {
    # Full IPv6 address
    retry=0

    ipv6_address_system_full=$(ip -6 a s | awk '(/inet6/) && (! /fe80|::1/) { print $2 }')
    log_and_reboot_on_error "${?}" "Unable to get full system's IPv6 address."

    while [ -z "${ipv6_address_system_full}" ]; do
        let retry=retry+1
        if [ ${retry} -ge 3 ]; then
            log_and_reboot_on_error "1" "Unable to get full system's IPv6 address."
            break
        else
            sleep 1
            ipv6_address_system_full=$(ip -6 a s | awk '(/inet6/) && (! /fe80|::1/) { print $2 }')
            log_and_reboot_on_error "${?}" "Unable to get full system's IPv6 address."
        fi
    done

    # IPv6 prefix
    retry=0

    ipv6_prefix_system=$(echo ${ipv6_address_system_full} | cut -d: -f1-4)
    log_and_reboot_on_error "${?}" "Unable to get system's IPv6 prefix."

    while [ -z "${ipv6_prefix_system}" ]; do
        let retry=retry+1
        if [ ${retry} -ge 3 ]; then
            log_and_reboot_on_error "1" "Unable to get system's IPv6 prefix."
            break
        else
            sleep 1
            ipv6_prefix_system=$(echo ${ipv6_address_system_full} | cut -d: -f1-4)
            log_and_reboot_on_error "${?}" "Unable to get system's IPv6 prefix."
        fi
    done

    # IPv6 subnet
    retry=0

    ipv6_subnet_system=$(echo ${ipv6_address_system_full} | awk -F '/' '{ print "/" $2 }')
    log_and_reboot_on_error "${?}" "Unable to get system's IPv6 subnet."

    while [ -z "${ipv6_subnet_system}" ]; do
        let retry=retry+1
        if [ ${retry} -ge 3 ]; then
            log_and_reboot_on_error "1" "Unable to get system's IPv6 subnet."
            break
        else
            sleep 1
            ipv6_subnet_system=$(echo ${ipv6_address_system_full} | awk -F '/' '{ print "/" $2 }')
            log_and_reboot_on_error "${?}" "Unable to get system's IPv6 subnet."
        fi
    done

    # IPv6 gateway
    retry=0

    ipv6_gateway_system=$(ip -6 r s | awk '(/^default/) { print $3 }')
    log_and_reboot_on_error "${?}" "Unable to get system's IPv6 gateway."

    while [ -z "${ipv6_gateway_system}" ]; do
        let retry=retry+1
        if [ ${retry} -ge 3 ]; then
            log_and_reboot_on_error "1" "Unable to get system's IPv6 gateway."
            break
        else
            sleep 1
            ipv6_gateway_system=$(ip -6 r s | awk '(/^default/) { print $3 }')
            log_and_reboot_on_error "${?}" "Unable to get system's IPv6 gateway."
        fi
    done

    # IPv6 address
    retry=0

    ipv6_address_system=$(echo ${ipv6_address_system_full} | awk -F '/' '{ print $1 }')
    log_and_reboot_on_error "${?}" "Unable to get system's IPv6 subnet."

    while [ -z "${ipv6_address_system}" ]; do
        let retry=retry+1
        if [ ${retry} -ge 3 ]; then
            log_and_reboot_on_error "1" "Unable to get system's IPv6 subnet."
            break
        else
            sleep 1
            ipv6_address_system=$(echo ${ipv6_address_system_full} | awk -F '/' '{ print $1 }')
            log_and_reboot_on_error "${?}" "Unable to get system's IPv6 subnet."
        fi
    done

    HOSTOS_IPV6_ADDRESS=$(/opt/ic/bin/generate-deterministic-ipv6.sh --index=0)
    GUESTOS_IPV6_ADDRESS=$(/opt/ic/bin/generate-deterministic-ipv6.sh --index=1)
}

function print_network_settings() {
    echo "* Printing user defined network settings..."
    echo "  IPv6 Prefix : ${ipv6_prefix}"
    echo "  IPv6 Subnet : ${ipv6_subnet}"
    echo "  IPv6 Gateway: ${ipv6_gateway}"
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

function ping_ipv6_gateway() {
    echo "* Pinging IPv6 gateway..."

    ping6 -c 4 ${ipv6_gateway_system} >/dev/null 2>&1
    log_and_reboot_on_error "${?}" "Unable to ping IPv6 gateway."

    echo "  success"
    echo " "
}

function assemble_nns_nodes_list() {
    NNS_URL=$(/opt/ic/bin/fetch-property.sh --key=.nns.url --config=${DEPLOYMENT})
    NNS_URL_LIST=$(echo $NNS_URL | sed 's@,@ @g')
}

function query_nns_nodes() {
    echo "* Querying NNS nodes..."

    i=0
    success=0
    nodes=$(echo ${NNS_URL_LIST} | wc -w)
    verify=1
    if [ ${nodes} -gt 1 ]; then
        verify=$(awk "BEGIN {printf \"%.0f\n\", ${nodes}*0.20}")
    fi
    for url in $(echo $NNS_URL_LIST); do
        curl --head --connect-timeout 3 --silent ${url} >/dev/null 2>&1
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
            log_and_reboot_on_error "1" "Unable to query enough healthy NNS nodes."
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
    ping_ipv6_gateway
    assemble_nns_nodes_list
    query_nns_nodes
    log_end "$(basename $0)"
}

main
