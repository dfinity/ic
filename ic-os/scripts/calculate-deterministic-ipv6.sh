#!/bin/bash

set -e

# Calculate a deterministic IPv6 address.

SCRIPT="$(basename $0)[$$]"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -d=* | --deployment=*)
            DEPLOYMENT="${argument#*=}"
            shift
            ;;
        -h | --help)
            echo 'Usage:
Calculate Deterministic IPv6 Address

Arguments:
  -d=, --deployment=    mandatory: specify the deployment name (Examples: mainnet, staging, testing)
  -h, --help            show this help message and exit
  -i=, --index=         required: specify the single digit node index (Examples: host: 0, guest: 1, boundary: 2)
  -m=, --mac=           required: specify the management MAC address (Examples: b0:7b:25:c8:f6:90)
       --prefix=        required: specify the IPv6 prefix (Examples: 2a02:41b:300e:0)
  -s=, --subnet=        required: specify the IPv6 subnet (Examples: /64)

Example:
  ./calculate-deterministic-ipv6.sh --deployment=mainnet --index=1 --mac=b0:7b:25:c8:f6:90 --prefix=2a02:41b:300e:0 --subnet=/64
'
            exit 1
            ;;
        -i=* | --index=*)
            INDEX="${argument#*=}"
            shift
            ;;
        -m=* | --mac=*)
            MAC="${argument#*=}"
            shift
            ;;
        --prefix=*)
            PREFIX="${argument#*=}"
            shift
            ;;
        -s=* | --subnet=*)
            SUBNET="${argument#*=}"
            shift
            ;;
        *)
            echo "Error: Argument is not supported."
            exit 1
            ;;
    esac
done

function validate_arguments() {
    if [ "${DEPLOYMENT}" == "" -o "${INDEX}" == "" -o "${MAC}" == "" -o "${PREFIX}" == "" -o "${SUBNET}" == "" ]; then
        $0 --help
    fi
}

function calculate_deterministic_mac() {
    local lower_mac=$(echo ${MAC} | tr '[:upper:]' '[:lower:]')
    if [ ! "$(echo ${lower_mac} | grep -o ':' | grep -c .)" -eq 5 ]; then
        echo "Management MAC address seems invalid. Please enter six octets separated by colons."
        exit 1
    fi
    SEED="${lower_mac}${DEPLOYMENT}"
    VENDOR_PART=$(echo ${SEED} | sha256sum | cut -c 1-8)

    VERSION_OCTET="6a"
    DETERMINISTIC_MAC=$(echo "${VERSION_OCTET}0${INDEX}${OUI_PART}${VENDOR_PART}" | sed 's/\(..\)/\1:/g;s/:$//')
}

function print_deterministic_mac() {
    echo "# Deterministic MAC Address"
    echo "${DETERMINISTIC_MAC}"
    echo
}

function calculate_deterministic_ipv6() {
    local ipv6_prefix=${PREFIX}
    local ipv6_subnet=${SUBNET}
    local output=$(echo "${DETERMINISTIC_MAC}" | sed 's/[.:-]//g' | tr '[:upper:]' '[:lower:]')
    local output="${output:0:6}fffe${output:6}"
    local output=$(printf "%02x%s" "$((0x${output:0:2} ^ 2))" "${output:2}")
    local output=$(echo "${output}" | sed 's/.\{4\}/&:/g;s/:$//')
    DETERMINISTIC_IPV6=$(echo "${ipv6_prefix}:${output}${ipv6_subnet}")
}

function print_deterministic_ipv6() {
    echo "# Deterministic IPv6 Address"
    echo "${DETERMINISTIC_IPV6}"
    echo
}

function main() {
    # Establish run order
    calculate_deterministic_mac
    calculate_deterministic_ipv6
    print_deterministic_mac
    print_deterministic_ipv6
}

main
