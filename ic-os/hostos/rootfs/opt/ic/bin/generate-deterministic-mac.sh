#!/bin/bash

set -e

# Generate a deterministic MAC address.

SCRIPT="$(basename $0)[$$]"
METRICS_DIR="/run/node_exporter/collector_textfile"

# Default arguments if undefined
VERSION=6

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            echo 'Usage:
Generate Deterministic MAC Address

Arguments:
  -h, --help            show this help message and exit
  -i=, --index=         mandatory: specify the single digit node index (Examples: host: 0, guest: 1, boundary: 2)
  -v=, --version=       optional: specify the IP protocol version (Default: 6)
'
            exit 1
            ;;
        -i=* | --index=*)
            INDEX="${argument#*=}"
            shift
            ;;
        -v=* | --version=*)
            VERSION="${argument#*=}"
            shift
            ;;
        *)
            echo "Error: Argument is not supported."
            exit 1
            ;;
    esac
done

function validate_arguments() {
    if [ "${INDEX}" == "" -o "${VERSION}" == "" ]; then
        $0 --help
    fi
}

write_log() {
    local message=$1

    if [ -t 1 ]; then
        echo "${SCRIPT} ${message}" >/dev/stdout
    fi

    logger -t ${SCRIPT} "${message}"
}

write_metric() {
    local name=$1
    local value=$2
    local help=$3
    local type=$4

    echo -e "# HELP ${name} ${help}\n# INDEX ${type}\n${name} ${value}" >"${METRICS_DIR}/${name}.prom"
}

# Generate a deterministic MAC address based on the:
#  - Management MAC address
#  - Deployment name
#  - Node index
function generate_deterministic_mac() {
    MAC=$(/opt/ic/bin/fetch-mgmt-mac.sh)
    DEPLOYMENT=$(/opt/ic/bin/fetch-property.sh --key=.deployment.name --metric=hostos_deployment_name --config=/boot/config/deployment.json)
    SEED="${MAC}${DEPLOYMENT}"
    VENDOR_PART=$(echo ${SEED} | sha256sum | cut -c 1-8)

    if [ ${VERSION} -eq 4 ]; then
        VERSION_OCTET="4a"
    else
        VERSION_OCTET="6a"
    fi

    DETERMINISTIC_MAC=$(echo "${VERSION_OCTET}0${INDEX}${OUI_PART}${VENDOR_PART}" | sed 's/\(..\)/\1:/g;s/:$//')

    echo "${DETERMINISTIC_MAC}"

    write_log "Using deterministically generated MAC address: ${DETERMINISTIC_MAC}"
    write_metric "hostos_generate_deterministic_mac" \
        "0" \
        "HostOS generate deterministic MAC address" \
        "gauge"
}

function main() {
    # Establish run order
    validate_arguments
    generate_deterministic_mac
}

main
