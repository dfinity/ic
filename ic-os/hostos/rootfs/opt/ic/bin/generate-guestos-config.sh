#!/bin/bash

set -e

# Generate the GuestOS configuration.

SCRIPT="$(basename $0)[$$]"
METRICS_DIR="/run/node_exporter/collector_textfile"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -c=* | --config=*)
            CONFIG="${argument#*=}"
            shift
            ;;
        -d=* | --deployment=*)
            DEPLOYMENT="${argument#*=}"
            shift
            ;;
        -h | --help)
            echo 'Usage:
Generate GuestOS Configuration

Arguments:
  -c=, --config=        specify the config.json configuration file (Default: /boot/config/config.json)
  -d=, --deployment=    specify the deployment.json configuration file (Default: /boot/config/deployment.json)
  -h, --help            show this help message and exit
  -i=, --input=         specify the input template file (Default: /opt/ic/share/guestos.xml.template)
  -m=, --media=         specify the config media image file (Default: /run/ic-node/config.img)
  -o=, --output=        specify the output configuration file (Default: /var/lib/libvirt/guestos.xml)
'
            exit 1
            ;;
        -i=* | --input=*)
            INPUT="${argument#*=}"
            shift
            ;;
        -m=* | --media=*)
            MEDIA="${argument#*=}"
            shift
            ;;
        -o=* | --output=*)
            OUTPUT="${argument#*=}"
            shift
            ;;
        *)
            echo "Error: Argument is not supported."
            exit 1
            ;;
    esac
done

function validate_arguments() {
    if [ "${CONFIG}" == "" -o "${DEPLOYMENT}" == "" -o "${INPUT}" == "" -o "${OUTPUT}" == "" ]; then
        $0 --help
    fi
}

# Set arguments if undefined
CONFIG="${CONFIG:=/boot/config/config.json}"
DEPLOYMENT="${DEPLOYMENT:=/boot/config/deployment.json}"
INPUT="${INPUT:=/opt/ic/share/guestos.xml.template}"
MEDIA="${MEDIA:=/run/ic-node/config.img}"
OUTPUT="${OUTPUT:=/var/lib/libvirt/guestos.xml}"

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

function assemble_config_media() {
    cmd=(/opt/ic/bin/build-bootstrap-config-image.sh ${MEDIA})
    if [ -d "/boot/config/guestos_accounts_ssh_authorized_keys" ]; then
        cmd+=(--accounts_ssh_authorized_keys /boot/config/guestos_accounts_ssh_authorized_keys)
    fi
    cmd+=(--nns_public_key "/boot/config/nns_public_key.pem")
    cmd+=(--journalbeat_hosts "$(/opt/ic/bin/fetch-property.sh --key=.logging.hosts --metric=hostos_logging_hosts --config=${DEPLOYMENT})")
    cmd+=(--ipv6_address "$(/opt/ic/bin/generate-deterministic-ipv6.sh --index=1)")
    cmd+=(--ipv6_gateway "$(/opt/ic/bin/fetch-property.sh --key=.ipv6_gateway --metric=hostos_ipv6_gateway --config=${CONFIG} -u)")
    cmd+=(--name_servers "$(/opt/ic/bin/fetch-property.sh --key=.network.name_servers --metric=hostos_name_servers --config=${CONFIG})")
    cmd+=(--hostname "guest-$(/opt/ic/bin/fetch-mgmt-mac.sh | sed 's/://g')")
    cmd+=(--nns_url "$(/opt/ic/bin/fetch-property.sh --key=.nns.url --metric=hostos_nns_url --config=${DEPLOYMENT})")

    # Run the above command
    "${cmd[@]}"
    write_log "Assembling config media for GuestOS: ${MEDIA}"
}

function generate_guestos_config() {
    RESOURCES_MEMORY=$(/opt/ic/bin/fetch-property.sh --key=.resources.memory --metric=hostos_resources_memory --config=${DEPLOYMENT})
    MAC_ADDRESS=$(/opt/ic/bin/generate-deterministic-mac.sh --index=1)

    if [ ! -f "${OUTPUT}" ]; then
        sed -e "s@{{ resources_memory }}@${RESOURCES_MEMORY}@" \
            -e "s@{{ mac_address }}@${MAC_ADDRESS}@" \
            "${INPUT}" >"${OUTPUT}"
        write_log "Generating GuestOS configuration file: ${OUTPUT}"
        write_metric "hostos_generate_guestos_config" \
            "1" \
            "HostOS generate GuestOS config" \
            "gauge"
    else
        write_log "GuestOS configuration file already exists: ${OUTPUT}"
        write_metric "hostos_generate_guestos_config" \
            "0" \
            "HostOS generate GuestOS config" \
            "gauge"
    fi
}

function main() {
    # Establish run order
    validate_arguments
    assemble_config_media
    generate_guestos_config
}

main
