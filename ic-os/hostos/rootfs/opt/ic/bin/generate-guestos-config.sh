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
  -c=, --config=        specify the config.ini configuration file (Default: /boot/config/config.ini)
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
CONFIG="${CONFIG:=/boot/config/config.ini}"
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

function assemble_config_media() {
    cmd=(/opt/ic/bin/build-bootstrap-config-image.sh ${MEDIA})
    cmd+=(--nns_public_key "/boot/config/nns_public_key.pem")
    cmd+=(--elasticsearch_hosts "$(/opt/ic/bin/fetch-property.sh --key=.logging.hosts --metric=hostos_logging_hosts --config=${DEPLOYMENT})")
    cmd+=(--ipv6_address "$(/opt/ic/bin/generate-deterministic-ipv6.sh --index=1)")
    cmd+=(--ipv6_gateway "${ipv6_gateway}")
    cmd+=(--name_servers "$(/opt/ic/bin/fetch-property.sh --key=.dns.name_servers --metric=hostos_dns_name_servers --config=${DEPLOYMENT})")
    cmd+=(--hostname "guest-$(/opt/ic/bin/fetch-mgmt-mac.sh | sed 's/://g')")
    cmd+=(--nns_url "$(/opt/ic/bin/fetch-property.sh --key=.nns.url --metric=hostos_nns_url --config=${DEPLOYMENT})")
    # AMDs cert download links do not support IPv6; NODE-817
    # cmd+=(--get_sev_certs)
    if [ -f "/boot/config/node_operator_private_key.pem" ]; then
        cmd+=(--node_operator_private_key "/boot/config/node_operator_private_key.pem")
    fi

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

TMP_MOUNT_DIR="/tmp/sev-guest-mount"
BOOT_COMPONENTS_DIR="/tmp/sev-guest-boot-components"
LOOP_DEVICE="/dev/loop0"
GUESTOS_LOCATION="/dev/mapper/hostlvm-guestos"
SEV_SNP_FILE="/opt/ic/share/SEV"

# Set up loop device and mount. Get the boot components
mount_guestos_image_and_copy_files() {
    mkdir -p "$TMP_MOUNT_DIR"
    losetup -P "$LOOP_DEVICE" /dev/mapper/hostlvm-guestos
    mount "${LOOP_DEVICE}p4" "$TMP_MOUNT_DIR"
    mkdir -p "$BOOT_COMPONENTS_DIR"
    cp "$TMP_MOUNT_DIR"/vmlinuz "$BOOT_COMPONENTS_DIR"
    cp "$TMP_MOUNT_DIR"/initrd.img "$BOOT_COMPONENTS_DIR"
    cp "$TMP_MOUNT_DIR"/extra_boot_args "$BOOT_COMPONENTS_DIR"
}

# Clean up loop device and mount
unmount_guestos_image() {
    umount -q "$TMP_MOUNT_DIR"
    rmdir "$TMP_MOUNT_DIR"
    losetup -d "$LOOP_DEVICE"
}

# Generate config for SEV GuestOS
# Use the qemu script template and mount the guestos image.
# Derive kernel, initrd and the cmdline and populate the qemu script.
function generate_sev_guestos_config() {
    INPUT="/opt/ic/share/sev_guestos.sh.template"
    OUTPUT="/var/lib/sev_guestos.sh"
    RESOURCES_MEMORY=$(/opt/ic/bin/fetch-property.sh --key=.resources.memory --metric=hostos_resources_memory --config=${DEPLOYMENT})
    MAC_ADDRESS=$(/opt/ic/bin/generate-deterministic-mac.sh --index=1)
    mount_guestos_image_and_copy_files
    unmount_guestos_image

    KERNEL="$BOOT_COMPONENTS_DIR/vmlinuz"
    INITRD="$BOOT_COMPONENTS_DIR/initrd.img"
    source "$BOOT_COMPONENTS_DIR"/extra_boot_args
    if [ ! -f "${OUTPUT}" ]; then
        sed -e "s@{{ resources_memory }}@${RESOURCES_MEMORY}@" \
            -e "s@{{ mac_address }}@${MAC_ADDRESS}@" \
            -e "s@{{ kernel }}@${KERNEL}@" \
            -e "s@{{ initrd }}@${INITRD}@" \
            -e "s@{{ extra_boot_args }}@${EXTRA_BOOT_ARGS}@" \
            "${INPUT}" >"${OUTPUT}"
        chmod ug+x "${OUTPUT}"
        write_log "Generating SEV GuestOS configuration file: ${OUTPUT}"
        write_metric "hostos_generate_sev_guestos_config" \
            "1" \
            "HostOS generate SEV GuestOS config" \
            "gauge"
    else
        write_log "SEV GuestOS configuration file already exists: ${OUTPUT}"
        write_metric "hostos_generate_sev_guestos_config" \
            "0" \
            "HostOS generate SEV GuestOS config" \
            "gauge"
    fi
}

# Check if SEV-SNP if enabled on host
function is_sev_snp_enabled() {
    if [ -f "$SEV_SNP_FILE" ]; then
        return 0
    fi

    return 1
}

function main() {
    # Establish run order
    validate_arguments
    read_variables
    assemble_config_media
    if is_sev_snp_enabled; then
        generate_sev_guestos_config
    else
        generate_guestos_config
    fi
}

main
