#!/bin/bash

set -e

# Generate the GuestOS configuration.

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

function usage() {
    echo 'Usage:
    Generate GuestOS Configuration

    Arguments:
      -c=, --config=        specify the config.ini configuration file (Default: /boot/config/config.ini)
      -d=, --deployment=    specify the deployment.json configuration file (Default: /boot/config/deployment.json)
      -h, --help            show this help message and exit
      -i=, --input=         specify the input template file (Default: /opt/ic/share/guestos.xml.template)
      -m=, --media=         specify the config media image file (Default: /run/ic-node/config.img)
      -g=, --guestos_type=  guestos type to start, either "default" or "upgrade" (Default: default)
      -o=, --output=        specify the output configuration file (Default: /var/lib/libvirt/guestos.xml or /var/lib/libvirt/guestos-upgrader.xml)
    '
    exit 1
}

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
            usage
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
        -g=* | --guestos_type=*)
            GUESTOS_TYPE="${argument#*=}"
            shift
            ;;
        *)
            echo "Error: Argument is not supported."
            exit 1
            ;;
    esac
done

function validate_arguments() {
    if [ "${CONFIG}" == "" ]; then
        echo "Error: Config path not specified"
        usage
    fi
    if [ "${DEPLOYMENT}" == "" ]; then
        echo "Error: Deployment path not specified"
        usage
    fi
    if [ "${INPUT}" == "" ]; then
        echo "Error: Input template path not specified"
        usage
    fi
    if [ "${OUTPUT}" == "" ]; then
        echo "Error: Output path not specified"
        usage
    fi
    if [ "${GUESTOS_TYPE}" != "upgrade" -a "${GUESTOS_TYPE}" != "default" ]; then
        echo "Error: Invalid guestos_type: ${GUESTOS_TYPE}, supported values are: default, upgrade"
        usage
    fi
}

function vm_name() {
    if [ "$GUESTOS_TYPE" == upgrade ]; then
        echo "guestos-upgrader"
    else
        echo "guestos"
    fi
}

function vm_uuid() {
    if [ "$GUESTOS_TYPE" == upgrade ]; then
        echo "60adee78-89b8-41bd-b2f2-852cafaed53e"
    else
        echo "fd897da5-8017-41c8-8575-a706dba30766"
    fi
}

# Set arguments if undefined
CONFIG="${CONFIG:=/boot/config/config.ini}"
DEPLOYMENT="${DEPLOYMENT:=/boot/config/deployment.json}"
INPUT="${INPUT:=/opt/ic/share/guestos.xml.template}"
MEDIA="${MEDIA:=/run/ic-node/config-$(vm_name).img}"
OUTPUT="${OUTPUT:=/var/lib/libvirt/$(vm_name).xml}"

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
            "node_reward_type") node_reward_type="${value}" ;;
        esac
    done <"${CONFIG}"
}

function assemble_config_media() {
    cmd=(/opt/ic/bin/build-bootstrap-config-image.sh ${MEDIA})
    cmd+=(--nns_public_key "/boot/config/nns_public_key.pem")
    cmd+=(--ipv6_gateway "${ipv6_gateway}")
    if [[ -n "$ipv4_address" && -n "$ipv4_prefix_length" && -n "$ipv4_gateway" && -n "$domain" ]]; then
        cmd+=(--ipv4_address "${ipv4_address}/${ipv4_prefix_length}")
        cmd+=(--ipv4_gateway "${ipv4_gateway}")
        cmd+=(--domain "${domain}")
    fi
    if [[ -n "$node_reward_type" ]]; then
        cmd+=(--node_reward_type "${node_reward_type}")
    fi
    if [ "$GUESTOS_TYPE" == upgrade ]; then
        cmd+=(--guestos_type upgrade)
        cmd+=(--ipv6_address "$(/opt/ic/bin/hostos_tool generate-ipv6-address --node-type UpgradeGuestOS)")
        cmd+=(--alternative_vm_ipv6_address "$(/opt/ic/bin/hostos_tool generate-ipv6-address --node-type GuestOS)")
    else
      cmd+=(--guestos_type default)
      cmd+=(--ipv6_address "$(/opt/ic/bin/hostos_tool generate-ipv6-address --node-type GuestOS)")
      cmd+=(--alternative_vm_ipv6_address "$(/opt/ic/bin/hostos_tool generate-ipv6-address --node-type UpgradeGuestOS)")
    fi
    cmd+=(--hostname "guest-$(/opt/ic/bin/hostos_tool fetch-mac-address | sed 's/://g')")
    cmd+=(--nns_urls "$(/opt/ic/bin/fetch-property.sh --key=.nns.url --metric=hostos_nns_url --config=${DEPLOYMENT})")
    if [ -f "/boot/config/node_operator_private_key.pem" ]; then
        cmd+=(--node_operator_private_key "/boot/config/node_operator_private_key.pem")
    fi

    # Run the above command
    "${cmd[@]}"
    write_log "Assembling config media for GuestOS: ${MEDIA}"
}

function prepare_guestos_boot() {
    lodev="$(losetup -Pfr --show /dev/hostlvm/guestos)"
    workdir="$(mktemp -d)"
    grubdir="${workdir}/grub"
    bootdir="${workdir}/boot"
    mkdir "${grubdir}" "${bootdir}"
    mount -o ro,sync "${lodev}p2" "${grubdir}"
    boot_alternative="$(grep -oP '^boot_alternative=\K[a-zA-Z]+' "${grubdir}/grubenv")"
    if [ "$boot_alternative" = "A" ]; then
        boot="${lodev}p4"
    elif [ "$boot_alternative" = "B" ]; then
        boot="${lodev}p7"
    else
        echo "Error: Unknown boot alternative: ${boot_alternative}"
        exit 1
    fi
    umount "${grubdir}"

    if [ "$GUESTOS_TYPE" == upgrade ]; then
        if [ "$boot_alternative" = "A" ]; then
            boot_alternative="B"
        else
            boot_alternative="A"
        fi
    fi

    mount -o ro,sync "${boot}" "${bootdir}"
    mkdir -p "/run/ic-node/guestos_vm/$(vm_name)"
    KERNEL="/run/ic-node/guestos_vm/$(vm_name)/vmlinuz"
    INITRD="/run/ic-node/guestos_vm/$(vm_name)/initrd.img"
    cp "${bootdir}/vmlinuz" "$KERNEL"
    cp "${bootdir}/initrd.img" "$INITRD"
    CMDLINE="$(cat "${bootdir}/cmdline_${boot_alternative}")"
    umount "${bootdir}"
    rm -rf "${workdir}"
}

function generate_guestos_config() {
    # TODO: configure memory for UpgradeVM
    RESOURCES_MEMORY=$(/opt/ic/bin/fetch-property.sh --key=.resources.memory --metric=hostos_resources_memory --config=${DEPLOYMENT})
    MAC_ADDRESS=$(/opt/ic/bin/hostos_tool generate-mac-address --node-type GuestOS)
    # NOTE: `fetch-property` will error if the target is not found. Here we
    # only want to act when the field is set.
    CPU_MODE=$(jq -r ".resources.cpu" ${DEPLOYMENT})

    CPU_DOMAIN="kvm"
    CPU_SPEC="/opt/ic/share/kvm-cpu.xml"
    if [ "${CPU_MODE}" == "qemu" ]; then
        CPU_DOMAIN="qemu"
        CPU_SPEC="/opt/ic/share/qemu-cpu.xml"
    fi

    # `yes` or `no`
    SEV_SUPPORTED="$(virsh domcapabilities --xpath /domainCapabilities/features/sev | grep -oP 'supported="\K[^"]+')"

    mkdir -p "$(dirname "$OUTPUT")"
    sed -e "s@{{ resources_memory }}@${RESOURCES_MEMORY}@" \
        -e "s@{{ vm_name }}@$(vm_name)@" \
        -e "s@{{ vm_uuid }}@$(vm_uuid)@" \
        -e "s@{{ config_image_path }}@${MEDIA}@" \
        -e "s@{{ mac_address }}@${MAC_ADDRESS}@" \
        -e "s@{{ cpu_domain }}@${CPU_DOMAIN}@" \
        -e "/{{ cpu_spec }}/{r ${CPU_SPEC}" -e "d" -e "}" \
        -e "s@{{ kernel }}@${KERNEL}@" \
        -e "s@{{ initrd }}@${INITRD}@" \
        -e "s@{{ cmdline }}@${CMDLINE}@" \
        "${INPUT}" >"${OUTPUT}"
    restorecon -R "$(dirname "$OUTPUT")"
    write_log "Generating GuestOS configuration file: ${OUTPUT}"
    write_metric "hostos_generate_guestos_config" \
        "1" \
        "HostOS generate GuestOS config" \
        "gauge"
}

function write_tty1_log() {
    local message=$1

    echo "${SCRIPT} ${message}" >/dev/tty1

    logger -t "${SCRIPT}" "${message}"
}

function define_guestos() {
    write_log "Defining GuestOS virtual machine."
    virsh undefine "$(vm_name)" || true
    virsh define ${OUTPUT}
    write_metric "hostos_guestos_service_define" \
        "1" \
        "GuestOS virtual machine define state" \
        "gauge"
}

function is_vm_running() {
  if [ "$(virsh list --state-running | grep " $(vm_name) ")" ]; then
    echo true
  else
    echo false
  fi
}

function assert_vm_not_running() {
    if [ $(is_vm_running) == true ]; then
        write_log "GuestOS virtual machine is already running."
        # TODO: review metrics
        write_metric "hostos_guestos_service_start" \
            "0" \
            "GuestOS virtual machine start state" \
            "gauge"
        exit 1
    fi
}

function start_guestos() {
    write_log "Starting GuestOS virtual machine."
    # Attempt to start; if it fails, dump logs.
    if ! virsh start "$(vm_name)"; then
        # The sleep below gives QEMU time to clear the console so that
        # error messages won't be immediately overwritten.
        sleep 20

        write_tty1_log "ERROR: Failed to start GuestOS virtual machine."

        write_tty1_log "#################################################"
        write_tty1_log "###      LOGGING GUESTOS.SERVICE LOGS...      ###"
        write_tty1_log "#################################################"
        # TODO: review this line
        journalctl -u guestos.service >/dev/tty1

        write_tty1_log "#################################################"
        write_tty1_log "###          TROUBLESHOOTING INFO...          ###"
        write_tty1_log "#################################################"
        host_ipv6_address="$(/opt/ic/bin/hostos_tool generate-ipv6-address --node-type HostOS 2>/dev/null)"
        write_tty1_log "Host IPv6 address: $host_ipv6_address"

        if [ -f /var/log/libvirt/qemu/$(vm_name)-serial.log ]; then
            write_tty1_log "#################################################"
            write_tty1_log "###  LOGGING GUESTOS CONSOLE LOGS, IF ANY...  ###"
            write_tty1_log "#################################################"
            tail -n 30 /var/log/libvirt/qemu/$(vm_name)-serial.log | while IFS= read -r line; do
                write_tty1_log "$line"
            done
        else
            write_tty1_log "No /var/log/libvirt/qemu/$(vm_name)-serial.log file found."
        fi

        write_tty1_log "Exiting start-guestos.sh so that systemd can restart guestos.service in 5 minutes."
        exit 1
    fi

    systemd-notify --ready --status="$(vm_name) virtual machine launched"
    sleep 20
    write_tty1_log ""
    write_tty1_log "#################################################"
    write_tty1_log "GuestOS virtual machine launched"
    write_tty1_log "IF ONBOARDING, please wait for up to 10 MINUTES for a 'Join request successful!' message"
    host_ipv6_address="$(/opt/ic/bin/hostos_tool generate-ipv6-address --node-type HostOS 2>/dev/null)"
    write_tty1_log "Host IPv6 address: $host_ipv6_address"
    write_tty1_log "#################################################"

    write_log "Starting GuestOS virtual machine."
    write_metric "hostos_guestos_service_start" \
        "1" \
        "GuestOS virtual machine start state" \
        "gauge"

    trap "virsh destroy $(vm_name)" SIGTERM
}

function wait_for_vm_shutdown() {
  while true; do
    virsh event "$(vm_name)" lifecycle
    if [[ $(is_vm_running) != true ]]; then
      echo "VM no longer running, exiting"
      systemd-notify --stopping
      exit
    fi
  done
}

function main() {
    # Establish run order
    validate_arguments
    read_variables
    assert_vm_not_running
    assemble_config_media
    prepare_guestos_boot
    generate_guestos_config
    define_guestos
    start_guestos
    wait_for_vm_shutdown
}

main
