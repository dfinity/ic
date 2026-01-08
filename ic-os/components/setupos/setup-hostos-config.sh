#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"
CONFIG_DIR="/config"

# Target mount point for the config partition
# Can be overridden by setting CONFIG_PARTITION_PATH before sourcing this script
CONFIG_PARTITION_PATH="${CONFIG_PARTITION_PATH:-/media}"

source /opt/ic/bin/config.sh
source /opt/ic/bin/functions.sh

function mount_config_partition() {
    echo "* Mounting hostOS config partition..."

    vgchange -ay hostlvm
    log_and_halt_installation_on_error "${?}" "Unable to activate hostOS config partition."

    mount /dev/mapper/hostlvm-config "${CONFIG_PARTITION_PATH}"
    log_and_halt_installation_on_error "${?}" "Unable to mount hostOS config partition."
}

function copy_config_files() {
    echo "* Copying SSH authorized keys..."
    use_ssh_authorized_keys=$(get_config_value '.icos_settings.use_ssh_authorized_keys')
    if [[ "${use_ssh_authorized_keys,,}" == "true" ]]; then
        if [ -d "${CONFIG_DIR}/ssh_authorized_keys" ]; then
            cp -a "${CONFIG_DIR}/ssh_authorized_keys" "${CONFIG_PARTITION_PATH}/"
            log_and_halt_installation_on_error "${?}" "Unable to copy SSH authorized keys to hostOS config partition."
        else
            log_and_halt_installation_on_error "1" "use_ssh_authorized_keys set to true but not found"
        fi
    else
        echo >&2 "SSH keys not in use."
    fi

    echo "* Copying node operator private key..."
    use_node_operator_private_key=$(get_config_value '.icos_settings.use_node_operator_private_key')
    if [[ "${use_node_operator_private_key,,}" == "true" ]]; then
        if [ -f "${CONFIG_DIR}/node_operator_private_key.pem" ]; then
            cp "${CONFIG_DIR}/node_operator_private_key.pem" "${CONFIG_PARTITION_PATH}/"
            log_and_halt_installation_on_error "${?}" "Unable to copy node operator private key to hostOS config partition."
            # Set restrictive permissions: owner read/write only (600) to prevent limited-console user from reading
            chmod 600 "${CONFIG_PARTITION_PATH}/node_operator_private_key.pem"
            log_and_halt_installation_on_error "${?}" "Unable to set permissions on node operator private key."
        else
            log_and_halt_installation_on_error "1" "use_node_operator_private_key set to true but not found"
        fi
    else
        echo >&2 "Warning: node_operator_private_key.pem does not exist, requiring HSM."
    fi

    echo "* Copying NNS public key override to hostOS config partition..."
    if [ -f "/data/nns_public_key_override.pem" ]; then
        cp /data/nns_public_key_override.pem "${CONFIG_PARTITION_PATH}/"
        log_and_halt_installation_on_error "${?}" "Unable to copy NNS public key override to hostOS config partition."
    else
        echo >&2 "nns_public_key_override.pem does not exist, skipping."
    fi

    echo "* Converting 'config.json' to hostOS config file 'config-hostos.json'..."
    /opt/ic/bin/config_tool generate-hostos-config
    log_and_halt_installation_on_error "${?}" "Unable to generate hostos configuration."

    echo "* Copying 'config-hostos.json' to hostOS config partition..."
    if [ -f "/var/ic/config/config-hostos.json" ]; then
        cp /var/ic/config/config-hostos.json "${CONFIG_PARTITION_PATH}/config.json"
        log_and_halt_installation_on_error "${?}" "Unable to copy 'config-hostos.json' to hostOS config partition."
    else
        log_and_halt_installation_on_error "1" "Configuration file 'config-hostos.json' does not exist."
    fi
}

function insert_hsm_if_necessary() {
    if [ ! -f "${CONFIG_DIR}/node_operator_private_key.pem" ]; then
        retry=0
        while [ -z "$(lsusb | grep -E 'Nitro|Clay')" ]; do
            let retry=retry+1
            if [ ${retry} -ge 3600 ]; then
                log_and_halt_installation_on_error "1" "Nitrokey HSM USB device could not be detected, giving up."
            else
                echo "* Please insert Nitrokey HSM USB device..."
                sleep 3
            fi
        done
        echo "HSM successfully detected."
    else
        echo "node_operator_private_key.pem found."
    fi
}

function unmount_config_partition() {
    echo "* Unmounting hostOS config partition..."

    sync
    log_and_halt_installation_on_error "${?}" "Unable to synchronize cached writes to persistent storage."

    umount "${CONFIG_PARTITION_PATH}"
    log_and_halt_installation_on_error "${?}" "Unable to unmount hostOS config partition."

    vgchange -an hostlvm
    log_and_halt_installation_on_error "${?}" "Unable to deactivate hostOS config partition."
}

# Establish run order
main() {
    log_start "$(basename $0)"
    mount_config_partition
    copy_config_files
    insert_hsm_if_necessary
    unmount_config_partition
    log_end "$(basename $0)"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
