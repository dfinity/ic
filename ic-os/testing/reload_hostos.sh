#!/bin/bash

set -e

# Directory containing this script
SCRIPT_DIR="$(dirname -- "${BASH_SOURCE[0]}")"

# Mount points and paths
export SETUPOS_CONFIG_MOUNT=/tmp/setupos
TARGET_BOOT_PARTITION_MOUNT=/tmp/target_boot_partition
GUESTOS_EXTRACT_DIR=/tmp/guestos_img

# Temporary download paths
HOSTOS_UPGRADE_TAR=/tmp/hostos-upgrade-img.tar.zst
GUESTOS_TAR=/tmp/guestos.tar.zst

usage() {
    echo "Usage: $0 --setupos-config-img=<path-to-setupos-config-image> --hostos-upgrade-img=<path-to-hostos-upgrade-image> --guestos-img=<path-to-guestos-image>" >&2
}

cleanup() {
    echo "Cleaning up..."
    umount /opt/ic/bin 2>/dev/null || true
    umount /var/ic 2>/dev/null || true
    umount /config 2>/dev/null || true
    umount /data 2>/dev/null || true
    umount /media 2>/dev/null || true
    umount "$SETUPOS_CONFIG_MOUNT" 2>/dev/null || true
    umount "$TARGET_BOOT_PARTITION_MOUNT" 2>/dev/null || true
    rm -rf "$TARGET_BOOT_PARTITION_MOUNT" 2>/dev/null || true
    rm -rf "$GUESTOS_EXTRACT_DIR" 2>/dev/null || true
    rm -f "$HOSTOS_UPGRADE_TAR" "$GUESTOS_TAR" 2>/dev/null || true
}

download_images() {
    echo "Downloading HostOS upgrade image..."
    curl "$HOSTOS_UPGRADE_IMG" -o "$HOSTOS_UPGRADE_TAR" --fail --silent --show-error --clobber

    if [ -n "$GUESTOS_IMG" ]; then
        echo "Downloading GuestOS image..."
        curl "$GUESTOS_IMG" -o "$GUESTOS_TAR" --fail --silent --show-error --clobber
    fi
}

setup_temp_mounts() {
    echo "Setting up temporary mounts..."
    mkdir -p /config /data
    mount -t tmpfs tmpfs /config
    mount -t tmpfs tmpfs /data
}

install_new_hostos() {
    echo "Invoking HostOS upgrade..."
    /opt/ic/bin/manageboot.sh hostos upgrade-install "$HOSTOS_UPGRADE_TAR"
}

install_new_guestos() {
    if [ -z "$GUESTOS_IMG" ]; then
        echo "No GuestOS image specified, skipping GuestOS upgrade."
        return
    fi

    echo "Installing GuestOS image..."
    mkdir -p "$GUESTOS_EXTRACT_DIR"
    tar -xavf "$GUESTOS_TAR" -C "$GUESTOS_EXTRACT_DIR"

    echo "Stopping GuestOS service..."
    systemctl stop guestos.service || true
    systemctl stop upgrade-guestos.service || true

    echo "Writing GuestOS disk image..."
    dd if="$GUESTOS_EXTRACT_DIR/disk.img" of=/dev/mapper/hostlvm-guestos bs=4M
    echo "Successfully installed GuestOS image."
}

mount_target_boot_partition() {
    local target_alternative="$1"

    echo "Mounting target boot partition..."
    mkdir -p "$TARGET_BOOT_PARTITION_MOUNT"
    mount "/dev/mapper/hostlvm-${target_alternative}_boot" "$TARGET_BOOT_PARTITION_MOUNT"
    echo "Mounted target boot partition: /dev/mapper/hostlvm-${target_alternative}_boot"
}

setup_config() {
    echo "Setting up configuration environment..."

    # Mount over existing script dir and use the shipped scripts instead of the ones already deployed on the node
    mount --bind "$SCRIPT_DIR" /opt/ic/bin

    # Create directories/mounts expected by the SetupOS tools
    mkdir -p /var/ic
    mount -t tmpfs tmpfs /var/ic

    # Mount SetupOS config image
    mkdir -p "$SETUPOS_CONFIG_MOUNT"
    mount "$SETUPOS_CONFIG_IMG" "$SETUPOS_CONFIG_MOUNT"

    # Preload and create config
    /opt/ic/bin/preload-config.sh
    /opt/ic/bin/config create-setupos-config

    echo "Copying configuration files to target partition..."

    export CONFIG_PARTITION_PATH=/boot/config
    source /opt/ic/bin/setup-hostos-config.sh
    copy_config_files
}

commit_and_reboot() {
    local boot_args="$1"

    echo "Committing HostOS upgrade..."
    /opt/ic/bin/manageboot.sh hostos upgrade-commit --no-reboot

    echo "Preparing kexec reboot..."
    kexec -l "$TARGET_BOOT_PARTITION_MOUNT/vmlinuz" \
        --initrd="$TARGET_BOOT_PARTITION_MOUNT/initrd.img" \
        --command-line="$boot_args"

    echo "Scheduling reboot via kexec..."
    nohup bash -c 'sleep 5; systemctl start kexec.target' >/dev/null 2>&1 &
}

SETUPOS_CONFIG_IMG=""
HOSTOS_UPGRADE_IMG=""
GUESTOS_IMG=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --setupos-config-img=*)
            SETUPOS_CONFIG_IMG="${1#*=}"
            shift
            ;;
        --hostos-upgrade-img=*)
            HOSTOS_UPGRADE_IMG="${1#*=}"
            shift
            ;;
        --guestos-img=*)
            GUESTOS_IMG="${1#*=}"
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 2
            ;;
    esac
done

if [ -z "$SETUPOS_CONFIG_IMG" ]; then
    echo "Missing required --setupos-config-img argument" >&2
    usage
    exit 2
fi
if [ -z "$HOSTOS_UPGRADE_IMG" ]; then
    echo "Missing required --hostos-upgrade-img argument" >&2
    usage
    exit 2
fi

trap cleanup EXIT

mount -o remount,rw /
cleanup

download_images
setup_temp_mounts
install_new_hostos
install_new_guestos

# Determine target alternative and mount its boot partition
target_alternative="$(/opt/ic/bin/manageboot.sh hostos target)"
echo "Will update HostOS into: $target_alternative"
mount_target_boot_partition "$target_alternative"

# Read boot arguments from new HostOS
eval "$(cat "$TARGET_BOOT_PARTITION_MOUNT/boot_args")"
boot_args_var=BOOT_ARGS_${target_alternative}

setup_config
commit_and_reboot "${!boot_args_var}"
