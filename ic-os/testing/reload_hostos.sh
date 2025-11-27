#!/bin/bash

set -e

# Directory containing this script
SCRIPT_DIR="$(dirname -- "${BASH_SOURCE[0]}")"

# Mount points and paths
export SETUPOS_CONFIG_MOUNT=/tmp/setupos
TARGET_BOOT_PARTITION_MOUNT=/tmp/target_boot_partition
GUESTOS_EXTRACT_DIR=/tmp/guestos_img

# Temporary download paths
SETUPOS_CONFIG_IMG_PATH=/tmp/setupos-config.img
HOSTOS_UPGRADE_IMG_TAR_PATH=/tmp/hostos-upgrade-img.tar.zst
GUESTOS_IMG_TAR_PATH=/tmp/guestos.tar.zst

usage() {
    echo "Usage: $0 [--setupos-config-img=<path-to-setupos-config-image>] [--hostos-upgrade-img=<path-to-hostos-upgrade-image>] [--guestos-img=<path-to-guestos-image>]" >&2
    echo "At least one of --hostos-upgrade-img or --guestos-img must be provided." >&2
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
    rm -rf "$TARGET_BOOT_PARTITION_MOUNT" "$GUESTOS_EXTRACT_DIR" 2>/dev/null || true
    rm -f "$SETUPOS_CONFIG_IMG_PATH" "$HOSTOS_UPGRADE_IMG_TAR_PATH" "$GUESTOS_IMG_TAR_PATH" 2>/dev/null || true
}

fetch_file() {
    # Fetch a file from a URL or local filesystem and store it at the specified path.
    local source="$1"
    local dest="$2"
    local name="$3"

    if echo "$source" | grep -q "://"; then
        echo "Downloading $name from $source..."
        curl "$source" -o "$dest" --fail --silent --show-error --clobber
    else
        if [ ! -f "$source" ]; then
            echo "Local file $source does not exist!" >&2
            exit 1
        fi
        echo "Using local $name from $source..."
        if [[ "$source" != "$dest" ]]; then
            mv "$source" "$dest"
        fi
    fi
}

fetch_images() {
    if [ -n "$SETUPOS_CONFIG_IMG_SRC" ]; then
        fetch_file "$SETUPOS_CONFIG_IMG_SRC" "$SETUPOS_CONFIG_IMG_PATH" "SetupOS config image"
    fi

    if [ -n "$HOSTOS_UPGRADE_IMG_TAR_SRC" ]; then
        fetch_file "$HOSTOS_UPGRADE_IMG_TAR_SRC" "$HOSTOS_UPGRADE_IMG_TAR_PATH" "HostOS upgrade image"
    fi

    if [ -n "$GUESTOS_IMG_TAR_SRC" ]; then
        fetch_file "$GUESTOS_IMG_TAR_SRC" "$GUESTOS_IMG_TAR_PATH" "GuestOS image"
    fi
}

setup_temp_mounts() {
    echo "Setting up temporary mounts..."
    mkdir -p /config /data
    mount -t tmpfs tmpfs /config
    mount -t tmpfs tmpfs /data
}

install_new_hostos() {
    if [ -z "$HOSTOS_UPGRADE_IMG_TAR_SRC" ]; then
        echo "No HostOS upgrade image specified, skipping HostOS upgrade."
        return
    fi

    echo "Invoking HostOS upgrade..."
    /opt/ic/bin/manageboot.sh hostos upgrade-install "$HOSTOS_UPGRADE_IMG_TAR_PATH"
}

install_new_guestos() {
    if [ -z "$GUESTOS_IMG_TAR_SRC" ]; then
        echo "No GuestOS image specified, skipping GuestOS upgrade."
        return
    fi

    echo "Installing GuestOS image..."
    mkdir -p "$GUESTOS_EXTRACT_DIR"
    tar -xavf "$GUESTOS_IMG_TAR_PATH" -C "$GUESTOS_EXTRACT_DIR"

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
    if [ -z "$SETUPOS_CONFIG_IMG_SRC" ]; then
        echo "No SetupOS config image provided, skipping configuration setup..."
        return
    fi

    echo "Setting up configuration environment..."

    # Mount over existing script dir and use the shipped scripts instead of the ones already deployed on the node
    mount --bind "$SCRIPT_DIR" /opt/ic/bin

    # Create directories/mounts expected by the SetupOS tools
    mkdir -p /var/ic
    mount -t tmpfs tmpfs /var/ic

    # Mount SetupOS config image
    mkdir -p "$SETUPOS_CONFIG_MOUNT"
    mount "$SETUPOS_CONFIG_IMG_PATH" "$SETUPOS_CONFIG_MOUNT"

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
    nohup bash -c 'sleep 2; systemctl start kexec.target' >/dev/null 2>&1 &
}

SETUPOS_CONFIG_IMG_SRC=""
HOSTOS_UPGRADE_IMG_TAR_SRC=""
GUESTOS_IMG_TAR_SRC=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --setupos-config-img=*)
            SETUPOS_CONFIG_IMG_SRC="${1#*=}"
            shift
            ;;
        --hostos-upgrade-img=*)
            HOSTOS_UPGRADE_IMG_TAR_SRC="${1#*=}"
            shift
            ;;
        --guestos-img=*)
            GUESTOS_IMG_TAR_SRC="${1#*=}"
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [ -z "$HOSTOS_UPGRADE_IMG_TAR_SRC" ] && [ -z "$GUESTOS_IMG_TAR_SRC" ] && [ -z "$SETUPOS_CONFIG_IMG_SRC" ]; then
    echo "At least one of --hostos-upgrade-img or --guestos-img or --setupos-config-img must be provided" >&2
    usage
    exit 1
fi

trap cleanup EXIT

mount -o remount,rw /
cleanup

fetch_images
setup_temp_mounts
install_new_hostos
install_new_guestos
setup_config

if [ -n "$HOSTOS_UPGRADE_IMG_TAR_SRC" ]; then
    # Determine target alternative and mount its boot partition
    target_alternative="$(/opt/ic/bin/manageboot.sh hostos target)"
    echo "Will update HostOS into: $target_alternative"
    mount_target_boot_partition "$target_alternative"

    # Read boot arguments from new HostOS
    eval "$(cat "$TARGET_BOOT_PARTITION_MOUNT/boot_args")"
    boot_args_var=BOOT_ARGS_${target_alternative}

    commit_and_reboot "${!boot_args_var}"
elif [ -n "$SETUPOS_CONFIG_IMG_SRC" ]; then
    # Config-only update: reboot with current kernel
    echo "Preparing kexec reboot with current kernel..."
    kexec -l /boot/vmlinuz --initrd=/boot/initrd.img --reuse-cmdline
    nohup bash -c 'sleep 2; systemctl start kexec.target' >/dev/null 2>&1 &
elif [ -n "$GUESTOS_IMG_TAR_SRC" ]; then
    echo "Only GuestOS was updated."
    echo "Starting GuestOS..."
    systemctl start guestos.service
fi
