#!/bin/bash

set -euo pipefail

# Directory containing this script
SCRIPT_DIR="$(dirname -- "${BASH_SOURCE[0]}")"

# These are files that are already on the HostOS but we ship our own version during reload_icos, so
# the workspace version is used instead of the one already on the HostOS.
STAGED_OPT_IC_BIN_FILES=(
    boot-state.sh
    config_tool
    functions.sh
    guestos-recovery-launcher.sh
    guestos-recovery-upgrader.sh
    preload-config.sh
    manageboot.sh
    metrics.sh
    setup-hostos-config.sh
)

# Mount points and paths
export SETUPOS_CONFIG_MOUNT=/tmp/setupos
TARGET_BOOT_PARTITION_MOUNT=/tmp/target_boot_partition
GUESTOS_EXTRACT_DIR=/tmp/guestos_img

# Temporary download paths
SETUPOS_CONFIG_IMG_PATH=/tmp/setupos-config.img
HOSTOS_UPGRADE_IMG_TAR_PATH=/tmp/hostos-upgrade-img.tar.zst
GUESTOS_FULL_IMG_TAR_PATH=/tmp/guestos.tar.zst
GUESTOS_UPGRADE_IMG_TAR_PATH=/tmp/guestos-upgrade.tar.zst
GUESTOS_RECOVERY_STAGE_DIR=/run/guestos-recovery/stage

SETUPOS_CONFIG_IMG_SRC=""
HOSTOS_UPGRADE_IMG_TAR_SRC=""
GUESTOS_FULL_IMG_TAR_SRC=""
GUESTOS_UPGRADE_IMG_TAR_SRC=""
GUESTOS_DEPLOYMENT_MODE="none"
GUESTOS_TARGET_BOOT_ALTERNATIVE=""
GUESTOS_WIPE_VAR_PARTITION=false

usage() {
    echo "Usage: $0 [--setupos-config-img=<path-to-setupos-config-image>] [--hostos-upgrade-img=<path-to-hostos-upgrade-image>] [--guestos-img=<path-to-guestos-image>] [--guestos-upgrade-img=<path-to-guestos-upgrade-image> --guestos-target-boot-alternative=<A|B> [--guestos-wipe-var-partition]]" >&2
    echo "At least one image or config input must be provided." >&2
}

cleanup() {
    echo "Cleaning up..."
    for staged_file in "${STAGED_OPT_IC_BIN_FILES[@]}"; do
        umount "/opt/ic/bin/${staged_file}" 2>/dev/null || true
    done
    umount /var/ic 2>/dev/null || true
    umount /config 2>/dev/null || true
    umount /data 2>/dev/null || true
    umount /media 2>/dev/null || true
    umount "$SETUPOS_CONFIG_MOUNT" 2>/dev/null || true
    umount "$TARGET_BOOT_PARTITION_MOUNT" 2>/dev/null || true
    rm -rf "$TARGET_BOOT_PARTITION_MOUNT" "$GUESTOS_EXTRACT_DIR" 2>/dev/null || true
    rm -f "$SETUPOS_CONFIG_IMG_PATH" "$HOSTOS_UPGRADE_IMG_TAR_PATH" "$GUESTOS_FULL_IMG_TAR_PATH" "$GUESTOS_UPGRADE_IMG_TAR_PATH" 2>/dev/null || true
}

fetch_file() {
    # Fetch a file from a URL or local filesystem and store it at the specified path.
    local source="$1"
    local dest="$2"
    local name="$3"

    if [[ "$source" == *"://"* ]]; then
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

    case "$GUESTOS_DEPLOYMENT_MODE" in
        full)
            fetch_file "$GUESTOS_FULL_IMG_TAR_SRC" "$GUESTOS_FULL_IMG_TAR_PATH" "GuestOS full disk image"
            ;;
        upgrade)
            fetch_file "$GUESTOS_UPGRADE_IMG_TAR_SRC" "$GUESTOS_UPGRADE_IMG_TAR_PATH" "GuestOS upgrade image"
            ;;
        none) ;;
    esac
}

setup_temp_mounts() {
    echo "Setting up temporary mounts..."
    mkdir -p /config /data
    mount -t tmpfs tmpfs /config
    mount -t tmpfs tmpfs /data

    for staged_file in "${STAGED_OPT_IC_BIN_FILES[@]}"; do
        local source_path="${SCRIPT_DIR}/${staged_file}"
        local target_path="/opt/ic/bin/${staged_file}"

        if [ ! -f "$source_path" ]; then
            echo "Missing staged file: ${source_path}" >&2
            exit 1
        fi

        [ -e "$target_path" ] || touch "$target_path"
        mount --bind "$source_path" "$target_path"
    done
}

install_new_hostos() {
    if [ -z "$HOSTOS_UPGRADE_IMG_TAR_SRC" ]; then
        echo "No HostOS upgrade image specified, skipping HostOS upgrade."
        return
    fi

    echo "Invoking HostOS upgrade..."
    /opt/ic/bin/manageboot.sh --nocheck hostos upgrade-install "$HOSTOS_UPGRADE_IMG_TAR_PATH"
}

install_guestos_full_image() {
    if [ "$GUESTOS_DEPLOYMENT_MODE" != "full" ]; then
        echo "No GuestOS full disk image specified, skipping full GuestOS installation."
        return
    fi

    echo "Installing GuestOS full disk image..."
    mkdir -p "$GUESTOS_EXTRACT_DIR"
    tar -xavf "$GUESTOS_FULL_IMG_TAR_PATH" -C "$GUESTOS_EXTRACT_DIR"

    echo "Stopping GuestOS service..."
    systemctl stop guestos.service || true
    systemctl stop upgrade-guestos.service || true

    echo "Writing GuestOS full disk image..."
    dd if="$GUESTOS_EXTRACT_DIR/disk.img" of=/dev/mapper/hostlvm-guestos bs=4M
    echo "Successfully installed GuestOS full disk image."
}

write_guestos_upgrade_prep_info() {
    cat >"$GUESTOS_RECOVERY_STAGE_DIR/prep-info" <<EOF
VERSION=
RECOVERY_HASH_PREFIX=
TARGET_BOOT_ALTERNATIVE=$GUESTOS_TARGET_BOOT_ALTERNATIVE
WIPE_VAR_PARTITION=$GUESTOS_WIPE_VAR_PARTITION
VERSION_HASH_FULL=
RECOVERY_HASH_FULL=
EOF
    chmod 0644 "$GUESTOS_RECOVERY_STAGE_DIR/prep-info"
}

stage_guestos_upgrade_artifacts() {
    echo "Staging GuestOS upgrade artifacts in $GUESTOS_RECOVERY_STAGE_DIR..."
    rm -rf "$GUESTOS_RECOVERY_STAGE_DIR"
    mkdir -p "$GUESTOS_RECOVERY_STAGE_DIR"
    mv "$GUESTOS_UPGRADE_IMG_TAR_PATH" "$GUESTOS_RECOVERY_STAGE_DIR/upgrade.tar.zst"
    write_guestos_upgrade_prep_info
}

install_guestos_upgrade_image() {
    if [ "$GUESTOS_DEPLOYMENT_MODE" != "upgrade" ]; then
        echo "No GuestOS upgrade image specified, skipping GuestOS upgrade image install."
        return
    fi

    echo "Installing GuestOS upgrade image..."
    stage_guestos_upgrade_artifacts

    local -a launcher_args=(mode=install "target-boot-alternative=$GUESTOS_TARGET_BOOT_ALTERNATIVE")
    if [ "$GUESTOS_WIPE_VAR_PARTITION" = "true" ]; then
        launcher_args+=(wipe-var-partition)
    fi

    /opt/ic/bin/guestos-recovery-launcher.sh "${launcher_args[@]}"
    echo "Successfully installed GuestOS upgrade image."
}

install_guestos() {
    case "$GUESTOS_DEPLOYMENT_MODE" in
        full)
            install_guestos_full_image
            ;;
        upgrade)
            install_guestos_upgrade_image
            ;;
        none)
            echo "No GuestOS deployment requested, skipping GuestOS installation."
            ;;
    esac
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

    # Create directories/mounts expected by the SetupOS tools
    mkdir -p /var/ic
    mount -t tmpfs tmpfs /var/ic

    # Mount SetupOS config image
    mkdir -p "$SETUPOS_CONFIG_MOUNT"
    mount "$SETUPOS_CONFIG_IMG_PATH" "$SETUPOS_CONFIG_MOUNT"

    # Wait for udev to create the /dev/disk/by-label/OVERRIDE symlink for the
    # loop-mounted config image, which preload-config.sh depends on.
    udevadm wait --timeout=10 /dev/disk/by-label/OVERRIDE

    # Preload and create config
    /opt/ic/bin/preload-config.sh
    /opt/ic/bin/config_tool create-setupos-config

    echo "Copying configuration files to target partition..."

    export CONFIG_PARTITION_PATH=/boot/config
    source /opt/ic/bin/setup-hostos-config.sh
    copy_config_files
}

commit_and_reboot() {
    local boot_args="$1"

    if command -v kexec >/dev/null 2>&1; then
        echo "Preparing kexec for fast reboot..."
        kexec -l "$TARGET_BOOT_PARTITION_MOUNT/vmlinuz" \
            --initrd="$TARGET_BOOT_PARTITION_MOUNT/initrd.img" \
            --command-line="$boot_args"
    else
        echo "kexec not available, will perform slow reboot..."
    fi

    echo "Committing HostOS upgrade..."
    /opt/ic/bin/manageboot.sh --nocheck hostos upgrade-commit
}

parse_args() {
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
                GUESTOS_FULL_IMG_TAR_SRC="${1#*=}"
                shift
                ;;
            --guestos-upgrade-img=*)
                GUESTOS_UPGRADE_IMG_TAR_SRC="${1#*=}"
                shift
                ;;
            --guestos-target-boot-alternative=*)
                GUESTOS_TARGET_BOOT_ALTERNATIVE="${1#*=}"
                shift
                ;;
            --guestos-wipe-var-partition)
                GUESTOS_WIPE_VAR_PARTITION=true
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
}

validate_guestos_args() {
    if [ -n "$GUESTOS_FULL_IMG_TAR_SRC" ] && [ -n "$GUESTOS_UPGRADE_IMG_TAR_SRC" ]; then
        echo "--guestos-img and --guestos-upgrade-img are mutually exclusive" >&2
        usage
        exit 1
    fi

    if [ -n "$GUESTOS_FULL_IMG_TAR_SRC" ]; then
        GUESTOS_DEPLOYMENT_MODE="full"
    elif [ -n "$GUESTOS_UPGRADE_IMG_TAR_SRC" ]; then
        GUESTOS_DEPLOYMENT_MODE="upgrade"
    else
        GUESTOS_DEPLOYMENT_MODE="none"
    fi

    case "$GUESTOS_DEPLOYMENT_MODE" in
        full)
            if [ -n "$GUESTOS_TARGET_BOOT_ALTERNATIVE" ] || [ "$GUESTOS_WIPE_VAR_PARTITION" = "true" ]; then
                echo "--guestos-target-boot-alternative and --guestos-wipe-var-partition require --guestos-upgrade-img" >&2
                usage
                exit 1
            fi
            ;;
        upgrade)
            if [ -z "$GUESTOS_TARGET_BOOT_ALTERNATIVE" ]; then
                echo "--guestos-target-boot-alternative is required with --guestos-upgrade-img" >&2
                usage
                exit 1
            fi
            if [ "$GUESTOS_TARGET_BOOT_ALTERNATIVE" != "A" ] && [ "$GUESTOS_TARGET_BOOT_ALTERNATIVE" != "B" ]; then
                echo "--guestos-target-boot-alternative must be A or B" >&2
                usage
                exit 1
            fi
            ;;
        none)
            if [ -n "$GUESTOS_TARGET_BOOT_ALTERNATIVE" ] || [ "$GUESTOS_WIPE_VAR_PARTITION" = "true" ]; then
                echo "--guestos-target-boot-alternative and --guestos-wipe-var-partition require --guestos-upgrade-img" >&2
                usage
                exit 1
            fi
            ;;
    esac
}

validate_inputs() {
    if [ -z "$HOSTOS_UPGRADE_IMG_TAR_SRC" ] && [ -z "$GUESTOS_FULL_IMG_TAR_SRC" ] && [ -z "$GUESTOS_UPGRADE_IMG_TAR_SRC" ] && [ -z "$SETUPOS_CONFIG_IMG_SRC" ]; then
        echo "At least one of --hostos-upgrade-img, --guestos-img, --guestos-upgrade-img or --setupos-config-img must be provided" >&2
        usage
        exit 1
    fi

    validate_guestos_args
}

finalize_deployment() {
    if [ -n "$HOSTOS_UPGRADE_IMG_TAR_SRC" ]; then
        # Determine target alternative and mount its boot partition
        target_alternative="$(/opt/ic/bin/manageboot.sh hostos target)"
        echo "Will update HostOS into: $target_alternative"
        mount_target_boot_partition "$target_alternative"

        # Read boot arguments from new HostOS
        eval "$(cat "$TARGET_BOOT_PARTITION_MOUNT/boot_args")"
        boot_args_var=BOOT_ARGS_${target_alternative}

        commit_and_reboot "${!boot_args_var}"
        return
    fi

    if [ -n "$SETUPOS_CONFIG_IMG_SRC" ]; then
        # Config-only update: reboot with current kernel
        echo "Preparing kexec reboot with current kernel..."
        kexec -l /boot/vmlinuz --initrd=/boot/initrd.img --reuse-cmdline
        nohup bash -c 'sleep 2; systemctl start kexec.target' >/dev/null 2>&1 &
        return
    fi

    case "$GUESTOS_DEPLOYMENT_MODE" in
        full)
            echo "Only a GuestOS full disk image was updated."
            echo "Starting GuestOS..."
            systemctl start guestos.service
            ;;
        upgrade)
            echo "Only a GuestOS upgrade image was applied."
            ;;
        none) ;;
    esac
}

trap cleanup EXIT

parse_args "$@"
validate_inputs

mount -o remount,rw /
cleanup

fetch_images
setup_temp_mounts
install_new_hostos
install_guestos
setup_config
finalize_deployment
