#!/bin/bash

set -e

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh
source /opt/ic/bin/grub.sh

SCRIPT="$(basename "$0")[$$]"
VERSION_FILE="/opt/ic/share/version.txt"

get_version_noreport() {
    if [ -r "${VERSION_FILE}" ]; then
        VERSION=$(cat ${VERSION_FILE})
        VERSION_OK=1
    else
        VERSION="unknown"
        VERSION_OK=0
    fi
}

# Convert A -> B and B -> A
swap_alternative() {
    if [ "$1" == B ]; then
        echo A
    else
        echo B
    fi
}

declare -A GUESTOS_PARTITIONS=(
    [A_boot]="/dev/sda4"
    [B_boot]="/dev/sda7"
    [A_root]="/dev/sda5"
    [B_root]="/dev/sda8"
    [A_var]="/dev/sda6"
    [B_var]="/dev/sda9"
)

declare -A HOSTOS_PARTITIONS=(
    [A_boot]="/dev/hostlvm/A_boot"
    [B_boot]="/dev/hostlvm/B_boot"
    [A_root]="/dev/hostlvm/A_root"
    [B_root]="/dev/hostlvm/B_root"
    [A_var]="/dev/hostlvm/A_var"
    [B_var]="/dev/hostlvm/B_var"
)

# Get partition based on alternative and type
# Arguments:
# $1 - alternative (A or B)
# $2 - partition type (boot, root, var)
get_partition() {
    local ALTERNATIVE="$1"
    local PARTITION_TYPE="$2"

    if [ "$SYSTEM_TYPE" == "guestos" ]; then
        echo "${GUESTOS_PARTITIONS[${ALTERNATIVE}_${PARTITION_TYPE}]}"
    elif [ "$SYSTEM_TYPE" == "hostos" ]; then
        echo "${HOSTOS_PARTITIONS[${ALTERNATIVE}_${PARTITION_TYPE}]}"
    fi
}

usage() {
    cat <<EOF
Usage:
  manageboot.sh [ -f grubenvfile] system_type action

  -f specify alternative grubenv file (defaults to /boot/grub/grubenv).
     Primarily useful for testing

  Arguments:
    system_type - System type (guestos or hostos)

  Action is one of

    upgrade-install
      Installs a new system image into the spare partition.
      The new system image can be given in two different ways:
      - as a single .tar (or .tar.zst) file containing two files
        named "boot.img" and "root.img"
      - as two filenames: first the "boot" partition
        image, then the "root" partition image.
      The update is written to the partitions, but the bootloader is
      not changed yet; see upgrade-commit command.

    upgrade-commit [--no-reboot]
      Commits a previously installed upgrade by writing instructions to the
      bootloader to switch to the new system after reboot, and also triggers
      reboot immediately (unless --no-reboot is specified).
      This must be called after the upgrade-install command above finished
      successfully. Calling it under any other circumstances is illegal and
      will result in a wrong (possibly failing) boot.

      Options:
        --no-reboot  Skip the automatic reboot after committing the upgrade.

    confirm
      Confirm that the current system booted fine (required after first
      boot of newly installed upgrade to prevent bootloader falling back
      to previous installation). This simply does nothing if the system
      has been confirmed previously already (safe to call as many times
      as you like, will not initiate I/O if nothing to be written).

    current
      Output currently booted system (A or B) on stdout and exit.

    target
      Output target system for incoming upgrade (A or B) on stdout and exit.

    next
      Output system (A or B) to be booted next. This may either be the
      same one as running now (if present system is "stable"), or it may
      be the other system (if newly upgraded system has not "confirmed"
      yet).

    current_root
      Output root partition of currently running system.

    target_root
      Output target root partition for incoming upgrade on stdout and exit.
EOF
}

# Re-execute the script as root always to allow privileged boot state reporting
# SELinux restrictions and standard permissions still apply, the script and
# the calling user are restricted to being allowed to sudo only this
if [ $(id -u) != 0 ]; then
    exec sudo "$0" "$@"
fi

# Parsing options first
GRUBENV_FILE=/boot/grub/grubenv
while getopts ":f:" OPT; do
    case "${OPT}" in
        f)
            GRUBENV_FILE="${OPTARG}"
            ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
done
shift $((OPTIND - 1))

SYSTEM_TYPE="$1"
ACTION="$2"
shift 2

if [ -z "${SYSTEM_TYPE}" ] || [ -z "${ACTION}" ]; then
    usage >&2
    exit 1
fi

if [[ "${SYSTEM_TYPE}" != "guestos" && "${SYSTEM_TYPE}" != "hostos" ]]; then
    write_log "Invalid system type. Must be 'guestos' or 'hostos'."
    exit 1
fi

get_version_noreport

# Read current state
read_grubenv "${GRUBENV_FILE}"
write_log "${SYSTEM_TYPE} read grub environment - boot_alternative: ${boot_alternative}, boot_cycle: ${boot_cycle}"

CURRENT_ALTERNATIVE="${boot_alternative}"
NEXT_BOOT="${CURRENT_ALTERNATIVE}"
IS_STABLE=1
if [ "${boot_cycle}" == "first_boot" ]; then
    # If the next system to be booted according to bootloader has never been
    # booted yet, then we must still be in the other system.
    write_log "WARNING: ${SYSTEM_TYPE} detected first_boot state - adjusting CURRENT_ALTERNATIVE from ${CURRENT_ALTERNATIVE} to $(swap_alternative "${CURRENT_ALTERNATIVE}")"
    CURRENT_ALTERNATIVE=$(swap_alternative "${CURRENT_ALTERNATIVE}")
    IS_STABLE=0
    write_log "${SYSTEM_TYPE} system marked as unstable due to first_boot state"

    write_metric "${SYSTEM_TYPE}_boot_stable" \
        "0" \
        "${SYSTEM_TYPE} is boot stable" \
        "gauge"
fi

if [ "${boot_cycle}" == "failsafe_check" ]; then
    # If the system booted is marked as "failsafe_check" then bootloader
    # will revert to the other system on next boot.
    write_log "${SYSTEM_TYPE} detected failsafe_check state - system will rollback to $(swap_alternative "${NEXT_BOOT}") on next reboot"
    NEXT_BOOT=$(swap_alternative "${NEXT_BOOT}")
    write_log "${SYSTEM_TYPE} sets ${NEXT_BOOT} as failsafe for next boot"

    # TODO should also set IS_STABLE=0 here to prevent manual overwrite
    # of a backup install slot.
    write_log "${SYSTEM_TYPE} WARNING: System is in failsafe_check state - upgrade attempts will fail until state is resolved"

    write_metric "${SYSTEM_TYPE}_boot_stable" \
        "0" \
        "${SYSTEM_TYPE} is boot stable" \
        "gauge"
    write_metric_attr "${SYSTEM_TYPE}_boot_action" \
        "{next_boot=\"${NEXT_BOOT}\",version=\"${VERSION}\"}" \
        "2" \
        "${SYSTEM_TYPE} boot action" \
        "gauge"
fi

TARGET_ALTERNATIVE=$(swap_alternative "${CURRENT_ALTERNATIVE}")
CURRENT_ROOT=$(get_partition "${CURRENT_ALTERNATIVE}" "root")
TARGET_ROOT=$(get_partition "${TARGET_ALTERNATIVE}" "root")
CURRENT_BOOT=$(get_partition "${CURRENT_ALTERNATIVE}" "boot")
TARGET_BOOT=$(get_partition "${TARGET_ALTERNATIVE}" "boot")
CURRENT_VAR=$(get_partition "${CURRENT_ALTERNATIVE}" "var")
TARGET_VAR=$(get_partition "${TARGET_ALTERNATIVE}" "var")

# Execute subsequent action
case "${ACTION}" in
    upgrade-install)
        write_log "${SYSTEM_TYPE} upgrade-install action called - IS_STABLE: ${IS_STABLE}, boot_cycle: ${boot_cycle}, boot_alternative: ${boot_alternative}"
        if [ "${IS_STABLE}" != 1 ]; then
            write_log "Cannot install an upgrade before present system is committed as stable."
            exit 1
        fi
        write_log "${SYSTEM_TYPE} upgrade-install proceeding - system is stable"

        if [ "$#" == 2 ]; then
            BOOT_IMG="$1"
            ROOT_IMG="$2"
        elif [ "$#" == 1 ]; then
            TMPDIR=$(mktemp -d -t upgrade-image-XXXXXXXXXXXX)
            trap "rm -rf $TMPDIR" exit
            tar -xaf "$1" -C "${TMPDIR}"
            BOOT_IMG="${TMPDIR}"/boot.img
            ROOT_IMG="${TMPDIR}"/root.img
        else
            usage >&2
            exit 1
        fi

        write_log "${SYSTEM_TYPE} current version ${VERSION} at slot ${CURRENT_ALTERNATIVE}"
        write_log "${SYSTEM_TYPE} upgrade started, modifying slot ${TARGET_ALTERNATIVE} at ${TARGET_BOOT} and ${TARGET_ROOT}"

        # Write to target partitions, and "wipe" header of var partition
        # (to ensure that new target starts from a pristine state).
        dd if="${BOOT_IMG}" of="${TARGET_BOOT}" bs=1M status=progress
        write_metric_attr "${SYSTEM_TYPE}_boot_action" \
            "{written_boot=\"${TARGET_BOOT}\"}" \
            "1" \
            "${SYSTEM_TYPE} boot action" \
            "gauge"

        dd if="${ROOT_IMG}" of="${TARGET_ROOT}" bs=1M status=progress
        write_metric_attr "${SYSTEM_TYPE}_boot_action" \
            "{written_root=\"${TARGET_ROOT}\"}" \
            "1" \
            "${SYSTEM_TYPE} boot action" \
            "gauge"

        dd if=/dev/zero of="${TARGET_VAR}" bs=1M count=16 status=progress
        write_metric_attr "${SYSTEM_TYPE}_boot_action" \
            "{written_var=\"true\"}" \
            "1" \
            "${SYSTEM_TYPE} boot action" \
            "gauge"

        write_log "${SYSTEM_TYPE} upgrade written to slot ${TARGET_ALTERNATIVE}"

        ;;
    upgrade-commit)
        write_log "${SYSTEM_TYPE} upgrade-commit action called - IS_STABLE: ${IS_STABLE}, boot_cycle: ${boot_cycle}, boot_alternative: ${boot_alternative}"
        if [ "${IS_STABLE}" != 1 ]; then
            write_log "Cannot install an upgrade before present system is committed as stable."
            exit 1
        fi

        NO_REBOOT=0
        if [ "$1" == "--no-reboot" ]; then
            NO_REBOOT=1
            write_log "${SYSTEM_TYPE} upgrade-commit called with --no-reboot flag"
        fi

        # Tell boot loader to switch partitions on next boot.
        write_log "${SYSTEM_TYPE} upgrade-commit proceeding - switching from ${boot_alternative} to ${TARGET_ALTERNATIVE}"
        write_log "Setting boot_alternative to ${TARGET_ALTERNATIVE} and boot_cycle to first_boot"
        write_grubenv "${GRUBENV_FILE}" "${TARGET_ALTERNATIVE}" "first_boot"
        # Only update variables after successful write_grubenv
        boot_alternative="${TARGET_ALTERNATIVE}"
        boot_cycle=first_boot

        write_log "${SYSTEM_TYPE} upgrade committed to slot ${TARGET_ALTERNATIVE}"
        write_metric_attr "${SYSTEM_TYPE}_boot_action" \
            "{committed=\"true\"}" \
            "1" \
            "${SYSTEM_TYPE} boot action" \
            "gauge"
        write_metric "${SYSTEM_TYPE}_boot_stable" \
            "0" \
            "${SYSTEM_TYPE} is boot stable" \
            "gauge"

        if [ "${NO_REBOOT}" == 1 ]; then
            write_log "${SYSTEM_TYPE} upgrade committed to slot ${TARGET_ALTERNATIVE}, skipping reboot"
        else
            write_log "${SYSTEM_TYPE} upgrade rebooting now, next slot ${TARGET_ALTERNATIVE}"
            # Ignore termination signals from the following reboot, so that
            # the script exits without error.
            trap 'write_log "upgrade-commit received SIGTERM"; exit 0' SIGTERM
            reboot
        fi
        ;;
    confirm)
        write_log "${SYSTEM_TYPE} confirm action called - current boot_cycle: ${boot_cycle}, boot_alternative: ${boot_alternative}, IS_STABLE: ${IS_STABLE}"
        if [ "$boot_cycle" != "stable" ]; then
            write_log "${SYSTEM_TYPE} transitioning from boot_cycle '${boot_cycle}' to 'stable' at slot ${CURRENT_ALTERNATIVE}"
            write_grubenv "${GRUBENV_FILE}" "$boot_alternative" "stable"
            # Only update boot_cycle after successful write_grubenv
            boot_cycle=stable
            write_log "${SYSTEM_TYPE} stable boot confirmed at slot ${CURRENT_ALTERNATIVE}"
            write_metric "${SYSTEM_TYPE}_boot_stable" \
                "1" \
                "${SYSTEM_TYPE} is boot stable" \
                "gauge"
            write_metric_attr "${SYSTEM_TYPE}_boot_action" \
                "{confirm_boot=\"${CURRENT_BOOT}\",version=\"${VERSION}\"}" \
                "1" \
                "${SYSTEM_TYPE} boot action" \
                "gauge"
        else
            write_log "${SYSTEM_TYPE} confirm called but boot_cycle is already 'stable' - no action needed"
        fi
        ;;
    current)
        echo "${CURRENT_ALTERNATIVE}"
        ;;
    target)
        echo "${TARGET_ALTERNATIVE}"
        ;;
    next)
        echo "${NEXT_BOOT}"
        ;;
    current_partition)
        echo "${CURRENT_ROOT}"
        ;;
    target_partition)
        echo "${TARGET_ROOT}"
        ;;
    *)
        usage
        ;;
esac
