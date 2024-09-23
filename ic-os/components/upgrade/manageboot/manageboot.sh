#!/bin/bash

set -e

source /opt/ic/bin/logging.sh
# Source the functions required for writing metrics
source /opt/ic/bin/metrics.sh

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

# Reads properties "boot_alternative" and "boot_cycle" from the grubenv
# file. The properties are stored as global variables.
#
# Arguments:
# $1 - name of grubenv file
read_grubenv() {
    local GRUBENV_FILE="$1"

    while IFS="=" read -r key value; do
        case "$key" in
            '#'*) ;;
            'boot_alternative' | 'boot_cycle')
                eval "$key=\"$value\""
                ;;
            *) ;;
        esac
    done <"$GRUBENV_FILE"
}

# Writes "boot_alternative" and "boot_cycle" global variables to grubenv file
#
# Arguments:
# $1 - name of grubenv file
write_grubenv() {
    local GRUBENV_FILE="$1"

    TMP_FILE=$(mktemp /tmp/grubenv-XXXXXXXXXXXX)
    (
        echo "# GRUB Environment Block"
        echo boot_alternative="$boot_alternative"
        echo boot_cycle="$boot_cycle"
        # Fill to make sure we will have 1024 bytes
        echo -n "################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################"
    ) >"${TMP_FILE}"
    # Truncate to arrive at precisely 1024 bytes
    truncate --size=1024 "${TMP_FILE}"
    cat "${TMP_FILE}" >"${GRUBENV_FILE}"
    rm "${TMP_FILE}"
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
    [A_boot]="/dev/vda4"
    [B_boot]="/dev/vda7"
    [A_root]="/dev/vda5"
    [B_root]="/dev/vda8"
    [A_var]="/dev/vda6"
    [B_var]="/dev/vda9"
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

    upgrade-commit
      Commits a previously installed upgrade by writing instructions to the
      bootloader to switch to the new system after reboot, and also triggers
      reboot immediately.
      This must be called after the upgrade-install command above finished
      successfully. Calling it under any other circumstances is illegal and
      will result in a wrong (possibly failing) boot.

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
    echo "Invalid system type. Must be 'guestos' or 'hostos'."
    exit 1
fi

get_version_noreport

# Read current state
read_grubenv "${GRUBENV_FILE}"

CURRENT_ALTERNATIVE="${boot_alternative}"
NEXT_BOOT="${CURRENT_ALTERNATIVE}"
IS_STABLE=1
if [ "${boot_cycle}" == "first_boot" ]; then
    # If the next system to be booted according to bootloader has never been
    # booted yet, then we must still be in the other system.
    CURRENT_ALTERNATIVE=$(swap_alternative "${CURRENT_ALTERNATIVE}")
    IS_STABLE=0

    write_metric "${SYSTEM_TYPE}_boot_stable" \
        "0" \
        "${SYSTEM_TYPE} is boot stable" \
        "gauge"
fi

if [ "${boot_cycle}" == "failsafe_check" ]; then
    # If the system booted is marked as "failsafe_check" then bootloader
    # will revert to the other system on next boot.
    NEXT_BOOT=$(swap_alternative "${NEXT_BOOT}")
    write_log "${SYSTEM_TYPE} sets ${NEXT_BOOT} as failsafe for next boot"

    # TODO should also set IS_STABLE=0 here to prevent manual overwrite
    # of a backup install slot.

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
        if [ "${IS_STABLE}" != 1 ]; then
            write_log "${SYSTEM_TYPE} attempted to install upgrade in unstable state"
            echo "Cannot install an upgrade before present system is committed as stable." >&2
            exit 1
        fi

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
        if [ "${IS_STABLE}" != 1 ]; then
            echo "Cannot install an upgrade before present system is committed as stable." >&2
            exit 1
        fi

        # Tell boot loader to switch partitions on next boot.
        boot_alternative="${TARGET_ALTERNATIVE}"
        boot_cycle=first_boot
        write_grubenv "${GRUBENV_FILE}"

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

        write_log "${SYSTEM_TYPE} upgrade rebooting now, next slot ${TARGET_ALTERNATIVE}"
        sync
        # Ignore termination signals from the following reboot, so that
        # the script exits without error.
        trap -- '' SIGTERM
        reboot
        ;;
    confirm)
        if [ "$boot_cycle" != "stable" ]; then
            boot_cycle=stable
            write_grubenv "${GRUBENV_FILE}"
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
