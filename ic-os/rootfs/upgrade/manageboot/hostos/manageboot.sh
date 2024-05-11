#!/bin/bash

set -e

# Source the functions required for writing metrics
source /opt/ic/bin/metrics.sh

SCRIPT="$(basename "$0")[$$]"
HOSTOS_VERSION_FILE="/opt/ic/share/version.txt"

write_log() {
    local message=$1

    if [ -t 1 ]; then
        echo "${SCRIPT} ${message}" >/dev/stdout
    fi

    logger -t ${SCRIPT} "${message}"
}

function get_hostos_version_noreport() {
    if [ -r ${HOSTOS_VERSION_FILE} ]; then
        HOSTOS_VERSION=$(cat ${HOSTOS_VERSION_FILE})
        HOSTOS_VERSION_OK=1
    else
        HOSTOS_VERSION="unknown"
        HOSTOS_VERSION_OK=0
    fi
}

# Reads properties "boot_alternative" and "boot_cycle" from the grubenv
# file. The properties are stored as global variables.
#
# Arguments:
# $1 - name of grubenv file
function read_grubenv() {
    local GRUBENV_FILE="$1"

    while IFS="=" read -r key value; do
        case "$key" in
            '#'*) ;;
            'boot_alternative') ;&
            'boot_cycle')
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
function write_grubenv() {
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
function swap_alternative() {
    if [ "$1" == B ]; then
        echo A
    else
        echo B
    fi
}

function get_boot_partition() {
    if [ "$1" == B ]; then
        echo /dev/hostlvm/B_boot
    else
        echo /dev/hostlvm/A_boot
    fi
}
function get_root_partition() {
    if [ "$1" == B ]; then
        echo /dev/hostlvm/B_root
    else
        echo /dev/hostlvm/A_root
    fi
}
function get_var_partition() {
    if [ "$1" == B ]; then
        echo /dev/hostlvm/B_var
    else
        echo /dev/hostlvm/A_var
    fi
}

function usage() {
    cat <<EOF
Usage:
  manageboot.sh [ -f grubenvfile] action

  -f specify alternative grubenv file (defaults to /boot/grub/grubenv).
     Primarily useful for testing

  Action is one of

    install
      Installs a new system image into the spare partition and changes
      bootloader to use it on next boot. (Caller will still have to
      reboot on next opportunity).
      The new system image must be given via two filenames as
      additional command line arguments: first the "boot" partition
      image, then the "root" partition image.

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

# Parsing options first
GRUBENV_FILE=/boot/grub/grubenv
while getopts ":f" OPT; do
    case "${OPT}" in
        f)
            GRUBENV_FILE="${OPTARG}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

get_hostos_version_noreport

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

    write_metric "hostos_boot_stable" \
        "0" \
        "HostOS is boot stable" \
        "gauge"
fi

if [ "${boot_cycle}" == "failsafe_check" ]; then
    # If the system booted is marked as "failsafe_check" then bootloader
    # will revert to the other system on next boot.
    NEXT_BOOT=$(swap_alternative "${NEXT_BOOT}")
    write_log "HostOS sets ${NEXT_BOOT} as failsafe for next boot"

    # TODO should also set IS_STABLE=0 here to prevent manual overwrite
    # of a backup install slot.

    write_metric "hostos_boot_stable" \
        "0" \
        "HostOS is boot stable" \
        "gauge"
    write_metric_attr "hostos_boot_action" \
        "{next_boot=\"${NEXT_BOOT}\",version=\"${HOSTOS_VERSION}\"}" \
        "2" \
        "HostOS boot action" \
        "gauge"

fi

TARGET_ALTERNATIVE=$(swap_alternative "${CURRENT_ALTERNATIVE}")
CURRENT_ROOT=$(get_root_partition "${CURRENT_ALTERNATIVE}")
TARGET_ROOT=$(get_root_partition "${TARGET_ALTERNATIVE}")
CURRENT_BOOT=$(get_boot_partition "${CURRENT_ALTERNATIVE}")
TARGET_BOOT=$(get_boot_partition "${TARGET_ALTERNATIVE}")
CURRENT_VAR=$(get_var_partition "${CURRENT_ALTERNATIVE}")
TARGET_VAR=$(get_var_partition "${TARGET_ALTERNATIVE}")

# Execute subsequent action
ACTION="$1"
shift

case "${ACTION}" in
    install)
        if [ "${IS_STABLE}" != 1 ]; then
            write_log "HostOS attempted to install upgrade in unstable state"
            echo "Cannot install an upgrade before present system is committed as stable." >&2
            exit 1
        fi
        BOOT_IMG="$1"
        ROOT_IMG="$2"

        if [ "${BOOT_IMG}" == "" -o "${ROOT_IMG}" == "" ]; then
            usage
            exit 1
        fi

        write_log "HostOS current version ${HOSTOS_VERSION} at slot ${CURRENT_ALTERNATIVE}"
        write_log "HostOS upgrade started, modifying slot ${TARGET_ALTERNATIVE} at ${TARGET_BOOT} and ${TARGET_ROOT}"

        # Write to target partitions, and "wipe" header of var partition
        # (to ensure that new target starts from a pristine state).

        dd if="${BOOT_IMG}" of="${TARGET_BOOT}" bs=1M status=progress
        write_metric_attr "hostos_boot_action" \
            "{written_boot=\"${TARGET_BOOT}\"}" \
            "1" \
            "HostOS boot action" \
            "gauge"

        dd if="${ROOT_IMG}" of="${TARGET_ROOT}" bs=1M status=progress
        write_metric_attr "hostos_boot_action" \
            "{written_root=\"${TARGET_ROOT}\"}" \
            "1" \
            "HostOS boot action" \
            "gauge"

        dd if=/dev/zero of="${TARGET_VAR}" bs=1M count=16 status=progress
        write_metric_attr "hostos_boot_action" \
            "{written_var=\"true\"}" \
            "1" \
            "HostOS boot action" \
            "gauge"

        boot_alternative="${TARGET_ALTERNATIVE}"
        boot_cycle=first_boot
        write_grubenv "${GRUBENV_FILE}"

        write_log "HostOS upgrade written to slot ${TARGET_ALTERNATIVE}"
        write_metric "hostos_boot_stable" \
            "0" \
            "HostOS is boot stable" \
            "gauge"
        ;;
    confirm)
        if [ "$boot_cycle" != "stable" ]; then
            boot_cycle=stable
            write_grubenv "${GRUBENV_FILE}"
            write_log "HostOS stable boot confirmed at slot ${CURRENT_ALTERNATIVE}"
            write_metric "hostos_boot_stable" \
                "1" \
                "HostOS is boot stable" \
                "gauge"
            write_metric_attr "hostos_boot_action" \
                "{confirm_boot=\"${CURRENT_BOOT}\",version=\"${HOSTOS_VERSION}\"}" \
                "1" \
                "HostOS boot action" \
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
