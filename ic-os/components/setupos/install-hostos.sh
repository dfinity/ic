#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/config.sh
source /opt/ic/bin/functions.sh

function install_hostos() {
    echo "* Installing HostOS disk-image..."

    target_drive=$(find_first_drive)

    TMPDIR=$(mktemp -d)
    echo "* Extracting HostOS image..."
    tar xaf /data/host-os.img.tar.zst -C "${TMPDIR}" disk.img
    log_and_halt_installation_on_error "${?}" "Unable to extract HostOS disk-image."

    echo "* Writing the HostOS image to /dev/${target_drive}..."
    dd if="${TMPDIR}/disk.img" of="/dev/${target_drive}" bs=10M conv=sparse status=progress
    log_and_halt_installation_on_error "${?}" "Unable to install HostOS disk-image."

    rm -rf "${TMPDIR}"

    sync
    log_and_halt_installation_on_error "${?}" "Unable to synchronize cached writes to persistent storage."
}

function configure_efi() {
    echo "* Configuring EFI..."

    target_drive=$(find_first_drive)
    partition_prefix=""
    if [[ "${target_drive}" = nvme* ]]; then
        partition_prefix="p"
    fi

    bootnum=$(efibootmgr --verbose | grep "IC-OS" | sed 's/Boot\([0-9A-F]*\).*/\1/')
    for b in ${bootnum}; do
        efibootmgr --delete-bootnum --bootnum ${b} >/dev/null 2>&1
        log_and_halt_installation_on_error "${?}" "Unable to delete existing 'IC-OS' boot entry."
    done

    efibootmgr --create --gpt --disk "/dev/${target_drive}${partition_prefix}1" --loader "\EFI\BOOT\BOOTX64.EFI" --label "IC-OS" >/dev/null 2>&1
    log_and_halt_installation_on_error "${?}" "Unable to create 'IC-OS' boot entry."

    efibootmgr --remove-dups >/dev/null 2>&1
    log_and_halt_installation_on_error "${?}" "Unable to remove duplicate boot order entries."

    efibootmgr --verbose | grep "IC-OS" | efibootmgr -o $(sed 's/Boot\([0-9A-F]*\).*/\1/') >/dev/null 2>&1
    log_and_halt_installation_on_error "${?}" "Unable to set EFI boot order."
}

function resize_partition() {
    echo "* Resizing partition..."

    target_drive=$(find_first_drive)

    # Repair header at end of disk
    sgdisk --move-second-header "/dev/${target_drive}" >/dev/null 2>&1
    log_and_halt_installation_on_error "${?}" "Unable to extend GPT data structures: /dev/${target_drive}"

    # Extend the LVM partition to fill disk
    parted -s --align optimal "/dev/${target_drive}" "resizepart 3 100%" >/dev/null 2>&1
    log_and_halt_installation_on_error "${?}" "Unable to resize partition: /dev/${target_drive}${partition_prefix}3"

    # Check and update PVs
    pvscan >/dev/null 2>&1
    log_and_halt_installation_on_error "${?}" "Unable scan physical volumes."

    # Extend PV to the end of LVM partition
    pvresize "/dev/${target_drive}${partition_prefix}3" >/dev/null 2>&1
    log_and_halt_installation_on_error "${?}" "Unable to resize physical volume: /dev/${target_drive}${partition_prefix}3"

    # Check and update VGs
    vgscan >/dev/null 2>&1
    log_and_halt_installation_on_error "${?}" "Unable scan volume groups."

    # Check and update LVs
    lvscan >/dev/null 2>&1
    log_and_halt_installation_on_error "${?}" "Unable scan logical volumes."

    # Add additional PVs to VG
    count=1
    large_drives=($(lsblk -nld -o NAME,SIZE | grep 'T$' | grep -o '^\S*'))
    for drive in $(echo ${large_drives[@]}); do
        # Avoid adding PV of main disk
        if [ "/dev/${drive}" == "/dev/${target_drive}" ]; then
            continue
        fi
        count=$((count + 1))

        vgextend hostlvm "/dev/${drive}"
        log_and_halt_installation_on_error "${?}" "Unable to include PV '/dev/${drive}' in VG."
    done

    local node_reward_type=$(get_config_value '.icos_settings.node_reward_type')

    # Configure multiple GuestOS if type4.X
    if [[ $node_reward_type =~ ^type4(\.[0-9]+)?$ ]]; then
        # Cleanup the initial GuestOS
        lvremove -f hostlvm/guestos >/dev/null 2>&1
        log_and_halt_installation_on_error "${?}" "Unable to cleanup initial GuestOS volume"

        # And set up new split volumes
        min_pv_free=$(pvs --noheadings -o pv_pe_count,pv_pe_alloc_count -S vg_name=hostlvm | awk '{print $1 - $2}' | sort -n | head -n1)

        create_guestos_lvs() {
            local total="$1"
            local each=$(((min_pv_free / total) * count))
            local i

            for ((i = 0; i < total; i++)); do
                lvcreate -i "${count}" --type striped -l "${each}" -n "guestos${i}" hostlvm >/dev/null 2>&1
                log_and_halt_installation_on_error "${?}" "Unable to create new GuestOS"
            done
        }

        case "${node_reward_type}" in
            type4.0) create_guestos_lvs 32 ;;
            type4.1) create_guestos_lvs 60 ;;
            type4.2) create_guestos_lvs 8 ;;
            type4.3) create_guestos_lvs 4 ;;
            type4.4) create_guestos_lvs 2 ;;
        esac
    # "Normal" behavior
    else
        # Extend GuestOS LV to fill VG space
        lvextend -i "${count}" --type striped -l +100%FREE /dev/hostlvm/guestos >/dev/null 2>&1
        log_and_halt_installation_on_error "${?}" "Unable to extend logical volume: /dev/hostlvm/guestos"
    fi
}

# Establish run order
main() {
    log_start "$(basename $0)"
    install_hostos
    configure_efi
    resize_partition
    log_end "$(basename $0)"
}

main
