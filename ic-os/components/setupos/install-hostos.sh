#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

function install_hostos() {
    target_drive=$(find_first_drive)
    echo "* Installing HostOS disk-image to ${target_drive}..."

    TMPDIR=$(mktemp -d)
    # Extract the disk image to RAM.  Cannot run concurrently with install-guestos.sh.
    echo "* Temporarily extracting the HostOS image to memory; please stand by for a few seconds"
    tar xaf /data/host-os.img.tar.zst -C "${TMPDIR}" disk.img
    log_and_halt_installation_on_error "${?}" "Unable to extract HostOS disk-image."
    # Write the extracted image to the disk.
    # Progress is handled by status=progress.
    # dd will detect nulls in chunks of 4M and sparsify the writes.
    # Makes a huge difference when running the setup under QEMU with no KVM.
    # In *non-KVM-accelerated* VM, this goes 500 MB/s, three times as fast as before.
    echo "* Writing the HostOS image to /dev/${target_drive}"
    dd if="${TMPDIR}/disk.img" of="/dev/${target_drive}" bs=4M conv=sparse status=progress
    log_and_halt_installation_on_error "${?}" "Unable to install HostOS disk-image on drive: /dev/${target_drive}"

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

    # Extend GuestOS LV to fill VG space
    lvextend -i "${count}" --type striped -l +100%FREE /dev/hostlvm/guestos >/dev/null 2>&1
    log_and_halt_installation_on_error "${?}" "Unable to extend logical volume: /dev/hostlvm/guestos"
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
