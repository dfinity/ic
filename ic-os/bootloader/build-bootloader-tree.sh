#!/bin/bash

# This builds the filesystem tree for the /boot hierarchy containing
# the /boot/grub and /boot/efi portions. From this, the grub and
# efi partitions of the disk image can be built.

set -eo pipefail

while getopts "o:t:v:p:x:" OPT; do
    case "${OPT}" in
        o)
            OUT_FILE="${OPTARG}"
            ;;
        *)
            echo "No output file given" >&2
            exit 1
            ;;
    esac
done

TMPDIR=$(mktemp -d -t build-image-XXXXXXXXXXXX)
trap "rm -rf ${TMPDIR}" exit

mkdir -p "${TMPDIR}"/boot/grub
cp -r /usr/lib/grub/x86_64-efi "${TMPDIR}"/boot/grub
mkdir -p "${TMPDIR}"/boot/efi/EFI/Boot
faketime "1970-1-1 0" grub-mkimage -p "(,gpt2)/" -O x86_64-efi -o "${TMPDIR}"/boot/efi/EFI/Boot/bootx64.efi \
    boot linux search normal configfile \
    part_gpt btrfs ext2 fat iso9660 loopback \
    test keystatus gfxmenu regexp probe \
    efi_gop efi_uga all_video gfxterm font \
    echo read ls cat png jpeg halt reboot loadenv

tar cf "${OUT_FILE}" --sort=name --owner=root:0 --group=root:0 "--mtime=UTC 1970-01-01 00:00:00" -C "${TMPDIR}" boot

rm -rf "${TMPDIR}"
