#!/bin/bash

# This builds the filesystem tree for the /boot hierarchy containing
# the /boot/grub and /boot/efi portions. From this, the grub and
# efi partitions of the disk image can be built.

set -exo pipefail

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

trap 'mountpoint "${TMPFS}" && sudo umount "${TMPFS}"; rm -rf "${TMPFS}"' exit
TMPFS=$(mktemp -d /tmp/mytempdir.XXXXXX)
sudo mount -t tmpfs tmpfs-podman "${TMPFS}"

trap 'rm -rf "${TMPDIR}"; sudo podman --root "${TMPFS}" rm -f "${CONTAINER}"' exit
TMPDIR=$(mktemp -d -t build-image-XXXXXXXXXXXX)

BASE_IMAGE="docker.io/dfinity/ic-build-bazel@sha256:1978886cfda51b09057bffd60f2e5edb588c6c0b74de87696cd4e964335dba87"

sudo podman --root "${TMPFS}" build --iidfile ${TMPDIR}/iidfile - <<<"
    FROM $BASE_IMAGE
    USER root:root
    RUN mkdir -p /build/boot/grub
    RUN cp -r /usr/lib/grub/x86_64-efi /build/boot/grub
    RUN mkdir -p /build/boot/efi/EFI/Boot
    RUN grub-mkimage --version
    RUN apt list --installed | grep grub
    RUN faketime -f '1970-1-1 0:0:0' grub-mkimage -p '(,gpt2)/' -O x86_64-efi -o /build/boot/efi/EFI/Boot/bootx64.efi \
        boot linux search normal configfile \
        part_gpt btrfs ext2 fat iso9660 loopback \
        test keystatus gfxmenu regexp probe \
        efi_gop efi_uga all_video gfxterm font \
        echo read ls cat png jpeg halt reboot loadenv lvm
"

IMAGE=$(cat ${TMPDIR}/iidfile | cut -d':' -f2)

CONTAINER=$(sudo podman --root "${TMPFS}" run --network=host --cgroupns=host -d "$IMAGE")

sudo podman --root "${TMPFS}" export "$CONTAINER" | tar -C "$TMPDIR" -x build --strip-components=1
tar cf "${OUT_FILE}" --sort=name --owner=root:0 --group=root:0 "--mtime=UTC 1970-01-01 00:00:00" -C "${TMPDIR}" boot
find "$TMPDIR/boot" -type f -exec sha256sum {} \; | sed "s|$TMPDIR||"
