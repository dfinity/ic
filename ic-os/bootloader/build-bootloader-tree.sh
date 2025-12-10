#!/bin/bash

# This builds the filesystem tree for the /boot hierarchy containing
# the /boot/grub and /boot/efi portions. From this, the grub and
# efi partitions of the disk image can be built.

set -exo pipefail

cleanup() {
    podman system prune --all --volumes --force
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

while getopts "o:" OPT; do
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

BASE_IMAGE="ghcr.io/dfinity/library/ubuntu@sha256:6015f66923d7afbc53558d7ccffd325d43b4e249f41a6e93eef074c9505d2233"

podman build --no-cache --iidfile "${TMPDIR}/iidfile" - <<<"
    FROM $BASE_IMAGE
    USER root:root
    RUN apt-get -y update && apt-get -y --no-install-recommends install grub-efi faketime
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

IMAGE_ID=$(cut -d':' -f2 <"${TMPDIR}/iidfile")

CONTAINER=$(podman run -d "${IMAGE_ID}")

podman export "${CONTAINER}" | tar --strip-components=1 -C "${TMPDIR}" -x build
tar cf "${OUT_FILE}" --sort=name --owner=root:0 --group=root:0 "--mtime=UTC 1970-01-01 00:00:00" -C "${TMPDIR}" boot
