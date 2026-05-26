#!/bin/bash

# This builds the filesystem tree for the /boot hierarchy containing
# the /boot/grub and /boot/efi portions. From this, the grub and
# efi partitions of the disk image can be built.

set -euxo pipefail

trap 'sudo rm -rf "${TMP_DIR}"' EXIT

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

TMP_DIR=$(mktemp -d --tmpdir="/tmp/containers" build-image-XXXXXXXXXXXX)

BASE_IMAGE="ghcr.io/dfinity/library/ubuntu@sha256:5e275723f82c67e387ba9e3c24baa0abdcb268917f276a0561c97bef9450d0b4"

podman --root "${TMP_DIR}/root" --runroot "${TMP_DIR}/runroot" build --iidfile "${TMP_DIR}/iidfile" - <<<"
    FROM $BASE_IMAGE
    USER root:root
    # Pin apt to an Ubuntu archive snapshot so the bootloader build is reproducible.
    # We rewrite the apt sources rather than using 'apt-get --snapshot' because that
    # flag requires apt >= 3.0 (Ubuntu 25.10+), while the base image above is older.
    # snapshot.ubuntu.com redirects HTTP -> HTTPS, but the pinned base image's CA
    # store cannot verify its certificate chain. We therefore disable TLS peer
    # verification: package integrity is still ensured by apt's GPG verification of
    # the Release file against the embedded ubuntu-keyring.
    RUN rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list \
     && printf '%s\n' \
            'deb https://snapshot.ubuntu.com/ubuntu/20260131T000000Z noble main universe' \
            'deb https://snapshot.ubuntu.com/ubuntu/20260131T000000Z noble-updates main universe' \
            'deb https://snapshot.ubuntu.com/ubuntu/20260131T000000Z noble-security main universe' \
            > /etc/apt/sources.list \
     && apt-get -o Acquire::Check-Valid-Until=false -o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false -y update \
     && apt-get -o Acquire::Check-Valid-Until=false -o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false -y --no-install-recommends install grub-efi faketime
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

IMAGE_ID=$(cut -d':' -f2 <"${TMP_DIR}/iidfile")
CONTAINER_NAME="${IMAGE_ID}_container"

podman --root "${TMP_DIR}/root" --runroot "${TMP_DIR}/runroot" create --name "${CONTAINER_NAME}" "${IMAGE_ID}"
podman --root "${TMP_DIR}/root" --runroot "${TMP_DIR}/runroot" export "${CONTAINER_NAME}" | tar --strip-components=1 -C "${TMP_DIR}" -x build
tar cf "${OUT_FILE}" --sort=name --owner=root:0 --group=root:0 "--mtime=UTC 1970-01-01 00:00:00" -C "${TMP_DIR}" boot
