#!/bin/bash
set -euo pipefail

SRC="/boot/grub.cfg"
DST="/grub/grub.cfg"

if [ ! -f "${SRC}" ]; then
    echo "Source grub configuration not found at ${SRC}. Exiting." >&2
    exit 1
fi

if [ ! -d "$(dirname "${DST}")" ]; then
    echo "Destination directory $(dirname "${DST}") does not exist. Exiting." >&2
    exit 1
fi

# Check if destination file exists and compare with source
if [ -f "${DST}" ] && cmp -s "${SRC}" "${DST}"; then
    echo "Source and destination grub configurations are identical. No action needed."
    exit 0
fi

echo "Source and destination grub configurations differ. Copying ${SRC} to ${DST}..."
cp "${SRC}" "${DST}"

echo "Grub configuration updated successfully. Rebooting..."
reboot
