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

echo "Copying ${SRC} to ${DST}..."
cp "${SRC}" "${DST}"

echo "Grub configuration updated successfully."
