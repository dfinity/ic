#!/usr/bin/env bash

set -euo pipefail

# First upload the image
sha256=$(sha256sum "$DISK_IMG" | cut -d' ' -f1)
image_download_url=$("$UPLOAD_SYSTEST_DEP" "$DISK_IMG")

cmd="$BIN --version $(cat "$VERSION_FILE") --url "$image_download_url" --sha256 "$sha256" --build-bootstrap-script $(realpath "$SCRIPT")"

# Hack to switch nested for SetupOS
if [[ "$0" =~ "setupos" ]]; then
    cmd="$cmd --nested"
fi

eval "$cmd"
