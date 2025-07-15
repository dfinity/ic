#!/usr/bin/env bash

set -euo pipefail

# First upload the image. Since this is a CAS url, we assume the last URL path part is the sha256
image_download_url=$("$UPLOAD_SYSTEST_DEP" "$DISK_IMG")
sha256="${image_download_url##*/}"

cmd="$BIN --version $(cat "$VERSION_FILE") --url "$image_download_url" --sha256 "$sha256""

# Hack to switch nested for SetupOS
if [[ "$0" =~ "setupos" ]]; then
    export ENV_DEPS__EMPTY_DISK_IMG_URL="$("$UPLOAD_SYSTEST_DEP" "$EMPTY_DISK_IMG_PATH")"
    export ENV_DEPS__EMPTY_DISK_IMG_HASH="${ENV_DEPS__EMPTY_DISK_IMG_URL##*/}"
    cmd="$cmd --nested"
fi

eval "$cmd"
