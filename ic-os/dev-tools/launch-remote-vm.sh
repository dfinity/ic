#!/usr/bin/env bash

set -euo pipefail

cmd="$BIN --version $(cat "$VERSION_FILE") --url $(cat "$URL_FILE") --sha256 $(cat "$SHA_FILE") --build-bootstrap-script $(realpath "$SCRIPT")"

# Hack to switch nested for SetupOS
if [[ "$0" =~ "setupos" ]]; then
    cmd="$cmd --nested"
fi

eval "$cmd"
