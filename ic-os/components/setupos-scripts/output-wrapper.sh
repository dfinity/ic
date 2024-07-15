#!/usr/bin/env bash

# Redirects script output to both the local tty and serial console for real-time monitoring and logging across different environments.

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <tee-target> <script> [script-args]"
    exit 1
fi

TEE_TARGET="$1"
SCRIPT_ARGS=("${@:2}")

"${SCRIPT_ARGS[@]}" 2>&1 | tee "${TEE_TARGET}"
