#!/usr/bin/env bash

# Redirects script output to both the local tty and serial console for real-time monitoring and logging across different environments.
# Necessary for logs to be visible in nested environment.

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

# Run the script and capture its exit code separately from tee
"${SCRIPT_ARGS[@]}" 2>&1 | tee "${TEE_TARGET}"
SCRIPT_EXIT_CODE=${PIPESTATUS[0]}

exit $SCRIPT_EXIT_CODE
