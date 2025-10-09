#!/usr/bin/env bash

# Redirects script output to multiple targets for real-time monitoring and logging across different environments.
# Necessary for logs to be visible in nested environment.

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <tee-target1> [tee-target2] <script> [script-args]"
    exit 1
fi

if [ $# -ge 2 ]; then
    # Check if second argument is a terminal device
    if [[ "$2" =~ ^/dev/tty ]]; then
        # Two targets: <target1> <target2> <script> [args...]
        TEE_TARGETS="$1 $2"
        SCRIPT_ARGS=("${@:3}")
    else
        # Single target: <target> <script> [args...]
        TEE_TARGETS="$1"
        SCRIPT_ARGS=("${@:2}")
    fi
else
    echo "Error: Invalid number of arguments"
    exit 1
fi

# Run the script and capture its exit code separately from tee
"${SCRIPT_ARGS[@]}" 2>&1 | tee ${TEE_TARGETS}
SCRIPT_EXIT_CODE=${PIPESTATUS[0]}

exit $SCRIPT_EXIT_CODE
