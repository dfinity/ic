#!/bin/bash

# Shared logging utilities.

# Writes a log message to both stdout (if running in a terminal) and the system log.
#
# Args:
#   message: The message to be logged.
write_log() {
    local message=$1

    if [ -t 1 ]; then
        echo "${SCRIPT} ${message}" >/dev/stdout
    fi

    logger -t "${SCRIPT}" "${message}"
}
