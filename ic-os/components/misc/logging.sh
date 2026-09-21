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

sanitize_output() {
    LC_ALL=C sed --unbuffered \
        -e 's|\x1b\[[0-?]*[ -/]*[@-~]||g' \
        -e 's|\x1b[]P_^][^\x1b\x07]*\(\x07\|\x1b\\\)\?||g' \
        -e 's|\x1b[ -/]*[0-~]||g' \
        | LC_ALL=C tr -cd '\011\012\040-\176'
}
