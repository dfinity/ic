#!/bin/bash

# Minimum # of seconds to wait/batch beforce processing
readonly BUFFER_SECONDS=5
# Minimum # of seconds between reloads
readonly THROTTLE_SECONDS=30

readonly TMP_DIR=$(mktemp -d /tmp/ic_router_control_plane_watcher.sh.XXXXXX)
readonly ROUTES_DIR='/var/cache/ic_routes'
readonly IC_ROUTING='/var/opt/nginx/ic'
readonly TRUSTED_CERTS="${IC_ROUTING}/trusted_certs.pem"
readonly NGINX_TABLE="${IC_ROUTING}/nginx_table.conf"
readonly IC_ROUTER_TABLE="${IC_ROUTING}/ic_router_table.js"

function reload_job() {
    # Reload jobs can be in one of two states, QUEUED or ACTIVE
    # A QUEUED job holds the RELOAD_JOB_QUEUED lock until it can become ACTIVE
    # An ACTIVE job holds the RELOAD_JOB lock until it has completed the reload
    # and slept for THROTTLE_SECONDS
    local -r RELOAD_JOB_QUEUED=$1
    local RELOAD_JOB
    exec {RELOAD_JOB}<>"${TMP_DIR}/RELOAD_JOB"

    echo "Queued for reloading..."
    # Always sleep a little (flush doesn't always mean the data is there).
    #
    # Also sleep so reload requests which come in rapid succession can be
    # batched
    sleep ${BUFFER_SECONDS}
    flock ${RELOAD_JOB}
    flock --unlock ${RELOAD_JOB_QUEUED}

    echo "Reloading..."
    python3 ic_router_control_plane.py "${ROUTES_DIR}" "${NGINX_TABLE}" "${IC_ROUTER_TABLE}" "${TRUSTED_CERTS}" --generate_upstream_declarations=True --deny_node_socket_addrs=
    service nginx reload

    # Continue holding the lock to prevent any other jobs from reloading
    echo "Waiting for ${THROTTLE_SECONDS} to signal completion..."
    sleep ${THROTTLE_SECONDS}
    echo "Complete."
}

function try_enqueue_reload() {
    local RELOAD_JOB_QUEUED
    exec {RELOAD_JOB_QUEUED}<>"${TMP_DIR}/RELOAD_JOB_QUEUED"

    # If the job is still queued, then just skip
    if ! flock --nonblock ${RELOAD_JOB_QUEUED}; then
        echo 'reload job is still queued, skipping'
        return
    fi
    # Pass the lock to the job
    reload_job ${RELOAD_JOB_QUEUED} &
}

mkdir -p "${ROUTES_DIR}"
try_enqueue_reload
inotifywait -q -m -e modify -e create -e close_write --format "%w%f %e" "${ROUTES_DIR}" \
    | while read -r FILE_PATH ACTION; do
        echo "${FILE_PATH} changed (${ACTION})"
        try_enqueue_reload
    done
