#!/bin/bash

readonly ROUTES_DIR='/var/cache/ic_routes'
readonly IC_ROUTING='/var/opt/nginx/ic'
readonly TRUSTED_CERTS="${IC_ROUTING}/trusted_certs.pem"
readonly NGINX_TABLE="${IC_ROUTING}/nginx_table.conf"
readonly IC_ROUTER_TABLE="${IC_ROUTING}/ic_router_table.js"

function rewrite() {
    python3 ic_router_control_plane.py "${ROUTES_DIR}" "${NGINX_TABLE}" "${IC_ROUTER_TABLE}" "${TRUSTED_CERTS}" --generate_upstream_declarations=True --deny_node_socket_addrs=
    service nginx reload
}

mkdir -p "${ROUTES_DIR}"
rewrite
inotifywait -q -m -e modify -e create -e close_write --format "%w%f" "${ROUTES_DIR}" \
    | while read -r path; do
        echo "${path} changed"
        sleep 1
        rewrite
    done
