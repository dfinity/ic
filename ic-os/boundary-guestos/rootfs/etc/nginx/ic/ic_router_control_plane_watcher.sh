#!/bin/bash

ROUTES_DIR=/var/cache/ic_routes
mkdir -p "$ROUTES_DIR"
python3 ic_router_control_plane.py "$ROUTES_DIR" nginx_table.conf ic_router_table.js trusted_certs.pem --generate_upstream_declarations=True --deny_node_socket_addrs=
inotifywait -q -m -e modify -e create -e close_write --format "%w%f" "$ROUTES_DIR" \
    | while read -r path; do
        echo $path changed
        sleep 1
        python3 ic_router_control_plane.py "$ROUTES_DIR" nginx_table.conf ic_router_table.js trusted_certs.pem --generate_upstream_declarations=True --deny_node_socket_addrs=
        service nginx reload
    done
