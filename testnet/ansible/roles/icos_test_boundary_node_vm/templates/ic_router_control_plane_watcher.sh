#!/bin/bash

python3 ic_router_control_plane.py /etc/nginx/ic_routes/ nginx_table.conf ic_router_table.js trusted_certs.pem --generate_upstream_declarations={{ generate_upstream_declarations }} --deny_node_socket_addrs={{ deny_node_socket_addrs }}
inotifywait -q -m -e modify -e create -e close_write --format "%w%f" /etc/nginx/ic_routes \
    | while read -r path; do
        echo $path changed
        sleep 1
        python3 ic_router_control_plane.py /etc/nginx/ic_routes/ nginx_table.conf ic_router_table.js trusted_certs.pem --generate_upstream_declarations={{ generate_upstream_declarations }} --deny_node_socket_addrs={{ deny_node_socket_addrs }}
        service nginx reload
    done
