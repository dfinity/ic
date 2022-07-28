#!/bin/bash

set -e

UPLOAD_DIR=/var/www/cgi-bin/artifacts
NGINX_DIR=/run/ic-node/etc/nginx

if [ "$1" = "certs" ]; then
    # Copy the new certificates in the right folder
    cp -r ${UPLOAD_DIR}/certs/* ${NGINX_DIR}/certs/
elif [ "$1" = "key" ]; then
    # Move the private key in the right folder
    mv ${UPLOAD_DIR}/bn_priv.key ${NGINX_DIR}/keys/bn_privkey.pem
fi
