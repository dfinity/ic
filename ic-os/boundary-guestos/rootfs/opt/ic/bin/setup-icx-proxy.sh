#!/bin/bash

set -ex

function setup_domain_name() {
    source /boot/config/nginxdomain.conf
    if [[ -z "$DOMAIN" ]] || [[ -z "$TLD" ]]; then
        echo "\$DOMAIN or \$TLD variable not set. icx-proxy won't be configured. " 1>&2
        exit 1
    fi
    pushd /etc/default
    for filename in ./icx-proxy; do
        sed -i -e "s/{{DOMAIN}}/${DOMAIN}/g" -e "s/{{TLD}}/${TLD}/g" ${filename}
    done
    popd
}

function enable_dev_mode() {
    # The boundary node image is built in prod configuration. Any changes need
    # to enable development mode at runtime should go in here.
    if [ $(cat /boot/config/deployment_type) == "dev" ]; then
        pushd /etc/default
        mv ./icx-proxy ./icx-proxy.disabled
        mv ./icx-proxy.test ./icx-proxy
        popd
    fi
}

enable_dev_mode
setup_domain_name
