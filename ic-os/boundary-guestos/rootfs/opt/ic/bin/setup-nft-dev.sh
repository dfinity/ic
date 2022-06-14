#!/bin/bash

set -ex

# This function adds extra rules to limit access if the provided domain is not ic0.app
function setup_dev_nftables() {

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "DOMAIN") DOMAIN="${value}" ;;
            "TLD") TLD="${value}" ;;
        esac
    done </boot/config/nginxdomain.conf

    if [[ -z "$DOMAIN" ]] || [[ -z "$TLD" ]]; then
        echo "\$DOMAIN or \$TLD variable not set. " 1>&2
        exit 1
    fi

    # We set a custom domain
    if [[ "$DOMAIN" != "ic0" ]] || [[ "$TLD" != "app" ]]; then
        # ... and do it in a production like setting (i.e. a staging network).
        if [[ $(cat /boot/config/deployment_type) != "dev" ]]; then
            cp -ra /etc/nftables/* /run/ic-node/etc/nftables
            mount --bind /run/ic-node/etc/nftables /etc/nftables
            pushd /etc/nftables
            mv ./ipv4-dev-ruleset.contents ./ipv4-dev.ruleset
            mv ./ipv6-dev-ruleset.contents ./ipv6-dev.ruleset
            popd
        fi
    fi
}

setup_dev_nftables
