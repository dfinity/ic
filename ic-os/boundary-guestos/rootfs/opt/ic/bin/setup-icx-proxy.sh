#!/bin/bash

set -ex

WLOC_ICX_PROXY="/run/ic-node/etc/default/icx-proxy"

# Move active configuration and prepare it for updates
if [ "$(cat /boot/config/deployment_type)" == "dev" ]; then
    cp -a /etc/default/icx-proxy.test "$WLOC_ICX_PROXY"
else
    cp -a /etc/default/icx-proxy "$WLOC_ICX_PROXY"
fi

if [ ! -f "/boot/config/nginxdomain.conf" ]; then
    echo "nginxdomain.conf is not provided. icx-proxy won't be configured. " 1>&2
    exit 1
fi

# Read limited set of keys. Be extra-careful quoting values as it could
# otherwise lead to executing arbitrary shell code!
while IFS="=" read -r key value; do
    case "${key}" in
        "DOMAIN") DOMAIN="${value}" ;;
        "TLD") TLD="${value}" ;;
    esac
done </boot/config/nginxdomain.conf

if [[ -z "$DOMAIN" ]] || [[ -z "$TLD" ]]; then
    echo "\$DOMAIN or \$TLD variable not set. icx-proxy won't be configured. " 1>&2
    exit 1
fi

sed -i -e "s/{{DOMAIN}}/${DOMAIN}/g" -e "s/{{TLD}}/${TLD}/g" "$WLOC_ICX_PROXY"

mount --bind "$WLOC_ICX_PROXY" /etc/default/icx-proxy
