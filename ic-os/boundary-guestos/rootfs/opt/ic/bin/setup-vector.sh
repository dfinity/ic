#!/bin/bash

set -ex

WLOC_VECTOR="/run/ic-node/etc/default/vector"

# Move active configuration and prepare it for updates
cp -a /etc/default/vector "$WLOC_VECTOR"

ELASTICSEARCH_URL="https://elasticsearch.testnet.dfinity.systems"
if [ -f "/boot/config/vector.conf" ]; then
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "ELASTICSEARCH_URL") ELASTICSEARCH_URL="${value}" ;;
        esac
    done </boot/config/vector.conf
fi

if [[ -z "$ELASTICSEARCH_URL" ]]; then
    echo "\$ELASTICSEARCH_URL variable not set. vector won't be configured. " 1>&2
    exit 1
fi

sed -i -e "s/{{ELASTICSEARCH_URL}}/${ELASTICSEARCH_URL}/g" "$WLOC_VECTOR"

mount --bind "$WLOC_VECTOR" /etc/default/vector
