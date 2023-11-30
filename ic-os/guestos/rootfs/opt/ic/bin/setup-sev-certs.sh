#!/bin/bash

set -e

if [[ -e "/dev/sev-guest" ]]; then
    if [[ -f "/boot/config/vcek.pem" ]]; then
        # For prod we expect that the host will generate the ask and vcek certs and pass in via the config.
        # We do this to avoid dependence on AMD server.
        # Also ARK endpoint is rate limited.
        # If certs are not provided via config, they will be fetched when required (i.e during p2p tls handshake)
        if ! cmp -s "/boot/config/ark.pem" "/opt/ic/share/ark.pem"; then
            echo "/boot/config/ark.pem does not match /opt/ic/share/ark.pem"
        fi
        for f in ask.pem vcek.pem; do
            cp "/boot/config/${f}" "/var/lib/ic/data/${f}"
        done
    fi

    # Always use our hard coded ark.pem as the root of trust.
    cp "/opt/ic/share/ark.pem" "/var/lib/ic/data/ark.pem"
fi
