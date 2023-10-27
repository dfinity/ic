#!/bin/bash

set -e

if [[ -e "/dev/sev-guest" ]]; then
    # Set permissions for sev-guest device
    # TODO: This should move to guest_launch tool
    chmod 777 /dev/sev-guest
    if [[ -f "/boot/config/vcek.pem" ]]; then
        # For prod we expect that the host will generate the ask and vcek certs and pass in via the config.
        if ! cmp -s "/boot/config/ark.pem" "/opt/ic/share/ark.pem"; then
            echo "/boot/config/ark.pem does not match /opt/ic/share/ark.pem"
        fi
        # Always use our hard coded ark.pem as the root of trust.
        cp "/opt/ic/share/ark.pem" "/run/ic-node/config/ark.pem"
        for f in ask.pem vcek.pem; do
            cp "/boot/config/${f}" "/run/ic-node/config/${f}"
        done
    else
        # For test/farm we expect that the host will store the PEM files via SNP_GET_EXT_REPORT because the
        # config may be generated on a machine other than the host.
        (
            cd /run/ic-node/config
            /opt/ic/bin/snptool get-certs
        )
        if [[ -f "/run/ic-node/config/ask.cert" && -f "/run/ic-node/config/vcek.cert" ]]; then
            # Always use our hard coded ask.pem as the root of trust.
            cp "/opt/ic/share/ark.pem" "/run/ic-node/config/ark.pem"
            for f in ask vcek; do
                # We are storing the PEM files instead of the DER files on the host.
                mv "/run/ic-node/conifg/${f}.cert" "/run/ic-node/config/${f}.pem"
            done
        fi
    fi
fi
