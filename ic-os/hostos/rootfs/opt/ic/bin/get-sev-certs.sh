#!/bin/bash

set -e

# Set up SEV-SNP certificates.

# Use the system installed version or the one from the environment if that is not available
VCEKURL="/opt/ic/bin/vcekurl"
if [[ ! -e "${VCEKURL}" ]]; then
    VCEKURL=vcekurl
fi

# Use supplied target location or '.' if that is not available
if [ $# -eq 0 ]; then
    DIR=.
else
    DIR="$1"
fi

if [[ -e /dev/sev ]]; then
    # Get ark.pem and ask.pem, and convert ask.pem to ask.dir
    wget -O "${DIR}/cert_chain.pem" "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"
    csplit -z -f "${DIR}/cert-chain-" "${DIR}/cert_chain.pem" '/-----BEGIN CERTIFICATE-----/' '{*}'
    mv "${DIR}/cert-chain-00" "${DIR}/ask.pem"
    mv "${DIR}/cert-chain-01" "${DIR}/ark.pem"
    openssl x509 -in "${DIR}/ark.pem" -inform PEM -out "${DIR}/ark.der" -outform DER
    # Get vcek.der and convert to vcek.pem
    vcek_url=$("${VCEKURL}")
    wget -O "${DIR}/vcek.der" "${vcek_url}"
    openssl x509 -in "${DIR}/vcek.der" -inform DER -out "${DIR}/vcek.pem" -outform PEM
else
    echo "/dev/sev not available, exiting..."
    exit 1
fi
