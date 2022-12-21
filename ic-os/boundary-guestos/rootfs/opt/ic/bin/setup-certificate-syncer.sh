#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'
source '/opt/ic/bin/exec_condition.shlib'

readonly IDENTITY_PEM="${BOOT_DIR}/certificate_issuer_identity.pem"

function main() {
    if [ ! -f "${IDENTITY_PEM}" ]; then
        echo "missing certificate-issuer identity: ${IDENTITY_PEM}, disabling certificate-syncer"
        disable
        return
    fi
}

main "$@"
