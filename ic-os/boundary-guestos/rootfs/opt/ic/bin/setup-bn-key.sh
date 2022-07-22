#!/bin/bash

set -ex

TOOL=/opt/ic/bin/sev-guest-get-report
DIR=/boot/config/sev
HTML_DIR=/var/www/html

if [ -e /dev/sev-guest ]; then
    # sev-snp enabled
    if [[ ! -e "${DIR}/BN.csr" ]]; then
        # first boot
        mkdir -p ${DIR}
        pushd ${DIR}

        # Create a key pair for the BN and a CSR according to the domain info
        openssl req -out ${DIR}/BN.csr -new -newkey rsa:2048 -nodes -keyout ${DIR}/bn_priv.key -config /etc/csr.conf
        openssl rsa -in ${DIR}/bn_priv.key -pubout >${DIR}/bn_pub.key

        # Create a pair of reports with a hash of the public key and the csr respectively
        ${TOOL} -x -f ${DIR}/BN.csr ${DIR}/guest_report_csr.bin
        ${TOOL} -x -f ${DIR}/bn_pub.key ${DIR}/guest_report_pem.bin

        # Rename the .cert files to .pem because of sevtool
        for cert in *.cert; do
            mv ${cert} ${cert%.cert}.pem
        done

        # Create the corresponding tarballs for the nginx to deliver
        tar -czvf ${HTML_DIR}/report_pem.tar.gz -C ${DIR} bn_pub.key guest_report_pem.bin vcek.pem ark.pem ask.pem
        tar -czvf ${HTML_DIR}/report_csr.tar.gz -C ${DIR} BN.csr guest_report_csr.bin vcek.pem ark.pem ask.pem

        popd

    fi
fi
