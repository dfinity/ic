#!/usr/bin/bash
#
# Attest BNs reports and trigger the priv. key exchange later
# Originated from the BN-x, triggered on the leader.
# This is meant to handle a POST request from the BN-x
# who is sending its attestation report along with its public key.
# The hash of the public key will be also included in the report's
# user data.

set -e

LOGFILE=/var/www/cgi-bin/cgi.log
UPLOAD_DIR=/var/www/cgi-bin/artifacts
SEV_TOOL=/opt/ic/bin/sevtool
SEV_GUEST_TOOL=/opt/ic/bin/sev-guest-parse-report
SEV_GUEST_TOOL_GET=/opt/ic/bin/sev-guest-get-report

log() {
    echo "[$(date --rfc-3339='ns')] $@" >>${LOGFILE}
}

cgi_response() {
    local mimetype="text/html"
    local title=$1
    local heading=$2
    local body=$3

    echo "Content-type: ${mimetype}"
    echo
    echo "<HTML>"
    echo "<HEAD><TITLE>${title}</TITLE></HEAD>"
    echo "<BODY>"
    echo "<H1>${heading}</H1><HR>"
    echo "${body}"
    echo "</BODY></HTML>"
}

is_cert_chain_valid() {
    local work_dir=${1}
    ${SEV_TOOL} --ofolder ${work_dir} --validate_cert_chain_vcek \
        | grep "Command Successful" >/dev/null
}

is_report_valid() {
    local work_dir=${1}
    ${SEV_TOOL} --ofolder ${work_dir} --validate_guest_report \
        | grep "Command Successful" >/dev/null
}

is_measurement_valid() {
    local work_dir=${1}
    local meas=$(${SEV_GUEST_TOOL} ${dir}/guest_report.bin \
        | sed 'N;28q;d' | tr -d '[:space:]' >/dev/null 2>&1)
    local my_meas=$(${SEV_GUEST_TOOL} /boot/config/sev/guest_report_pem.bin \
        | sed 'N;28q;d' | tr -d '[:space:]' >/dev/null 2>&1)
    if [[ "${meas}" != "${my_meas}" ]]; then
        log "Measurement does not match the expected one(mine)."
        return -1
    fi
}

validate_pubkey() {
    local dir=$1
    local report_hash=$(${SEV_GUEST_TOOL} -d ${dir}/guest_report.bin \
        | sed -e '1d' -e '2{N}' -e 's/[ \n]*//g')
    local pubkey_hash=$(sha512sum ${dir}/bn_pub.key | cut -d ' ' -f1)

    # Check that the report hash matches the pubkey and that the
    # guest report and it's cert chain validate correctly
    is_report_valid ${dir} && is_cert_chain_valid ${dir} && [ "${report_hash}" == "${pubkey_hash}" ]
    # Verify the measurement
    is_measurement_valid ${dir}
}

# Encrypt the private key with the given public key of the BN
# and prepare a fresh report with the hash of the encrypted key.
# Place the relevant files in a directory named after the BN's IP.
encrypt_send() {
    local bn_pub=$1/bn_pub.key
    local BN_DIR=${UPLOAD_DIR}/${IP}
    local KEYFILE=${BN_DIR}/rand.key

    mkdir -p ${BN_DIR}
    pushd ${BN_DIR} >/dev/null
    # Generate a random key to encrypt the private key.
    # We need that, because bn_priv.key is too big for direct encryption
    dd if=/dev/random of="${KEYFILE}" bs=16 count=1 >/dev/null 2>&1
    openssl enc -e -aes-256-cbc -pbkdf2 -kfile ${KEYFILE} -in /boot/config/sev/bn_priv.key -out ${BN_DIR}/bn_priv.enc -nosalt -iv 0 >/dev/null 2>&1
    # Encrypt the random key with the BN's pub key
    openssl pkeyutl -in ${KEYFILE} -out ${BN_DIR}/rand.enc -pubin -inkey ${bn_pub} -encrypt >/dev/null 2>&1
    # Create a report with its hash
    ${SEV_GUEST_TOOL_GET} -x -f ${BN_DIR}/bn_priv.enc ${BN_DIR}/guest_report.bin >/dev/null 2>&1
    # Rename the .cert files to .pem
    for cert in *.cert; do
        mv ${cert} ${cert%.cert}.pem
    done
    tar -czvf ${BN_DIR}/report_lead.tar.gz -C ${BN_DIR} bn_priv.enc rand.enc guest_report.bin ark.pem ask.pem vcek.pem >/dev/null 2>&1
    curl --data-binary @${BN_DIR}/report_lead.tar.gz -H "Content-Type: application/octet-stream" http://${IP}/cgi-bin/bn-priv-send.sh >/dev/null 2>&1
    popd >/dev/null
}

main() {
    # Change to a safe temporary directory
    local work_dir=$(mktemp -d /tmp/XXXXXX)
    pushd ${work_dir} >/dev/null

    # Read the BN's IP to do the POST request later
    read -N 13 IP
    IP=${IP::-1}
    log "IP=$IP"

    # Extract the tarball provided in the POST operation
    # This will contain the public key and the report
    tar -zxf /dev/stdin
    if [ "$?" -ne "0" ]; then
        cgi_response "BN Response" "Result" "Upload failed."
        exit 1
    fi

    log "Report and public key received."
    mv ${work_dir}/guest_report_pem.bin ${work_dir}/guest_report.bin
    # Validate the guest report and its certificate chain
    if validate_pubkey ${work_dir}; then
        log "Guest report validated successfully!"
    else
        log "Validation failed!"
        cgi_response "Attestation Response" "Result" "Validation failed."
        exit 2
    fi

    encrypt_send ${work_dir}

    # Cleanup
    popd >/dev/null
    rm -rf ${work_dir}

    # Send the required CGI response message
    cgi_response "BN Response" "Result" "SUCCESS"
    exit 0
}

main $@
