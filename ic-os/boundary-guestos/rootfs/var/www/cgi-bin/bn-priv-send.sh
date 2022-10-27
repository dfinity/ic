#!/usr/bin/bash
#
# Leader's priv. key exchange
# Request originated from the leader BN, triggered on the BN-x.
# This is meant to handle a POST request from the leader BN
# who is sending its attestation report along with its encrypted
# private key. The hash of the encrypted private key will be also
# included in the report's user data. The encryption is performed
# with a random symmetric key. The symmetric key is encrypted with
# BN's public key.

set -e

LOGFILE=/var/www/cgi-bin/cgi.log
UPLOAD_DIR=/var/www/cgi-bin/artifacts
SEV_TOOL=/opt/ic/bin/sevtool
SEV_GUEST_TOOL=/opt/ic/bin/sev-guest-parse-report

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

validate_privkey() {
    local dir=$1
    local report_hash=$(${SEV_GUEST_TOOL} -d ${dir}/guest_report.bin \
        | sed -e '1d' -e '2{N}' -e 's/[ \n]*//g')
    local privkey_hash=$(sha512sum ${dir}/bn_priv.enc | cut -d ' ' -f1)

    # Check that the report hash matches the pubkey and that the
    # guest report and it's cert chain validate correctly
    is_report_valid ${dir} && is_cert_chain_valid ${dir} && [ "${report_hash}" == "${privkey_hash}" ]
    # Verify the measurement
    is_measurement_valid ${dir}
}

validate_ssl_chain() {
    val1=$(openssl x509 -noout -modulus -in ${UPLOAD_DIR}/0001_cert.pem | openssl md5)
    val2=$(openssl rsa -noout -modulus -in ${UPLOAD_DIR}/bn_priv.key | openssl md5)
    if [ val1 == val2 ]; then
        log "Successful validation."
    else
        log "SSL certificate does not match private key."
    fi
}

install_priv() {
    local dir=$1
    openssl pkeyutl -in ${dir}/rand.enc -out ${dir}/rand -inkey /boot/config/sev/bn_priv.key -decrypt >/dev/null 2>&1
    openssl enc -d -aes-256-cbc -pbkdf2 -kfile ${dir}/rand -in ${dir}/bn_priv.enc -out ${dir}/bn_priv.key -nosalt -iv 0 >/dev/null 2>&1
    # incron job will install it in the right directory later
    cp ${dir}/bn_priv.key ${UPLOAD_DIR}
    #validate_ssl_chain
}

main() {
    # Change to a safe temporary directory
    local work_dir=$(mktemp -d /tmp/XXXXXX)
    pushd ${work_dir} >/dev/null

    # Extract the tarball provided in the POST operation
    # This will contain the encrypted private key and the report
    # which will have the latter one as user-data.
    tar -zxf /dev/stdin
    if [ "$?" -ne "0" ]; then
        cgi_response "BN Response" "Result" "Upload failed."
        exit 1
    fi

    log "Report and encrypted private key received."

    # Validate the guest report and its certificate chain
    if validate_privkey ${work_dir}; then
        log "Leader's report validated successfully!"
    else
        log "Validation failed!"
        cgi_response "Attestation Response" "Result" "Validation failed."
        exit 2
    fi

    install_priv ${work_dir}

    # Cleanup
    popd >/dev/null
    rm -rf ${work_dir}

    # Send the required CGI response message
    cgi_response "BN Response" "Result" "SUCCESS"
    exit 0
}

main $@
