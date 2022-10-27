#!/usr/bin/bash
#
# Originated from SM, triggered on the BN-x
# This is meant to handle a POST request from the SM
# that is sending the SSL certs along with the IP
# of the chosen leader --BN-0
set -e

LOGFILE=/var/www/cgi-bin/cgi.log
UPLOAD_DIR=/var/www/cgi-bin/artifacts

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

# Check if the IP matches the one that BN has to verify if it's the leader.
# If no, then it should do a POST request to the leader
# with a tarball containing its report and its public key.
act_upon() {
    my_IP=$(ip -brief -family inet address show scope global | grep -w UP | grep -o -m1 "[0-9]*\.[0-9*\.[0-9]*\.[0-9]*")
    if [ ${my_IP} != $IP ]; then
        log "Sending report tarball to BN-0 to get attested."
        curl -d "${my_IP}" --data-binary @/var/www/html/report_pem.tar.gz -H "Content-Type: application/octet-stream" http://${IP}/cgi-bin/bn-attest.sh >/dev/null 2>&1
    fi
}

main() {
    # Change to a safe temporary directory
    local work_dir=$(mktemp -d /tmp/XXXXXX)
    pushd ${work_dir} >/dev/null

    # Read the leader's IP
    read -N 13 IP
    IP=${IP::-1}

    # Extract the tarball provided in the POST operation containing the cert files
    tar -zxf /dev/stdin
    if [ "$?" -ne "0" ]; then
        cgi_response "BN Response" "Result" "Upload failed."
        exit 1
    fi

    log "SSL certificates received. Ready to copy them in user's directory"
    # incron job will install them in the right directory later
    cp ./* ${UPLOAD_DIR}/certs >/dev/null

    # Trigger a POST request if the BN is not the leader
    act_upon

    # Cleanup
    popd >/dev/null
    rm -rf ${work_dir}

    # Send the required CGI response message
    cgi_response "BN Response" "Result" "SUCCESS"
    exit 0
}

main $@
