#!/bin/bash

set -e

# Utils for working with the HSM on HostOS

SCRIPT="$(basename $0)[$$]"
METRICS_DIR="/run/node_exporter/collector_textfile"

# Default arguments if undefined
CHECK=0
FETCH=0
SAVE=0

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -c | --check)
            CHECK=1
            ;;
        -d=* | --dir=*)
            CONFIG_DIR="${argument#*=}"
            shift
            ;;
        -f | --fetch)
            FETCH=1
            ;;
        -h | --help)
            echo 'Usage:
Fetch Management MAC Address

Arguments:
  -c, --check           check if an HSM is present
  -d=, --dir=           specify the config partition directory (Default: /boot/config)
  -f, --fetch           fetch the fingerprint of the stored HSM public key
  -h, --help            show this help message and exit
  -s, --save            save the HSM public key as PEM file on the config partition
'
            exit 1
            ;;
        -s | --save)
            SAVE=1
            ;;
        *)
            echo "Error: Argument is not supported."
            exit 1
            ;;
    esac
done

# Set arguments if undefined
CONFIG_DIR="${CONFIG_DIR:=/boot/config}"

write_log() {
    local message=$1

    if [ -t 1 ]; then
        echo "${SCRIPT} ${message}" >/dev/stdout
    fi

    logger -t ${SCRIPT} "${message}"
}

write_metric() {
    local name=$1
    local value=$2
    local help=$3
    local type=$4

    echo -e "# HELP ${name} ${help}\n# TYPE ${type}\n${name} ${value}" >"${METRICS_DIR}/${name}.prom"
}

# Check if the HSM is plugged in
function check_hsm() {
    retry=0
    if [ "$(lsusb | grep -E 'Nitro|Clay')" ]; then
        write_log "Nitrokey HSM USB device detected."
    else
        write_log "Nitrokey HSM USB device could not be detected."
        exit 1
    fi
}

# Fetch the HSM public key fingerprint
function fetch_hsm_fingerprint() {
    if [ -r "${CONFIG_DIR}/hsm.pem" ]; then
        PUBKEY=$(cat "${CONFIG_DIR}/hsm.pem" | sha256sum | cut -d " " -f 1)
        echo "${PUBKEY}"
        write_log "Using HSM public key fingerprint: ${PUBKEY}"
    else
        write_log "ERROR: Unable to read HSM public key file: ${CONFIG_DIR}/hsm.pem"
        exit 1
    fi
}

# Extract the HSM public key file and store it as PEM formatted file on the
# config partition
function save_hsm_key() {
    TMPDIR=$(mktemp -d)
    pkcs11-tool --read-object --type pubkey --id 01 --output-file "${TMPDIR}"/hsm.der >/dev/null 2>&1
    openssl ec -pubin -inform DER -outform PEM -in "${TMPDIR}"/hsm.der -out ${CONFIG_DIR}/hsm.pem >/dev/null 2>&1
    rm -rf "${TMPDIR}"
    write_log "Saving HSM public key on config partition."
}

function main() {
    # Establish run order
    if [ ${CHECK} -eq 1 ]; then
        check_hsm
    elif [ ${FETCH} -eq 1 ]; then
        fetch_hsm_fingerprint
    elif [ ${SAVE} -eq 1 ]; then
        save_hsm_key
    else
        $0 --help
    fi
}

main
