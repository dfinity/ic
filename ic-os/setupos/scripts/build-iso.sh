#!/usr/bin/env bash

# Build Ubuntu Server based ISO image containing setup files

# Build Requirements:
# - Operating System: Ubuntu 20.04
# - Packages: ca-certificates, curl, git, isolinux, p7zip-full, syslinux, xorriso
# - Connectivity: 443/tcp outbound

set -o errexit
set -o pipefail
# NOTE: Validating inputs manually
#set -o nounset

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

BASE_DIR="$(dirname "${BASH_SOURCE[0]}")/.."
TMP_DIR="$(mktemp -d)"
ISO_DIR="${TMP_DIR}/iso"

UBUNTU_VERSION="20.04.4"
UBUNTU_ISO="ubuntu-${UBUNTU_VERSION}-live-server-amd64.iso"
UBUNTU_URL="https://releases.ubuntu.com/${UBUNTU_VERSION}/${UBUNTU_ISO}"
UBUNTU_CHECKSUM="28ccdb56450e643bad03bb7bcf7507ce3d8d90e8bf09e38f6bd9ac298a98eaad"

EFIBOOTMGR_URL="http://archive.ubuntu.com/ubuntu/pool/main/e/efibootmgr/efibootmgr_17-1_amd64.deb"
EFIBOOTMGR_CHECKSUM="0da33e43c97e5505d4d54e4145a72e76ce72278c3a9488792da86d9f30709d73"

JQ_URL="http://archive.ubuntu.com/ubuntu/pool/universe/j/jq/jq_1.6-1ubuntu0.20.04.1_amd64.deb"
JQ_CHECKSUM="8e4c8223f6ec158dc6c2a0d065b76c337bb7664e35cbbecd2ad02142d3b83470"

LIBJQ1_URL="http://archive.ubuntu.com/ubuntu/pool/universe/j/jq/libjq1_1.6-1ubuntu0.20.04.1_amd64.deb"
LIBJQ1_CHECKSUM="5aafb335442d3a694b28204e390c831de9efc3f3a18245328840d406edc8a163"

LIBONIG5_URL="http://archive.ubuntu.com/ubuntu/pool/universe/libo/libonig/libonig5_6.9.4-1_amd64.deb"
LIBONIG5_CHECKSUM="041f5fb2dc781fcd1bcdc5a4115108a3ecca770c1cab69d5f25aafffe7842cf5"

# Fixed timestamp for reproducible build
TOUCH_TIMESTAMP="200901031815.05"
XORRISO_TIMESTAMP="2009010318150500"
export SOURCE_DATE_EPOCH="1231006505"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -c=* | --config=*)
            CONFIG="${argument#*=}"
            shift
            ;;
        -d=* | --deployment=*)
            DEPLOYMENT="${argument#*=}"
            shift
            ;;
        -h | --help)
            echo 'Usage:
SetupOS Builder

Arguments:
  -c=, --config=        specify the config.json configuration file (Default: ./src/nocloud/config.json)
  -d=, --deployment=    specify the deployment name (Default: mainnet)
  --host-os=            specify the HostOS disk-image file (Default: ./src/nocloud/host-os.img.tar.gz)
  --host-ssh=           specify a folder containing the accounts SSH public keys (Example: ./ssh_authorized_keys)
                        the folder is expected to contain files named after the built-in accounts (admin, backup, readonly)
  --guest-os=           specify the GuestOS disk-image file (Default: ./src/nocloud/guest-os.img.tar.gz)
  --guest-ssh=          specify a folder containing the accounts SSH public keys (Example: ./ssh_authorized_keys)
                        the folder is expected to contain files named after the built-in accounts (admin, backup, readonly)
  -h, --help            show this help message and exit
  -k=, --key=           specify the NNS public key (Default: ./src/nocloud/nns_public_key.pem)
  -l=, --logging=       specify the logging hosts/destination (Default: telemetry01.mainnet.dfinity.network telemetry02.mainnet.dfinity.network telemetry03.mainnet.dfinity.network)
  -n=, --nns-url=       specify the NNS URL for the GuestOS (Default: <http://[mainnet]:8080>)
  -o=, --output=        ISO output directory (Default: ./build-out/)
  -u=, --ubuntu=        specify a folder containing the Ubuntu Live Server ISO image (Example: ./ubuntu/)
  --memory=             specify the amount of memory in GiB (Gibibytes) for the GuestOS (Default: 490)
'
            exit 1
            ;;
        --host-os=*)
            HOST_OS="${argument#*=}"
            shift
            ;;
        --host-ssh=*)
            HOST_SSH="${argument#*=}"
            shift
            ;;
        --guest-os=*)
            GUEST_OS="${argument#*=}"
            shift
            ;;
        --guest-ssh=*)
            GUEST_SSH="${argument#*=}"
            shift
            ;;
        -k=* | --key=*)
            KEY="${argument#*=}"
            shift
            ;;
        -l=* | --logging=*)
            LOGGING="${argument#*=}"
            shift
            ;;
        -n=* | --nns-url=*)
            NNS_URL="${argument#*=}"
            shift
            ;;
        -o=* | --output=*)
            OUTPUT="${argument#*=}"
            shift
            ;;
        -u=* | --ubuntu=*)
            UBUNTU="${argument#*=}"
            shift
            ;;
        --memory=*)
            MEMORY="${argument#*=}"
            shift
            ;;
        *)
            echo "Error: Argument is not supported: ${argument#*=}"
            exit 1
            ;;
    esac
done

# Set arguments if undefined
CONFIG="${CONFIG:=${BASE_DIR}/src/nocloud/config.json}"
DEPLOYMENT="${DEPLOYMENT:=mainnet}"
HOST_OS="${HOST_OS:=${BASE_DIR}/src/nocloud/host-os.img.tar.gz}"
GUEST_OS="${GUEST_OS:=${BASE_DIR}/src/nocloud/guest-os.img.tar.gz}"
KEY="${KEY:=${BASE_DIR}/src/nocloud/nns_public_key.pem}"
LOGGING="${LOGGING:=elasticsearch-node-0.mercury.dfinity.systems:443 elasticsearch-node-1.mercury.dfinity.systems:443 elasticsearch-node-2.mercury.dfinity.systems:443 elasticsearch-node-3.mercury.dfinity.systems:443}"
MEMORY="${MEMORY:=490}"
NNS_URL="${NNS_URL:=http://[2600:c02:b002:15:5000:ceff:fecc:d5cd]:8080,http://[2604:3fc0:3002:0:5000:6bff:feb9:6baf]:8080,http://[2a00:fb01:400:100:5000:5bff:fe6b:75c6]:8080,http://[2604:3fc0:2001:0:5000:b0ff:fe7b:ff55]:8080,http://[2600:3000:6100:200:5000:cbff:fe4b:b207]:8080,http://[2604:3fc0:3002:0:5000:4eff:fec2:4806]:8080,http://[2001:920:401a:1708:5000:5fff:fec1:9ddb]:8080,http://[2001:920:401a:1706:5000:87ff:fe11:a9a0]:8080,http://[2401:3f00:1000:24:5000:deff:fed6:1d7]:8080,http://[2a00:fb01:400:100:5000:61ff:fe2c:14ac]:8080,http://[2a04:9dc0:0:108:5000:ccff:feb7:c03b]:8080,http://[2600:c02:b002:15:5000:53ff:fef7:d3c0]:8080,http://[2401:3f00:1000:22:5000:c3ff:fe44:36f4]:8080,http://[2607:f1d0:10:1:5000:a7ff:fe91:44e]:8080,http://[2a04:9dc0:0:108:5000:96ff:fe4a:be10]:8080,http://[2604:7e00:50:0:5000:20ff:fea7:efee]:8080,http://[2600:3004:1200:1200:5000:59ff:fe54:4c4b]:8080,http://[2a0f:cd00:2:1:5000:3fff:fe36:cab8]:8080,http://[2401:3f00:1000:23:5000:80ff:fe84:91ad]:8080,http://[2607:f758:c300:0:5000:72ff:fe35:3797]:8080,http://[2607:f758:1220:0:5000:12ff:fe0c:8a57]:8080,http://[2a01:138:900a:0:5000:2aff:fef4:c47e]:8080,http://[2a0f:cd00:2:1:5000:87ff:fe58:ceba]:8080,http://[2401:3f00:1000:24:5000:86ff:fea6:9bb5]:8080,http://[2600:2c01:21:0:5000:27ff:fe23:4839]:8080,http://[2a04:9dc0:0:108:5000:7cff:fece:97d]:8080,http://[2001:920:401a:1708:5000:4fff:fe92:48f1]:8080,http://[2604:3fc0:3002:0:5000:acff:fe31:12e8]:8080,http://[2a04:9dc0:0:108:5000:6bff:fe08:5f57]:8080,http://[2607:f758:c300:0:5000:3eff:fe6d:af08]:8080,http://[2607:f758:1220:0:5000:bfff:feb9:6794]:8080,http://[2607:f758:c300:0:5000:8eff:fe8b:d68]:8080,http://[2607:f758:1220:0:5000:3aff:fe16:7aec]:8080,http://[2a00:fb01:400:100:5000:ceff:fea2:bb0]:8080,http://[2a00:fa0:3:0:5000:5aff:fe89:b5fc]:8080,http://[2a00:fa0:3:0:5000:68ff:fece:922e]:8080,http://[2600:3000:6100:200:5000:c4ff:fe43:3d8a]:8080,http://[2001:920:401a:1710:5000:d7ff:fe6f:fde7]:8080,http://[2a01:138:900a:0:5000:5aff:fece:cf05]:8080,http://[2600:3006:1400:1500:5000:20ff:fe3f:3c98]:8080}"
OUTPUT="${OUTPUT:=${BASE_DIR}/build-out}"

function validate_input() {
    local variable="${1}"
    local message="${2}"

    if [ -z ${variable} ]; then
        echo "Missing Argument:"
        echo "  ${message}"
        exit 1
    fi
}

function log_and_exit_on_error() {
    local exit_code="${1}"
    local log_message="${2}"

    if [ "${exit_code}" -ne 0 ]; then
        echo "${log_message}"
        exit "${exit_code}"
    fi
}

function log_start() {
    TIME_START=$(date '+%s')

    echo "SetupOS Builder - Start"
    log_and_exit_on_error "${?}" "Unable to start SetupOS builder."
}

function validate_guest_os() {
    echo "* Validating GuestOS disk-image..."
    if [ ! -r "${GUEST_OS}" ]; then
        log_and_exit_on_error "1" "Unable to find or read GuestOS disk-image."
    fi
}

function validate_host_os() {
    echo "* Validating HostOS disk-image..."
    if [ ! -r "${HOST_OS}" ]; then
        log_and_exit_on_error "1" "Unable to find or read HostOS disk-image."
    fi
}

function validate_ubuntu_path() {
    if [ -z "${UBUNTU}" ]; then
        echo "* No Ubuntu Live Server ISO image specified."
        UBUNTU_ISO_PATH="${TMP_DIR}"
    else
        echo "* Existing Ubuntu Live Server ISO image specified: ${UBUNTU}"
        UBUNTU_ISO_PATH="${UBUNTU}"
    fi
}

function prepare_build_directories() {
    if [ ! -d "${OUTPUT}" ]; then
        echo "* Creating build directories..."
        mkdir -p "${OUTPUT}"
    fi
}

function download_ubuntu_packages() {
    echo "* Downloading Ubuntu packages..."

    curl --output "${TMP_DIR}/efibootmgr.deb" --location "${EFIBOOTMGR_URL}"
    curl --output "${TMP_DIR}/libonig5.deb" --location "${LIBONIG5_URL}"
    curl --output "${TMP_DIR}/libjq1.deb" --location "${LIBJQ1_URL}"
    curl --output "${TMP_DIR}/jq.deb" --location "${JQ_URL}"
}

function verify_ubuntu_packages() {
    echo "* Verifying checksum of Ubuntu packages..."

    cd "${TMP_DIR}"
    echo "${EFIBOOTMGR_CHECKSUM} *efibootmgr.deb" | shasum --algorithm 256 --check
    echo "${LIBONIG5_CHECKSUM} *libonig5.deb" | shasum --algorithm 256 --check
    echo "${LIBJQ1_CHECKSUM} *libjq1.deb" | shasum --algorithm 256 --check
    echo "${JQ_CHECKSUM} *jq.deb" | shasum --algorithm 256 --check
    cd -
}

function download_ubuntu_iso() {
    if [ -z "${UBUNTU}" ]; then
        echo "* Downloading Ubuntu Live Server ISO image..."
        curl -L --output "${TMP_DIR}/${UBUNTU_ISO}" ${UBUNTU_URL}
    fi
}

function verify_ubuntu_iso() {
    echo "* Verifying Ubuntu Live Server ISO image checksum..."

    cd "${UBUNTU_ISO_PATH}"
    echo "${UBUNTU_CHECKSUM} *${UBUNTU_ISO}" | shasum --algorithm 256 --check
    cd -
}

function extract_ubuntu_iso() {
    echo "* Extracting Ubuntu Live Server ISO image..."

    # Extract Ubuntu ISO image except BOOT directory
    7z x ${UBUNTU_ISO_PATH}/${UBUNTU_ISO} -x'![BOOT]' -o${ISO_DIR}
}

function prepare_build() {
    echo "* Preparing SetupOS build..."

    # Create nocloud directory
    mkdir -p "${ISO_DIR}/nocloud"

    # Copy Ubuntu packages to ISO
    cp --preserve=timestamp "${TMP_DIR}/libonig5.deb" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${TMP_DIR}/libjq1.deb" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${TMP_DIR}/jq.deb" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${TMP_DIR}/efibootmgr.deb" "${ISO_DIR}/nocloud"

    # Copy setup files to ISO
    cp --preserve=timestamp "${BASE_DIR}/src/nocloud/meta-data" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${BASE_DIR}/src/nocloud/user-data" "${ISO_DIR}/nocloud"

    # Copy setup scripts to ISO
    cp --preserve=timestamp "${BASE_DIR}/src/nocloud/00_common.sh" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${BASE_DIR}/src/nocloud/01_setupos.sh" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${BASE_DIR}/src/nocloud/02_hardware.sh" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${BASE_DIR}/src/nocloud/03_firmware.sh" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${BASE_DIR}/src/nocloud/04_uefi.sh" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${BASE_DIR}/src/nocloud/05_disk.sh" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${BASE_DIR}/src/nocloud/06_hostos.sh" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${BASE_DIR}/src/nocloud/07_guestos.sh" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${BASE_DIR}/src/nocloud/08_devices.sh" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${BASE_DIR}/src/nocloud/09_setupos.sh" "${ISO_DIR}/nocloud"

    # Copy config.json, deployment.json, nns_public_key.pem to ISO
    cp --preserve=timestamp "${CONFIG}" "${ISO_DIR}/nocloud/config.json"
    cp --preserve=timestamp "${BASE_DIR}/src/nocloud/deployment.json" "${ISO_DIR}/nocloud"
    cp --preserve=timestamp "${KEY}" "${ISO_DIR}/nocloud/nns_public_key.pem"

    # Copy HostOS accounts SSH authorized keys
    if [ ! -z "${HOST_SSH}" ]; then
        echo "* Copying HostOS accounts SSH authorized keys..."
        mkdir -p "${ISO_DIR}/nocloud/hostos_accounts_ssh_authorized_keys"

        for file in admin backup readonly; do
            if [ -r "${HOST_SSH}/${file}" ]; then
                echo "* Copying HostOS '${file}' SSH authorized keys..."
                cp --preserve=timestamp "${HOST_SSH}/${file}" "${ISO_DIR}/nocloud/hostos_accounts_ssh_authorized_keys/"
            fi
        done
    fi

    # Copy GuestOS accounts SSH authorized keys
    if [ ! -z "${GUEST_SSH}" ]; then
        echo "* Copying GuestOS accounts SSH authorized keys..."
        mkdir -p "${ISO_DIR}/nocloud/guestos_accounts_ssh_authorized_keys"

        for file in admin backup readonly; do
            if [ -r "${GUEST_SSH}/${file}" ]; then
                echo "* Copying GuestOS '${file}' SSH authorized keys..."
                cp --preserve=timestamp "${GUEST_SSH}/${file}" "${ISO_DIR}/nocloud/guestos_accounts_ssh_authorized_keys/"
            fi
        done
    fi

    # Inject deployment configuration
    sed -i "s@{{ nns_url }}@${NNS_URL}@g" "${ISO_DIR}/nocloud/deployment.json"
    sed -i "s@{{ deployment_name }}@${DEPLOYMENT}@g" "${ISO_DIR}/nocloud/deployment.json"
    sed -i "s@{{ logging_hosts }}@${LOGGING}@g" "${ISO_DIR}/nocloud/deployment.json"
    sed -i "s@{{ resources_memory }}@${MEMORY}@g" "${ISO_DIR}/nocloud/deployment.json"

    # Copy disk-image files
    cp --preserve=timestamp "${GUEST_OS}" "${ISO_DIR}/nocloud/guest-os.img.tar.gz"
    cp --preserve=timestamp "${HOST_OS}" "${ISO_DIR}/nocloud/host-os.img.tar.gz"

    # Update boot flags with cloud-init autoinstall
    sed -i 's|---|autoinstall ds=nocloud\\\;s=/cdrom/nocloud/ ---|g' ${ISO_DIR}/boot/grub/grub.cfg
    sed -i 's|---|autoinstall ds=nocloud;s=/cdrom/nocloud/ ---|g' ${ISO_DIR}/isolinux/txt.cfg

    # Disable autoinstall
    rm -f ${ISO_DIR}/casper/installer.squashfs

    # Disable md5 checksum on boot
    md5sum ${ISO_DIR}/dists/focal/Release >${ISO_DIR}/md5sum.txt
    sed -i "s@${ISO_DIR}/@./@g" ${ISO_DIR}/md5sum.txt

    # Fix timestamps for reproducible build
    touch -t ${TOUCH_TIMESTAMP} ${ISO_DIR}/nocloud \
        ${ISO_DIR}/nocloud/deployment.json \
        ${ISO_DIR}/boot/grub \
        ${ISO_DIR}/boot/grub/grub.cfg \
        ${ISO_DIR}/isolinux/txt.cfg \
        ${ISO_DIR}/boot/grub \
        ${ISO_DIR}/boot/grub/grub.cfg \
        ${ISO_DIR}/isolinux/txt.cfg \
        ${ISO_DIR}/md5sum.txt \
        ${ISO_DIR}/casper \
        ${ISO_DIR}/isolinux \
        ${ISO_DIR}
}

function build_iso() {
    echo "* Building SetupOS ISO image..."

    # Create ISO image from extracted Ubuntu ISO
    xorriso -as mkisofs -r \
        -o ${OUTPUT}/setup-os.iso \
        -J -l -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot \
        -boot-load-size 4 -boot-info-table \
        -eltorito-alt-boot -e boot/grub/efi.img -no-emul-boot \
        -isohybrid-gpt-basdat -isohybrid-apm-hfsplus \
        -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
        ${TMP_DIR}/iso/boot ${TMP_DIR}/iso \
        -- \
        -volume_date "c" "${XORRISO_TIMESTAMP}" \
        -volume_date "m" "${XORRISO_TIMESTAMP}" \
        -volume_date "x" "default" \
        -volume_date "f" "default" \
        -alter_date_r "b" "${XORRISO_TIMESTAMP}" / -- \
        -alter_date_r "c" "${XORRISO_TIMESTAMP}" / --
}

function remove_temporary_directory() {
    echo "* Cleaning up build directories..."

    rm -rf ${TMP_DIR}
}

function log_end() {
    local time_end=$(date '+%s')
    local time_exec=$(expr "${time_end}" - "${TIME_START}")
    local time_hr=$(date -d "1970-01-01 ${time_exec} sec" '+%H:%M:%S')

    echo "SetupOS Builder - End (${time_hr})"
    log_and_exit_on_error "${?}" "Unable to end SetupOS builder."
}

# Establish run order
function main() {
    log_start
    validate_guest_os
    validate_host_os
    validate_ubuntu_path
    prepare_build_directories
    download_ubuntu_packages
    verify_ubuntu_packages
    download_ubuntu_iso
    verify_ubuntu_iso
    extract_ubuntu_iso
    prepare_build
    build_iso
    remove_temporary_directory
    log_end
}

main
