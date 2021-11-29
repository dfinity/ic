#!/bin/env bash

set -eo pipefail

FARM_BASE_URL="https://farm.dfinity.systems/"
SCRIPT_NAME=$(basename "$0")

function usage() {
    set +x
    cat <<EOF
Usage:
  farm-deploy-vm -i disk-image.img[.zst|.gz] [-c config-disk-image.img[.zst|.gz]] [-t TTL]

  Deploy and run a single [ic-os] virtual machine on farm.

  -i disk-image.img[.zst|.gz]: boot image; mandatory
  -c config-image.img[.zst|.gz]; config disk image; optional
  -t time-to-live; default: 600 (seconds)

  If -c is specified, the given image will be attached as USB disk.
EOF
}

function is_reasonable_sized_file() {
    if ! [[ -f "$1" ]] || ! [[ -s "$1" ]]; then
        echo "ERROR: '$1' either does not exist or is empty"
        echo ""
        usage
        exit 1
    fi
    SIZE=$(stat -c %s "$1")
    if [[ "$SIZE" -gt 1073741824 ]]; then
        echo "ERROR: '$1' is larger than 1 GiB,"
        echo "consider compressing with gzip or zstd"
        exit 1
    fi
}

function sha256() {
    sha256sum "$1" | cut -d " " -f 1
}

function log() {
    echo -e "\n$(date --iso-8601=seconds):+:+:+:+: ${SCRIPT_NAME}: $1"
}

while getopts "i:c:t:" OPT; do
    case "${OPT}" in
        i)
            BOOT_IMG="${OPTARG}"
            ;;
        c)
            CFG_IMG="${OPTARG}"
            ;;
        t)
            TTL="${OPTARG}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

if [[ -z "$BOOT_IMG" ]]; then
    usage
fi
is_reasonable_sized_file "$BOOT_IMG"
BOOT_SHA256=$(sha256 "$BOOT_IMG")

if [[ -n "$CFG_IMG" ]]; then
    is_reasonable_sized_file "$CFG_IMG"
    CFG_SHA256=$(sha256 "$CFG_IMG")
fi

TTL="${TTL:-600}"

GRP_NAME=$(
    T=$(head -c 10 /dev/urandom | sha256sum | cut -d " " -f 1)
    echo -n "${T::10}"
)
log "GROUP NAME: $GRP_NAME"
log "TTL: $TTL"
log "VM NAME: $BOOT_SHA256"

GROUP_DEF="{\"ttl\": $TTL, \"spec\": {}}"
log "Creating group ..."
curl -X POST "${FARM_BASE_URL}group/$GRP_NAME" \
    -H "accept: application/json" -H "Content-Type: application/json" \
    -d "$GROUP_DEF" --fail --show-error

log "Upload boot image ..."
curl -X POST "${FARM_BASE_URL}group/$GRP_NAME/image" \
    -F image1="@$BOOT_IMG" --fail --show-error

primaryImage="{\"_tag\":\"imageViaId\",\"id\":\"$BOOT_SHA256\"}"
newVm="{\"type\":\"production\",\"primaryImage\":$primaryImage,\"vCPUs\":4,\"memoryKiB\":16777216}"

log "Create Virtual Machine ..."
curl -X POST "${FARM_BASE_URL}group/$GRP_NAME/vm/$BOOT_SHA256" \
    -H "accept: application/json" -H "Content-Type: application/json" \
    -d "$newVm" --fail --show-error

if [[ -n "$CFG_IMG" ]]; then
    log "Uploading configuration image '$CFG_IMG' (sha256: $CFG_SHA256)"
    curl -X POST "${FARM_BASE_URL}group/$GRP_NAME/image" \
        -F image1="@$CFG_IMG" --fail --show-error

    log "Attaching configuration image as usb-storage"
    curl -X PUT --insecure "${FARM_BASE_URL}group/$GRP_NAME/vm/$BOOT_SHA256/drive-templates/usb-storage" \
        -H "accept: application/json" -H "Content-Type: application/json" \
        -d "{\"drives\":[{\"_tag\":\"imageViaId\",\"id\":\"$CFG_SHA256\"}]}" \
        --fail --silent --show-error
fi

log "Starting VM"
curl -X PUT "${FARM_BASE_URL}group/$GRP_NAME/vm/$BOOT_SHA256/start" \
    --fail --show-error

function teardown() {
    log "Tearing the group down"
    curl -X DELETE "${FARM_BASE_URL}group/$GRP_NAME" \
        --fail --show-error
}

# Call on_sigterm() when the user presses Ctrl+C
trap "on_sigterm" 2

function on_sigterm() {
    teardown
}

log "Sleeping for $TTL seconds ... press Ctrl+C to abort and tear down the group."
sleep "$TTL"

teardown
