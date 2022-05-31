#! /usr/bin/env bash

set -euo pipefail

CURRENT="$(pwd)"
cd "$(dirname "$0")"
REPO_ROOT="$(git rev-parse --show-toplevel)"
TEMPDIR=$(mktemp -d /tmp/boot-standalone-bn.sh.XXXXXXXXXX)

function usage() {
    cat <<EOF
Usage:
  boot-standalone-bn.sh [--farm-base-url FARM_BASE_URL] [--ttl TTL] [--img-CI-id  <ID>] [--disk-image <image>] [--config-image <config>] [--ic-binaries <path_to_ic_binaries>] [--version <version>]

  This locally builds a boundary node VM image, takes a disk image as parameter
  or takes the ID of an image build by the CI pipeline.

  It also creates a minimal config image or requires one as parameter.

  It then creates a Farm group containing a single boundary node VM that boots from this image and which mounts the config image.

  It will then wait for the VM to be pingable over IPv6 before printing a handy message how to SSH to the VM.

  The script will then wait until the user presses Enter after which the group and the associated VM will be deleted.

  Examples:

      Binaries for the boundary node have been build via cargo (i.e., boundary-node-control-plane)
      ic-os/boundary-guestos/scripts/build-disk-image.sh --ic-binaries rs/target/x86_64-unknown-linux-gnu/debug/ --version 1234

      In case you have already build an image:
      ic-os/boundary-guestos/scripts/build-disk-image.sh -o /tmp/disk.img
      boot-standalone-bn.sh --disk-image /tmp/disk.img --version 1234

  --help

    Displays this help message.

  --farm-base-url

    Configures the base URL that should point to the Farm service that you want to use.
    Defaults to: https://farm.dfinity.systems

  --ttl

    Configures the Time-To-Live for the created group.
    Defaults to: 3600 seconds

  --img-CI-id

    It is assumed the image has been build via the CI and is downloaded from the CDN at:
      https://download.dfinity.systems/ic/<ID>/boundary-os/disk-img/disk-img.tar.gz
    To get the latest image ID from master:
       gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh master

  --disk-image
    Provide a disk image that has been build locally via:
      ic-os/boundary-guestos/scripts/build-disk-image.sh

  --ic-binaries
      E.g., provided via the default way to build the ic binaries (see ic/README.adoc)

  --version
      The version written into the image.

  --config-image
    A custom config image can be provide. Such an image can be created via:
      ic-os/boundary-guestos/scripts/build-bootstrap-config-image.sh
EOF
    exit
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --help)
            shift
            usage
            ;;
        --farm-base-url)
            FARM_BASE_URL="$2"
            shift
            shift
            ;;
        --ttl)
            TTL="$2"
            shift
            shift
            ;;
        --img-CI-id)
            IMG_ID="$2"
            shift
            shift
            ;;
        --disk-image)
            DISK_IMAGE="$2"
            shift
            shift
            ;;
        --config-image)
            CONFIG_IMAGE="$2"
            shift
            shift
            ;;
        --ic-binaries)
            IC_BINARIES="$2"
            shift
            shift
            ;;
        --version)
            IMG_VERSION="$2"
            shift
            shift
            ;;
    esac
done

info() { echo "$*" 1>&2; }

if [ -z ${IMG_VERSION:-} ] && [ -z ${DISK_IMAGE:-} ]; then
    info "Either --version or --disk-image needs to be provided!"
    usage
fi

if [ -z ${IC_BINARIES:-} ] && [ -z ${DISK_IMAGE:-} ]; then
    info "Either --ic-binaries or --disk-image needs to be provided!"
    usage
fi

FARM_BASE_URL=${FARM_BASE_URL:-https://farm.dfinity.systems}
TTL=${TTL:-3600}

group="test-boundary-guestos-vm-$(whoami)-$(date +%Y-%m-%dT%H:%M:%S%z)"

base="$FARM_BASE_URL/group/$group"

finalize() {
    info "Deleting group $group..."
    curl --silent --show-error --fail -X DELETE "$base"
    info "Delete $TEMPDIR?"
}
trap finalize EXIT

if [ -z ${IMG_ID:-} ]; then
    if [ -z ${DISK_IMAGE:-} ]; then
        info "Building boundary guestos image ..."
        image=$TEMPDIR/disk.img
        cd $REPO_ROOT/ic-os/boundary-guestos

        if [[ ! "${IC_BINARIES:0:1}" == / && ! "${IC_BINARIES:0:2}" == ~[/a-z] ]]; then
            IC_BINARIES=$CURRENT/$IC_BINARIES
        fi
        info "We copy the IC binaries from here $IC_BINARIES"

        ./scripts/build-disk-image.sh -o $image -x $IC_BINARIES -v $IMG_VERSION
    else
        if [[ "${DISK_IMAGE:0:1}" == / || "${DISK_IMAGE:0:2}" == ~[/a-z] ]]; then
            image=$DISK_IMAGE
        else
            image=$CURRENT/$DISK_IMAGE
        fi
    fi
    info "Compress image ..."
    zstd $image
    image=$image.zst
    du -h "$image"
fi

info "Creating group $group on $FARM_BASE_URL..."
groupExpiresAt="$(curl --silent --show-error --fail -X POST "$base" \
    -d "$(jo ttl=$TTL spec=$(jo vmAllocation=distributeWithinSingleHost))" \
    -H 'accept: application/json' \
    -H 'content-type: application/json' \
    | jq .expiresAt --raw-output)"
info "Group $group created and expires at: $groupExpiresAt"

upload_image() {
    image="$1"
    info "Checking if $image was already uploaded..."
    image_id="$(sha256sum $image | cut -d' ' -f1)"
    if curl --silent --fail -X PUT "$base/file/$image_id"; then
        info "Image $image_id is already uploaded :)"
    else
        info "Uploading $image ..."
        image_id="$(curl --fail -X POST "$base/file" -F image=@"$image" \
            -H 'accept: application/json' \
            | jq .fileIds.image --raw-output)"
    fi
    echo "$image_id"
}

if [[ -z ${IMG_ID:-} ]]; then
    image_id="$(upload_image "$image")"
    echo "image_id=$image_id"
    primaryImage="$(jo _tag=imageViaId id="$image_id")"
else
    base_url="https://download.dfinity.systems/ic/$IMG_ID/boundary-os/disk-img"
    SHA256="$(curl --silent --show-error --fail $base_url/SHA256SUMS)"
    primaryImage="$(jo _tag=icOsImageViaUrl url="$base_url/disk-img.tar.gz" sha256="${SHA256:0:64}")"
fi

vm_name="boundary-guestos-vm"
vm_base="$base/vm/$vm_name"
info "Creating $vm_name..."
echo $vm_base

echo "$primaryImage"

sleep 10

ipv6="$(curl --silent --show-error --fail -X POST "$vm_base" \
    -d "$(
        jo type=production \
            vCPUs=2 \
            memoryKiB=25165824 \
            primaryImage="$primaryImage" \
            hasIPv4=true
    )" \
    -H 'accept: application/json' \
    -H 'content-type: application/json' \
    | jq .ipv6 --raw-output)"
info "$vm_name will get IPv6: $ipv6"

if [[ -z ${CONFIG_IMAGE:-} ]]; then
    info "Building an example config image ..."
    CONFIG_IMAGE=$TEMPDIR/config.img
    $REPO_ROOT/ic-os/boundary-guestos/scripts/build-bootstrap-config-image.sh $CONFIG_IMAGE --accounts_ssh_authorized_keys $REPO_ROOT/testnet/config/ssh_authorized_keys --hostname "test-boundary-guestos-vm-$(whoami)" --deployment-type dev
else
    if [[ "${CONFIG_IMAGE:0:1}" == / || "${CONFIG_IMAGE:0:2}" == ~[/a-z] ]]; then
        cp $CONFIG_IMAGE $TEMPDIR/config.img
    else
        cp $CURRENT/$CONFIG_IMAGE $TEMPDIR/config.img
    fi

    info "We use the provided config image: $CONFIG_IMAGE"
    CONFIG_IMAGE=$TEMPDIR/config.img
fi

gzip $CONFIG_IMAGE
CONFIG_IMAGE=$CONFIG_IMAGE.gz
du -h "$CONFIG_IMAGE"

config_image_id="$(upload_image "$CONFIG_IMAGE")"

info "Mounting config image $config_image_id to VM ..."
curl --silent --fail --show-error \
    -X PUT "$vm_base/drive-templates/usb-storage" \
    -d "$(jo drives=$(jo -a \
        $(jo _tag="imageViaId" id=$config_image_id)))" \
    -H 'accept: application/json' \
    -H 'content-type: application/json'

info "Starting $vm_name ..."
curl --silent --show-error --fail -X PUT "$vm_base/start"

info "$vm_name started"
info "Console: $vm_base/console"

info "Waiting until $ipv6 is online..."
until ping -c1 -W3 "$ipv6"; do
    sleep 1
done

info "$ipv6 is online. Connect to it using:"
info "ssh admin@$ipv6"

info "Waiting for IPv4 address..."
ipv4="$(
    cat <<'EOF' | ssh -o StrictHostKeyChecking=no "admin@$ipv6" bash
set -e -o pipefail

sleep 5
ipv4=$(/sbin/ifconfig enp2s0 | grep 'inet' |  awk '{print $2}')
echo "$ipv4"
EOF
)"

info "IPv4: $ipv4"
info "Test if the nginx is working by browsing to the following URLs:"
info "curl --insecure https://$ipv4"
info "curl --insecure https://[$ipv6]"

info "Keep this running until you're done testing,"
info "then press ENTER to delete the group $group."
read
