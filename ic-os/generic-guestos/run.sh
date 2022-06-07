#!/bin/bash

diskimg="disk.img"
mediaimg="media.img"
bridge="virbr0"

function usage() {
    echo QEMU boot a generic os image
    echo "$0 [-d | --disk] [-m | --media] [-b | --bridge]"
    echo -d OS disk image
    echo -m media image
    echo -b networking bridge name
    echo $0 -d osdisk.img -m media.img -b bridge
}

while [ "$1" != "" ]; do
    case $1 in
        -d | --disk)
            shift
            diskimg="$1"
            ;;
        -m | --media)
            shift
            mediaimg="$1"
            ;;
        -b | --bridge)
            shift
            bridge="$1"
            ;;
        -h | --help)
            usage
            exit
            ;;
        *)
            usage
            exit 1
            ;;
    esac
    shift
done

#GZIP=-n tar --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2020-01-01' --sparse -cvzf ./disk-img.tar.gz ${diskimg}

sudo qemu-system-x86_64 \
    -nographic \
    -display none -serial mon:stdio \
    -machine type=q35,accel=kvm -enable-kvm \
    -cpu host \
    -m 4G \
    -bios /usr/share/OVMF/OVMF_CODE.fd \
    \
    -device virtio-blk-pci,drive=drive0,addr=2.0 \
    -drive file=${diskimg},format=raw,id=drive0,if=none \
    \
    -device pcie-root-port,id=pcie.1,chassis=1 \
    -netdev bridge,br=${bridge},id=enp1s0 \
    -device virtio-net-pci,netdev=enp1s0,bus=pcie.1,addr=0.0 \
    \
    -device qemu-xhci \
    \
    -device usb-storage,drive=removable,removable=true \
    -drive file=${mediaimg},format=raw,id=removable,if=none
