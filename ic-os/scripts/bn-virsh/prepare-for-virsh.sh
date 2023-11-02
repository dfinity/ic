#!/usr/bin/env bash

# Get the image.  Either from a pre-built image or built locally.
# wget https://download.dfinity.systems/ic/39b8ec113e4f387c0de3fd43954a790e98e7fbb7/boundary-os/disk-img-snp-dev/disk-img.tar.zst
tar xfv bazel-out/k8-opt/bin/ic-os/boundary-guestos/envs/dev-sev/disk-img.tar

# Mount and pull out the kernel and initrd.img
start=$(fdisk -l disk.img 2>/dev/null | grep img4 | awk '$0=$2')
offset=$((start * 512))
[ ! -d tmp_mount ] || sudo umount -q tmp_mount
mkdir -p tmp_mount
sudo mount -o loop,offset=${offset} ./disk.img ./tmp_mount
sudo cp ./tmp_mount/initrd.img .
sudo cp ./tmp_mount/vmlinuz .
sudo chown "$USER"."$USER" initrd.img vmlinuz
sudo umount -q tmp_mount
rmdir ./tmp_mount

# Prepare config
mkdir tmp_config
(
    cd ic-os/scripts/bn-virsh/data/bn_config || exit 1
    tar cf ../../../../../tmp_config/ic-bootstrap.tar ./*
)
make_ext4fs -T 0 -l 10M config.img tmp_config
rm -rf tmp_config

# Specialize virsh config
cp ./ic-os/scripts/bn-virsh/data/bn_sev_vm.xml ./bn_sev_vm.xml
sed -i "s/USER/$USER/g" bn_sev_vm.xml

# Stage in /tmp so that we get the right perms for virsh
TMP_DIR=/tmp/$USER-sev-vm
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"
ln ./disk.img "$TMP_DIR"/
ln ./initrd.img "$TMP_DIR"/
ln ./vmlinuz "$TMP_DIR"/
ln ./config.img "$TMP_DIR"/config.img

# Help out the user
echo "\$ virsh create ./bn_sev_vm.xml # to create"
echo "\$ virsh console boundary_nodes_sev_snp-$USER # for login prompt as root:root"
echo "control-] to exit"
echo "\$ virsh destroy boundary_nodes_sev_snp-$USER # to destroy"
