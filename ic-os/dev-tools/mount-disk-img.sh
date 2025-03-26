#!/usr/bin/env bash

# this mounts A_boot, but other can be mounted as well from the guest image:
# disk.img1      2048    206847   204800  100M EFI System
# disk.img2    206848    411647   204800  100M Linux filesystem
# disk.img3    411648    616447   204800  100M Linux filesystem
# disk.img4    616448   2713599  2097152    1G Linux filesystem
# disk.img5   2713600  23685119 20971520   10G Linux filesystem
# disk.img6  23685120  44656639 20971520   10G Linux filesystem
# disk.img7  44656640  46753791  2097152    1G Linux filesystem
# disk.img8  46753792  67725311 20971520   10G Linux filesystem
# disk.img9  67725312  88696831 20971520   10G Linux filesystem
# disk.img10 88696832 104857566 16160735  7.7G Linux filesystem
# e.g. img7 is B_boot
start=$(fdisk -l disk.img 2>/dev/null | grep img4 | awk '$0=$2')
offset=$(("$start" * 512))
[ ! -d tmp_mount ] || sudo umount -q tmp_mount
mkdir -p tmp_mount
sudo mount -o rw,loop,offset=${offset} ./disk.img ./tmp_mount
