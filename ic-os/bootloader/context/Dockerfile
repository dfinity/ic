# Bootloader tree: builds the /boot hierarchy with the /boot/grub and /boot/efi
# portions under /build, from which the grub and EFI partitions of the disk
# images are built (see ../BUILD.bazel).

# The base image is defined in docker-base and MUST be given by the build.
ARG BASE_IMAGE=

FROM $BASE_IMAGE

USER root:root

RUN mkdir -p /build/boot/grub
RUN cp -r /usr/lib/grub/x86_64-efi /build/boot/grub
RUN mkdir -p /build/boot/efi/EFI/Boot
RUN grub-mkimage --version
RUN apt list --installed | grep grub
RUN faketime -f '1970-1-1 0:0:0' grub-mkimage -p '(,gpt2)/' -O x86_64-efi -o /build/boot/efi/EFI/Boot/bootx64.efi \
        boot linux search normal configfile \
        part_gpt btrfs ext2 fat iso9660 loopback \
        test keystatus gfxmenu regexp probe \
        efi_gop all_video gfxterm font \
        echo read ls cat png jpeg halt reboot loadenv lvm
