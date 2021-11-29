# 20.04
FROM ubuntu:focal-20211006

RUN apt-get -y update && apt-get -y upgrade && apt-get -y --no-install-recommends install \
    grub-efi-amd64-bin faketime

# Copy all grub modules into their requisite place
RUN mkdir -p /boot/grub ; cp -r /usr/lib/grub/x86_64-efi /boot/grub

# Build grub image itself into EFI directory tree
RUN mkdir -p /boot/efi/EFI/Boot
RUN faketime "1970-1-1 0" grub-mkimage -p "(,gpt2)/" -O x86_64-efi -o /boot/efi/EFI/Boot/bootx64.efi \
    boot linux search normal configfile \
    part_gpt btrfs ext2 fat iso9660 loopback \
    test keystatus gfxmenu regexp probe \
    efi_gop efi_uga all_video gfxterm font \
    echo read ls cat png jpeg halt reboot loadenv \
