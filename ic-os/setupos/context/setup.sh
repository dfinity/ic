#!/bin/bash

# SetupOS - Main setup script

source "/icos_build/build_utils.sh"

set -xeuo pipefail

export SOURCE_DATE_EPOCH=0
export PATH=$PATH:/usr/sbin

# ------ NEAR-COMMON OS WORK ------------------------------------------

mkdir -p /config \
    /data \
    /boot/efi \
    /boot/grub
copy_component /etc
copy_component /opt

# Deactivate motd, it tries creating $HOME/.cache/motd.legal-displayed,
# but we want to prohibit it from writing to user home dirs
sed -e '/.*pam_motd.so.*/d' -i /etc/pam.d/login

# Deactivate lvm backup/archive: It writes backup information to /etc/lvm,
# but this is per system (so backups are not persisted across upgrades)
# and thus not very useful, and /etc is read-only.
# So simply suppress generating backups.
sed -e 's/\(# \)\?\(backup *= *\)[01]/\20/' -e 's/\(# \)\?\(archive *= *\)[01]/\20/' -i /etc/lvm/lvm.conf

# Deactivate systemd userdb. We don't use it.
sed -e 's/ *systemd//' -i /etc/nsswitch.conf

# Compile locale specification
localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8

# Clear files that may lead to indeterministic build.
apt-get clean &&
    find /usr/lib/python3.12 -name "*.pyc" | xargs rm &&
    find /usr/lib/python3 -name "*.pyc" | xargs rm &&
    find /usr/share/python3 -name "*.pyc" | xargs rm &&
    truncate --size 0 /etc/machine-id

# ------ NEAR-COMMON ICOS WORK ----------------------------------------

# Update POSIX permissions in /etc/
# TODO: We overwrite all /etc files with 644 except for the specified.
# See [NODE-1348] for context.
find /etc -type d -exec chmod 0755 {} \+ &&
    find /etc -type f -exec chmod 0644 {} \+ &&
    chmod 0755 /etc/systemd/system-generators/*

# Regenerate initramfs (config changed after copying in /etc)
RESUME=none update-initramfs -c -k all

for SERVICE in /etc/systemd/system/*; do
    if [ -f "$SERVICE" ] && [ ! -L "$SERVICE" ] && ! echo "$SERVICE" | grep -Eq "@\.service$"; then
        systemctl enable "${SERVICE#/etc/systemd/system/}"
    fi
done

systemctl enable \
    chrony \
    systemd-networkd \
    systemd-networkd-wait-online \
    systemd-resolved

systemctl disable \
    ssh

# ------ SETUPOS WORK --------------------------------------------

# commit-time is checked in the setupOS installation to verify that images
# are < six weeks old.
copy_component /commit-time

# Clear additional files that may lead to indeterministic build.
rm -rf \
    /var/cache/fontconfig/* /var/cache/ldconfig/aux-cache \
    /var/log/alternatives.log /var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log \
    /var/lib/apt/lists/* /var/lib/dbus/machine-id \
    /var/lib/initramfs-tools/5.8.0-50-generic

passwd -d root

# ------ INSTALL SCRIPTS ------------------------------------------

mkdir -p /opt/ic/share

# Update POSIX permissions in /opt/ic/
find /opt -type d -exec chmod 0755 {} \+ &&
    find /opt -type f -exec chmod 0644 {} \+ &&
    chmod 0755 /opt/ic/bin/*
