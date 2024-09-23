# SetupOS - Main Docker Image
#
# Build steps:
# - `docker build --pull -t dfinity/setupos-main -f Dockerfile .`

# ------ NEAR-COMMON OS WORK ------------------------------------------

# The base images are defined in docker-base. Update the references there when
# a new base image has been built. Note that this argument MUST be given by the
# build script, otherwise build will fail.
ARG BASE_IMAGE=


FROM $BASE_IMAGE

USER root:root

RUN mkdir -p /config \
             /data \
             /boot/efi \
             /boot/grub
COPY etc /etc

# Deactivate motd, it tries creating $HOME/.cache/motd.legal-displayed,
# but we want to prohibit it from writing to user home dirs
RUN sed -e '/.*pam_motd.so.*/d' -i /etc/pam.d/login

# Deactivate lvm backup/archive: It writes backup information to /etc/lvm,
# but this is per system (so backups are not persisted across upgrades)
# and thus not very useful, and /etc is read-only.
# So simply suppress generating backups.
RUN sed -e 's/\(# \)\?\(backup *= *\)[01]/\20/' -e 's/\(# \)\?\(archive *= *\)[01]/\20/' -i /etc/lvm/lvm.conf

# Deactivate systemd userdb. We don't use it.
RUN sed -e 's/ *systemd//' -i /etc/nsswitch.conf

# Compile locale specification
RUN localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8

# Clear files that may lead to indeterministic build.
RUN apt-get clean && \
    find /usr/lib/python3.12 -name "*.pyc" | xargs rm && \
    find /usr/lib/python3 -name "*.pyc" | xargs rm && \
    find /usr/share/python3 -name "*.pyc" | xargs rm && \
    truncate --size 0 /etc/machine-id

# ------ NEAR-COMMON ICOS WORK ----------------------------------------

# Ensure correct permissions for /etc/{hosts, hostname, resolv.conf}.
# Container engines bind mount these files to use the host's versions,
# so changes made with RUN commands don't affect the final image.
# Using COPY --chmod ensures the files are copied with the right permissions.
COPY --chmod=644 etc/hosts /etc/hosts
COPY --chmod=644 etc/hostname /etc/hostname
COPY --chmod=644 etc/resolv.conf /etc/resolv.conf

# Update POSIX permissions in /etc/
# TODO: We overwrite all /etc files with 644 except for the specified.
# See [NODE-1348] for context.
RUN find /etc -type d -exec chmod 0755 {} \+ && \
    find /etc -type f -not -path "/etc/hostname" -not -path "/etc/hosts" -not -path "/etc/resolv.conf" -exec chmod 0644 {} \+ && \
    chmod 0755 /etc/systemd/system-generators/*

# Regenerate initramfs (config changed after copying in /etc)
RUN RESUME=none update-initramfs -c -k all

RUN \
    for SERVICE in /etc/systemd/system/*; do \
    if [ -f "$SERVICE" -a ! -L "$SERVICE" ] && grep -q '^.Install.' "$SERVICE" ; then systemctl enable "${SERVICE#/etc/systemd/system/}" ; fi ; \
    done

RUN systemctl enable \
    chrony \
    systemd-networkd \
    systemd-networkd-wait-online \
    systemd-resolved

RUN systemctl disable \
    ssh

# ------ SETUPOS WORK --------------------------------------------

# Clear additional files that may lead to indeterministic build.
RUN rm -rf \
    /var/cache/fontconfig/* /var/cache/ldconfig/aux-cache \
    /var/log/alternatives.log /var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log \
    /var/lib/apt/lists/* /var/lib/dbus/machine-id \
    /var/lib/initramfs-tools/5.8.0-50-generic

RUN passwd -d root

# ------ INSTALL SCRIPTS ------------------------------------------

# Install scripts and other data late -- this means everything above
# will be cached when only the scripts change.
COPY opt /opt

RUN mkdir /opt/ic/share

# Update POSIX permissions in /opt/ic/
RUN find /opt -type d -exec chmod 0755 {} \+ && \
    find /opt -type f -exec chmod 0644 {} \+ && \
    chmod 0755 /opt/ic/bin/*
