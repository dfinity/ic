# SetupOS - Main Docker Image
#
# Build steps:
# - `docker build --pull -t dfinity/setupos-main -f Dockerfile .`
#
# First build stage:
# - Download 3rd party tools
#

# The base images are defined in docker-base. Update the references there when
# a new base image has been built. Note that this argument MUST be given by the
# build script, otherwise build will fail.
ARG BASE_IMAGE=

#
# First build stage:
# - Construct the actual target image (SetupOS root filesystem)
#

FROM $BASE_IMAGE

RUN mkdir -p /config \
             /data \
             /boot/efi \
             /boot/grub
COPY etc /etc

# Update POSIX permissions in /etc/
RUN find /etc -type d -exec chmod 0755 {} \+ && \
    find /etc -type f -not -path "/etc/hostname" -not -path "/etc/hosts" -not -path "/etc/resolv.conf" -exec chmod 0644 {} \+ && \
    chmod 0755 /etc/systemd/system-generators/*

# Deactivate motd, it tries creating $HOME/.cache/motd.legal-displayed,
# but we want to prohibit it from writing to user home dirs
RUN sed -e '/.*pam_motd.so.*/d' -i /etc/pam.d/login

# Deactivate systemd userdb. We don't use it.
RUN sed -e 's/ *systemd//' -i /etc/nsswitch.conf

# Regenerate initramfs (config changed after copying in /etc)
RUN RESUME=none update-initramfs -c -k all

RUN echo "root:$(openssl passwd -6 -salt jE8zzDEHeRg/DuGq password)" | chpasswd -e

COPY prep /prep
RUN cd /prep && ./prep.sh && cd / && rm -rf /prep

# All of the above sets up the base operating system. Everything below relates
# to node operation.

RUN \
    for SERVICE in /etc/systemd/system/*; do \
        if [ -f "$SERVICE" -a ! -L "$SERVICE" ] ; then systemctl enable "${SERVICE#/etc/systemd/system/}" ; fi ; \
    done

RUN systemctl disable systemd-resolved && \
    systemctl disable systemd-timesyncd

# Clear all files that may lead to indeterministic build.
RUN apt-get clean && \
    rm -rf \
        /var/cache/fontconfig/* /var/cache/ldconfig/aux-cache \
        /var/log/alternatives.log /var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log \
        /var/lib/apt/lists/* /var/lib/dbus/machine-id \
        /var/lib/initramfs-tools/5.8.0-50-generic && \
    find /usr/lib/python3.8 -name "*.pyc" | xargs rm && \
    find /usr/lib/python3 -name "*.pyc" | xargs rm && \
    find /usr/share/python3 -name "*.pyc" | xargs rm && \
    truncate --size 0 /etc/machine-id

# Install scripts and other data late -- this means everything above
# will be cached when only the scripts change.
COPY opt /opt

RUN mkdir /opt/ic/share

# Update POSIX permissions in /opt/ic/
RUN find /opt -type d -exec chmod 0755 {} \+ && \
    find /opt -type f -exec chmod 0644 {} \+ && \
    chmod 0755 /opt/ic/bin/*
