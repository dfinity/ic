# BoundaryGuestOS - Main Docker Image
#
# Build step for example:
# - `docker build --pull -t dfinity/boundaryos-main --build-arg BUILD_TYPE=dev \ `
#   `--build-arg BASE_IMAGE=docker.io/dfinity/boundaryos-base@sha256:dc1a2892b0241131dd97ddd4dce560ab274d00a90110a4b5fc4cb2245ff1f0db -f Dockerfile .`
#
#
# The base images are defined in docker-base.prod and docker-base.dev. Update
# the references there when a new base image has been built. Note that this
# argument MUST be given by the build script, otherwise build will fail.
ARG BASE_IMAGE=

# We support prod and dev images
ARG BUILD_TYPE=

#
# First build stage: download software (service worker) that frequently changes, build and verify it (such that it
# does not change under our noses).
#
FROM $BASE_IMAGE AS download

USER root:root

WORKDIR /tmp

# Download and verify ic-gateway
RUN \
    curl -L -O https://github.com/dfinity/ic-gateway/releases/download/v0.1.43/ic-gateway_0.1.43_amd64.deb && \
    echo "e220f7f23cf8ca1eeeacf6e50380c5f69ed3f978  ic-gateway_0.1.43_amd64.deb" | shasum -c

#
# Second build stage:
# - Construct base images with the differences between dev and prod (IC-OS root filesystem)
#
FROM $BASE_IMAGE as image-dev
# nns public key will be on the USB stick

FROM $BASE_IMAGE as image-prod
USER root:root

# Bake the nns public key into the image
# For the dev image the public key will come from the usb stick
# See get_nns_pem_path in helpers.shlib
RUN printf '%s\n' >/etc/nns_public_key.pem \
    '-----BEGIN PUBLIC KEY-----' \
    'MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAIFMDm7HH6tYOwi9' \
    'gTc8JVw8NxsuhIY8mKTx4It0I10U+12cDNVG2WhfkToMCyzFNBWDv0tDkuRn25bW' \
    'W5u0y3FxEvhHLg1aTRRQX/10hLASkQkcX4e5iINGP5gJGguqrg==' \
    '-----END PUBLIC KEY-----'

#
# Fourth build stage:
# - Construct the actual target image (IC-OS root filesystem)
#
FROM image-${BUILD_TYPE}

USER root:root

COPY --from=download /tmp/ic-gateway_0.1.43_amd64.deb /tmp/ic-gateway_0.1.43_amd64.deb
RUN dpkg -i --force-confold /tmp/ic-gateway_0.1.43_amd64.deb && \
    rm /tmp/ic-gateway_0.1.43_amd64.deb

RUN mkdir -p /boot/config \
             /boot/efi \
             /boot/grub

COPY etc /etc

# Change permissions on special files as they are copied.
# See ic-os/boundary-guestos/context/Dockerfile for details
COPY --chmod=644 etc/hosts /etc/hosts
COPY --chmod=644 etc/hostname /etc/hostname
COPY --chmod=644 etc/resolv.conf /etc/resolv.conf

# Update POSIX permissions in /etc/
RUN find /etc -type d -exec chmod 0755 {} \+ && \
    find /etc -type f -not -path "/etc/hostname" -not -path "/etc/hosts" -not -path "/etc/resolv.conf" -exec chmod 0644 {} \+ && \
    chmod 0755 /etc/systemd/system-generators/* && \
    chmod 0440 /etc/sudoers && \
    chmod 755 /etc/initramfs-tools/scripts/init-bottom/set-machine-id && \
    chmod 755 /etc/initramfs-tools/scripts/init-premount/verity-root && \
    chmod 755 /etc/initramfs-tools/hooks/veritysetup

    # Deactivate motd, it tries creating $HOME/.cache/motd.legal-displayed,
    # but we want to prohibit it from writing to user home dirs
RUN sed -e '/.*pam_motd.so.*/d' -i /etc/pam.d/login && \
    sed -e '/.*pam_motd.so.*/d' -i /etc/pam.d/sshd && \
    # Deactivate lvm backup/archive: It writes backup information to /etc/lvm, but a) this is
    # per system (so backups are not persisted across upgrades) and thus not very
    # useful, and b) we want to turn /etc read-only eventually. So simply suppress
    # generating backups.
    sed -e 's/\(backup *= *\)1/\10/' -e 's/\(archive *= *\)1/\10/' -i /etc/lvm/lvm.conf && \
    # Deactivate systemd userdb. We don't use it.
    sed -e 's/ *systemd//' -i /etc/nsswitch.conf

# Regenerate initramfs (config changed after copying in /etc)
RUN RESUME=none update-initramfs -c -k all

ARG ROOT_PASSWORD=
RUN if [ "${ROOT_PASSWORD}" != "" ]; then \
        echo "root:$(openssl passwd -6 -salt jE8zzDEHeRg/DuGq ${ROOT_PASSWORD})" | chpasswd -e ; \
    fi && \
    # Prepare for bind mount of authorized_keys
    mkdir -p /root/.ssh && chmod 0700 /root/.ssh && \
    # Delete generated ssh keys, otherwise every host will have the same key pair.
    # They will be generated on first boot.
    rm /etc/ssh/ssh*key* && \
    # Allow root login only via keys. In prod deployments there are never any
    # keys set up for root, but in dev deployments there may be.
    # Actually, prohibit-password is the default config, so would not be
    # strictly necessary to be explicit here.
    sed -e "s/.*PermitRootLogin.*/PermitRootLogin prohibit-password/" -i /etc/ssh/sshd_config

# All of the above sets up the base operating system. Everything below relates
# to node operation.

RUN for SERVICE in /etc/systemd/system/*; do \
    if [ -f "$SERVICE" -a ! -L "$SERVICE" ] && grep -q '^.Install.' "$SERVICE" ; then systemctl enable "${SERVICE#/etc/systemd/system/}" ; fi ; \
    done && \
    systemctl enable \
    chrony \
    nftables \
    systemd-networkd \
    systemd-networkd-wait-online \
    systemd-resolved \
    systemd-journal-gatewayd

# TODO remove when nginx is removed from base image
RUN systemctl disable nginx

# Add user/group entries specified here: /usr/lib/sysusers.d/systemd.conf
# E.g., systemd-timesync/coredump
RUN systemd-sysusers && \
    # Fix reproducibility issue. Notes in boundary-guestos/context/Dockerfile
    usermod -p '!!' systemd-timesync && \
    usermod -p '!!' systemd-coredump && \
    # Set /bin/sh to point to /bin/bash instead of the default /bin/dash
    echo "set dash/sh false" | debconf-communicate && dpkg-reconfigure -fnoninteractive dash

# Group accounts to which parts of the runtime state are assigned such that
# user accounts can be granted individual access rights.
# Note that a group "backup" already exists and is used for the purpose of
# allowing backup read access.
RUN addgroup --system nonconfidential && \
    addgroup --system confidential && \
    # Accounts to allow remote access to state bits
    # The "backup" user account. We simply use the existing "backup" account and
    # reconfigure it for our purposes.
    chsh -s /bin/bash backup && \
    mkdir /var/lib/backup && \
    chown backup:backup /var/lib/backup && \
    usermod -d /var/lib/backup backup && \
    adduser backup systemd-journal && \
    # The "read-only" user account. May read everything besides crypto.
    adduser --system --disabled-password --home /var/lib/readonly --shell /bin/bash readonly && \
    adduser readonly backup && \
    adduser readonly nonconfidential && \
    adduser readonly systemd-journal && \
    # The omnipotent "admin" account. May read everything and crucially can also
    # arbitrarily change system state via sudo.
    adduser --system --disabled-password --home /var/lib/admin --shell /bin/bash admin && \
    chown admin:staff /var/lib/admin && \
    adduser admin backup && \
    adduser admin nonconfidential && \
    adduser admin systemd-journal && \
    adduser admin sudo && \
    # The "vector" account. Used to run vector binary
    adduser --system --disabled-password --shell /usr/sbin/nologin --no-create-home vector && \
    adduser vector vector


# The "node_exporter" account. Used to run node_exporter binary to export
# telemetry metrics of the GuestOS.
RUN addgroup node_exporter && \
    adduser --system --disabled-password --shell /usr/sbin/nologin --no-create-home node_exporter && \
    adduser node_exporter node_exporter && \
    # The "socks" account for socks proxy
    # Also set correct permissions for dante.
    addgroup socks && \
    adduser --system --disabled-password --shell /usr/sbin/nologin --no-create-home socks && \
    adduser socks socks && chmod +s /usr/sbin/danted

# Setup prober
RUN \
    addgroup prober && \
    adduser --system --disabled-password --shell /usr/sbin/nologin --no-create-home prober && \
    adduser prober prober && \
    mkdir -p /var/log/prober && \
    chown prober:prober /var/log/prober && \
    chmod 755 /var/log/prober

# Install node_exporter
RUN chown root:root /etc/node_exporter \
                    /usr/local/bin/node_exporter && \
    chmod 0755 /etc/node_exporter \
               /usr/local/bin/node_exporter

# Install IC binaries and other data late -- this means everything above
# will be cached when only the binaries change.
COPY opt /opt

# Clear all files that may lead to indeterministic build.
RUN apt-get clean && \
    rm -rf \
        /var/cache/fontconfig/* /var/cache/ldconfig/aux-cache \
        /var/log/alternatives.log /var/log/apt/history.log \
        /var/log/apt/term.log /var/log/dpkg.log \
        /var/lib/apt/lists/* /var/lib/dbus/machine-id \
        /var/lib/initramfs-tools/5.8.0-50-generic && \
    find /usr/local/share/fonts -name .uuid | xargs rm && \
    find /usr/share/fonts -name .uuid | xargs rm && \
    find /usr/lib -name "*.pyc" | xargs rm -rf&& \
    find /usr/share -name "*.pyc" | xargs rm -rf&& \
    truncate --size 0 /etc/machine-id

# Update POSIX permissions in /opt
RUN find /opt -type d -exec chmod 0755 {} \+ && \
    find /opt -type f -exec chmod 0644 {} \+ && \
    chmod 0755 /opt/ic/bin/*

# Increase the default limit on the number of open files for all systemd services
RUN sed -i '/^#DefaultLimitNOFILE=/c\DefaultLimitNOFILE=1048576:1048576' /etc/systemd/system.conf
