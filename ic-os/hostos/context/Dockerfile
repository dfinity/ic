# HostOS - Main Docker Image
#
# Build steps:
# - `docker build --pull -t dfinity/hostos-main -f Dockerfile .`

# ------ NEAR-COMMON OS WORK ----------------------------------------

# The base images are defined in docker-base.prod and docker-base.dev. Update
# the references there when a new base image has been built. Note that this
# argument MUST be given by the build script, otherwise build will fail.
ARG BASE_IMAGE=


FROM $BASE_IMAGE

USER root:root

RUN mkdir -p /boot/config \
             /boot/efi \
             /boot/grub
COPY etc /etc

# Deactivate motd, it tries creating $HOME/.cache/motd.legal-displayed,
# but we want to prohibit it from writing to user home dirs
RUN sed -e '/.*pam_motd.so.*/d' -i /etc/pam.d/login && \
    sed -e '/.*pam_motd.so.*/d' -i /etc/pam.d/sshd

# Deactivate lvm backup/archive: It writes backup information to /etc/lvm,
# but this is per system (so backups are not persisted across upgrades)
# and thus not very useful, and /etc is read-only.
# So simply suppress generating backups.
RUN sed -e 's/\(backup *= *\)1/\10/' -e 's/\(archive *= *\)1/\10/' -i /etc/lvm/lvm.conf

# Deactivate systemd userdb. We don't use it.
RUN sed -e 's/ *systemd//' -i /etc/nsswitch.conf

# Compile locale specification
RUN localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8

# Clear files that may lead to indeterministic build.
RUN apt-get clean && \
    find /usr/lib/python3.8 -name "*.pyc" | xargs rm && \
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
    chmod 0755 /etc/systemd/system-generators/* && \
    chmod 0440 /etc/sudoers && \
    chmod 755 /etc/initramfs-tools/scripts/init-bottom/set-machine-id

# Regenerate initramfs (config changed after copying in /etc)
RUN RESUME=none update-initramfs -c -k all

# Activate the NSS IC OS Name Service Switch plugin.
# See ../../../rs/ic_os//nss_icos/README.md for context.
RUN sed -r -e 's/hosts:( *)files/hosts:\1files icos/' -i /etc/nsswitch.conf

# Prepare for bind mount of authorized_keys
RUN mkdir -p /root/.ssh && chmod 0700 /root/.ssh

# Delete generated ssh keys, otherwise every host will have the same key pair.
# They will be generated on first boot.
RUN rm /etc/ssh/ssh*key*
# Allow root login only via keys. In prod deployments there are never any
# keys set up for root, but in dev deployments there may be.
# Actually, prohibit-password is the default config, so would not be
# strictly necessary to be explicit here.
RUN sed -e "s/.*PermitRootLogin.*/PermitRootLogin prohibit-password/" -i /etc/ssh/sshd_config

RUN \
    for SERVICE in /etc/systemd/system/*; do \
    if [ -f "$SERVICE" -a ! -L "$SERVICE" ] && grep -q '^.Install.' "$SERVICE" ; then systemctl enable "${SERVICE#/etc/systemd/system/}" ; fi ; \
    done

RUN systemctl enable \
    chrony \
    libvirtd \
    nftables \
    systemd-journal-gatewayd \
    systemd-networkd \
    systemd-networkd-wait-online \
    systemd-resolved

RUN systemctl disable \
    apt-daily.service \
    apt-daily.timer \
    apt-daily-upgrade.service \
    apt-daily-upgrade.timer \
    motd-news.service \
    motd-news.timer

# ------ HOSTOS WORK ---------------------------------------------

ARG ROOT_PASSWORD=
RUN \
    if [ "${ROOT_PASSWORD}" != "" ]; then \
        echo "root:$(openssl passwd -6 -salt jE8zzDEHeRg/DuGq ${ROOT_PASSWORD})" | chpasswd -e ; \
    fi

# Clear additional files that may lead to indeterministic build.
RUN rm -rf \
        /usr/local/share/qemu/edk2-arm-code.fd \
        /usr/local/share/qemu/edk2-arm-vars.fd

# Add user/group entries specified here: /usr/lib/sysusers.d/systemd.conf E.g., systemd-timesync/coredump
RUN systemd-sysusers && \
    # Fix reproducibility issue. Notes in hostos/context/Dockerfile    
    usermod -p '!!' systemd-timesync && \
    usermod -p '!!' systemd-coredump

# Set /bin/sh to point to /bin/bash instead of the default /bin/dash
RUN echo "set dash/sh false" | debconf-communicate && dpkg-reconfigure -fnoninteractive dash

# Group accounts to which parts of the runtime state are assigned such that
# user accounts can be granted individual access rights.
# Note that a group "backup" already exists and is used for the purpose of
# allowing backup read access.
RUN addgroup --system nonconfidential && \
    addgroup --system confidential && \
    addgroup --system vsock

# User which will run the replica service.
RUN adduser --system --disabled-password --home /var/lib/ic --group --no-create-home ic-replica && \
    adduser ic-replica backup && \
    adduser ic-replica nonconfidential && \
    adduser ic-replica confidential && \
    adduser ic-replica vsock && \
    adduser ic-replica sudo

# Accounts to allow remote access to state bits

# The "backup" user account. We simply use the existing "backup" account and
# reconfigure it for our purposes.
RUN chsh -s /bin/bash backup && \
    mkdir /var/lib/backup && \
    chown backup:backup /var/lib/backup && \
    usermod -d /var/lib/backup backup && \
    adduser backup systemd-journal

# The "read-only" user account.
RUN adduser --system --disabled-password --home /var/lib/readonly --shell /bin/bash readonly && \
    adduser readonly backup && \
    adduser readonly nonconfidential && \
    adduser readonly systemd-journal

# The omnipotent "admin" account. May read everything and crucially can also
# arbitrarily change system state via sudo.
RUN adduser --system --disabled-password --home /var/lib/admin --shell /bin/bash admin && \
    chown admin:staff /var/lib/admin && \
    adduser admin backup && \
    adduser admin nonconfidential && \
    adduser admin systemd-journal && \
    adduser admin vsock && \
    adduser admin sudo

# The "node_exporter" account. Used to run node_exporter binary to export
# telemetry metrics of the GuestOS.
RUN addgroup node_exporter && \
    adduser --system --disabled-password --shell /usr/sbin/nologin -c "Node Exporter" node_exporter && \
    adduser node_exporter node_exporter && \
    chown root:root /etc/node_exporter \
                    /usr/local/bin/node_exporter && \
    chmod 0755 /etc/node_exporter \
               /usr/local/bin/node_exporter && \
    chmod 0644 /etc/default/node_exporter \
               /etc/node_exporter/web.yml

# User which will run the metrics proxy service.
# Needs access to the node exporter SSL certificate private key,
# stored in /etc/node_exporter.
RUN adduser --system --disabled-password --home /var/lib/metrics-proxy --group --no-create-home metrics-proxy && \
    usermod -a -G node_exporter metrics-proxy

# ------ INSTALL SCRIPTS -----------------------------------------

# Install IC binaries and other data late -- this means everything above
# will be cached when only the binaries change.
COPY opt /opt

# Update POSIX permissions in /opt/ic/
RUN chown root:root /opt
RUN find /opt -type d -exec chmod 0755 {} \+ && \
    find /opt -type f -exec chmod 0644 {} \+ && \
    chmod 0755 /opt/ic/bin/* && \
    chmod 0644 /opt/ic/share/*
