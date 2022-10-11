# HostOS - Main Docker Image
#
# Build steps:
# - `docker build --pull -t dfinity/hostos-main -f Dockerfile .`
#

#
# First build stage:
# - Construct the actual target image (IC-OS root filesystem)
#
# Update below image when new dfinity/hostos-base image gets produced (see deploy-host-os-baseimg CI job on master/rc).
FROM dfinity/hostos-base@sha256:f744cac1e9f7110ed46defa6ab3877dfd8dac9881f153af6898dab9c3ad2f3cd

USER root:root

RUN mkdir -p /boot/config \
             /boot/efi \
             /boot/grub
COPY etc /etc

# Update POSIX permissions in /etc/
RUN find /etc -type d -exec chmod 0755 {} \+ && \
    find /etc -type f -not -path "/etc/hostname" -not -path "/etc/hosts" -not -path "/etc/resolv.conf" -exec chmod 0644 {} \+ && \
    chmod 0755 /etc/systemd/system-generators/mount-generator && \
    chmod 0440 /etc/sudoers && \
    chmod 755 /etc/initramfs-tools/scripts/init-bottom/set-machine-id

# Deactivate motd, it tries creating $HOME/.cache/motd.legal-displayed,
# but we want to prohibit it from writing to user home dirs
RUN sed -e '/.*pam_motd.so.*/d' -i /etc/pam.d/login && \
    sed -e '/.*pam_motd.so.*/d' -i /etc/pam.d/sshd

# Deactivate lvm backup/archive: It writes backup information to /etc/lvm, but a) this is
# per system (so backups are not persisted across upgrades) and thus not very
# useful, and b) we want to turn /etc read-only eventually. So simply suppress
# generating backups.
RUN sed -e 's/\(backup *= *\)1/\10/' -e 's/\(archive *= *\)1/\10/' -i /etc/lvm/lvm.conf

# Deactivate systemd userdb. We don't use it.
RUN sed -e 's/ *systemd//' -i /etc/nsswitch.conf

# Regenerate initramfs (config changed after copying in /etc)
RUN RESUME=none update-initramfs -c -k all

ARG ROOT_PASSWORD=
RUN \
    if [ "${ROOT_PASSWORD}" != "" ]; then \
        echo "root:$(openssl passwd -6 -salt jE8zzDEHeRg/DuGq ${ROOT_PASSWORD})" | chpasswd -e ; \
    fi

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

# All of the above sets up the base operating system. Everything below relates
# to node operation.

RUN \
    for SERVICE in /etc/systemd/system/*; do \
        if [ -f "$SERVICE" -a ! -L "$SERVICE" ]; then systemctl enable "${SERVICE#/etc/systemd/system/}" ; fi ; \
    done

RUN systemctl enable \
    chrony \
    libvirtd \
    nftables \
    systemd-journal-gatewayd \
    systemd-networkd \
    systemd-networkd-wait-online \
    systemd-resolved

# Add user/group entries specified here: /usr/lib/sysusers.d/systemd.conf E.g., systemd-timesync/coredump
RUN faketime "1970-1-1 0" systemd-sysusers

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

# The "journalbeat" account. Used to run journalbeat binary to send logs of the
# GuestOS.
RUN addgroup journalbeat && \
    adduser --system --disabled-password --shell /usr/sbin/nologin -c "Journalbeat" journalbeat && \
    adduser journalbeat journalbeat && \
    adduser journalbeat systemd-journal && \
    chown root:root /etc/journalbeat/*.yml \
                    /usr/local/bin/journalbeat && \
    chown journalbeat:journalbeat /var/lib/journalbeat \
                                  /var/log/journalbeat && \
    chmod 0755 /etc/journalbeat && \
    chmod 0750 /var/lib/journalbeat \
               /var/log/journalbeat && \
    chmod 0644 /etc/journalbeat/*.yml

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

# Compile locale specification
RUN localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8

# Clear all files that may lead to indeterministic build.
RUN apt-get clean && \
    rm -rf \
        /var/cache/fontconfig/* /var/cache/ldconfig/aux-cache \
        /var/log/alternatives.log /var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log \
        /var/lib/apt/lists/* /var/lib/dbus/machine-id \
        /var/lib/initramfs-tools/5.8.0-50-generic && \
    find /usr/local/share/fonts -name .uuid | xargs rm && \
    find /usr/share/fonts -name .uuid | xargs rm && \
    find /usr/lib/python3.8 -name "*.pyc" | xargs rm && \
    find /usr/lib/python3 -name "*.pyc" | xargs rm && \
    find /usr/share/python3 -name "*.pyc" | xargs rm && \
    truncate --size 0 /etc/machine-id

# Install IC binaries and other data late -- this means everything above
# will be cached when only the binaries change.
COPY opt /opt

# Update POSIX permissions in /opt/ic/
RUN chown root:root /opt
RUN find /opt -type d -exec chmod 0755 {} \+ && \
    find /opt -type f -exec chmod 0644 {} \+ && \
    chmod 0755 /opt/ic/bin/* && \
    chmod 0644 /opt/ic/share/*

COPY boot /boot
# Update POSIX permissions in /boot/
RUN chown root:root /boot
RUN chmod 0644 /boot/extra_boot_args /boot/version.txt
