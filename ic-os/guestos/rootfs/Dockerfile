# GuestOS - Main Docker Image
#
# Build steps:
# - `docker build --pull -t dfinity/guestos-main -f Dockerfile .`
#
# First build stage:
# - Download 3rd party tools
#

# The base images are defined in docker-base.prod and docker-base.dev. Update
# the references there when a new base image has been built. Note that this
# argument MUST be given by the build script, otherwise build will fail.
ARG BASE_IMAGE=

FROM ubuntu:20.04 as download

ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt-get -y update && apt-get -y upgrade && apt-get -y --no-install-recommends install \
    ca-certificates \
    curl \
    perl

# Download and verify journalbeat
RUN cd /tmp/ && \
    curl -L -O https://artifacts.elastic.co/downloads/beats/journalbeat/journalbeat-oss-7.14.0-linux-x86_64.tar.gz && \
    echo "3c97e8706bd0d2e30678beee7537b6fe6807cf858a0dd2e7cfce5beccb621eb0fefe6871027bc7b55e2ea98d7fe2ca03d4d92a7b264abbb0d6d54ecfa6f6a305  journalbeat-oss-7.14.0-linux-x86_64.tar.gz" > journalbeat.sha512 && \
    shasum -c journalbeat.sha512

# Download and verify node_exporter
RUN cd /tmp/ && \
    curl -L -O https://github.com/prometheus/node_exporter/releases/download/v1.3.1/node_exporter-1.3.1.linux-amd64.tar.gz && \
    echo "68f3802c2dd3980667e4ba65ea2e1fb03f4a4ba026cca375f15a0390ff850949  node_exporter-1.3.1.linux-amd64.tar.gz" > node_exporter.sha256 && \
    shasum -c node_exporter.sha256

#
# Second build stage:
# - Construct the actual target image (IC-OS root filesystem)
# - Copy downloaded archives from first build stage into the target image
#
FROM $BASE_IMAGE

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

# Divert symbolic link for dynamically generated nftables
# ruleset.
RUN ln -sf /run/ic-node/nftables-ruleset/nftables.conf /etc/nftables.conf

# Regenerate initramfs (config changed after copying in /etc)
RUN RESUME=none update-initramfs -c -k all

ARG ROOT_PASSWORD=
RUN \
    if [ "${ROOT_PASSWORD}" != "" ]; then \
        echo "root:$(openssl passwd -6 -salt jE8zzDEHeRg/DuGq ${ROOT_PASSWORD})" | chpasswd -e ; \
    fi

# Prepare for bind mount of authorized_keys
RUN mkdir -p /root/.ssh && chmod 0700 /root/.ssh

COPY prep /prep
RUN cd /prep && ./prep.sh && cd / && rm -rf /prep

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

# Mount points for data storage.
RUN mkdir -p /var/lib/ic/backup \
             /var/lib/ic/crypto \
             /var/lib/ic/data

RUN \
    for SERVICE in /etc/systemd/system/*; do \
        if [ -f "$SERVICE" -a ! -L "$SERVICE" ] ; then systemctl enable "${SERVICE#/etc/systemd/system/}" ; fi ; \
    done

RUN systemctl enable \
    chrony \
    nftables \
    systemd-networkd \
    systemd-networkd-wait-online \
    systemd-resolved \
    systemd-journal-gatewayd

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
    addgroup --system vsock && \
    addgroup --system ic-registry-local-store

# User which will run the replica service.
RUN adduser --system --disabled-password --home /var/lib/ic --group --no-create-home ic-replica && \
    adduser ic-replica backup && \
    adduser ic-replica nonconfidential && \
    adduser ic-replica confidential && \
    adduser ic-replica ic-registry-local-store && \
    adduser ic-replica vsock && \
    adduser ic-replica sudo

# Accounts to allow remote access to state bits

# The "backup" user account. We simply use the existing "backup" account and
# reconfigure it for our purposes.
RUN chsh -s /bin/bash backup && \
    mkdir /var/lib/backup && \
    chown backup:backup /var/lib/backup && \
    usermod -d /var/lib/backup backup && \
    adduser backup systemd-journal && \
    adduser backup ic-registry-local-store

# The "read-only" user account. May read everything besides crypto.
RUN adduser --system --disabled-password --home /var/lib/readonly --shell /bin/bash readonly && \
    adduser readonly backup && \
    adduser readonly nonconfidential && \
    adduser readonly systemd-journal && \
    adduser readonly ic-registry-local-store

# The omnipotent "admin" account. May read everything and crucially can also
# arbitrarily change system state via sudo.
RUN adduser --system --disabled-password --home /var/lib/admin --shell /bin/bash admin && \
    chown admin:staff /var/lib/admin && \
    adduser admin backup && \
    adduser admin nonconfidential && \
    adduser admin ic-registry-local-store && \
    adduser admin systemd-journal && \
    adduser admin vsock && \
    adduser admin sudo

# The "journalbeat" account. Used to run journalbeat binary to send logs of the
# GuestOS.
RUN addgroup journalbeat && \
    adduser --system --disabled-password --shell /usr/sbin/nologin -c "Journalbeat" journalbeat && \
    adduser journalbeat journalbeat && \
    adduser journalbeat systemd-journal

# The "node_exporter" account. Used to run node_exporter binary to export
# telemetry metrics of the GuestOS.
RUN addgroup node_exporter && \
    adduser --system --disabled-password --shell /usr/sbin/nologin -c "Node Exporter" node_exporter && \
    adduser node_exporter node_exporter

# Install journalbeat
COPY --from=download /tmp/journalbeat-oss-7.14.0-linux-x86_64.tar.gz /tmp/journalbeat-oss-7.14.0-linux-x86_64.tar.gz
RUN cd /tmp/ && \
    mkdir -p /etc/journalbeat \
             /var/lib/journalbeat \
             /var/log/journalbeat && \
    tar --strip-components=1 -C /etc/journalbeat/ -zvxf journalbeat-oss-7.14.0-linux-x86_64.tar.gz journalbeat-7.14.0-linux-x86_64/fields.yml && \
    tar --strip-components=1 -C /etc/journalbeat/ -zvxf journalbeat-oss-7.14.0-linux-x86_64.tar.gz journalbeat-7.14.0-linux-x86_64/journalbeat.reference.yml && \
    tar --strip-components=1 -C /usr/local/bin/ -zvxf journalbeat-oss-7.14.0-linux-x86_64.tar.gz journalbeat-7.14.0-linux-x86_64/journalbeat && \
    chown root:root /etc/journalbeat/*.yml \
                    /usr/local/bin/journalbeat && \
    chown journalbeat:journalbeat /var/lib/journalbeat \
                                  /var/log/journalbeat && \
    chmod 0755 /etc/journalbeat && \
    chmod 0750 /var/lib/journalbeat \
               /var/log/journalbeat && \
    chmod 0644 /etc/journalbeat/*.yml && \
    rm /tmp/journalbeat-oss-7.14.0-linux-x86_64.tar.gz

# Install node_exporter
COPY --from=download /tmp/node_exporter-1.3.1.linux-amd64.tar.gz /tmp/node_exporter-1.3.1.linux-amd64.tar.gz
RUN cd /tmp/ && \
    mkdir -p /etc/node_exporter && \
    tar --strip-components=1 -C /usr/local/bin/ -zvxf node_exporter-1.3.1.linux-amd64.tar.gz node_exporter-1.3.1.linux-amd64/node_exporter && \
    chown root:root /etc/node_exporter \
                    /usr/local/bin/node_exporter && \
    chmod 0755 /etc/node_exporter \
               /usr/local/bin/node_exporter && \
    chmod 0644 /etc/default/node_exporter \
               /etc/node_exporter/web.yml && \
    rm /tmp/node_exporter-1.3.1.linux-amd64.tar.gz

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
RUN find /opt -type d -exec chmod 0755 {} \+ && \
    find /opt -type f -exec chmod 0644 {} \+ && \
    chmod 0755 /opt/ic/bin/* && \
    chmod 0644 /opt/ic/share/*

COPY boot /boot
# Update POSIX permissions in /boot/
RUN chmod 0644 /boot/extra_boot_args /boot/version.txt
