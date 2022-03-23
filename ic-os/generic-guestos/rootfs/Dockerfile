# GenericOS - Main Docker Image
#
# Build steps:
# - `docker build --pull -t dfinity/genericos-main -f Dockerfile .`
#
# First build stage:
# - Construct the actual target image (IC-OS root filesystem)
#
# Update below image when new dfinity/genericos-base image gets produced (see deploy-guest-os-baseimg CI job on master/rc).
FROM dfinity/genericos-base@sha256:058e1ad7c8de4a482416eac322497b9aa44452a606b407aa4ca5d3cb7edaf27c

RUN mkdir -p /boot/{efi,grub}

COPY /etc /etc
COPY /opt /opt

# Update POSIX permissions in /etc/
RUN find /etc -type d -exec chmod 0755 {} \+ && \
    find /etc -type f -not -path "/etc/hostname" -not -path "/etc/hosts" -not -path "/etc/resolv.conf" -exec chmod 0644 {} \+

# Regenerate initramfs (config changed after copying in /etc)
RUN RESUME=none SOURCE_DATE_EPOCH=0 update-initramfs -c -k all

ARG ROOT_PASSWORD=
RUN if [ "${ROOT_PASSWORD}" != "" ]; then echo "root:${ROOT_PASSWORD}" | chpasswd ; fi

# Delete generated ssh keys, otherwise every host will have the same key pair.
# They will be generated on first boot.
RUN rm /etc/ssh/ssh*key*
# Allow root login only via keys. In prod deployments there are never any
# keys set up for root, but in dev deployments there may be.
# Actually, prohibit-password is the default config, so would not be
# strictly necessary to be explicit here.
RUN sed -e "s/.*PermitRootLogin.*/PermitRootLogin prohibit-password/" -i /etc/ssh/sshd_config

# Mount points for config storage.
RUN mkdir -p /var/lib/ic/data

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

# User which will run the dfinity boundary node service.
RUN adduser --system --disabled-password --home /var/lib/ic --no-create-home dfinity

# Group accounts to which parts of the runtime state are assigned such that
# user accounts can be granted individual access rights.
# Note that a group "backup" already exists and is used for the purpose of
# allowing backup read access.
RUN addgroup --system nonconfidential && \
    addgroup --system confidential && \
    addgroup --system vsock

# The "read-only" user account. May read everything besides crypto.
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

# Delete generated ssh keys, otherwise every host will have the same key pair.
# They will be generated on first boot.
# Allow root login via default password (for now).
# RUN rm /etc/ssh/ssh*key*
# RUN sed -e "s/.*PermitRootLogin.*/PermitRootLogin yes/" -i /etc/ssh/sshd_config

RUN chmod 0440 /etc/sudoers

# Compile locale specification
RUN apt-get -y update && apt-get -y --no-install-recommends install locales
RUN localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
