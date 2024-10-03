#!/bin/bash

# GuestOS - Main setup script

source "/icos_build/build_utils.sh"

set -euo pipefail

export SOURCE_DATE_EPOCH=0
export PATH=$PATH:/usr/sbin

mkdir -p /boot/config \
             /boot/efi \
             /boot/grub

copy_component /etc
copy_component /opt

# Deactivate motd, it tries creating $HOME/.cache/motd.legal-displayed,
# but we want to prohibit it from writing to user home dirs
sed -e '/.*pam_motd.so.*/d' -i /etc/pam.d/login && \
  sed -e '/.*pam_motd.so.*/d' -i /etc/pam.d/sshd

# Deactivate lvm backup/archive: It writes backup information to /etc/lvm,
# but this is per system (so backups are not persisted across upgrades)
# and thus not very useful, and /etc is read-only.
# So simply suppress generating backups.
sed -e 's/\(# \)\?\(backup *= *\)[01]/\20/' -e 's/\(# \)\?\(archive *= *\)[01]/\20/' -i /etc/lvm/lvm.conf

# Deactivate systemd userdb. We don't use it.
sed -e 's/ *systemd//' -i /etc/nsswitch.conf

# Clear files that may lead to indeterministic build.

find /usr/lib/python3.12 -name "*.pyc" | xargs rm
find /usr/lib/python3 -name "*.pyc" | xargs rm
find /usr/share/python3 -name "*.pyc" | xargs rm
truncate --size 0 /etc/machine-id

# ------ NEAR-COMMON ICOS WORK ----------------------------------------

# Update POSIX permissions in /etc/
# TODO: We overwrite all /etc files with 644 except for the specified.
# See [NODE-1348] for context.
find /etc -type d -exec chmod 0755 {} \+ && \
  find /etc -type f -exec chmod 0644 {} \+ && \
  chmod 0755 /etc/systemd/system-generators/* && \
  chmod 0755 /etc/init.d/* && \
  chmod 0440 /etc/sudoers && \
  chmod 755 /etc/initramfs-tools/scripts/init-bottom/set-machine-id && \
  chmod 755 /etc/initramfs-tools/scripts/init-premount/verity-root && \
  chmod 755 /etc/initramfs-tools/hooks/veritysetup

# Regenerate initramfs (config changed after copying in /etc)
RESUME=none update-initramfs -c -k all

copy_component /prep
cd /prep && ./prep.sh && cd / && rm -rf /prep

# Activate the NSS IC OS Name Service Switch plugin.
# See /rs/ic_os/nss_icos/README.md for context.
sed -r -e 's/hosts:( *)files/hosts:\1files icos/' -i /etc/nsswitch.conf

# Prepare for bind mount of authorized_keys
mkdir -p /root/.ssh && chmod 0700 /root/.ssh

# Delete generated ssh keys, otherwise every host will have the same key pair.
# They will be generated on first boot.
rm /etc/ssh/ssh*key*
# Allow root login only via keys. In prod deployments there are never any
# keys set up for root, but in dev deployments there may be.
# Actually, prohibit-password is the default config, so would not be
# strictly necessary to be explicit here.
sed -e "s/.*PermitRootLogin.*/PermitRootLogin prohibit-password/" -i /etc/ssh/sshd_config

for SERVICE in /etc/systemd/system/*; do \
    if [ -f "$SERVICE" ] && [ ! -L "$SERVICE" ] && ! echo "$SERVICE" | grep -Eq "@\.service$"; then \
        systemctl enable "${SERVICE#/etc/systemd/system/}"; \
    fi ; \
done

systemctl enable \
  chrony \
  nftables \
  ssh \
  systemd-networkd \
  systemd-networkd-wait-online \
  systemd-resolved \
  systemd-journal-gatewayd

systemctl disable \
  apt-daily.service \
  apt-daily.timer \
  apt-daily-upgrade.service \
  apt-daily-upgrade.timer \
  motd-news.service \
  motd-news.timer \
  fstrim.service \
  fstrim.timer

# ------ GUESTOS WORK --------------------------------------------

# Divert symbolic link for dynamically generated nftables
# ruleset.
ln -sf /run/ic-node/nftables-ruleset/nftables.conf /etc/nftables.conf

# Mount points for data storage.
mkdir -p /var/lib/ic/backup \
         /var/lib/ic/crypto \
         /var/lib/ic/data

# Create two mount points for temporary use during setup of "var" partition
mkdir -p /mnt/var_old /mnt/var_new


# Set /bin/sh to point to /bin/bash instead of the default /bin/dash
ln -sf /bin/bash /usr/bin/sh

# Group accounts to which parts of the runtime state are assigned such that
# user accounts can be granted individual access rights.
# Note that a group "backup" already exists and is used for the purpose of
# allowing backup read access.
addgroup --system nonconfidential && \
  addgroup --system ic-csp-vault-socket && \
  addgroup --system vsock && \
  addgroup --system ic-registry-local-store

# The "ic-csp-vault" account. Used to run `ic-crypto-csp` binary and access the crypto key material.
addgroup ic-csp-vault && \
  adduser --system --disabled-password --shell /usr/sbin/nologin -c "IC crypto CSP vault" ic-csp-vault && \
  adduser ic-csp-vault ic-csp-vault && \
  adduser ic-csp-vault ic-csp-vault-socket

# The "ic-http-adapter" account. Used to run `ic-https-outcalls-adapter` binary
# to allow nodes to make HTTP calls.
addgroup ic-http-adapter && \
  adduser --system --disabled-password --shell /usr/sbin/nologin -c "IC Canister HTTP Adapter" ic-http-adapter && \
  adduser ic-http-adapter ic-http-adapter

# User which will run the replica service.
adduser --system --disabled-password --home /var/lib/ic --group --no-create-home ic-replica && \
  adduser ic-replica backup && \
  adduser ic-replica ic-csp-vault-socket && \
  adduser ic-replica nonconfidential && \
  adduser ic-replica ic-registry-local-store && \
  adduser ic-replica ic-http-adapter && \
  adduser ic-replica vsock

# Accounts to allow remote access to state bits

# The "backup" user account. We simply use the existing "backup" account and
# reconfigure it for our purposes.
chsh -s /bin/bash backup && \
  mkdir /var/lib/backup && \
  chown backup:backup /var/lib/backup && \
  usermod -d /var/lib/backup backup && \
  adduser backup systemd-journal && \
  adduser backup ic-registry-local-store

# The "read-only" user account. May read everything besides crypto.
adduser --system --disabled-password --home /var/lib/readonly --shell /bin/bash readonly && \
  adduser readonly backup && \
  adduser readonly nonconfidential && \
  adduser readonly systemd-journal && \
  adduser readonly ic-registry-local-store

# The omnipotent "admin" account. May read everything and crucially can also
# arbitrarily change system state via sudo.
adduser --system --disabled-password --home /var/lib/admin --shell /bin/bash admin && \
  chown admin:staff /var/lib/admin && \
  adduser admin backup && \
  adduser admin nonconfidential && \
  adduser admin ic-registry-local-store && \
  adduser admin systemd-journal && \
  adduser admin vsock && \
  adduser admin sudo

# The "filebeat" account. Used to run filebeat binary to send logs of the
# GuestOS.
addgroup filebeat && \
  adduser --system --disabled-password --shell /usr/sbin/nologin -c "Filebeat" filebeat && \
  adduser filebeat filebeat && \
  adduser filebeat systemd-journal && \
  chown root:root /usr/local/bin/filebeat

# The "node_exporter" account. Used to run node_exporter binary to export
# telemetry metrics of the GuestOS.
addgroup node_exporter && \
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
adduser --system --disabled-password --home /var/lib/metrics-proxy --group --no-create-home metrics-proxy && \
  usermod -a -G node_exporter metrics-proxy

# ------ INSTALL SCRIPTS -----------------------------------------

# Update POSIX permissions in /opt/ic/
find /opt -type d -exec chmod 0755 {} \+ && \
  find /opt -type f -exec chmod 0644 {} \+ && \
  chmod 0755 /opt/ic/bin/* && \
  chmod 0644 /opt/ic/share/*

# ------ DEV VARIANT ---------------------------------------------

if [[ $BUILD_TYPE != 'dev' ]]; then
  exit
fi

# Set a root password if specified
if [ "$ROOT_PASSWORD" != "" ]; then
    echo "root:$(openssl passwd -6 -salt jE8zzDEHeRg/DuGq $ROOT_PASSWORD)" | chpasswd -e
fi

# Include the dev root CA cert
copy_component dev-certs/canister_http_test_ca.cert /usr/local/share/ca-certificates/dev-root-ca.crt
chmod 0644 /usr/local/share/ca-certificates/dev-root-ca.crt
update-ca-certificates
