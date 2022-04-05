
# Service worker verion and sha256
ARG sw_version=1.0.0
ARG sw_sha256=1e4d288888c493318970fa0134090a8b2539963c2f6e67a4d04b3a0546f3788e

# First build stage: download software, build and verify it (such that it
# does not change under our noses).
FROM ubuntu:20.04 AS download

ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt-get -y update && apt-get -y upgrade && apt-get -y --no-install-recommends install \
    ca-certificates \
    curl \
    pkg-config \
    libffi-dev \
    libssl-dev \
    ssl-cert \
    rustc \
    cargo \
    perl

# Download and verify journalbeat
RUN cd /tmp/ && \
    curl -L -O https://artifacts.elastic.co/downloads/beats/journalbeat/journalbeat-oss-7.5.1-linux-x86_64.tar.gz && \
    echo "b1c4c12a5ea8b0e95ed78243ad08dc6e82dc414186da8324d86833c5114846c6edf06590b45cf6c0f29f57e4631c4bf4163e0020d466cf3a2cb65910540f39c5  journalbeat-oss-7.5.1-linux-x86_64.tar.gz" > journalbeat.sha512 && \
    shasum -c journalbeat.sha512

# Download and verify node_exporter
RUN cd /tmp/ && \
    curl -L -O https://github.com/prometheus/node_exporter/releases/download/v1.3.1/node_exporter-1.3.1.linux-amd64.tar.gz && \
    echo "68f3802c2dd3980667e4ba65ea2e1fb03f4a4ba026cca375f15a0390ff850949  node_exporter-1.3.1.linux-amd64.tar.gz" > node_exporter.sha256 && \
    shasum -c node_exporter.sha256

# Download libnginx-mod-http-ndk.deb
RUN cd /tmp/ && \
   curl -L -O https://github.com/dfinity/nginx-module-cbor-input/releases/download/v0.0.9/libnginx-mod-http-ndk_0.3.1_amd64.deb && \
   echo "6a496d8c7f3357fda9e5adeb7a729e76c453f32c6d67bc0ec563b0f71e2a0aca  libnginx-mod-http-ndk_0.3.1_amd64.deb" > libnginx-mod-http-ndk.sha256 && \
   shasum -c  libnginx-mod-http-ndk.sha256

# Download libnginx-mod-http-cbor-input.deb
RUN cd /tmp/ && \
   curl -L -O https://github.com/dfinity/nginx-module-cbor-input/releases/download/v0.0.9/libnginx-mod-http-cbor-input_0.0.9_amd64.deb && \
   echo "8dca8fb93a6645c4aee23f601e9d9f62a00638ff29f95ceafcd10f422a3126f0  libnginx-mod-http-cbor-input_0.0.9_amd64.deb" > libnginx-mod-httpor-input.sha256 && \
   shasum -c  libnginx-mod-httpor-input.sha256


# Download icx-proxy.deb 
RUN cd /tmp/ && \
   curl -L -O https://github.com/dfinity/icx-proxy/releases/download/f289318/icx-proxy.deb && \
   echo "9b434ce9ec1cddb2caf5e6550d5b8bcebd225614809280233334187e088017a9  ./icx-proxy.deb" > icx-proxy.sha256 && \
   shasum -c icx-proxy.sha256

# Download and check service worker
ARG sw_version
ARG sw_sha256
RUN cd /tmp/ && \
   curl -L -O https://registry.npmjs.org/@dfinity/service-worker/-/service-worker-${sw_version}.tgz && \
   echo "${sw_sha256}  ./service-worker-${sw_version}.tgz" > sw.sha256 && \
   shasum -c sw.sha256

# Second build stage: construct the actual target image (root filesystem of the
# boundary node VM).
# The downloads from previous stage will be used and installed into the target
# image.
#
# Build steps:
# - `docker build --pull -t dfinity/boundaryos-main -f Dockerfile .`
#
# - Construct the actual target image (IC-OS root filesystem)
#
# Update below image when new dfinity/boundaryos-base image gets produced (see deploy-guest-os-baseimg CI job on master/rc).
FROM dfinity/boundaryos-base@sha256:aa6724deaf12f10fb4ec298adf86397d6fdd61bea950460eb7e0dc182505a647

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
    addgroup --system confidential

# Accounts to allow remote access to state bits

# The "backup" user account. We simply use the existing "backup" account and
# reconfigure it for our purposes.
RUN chsh -s /bin/bash backup && \
    mkdir /var/lib/backup && \
    chown backup:backup /var/lib/backup && \
    usermod -d /var/lib/backup backup && \
    adduser backup systemd-journal

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

# The "socks" account for socks proxy
# Also set correct permissions for dante and stunnel.
# Stunnel4 cannot be started as a systemctl service so starting it as `stunnel4 start`
RUN addgroup socks && \
    adduser --system --disabled-password --shell /usr/sbin/nologin -c "Socks" socks && \
    adduser socks socks && chmod +s /usr/sbin/danted && \
    chmod 0755 /etc/init.d/stunnel4

# Install journalbeat
COPY --from=download /tmp/journalbeat-oss-7.5.1-linux-x86_64.tar.gz /tmp/journalbeat-oss-7.5.1-linux-x86_64.tar.gz
RUN cd /tmp/ && \
    mkdir -p /etc/journalbeat \
             /var/lib/journalbeat \
             /var/log/journalbeat && \
    tar --strip-components=1 -C /etc/journalbeat/ -zvxf journalbeat-oss-7.5.1-linux-x86_64.tar.gz journalbeat-7.5.1-linux-x86_64/fields.yml && \
    tar --strip-components=1 -C /etc/journalbeat/ -zvxf journalbeat-oss-7.5.1-linux-x86_64.tar.gz journalbeat-7.5.1-linux-x86_64/journalbeat.reference.yml && \
    tar --strip-components=1 -C /usr/local/bin/ -zvxf journalbeat-oss-7.5.1-linux-x86_64.tar.gz journalbeat-7.5.1-linux-x86_64/journalbeat && \
    chown root:root /etc/journalbeat/*.yml \
                    /usr/local/bin/journalbeat && \
    chown journalbeat:journalbeat /var/lib/journalbeat \
                                  /var/log/journalbeat && \
    chmod 0755 /etc/journalbeat && \
    chmod 0750 /var/lib/journalbeat \
               /var/log/journalbeat && \
    chmod 0644 /etc/journalbeat/*.yml && \
    rm /tmp/journalbeat-oss-7.5.1-linux-x86_64.tar.gz

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

# Install IC binaries and other data late -- this means everything above
# will be cached when only the binaries change.
COPY opt /opt

RUN rm -rf /etc/nginx/sites-enabled/nginx.conf

# Install libnginx-mod-http-ndk 
COPY --from=download /tmp/libnginx-mod-http-ndk_0.3.1_amd64.deb /tmp/
RUN dpkg -i /tmp/libnginx-mod-http-ndk_0.3.1_amd64.deb &&\
    rm /tmp/libnginx-mod-http-ndk_0.3.1_amd64.deb

# Install libnginx-mod-http-cbor-input
COPY --from=download /tmp/libnginx-mod-http-cbor-input_0.0.9_amd64.deb /tmp/libnginx-mod-http-cbor-input_0.0.9_amd64.deb
RUN dpkg -i /tmp/libnginx-mod-http-cbor-input_0.0.9_amd64.deb &&\
    rm /tmp/libnginx-mod-http-cbor-input_0.0.9_amd64.deb

# Install icx-proxy
COPY --from=download /tmp/icx-proxy.deb /tmp/icx-proxy.deb
RUN dpkg -i /tmp/icx-proxy.deb &&\
    rm /tmp/icx-proxy.deb

# Install ic service worker porduction version from: https://registry.npmjs.org/@dfinity/service-worker/-/
ARG sw_version
COPY --from=download /tmp/service-worker-${sw_version}.tgz /tmp/service-worker-${sw_version}.tgz
RUN cd /tmp && tar xfvz service-worker-${sw_version}.tgz &&\
    mkdir -p /var/www/html/service_worker &&\
    cp -rf /tmp/package/dist-prod/* /var/www/html/service_worker/ &&\
    rm -rf /tmp/package /tmp/service-worker-${sw_version}.tgz
RUN chown www-data:www-data /var/www/html && \
    chmod 0755 /var/www/html/*
# Install other files (e.g. the uninstall-script)
COPY var/www/html /var/www/html

# Clear all files that may lead to indeterministic build.
RUN apt-get clean && \
    rm -rf \
        /var/cache/fontconfig/* /var/cache/ldconfig/aux-cache \
        /var/log/alternatives.log /var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log \
        /var/lib/apt/lists/* /var/lib/dbus/machine-id \
        /var/lib/initramfs-tools/5.8.0-50-generic && \
    find /usr/local/share/fonts -name .uuid | xargs rm && \
    find /usr/share/fonts -name .uuid | xargs rm && \
    find /usr/lib -name "*.pyc" | xargs rm -rf&& \
    find /usr/share -name "*.pyc" | xargs rm -rf&& \
    truncate --size 0 /etc/machine-id

# Update POSIX permissions in /opt/ic/
RUN find /opt -type d -exec chmod 0755 {} \+ && \
    find /opt -type f -exec chmod 0644 {} \+ && \
    chmod 0755 /opt/ic/bin/* && \
    chmod 0644 /opt/ic/share/*

COPY boot /boot
# Update POSIX permissions in /boot/
RUN chmod 0644 /boot/extra_boot_args /boot/version.txt



# CERTIFICATES
# Default image has
# 1. fullchain.pem: self signed certificates from the ssl-cert package.
# 2. privkey.pem: key for the self signed certificate.
# 3. chain.pem: Dummy certficate of the issuer for OCSP stapling to work.
#    This cert is irrelevant because the certificate is self signed.
#
# Prod image
#
# Has the above 3 certificates in /boot/config/cert. The setup-nginx service
# copies over the certificates in the correct location to match the nginx conf
# file
#
# The naming convetion is the same a certificates generated by certbot renew
RUN mkdir -p /etc/nginx/certs
RUN mkdir -p /etc/nginx/keys
RUN cp /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/nginx/certs/fullchain.pem
RUN cp /etc/ssl/private/ssl-cert-snakeoil.key /etc/nginx/keys/privkey.pem
RUN cp /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/nginx/certs/chain.pem


# trusted_cert.pem contains all certificates for the upstream replica. This file
# is periodically updated by the proxy+watcher service. To bootstrap the process
# we initially place a dummy trusted cert. This dummy is the copy of the
# snakeoil cert. This allows the nginx service to start, but upstream routing
# will only happen once the control plane pulls the initial set of routes
#
RUN cp /etc/nginx/certs/fullchain.pem /etc/nginx/ic/trusted_certs.pem

# Take care of nginx files
RUN chmod 0755 /etc/nginx/*
RUN chmod 0644 /etc/nginx/ic_public_key.pem
RUN chmod 0644 /etc/nginx/nginx.conf
RUN chmod 0644 /etc/nginx/modules-enabled/ngx_http_cbor_input_module.conf
RUN chmod 0644 /etc/nginx/modules-enabled/ngx_http_js_module.conf
RUN chmod 0755 /etc/nginx/ic/ic_router_control_plane_watcher.sh
RUN rm -rf /etc/nginx/conf.d/nginx-global.conf
RUN rm -rf /etc/nginx/conf.d/default.conf
RUN rm -rf /etc/nginx/sites-enabled/default
RUN rm -rf /etc/nginx/conf.d/default
