# BoundarGuestOS - Main Docker Image
#
# Build step for exmaple:
# - `docker build --pull -t dfinity/boundaryos-main --build-arg BUILD_TYPE=dev --build-arg SW=true \ `
#   `--build-arg BASE_IMAGE=dfinity/boundaryos-base@sha256:af049f9896ecd9bfbd7129e0f6e12e673b72a6d2960beac76ac1a8fe07a62d3b -f Dockerfile .`
#
#
# The base images are defined in docker-base.prod and docker-base.dev. Update
# the references there when a new base image has been built. Note that this
# argument MUST be given by the build script, otherwise build will fail.
ARG BASE_IMAGE=

# We support prod and dev images
ARG BUILD_TYPE=

# Service worker version and sha256; only if SW is `true` the service worker from npm is used
ARG SW=
ARG sw_version=1.4.0
ARG sw_sha256=98d0cb03036f9b0bbe5664819082955195d5c42532efb033581ec2b8acac76e5

#
# First build stage: download software (service worker) that frequently changes, build and verify it (such that it
# does not change under our noses).
#
FROM $BASE_IMAGE AS download

USER root:root

WORKDIR /tmp

# Download and check service worker production version
# from: https://registry.npmjs.org/@dfinity/service-worker/-/
ARG sw_version
ARG sw_sha256
RUN \
   curl -L  https://registry.npmjs.org/@dfinity/service-worker/-/service-worker-${sw_version}.tgz -o service-worker.tgz && \
   echo "${sw_sha256}  service-worker.tgz" | shasum -c

# Download Nginx NJS Plugins
ARG NGINX_NJS_PLUGINS_PROJECT_ID=38466408
ARG NGINX_NJS_PLUGINS_REF_NAME=v1.0.0
ARG NGINX_NJS_PLUGINS_GITLAB_READ_ONLY_CI_TOKEN=glpat-2s2iXys15ZmVpgdxok58

RUN \
    curl -sL -o njs-plugin-is-bot.js \
        -H "Private-Token: ${NGINX_NJS_PLUGINS_GITLAB_READ_ONLY_CI_TOKEN}" \
        https://gitlab.com/api/v4/projects/${NGINX_NJS_PLUGINS_PROJECT_ID}/jobs/artifacts/${NGINX_NJS_PLUGINS_REF_NAME}/raw/dist/njs-plugin-is-bot.js?job=build-plugins && \
    echo "4cd35a7356469d5bf9d69cbce356c2135854a2e8e8dc45c2c855cd0e848861c77ea19ee80d530326fab8cf5abc684bd6e9b16678a7e2049f9a4aec5dd9ecb496  njs-plugin-is-bot.js" | shasum -c

#
# Second build stage:
# - Construct the actual target image (IC-OS root filesystem)
#
FROM $BASE_IMAGE

USER root:root

# Fetch and install npm ic service worker for production
COPY --from=download /tmp/service-worker.tgz /tmp/service-worker.tgz

ARG SW=
ARG BUILD_TYPE=
RUN if [ "$SW" = "true" ] ; then cd /tmp && tar xfvz service-worker.tgz &&\
    mkdir -p /var/www/html/ &&\
    cp -rf /tmp/package/dist-"$BUILD_TYPE"/* /var/www/html/ ; fi

RUN rm -rf /tmp/package /tmp/service-worker.tgz

RUN mkdir -p /boot/config \
             /boot/efi \
             /boot/grub

COPY etc /etc

# Install Nginx NJS Plugins
COPY --from=download \
    /tmp/njs-plugin-is-bot.js /etc/nginx/njs/

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
        if [ -f "$SERVICE" -a ! -L "$SERVICE" ] ; then systemctl enable "${SERVICE#/etc/systemd/system/}" ; fi ; \
    done && \
    systemctl enable \
    chrony \
    nftables \
    systemd-networkd \
    systemd-networkd-wait-online \
    systemd-resolved \
    systemd-journal-gatewayd

    # Add user/group entries specified here: /usr/lib/sysusers.d/systemd.conf
    # E.g., systemd-timesync/coredump
RUN faketime "1970-1-1 0" systemd-sysusers && \
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
    adduser --system --disabled-password --shell /usr/sbin/nologin -c "Vector" vector && \
    adduser vector vector

# The "node_exporter" account. Used to run node_exporter binary to export
# telemetry metrics of the GuestOS.
RUN addgroup node_exporter && \
    adduser --system --disabled-password --shell /usr/sbin/nologin -c "Node Exporter" node_exporter && \
    adduser node_exporter node_exporter && \
    # The "socks" account for socks proxy
    # Also set correct permissions for dante and stunnel.
    # Stunnel4 cannot be started as a systemctl service so starting it as `stunnel4 start`
    addgroup socks && \
    adduser --system --disabled-password --shell /usr/sbin/nologin -c "Socks" socks && \
    adduser socks socks && chmod +s /usr/sbin/danted && \
    chmod 0755 /etc/init.d/stunnel4 && \
    addgroup prober && \
    adduser --system --disabled-password --shell /usr/sbin/nologin -c "Prober" prober && \
    adduser prober prober && \
    mkdir -p /var/log/prober && \
    chown prober:prober /var/log/prober && \
    chmod 755 /var/log/prober

# Setup denylist-updater
RUN \
    addgroup denylist-updater && \
    adduser --system --disabled-password --shell /usr/sbin/nologin -c "denylist-updater" denylist-updater && \
    adduser denylist-updater denylist-updater && \
    mkdir -p /var/opt/nginx/denylist && \
    chown denylist-updater:denylist-updater /var/opt/nginx/denylist && \
    chmod 644 /var/opt/nginx/denylist

RUN \
    mkdir -p /var/opt/nginx/denylist && \
    chown denylist-updater:denylist-updater /var/opt/nginx/denylist && \
    chmod 644 /var/opt/nginx/denylist

# Install node_exporter
RUN chown root:root /etc/node_exporter \
                    /usr/local/bin/node_exporter && \
    chmod 0755 /etc/node_exporter \
               /usr/local/bin/node_exporter

# Install IC binaries and other data late -- this means everything above
# will be cached when only the binaries change.
COPY opt /opt

RUN rm -rf /etc/nginx/sites-enabled/nginx.conf

# Install ic service worker production version from: https://registry.npmjs.org/@dfinity/service-worker/-/
RUN mkdir -p /var/www/html && chown www-data:www-data /var/www/html

# Install other files (e.g. the uninstall-script)
COPY var/www/html /var/www/html
RUN chmod 0644 /var/www/html/*

# Install cgi-scripts
RUN mkdir -p /var/www/cgi-bin && \
    chown www-data:www-data /var/www/cgi-bin
COPY var/www/cgi-bin/* /var/www/cgi-bin/
RUN mkdir -p /var/www/cgi-bin/artifacts && \
    mkdir -p /var/www/cgi-bin/artifacts/certs && \
    chown www-data:www-data /var/www/cgi-bin/artifacts && \
    chown www-data:www-data /var/www/cgi-bin/artifacts/certs && \
    touch /var/www/cgi-bin/cgi.log && \
    chown www-data:www-data /var/www/cgi-bin/* && \
    chmod 0755 /var/www/cgi-bin/*

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

# Take care of nginx files
RUN chmod 0755 /etc/nginx/* && \
    chmod 0644 /etc/nginx/nginx.conf && \
    chmod 0644 /etc/nginx/modules-enabled/ngx_http_cbor_input_module.conf && \
    chmod 0644 /etc/nginx/modules-enabled/ngx_http_js_module.conf && \
    chmod 0755 /etc/nginx/ic/ic_router_control_plane_watcher.sh && \
    rm -rf /etc/nginx/conf.d/nginx-global.conf && \
    rm -rf /etc/nginx/conf.d/default.conf && \
    rm -rf /etc/nginx/sites-enabled/default && \
    rm -rf /etc/nginx/conf.d/default

# Configure incron
COPY etc/incron.tb /etc/incron.d/incron.tb
RUN echo root >> /etc/incron.allow
