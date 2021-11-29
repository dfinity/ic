ARG UBUNTU_ROOTFS
FROM ${UBUNTU_ROOTFS}

# Copy in some config settings for the container -- particularly, a
# deterministic set of ssh keys to avoid annoyances like key changes during
# development.

COPY etc /etc
RUN chmod 400 /etc/ssh/ssh_host*key ; chmod 444 /etc/ssh/ssh_host*key.pub

# Remove everything related to filesystem mounts and encrypted filesystem setup.
# This would fail the boot when run as a docker container.
RUN rm -rf /etc/fstab /etc/systemd/system-generators /etc/crypttab

# Disable all our newly installed services that are going to fail unless run on
# a VM (i.e. all those that set up filesystem mounts etc.).
# Leave the replica service for bootstrap and running the node intact.
# Also don't touch system-installed services (they exist as symbolic
# links in the same directory).
RUN for file in /etc/systemd/system/*.service ; do \
    svc="${file#/etc/systemd/system/}" ; \
    if [ "${svc}" != "ic-replica.service" -a "${svc}" != "bootstrap-ic-node.service" -a ! -L "/etc/systemd/system/${svc}" ]; then \
        systemctl disable "$svc" ; rm "/etc/systemd/system/${svc}" ; \
    fi ; \
    done

# Remove dependency on this service -- it is not started in container.
RUN sed -e '/\(After\|Wants\)=systemd-networkd-wait-online/d' -i /etc/systemd/system/ic-replica.service

ENTRYPOINT [ "/lib/systemd/systemd" ]
