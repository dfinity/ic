"""
Enumerate every component file dependency for HostOS
"""

component_files = {
    # hostos-scripts
    Label("hostos-scripts/generate-guestos-config/generate-guestos-config.sh"): "/opt/ic/bin/generate-guestos-config.sh",
    Label("hostos-scripts/generate-guestos-config/generate-guestos-config.service"): "/etc/systemd/system/generate-guestos-config.service",
    Label("hostos-scripts/guestos/guestos.service"): "/etc/systemd/system/guestos.service",
    Label("hostos-scripts/guestos/start-guestos.sh"): "/opt/ic/bin/start-guestos.sh",
    Label("hostos-scripts/guestos/stop-guestos.sh"): "/opt/ic/bin/stop-guestos.sh",
    Label("hostos-scripts/guestos/guestos.xml.template"): "/opt/ic/share/guestos.xml.template",
    Label("hostos-scripts/guestos/kvm-cpu.xml"): "/opt/ic/share/kvm-cpu.xml",
    Label("hostos-scripts/guestos/qemu-cpu.xml"): "/opt/ic/share/qemu-cpu.xml",
    Label("hostos-scripts/libvirt/setup-libvirt.sh"): "/opt/ic/bin/setup-libvirt.sh",
    Label("hostos-scripts/libvirt/setup-libvirt.service"): "/etc/systemd/system/setup-libvirt.service",
    Label("hostos-scripts/misc/setup-var.sh"): "/opt/ic/bin/setup-var.sh",
    Label("hostos-scripts/misc/fetch-mgmt-mac.sh"): "/opt/ic/bin/fetch-mgmt-mac.sh",
    Label("hostos-scripts/misc/detect-first-boot.sh"): "/opt/ic/bin/detect-first-boot.sh",
    Label("hostos-scripts/monitoring/monitor-guestos.sh"): "/opt/ic/bin/monitor-guestos.sh",
    Label("hostos-scripts/monitoring/monitor-guestos.service"): "/etc/systemd/system/monitor-guestos.service",
    Label("hostos-scripts/monitoring/monitor-guestos.timer"): "/etc/systemd/system/monitor-guestos.timer",
    Label("hostos-scripts/monitoring/monitor-nvme.sh"): "/opt/ic/bin/monitor-nvme.sh",
    Label("hostos-scripts/monitoring/monitor-nvme.service"): "/etc/systemd/system/monitor-nvme.service",
    Label("hostos-scripts/monitoring/monitor-nvme.timer"): "/etc/systemd/system/monitor-nvme.timer",
    Label("hostos-scripts/monitoring/monitor-power.sh"): "/opt/ic/bin/monitor-power.sh",
    Label("hostos-scripts/monitoring/monitor-power.service"): "/etc/systemd/system/monitor-power.service",
    Label("hostos-scripts/monitoring/monitor-power.timer"): "/etc/systemd/system/monitor-power.timer",
    Label("hostos-scripts/build-bootstrap-config-image.sh"): "/opt/ic/bin/build-bootstrap-config-image.sh",
    Label("hostos-scripts/verbose-logging/verbose-logging.sh"): "/opt/ic/bin/verbose-logging.sh",
    Label("hostos-scripts/verbose-logging/verbose-logging.service"): "/etc/systemd/system/verbose-logging.service",
    Label("hostos-scripts/verbose-logging/logrotate.d/verbose-logging"): "/etc/logrotate.d/verbose-logging",
    Label("hostos-scripts/log-config/log-config.service"): "/etc/systemd/system/log-config.service",
    Label("hostos-scripts/log-config/log-config.sh"): "/opt/ic/bin/log-config.sh",

    # early-boot
    Label("early-boot/relabel-machine-id/relabel-machine-id.sh"): "/opt/ic/bin/relabel-machine-id.sh",
    Label("early-boot/relabel-machine-id/relabel-machine-id.service"): "/etc/systemd/system/relabel-machine-id.service",
    Label("early-boot/setup-hostname/hostos/setup-hostname.sh"): "/opt/ic/bin/setup-hostname.sh",
    Label("early-boot/setup-hostname/hostos/setup-hostname.service"): "/etc/systemd/system/setup-hostname.service",
    Label("early-boot/setup-hostname/hostname-empty"): "/etc/hostname",
    Label("early-boot/save-machine-id/save-machine-id.sh"): "/opt/ic/bin/save-machine-id.sh",
    Label("early-boot/save-machine-id/save-machine-id.service"): "/etc/systemd/system/save-machine-id.service",
    Label("early-boot/fstab/fstab-hostos"): "/etc/fstab",
    Label("early-boot/locale"): "/etc/default/locale",
    Label("early-boot/initramfs-tools/hostos/initramfs.conf"): "/etc/initramfs-tools/initramfs.conf",
    Label("early-boot/initramfs-tools/hostos/modules"): "/etc/initramfs-tools/modules",
    Label("early-boot/initramfs-tools/hostos/set-machine-id/set-machine-id"): "/etc/initramfs-tools/scripts/init-bottom/set-machine-id/set-machine-id",

    # misc
    Label("misc/logging.sh"): "/opt/ic/bin/logging.sh",
    Label("misc/metrics.sh"): "/opt/ic/bin/metrics.sh",
    Label("misc/fetch-property.sh"): "/opt/ic/bin/fetch-property.sh",
    Label("misc/vsock/vsock-agent.service"): "/etc/systemd/system/vsock-agent.service",
    Label("misc/vsock/10-vhost-vsock.rules"): "/etc/udev/rules.d/10-vhost-vsock.rules",
    Label("misc/chrony/chrony.conf"): "/etc/chrony/chrony.conf",
    Label("misc/chrony/chrony-var.service"): "/etc/systemd/system/chrony-var.service",
    Label("misc/hostos/sudoers"): "/etc/sudoers",
    Label("misc/hostos/ic-node.conf"): "/etc/tmpfiles.d/ic-node.conf",
    Label("misc/hostos/20-ipmi.rules"): "/etc/udev/rules.d/20-ipmi.rules",

    # monitoring
    Label("monitoring/systemd-user/user@.service"): "/etc/systemd/system/user@.service",
    Label("monitoring/node_exporter/node_exporter.crt"): "/etc/node_exporter/node_exporter.crt",
    Label("monitoring/node_exporter/node_exporter.key"): "/etc/node_exporter/node_exporter.key",
    Label("monitoring/node_exporter/web.yml"): "/etc/node_exporter/web.yml",
    Label("monitoring/node_exporter/node_exporter.service"): "/etc/systemd/system/node_exporter.service",
    Label("monitoring/node_exporter/node_exporter"): "/etc/default/node_exporter",
    Label("monitoring/node_exporter/setup-node_exporter-keys/setup-node_exporter-keys.sh"): "/opt/ic/bin/setup-node_exporter-keys.sh",
    Label("monitoring/node_exporter/setup-node_exporter-keys/setup-node_exporter-keys.service"): "/etc/systemd/system/setup-node_exporter-keys.service",
    Label("monitoring/metrics-proxy/hostos/metrics-proxy.yaml"): "/etc/metrics-proxy.yaml",
    Label("monitoring/metrics-proxy/metrics-proxy.service"): "/etc/systemd/system/metrics-proxy.service",
    Label("monitoring/journald.conf"): "/etc/systemd/journald.conf",
    Label("monitoring/logrotate/override.conf"): "/etc/systemd/system/logrotate.service.d/override.conf",

    # networking
    Label("networking/generate-network-config/hostos/generate-network-config.service"): "/etc/systemd/system/generate-network-config.service",
    Label("networking/fallback.conf"): "/etc/systemd/resolved.conf.d/fallback.conf",
    Label("networking/resolv.conf"): "/etc/resolv.conf",
    Label("networking/network-tweaks.conf"): "/etc/sysctl.d/network-tweaks.conf",
    Label("networking/nftables/nftables-hostos.conf"): "/etc/nftables.conf",
    Label("networking/hosts"): "/etc/hosts",

    # ssh
    Label("ssh/setup-ssh-keys/setup-ssh-keys.sh"): "/opt/ic/bin/setup-ssh-keys.sh",
    Label("ssh/setup-ssh-keys/setup-ssh-keys.service"): "/etc/systemd/system/setup-ssh-keys.service",
    Label("ssh/setup-ssh-account-keys/setup-ssh-account-keys.sh"): "/opt/ic/bin/setup-ssh-account-keys.sh",
    Label("ssh/setup-ssh-account-keys/setup-ssh-account-keys.service"): "/etc/systemd/system/setup-ssh-account-keys.service",
    Label("ssh/deploy-updated-ssh-account-keys/deploy-updated-ssh-account-keys.sh"): "/opt/ic/bin/deploy-updated-ssh-account-keys.sh",
    Label("ssh/deploy-updated-ssh-account-keys/deploy-updated-ssh-account-keys.service"): "/etc/systemd/system/deploy-updated-ssh-account-keys.service",

    # upgrade
    Label("upgrade/manageboot/manageboot.sh"): "/opt/ic/bin/manageboot.sh",
    Label("upgrade/systemd-generators/hostos/mount-generator"): "/etc/systemd/system-generators/mount-generator",
    Label("upgrade/systemd-generators/systemd-gpt-auto-generator"): "/etc/systemd/system-generators/systemd-gpt-auto-generator",
    Label("upgrade/install-upgrade.sh"): "/opt/ic/bin/install-upgrade.sh",
}
