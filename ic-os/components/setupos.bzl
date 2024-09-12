"""
Enumerate every component file dependency for SetupOS
"""

component_files = {
    # setupos-scripts
    Label("setupos-scripts/check-setupos-age.sh"): "/opt/ic/bin/check-setupos-age.sh",
    Label("setupos-scripts/setup-hostos-config.sh"): "/opt/ic/bin/setup-hostos-config.sh",
    Label("setupos-scripts/setup-disk.sh"): "/opt/ic/bin/setup-disk.sh",
    Label("setupos-scripts/functions.sh"): "/opt/ic/bin/functions.sh",
    Label("setupos-scripts/guestos.sh"): "/opt/ic/bin/guestos.sh",
    Label("setupos-scripts/check-hardware.sh"): "/opt/ic/bin/check-hardware.sh",
    Label("setupos-scripts/hostos.sh"): "/opt/ic/bin/hostos.sh",
    Label("setupos-scripts/check-network.sh"): "/opt/ic/bin/check-network.sh",
    Label("setupos-scripts/output-wrapper.sh"): "/opt/ic/bin/output-wrapper.sh",
    Label("setupos-scripts/setupos.sh"): "/opt/ic/bin/setupos.sh",
    Label("setupos-scripts/config.service"): "/etc/systemd/system/config.service",
    Label("setupos-scripts/setupos.service"): "/etc/systemd/system/setupos.service",

    # early-boot
    Label("early-boot/setup-hostname/hostname-setupos"): "/etc/hostname",
    Label("early-boot/fstab/fstab-setupos"): "/etc/fstab",
    Label("early-boot/locale"): "/etc/default/locale",
    Label("early-boot/initramfs-tools/setupos/initramfs.conf"): "/etc/initramfs-tools/initramfs.conf",

    # misc
    Label("misc/logging.sh"): "/opt/ic/bin/logging.sh",
    Label("misc/config.sh"): "/opt/ic/bin/config.sh",
    Label("misc/chrony/chrony.conf"): "/etc/chrony/chrony.conf",
    Label("misc/chrony/chrony-var.service"): "/etc/systemd/system/chrony-var.service",
    Label("misc/serial-getty@/setupos/serial-getty@.service"): "/etc/systemd/system/serial-getty@.service",
    Label("monitoring/journald.conf"): "/etc/systemd/journald.conf",

    # networking
    Label("networking/generate-network-config/setupos/generate-network-config.service"): "/etc/systemd/system/generate-network-config.service",
    Label("networking/fallback.conf"): "/etc/systemd/resolved.conf.d/fallback.conf",
    Label("networking/resolv.conf"): "/etc/resolv.conf",
    Label("networking/hosts"): "/etc/hosts",

    # upgrade
    Label("upgrade/systemd-generators/systemd-gpt-auto-generator"): "/etc/systemd/system-generators/systemd-gpt-auto-generator",
}
