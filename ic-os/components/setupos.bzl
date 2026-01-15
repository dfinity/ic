"""
Enumerate every component file dependency for SetupOS
"""

component_files = {
    # commit-time is checked in the setupOS installation to verify that images are not too old.
    Label("//ic-os/components:commit_timestamp_txt"): "/commit-time",

    # setupos components
    Label("//ic-os/components/setupos:check-setupos-age.sh"): "/opt/ic/bin/check-setupos-age.sh",
    Label("//ic-os/components/setupos:check-config.sh"): "/opt/ic/bin/check-config.sh",
    Label("//ic-os/components/setupos:preload-config.sh"): "/opt/ic/bin/preload-config.sh",
    Label("//ic-os/components/setupos:setup-hostos-config.sh"): "/opt/ic/bin/setup-hostos-config.sh",
    Label("//ic-os/components/setupos:setup-disk.sh"): "/opt/ic/bin/setup-disk.sh",
    Label("//ic-os/components/setupos:functions.sh"): "/opt/ic/bin/functions.sh",
    Label("//ic-os/components/setupos:install-guestos.sh"): "/opt/ic/bin/install-guestos.sh",
    Label("//ic-os/components/setupos:check-hardware.sh"): "/opt/ic/bin/check-hardware.sh",
    Label("//ic-os/components/setupos:install-hostos.sh"): "/opt/ic/bin/install-hostos.sh",
    Label("//ic-os/components/setupos:check-network.sh"): "/opt/ic/bin/check-network.sh",
    Label("//ic-os/components/setupos:check-ntp.sh"): "/opt/ic/bin/check-ntp.sh",
    Label("//ic-os/components/setupos:setupos.sh"): "/opt/ic/bin/setupos.sh",
    Label("//ic-os/components/setupos:config.service"): "/etc/systemd/system/config.service",
    Label("//ic-os/components/setupos:setupos.service"): "/etc/systemd/system/setupos.service",

    # early-boot
    Label("early-boot/setup-hostname/hostname-setupos"): "/etc/hostname",
    Label("early-boot/fstab/fstab-setupos"): "/etc/fstab",
    Label("early-boot/locale"): "/etc/default/locale",
    Label("early-boot/initramfs-tools/setupos/initramfs.conf"): "/etc/initramfs-tools/initramfs.conf",
    Label("early-boot/initramfs-tools/setupos/amd64-microcode"): "/etc/default/amd64-microcode",
    Label("early-boot/initramfs-tools/setupos/intel-microcode"): "/etc/default/intel-microcode",

    # misc
    Label("misc/logging.sh"): "/opt/ic/bin/logging.sh",
    Label("misc/output-wrapper.sh"): "/opt/ic/bin/output-wrapper.sh",
    Label("misc/config/config-setupos.sh"): "/opt/ic/bin/config.sh",
    Label("misc/chrony/chrony.conf"): "/etc/chrony/chrony.conf",
    Label("misc/chrony/chrony-var.service"): "/etc/systemd/system/chrony-var.service",
    Label("misc/serial-getty@/setupos/override.conf"): "/etc/systemd/system/serial-getty@.service.d/override.conf",
    Label("monitoring/journald.conf"): "/etc/systemd/journald.conf",

    # networking
    Label("networking/generate-network-config/generate-network-config-setupos.service"): "/etc/systemd/system/generate-network-config.service",
    Label("networking/fallback.conf"): "/etc/systemd/resolved.conf.d/fallback.conf",
    Label("networking/resolv.conf"): "/etc/resolv.conf",
    Label("networking/hosts"): "/etc/hosts",
    Label("networking/network-tweaks.conf"): "/etc/sysctl.d/network-tweaks.conf",

    # upgrade
    Label("upgrade/systemd-generators/systemd-gpt-auto-generator"): "/etc/systemd/system-generators/systemd-gpt-auto-generator",
}
