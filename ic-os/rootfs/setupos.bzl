"""
Enumerate every rootfs file dependency for SetupOS
"""

rootfs_files = {
    # setupos-scripts
    Label("setupos-scripts/check-setupos-age.sh"): "/opt/ic/bin/check-setupos-age.sh",
    Label("setupos-scripts/config.sh"): "/opt/ic/bin/config.sh",
    Label("setupos-scripts/devices.sh"): "/opt/ic/bin/devices.sh",
    Label("setupos-scripts/disk.sh"): "/opt/ic/bin/disk.sh",
    Label("setupos-scripts/functions.sh"): "/opt/ic/bin/functions.sh",
    Label("setupos-scripts/guestos.sh"): "/opt/ic/bin/guestos.sh",
    Label("setupos-scripts/hardware.sh"): "/opt/ic/bin/hardware.sh",
    Label("setupos-scripts/hostos.sh"): "/opt/ic/bin/hostos.sh",
    Label("setupos-scripts/network.sh"): "/opt/ic/bin/network.sh",
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
    Label("misc/fetch-property/setupos/fetch-property.sh"): "/opt/ic/bin/fetch-property.sh",
    Label("misc/serial-getty@/setupos/serial-getty@.service"): "/etc/systemd/system/serial-getty@.service",

    # networking
    Label("networking/generate-network-config/setupos/generate-network-config.service"): "/etc/systemd/system/generate-network-config.service",
    Label("networking/fallback.conf"): "/etc/systemd/resolved.conf.d/fallback.conf",
    Label("networking/resolv.conf"): "/etc/resolv.conf",
    Label("networking/hosts"): "/etc/hosts",

    # prep
    Label("prep/setupos/fscontext-fixes/fscontext-fixes.fc"): "/prep/fscontext-fixes/fscontext-fixes.fc",
    Label("prep/setupos/fscontext-fixes/fscontext-fixes.if"): "/prep/fscontext-fixes/fscontext-fixes.if",
    Label("prep/setupos/fscontext-fixes/fscontext-fixes.te"): "/prep/fscontext-fixes/fscontext-fixes.te",
    Label("prep/setupos/misc-fixes/misc-fixes.if"): "/prep/misc-fixes/misc-fixes.if",
    Label("prep/setupos/misc-fixes/misc-fixes.te"): "/prep/misc-fixes/misc-fixes.te",
    Label("prep/setupos/prep.sh"): "/prep/prep.sh",
    Label("prep/setupos/systemd-fixes/systemd-fixes.if"): "/prep/systemd-fixes/systemd-fixes.if",
    Label("prep/setupos/systemd-fixes/systemd-fixes.te"): "/prep/systemd-fixes/systemd-fixes.te",

    # upgrade
    Label("upgrade/systemd-generators/systemd-gpt-auto-generator"): "/etc/systemd/system-generators/systemd-gpt-auto-generator",
}
