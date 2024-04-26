"""
Enumerate every rootfs file dependency for SetupOS
"""

rootfs_files = {
    Label("setupos/etc/default/locale"): "/etc/default/locale",
    Label("setupos/etc/fstab"): "/etc/fstab",
    Label("setupos/etc/hostname"): "/etc/hostname",
    Label("setupos/etc/hosts"): "/etc/hosts",
    Label("setupos/etc/initramfs-tools/initramfs.conf"): "/etc/initramfs-tools/initramfs.conf",
    Label("setupos/etc/resolv.conf"): "/etc/resolv.conf",
    Label("setupos/etc/systemd/resolved.conf.d/fallback.conf"): "/etc/systemd/resolved.conf.d/fallback.conf",
    Label("setupos/etc/systemd/system/config.service"): "/etc/systemd/system/config.service",
    Label("setupos/etc/systemd/system/generate-network-config.service"): "/etc/systemd/system/generate-network-config.service",
    Label("setupos/etc/systemd/system/serial-getty@.service"): "/etc/systemd/system/serial-getty@.service",
    Label("setupos/etc/systemd/system/setupos.service"): "/etc/systemd/system/setupos.service",
    Label("setupos/opt/ic/bin/check-setupos-age.sh"): "/opt/ic/bin/check-setupos-age.sh",
    Label("setupos/opt/ic/bin/config.sh"): "/opt/ic/bin/config.sh",
    Label("setupos/opt/ic/bin/devices.sh"): "/opt/ic/bin/devices.sh",
    Label("setupos/opt/ic/bin/disk.sh"): "/opt/ic/bin/disk.sh",
    Label("setupos/opt/ic/bin/fetch-property.sh"): "/opt/ic/bin/fetch-property.sh",
    Label("setupos/opt/ic/bin/functions.sh"): "/opt/ic/bin/functions.sh",
    Label("setupos/opt/ic/bin/guestos.sh"): "/opt/ic/bin/guestos.sh",
    Label("setupos/opt/ic/bin/hardware.sh"): "/opt/ic/bin/hardware.sh",
    Label("setupos/opt/ic/bin/hostos.sh"): "/opt/ic/bin/hostos.sh",
    Label("setupos/opt/ic/bin/network.sh"): "/opt/ic/bin/network.sh",
    Label("setupos/opt/ic/bin/output-wrapper.sh"): "/opt/ic/bin/output-wrapper.sh",
    Label("setupos/opt/ic/bin/setupos.sh"): "/opt/ic/bin/setupos.sh",
    Label("setupos/prep/fscontext-fixes/fscontext-fixes.fc"): "/prep/fscontext-fixes/fscontext-fixes.fc",
    Label("setupos/prep/fscontext-fixes/fscontext-fixes.if"): "/prep/fscontext-fixes/fscontext-fixes.if",
    Label("setupos/prep/fscontext-fixes/fscontext-fixes.te"): "/prep/fscontext-fixes/fscontext-fixes.te",
    Label("setupos/prep/misc-fixes/misc-fixes.if"): "/prep/misc-fixes/misc-fixes.if",
    Label("setupos/prep/misc-fixes/misc-fixes.te"): "/prep/misc-fixes/misc-fixes.te",
    Label("setupos/prep/prep.sh"): "/prep/prep.sh",
    Label("setupos/prep/systemd-fixes/systemd-fixes.if"): "/prep/systemd-fixes/systemd-fixes.if",
    Label("setupos/prep/systemd-fixes/systemd-fixes.te"): "/prep/systemd-fixes/systemd-fixes.te",

    # consolidated files:
    Label("systemd-generators/systemd-gpt-auto-generator"): "/etc/systemd/system-generators/systemd-gpt-auto-generator",
}
