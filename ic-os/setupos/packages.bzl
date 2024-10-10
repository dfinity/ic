# This defines all Ubuntu packages to be installed on the target image. The
# packages here are intended to be the bare minimum required for
# operation for the "prod" image.
common_packages = [
    # Need kernel to boot anything
    "linux-image-generic-hwe-24.04",
    "initramfs-tools",

    # Need systemd for boot process
    "systemd",
    "systemd-sysv",
    "systemd-journal-remote",
    "systemd-resolved",

    # Third-party services we will be running
    "chrony",

    # Required system setup tools
    "ssh",
    "attr",
    "ca-certificates",
    "curl",
    "ethtool",
    "efibootmgr",
    "faketime",
    "gdisk",
    "ipmitool",
    "iproute2",
    "iputils-ping",
    "isc-dhcp-client",
    "jq",
    "less",
    "locales",
    "lshw",
    "lvm2",
    "net-tools",
    "parted",
    "pv",
    "python-is-python3",
    "sudo",
    "udev",
    "usbutils",
    "xfsprogs",
    "zstd",

    # SELinux support
    "selinux-policy-default",
    "selinux-utils",
    "semodule-utils",
    "policycoreutils",
    # this is required for policy building -- presently policy modules are built
    # inside the target which is not fully proper. When the build is moved out,
    # this package can be removed
    "selinux-policy-dev",
    "checkpolicy",
]

# These are additional Ubuntu packages installed on the "dev" images.
dev_packages = [
    # editor for convenience
    "vim",
    "nano",

    # packages requested by networking
    "tcpdump",
    "iperf",
    "netcat-openbsd",
    "curl",
    "iputils-ping",

    # Third-party services we will be running
    "openssh-server",

    # may want to ssh into other hosts -- not sure if this is really advisable
    "openssh-client",

    # useful for first-order debugging
    "gdb",
    "strace",

    # useful for SELinux development
    "setools",
]
