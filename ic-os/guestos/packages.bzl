common_packages = [
    # This defines all Ubuntu packages to be installed on the target image. The
    # packages here are intended to be the bare minimum required for replica
    # operation for the "prod" image. Please put debugging / dev
    # utilities into packages.dev, these will then be available on the dev
    # image only.

    # Need kernel to boot anything
    "linux-image-virtual-hwe-24.04",
    "initramfs-tools",

    # Need systemd for boot process
    "systemd",
    "systemd-sysv",
    "systemd-journal-remote",
    "systemd-resolved",

    # Third-party services we will be running
    "chrony",
    "openssh-server",

    # Runtime libraries for replica
    "liblmdb0",
    "libunwind8",
    "libselinux1",

    # Smartcard support for replica
    "pcsc-tools",
    "pcscd",
    "opensc",

    # Required system setup tools
    "attr",
    "ca-certificates",
    "cryptsetup",
    "curl",
    "faketime",
    "fdisk",
    "iproute2",
    "isc-dhcp-client",
    "jq",
    "less",
    "lvm2",
    "net-tools",
    "nftables",
    "parted",
    "rsync",
    "sudo",
    "sysfsutils",
    "udev",
    "usbutils",
    "xfsprogs",
    "zstd",

    # This is unclear -- why is this here? This should "probably" be dev tool.
    "protobuf-compiler",

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
    # may want to ssh into other hosts -- not sure if this is really advisable
    "openssh-client",
    # useful for first-order debugging
    "gdb",
    "strace",
    # useful for SELinux development
    "setools",
    # flamegraphs (scalability suite)
    "linux-tools-virtual-hwe-24.04",
    # performance testing additions
    "fio",
    "stress-ng",
    "sysbench",
    "bpftrace",
    "linux-tools-common",
    "linux-tools-generic",
    "sysstat",
    "perf-tools-unstable",
    # xz needed by bpftrace and others
    "xz-utils",
    # static busybox for various missing utilities and to have a static binary with less noise
    "busybox-static",
]
