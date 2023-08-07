"""
Hold manifest common to all GuestOS variants.
"""

# Declare the dependencies that we will have for the built filesystem images.
# This needs to be done separately from the build rules because we want to
# compute the hash over all inputs going into the image and derive the
# "version.txt" file from it.

def image_deps(mode, malicious = False):
    """
    Define all GuestOS inputs.

    Args:
      mode: Variant to be built, dev, dev-sev or prod.
      malicious: if True, bundle the `malicious_replica`
    Returns:
      A dict containing inputs to build this image.
    """

    deps = {
        # Define rootfs and bootfs
        "bootfs": {
            # base layer
            ":rootfs-tree.tar": "/",
        },
        "rootfs": {
            # base layer
            ":rootfs-tree.tar": "/",

            # additional files to install
            "//publish/binaries:canister_sandbox": "/opt/ic/bin/canister_sandbox:0755",
            "//publish/binaries:ic-btc-adapter": "/opt/ic/bin/ic-btc-adapter:0755",
            "//publish/binaries:ic-consensus-pool-util": "/opt/ic/bin/ic-consensus-pool-util:0755",
            "//publish/binaries:ic-https-outcalls-adapter": "/opt/ic/bin/ic-https-outcalls-adapter:0755",
            "//publish/binaries:ic-crypto-csp": "/opt/ic/bin/ic-crypto-csp:0755",
            "//publish/binaries:ic-regedit": "/opt/ic/bin/ic-regedit:0755",
            "//publish/binaries:ic-recovery": "/opt/ic/bin/ic-recovery:0755",
            "//publish/binaries:orchestrator": "/opt/ic/bin/orchestrator:0755",
            ("//publish/malicious:replica" if malicious else "//publish/binaries:replica"): "/opt/ic/bin/replica:0755",  # Install the malicious replica if set
            "//publish/binaries:sandbox_launcher": "/opt/ic/bin/sandbox_launcher:0755",
            "//publish/binaries:sevctl": "/opt/ic/bin/sevctl:0755",
            "@sevtool": "/opt/ic/bin/sevtool:0755",
            "//publish/binaries:state-tool": "/opt/ic/bin/state-tool:0755",
            "//publish/binaries:vsock_guest": "/opt/ic/bin/vsock_guest:0755",
            "//ic-os/utils:infogetty": "/opt/ic/bin/infogetty:0755",
            "//ic-os/utils:prestorecon": "/opt/ic/bin/prestorecon:0755",
        },

        # Set various configuration values
        "base_image": Label("//ic-os/guestos:rootfs/docker-base." + mode),
        "docker_context": Label("//ic-os/guestos:rootfs-files"),
        "partition_table": Label("//ic-os/guestos:partitions.csv"),
        "expanded_size": "50G",
        "rootfs_size": "3G",
        "bootfs_size": "1G",

        # Add any custom partitions to the manifest
        "custom_partitions": lambda: [Label("//ic-os/guestos:partition-config.tar")],

        # We will install extra_boot_args onto the system, after substituting the
        # hash of the root filesystem into it. Track the template (before
        # substitution) as a dependency so that changes to the template file are
        # reflected in the overall version hash (the root_hash must include the
        # version hash, it cannot be the other way around).
        "boot_args_template": Label("//ic-os/guestos:rootfs/extra_boot_args.template"),
    }

    # Add extra files depending on image variant
    extra_rootfs_deps = {
        "dev": {"//ic-os/guestos:rootfs/allow_console_root": "/etc/allow_console_root:0644"},
        "dev-sev": {"//ic-os/guestos:rootfs/allow_console_root": "/etc/allow_console_root:0644"},
        "dev-malicious": {},
        "prod": {},
    }

    deps["rootfs"].update(extra_rootfs_deps[mode])

    return deps
