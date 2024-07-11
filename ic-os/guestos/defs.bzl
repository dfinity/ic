"""
Hold manifest common to all GuestOS variants.
"""

load("//ic-os/components:guestos.bzl", "component_files")

# Declare the dependencies that we will have for the built filesystem images.
# This needs to be done separately from the build rules because we want to
# compute the hash over all inputs going into the image and derive the
# "version.txt" file from it.

def image_deps(mode, malicious = False):
    """
    Define all GuestOS inputs.

    Args:
      mode: Variant to be built, dev or prod.
      malicious: if True, bundle the `malicious_replica`
    Returns:
      A dict containing inputs to build this image.
    """

    deps = {
        "base_dockerfile": "//ic-os/guestos/context:Dockerfile.base",
        "dockerfile": "//ic-os/guestos/context:Dockerfile",

        # Extra files to be added to rootfs and bootfs
        "bootfs": {},
        "rootfs": {
            # additional files to install
            "//publish/binaries:canister_sandbox": "/opt/ic/bin/canister_sandbox:0755",
            "//publish/binaries:compiler_sandbox": "/opt/ic/bin/compiler_sandbox:0755",
            "//publish/binaries:fstrim_tool": "/opt/ic/bin/fstrim_tool:0755",
            "//publish/binaries:guestos_tool": "/opt/ic/bin/guestos_tool:0755",
            "//publish/binaries:ic-btc-adapter": "/opt/ic/bin/ic-btc-adapter:0755",
            "//publish/binaries:ic-consensus-pool-util": "/opt/ic/bin/ic-consensus-pool-util:0755",
            "//publish/binaries:ic-https-outcalls-adapter": "/opt/ic/bin/ic-https-outcalls-adapter:0755",
            "//publish/binaries:ic-crypto-csp": "/opt/ic/bin/ic-crypto-csp:0755",
            "//publish/binaries:ic-regedit": "/opt/ic/bin/ic-regedit:0755",
            "//publish/binaries:ic-recovery": "/opt/ic/bin/ic-recovery:0755",
            "//publish/binaries:orchestrator": "/opt/ic/bin/orchestrator:0755",
            "//publish/binaries:ic-boundary-tls": "/opt/ic/bin/ic-boundary:0755",
            ("//publish/malicious:replica" if malicious else "//publish/binaries:replica"): "/opt/ic/bin/replica:0755",  # Install the malicious replica if set
            "//publish/binaries:metrics-proxy": "/opt/ic/bin/metrics-proxy:0755",
            "//publish/binaries:sandbox_launcher": "/opt/ic/bin/sandbox_launcher:0755",
            "//publish/binaries:state-tool": "/opt/ic/bin/state-tool:0755",
            "//publish/binaries:vsock_guest": "/opt/ic/bin/vsock_guest:0755",
            "//cpp:infogetty": "/opt/ic/bin/infogetty:0755",
            "//cpp:prestorecon": "/opt/ic/bin/prestorecon:0755",

            # additional libraries to install
            "//publish/binaries:nss_icos": "/usr/lib/x86_64-linux-gnu/libnss_icos.so.2:0644",
        },

        # Set various configuration values
        "container_context_files": Label("//ic-os/guestos/context:context-files"),
        "component_files": component_files,
        "partition_table": Label("//ic-os/guestos:partitions.csv"),
        "expanded_size": "50G",
        "rootfs_size": "3G",
        "bootfs_size": "1G",

        # Add any custom partitions to the manifest
        "custom_partitions": lambda: [Label("//ic-os/guestos:partition-config.tzst")],

        # We will install extra_boot_args onto the system, after substituting the
        # hash of the root filesystem into it. Track the template (before
        # substitution) as a dependency so that changes to the template file are
        # reflected in the overall version hash (the root_hash must include the
        # version hash, it cannot be the other way around).
        "boot_args_template": Label("//ic-os/guestos/context:extra_boot_args.template"),
    }

    dev_build_args = ["BUILD_TYPE=dev", "ROOT_PASSWORD=root"]
    prod_build_args = ["BUILD_TYPE=prod"]
    dev_file_build_arg = "BASE_IMAGE=docker-base.dev"
    prod_file_build_arg = "BASE_IMAGE=docker-base.prod"

    image_variants = {
        "dev": {
            "build_args": dev_build_args,
            "file_build_arg": dev_file_build_arg,
        },
        "local-base-dev": {
            "build_args": dev_build_args,
            "file_build_arg": dev_file_build_arg,
        },
        "dev-malicious": {
            "build_args": dev_build_args,
            "file_build_arg": dev_file_build_arg,
        },
        "local-base-prod": {
            "build_args": prod_build_args,
            "file_build_arg": prod_file_build_arg,
        },
        "prod": {
            "build_args": prod_build_args,
            "file_build_arg": prod_file_build_arg,
        },
    }

    deps.update(image_variants[mode])

    # Add extra files depending on image variant
    extra_rootfs_deps = {
        "dev": {
            "//ic-os/guestos/context:allow_console_root": "/etc/allow_console_root:0644",
        },
        "local-base-dev": {
            "//ic-os/guestos/context:allow_console_root": "/etc/allow_console_root:0644",
        },
    }

    deps["rootfs"].update(extra_rootfs_deps.get(mode, {}))

    return deps
