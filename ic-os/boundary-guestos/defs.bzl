"""
Hold manifest common to all Boundary GuestOS variants.
"""

# Declare the dependencies that we will have for the built filesystem images.
# This needs to be done separately from the build rules because we want to
# compute the hash over all inputs going into the image and derive the
# "version.txt" file from it.

def image_deps(mode):
    """
    Define all Boundary GuestOS inputs.

    Args:
      mode: Variant to be built, dev or prod.
    Returns:
      A dict containing all file inputs to build this image.
    """

    deps = {
        "bootfs": {
            # base layer
            ":rootfs-tree.tar": "/",

            # We will install extra_boot_args onto the system, after substituting the
            # hash of the root filesystem into it. Track the template (before
            # substitution) as a dependency so that changes to the template file are
            # reflected in the overall version hash (the root_hash must include the
            # version hash, it cannot be the other way around).
            "//ic-os/boundary-guestos:bootloader/extra_boot_args.template": "/boot/extra_boot_args.template:0644",
        },
        "rootfs": {
            # base layer
            ":rootfs-tree.tar": "/",

            # additional files to install
            "//publish/binaries:canary-proxy": "/opt/ic/bin/canary-proxy:0755",
            "//publish/binaries:boundary-node-prober": "/opt/ic/bin/boundary-node-prober:0755",
            "//publish/binaries:certificate-issuer": "/opt/ic/bin/certificate-issuer:0755",
            "//publish/binaries:certificate-syncer": "/opt/ic/bin/certificate-syncer:0755",
            "//publish/binaries:ic-balance-exporter": "/opt/ic/bin/ic-balance-exporter:0755",
            "//publish/binaries:icx-proxy": "/opt/ic/bin/icx-proxy:0755",
            "//publish/binaries:systemd-journal-gatewayd-shim": "/opt/ic/bin/systemd-journal-gatewayd-shim:0755",
            "//publish/binaries:ic-boundary": "/opt/ic/bin/ic-boundary:0755",
        },
    }

    extra_deps = {
        "dev": {
            "build_container_filesystem_config_file": "//ic-os/boundary-guestos/envs/dev:build_container_filesystem_config.txt",
        },
        "prod": {
            "build_container_filesystem_config_file": "//ic-os/boundary-guestos/envs/prod:build_container_filesystem_config.txt",
        },
    }

    deps.update(extra_deps[mode])

    return deps
