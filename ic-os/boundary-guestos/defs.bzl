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
        # Extra files to be added to rootfs and bootfs
        "bootfs": {},
        "rootfs": {
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
