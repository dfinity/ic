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
        "bootfs": {
            "//ic-os/components/ovmf:ovmf_sev": "/OVMF_SEV.fd:0644",
        },
        "rootfs": {
            # additional files to install
            # Required by the IC protocol
            "//publish/binaries:canister_sandbox": "/opt/ic/bin/canister_sandbox:0755",  # Need for the canister sandboxing to work.
            "//publish/binaries:compiler_sandbox": "/opt/ic/bin/compiler_sandbox:0755",  # Need for the Wasm compilation sandboxing to work.
            "//publish/binaries:sandbox_launcher": "/opt/ic/bin/sandbox_launcher:0755",  # Need for the canister/compilation sandboxing to work.
            "//publish/binaries:ic-btc-adapter": "/opt/ic/bin/ic-btc-adapter:0755",  # Need for the Bitcoin and Dogecoin integration.
            "//publish/binaries:ic-https-outcalls-adapter-https-only": "/opt/ic/bin/ic-https-outcalls-adapter:0755",  # Need for the HTTPS outcalls feature. `//publish/binaries:ic-https-outcalls-adapter` is for testing and must NOT be used here
            "//publish/binaries:ic-crypto-csp": "/opt/ic/bin/ic-crypto-csp:0755",  # Crypto operations provider, required by the IC protocol (signing, etc).
            "//publish/binaries:orchestrator": "/opt/ic/bin/orchestrator:0755",  # Replica process manager, required by the IC protocol (upgrades, node addition, etc).
            ("//publish/malicious:replica" if malicious else "//publish/binaries:replica"): "/opt/ic/bin/replica:0755",  # Main protocol binary, required by the IC protocol. Installs the malicious replica iff set only in test builds.
            "//publish/binaries:ic-boundary": "/opt/ic/bin/ic-boundary:0755",  # API boundary node binary, required by the IC protocol. The same GuestOS is used both for the replica and API boundary nodes.
            "//publish/binaries:ic-consensus-pool-util": "/opt/ic/bin/ic-consensus-pool-util:0755",  # May be used during recoveries to export/import consensus pool artifacts.
            "//publish/binaries:ic-recovery": "/opt/ic/bin/ic-recovery:0755",  # Required for performing subnet recoveries on the node directly.
            "//publish/binaries:state-tool": "/opt/ic/bin/state-tool:0755",  # May be used during recoveries for calculating the state hash and inspecting the state more generally.
            "//publish/binaries:ic-regedit": "/opt/ic/bin/ic-regedit:0755",  # May be used for inspecting and recovering the registry.
            # Required by the GuestOS
            "//rs/ic_os/release:fstrim_tool": "/opt/ic/bin/fstrim_tool:0755",  # The GuestOS periodically calls fstrim to trigger the host os to free the memory that stored old version of the secret key store, so that it can be garbage collected more quickly.
            "//rs/ic_os/release:guestos_tool": "/opt/ic/bin/guestos_tool:0755",  # Tool for generating network config and hardware observability.
            "//rs/ic_os/os_tools/guest_disk": "/opt/ic/bin/guest_disk:0755",
            "//rs/ic_os/release:nft-exporter": "/opt/ic/bin/nft-exporter:0755",  # Firewall (NFTables) counter exporter for observability.
            "//rs/ic_os/release:vsock_guest": "/opt/ic/bin/vsock_guest:0755",  # HostOS <--> GuestOS communication client.
            "//cpp:infogetty": "/opt/ic/bin/infogetty:0755",  # Terminal manager that replaces the login shell.
            "//rs/ic_os/release:metrics-proxy": "/opt/ic/bin/metrics-proxy:0755",  # Proxies, filters, and serves public node metrics.
            "//rs/ic_os/release:metrics_tool": "/opt/ic/bin/metrics_tool:0755",  # Collects and reports custom metrics.
            "//rs/ic_os/remote_attestation/server": "/opt/ic/bin/remote_attestation_server:0755",  # Remote Attestation service
            "//rs/ic_os/guest_upgrade/client": "/opt/ic/bin/guest_upgrade_client:0755",  # Disk encryption key exchange client

            # additional libraries to install
            "//rs/ic_os/release:nss_icos": "/usr/lib/x86_64-linux-gnu/libnss_icos.so.2:0644",  # Allows referring to the guest IPv6 by name guestos from host, and host as hostos from guest.
            "//rs/ic_os/release:config": "/opt/ic/bin/config:0755",
        },

        # Set various configuration values
        "container_context_files": Label("//ic-os/guestos/context:context-files"),
        "component_files": dict(component_files),  # Make a copy because we might update it later
        "partition_table": Label("//ic-os/guestos:partitions.csv"),
        "expanded_size": "50G",
        "rootfs_size": "3G",
        "bootfs_size": "1G",
        "grub_config": Label("//ic-os/bootloader:guestos_grub.cfg"),

        # Add any custom partitions to the manifest
        "custom_partitions": lambda _: [Label("//ic-os/guestos:partition-config.tzst")],
        "boot_args_template": Label("//ic-os/bootloader:guestos_boot_args.template"),
        # GuestOS requires dm-verity root partition signing
        "requires_root_signing": True,
        "generate_launch_measurements": True,
    }

    dev_build_args = ["BUILD_TYPE=dev", "ROOT_PASSWORD=root"]
    prod_build_args = ["BUILD_TYPE=prod"]
    dev_file_build_arg = "BASE_IMAGE=docker-base.dev"
    prod_file_build_arg = "BASE_IMAGE=docker-base.prod"

    # Determine build configuration based on mode name
    if "dev" in mode:
        deps.update({
            "build_args": dev_build_args,
            "file_build_arg": dev_file_build_arg,
        })
    else:
        deps.update({
            "build_args": prod_build_args,
            "file_build_arg": prod_file_build_arg,
        })

    # Update dev rootfs
    if "dev" in mode:
        # Allow console access
        deps["component_files"].update({
            Label("//ic-os/components:misc/serial-getty@/guestos-dev/override.conf"): "/etc/systemd/system/serial-getty@.service.d/override.conf",
        })

        # Dev config tool
        deps["rootfs"].pop("//rs/ic_os/release:config", None)
        deps["rootfs"].update({"//rs/ic_os/release:config_dev": "/opt/ic/bin/config:0755"})

        # Dev guest_upgrade client
        deps["rootfs"].pop("//rs/ic_os/guest_upgrade/client", None)
        deps["rootfs"].update({"//rs/ic_os/guest_upgrade/client:client_dev": "/opt/ic/bin/guest_upgrade_client:0755"})
    else:
        deps["component_files"].update({
            Label("//ic-os/components:misc/serial-getty@/guestos-prod/override.conf"): "/etc/systemd/system/serial-getty@.service.d/override.conf",
        })

    # Update recovery component_files
    # Service files and SELinux policies must be added to components instead of rootfs so that they are processed by the Dockerfile
    if mode in ["recovery", "recovery-dev"]:
        deps["component_files"].update({
            Label("//ic-os/components:misc/guestos-recovery/guestos-recovery-engine/guestos-recovery-engine.sh"): "/opt/ic/bin/guestos-recovery-engine.sh",
            Label("//ic-os/components:misc/guestos-recovery/guestos-recovery-engine/guestos-recovery-engine.service"): "/etc/systemd/system/guestos-recovery-engine.service",
            Label("//ic-os/components:guestos/selinux/guestos-recovery-engine/guestos-recovery-engine.fc"): "/prep/guestos-recovery-engine/guestos-recovery-engine.fc",
            Label("//ic-os/components:guestos/selinux/guestos-recovery-engine/guestos-recovery-engine.te"): "/prep/guestos-recovery-engine/guestos-recovery-engine.te",
        })

    return deps
