# IC-OS

**Crates**: `guestos_tool`, `hostos_tool`, `setupos_tool`, `open_rootfs`, `linux_kernel_command_line`, `os_qualification`, `os_qualification_utils`, `sev_guest_firmware`, `ic-fstrim-tool`, `ic_device`, `ic_stable_memory_integrity`

IC-OS comprises the operating system layers that run Internet Computer nodes. It is organized into three tiers: SetupOS (initial deployment), HostOS (host machine management), and GuestOS (replica runtime environment). The system includes configuration management, metrics collection, disk management, SEV-SNP attestation, and vsock-based host-guest communication.

## Requirements

### Requirement: OS Configuration Versioning and Backwards Compatibility
IC-OS configuration must maintain backwards compatibility across upgrades since configuration persists across reboots.

#### Scenario: Config version tracking
- **WHEN** a configuration is created or updated
- **THEN** the `config_version` field is set to the current `CONFIG_VERSION` constant (currently "1.13.0")
- **AND** the minor version is incremented on any configuration structure change

#### Scenario: Adding new configuration fields
- **WHEN** a new field is added to a configuration struct
- **THEN** the field must be optional or have a default value via `Default` or `#[serde(default)]`
- **AND** older configuration files remain deserializable

#### Scenario: Adding new enum variants
- **WHEN** a new variant is added to a configuration enum
- **THEN** a fallback variant with `#[serde(other)]` must exist for forward compatibility
- **AND** older OS versions encountering the new variant will use the fallback

#### Scenario: Removing configuration fields
- **WHEN** a required field is to be removed
- **THEN** it must first be given a `#[serde(default)]` attribute and all references removed
- **AND** only after the change has rolled out to all OSes can the field be fully removed
- **AND** the removed field path must be added to `RESERVED_FIELD_PATHS` to prevent reuse

#### Scenario: Reserved field paths
- **WHEN** a developer attempts to reuse a removed field path
- **THEN** the `RESERVED_FIELD_PATHS` list serves as documentation of fields that must not be reintroduced
- **AND** paths include "icos_settings.logging", "hostos_settings.vm_cpu", "guestos_settings.inject_ic_crypto", among others

### Requirement: SetupOS Configuration
SetupOS is the initial deployment system that configures a new IC node from user-facing configuration files.

#### Scenario: SetupOS config creation
- **WHEN** a new node is being deployed
- **THEN** user-facing files (`config.ini`, `deployment.json`) are transformed into a `SetupOSConfig` struct
- **AND** the config contains `network_settings`, `icos_settings`, `setupos_settings`, `hostos_settings`, and `guestos_settings`

#### Scenario: Config.ini parsing
- **WHEN** the SetupOS config tool processes `config.ini`
- **THEN** key-value pairs are extracted from the file at `/config/config.ini`
- **AND** network configuration, NNS URLs, and other deployment parameters are populated

#### Scenario: Deployment.json parsing
- **WHEN** the SetupOS config tool processes `deployment.json`
- **THEN** deployment-specific configuration including NNS URLs and environment settings are loaded from `/data/deployment.json`

### Requirement: HostOS Configuration
HostOS manages the physical host machine and the GuestOS virtual machine.

#### Scenario: HostOS config inheritance
- **WHEN** HostOS boots
- **THEN** it inherits settings from the `SetupOSConfig` created during initial deployment
- **AND** the `HostOSConfig` contains `network_settings`, `icos_settings`, `hostos_settings`, and `guestos_settings`

#### Scenario: HostOS config persistence
- **WHEN** HostOS configuration is written
- **THEN** it is serialized to JSON at `/boot/config/config.json`
- **AND** the GuestOS configuration is written to `/boot/config/config-guestos.json`

#### Scenario: GuestOS VM type management
- **WHEN** HostOS manages a GuestOS VM
- **THEN** the `GuestVMType` indicates whether the VM is `Default` (normal operation), `Upgrade` (temporary during upgrade), or `Unknown` (forward compatibility fallback)

### Requirement: GuestOS Configuration
GuestOS is the environment where the replica process runs.

#### Scenario: GuestOS config loading
- **WHEN** GuestOS boots
- **THEN** the configuration is loaded from `/run/config/config.json`
- **AND** the IC replica configuration (`ic.json5`) is generated and written to `/run/ic-node/config/ic.json5`

#### Scenario: GuestOS bootstrap
- **WHEN** the GuestOS bootstrap process runs
- **THEN** `bootstrap_ic_node` generates the IC node configuration
- **AND** `generate_ic_config` produces the `ic.json5` file from the GuestOS configuration
- **AND** the bootstrap directory is at `/run/config/bootstrap`

#### Scenario: Trusted execution environment support
- **WHEN** the node runs on SEV-SNP capable hardware with TEE enabled
- **THEN** `trusted_execution_environment_config` is populated with the AMD SEV-SNP certificate chain in PEM format

#### Scenario: Recovery configuration
- **WHEN** a manual recovery is needed
- **THEN** the `recovery_config` field contains the hash of recovery artifacts to be used

### Requirement: Network Settings
IC-OS manages both IPv6 (primary) and optional IPv4 network configuration.

#### Scenario: Network settings structure
- **WHEN** network settings are configured
- **THEN** the `NetworkSettings` struct contains IPv6 address, gateway, prefix length
- **AND** optional IPv4 address, gateway, and prefix length
- **AND** management MAC address for hardware identification

### Requirement: ICOS Common Settings
Settings shared across all IC-OS tiers are managed through the `ICOSSettings` structure.

#### Scenario: ICOS settings content
- **WHEN** ICOS settings are configured
- **THEN** they include: node reward type, management MAC address, deployment environment, NNS URLs, and node operator private key
- **AND** the `DeploymentEnvironment` determines the operational context (mainnet, testnet, etc.)
- **AND** all configuration objects are safe to log (no secret material in non-sensitive fields)

### Requirement: IC-OS Metrics Collection
IC-OS includes tools for collecting system-level metrics including filesystem trim statistics.

#### Scenario: Fstrim metrics collection
- **WHEN** the fstrim tool runs
- **THEN** it executes filesystem TRIM operations on IC-OS partitions
- **AND** metrics about TRIM operations (bytes trimmed, duration, errors) are collected and exported
- **AND** metrics are available in Prometheus format for monitoring

#### Scenario: NFT exporter
- **WHEN** the NFT exporter runs
- **THEN** it collects nftables statistics and exports them as metrics

#### Scenario: Metrics tool
- **WHEN** the IC-OS metrics tool runs
- **THEN** it collects system-level metrics from the operating system
- **AND** exposes them for scraping by the monitoring infrastructure

### Requirement: Vsock Host-Guest Communication
IC-OS uses vsock for secure communication between the HostOS and GuestOS.

#### Scenario: Vsock protocol
- **WHEN** the GuestOS needs to communicate with the HostOS
- **THEN** it uses the vsock client to send structured messages
- **AND** the HostOS vsock server receives and processes these messages
- **AND** the protocol supports HSM operations, command execution, and upgrade orchestration

#### Scenario: Vsock host agent
- **WHEN** the HostOS vsock agent receives a request
- **THEN** it processes commands from the GuestOS including HSM interactions and utility operations
- **AND** responses are sent back through the vsock connection

### Requirement: SEV-SNP Attestation
IC-OS supports AMD SEV-SNP for hardware-level trusted execution.

#### Scenario: Guest attestation package
- **WHEN** SEV-SNP is enabled on the host
- **THEN** the guest creates an attestation package containing measurement data
- **AND** key derivation is performed using the SEV-SNP key deriver
- **AND** attestation reports can be verified by external parties

#### Scenario: Host firmware management
- **WHEN** SEV-SNP attestation is configured
- **THEN** the host manages firmware images for the SEV-SNP platform
- **AND** firmware versions and measurements are tracked for attestation verification

### Requirement: Remote Attestation
IC-OS provides a remote attestation server for verifying node integrity.

#### Scenario: Remote attestation service
- **WHEN** a remote attestation request is received
- **THEN** the attestation server provides cryptographic proof of the node's software configuration
- **AND** shared structures define the attestation protocol between client and server

### Requirement: Boot Configuration
IC-OS manages the GRUB bootloader configuration.

#### Scenario: GRUB configuration
- **WHEN** the boot partition is configured
- **THEN** the GRUB bootloader is set up with appropriate kernel parameters
- **AND** boot configuration supports A/B partition upgrades

### Requirement: Development and Testing Tools
IC-OS provides tools for development and testing deployments.

#### Scenario: SetupOS disable checks
- **WHEN** running in a development/test environment
- **THEN** the `setupos-disable-checks` tool can disable certain validation checks

#### Scenario: SetupOS image configuration
- **WHEN** creating a test SetupOS image
- **THEN** the `setupos-image-config` tool embeds configuration into the image

#### Scenario: Bare metal deployment
- **WHEN** deploying to bare metal hardware for testing
- **THEN** the `bare_metal_deployment` tool handles the deployment process
