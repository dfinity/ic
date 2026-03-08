# IC-OS Sub-crates Specification

This specification covers all IC-OS sub-crates located under `rs/ic_os/`.

---

## Build Tools

### Requirement: GRUB Environment Block Management (grub)

The `grub` crate provides reading, writing, and manipulation of GRUB environment blocks used for A/B boot partition selection and boot cycle state tracking.

#### Scenario: Parse a complete GRUB environment block
- **WHEN** a GRUB environment block file containing `boot_alternative=A` and `boot_cycle=stable` is read
- **THEN** the `boot_alternative` field is parsed as `BootAlternative::A`
- **AND** the `boot_cycle` field is parsed as `BootCycle::Stable`

#### Scenario: Parse boot cycle states
- **WHEN** a GRUB environment block contains `boot_cycle=first_boot`
- **THEN** the system recognizes it as the first boot after an upgrade
- **AND** the next state transition will move to `failsafe_check`

#### Scenario: Handle failsafe check boot cycle
- **WHEN** the boot cycle is `failsafe_check`
- **THEN** the system understands that the current system was not acknowledged as working
- **AND** it will fall back to the alternative boot partition and declare it stable

#### Scenario: Handle install boot cycle
- **WHEN** the boot cycle is `install`
- **THEN** the system recognizes this is the initial post-install state

#### Scenario: Handle undefined variables with defaults
- **WHEN** a GRUB environment variable is not present in the file
- **THEN** the variable is reported as `Undefined`
- **AND** calling `with_default_if_undefined` returns the provided default value

#### Scenario: Handle invalid variable values
- **WHEN** a GRUB environment variable contains an unrecognized value (e.g., `boot_alternative=C`)
- **THEN** the variable is reported as a `ParseError` with the invalid value
- **AND** calling `with_default_if_undefined` propagates the error (does not substitute the default)

#### Scenario: Duplicate variables use last-wins semantics
- **WHEN** a GRUB environment block contains duplicate variable assignments
- **THEN** the last assignment wins

#### Scenario: Write GRUB environment block with padding
- **WHEN** a `GrubEnv` is written to a file
- **THEN** the output begins with `# GRUB Environment Block`
- **AND** the total output size is exactly 1024 bytes
- **AND** unused bytes are padded with `#` characters

#### Scenario: Reject oversized GRUB environment
- **WHEN** the serialized GRUB environment exceeds 1024 bytes
- **THEN** the write operation fails with an error
- **AND** the original file is not modified (atomic write)

#### Scenario: Get opposite boot alternative
- **WHEN** the current boot alternative is `A`
- **THEN** `get_opposite()` returns `B`
- **AND** vice versa

---

### Requirement: Deterministic Sparse Tar Archive Creation (dflate)

The `dflate` crate creates deterministic tar archives that preserve sparse file regions, using SEEK_DATA/SEEK_HOLE to detect empty regions efficiently.

#### Scenario: Scan a file for empty sections
- **WHEN** a file is scanned using `scan_file_for_holes`
- **THEN** the tool uses `SEEK_DATA` and `SEEK_HOLE` system calls to identify data regions
- **AND** only non-zero 512-byte blocks within data regions are recorded

#### Scenario: Create a sparse tar archive
- **WHEN** multiple files are passed via `--input` flags
- **THEN** each file is scanned for holes and added to the archive in GNU sparse format
- **AND** the output archive is deterministic (same inputs produce byte-identical outputs)
- **AND** the `HeaderMode::Deterministic` option normalizes metadata

#### Scenario: Preserve file content through archive round-trip
- **WHEN** files are archived via `dflate` and then extracted
- **THEN** the extracted file contents are byte-identical to the originals

#### Scenario: Reject non-file inputs
- **WHEN** the input path is not a regular file (e.g., a directory)
- **THEN** `scan_file_for_holes` returns an error indicating the input is not a file

#### Scenario: Handle extended sparse headers
- **WHEN** a file has more than 4 sparse data regions
- **THEN** additional `GnuExtSparseHeader` entries are emitted
- **AND** the `isextended` flag is set on the main header and all intermediate extended headers

#### Scenario: Pad archive entries to 512-byte boundaries
- **WHEN** the total size of data blocks is not a multiple of 512
- **THEN** zero padding is appended to reach the next 512-byte boundary

---

### Requirement: e2fsdroid fs_config Generation (diroid)

The `diroid` crate generates filesystem configuration files for `e2fsdroid` by walking a directory tree and combining it with fakeroot state.

#### Scenario: Generate fs_config from directory tree and fakeroot state
- **WHEN** `diroid` is given `--fakeroot`, `--input-dir`, and `--output` arguments
- **THEN** it walks the input directory recursively
- **AND** for each entry, looks up the inode in the fakeroot state to get uid/gid
- **AND** writes one line per entry in the format: `<relative_path> <uid> <gid> <octal_mode>`

#### Scenario: Root directory uses hardcoded ownership
- **WHEN** the entry being processed is the root directory itself
- **THEN** uid and gid are set to 0 (root)
- **AND** fakeroot state is not consulted for the root entry

#### Scenario: Missing inode in fakeroot state
- **WHEN** a file's inode is not found in the fakeroot state file
- **THEN** the tool exits with an error indicating the missing inode

#### Scenario: Parse fakeroot state file
- **WHEN** the fakeroot state file is read
- **THEN** each line is parsed for `ino=`, `uid=`, and `gid=` fields
- **AND** a mapping from inode to (uid, gid) is constructed
- **AND** missing fields cause an error

---

### Requirement: Disk Image Partition Manipulation (partition_tools)

The `partition_tools` crate provides a `Partition` trait and implementations for ext4 and FAT32 partitions, supporting read/write operations on disk images without mounting.

#### Scenario: Open ext4 partition by index
- **WHEN** an ext4 partition is opened with a GPT partition index
- **THEN** the partition offset and length are read from the GPT table
- **AND** the partition data is extracted to a temporary backing store via `dd`

#### Scenario: Open ext4 partition without index
- **WHEN** an ext4 partition image is opened without an index
- **THEN** the entire image is copied to a temporary backing store

#### Scenario: Write a file to an ext4 partition
- **WHEN** `write_file` is called with an input path and a target path
- **THEN** `debugfs` is used to create parent directories and write the file
- **AND** timestamps are set to epoch via `faketime`

#### Scenario: Read a file from an ext4 partition
- **WHEN** `read_file` is called with a file path
- **THEN** `debugfs` extracts the file to a temporary location
- **AND** the file contents are returned as bytes

#### Scenario: Read a non-existent file from ext4 partition
- **WHEN** `read_file` is called with a path that does not exist in the partition
- **THEN** an error is returned containing "File not found"

#### Scenario: Close ext4 partition writes back changes
- **WHEN** `close` is called on an ext4 partition opened with an offset
- **THEN** the modified backing store is written back to the original image at the correct offset

#### Scenario: Copy all files from ext4 partition
- **WHEN** `copy_files_to` is called with an output directory
- **THEN** all files are recursively dumped from the partition using `debugfs rdump`

#### Scenario: Fix up metadata on ext4 partition
- **WHEN** `fixup_metadata` is called with mode and optional SELinux context
- **THEN** ownership is set to root:root
- **AND** all timestamps (atime, ctime, mtime, crtime) are set to 0
- **AND** the SELinux security context is applied if provided

#### Scenario: Look up SELinux file contexts
- **WHEN** a `FileContexts` object is constructed from a contexts file
- **THEN** paths can be looked up against regex patterns
- **AND** the last matching pattern's label is returned (most specific match)

#### Scenario: Open FAT32 partition by index
- **WHEN** a FAT32 partition is opened with a GPT partition index
- **THEN** the partition offset is read from the GPT table
- **AND** `mtools` (mcopy) operates directly on the image using the `@@offset` syntax

#### Scenario: Write and read files on FAT32 partition
- **WHEN** a file is written to a FAT32 partition via `write_file`
- **THEN** `mcopy` copies the file into the image
- **AND** `read_file` can retrieve the same content back

#### Scenario: Extract GuestOS image from SetupOS image
- **WHEN** `extract_guestos` is given a SetupOS disk image
- **THEN** it decompresses the `.tar.zst` archive if needed
- **AND** opens the 4th GPT partition (data partition) as ext4
- **AND** extracts the `guest-os.img.tar.zst` file

#### Scenario: Get partition offset and length from GPT
- **WHEN** `get_partition_offset` or `get_partition_length` is called with a disk image and index
- **THEN** the GPT table is read and the byte offset/length of the specified partition is returned

---

## Configuration

### Requirement: IC-OS Configuration Type Definitions (config_types)

The `config_types` crate defines the configuration data structures for SetupOS, HostOS, and GuestOS, with strict backwards compatibility requirements.

#### Scenario: SetupOS configuration hierarchy
- **WHEN** a `SetupOSConfig` is created
- **THEN** it contains `config_version`, `network_settings`, `icos_settings`, `setupos_settings`, `hostos_settings`, and `guestos_settings`

#### Scenario: HostOS configuration inherits from SetupOS
- **WHEN** a `HostOSConfig` is generated from a `SetupOSConfig`
- **THEN** it includes `config_version`, `network_settings`, `icos_settings`, `hostos_settings`, and `guestos_settings`
- **AND** `setupos_settings` is excluded

#### Scenario: GuestOS configuration includes VM type and upgrade config
- **WHEN** a `GuestOSConfig` is deserialized
- **THEN** it includes `guest_vm_type` (Default, Upgrade, or Unknown)
- **AND** `upgrade_config` with optional `peer_guest_vm_address`
- **AND** optional `trusted_execution_environment_config` for SEV-SNP

#### Scenario: Forward compatibility for unknown enum variants
- **WHEN** a `GuestOSConfig` contains an unknown `guest_vm_type` variant
- **THEN** it deserializes to `GuestVMType::Unknown` without error

#### Scenario: Forward compatibility for unknown IPv6 config
- **WHEN** a `NetworkSettings` contains an unknown `Ipv6Config` variant
- **THEN** it deserializes to `Ipv6Config::Unknown` without error

#### Scenario: Reserved field paths are not reused
- **WHEN** the configuration is serialized
- **THEN** none of the field paths in `RESERVED_FIELD_PATHS` appear in the output
- **AND** previously removed fields like `icos_settings.logging` and `hostos_settings.vm_cpu` remain blocked

#### Scenario: Config version tracking
- **WHEN** any configuration change is made
- **THEN** `CONFIG_VERSION` must be incremented
- **AND** a deserialization test for the new version must be added

#### Scenario: Deployment environment parsing
- **WHEN** a deployment environment string is parsed
- **THEN** "mainnet" maps to `DeploymentEnvironment::Mainnet`
- **AND** "testnet" maps to `DeploymentEnvironment::Testnet`
- **AND** any other string returns an error

#### Scenario: IPv6 configuration modes
- **WHEN** IPv6 configuration is specified
- **THEN** it supports `Deterministic` (prefix + SLAAC), `Fixed` (explicit address), and `RouterAdvertisement` modes

#### Scenario: Default HostOS dev settings
- **WHEN** `HostOSDevSettings::default()` is used
- **THEN** `vm_memory` defaults to 16 GiB
- **AND** `vm_cpu` defaults to "kvm"
- **AND** `vm_nr_of_vcpus` defaults to 16

---

### Requirement: IC-OS Configuration Tool (config_tool)

The `config_tool` crate provides CLI commands for creating, transforming, and managing OS configuration across the SetupOS, HostOS, and GuestOS lifecycle.

#### Scenario: Create SetupOS config from config.ini and deployment.json
- **WHEN** the `create-setupos-config` command is run
- **THEN** it reads `config.ini` for network settings (IPv6 prefix, gateway, optional IPv4)
- **AND** reads `deployment.json` for NNS URLs, deployment environment, and VM resources
- **AND** resolves the management MAC address
- **AND** validates the `node_reward_type` matches the pattern `^type[0-9]+(\.[0-9])?$`
- **AND** writes a `SetupOSConfig` JSON file

#### Scenario: Generate HostOS config from SetupOS config
- **WHEN** the `generate-hostos-config` command is run
- **THEN** it reads the existing `SetupOSConfig`
- **AND** creates a `HostOSConfig` by copying all fields except `setupos_settings`
- **AND** writes the result as JSON

#### Scenario: Bootstrap IC node
- **WHEN** the `bootstrap-ic-node` command is run
- **THEN** it reads the `GuestOSConfig`
- **AND** sets up the IC node from the bootstrap directory and config

#### Scenario: Generate IC configuration
- **WHEN** the `generate-ic-config` command is run
- **THEN** it reads the `GuestOSConfig`
- **AND** generates the `ic.json5` configuration file

#### Scenario: Update HostOS config with node operator private key
- **WHEN** the `update-config` command is run
- **THEN** if the node operator private key file exists and is not already in config
- **THEN** the key is read and injected into `icos_settings.node_operator_private_key`
- **AND** `config_version` is updated to the current `CONFIG_VERSION`

#### Scenario: Skip update when key already present
- **WHEN** `update-config` is run but the config already contains a node operator private key
- **THEN** the update is skipped
- **AND** no file is modified

#### Scenario: Dump OS configuration
- **WHEN** the `dump-os-config` command is run with `--os-type HostOS`
- **THEN** the HostOS config is read from `/boot/config/config.json` and printed
- **AND** `SetupOS` type returns an error (not supported)

#### Scenario: Partial IPv4 configuration is rejected
- **WHEN** only some IPv4 fields are provided (e.g., address but no gateway)
- **THEN** a warning is printed
- **AND** the IPv4 configuration is set to `None`

---

## Networking

### Requirement: Deterministic IPv6 Address Generation (deterministic_ips)

The `deterministic_ips` crate generates deterministic MAC addresses and IPv6 addresses for IC-OS nodes based on the management MAC address and deployment environment.

#### Scenario: Calculate SLAAC IPv6 address from MAC and prefix
- **WHEN** `calculate_slaac` is called with a MAC address and IPv6 prefix
- **THEN** an EUI-64 interface identifier is computed by inserting `ff:fe` in the middle of the MAC
- **AND** the Universal/Local bit (bit 6 of the first octet) is flipped
- **AND** the identifier is combined with the prefix to form a full IPv6 address

#### Scenario: Calculate deterministic MAC from management MAC
- **WHEN** `calculate_deterministic_mac` is called with a management MAC, deployment environment, and node type
- **THEN** a seed string is formed as `<lowercase_mgmt_mac><deployment_environment>\n`
- **AND** the seed is SHA-256 hashed
- **AND** the resulting MAC has prefix `6a` (locally administered, unicast) followed by the node type index and 4 hash bytes

#### Scenario: Node type indices are unique and stable
- **WHEN** a `NodeType` is converted to its index
- **THEN** SetupOS maps to `0x0f`, HostOS to `0x00`, GuestOS to `0x01`, UpgradeGuestOS to `0x02`

#### Scenario: Parse node type from string (case-insensitive)
- **WHEN** a node type string like "gUest.oS" is parsed
- **THEN** non-alphanumeric characters are stripped and case is normalized
- **AND** the correct `NodeType` variant is returned

#### Scenario: Handle IPv6 prefix with and without trailing `::`
- **WHEN** a prefix like `2a04:9dc0:0:108` is provided (without `::`)
- **THEN** `::` is appended before parsing as an Ipv6Addr
- **AND** if the prefix already contains `::`, it is used as-is

#### Scenario: Reject invalid IPv6 prefixes
- **WHEN** an invalid prefix string is provided
- **THEN** `calculate_slaac` returns an error

---

### Requirement: Network Configuration Generation (network)

The `network` crate generates systemd network configuration files and resolves management MAC addresses.

#### Scenario: Generate network config for deterministic IPv6
- **WHEN** `generate_network_config` is called with `Ipv6Config::Deterministic`
- **THEN** the SLAAC address is calculated from the generated MAC and prefix
- **AND** systemd network configuration files are written to the output directory

#### Scenario: Reject unsupported IPv6 configuration modes
- **WHEN** `generate_network_config` is called with `RouterAdvertisement`, `Fixed`, or `Unknown`
- **THEN** an error is returned indicating the mode is not yet supported

#### Scenario: Resolve management MAC from deployment.json override
- **WHEN** `resolve_mgmt_mac` is called with a MAC address string
- **THEN** the string is parsed as a `MacAddr6`

#### Scenario: Resolve management MAC from IPMI
- **WHEN** `resolve_mgmt_mac` is called with `None`
- **THEN** `ipmitool lan print` is executed
- **AND** the MAC address line is parsed from the output using regex matching

#### Scenario: Handle ipmitool parse failures
- **WHEN** the ipmitool output does not contain a valid MAC address line
- **THEN** an error is returned with the full ipmitool output for debugging

---

### Requirement: NSS Name Resolution for IC-OS (nss_icos)

The `nss_icos` crate is a Name Service Switch (NSS) module that resolves the hostnames "hostos" and "guestos" to their respective IPv6 addresses.

#### Scenario: Resolve "hostos" hostname
- **WHEN** `get_host_by_name("hostos", IPv6)` is called
- **THEN** the local IPv6 address is obtained
- **AND** the 5th segment of the address is replaced with `0x6800`
- **AND** the resulting address is returned as the HostOS address

#### Scenario: Resolve "guestos" hostname
- **WHEN** `get_host_by_name("guestos", IPv6)` is called
- **THEN** the local IPv6 address is obtained
- **AND** the 5th segment of the address is replaced with `0x6801`
- **AND** the resulting address is returned as the GuestOS address

#### Scenario: Reverse lookup by IPv6 address
- **WHEN** `get_host_by_addr` is called with an IPv6 address
- **THEN** if it matches the computed HostOS address, "hostos" is returned
- **AND** if it matches the computed GuestOS address, "guestos" is returned
- **AND** otherwise `NotFound` is returned

#### Scenario: IPv4 lookups are not supported
- **WHEN** an IPv4 address or `AddressFamily::IPv4` is queried
- **THEN** `NotFound` is returned

#### Scenario: Unknown hostnames are not resolved
- **WHEN** `get_host_by_name` is called with any name other than "hostos" or "guestos"
- **THEN** `NotFound` is returned

#### Scenario: Local IPv6 address is cached
- **WHEN** the module is loaded
- **THEN** the local IPv6 address is queried once and cached via `lazy_static`
- **AND** subsequent lookups reuse the cached address without re-querying network interfaces

---

## Guest Upgrade

### Requirement: Guest Upgrade Shared Protocol (guest_upgrade_shared)

The `guest_upgrade_shared` crate defines the gRPC service protocol, constants, and attestation data structures shared between the upgrade client and server.

#### Scenario: Default server port
- **WHEN** the upgrade service is started
- **THEN** it listens on port 19522

#### Scenario: Store device path
- **WHEN** the encrypted store partition is referenced
- **THEN** the device path is `/dev/disk/by-partuuid/231213c6-ec9e-11f0-b45f-b7bbea44aaf0`

#### Scenario: Attestation custom data encoding stability
- **WHEN** `GetDiskEncryptionKeyTokenCustomData` is encoded for SEV attestation
- **THEN** the encoding is deterministic and stable across versions
- **AND** changing the encoding would break attestation report verification

#### Scenario: Attestation custom data namespace
- **WHEN** custom data is created for disk encryption key exchange
- **THEN** it uses the `SevCustomDataNamespace::GetDiskEncryptionKeyToken` namespace

---

### Requirement: Guest Upgrade Client (guest_upgrade_client)

The `guest_upgrade_client` crate runs inside the Upgrade Guest VM and retrieves the disk encryption key from the Default Guest VM via an attested TLS connection.

#### Scenario: Skip key exchange when not an upgrade VM
- **WHEN** the client starts and `guest_vm_type` is not `Upgrade`
- **THEN** it prints "Not an upgrade VM, skipping key exchange"
- **AND** exits successfully

#### Scenario: Skip key exchange when store can already be opened
- **WHEN** the client can already open the store partition with existing keys
- **THEN** it does not request a new disk encryption key
- **AND** it still signals success to the server

#### Scenario: Perform disk encryption key exchange
- **WHEN** the client connects to the server
- **THEN** it generates a self-signed TLS certificate
- **AND** connects to the peer Guest VM address on port 19522
- **AND** extracts the server's public key from the TLS connection

#### Scenario: Verify server attestation report
- **WHEN** the server's attestation package is received
- **THEN** the client verifies the server's measurement against blessed measurements from the NNS registry
- **AND** verifies that the custom data matches (binding both TLS public keys)
- **AND** verifies that the chip ID matches (same physical machine)

#### Scenario: Save retrieved disk encryption key
- **WHEN** the disk encryption key is successfully retrieved
- **THEN** it is written to the previous key path (`/var/alternative_store.keyfile`)

#### Scenario: Shutdown after exchange
- **WHEN** the key exchange completes (success or failure)
- **THEN** the Upgrade VM initiates a shutdown via `shutdown -h now`

#### Scenario: Create NNS registry client
- **WHEN** the registry client is initialized
- **THEN** the NNS public key is read from `/run/config/nns_public_key.pem`
- **AND** a `CertifiedNnsDataProvider` is created with the configured NNS URLs
- **AND** the client polls until the latest version is retrieved

---

### Requirement: Guest Upgrade Server (guest_upgrade_server)

The `guest_upgrade_server` crate runs inside the Default Guest VM and provides the disk encryption key to the Upgrade Guest VM via an attested gRPC service.

#### Scenario: Start key exchange server
- **WHEN** `exchange_keys` is called
- **THEN** a self-signed TLS certificate is generated
- **AND** blessed measurements are fetched from the NNS registry
- **AND** the gRPC server is started on the configured port

#### Scenario: Trigger Upgrade VM start
- **WHEN** the server is ready
- **THEN** it sends `Command::StartUpgradeGuestVM` to the host via vsock
- **AND** waits for the client to signal success

#### Scenario: Wait for key exchange completion with timeout
- **WHEN** the server waits for the Upgrade VM to complete
- **THEN** it uses a default timeout of 600 seconds
- **AND** if the timeout is exceeded, an `UpgradeVmError` is returned

#### Scenario: Handle Upgrade VM failure
- **WHEN** the Upgrade VM signals failure
- **THEN** the server returns a `DiskEncryptionKeyExchangeError::UpgradeVmError` with debug info

---

## OS Tools

### Requirement: Guest Disk Encryption (guest_disk)

The `guest_disk` crate manages LUKS2-encrypted disk partitions (var and store) for GuestOS, supporting both SEV-derived and pre-shared key encryption.

#### Scenario: Open var partition with SEV-derived key
- **WHEN** a var partition is opened with SEV encryption
- **THEN** a key is derived from the SEV measurement using HKDF-SHA256
- **AND** the LUKS device is activated under `/dev/mapper/var_crypt`

#### Scenario: Open store partition with previous key during upgrade
- **WHEN** a store partition is opened and a previous key file exists
- **THEN** the partition is first unlocked with the previous key
- **AND** the new SEV-derived key is added to the LUKS keyslots
- **AND** old keyslots (except the previous key and new key) are destroyed

#### Scenario: Clean up previous key on first boot after upgrade
- **WHEN** the GuestOS boots for the first time as the Default VM after an upgrade
- **THEN** the previous key file is removed from `/var/alternative_store.keyfile`

#### Scenario: Fall back to SEV key when previous key fails
- **WHEN** the previous key file exists but fails to unlock the store partition
- **THEN** the system falls through and attempts to open with the SEV-derived key

#### Scenario: Format partition with LUKS2
- **WHEN** `format` is called on a device path
- **THEN** a key is derived from the SEV measurement
- **AND** the device is formatted with LUKS2 using the derived key

#### Scenario: Check if store can be opened
- **WHEN** `can_open_store` is called
- **THEN** it first checks if the previous key file exists and can unlock the device
- **AND** if not, it checks if the SEV-derived key can unlock the device
- **AND** returns `true` if either key works

#### Scenario: Var partition does not allow discards
- **WHEN** the var partition is opened
- **THEN** `CryptActivate::empty()` flags are used (no TRIM/discard)

#### Scenario: Store partition allows discards
- **WHEN** the store partition is opened
- **THEN** `CryptActivate::ALLOW_DISCARDS` flag is set to enable TRIM

#### Scenario: Derive key from SEV measurement
- **WHEN** `derive_key_from_sev_measurement` is called
- **THEN** the SEV firmware provides a 32-byte derived key based on the guest measurement
- **AND** HKDF-SHA256 is used with an info string including the device path
- **AND** the result is returned as a base64-encoded string

#### Scenario: Different device paths produce different keys
- **WHEN** keys are derived for different device paths (e.g., `/dev/vda1` through `/dev/vda10`)
- **THEN** all derived keys are unique

---

### Requirement: Guest VM Runner (guest_vm_runner)

The `guest_vm_runner` crate manages the lifecycle of GuestOS virtual machines on the HostOS, including VM creation, direct boot, hugepage management, and upgrade orchestration.

#### Scenario: Start a Default Guest VM
- **WHEN** the guest VM runner starts the default VM
- **THEN** it reads the HostOS configuration
- **AND** calculates the deterministic MAC and IPv6 address for the GuestOS
- **AND** assembles the config media (configuration injected into the VM)
- **AND** reserves hugepages for VM memory
- **AND** generates the libvirt VM definition
- **AND** starts the VM via libvirt

#### Scenario: Direct boot support
- **WHEN** the VM is started with direct boot
- **THEN** the kernel and initrd are extracted from the GuestOS image
- **AND** kernel command line arguments are set
- **AND** the VM boots without a bootloader

#### Scenario: Handle Upgrade Guest VM request
- **WHEN** a `StartUpgradeGuestVM` command is received
- **THEN** the runner creates a mapped device for the upgrade partition
- **AND** assigns the upgrade VM a distinct MAC address (UpgradeGuestOS node type)
- **AND** configures the upgrade VM with peer address pointing to the default VM

#### Scenario: Monitor VM state
- **WHEN** the VM is running
- **THEN** the runner monitors for SIGTERM, SIGINT, and SIGHUP signals
- **AND** on shutdown signal, the VM is gracefully destroyed

#### Scenario: Require root privileges
- **WHEN** the runner is started without root privileges
- **THEN** an error is reported

---

### Requirement: Manual GuestOS Recovery (manual_guestos_recovery)

The `manual_guestos_recovery` crate provides an interactive TUI for performing manual GuestOS recovery operations.

#### Scenario: Accept recovery parameters
- **WHEN** the recovery TUI is launched
- **THEN** the user enters a version (40 hex character git commit hash)
- **AND** a recovery hash prefix (6 hex characters)

#### Scenario: Execute recovery preparation
- **WHEN** recovery parameters are submitted
- **THEN** a preparation command is built and executed
- **AND** process output is monitored with a polling interval of 100ms
- **AND** up to 30 error lines are displayed

#### Scenario: Execute recovery installation
- **WHEN** preparation completes successfully
- **THEN** the installation command is built and executed
- **AND** metadata is read from `/run/guestos-recovery/stage/prep-info`

---

## Remote Attestation

### Requirement: Remote Attestation Service (remote_attestation_server, remote_attestation_shared)

The remote attestation crates provide a gRPC service that generates SEV-SNP attestation packages for external verification.

#### Scenario: Handle attestation request with custom data
- **WHEN** an `AttestRequest` with 32 bytes of custom data is received
- **THEN** the custom data is wrapped in `SevCustomData` with the `RawRemoteAttestation` namespace
- **AND** an attestation package is generated via SEV firmware
- **AND** the response contains the full attestation package

#### Scenario: Handle attestation request without custom data
- **WHEN** an `AttestRequest` with no custom data is received
- **THEN** 32 zero bytes are used as the custom data
- **AND** the attestation package is generated normally

#### Scenario: Reject invalid custom data length
- **WHEN** an `AttestRequest` with custom data that is not exactly 32 bytes is received
- **THEN** an `InvalidArgument` error is returned with message "custom_data must be 32 bytes"

#### Scenario: SEV disabled node
- **WHEN** SEV is not active on the node
- **THEN** all attestation requests return an `Unavailable` error "SEV is not enabled on this node"

#### Scenario: Service listens on default port
- **WHEN** the remote attestation server starts
- **THEN** it listens on port 19523 (from `remote_attestation_shared::DEFAULT_PORT`)
- **AND** binds to all IPv6 interfaces (`[::]`)

#### Scenario: Detect SEV status
- **WHEN** the server starts
- **THEN** it checks `is_sev_active()` to determine if SEV firmware is available
- **AND** if SEV is active, it opens `/dev/sev-guest` and reads the TEE config from GuestOS config

---

## SEV (AMD Secure Encrypted Virtualization)

### Requirement: SEV Guest Firmware Interface (sev_guest)

The `sev_guest` crate provides guest-side SEV-SNP operations including key derivation and attestation report generation.

#### Scenario: Check if SEV is active
- **WHEN** `is_sev_active()` is called
- **THEN** the `SEV_ACTIVE` environment variable is read
- **AND** "1" returns `Ok(true)`, "0" returns `Ok(false)`
- **AND** any other value returns an error

#### Scenario: Generate attestation package
- **WHEN** `generate_attestation_package` is called
- **THEN** the SEV firmware generates an attestation report with custom data
- **AND** the report is combined with the certificate chain from the TEE config
- **AND** the resulting package can be verified by remote parties

#### Scenario: Key derivation uses measurement binding
- **WHEN** a key is derived via `derive_key_from_sev_measurement`
- **THEN** `GuestFieldSelect::measurement` is set to true
- **AND** the derived key is unique per guest measurement (code identity)

---

### Requirement: SEV Host Certificate Provider (sev_host)

The `sev_host` crate runs on the HostOS and provides SEV certificate chains to Guest VMs.

#### Scenario: Load certificate chain with caching
- **WHEN** `load_certificate_chain_pem` is called
- **THEN** the VCEK (Versioned Chip Endorsement Key) is loaded
- **AND** it is concatenated with the ASK (AMD SEV Key) and ARK (AMD Root Key)
- **AND** the result is a PEM string containing exactly 3 certificates

#### Scenario: VCEK cache hit
- **WHEN** the VCEK has been previously downloaded
- **THEN** it is loaded from the file cache instead of the AMD key server
- **AND** the cache filename encodes the chip ID and TCB version

#### Scenario: VCEK cache miss
- **WHEN** the VCEK is not in the cache
- **THEN** it is fetched from the AMD Key Distribution Service (KDS)
- **AND** the URL includes the chip ID and TCB version parameters
- **AND** the downloaded VCEK is verified as valid DER before caching

#### Scenario: Retry on AMD key server failure
- **WHEN** the AMD key server request fails
- **THEN** up to 5 attempts are made with exponential backoff (2s, 4s, 6s, 8s, 10s)
- **AND** if all attempts fail, an error is returned

#### Scenario: Fallback to SOCKS proxy
- **WHEN** a direct connection to the AMD key server fails
- **THEN** a SOCKS5 proxy at `socks5://socks5.ic0.app:1080` is used as fallback

#### Scenario: Disabled TEE mode
- **WHEN** `enable_trusted_execution_environment` is false
- **THEN** `load_certificate_chain_pem` returns `None`

---

### Requirement: SEV Attestation Verification (attestation)

The `attestation` crate provides attestation package parsing, verification, and custom data encoding.

#### Scenario: Verify attestation package measurement
- **WHEN** an attestation package is parsed and `verify_measurement` is called
- **THEN** the measurement in the attestation report is checked against a list of blessed measurements
- **AND** verification fails if no blessed measurement matches

#### Scenario: Verify attestation package custom data
- **WHEN** `verify_custom_data` is called
- **THEN** the custom data in the attestation report is compared against the expected value
- **AND** verification fails on mismatch

#### Scenario: Verify chip ID
- **WHEN** `verify_chip_id` is called with a list of allowed chip IDs
- **THEN** the chip ID in the attestation report must match one of the allowed IDs

#### Scenario: Verify certificate chain
- **WHEN** an attestation package is parsed with `SevRootCertificateVerification::Verify`
- **THEN** the certificate chain (VCEK, ASK, ARK) is validated
- **AND** the attestation report signature is verified against the VCEK

#### Scenario: Custom data namespace isolation
- **WHEN** custom data is encoded with a namespace
- **THEN** different namespaces (e.g., `RawRemoteAttestation` vs `GetDiskEncryptionKeyToken`) produce different encodings
- **AND** this prevents cross-purpose replay of attestation reports

#### Scenario: Verification error types
- **WHEN** attestation verification fails
- **THEN** the error includes a specific detail variant: `InvalidAttestationReport`, `InvalidCertificateChain`, `InvalidChipId`, `InvalidCustomData`, `InvalidMeasurement`, or `InvalidSignature`

---

## Metrics

### Requirement: Filesystem TRIM Tool (fstrim_tool)

The `fstrim_tool` crate runs `fstrim` on specified directories and exports Prometheus metrics about TRIM operations.

#### Scenario: Run fstrim on target directory
- **WHEN** `fstrim_tool` is called with a target directory
- **THEN** the `fstrim` command is executed on the target
- **AND** elapsed time and success/failure are recorded

#### Scenario: Run fstrim on data directory for unassigned nodes
- **WHEN** `fstrim_tool` is called with a non-empty `datadir_target`
- **THEN** if the node is not assigned (no CatchUpPackage exists)
- **THEN** `fstrim` is also run on the data directory
- **AND** metrics are updated separately for the data directory

#### Scenario: Skip data directory trim for assigned nodes
- **WHEN** a CatchUpPackage file exists at `/var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb`
- **THEN** the data directory trim is skipped

#### Scenario: Initialize metrics file
- **WHEN** `fstrim_tool` is called with `--init-only`
- **THEN** an initial metrics file is written if one does not already exist
- **AND** no `fstrim` command is executed

#### Scenario: Update metrics atomically
- **WHEN** metrics are written
- **THEN** they are written to a temporary file first
- **AND** then atomically renamed to the target path

#### Scenario: Handle pre-existing metrics
- **WHEN** a metrics file already exists
- **THEN** existing metrics are parsed and updated (not overwritten)
- **AND** parse errors fall back to default metrics

---

### Requirement: NFT Firewall Counter Exporter (nft_exporter)

The `nft_exporter` crate exports nftables firewall counters as Prometheus metrics.

#### Scenario: Export nftables counters
- **WHEN** the exporter runs
- **THEN** it executes `nft --json list ruleset`
- **AND** parses the JSON output to extract counter objects
- **AND** writes Prometheus-formatted metrics to the metrics file

#### Scenario: Format counters as Prometheus metrics
- **WHEN** a counter is converted to a metric string
- **THEN** it includes `# HELP`, `# TYPE counter`, and the counter value
- **AND** the metric name matches the nft counter name

#### Scenario: Handle empty ruleset
- **WHEN** the nftables ruleset contains no counters
- **THEN** an empty metrics file is written (with trailing newline)

#### Scenario: Handle invalid JSON structure
- **WHEN** the nftables JSON output does not contain a `nftables` key
- **THEN** an error is returned

#### Scenario: Default metrics file path
- **WHEN** no `--metrics-file` argument is provided
- **THEN** the default path `/run/node_exporter/collector_textfile/firewall_counters.prom` is used

---

## Vsock Communication

### Requirement: Vsock Protocol (vsock_lib)

The `vsock_lib` crate implements the vsock communication protocol between GuestOS and HostOS, including the client, server, and command protocol.

#### Scenario: Send command from guest to host
- **WHEN** a `VSockClient` sends a command
- **THEN** a `Request` is constructed with the guest's CID and the command
- **AND** it is serialized as JSON and sent over a vsock stream to port 19090

#### Scenario: Supported commands
- **WHEN** the guest sends a command
- **THEN** the following commands are supported:
  - `AttachHSM` - attach a Hardware Security Module
  - `DetachHSM` - detach the HSM
  - `Upgrade(url, target_hash)` - trigger a HostOS upgrade
  - `Notify(count, message)` - send a notification
  - `GetVsockProtocol` - query the vsock protocol version
  - `GetHostOSVersion` - query the HostOS version
  - `StartUpgradeGuestVM` - start the upgrade guest VM

#### Scenario: Server verifies sender CID
- **WHEN** a request is received by the host server
- **THEN** the `guest_cid` field in the request must match the peer address CID from the vsock stream
- **AND** a mismatch results in an error response

#### Scenario: Host server processes connections
- **WHEN** the host vsock server receives a connection
- **THEN** it sets 5-second read/write timeouts
- **AND** spawns a thread to process the request
- **AND** dispatches the command and sends the JSON response

#### Scenario: Guest client timeouts
- **WHEN** the guest vsock client creates a connection
- **THEN** read and write timeouts are set to 5 minutes (300 seconds)
- **AND** this allows enough time for long-running operations like HostOS upgrades

#### Scenario: Response payloads
- **WHEN** a response is received
- **THEN** it is either `Ok(Payload)` or `Err(String)`
- **AND** `Payload` can be `HostOSVsockVersion`, `HostOSVersion(String)`, or `NoPayload`

#### Scenario: Vsock protocol versioning
- **WHEN** `GetVsockProtocol` is requested
- **THEN** the response contains a `HostOSVsockVersion` with major, minor, and patch fields

---

### Requirement: Vsock Host Server (vsock_host)

The vsock host server binary runs on the HostOS and listens for vsock connections from GuestOS.

#### Scenario: Start vsock host server
- **WHEN** the vsock host binary is started
- **THEN** it binds to `VMADDR_CID_ANY` on port 19090
- **AND** listens for incoming vsock connections indefinitely

---

### Requirement: Vsock Guest Client (vsock_guest)

The vsock guest binary runs inside GuestOS and sends commands to the HostOS.

#### Scenario: Send command to host
- **WHEN** the vsock guest binary is invoked with a command
- **THEN** it obtains its local CID via `vsock::get_local_cid()`
- **AND** constructs and sends a request to the host
- **AND** parses and returns the response
