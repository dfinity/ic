# Supporting Crates

**Crates**: `candid-utils`, `fe-derive`, `command_runner`, `local_key`

## Requirements

### Requirement: tree_deserializer Labeled Tree Deserialization
tree_deserializer provides deserialization of IC's labeled tree structure, used for certified data and state tree traversal.

#### Scenario: Tree deserialization
- **WHEN** a labeled tree is deserialized
- **THEN** it produces a structured representation of the IC state tree
- **AND** types are defined in the types submodule

### Requirement: ic-sys OS Page Management
ic-sys provides platform-specific constants and utilities for OS-level memory page management.

#### Scenario: PAGE_SIZE platform specificity
- **WHEN** running on aarch64 Apple (M-series Mac)
- **THEN** PAGE_SIZE is 16384 bytes (16 KiB)
- **WHEN** running on other platforms (x86_64 Linux)
- **THEN** PAGE_SIZE is 4096 bytes (4 KiB)

#### Scenario: HUGE_PAGE_SIZE platform specificity
- **WHEN** running on x86_64 Linux
- **THEN** HUGE_PAGE_SIZE is 2 MiB for huge page optimization
- **WHEN** running on aarch64 Apple
- **THEN** HUGE_PAGE_SIZE equals PAGE_SIZE (no huge page optimization)

#### Scenario: PAGE_SIZE matches system config
- **WHEN** sysconf_page_size() is called
- **THEN** it returns the same value as the compile-time PAGE_SIZE constant

#### Scenario: PageIndex type safety
- **WHEN** PageIndex is used
- **THEN** it is Id<PageIndexTag, u64> representing a 0-based OS page index in Wasm instance memory
- **AND** it MUST NOT be confused with 64KiB Wasm memory pages (which consist of 16 OS pages on x86)

#### Scenario: PageBytes type
- **WHEN** PageBytes is used
- **THEN** it is [u8; PAGE_SIZE] representing the raw contents of an OS page

#### Scenario: page_bytes_from_ptr safety contract
- **WHEN** page_bytes_from_ptr(owner, ptr) is called
- **THEN** the caller MUST ensure the memory range [ptr..ptr+PAGE_SIZE) has no mutable borrows
- **AND** the memory remains valid for the lifetime of the owner reference
- **AND** the function returns a &PageBytes reference tied to the owner's lifetime

### Requirement: ic-sys Filesystem and Utility Commands
ic-sys provides filesystem utilities (fs module), memory mapping (mmap module), and utility command execution (utility_command module).

#### Scenario: WSL detection
- **WHEN** IS_WSL is accessed
- **THEN** it returns true if running under Windows Subsystem for Linux

### Requirement: ic-utils Common Utilities
ic-utils provides small utility types and functions shared across the codebase.

#### Scenario: byte_slice_fmt truncation
- **WHEN** truncate_and_format is used on a byte slice
- **THEN** it provides a human-readable truncated representation

#### Scenario: str ellipsize
- **WHEN** StrEllipsize is used on a string
- **THEN** it truncates the string with an ellipsis if it exceeds the maximum length

#### Scenario: serde_arc transparent serialization
- **WHEN** Arc<T> is serialized via serde_arc
- **THEN** the serialization is transparent (same format as T)

#### Scenario: deterministic_operations
- **WHEN** deterministic file operations are needed (Unix only)
- **THEN** the deterministic_operations module provides them

#### Scenario: rle Run-Length Encoding
- **WHEN** data needs compact representation
- **THEN** the rle module provides run-length encoding utilities

### Requirement: Artifact Traits IdentifiableArtifact and PbArtifact
IdentifiableArtifact defines the contract for artifacts that can be stored in pools and replicated via P2P, while PbArtifact extends it with protobuf serialization support.

#### Scenario: IdentifiableArtifact contract
- **WHEN** a type implements IdentifiableArtifact
- **THEN** it provides a NAME constant, an associated Id type (Hash + Clone + Eq + Send + Sync), and an id() method
- **AND** it must be Send + 'static

#### Scenario: PbArtifact serialization contract
- **WHEN** a type implements PbArtifact
- **THEN** PbId defines the protobuf ID wire type with From<Id> and TryInto<Id>
- **AND** PbMessage defines the protobuf message type with From<Self> and TryInto<Self>
- **AND** both conversion errors implement std::error::Error and Into<ProxyDecodeError>

### Requirement: UnvalidatedArtifactMutation Pool Mutation Operations
UnvalidatedArtifactMutation<Artifact> represents insertions and removals in the unvalidated artifact pool.

#### Scenario: Insert mutation
- **WHEN** Insert((artifact, node_id)) is applied
- **THEN** the artifact is added to the unvalidated pool tagged with its source node

#### Scenario: Remove mutation
- **WHEN** Remove(id) is applied
- **THEN** the artifact with the given ID is removed from the unvalidated pool

### Requirement: Registry Error Types
RegistryClientError and RegistryDataProviderError capture all failure modes when interacting with the registry.

#### Scenario: VersionNotAvailable
- **WHEN** a specific registry version is requested but not available locally
- **THEN** RegistryClientError::VersionNotAvailable is returned

#### Scenario: DataProviderTimeout
- **WHEN** fetching registry updates times out
- **THEN** RegistryDataProviderError::Timeout is returned

#### Scenario: DataProviderTransfer
- **WHEN** the registry transport client fails
- **THEN** RegistryDataProviderError::Transfer { source } is returned with error details

#### Scenario: DecodeError
- **WHEN** registry contents cannot be decoded
- **THEN** RegistryClientError::DecodeError { error } is returned
