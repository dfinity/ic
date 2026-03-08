# Core Types

**Crates**: `ic-limits`

## Requirements

### Requirement: PrincipalId Identity Representation
PrincipalId is the fundamental identity type on the Internet Computer, representing principals as variable-length blobs (up to 29 bytes) encoded as a fixed-size array with a length field. It wraps the candid Principal type and implements Copy semantics.

#### Scenario: PrincipalId maximum length constraint
- **WHEN** a PrincipalId is constructed from a byte slice
- **THEN** the slice length MUST NOT exceed 29 bytes (MAX_LENGTH_IN_BYTES)
- **AND** an error is returned if the slice is too long

#### Scenario: PrincipalId textual representation roundtrip
- **WHEN** a PrincipalId is converted to its textual representation
- **THEN** parsing the textual representation back yields the same PrincipalId
- **AND** parsing is case-insensitive per the IC interface spec

#### Scenario: PrincipalId binary representation roundtrip
- **WHEN** a PrincipalId is converted to a byte vector via to_vec()
- **THEN** constructing a PrincipalId from that byte vector via TryFrom yields the same PrincipalId

#### Scenario: PrincipalId class identification
- **WHEN** a PrincipalId is created with new_opaque()
- **THEN** its class() returns Ok(PrincipalIdClass::Opaque)
- **WHEN** a PrincipalId is created with new_self_authenticating(pubkey)
- **THEN** its class() returns Ok(PrincipalIdClass::SelfAuthenticating)
- **AND** authenticates_for_pubkey(pubkey) returns true
- **WHEN** a PrincipalId is created with new_derived(registerer, seed)
- **THEN** its class() returns Ok(PrincipalIdClass::Derived)
- **AND** is_derived(registerer, seed) returns true
- **WHEN** a PrincipalId is created with new_anonymous()
- **THEN** its class() returns Ok(PrincipalIdClass::Anonymous)
- **AND** is_anonymous() returns true
- **AND** its textual form is "2vxsx-fae"

#### Scenario: PrincipalId self-authenticating construction
- **WHEN** new_self_authenticating(pubkey) is called
- **THEN** the PrincipalId contains the SHA-224 hash of the public key
- **AND** the last byte is set to PrincipalIdClass::SelfAuthenticating (2)
- **AND** the total length is exactly 29 bytes (28 hash bytes + 1 class byte)

#### Scenario: PrincipalId derived construction
- **WHEN** new_derived(registerer, seed) is called
- **THEN** the blob is formed by prepending the registerer's length, concatenating the registerer bytes and seed, then SHA-224 hashing
- **AND** the last byte is set to PrincipalIdClass::Derived (3)

#### Scenario: PrincipalId ordering
- **WHEN** PrincipalIds are sorted
- **THEN** they are ordered lexicographically by their byte representation length first, then by content

#### Scenario: PrincipalId protobuf conversion
- **WHEN** a PrincipalId is converted to pb::PrincipalId
- **THEN** the raw field contains the PrincipalId's byte representation
- **AND** converting back via TryFrom yields the same PrincipalId

#### Scenario: PrincipalId textual format validation
- **WHEN** parsing from a string with bad checksum
- **THEN** a CheckSequenceNotMatch error is returned
- **WHEN** parsing from an empty string or too-short string
- **THEN** a TextTooShort error is returned
- **WHEN** parsing from a string exceeding maximum length
- **THEN** a TextTooLong error is returned

### Requirement: CanisterId Type Safety
CanisterId wraps a PrincipalId to represent canister identities. It provides a from_u64 constructor for creating well-formed canister IDs and an unchecked constructor for legacy compatibility.

#### Scenario: CanisterId from_u64 construction
- **WHEN** CanisterId::from_u64(val) is called
- **THEN** the resulting PrincipalId contains val as big-endian bytes followed by 0x01 marker byte and Opaque class byte
- **AND** the total raw length is 10 bytes
- **AND** ordering of CanisterIds matches ordering of their u64 values

#### Scenario: CanisterId management canister
- **WHEN** CanisterId::ic_00() is called
- **THEN** the returned CanisterId has an empty PrincipalId (length 0)
- **AND** it represents the management canister

#### Scenario: CanisterId try_from_principal_id validation
- **WHEN** try_from_principal_id is called with a valid canister principal
- **THEN** it succeeds if the principal is Opaque class, 10 bytes long, and byte 8 is 0x01
- **WHEN** the principal is not Opaque class, wrong length, or missing 0x01 marker
- **THEN** an InvalidPrincipalId error is returned

#### Scenario: CanisterId unchecked_from_principal backward compatibility
- **WHEN** CanisterId::unchecked_from_principal(principal_id) is called
- **THEN** the CanisterId is created WITHOUT validation
- **AND** TryFrom<PrincipalId> for CanisterId ALWAYS returns Ok (legacy behavior)

#### Scenario: CanisterId protobuf roundtrip
- **WHEN** a CanisterId is converted to pb::CanisterId
- **THEN** it contains the inner PrincipalId in the principal_id field
- **AND** converting back via TryFrom requires the principal_id field to be present

### Requirement: NodeId, SubnetId, and UserId Type-Safe Wrappers
NodeId, SubnetId, and UserId are type-safe wrappers around PrincipalId using the phantom_newtype Id pattern, preventing accidental mixing of different identity types.

#### Scenario: NodeId is distinct from SubnetId
- **WHEN** a NodeId and SubnetId are created from the same PrincipalId
- **THEN** they are incompatible types that cannot be compared or assigned to each other at compile time

#### Scenario: NodeId protobuf conversion
- **WHEN** node_id_into_protobuf(id) is called
- **THEN** the pb::NodeId contains the inner PrincipalId
- **AND** node_id_try_from_option(Some(pb_node_id)) recovers the original NodeId
- **AND** node_id_try_from_option(None) returns ProxyDecodeError::MissingField

#### Scenario: SubnetId protobuf conversion
- **WHEN** subnet_id_into_protobuf(id) is called
- **THEN** the pb::SubnetId contains the inner PrincipalId
- **AND** subnet_id_try_from_protobuf recovers the original SubnetId
- **AND** subnet_id_try_from_option(None, field_name) returns ProxyDecodeError::MissingField

### Requirement: RegistryVersion Monotonic Counter
RegistryVersion represents the registry's version as a type-safe AmountOf<RegistryVersionTag, u64>, supporting arithmetic and comparison operations.

#### Scenario: RegistryVersion arithmetic
- **WHEN** two RegistryVersions are compared
- **THEN** comparison follows the underlying u64 ordering
- **AND** increment/decrement operations produce the expected values

### Requirement: Height Block Chain Sequencing
Height represents a block's position in the chain as AmountOf<HeightTag, u64>.

#### Scenario: Height monotonic progression
- **WHEN** a block is created at Height h
- **THEN** its child block MUST have Height h+1
- **AND** Heights support arithmetic operations for increment/decrement

### Requirement: NumBytes and NumInstructions Resource Tracking
NumBytes and NumInstructions provide type-safe representations of resource quantities.

#### Scenario: NumBytes display formatting
- **WHEN** a NumBytes value is displayed
- **THEN** it uses the most appropriate binary power unit (bytes, KiB, MiB, GiB) with up to 2 decimal places
- **AND** no decimals are used when the unit is 'bytes'

#### Scenario: NumInstructions display formatting
- **WHEN** a NumInstructions value is displayed
- **THEN** it formats the number with underscore separators for readability

### Requirement: Time Representation
Time represents nanoseconds since Unix epoch as a u64, with explicit construction preventing the Default trait from being implemented.

#### Scenario: Time from nanoseconds
- **WHEN** Time::from_nanos_since_unix_epoch(nanos) is called
- **THEN** as_nanos_since_unix_epoch() returns the same nanos value

#### Scenario: Time from milliseconds
- **WHEN** Time::from_millis_since_unix_epoch(millis) is called
- **THEN** the result equals millis * 1_000_000 in nanoseconds
- **AND** overflow returns an error

#### Scenario: Time arithmetic
- **WHEN** a Duration is added to a Time
- **THEN** the result is a new Time advanced by that duration
- **AND** UNIX_EPOCH is the constant for time zero

#### Scenario: GENESIS constant
- **WHEN** GENESIS is referenced
- **THEN** it corresponds to 2021-05-06T19:17:10 UTC (1_620_328_630_000_000_000 nanos)

### Requirement: ComputeAllocation Bounded Percentage
ComputeAllocation represents a canister's compute allocation as a percentage between 0 and 100 inclusive.

#### Scenario: ComputeAllocation valid range
- **WHEN** ComputeAllocation is created from a u64 value
- **THEN** values 0..=100 succeed
- **AND** values > 100 return InvalidComputeAllocationError

#### Scenario: ComputeAllocation default
- **WHEN** ComputeAllocation::default() is called
- **THEN** it returns 0% allocation per the IC interface spec

### Requirement: MemoryAllocation Resource Reservation
MemoryAllocation represents a canister's pre-allocated memory as a number of bytes.

#### Scenario: MemoryAllocation allocated_bytes
- **WHEN** allocated_bytes(memory_usage) is called
- **THEN** it returns the maximum of the pre-allocated amount and actual memory usage

### Requirement: Randomness Type Safety
Randomness is typed as Id<RandomnessTag, [u8; 32]>, ensuring 256-bit random values produced by consensus are not confused with other 32-byte values.

#### Scenario: Randomness construction
- **WHEN** Randomness is created from a [u8; 32]
- **THEN** it wraps the value with type safety preventing misuse as a CryptoHash or other 32-byte type

### Requirement: SnapshotId Cross-Subnet Uniqueness
SnapshotId combines a canister ID and a local snapshot ID (u64) into a globally unique identifier.

#### Scenario: SnapshotId construction from canister and local ID
- **WHEN** SnapshotId::from((canister_id, local_id)) is called
- **THEN** the first 8 bytes contain the local_id in big-endian format
- **AND** the remaining bytes contain the canister_id's principal bytes

#### Scenario: SnapshotId roundtrip serialization
- **WHEN** a SnapshotId is encoded via Candid and decoded back
- **THEN** the decoded SnapshotId equals the original

#### Scenario: SnapshotId length validation
- **WHEN** SnapshotId::try_from is called with fewer than 8 bytes
- **THEN** InvalidLength error is returned
- **WHEN** called with more than MAX_LENGTH_IN_BYTES bytes
- **THEN** InvalidLength error is returned

### Requirement: ExecutionRound vs Height Semantic Distinction
ExecutionRound (Id<ExecutionRoundTag, u64>) and Height (AmountOf<HeightTag, u64>) represent related but semantically different concepts. A batch at Height h triggers ExecutionRound h, but the round may process messages from earlier heights.

#### Scenario: ExecutionRound identity semantics
- **WHEN** an ExecutionRound is used in scheduler context
- **THEN** it identifies the round without supporting arithmetic operations on it
- **AND** Height supports increment/decrement for Message Routing use

### Requirement: CanisterTimer Scheduled Execution
CanisterTimer represents either an inactive timer or an active timer set at a specific Time.

#### Scenario: CanisterTimer inactive state
- **WHEN** CanisterTimer::Inactive is checked with has_reached_deadline(now)
- **THEN** it returns false regardless of the current time

#### Scenario: CanisterTimer active deadline
- **WHEN** CanisterTimer::Active(deadline) is checked with has_reached_deadline(now)
- **THEN** it returns true if now >= deadline, false otherwise

#### Scenario: CanisterTimer protobuf roundtrip
- **WHEN** a CanisterTimer is converted to protobuf and back
- **THEN** Inactive maps to global_timer_nanos: None
- **AND** Active(time) maps to global_timer_nanos: Some(nanos)

### Requirement: LongExecutionMode Scheduling Strategy
LongExecutionMode controls whether a long-running canister execution is scheduled opportunistically or with priority.

#### Scenario: Default execution mode
- **WHEN** LongExecutionMode::default() is called
- **THEN** it returns Opportunistic

### Requirement: CountBytes Estimation Trait
CountBytes allows objects to report an estimated byte size, used for resource management and payload size enforcement.

#### Scenario: CountBytes contract
- **WHEN** count_bytes() is called on an object
- **THEN** it returns an estimated byte size (not necessarily exact heap usage or serialized length)

### Requirement: CryptoHash and CryptoHashOf Type Safety
CryptoHash wraps a Vec<u8> for cryptographic hashes. CryptoHashOf<T> (type alias for Id<T, CryptoHash>) provides type safety for hashes of specific content types.

#### Scenario: CryptoHashOf type distinction
- **WHEN** a CryptoHashOf<Block> and CryptoHashOf<State> exist
- **THEN** they are incompatible types at compile time, preventing hash confusion

### Requirement: Signed Content Wrapper
Signed<T, S> pairs content of type T with a signature S, providing a generic signed artifact container.

#### Scenario: Signed content and signature
- **WHEN** a Signed<T, S> is constructed
- **THEN** it contains both .content of type T and .signature of type S
- **AND** CountBytes is implemented if both T and S implement CountBytes

### Requirement: hash_of_map Deterministic Hashing
hash_of_map computes a deterministic hash of a BTreeMap following the IC public spec's hash_of_map specification.

#### Scenario: hash_of_map ordering independence
- **WHEN** hash_of_map is called on a BTreeMap
- **THEN** the pair hashes are sorted before final hashing
- **AND** the result is deterministic regardless of insertion order (guaranteed by BTreeMap)
