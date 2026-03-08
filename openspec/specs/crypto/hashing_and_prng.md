# Hashing and Pseudorandom Number Generation

## Requirements

### Requirement: SHA-256 Hashing
The `ic_crypto_sha2::Sha256` type provides SHA-256 hashing with a constant 32-byte output.

#### Scenario: Hashing data incrementally
- **WHEN** a `Sha256` hasher is created with `Sha256::new()`
- **THEN** data can be written incrementally via `write()`
- **AND** `finish()` produces a `[u8; 32]` digest

#### Scenario: Hashing data with convenience function
- **WHEN** `Sha256::hash(data)` is called
- **THEN** a `[u8; 32]` SHA-256 digest is returned

#### Scenario: Using Sha256 as std::io::Writer
- **WHEN** `Sha256` is used with `std::io::copy`
- **THEN** data is streamed through the hasher
- **AND** the digest can be retrieved after streaming

### Requirement: SHA-224 Hashing
The `ic_crypto_sha2::Sha224` type provides SHA-224 hashing with a constant 28-byte output.

#### Scenario: Hashing data incrementally
- **WHEN** a `Sha224` hasher is created with `Sha224::new()`
- **THEN** data can be written incrementally via `write()`
- **AND** `finish()` produces a `[u8; 28]` digest

#### Scenario: Hashing data with convenience function
- **WHEN** `Sha224::hash(data)` is called
- **THEN** a `[u8; 28]` SHA-224 digest is returned

### Requirement: SHA-512 Hashing
The `ic_crypto_sha2::Sha512` type provides SHA-512 hashing.

#### Scenario: SHA-512 availability
- **WHEN** `Sha512` is used
- **THEN** it follows the same API pattern as Sha256 and Sha224

### Requirement: Domain Separation Context
The `DomainSeparationContext` type provides domain separation for hash functions.

#### Scenario: Domain-separated hashing
- **WHEN** a `DomainSeparationContext` is used
- **THEN** it prepends domain separation information to the hash input
- **AND** different domains produce different hashes for the same data

### Requirement: Algorithm Stability
Hash algorithms are guaranteed not to change across registry versions.

#### Scenario: Algorithm guarantee
- **WHEN** `Sha256`, `Sha224`, or `Sha512` is used
- **THEN** the underlying algorithm is fixed and will not change
- **AND** digests can be safely persisted to disk for later comparison

### Requirement: Hardware Acceleration
The SHA-2 implementation leverages hardware acceleration where available.

#### Scenario: Hardware-accelerated hashing
- **WHEN** the platform supports SHA-NI (x86) or ARMv8 SHA extensions
- **THEN** the hardware-accelerated implementation is used automatically
- **AND** a pure Rust fallback is available for Wasm targets

---

### Requirement: Cryptographically Secure PRNG
The `Csprng` type provides a cryptographically secure pseudorandom number generator using the ChaCha20 stream cipher.

#### Scenario: Creating CSPRNG from random beacon
- **WHEN** `Csprng::from_random_beacon_and_purpose` is called with a `RandomBeacon` and `RandomnessPurpose`
- **THEN** randomness is derived from the beacon via `randomness_from_crypto_hashable`
- **AND** a domain-separated seed is created from the randomness and purpose

#### Scenario: Creating CSPRNG from randomness
- **WHEN** `Csprng::from_randomness_and_purpose` is called with `Randomness` and `RandomnessPurpose`
- **THEN** a `Seed` is created from the randomness bytes
- **AND** the seed is derived with the purpose's domain separator
- **AND** a `ChaCha20Rng` is created from the derived seed

#### Scenario: CSPRNG implements RngCore and CryptoRng
- **WHEN** a `Csprng` instance is used
- **THEN** it implements `RngCore` (providing `next_u32`, `next_u64`, `fill_bytes`, `try_fill_bytes`)
- **AND** it implements `CryptoRng` (marking it as suitable for cryptographic use)

### Requirement: Randomness Purpose Domain Separation
Different randomness purposes produce independent PRNG streams.

#### Scenario: CommitteeSampling purpose
- **WHEN** the purpose is `RandomnessPurpose::CommitteeSampling`
- **THEN** the domain separator is `"ic-crypto-prng-committee-sampling"`

#### Scenario: BlockmakerRanking purpose
- **WHEN** the purpose is `RandomnessPurpose::BlockmakerRanking`
- **THEN** the domain separator is `"ic-crypto-prng-blockmaker-ranking"`

#### Scenario: ExecutionThread purpose
- **WHEN** the purpose is `RandomnessPurpose::ExecutionThread(thread_id)`
- **THEN** the domain separator is `"ic-crypto-prng-execution-thread-{thread_id}"`

### Requirement: PRNG Security Properties

#### Scenario: No SeedableRng implementation
- **WHEN** attempting to construct `Csprng` via `SeedableRng`
- **THEN** it is not possible because `SeedableRng` is intentionally not implemented
- **AND** this prevents accidental construction of weak PRNGs via `seed_from_u64`

#### Scenario: Debug output does not expose state
- **WHEN** `Debug` is used on a `Csprng` instance
- **THEN** the output is `"Csprng {}"` (internal state is not exposed)

#### Scenario: Algorithm non-reproducibility
- **WHEN** the PRNG algorithm is considered
- **THEN** it must not be treated as reproducible across protocol versions
- **AND** the algorithm may change as security evidence evolves

---

### Requirement: Tree Hashing (Merkle/Hash Trees)
The `ic_crypto_tree_hash` crate provides Merkle hash tree construction and witness generation for certified variables.

#### Scenario: Hash tree domain separation
- **WHEN** hash tree nodes are constructed
- **THEN** different domain separators are used for different node types:
  - Leaf: `"ic-hashtree-leaf"`
  - Empty subtree: `"ic-hashtree-empty"`
  - Labeled node: `"ic-hashtree-labeled"`
  - Fork: `"ic-hashtree-fork"`

#### Scenario: Building a hash tree
- **WHEN** a `HashTreeBuilder` is used to construct a tree
- **THEN** it produces a `HashTree` with domain-separated SHA-256 digests at each node

#### Scenario: Generating a witness
- **WHEN** a `WitnessGenerator` generates a witness for a specific path
- **THEN** the witness contains the necessary intermediate hashes to verify inclusion
- **AND** `WitnessGenerationError` is returned if the path is not in the tree

#### Scenario: Hash tree depth limit
- **WHEN** a hash tree is constructed or deserialized
- **THEN** the maximum depth is limited to `MAX_HASH_TREE_DEPTH` (50 for debug printing)
- **AND** trees deeper than the limit result in errors

#### Scenario: MixedHashTree operations
- **WHEN** a `MixedHashTree` is used
- **THEN** it supports a combination of hash nodes and data nodes
- **AND** it can be used for partial tree verification (certificate validation)

### Requirement: Labels and Paths

#### Scenario: Path creation
- **WHEN** a `Path` is created from labels
- **THEN** it can be constructed from `Vec<Label>`, a single `Label`, or an iterator
- **AND** display format is `/label1/label2/...`

#### Scenario: Label representation
- **WHEN** a `Label` is used
- **THEN** it is an arbitrary byte sequence (most are printable ASCII, some are short byte sequences like CanisterIds)
