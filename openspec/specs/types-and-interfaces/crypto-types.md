# Crypto Types

## Requirements

### Requirement: CryptoHash Generic Hash Container
CryptoHash wraps a Vec<u8> representing a cryptographic hash value, with CryptoHashOf<T> providing type-safe hashes for specific content types.

#### Scenario: CryptoHash debug output
- **WHEN** CryptoHash is debug-formatted
- **THEN** it displays as "CryptoHash(0x<hex>)"

#### Scenario: CryptoHashOf type safety
- **WHEN** CryptoHashOf<Block> and CryptoHashOf<State> exist
- **THEN** they are distinct types that cannot be interchanged at compile time
- **AND** CryptoHashOf<T> is defined as Id<T, CryptoHash>

### Requirement: Signed Generic Signed Content
Signed<T, S> pairs content (T) with a signature (S), used as the foundation for all signed artifacts.

#### Scenario: Signed CountBytes
- **WHEN** CountBytes is called on Signed<T, S> where both T and S implement CountBytes
- **THEN** the result is content.count_bytes() + signature.count_bytes()

### Requirement: BasicSignature Single-Node Signature
BasicSignature<T> captures a basic signature on a value and the identity of the signing node.

#### Scenario: BasicSignature protobuf roundtrip
- **WHEN** BasicSignature is converted to pb::BasicSignature and back
- **THEN** the signature bytes and signer NodeId are preserved

### Requirement: ThresholdSignature Aggregated Threshold Signature
ThresholdSignature<T> captures a combined threshold signature with the NiDkgId of the key material used.

#### Scenario: ThresholdSignature components
- **WHEN** a ThresholdSignature is constructed
- **THEN** it contains a CombinedThresholdSigOf<T> signature and a NiDkgId signer

### Requirement: MultiSignature Multi-Party Signature
MultiSignature<T> captures a combined multi-signature from multiple signers, with signers listed as Vec<NodeId>.

#### Scenario: MultiSignature aggregation
- **WHEN** multiple MultiSignatureShares are aggregated
- **THEN** the resulting MultiSignature contains the combined signature and list of all signers

### Requirement: BasicSignatureBatch Batch of Basic Signatures
BasicSignatureBatch<T> collects multiple basic signatures on the same value in a BTreeMap<NodeId, BasicSigOf<T>>.

#### Scenario: Batch signature collection
- **WHEN** signatures are collected from multiple nodes
- **THEN** each node's signature is stored keyed by its NodeId

### Requirement: Signature Type Hierarchy
The crypto module defines typed signature wrappers: BasicSigOf<T>, CombinedThresholdSigOf<T>, ThresholdSigShareOf<T>, CombinedMultiSigOf<T>, IndividualMultiSigOf<T>.

#### Scenario: Signature type distinction
- **WHEN** different signature types exist (basic, threshold, multi)
- **THEN** they cannot be confused at the type level
- **AND** each wraps the raw signature bytes with phantom type T

### Requirement: CryptoHashable Domain-Separated Hashing
CryptoHashable trait defines how types compute their cryptographic hash, with CryptoHashDomain providing domain separation.

#### Scenario: Domain-separated hashing
- **WHEN** crypto_hash(value) is called on a CryptoHashable type
- **THEN** the hash includes a domain separator to prevent cross-type collision

### Requirement: Signable and SignableMock
Signable trait defines how types are serialized for signing, with SignableMock providing a test double.

#### Scenario: Signing serialization
- **WHEN** a value implementing Signable is signed
- **THEN** as_signed_bytes_without_domain_separator() provides the canonical bytes to sign
- **AND** DOMAIN_IC_REQUEST is the domain separator constant for IC request signing

### Requirement: NI-DKG Types
Non-interactive DKG types define the distributed key generation protocol structures.

#### Scenario: NiDkgId identification
- **WHEN** a DKG transcript is created
- **THEN** it has a unique NiDkgId containing start_block_height, dealer_subnet, dkg_tag, and target_subnet

#### Scenario: NiDkgConfig validation
- **WHEN** NiDkgConfig is constructed
- **THEN** dealers must be a non-empty set of NodeIds
- **AND** receivers must be a non-empty set of NodeIds
- **AND** threshold must be valid (> 0 and <= number of receivers)

### Requirement: Canister Threshold Signature Types (IDKG)
Types for the IDKG (Interactive DKG) protocol supporting canister threshold ECDSA and Schnorr signatures.

#### Scenario: IDkgTranscriptId uniqueness
- **WHEN** IDkgTranscriptIds are compared
- **THEN** each ID is unique based on its source height and subnet

#### Scenario: IDkgDealing support
- **WHEN** IDkgDealingSupport is provided
- **THEN** it contains the transcript_id and dealing_hash linking to the supported dealing

#### Scenario: Pre-signature management
- **WHEN** pre-signatures are created for threshold signing
- **THEN** each has a unique PreSigId and is associated with a MasterPublicKeyId

### Requirement: VetKd Types
VetKd (Verifiably Encrypted Threshold Key Derivation) types support encrypted key derivation.

#### Scenario: VetKd key share
- **WHEN** a VetKdKeyShare is generated
- **THEN** it contains the necessary data for verifiable encryption of derived keys

### Requirement: CryptoError and ErrorReproducibility
CryptoError represents cryptographic operation failures with ErrorReproducibility indicating whether the error is deterministic.

#### Scenario: Reproducible crypto errors
- **WHEN** a CryptoError is reproducible (is_reproducible() returns true)
- **THEN** retrying the operation will produce the same error
- **AND** the artifact should be considered permanently invalid

#### Scenario: Transient crypto errors
- **WHEN** a CryptoError is not reproducible
- **THEN** the operation may succeed on retry
- **AND** the artifact should be considered transiently invalid
