# Protobuf Serialization

**Crates**: `ic-base-types-protobuf-generator`, `ic-crypto-internal-csp-protobuf-generator`, `ic-nervous-system-proto-protobuf-generator`, `ic-nns-common-protobuf-generator`, `ic-nns-governance-protobuf-generator`, `ic-nns-gtc-protobuf-generator`, `ic-nns-handler-root-protobuf-generator`, `ic-node-rewards-protobuf-generator`, `ic-protobuf-generator`, `ic-registry-common-proto-generator`, `ic-registry-transport-protobuf-generator`, `ic-sns-governance-protobuf-generator`, `ic-sns-init-protobuf-generator`, `ic-sns-root-protobuf-generator`, `ic-sns-swap-protobuf-generator`, `ic-sns-wasm-protobuf-generator`, `ledger-canister-protobuf-generator`, `registry-canister-protobuf-generator`

## Requirements

### Requirement: ProtoProxy Encoding/Decoding Framework
ProtoProxy<T> provides a generic mechanism to encode/decode arbitrary Rust structs using protocol buffer binary format via intermediate prost::Message "proxy" types.

#### Scenario: Proxy encoding
- **WHEN** proxy_encode(t) is called on a type implementing Into<M> where M: prost::Message
- **THEN** the Rust value is converted to the proxy Message and then encoded to Vec<u8>

#### Scenario: Proxy decoding
- **WHEN** proxy_decode(bytes) is called
- **THEN** bytes are decoded into the proxy Message
- **AND** the proxy Message is converted to the Rust type via TryInto
- **AND** errors from either step are captured as ProxyDecodeError

#### Scenario: Proxy roundtrip
- **WHEN** a Rust value is encoded via proxy_encode and then decoded via proxy_decode
- **THEN** the decoded value equals the original

### Requirement: ProxyDecodeError Comprehensive Error Taxonomy
ProxyDecodeError captures all possible failure modes when converting protobuf messages to Rust types.

#### Scenario: DecodeError from protobuf
- **WHEN** prost fails to decode the binary protobuf
- **THEN** ProxyDecodeError::DecodeError(prost::DecodeError) is returned

#### Scenario: CborDecodeError
- **WHEN** CBOR decoding fails during conversion
- **THEN** ProxyDecodeError::CborDecodeError is returned

#### Scenario: MissingField
- **WHEN** a required field in the protobuf message is None
- **THEN** ProxyDecodeError::MissingField(field_name) is returned
- **AND** field_name is a static string identifying the missing field

#### Scenario: ValueOutOfRange
- **WHEN** a protobuf value cannot be represented in the target Rust type
- **THEN** ProxyDecodeError::ValueOutOfRange { typ, err } is returned

#### Scenario: InvalidPrincipalId
- **WHEN** a bytes field cannot be parsed as a PrincipalId
- **THEN** ProxyDecodeError::InvalidPrincipalId is returned

#### Scenario: InvalidCanisterId
- **WHEN** a bytes field cannot be parsed as a CanisterId
- **THEN** ProxyDecodeError::InvalidCanisterId is returned

#### Scenario: InvalidDigestLength
- **WHEN** a hash/digest blob has wrong length
- **THEN** ProxyDecodeError::InvalidDigestLength { expected, actual } is returned

#### Scenario: InvalidMessageId
- **WHEN** a MessageId blob has wrong length
- **THEN** ProxyDecodeError::InvalidMessageId { expected, actual } is returned

#### Scenario: DuplicateEntry
- **WHEN** a map contains duplicate keys
- **THEN** ProxyDecodeError::DuplicateEntry { key, v1, v2 } is returned

#### Scenario: UnknownCertificationVersion
- **WHEN** a certification version number is not supported by this replica
- **THEN** ProxyDecodeError::UnknownCertificationVersion(version) is returned

#### Scenario: UnknownStateSyncVersion
- **WHEN** a state sync version number is not supported
- **THEN** ProxyDecodeError::UnknownStateSyncVersion(version) is returned

### Requirement: try_from_option_field Required Field Helper
try_from_option_field converts an optional protobuf field into a Rust type, returning MissingField error if None.

#### Scenario: Present field conversion
- **WHEN** try_from_option_field(Some(value), field_name) is called
- **THEN** T::try_from(value) is called on the inner value

#### Scenario: Missing field error
- **WHEN** try_from_option_field(None, field_name) is called
- **THEN** ProxyDecodeError::MissingField(field_name) is returned

### Requirement: try_decode_hash Fixed-Length Hash Conversion
try_decode_hash converts a variable-length byte slice into a fixed [u8; 32] hash.

#### Scenario: Correct length slice
- **WHEN** try_decode_hash is called with a 32-byte slice
- **THEN** Ok([u8; 32]) is returned

#### Scenario: Incorrect length slice
- **WHEN** try_decode_hash is called with a slice of length != 32
- **THEN** ProxyDecodeError::InvalidDigestLength { expected: 32, actual } is returned

### Requirement: Proto Definitions for Core IC Types
Proto files define the wire format for all IC types under types/v1/, state/v1/, registry/, crypto/v1/, transport/v1/, p2p/v1/.

#### Scenario: types/v1/types.proto core types
- **WHEN** IC core types are serialized
- **THEN** PrincipalId, SubnetId, NodeId, CanisterId, UserId have protobuf representations
- **AND** NiDkgId, ThresholdSignature, BasicSignature have protobuf representations

#### Scenario: types/v1/consensus.proto consensus artifacts
- **WHEN** consensus artifacts are serialized
- **THEN** Block, BlockProposal, Notarization, Finalization, RandomBeacon, CatchUpPackage have protobuf representations

#### Scenario: types/v1/artifact.proto artifact identifiers
- **WHEN** artifact identifiers are serialized
- **THEN** ConsensusMessageId, ConsensusMessageHash have protobuf representations

#### Scenario: state/queues/v1/queues.proto canister queues
- **WHEN** canister queue state is serialized
- **THEN** Request, Response, and canister queue structures have protobuf representations

#### Scenario: state/ingress/v1/ingress.proto ingress state
- **WHEN** ingress history state is serialized
- **THEN** IngressStatus and related types have protobuf representations

#### Scenario: registry/crypto/v1/crypto.proto crypto registry
- **WHEN** crypto registry keys are serialized
- **THEN** PublicKey and X509PublicKeyCert have protobuf representations

#### Scenario: state/sync/v1/manifest.proto state sync
- **WHEN** state sync manifests are serialized
- **THEN** manifest and chunk metadata have protobuf representations

### Requirement: Protobuf Determinism
Generated protobuf serialization MUST be deterministic across replicas to ensure consensus.

#### Scenario: Deterministic encoding
- **WHEN** the same Rust value is encoded on different replicas
- **THEN** the resulting bytes MUST be identical
- **AND** this is verified by the determinism_test module
