# Crypto Utility Sub-Crates Specification

This specification covers the following crypto utility crates and the signature verification interface:

- `ic-crypto-utils-basic-sig` (`rs/crypto/utils/basic_sig/`)
- `ic-crypto-utils-canister-threshold-sig` (`rs/crypto/utils/canister_threshold_sig/`)
- `ic-crypto-utils-ni-dkg` (`rs/crypto/utils/ni_dkg/`)
- `ic-crypto-utils-threshold-sig` (`rs/crypto/utils/threshold_sig/`)
- `ic-crypto-utils-threshold-sig-der` (`rs/crypto/utils/threshold_sig_der/`)
- `ic-crypto-utils-tls` (`rs/crypto/utils/tls/`)
- `ic-crypto-interfaces-sig-verification` (`rs/crypto/interfaces/sig_verification/`)

---

## ic-crypto-utils-basic-sig

Crate: `ic-crypto-utils-basic-sig`
Path: `rs/crypto/utils/basic_sig/`

Provides conversion utilities for basic signature public keys, specifically deriving NodeIds from Ed25519 public keys.

### Requirements

### Requirement: Node ID Derivation from Public Key
A `NodeId` must be deterministically derivable from an Ed25519 node signing public key in protobuf format.

#### Scenario: Derive NodeId from valid Ed25519 public key
- **WHEN** `derive_node_id` is called with a `PublicKeyProto` containing a valid Ed25519 public key in `key_value`
- **THEN** the raw key bytes are deserialized as an Ed25519 public key
- **AND** the key is serialized to RFC 8410 DER format
- **AND** a self-authenticating `PrincipalId` is computed from the DER bytes
- **AND** a `NodeId` is constructed from that `PrincipalId` and returned

#### Scenario: Derive NodeId from known test vector
- **WHEN** `derive_node_id` is called with the Ed25519 public key `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`
- **THEN** the returned `NodeId` corresponds to principal `e73il-iz5tp-nkgt7-idxyw-ngkah-47bpv-qdase-pzde6-g6vwc-a3eql-jae`

#### Scenario: Derive NodeId from malformed key bytes
- **WHEN** `derive_node_id` is called with a `PublicKeyProto` whose `key_value` is not a valid 32-byte Ed25519 public key
- **THEN** `InvalidNodePublicKey::MalformedRawBytes` is returned with an `internal_error` describing the deserialization failure

#### Scenario: Forbidden unsafe code
- **WHEN** the crate is compiled
- **THEN** `#![forbid(unsafe_code)]` ensures no unsafe code exists

#### Scenario: No unwrap usage
- **WHEN** the crate is compiled with clippy
- **THEN** `#![deny(clippy::unwrap_used)]` ensures no `.unwrap()` calls exist

---

## ic-crypto-utils-canister-threshold-sig

Crate: `ic-crypto-utils-canister-threshold-sig`
Path: `rs/crypto/utils/canister_threshold_sig/`

Provides threshold public key derivation from a master public key using an extended derivation path.

### Requirements

### Requirement: Threshold Public Key Derivation
A threshold public key must be derivable from a master public key and an extended derivation path.

#### Scenario: Derive threshold public key with valid inputs
- **WHEN** `derive_threshold_public_key` is called with a `MasterPublicKey` and an `ExtendedDerivationPath`
- **THEN** the `ExtendedDerivationPath` is converted to a `DerivationPath`
- **AND** the internal `derive_threshold_public_key` function computes the derived public key
- **AND** a `PublicKey` is returned

#### Scenario: Derive threshold public key with invalid argument
- **WHEN** `derive_threshold_public_key` is called and the internal derivation returns `DeriveThresholdPublicKeyError::InvalidArgument`
- **THEN** `CanisterThresholdGetPublicKeyError::InvalidArgument` is returned with the same error message

#### Scenario: Derive threshold public key with internal error
- **WHEN** `derive_threshold_public_key` is called and the internal derivation returns `DeriveThresholdPublicKeyError::InternalError`
- **THEN** `CanisterThresholdGetPublicKeyError::InternalError` is returned with a debug-formatted error message

---

## ic-crypto-utils-ni-dkg

Crate: `ic-crypto-utils-ni-dkg`
Path: `rs/crypto/utils/ni_dkg/`

Provides utilities for extracting threshold signature public keys from NI-DKG transcripts.

### Requirements

### Requirement: Subnet Threshold Signing Public Key Extraction
A subnet's threshold signing public key must be extractable from an `InitialNiDkgTranscriptRecord`.

#### Scenario: Extract public key from valid initial transcript record
- **WHEN** `extract_subnet_threshold_sig_public_key` is called with a valid `InitialNiDkgTranscriptRecord`
- **THEN** the record is deserialized into a `CspNiDkgTranscript`
- **AND** the threshold signature public key is extracted from the transcript's coefficients
- **AND** a `ThresholdSigPublicKey` is returned

#### Scenario: Extract public key from record with deserialization failure
- **WHEN** `extract_subnet_threshold_sig_public_key` is called with an `InitialNiDkgTranscriptRecord` that cannot be deserialized
- **THEN** `SubnetPubKeyExtractionError::Deserialization` is returned

#### Scenario: Extract public key from record with empty coefficients
- **WHEN** `extract_subnet_threshold_sig_public_key` is called and the transcript has empty Groth20_Bls12_381 coefficients
- **THEN** `SubnetPubKeyExtractionError::CoefficientsEmpty` is returned

### Requirement: Threshold Signing Public Key Extraction from Transcript
A threshold signature public key must be extractable from a `CspNiDkgTranscript`.

#### Scenario: Extract public key from valid transcript
- **WHEN** `extract_threshold_sig_public_key` is called with a `CspNiDkgTranscript` containing non-empty Groth20_Bls12_381 coefficients
- **THEN** the first public coefficient (at index 0) is extracted as `PublicKeyBytes`
- **AND** a `ThresholdSigPublicKey` is constructed from these bytes and returned

#### Scenario: Extract public key from transcript with empty coefficients
- **WHEN** `extract_threshold_sig_public_key` is called with a transcript whose Groth20_Bls12_381 coefficients are empty
- **THEN** `ThresholdPubKeyExtractionError::CoefficientsEmpty` is returned

---

## ic-crypto-utils-threshold-sig

Crate: `ic-crypto-utils-threshold-sig`
Path: `rs/crypto/utils/threshold_sig/`

Provides static verification functions for combined threshold signatures, compatible with the IDKM flow.

### Requirements

### Requirement: Combined Threshold Signature Verification
Combined threshold signatures must be verifiable against a threshold public key.

#### Scenario: Verify a valid combined threshold signature
- **WHEN** `verify_combined` is called with a `Signable` message, a `CombinedThresholdSigOf<T>`, and a `ThresholdSigPublicKey`
- **THEN** the public key bytes are extracted from the `ThresholdSigPublicKey`
- **AND** the signature bytes are converted to `CombinedSignatureBytes`
- **AND** `bls12_381::api::verify_combined_signature` is called with the signed bytes, signature, and public key
- **AND** `Ok(())` is returned if the signature is valid

#### Scenario: Verify an invalid combined threshold signature
- **WHEN** `verify_combined` is called with a signature that does not match the message and public key
- **THEN** an `Err` with a `CryptoError` indicating verification failure is returned

#### Scenario: Verify with malformed signature bytes
- **WHEN** `verify_combined` is called with a `CombinedThresholdSigOf` whose internal bytes cannot be converted to `CombinedSignatureBytes`
- **THEN** a `CryptoError` is returned from the `TryFrom` conversion

### Requirement: Combined Threshold Signature Verification with Cache
Combined threshold signatures must be verifiable using a verification cache for performance.

#### Scenario: Verify a valid combined threshold signature with cache
- **WHEN** `verify_combined_with_cache` is called with a valid message, signature, and public key
- **THEN** `bls12_381::api::verify_combined_signature_with_cache` is called
- **AND** `Ok(())` is returned if the signature is valid
- **AND** the result is cached for future lookups with the same inputs

#### Scenario: Verify a cached threshold signature
- **WHEN** `verify_combined_with_cache` is called with inputs that were previously verified successfully
- **THEN** the result may be served from the cache without re-performing the pairing computation

### Requirement: Forbidden Unsafe Code
- **WHEN** the crate is compiled
- **THEN** `#![forbid(unsafe_code)]` ensures no unsafe code exists

---

## ic-crypto-utils-threshold-sig-der

Crate: `ic-crypto-utils-threshold-sig-der`
Path: `rs/crypto/utils/threshold_sig_der/`

Provides DER and PEM encoding/decoding for BLS12-381 threshold signature public keys.

### Requirements

### Requirement: Public Key DER Encoding
BLS12-381 threshold signature public keys must be encodable to DER format.

#### Scenario: Encode a 96-byte public key to DER
- **WHEN** `public_key_to_der` is called with a 96-byte BLS12-381 public key
- **THEN** the key is encoded as an ASN.1 DER structure containing:
  - A SEQUENCE with an algorithm identifier SEQUENCE (BLS algorithm OID `1.3.6.1.4.1.44668.5.3.1.2.1` and curve OID `1.3.6.1.4.1.44668.5.3.2.1`)
  - A BIT STRING containing the 96-byte public key
- **AND** the DER bytes are returned

#### Scenario: Encode a key with wrong length
- **WHEN** `public_key_to_der` is called with a key that is not exactly 96 bytes
- **THEN** an `Err` with "key length is not 96 bytes" is returned

### Requirement: Public Key DER Decoding
DER-encoded BLS12-381 public keys must be decodable back to raw bytes.

#### Scenario: Decode a valid DER-encoded public key
- **WHEN** `public_key_from_der` is called with valid DER bytes containing a BLS12-381 public key
- **THEN** the 96-byte public key is extracted from the ASN.1 structure
- **AND** the algorithm and curve OIDs are verified
- **AND** a `[u8; 96]` is returned

#### Scenario: Decode DER with invalid ASN.1
- **WHEN** `public_key_from_der` is called with bytes that are not valid ASN.1 DER
- **THEN** an `Err` with "failed to deserialize DER blocks" is returned

#### Scenario: Decode DER with unsupported OIDs
- **WHEN** `public_key_from_der` is called with DER bytes containing non-BLS algorithm or curve OIDs
- **THEN** an `Err` indicating "unsupported algorithm and/or curve OIDs" is returned

#### Scenario: Decode DER with unexpected key length
- **WHEN** `public_key_from_der` is called with DER bytes containing a bit string that is not 768 bits (96 bytes)
- **THEN** an `Err` with "unexpected key length" is returned

#### Scenario: Decode DER with unexpected ASN.1 structure
- **WHEN** `public_key_from_der` is called with DER bytes containing unexpected ASN.1 blocks
- **THEN** an `Err` describing the unexpected structure is returned

### Requirement: PEM File Parsing
Threshold signature public keys must be parseable from PEM-encoded files.

#### Scenario: Parse a valid PEM file
- **WHEN** `parse_threshold_sig_key_from_pem_file` is called with a path to a valid PEM file containing a "PUBLIC KEY" tag
- **THEN** the PEM is decoded to DER bytes
- **AND** the DER bytes are parsed to extract the public key
- **AND** a `ThresholdSigPublicKey` is returned

#### Scenario: Parse a PEM file that does not exist
- **WHEN** `parse_threshold_sig_key_from_pem_file` is called with a non-existent file path
- **THEN** `KeyConversionError::IoError` is returned

#### Scenario: Parse a PEM file with invalid PEM encoding
- **WHEN** `parse_threshold_sig_key_from_pem_file` is called with a file that is not valid PEM
- **THEN** `KeyConversionError::InvalidPem` is returned

#### Scenario: Parse a PEM file with wrong tag
- **WHEN** `parse_threshold_sig_key_from_pem_file` is called with a PEM file whose tag is not "PUBLIC KEY"
- **THEN** `KeyConversionError::InvalidPem` is returned with a message about the expected tag

### Requirement: DER Bytes Parsing
Threshold signature public keys must be parseable from raw DER bytes.

#### Scenario: Parse valid DER bytes
- **WHEN** `parse_threshold_sig_key_from_der` is called with valid DER-encoded BLS12-381 public key bytes
- **THEN** a `ThresholdSigPublicKey` is returned

#### Scenario: Parse invalid DER bytes
- **WHEN** `parse_threshold_sig_key_from_der` is called with invalid DER bytes
- **THEN** `KeyConversionError::InvalidDer` is returned

### Requirement: Threshold Public Key to DER Encoding
A `ThresholdSigPublicKey` must be encodable to DER format.

#### Scenario: Encode threshold public key to DER
- **WHEN** `threshold_sig_public_key_to_der` is called with a `ThresholdSigPublicKey`
- **THEN** the 96-byte key is extracted and DER-encoded
- **AND** the DER bytes are returned

#### Scenario: Encode threshold public key to DER fails
- **WHEN** `threshold_sig_public_key_to_der` is called and DER encoding fails
- **THEN** `KeyConversionError::DerEncoding` is returned

### Requirement: Threshold Public Key to PEM Encoding
A `ThresholdSigPublicKey` must be encodable to PEM format.

#### Scenario: Encode threshold public key to PEM
- **WHEN** `threshold_sig_public_key_to_pem` is called with a `ThresholdSigPublicKey`
- **THEN** the key is first DER-encoded
- **AND** the DER bytes are wrapped in a PEM envelope with "PUBLIC KEY" tag and LF line endings
- **AND** the PEM bytes are returned

### Requirement: DER to PEM Conversion
Raw DER bytes must be convertible to PEM format.

#### Scenario: Convert DER bytes to PEM
- **WHEN** `public_key_der_to_pem` is called with DER-encoded bytes
- **THEN** a PEM-encoded byte vector is returned with "PUBLIC KEY" tag and LF line endings

---

## ic-crypto-utils-tls

Crate: `ic-crypto-utils-tls`
Path: `rs/crypto/utils/tls/`

Provides utilities for extracting node identity from TLS certificates.

### Requirements

### Requirement: Node ID Extraction from TLS Certificate
A `NodeId` must be extractable from a DER-encoded X.509 TLS certificate's subject common name.

#### Scenario: Extract NodeId from valid certificate
- **WHEN** `node_id_from_certificate_der` is called with a DER-encoded X.509 certificate
- **AND** the certificate has exactly one subject common name (CN) that is a valid IC principal
- **THEN** the CN is parsed as a `PrincipalId`
- **AND** a `NodeId` is constructed from the principal and returned

#### Scenario: Extract NodeId from invalid DER
- **WHEN** `node_id_from_certificate_der` is called with bytes that are not valid DER-encoded X.509
- **THEN** `NodeIdFromCertificateDerError::InvalidCertificate` is returned

#### Scenario: Extract NodeId from DER with trailing data
- **WHEN** `node_id_from_certificate_der` is called with DER bytes that have a remainder after parsing
- **THEN** `NodeIdFromCertificateDerError::InvalidCertificate` is returned with "Input remains after parsing."

#### Scenario: Extract NodeId from certificate with no common name
- **WHEN** `node_id_from_certificate_der` is called with a certificate that has no subject CN
- **THEN** `NodeIdFromCertificateDerError::UnexpectedContent` is returned with "Missing common name (CN)"

#### Scenario: Extract NodeId from certificate with multiple common names
- **WHEN** `node_id_from_certificate_der` is called with a certificate that has more than one subject CN
- **THEN** `NodeIdFromCertificateDerError::UnexpectedContent` is returned with "found second common name (CN) entry, but expected a single one"

#### Scenario: Extract NodeId from certificate with invalid principal
- **WHEN** `node_id_from_certificate_der` is called with a certificate whose CN is not a valid IC principal
- **THEN** `NodeIdFromCertificateDerError::UnexpectedContent` is returned with the principal parsing error

### Requirement: Forbidden Unsafe Code
- **WHEN** the crate is compiled
- **THEN** `#![forbid(unsafe_code)]` ensures no unsafe code exists

### Requirement: No Unwrap Usage
- **WHEN** the crate is compiled with clippy
- **THEN** `#![deny(clippy::unwrap_used)]` ensures no `.unwrap()` calls exist

### Requirement: No rustls Types in Public API
- **WHEN** the crate's public function signatures are examined
- **THEN** they include only primitive or local types, not `rustls` types
- **AND** this ensures upgrading `rustls` does not require upgrading all callers

---

## ic-crypto-interfaces-sig-verification

Crate: `ic-crypto-interfaces-sig-verification`
Path: `rs/crypto/interfaces/sig_verification/`

Defines trait interfaces for signature verification in the IC crypto component.

### Requirements

### Requirement: Basic Signature Verification by Public Key (BasicSigVerifierByPublicKey)
A trait for verifying basic signatures using a user-provided public key.

#### Scenario: Verify valid basic signature
- **WHEN** `verify_basic_sig_by_public_key` is called with a valid `BasicSigOf<T>`, a `Signable` message, and a `UserPublicKey`
- **THEN** the signature is verified against the public key and signed bytes
- **AND** `Ok(())` is returned

#### Scenario: Verify basic signature with malformed public key
- **WHEN** `verify_basic_sig_by_public_key` is called with a malformed `UserPublicKey`
- **THEN** `CryptoError::MalformedPublicKey` is returned

#### Scenario: Verify basic signature with malformed signature
- **WHEN** `verify_basic_sig_by_public_key` is called with a malformed `BasicSigOf<T>`
- **THEN** `CryptoError::MalformedSignature` is returned

#### Scenario: Verify basic signature with unsupported algorithm
- **WHEN** `verify_basic_sig_by_public_key` is called with a public key for an unsupported algorithm
- **THEN** `CryptoError::AlgorithmNotSupported` is returned

#### Scenario: Verify basic signature that fails verification
- **WHEN** `verify_basic_sig_by_public_key` is called with a signature that does not match the message and key
- **THEN** `CryptoError::SignatureVerification` is returned

### Requirement: Canister Signature Verification (CanisterSigVerifier)
A trait for verifying ICCSA canister signatures.

#### Scenario: Verify valid canister signature
- **WHEN** `verify_canister_sig` is called with a valid `CanisterSigOf<T>`, a `Signable` message, a `UserPublicKey`, and an `IcRootOfTrust`
- **THEN** the canister signature is verified using the root of trust
- **AND** `Ok(())` is returned

#### Scenario: Verify canister signature with unsupported algorithm
- **WHEN** `verify_canister_sig` is called with a signature algorithm not supported for canister signatures
- **THEN** `CryptoError::AlgorithmNotSupported` is returned

#### Scenario: Verify canister signature with missing root subnet public key
- **WHEN** `verify_canister_sig` is called and the root subnet threshold signing public key cannot be found
- **THEN** `CryptoError::RootSubnetPublicKeyNotFound` is returned

#### Scenario: Verify canister signature with malformed root public key
- **WHEN** `verify_canister_sig` is called and the root subnet's threshold signing public key is malformed
- **THEN** `CryptoError::MalformedPublicKey` is returned

#### Scenario: Verify canister signature with malformed signature
- **WHEN** `verify_canister_sig` is called with a malformed `CanisterSigOf<T>`
- **THEN** `CryptoError::MalformedSignature` is returned

#### Scenario: Verify canister signature that fails verification
- **WHEN** `verify_canister_sig` is called with a signature that does not validate
- **THEN** `CryptoError::SignatureVerification` is returned

### Requirement: Ingress Signature Verifier Trait (IngressSigVerifier)
A composite trait combining basic and canister signature verification for ingress messages.

#### Scenario: IngressSigVerifier is a composite trait
- **WHEN** a type implements `Send + Sync`
- **AND** implements `BasicSigVerifierByPublicKey<WebAuthnEnvelope>`
- **AND** implements `BasicSigVerifierByPublicKey<MessageId>`
- **AND** implements `BasicSigVerifierByPublicKey<Delegation>`
- **AND** implements `CanisterSigVerifier<Delegation>`
- **AND** implements `CanisterSigVerifier<MessageId>`
- **THEN** it automatically implements `IngressSigVerifier` via blanket implementation

#### Scenario: IngressSigVerifier requires Send + Sync
- **WHEN** a type does not implement `Send + Sync`
- **THEN** it cannot implement `IngressSigVerifier` even if all verification traits are implemented

#### Scenario: Verify WebAuthn envelope basic signature
- **WHEN** an `IngressSigVerifier` verifies a basic signature on a `WebAuthnEnvelope`
- **THEN** `BasicSigVerifierByPublicKey<WebAuthnEnvelope>::verify_basic_sig_by_public_key` is called

#### Scenario: Verify MessageId basic signature
- **WHEN** an `IngressSigVerifier` verifies a basic signature on a `MessageId`
- **THEN** `BasicSigVerifierByPublicKey<MessageId>::verify_basic_sig_by_public_key` is called

#### Scenario: Verify Delegation basic signature
- **WHEN** an `IngressSigVerifier` verifies a basic signature on a `Delegation`
- **THEN** `BasicSigVerifierByPublicKey<Delegation>::verify_basic_sig_by_public_key` is called

#### Scenario: Verify Delegation canister signature
- **WHEN** an `IngressSigVerifier` verifies a canister signature on a `Delegation`
- **THEN** `CanisterSigVerifier<Delegation>::verify_canister_sig` is called

#### Scenario: Verify MessageId canister signature
- **WHEN** an `IngressSigVerifier` verifies a canister signature on a `MessageId`
- **THEN** `CanisterSigVerifier<MessageId>::verify_canister_sig` is called
