# Crypto Utilities

## Requirements

### Requirement: Secrets Containers
The `ic_crypto_secrets_containers` crate provides newtypes that protect sensitive data (e.g., secret keys) with the following properties:

#### Scenario: Automatic zeroization on drop
- **WHEN** a `SecretArray`, `SecretVec`, or `SecretBytes` goes out of scope
- **THEN** the underlying memory is zeroed (best-effort)
- **AND** copies made during creation or serialization may need manual clearing

#### Scenario: Controlled access via expose_secret
- **WHEN** the sensitive data needs to be accessed
- **THEN** it must be accessed through the `expose_secret` method
- **AND** this pattern aids auditing of all secret key accesses

#### Scenario: Debug redaction
- **WHEN** `Debug` formatting is applied to a secrets container
- **THEN** the sensitive data is redacted (not printed)

#### Scenario: No implicit Copy
- **WHEN** a secrets container value is used
- **THEN** it cannot be `Copy`'d (because Drop is implemented for zeroization)
- **AND** explicit `move` semantics must be used

### Requirement: Standalone Signature Verifier
The `ic_crypto_standalone_sig_verifier` crate provides stateless signature verification without needing a full crypto component.

#### Scenario: Verifying Ed25519 basic signature by public key
- **WHEN** `verify_basic_sig_by_public_key` is called with `AlgorithmId::Ed25519`
- **THEN** the public key is deserialized as raw 32-byte Ed25519 key
- **AND** the signature must be exactly 64 bytes (the Ed25519 signature size)
- **AND** signature verification is performed
- **AND** `CryptoError::MalformedPublicKey`, `CryptoError::MalformedSignature`, or `CryptoError::SignatureVerification` is returned on failure

#### Scenario: Verifying ECDSA P-256 basic signature
- **WHEN** `verify_basic_sig_by_public_key` is called with `AlgorithmId::EcdsaP256`
- **THEN** the public key is deserialized in SEC1 format
- **AND** the signature must be exactly 64 bytes
- **AND** P-256 ECDSA verification is performed

#### Scenario: Verifying ECDSA secp256k1 basic signature
- **WHEN** `verify_basic_sig_by_public_key` is called with `AlgorithmId::EcdsaSecp256k1`
- **THEN** the public key is deserialized in SEC1 format
- **AND** the signature must be exactly 64 bytes
- **AND** secp256k1 ECDSA verification is performed

#### Scenario: Verifying RSA SHA-256 basic signature
- **WHEN** `verify_basic_sig_by_public_key` is called with `AlgorithmId::RsaSha256`
- **THEN** the public key is deserialized from DER SPKI format
- **AND** RSA PKCS#1 v1.5 with SHA-256 verification is performed

#### Scenario: Unsupported algorithm
- **WHEN** the algorithm is not Ed25519, EcdsaP256, EcdsaSecp256k1, or RsaSha256
- **THEN** `CryptoError::AlgorithmNotSupported` is returned

#### Scenario: Verifying canister signature (ICCSA)
- **WHEN** `verify_canister_sig` is called with message, signature, public key, and root of trust
- **THEN** the `ic_crypto_iccsa::verify` function is called
- **AND** the root of trust (IC root public key) is used to verify the certified state tree

### Requirement: Standalone Signature Utilities

#### Scenario: Extracting user public key from bytes
- **WHEN** `user_public_key_from_bytes` is called with DER-encoded key bytes
- **THEN** the key is parsed and the algorithm is determined
- **AND** a `UserPublicKey` with the appropriate `AlgorithmId` is returned

#### Scenario: Converting Ed25519 public key to DER
- **WHEN** `ed25519_public_key_to_der` is called with raw key bytes
- **THEN** a DER-encoded SubjectPublicKeyInfo is returned

#### Scenario: Extracting ECDSA P-256 signature from DER
- **WHEN** `ecdsa_p256_signature_from_der_bytes` is called with DER-encoded signature bytes
- **THEN** the signature is decoded and returned in raw (r||s) format

### Requirement: Verification-Only Crypto Component
The `ic_crypto_for_verification_only` crate provides a crypto component intended solely for signature verification (public key operations).

#### Scenario: Creating a verification-only component
- **WHEN** `new(registry_client)` is called
- **THEN** a `TempCryptoComponent` is created with all key types generated
- **AND** the secret keys are stored in a temporary directory that is deleted when the component is dropped
- **AND** the component implements the `CryptoComponentForVerificationOnly` trait
- **AND** the component should only be used for verification (not signing), since its keys are ephemeral

### Requirement: Temporary Crypto Component (TempCryptoComponent)
The `TempCryptoComponent` from the `temp_crypto` crate is a builder-based test utility for creating crypto components with specific key configurations.

#### Scenario: Building a temp crypto component
- **WHEN** `TempCryptoComponent::builder()` is used
- **THEN** it can be configured with:
  - `.with_registry(registry_client)` - the registry to use
  - `.with_keys(NodeKeysToGenerate)` - which key types to generate
  - `.with_node_id(node_id)` - a specific node ID
  - `.build()` - creates the component with a temp directory for key storage

### Requirement: ICCSA (Internet Computer Canister Signature Algorithm)
The `ic_crypto_iccsa` crate implements canister signature verification.

#### Scenario: ICCSA verification
- **WHEN** `ic_crypto_iccsa::verify` is called with message, signature bytes, public key bytes, and root of trust
- **THEN** the signature is verified against the IC's certified state tree
- **AND** the root of trust (root subnet public key) is used to verify the tree's root hash
- **AND** the canister's certified data is checked against the public key's embedded canister ID and seed

### Requirement: Crypto Utility Crates

#### Scenario: Basic signature utilities (ic_crypto_utils_basic_sig)
- **WHEN** basic signature utility functions are used
- **THEN** `derive_node_id` derives a `NodeId` from a node signing public key protobuf
- **AND** other conversions between protobuf and internal key formats are provided

#### Scenario: Threshold signature DER utilities (ic_crypto_utils_threshold_sig_der)
- **WHEN** threshold signature DER conversion is needed
- **THEN** conversions between BLS12-381 threshold public keys and DER format are provided

#### Scenario: NI-DKG utilities (ic_crypto_utils_ni_dkg)
- **WHEN** NI-DKG utility functions are used
- **THEN** helper functions for NI-DKG operations are provided

#### Scenario: TLS utilities (ic_crypto_utils_tls)
- **WHEN** TLS utility functions are used
- **THEN** helper functions for TLS certificate and key operations are provided

#### Scenario: Canister threshold sig utilities (ic_crypto_utils_canister_threshold_sig)
- **WHEN** canister threshold signature utilities are used
- **THEN** helper functions for working with IDkg transcripts and threshold signature operations are provided

### Requirement: Crypto Service Provider (CSP) Architecture
The internal CSP (`ic_crypto_internal_crypto_service_provider`) provides the low-level cryptographic operations, separated from the higher-level `CryptoComponentImpl`.

#### Scenario: CSP vault abstraction
- **WHEN** cryptographic operations requiring secret keys are performed
- **THEN** they are delegated to the CSP vault (`CspVault` trait)
- **AND** the vault may run in-process or in a separate process communicating via Unix socket

#### Scenario: CSP public operations
- **WHEN** signature verification or other public-key-only operations are performed
- **THEN** they are performed by the CSP without needing the vault

### Requirement: Internal Crypto Libraries

#### Scenario: BLS12-381 library
- **WHEN** BLS12-381 operations are needed
- **THEN** `ic_crypto_internal_crypto_lib_bls12_381` provides the implementation
- **AND** it supports point caching (G2Affine deserialize cache, G2Prepared cache) for performance

#### Scenario: Multi-sig BLS12-381 library
- **WHEN** BLS12-381 multi-signature operations are needed
- **THEN** `ic_crypto_internal_crypto_lib_multi_sig` provides combination and verification

#### Scenario: Threshold sig BLS12-381 library
- **WHEN** threshold BLS12-381 signature operations are needed
- **THEN** `ic_crypto_internal_crypto_lib_threshold_sig` provides signing, verification, and combination
- **AND** a BLS signature cache is maintained for performance

#### Scenario: Basic sig library
- **WHEN** basic Ed25519 signature operations are needed internally
- **THEN** `ic_crypto_internal_crypto_lib_basic_sig` provides the implementation

#### Scenario: HMAC library
- **WHEN** HMAC operations are needed
- **THEN** `ic_crypto_internal_crypto_lib_hmac` provides the implementation

#### Scenario: Seed library
- **WHEN** cryptographic seed derivation is needed
- **THEN** `ic_crypto_internal_crypto_lib_seed` provides seed creation and derivation with domain separation
