# Signatures

## Requirements

### Requirement: Basic Signature Signing (Ed25519)
The `BasicSigner` trait allows a node to sign a message using its node signing key (Ed25519). The signing key is stored in the CSP vault.

#### Scenario: Signing a message
- **WHEN** `sign_basic` is called with a `Signable` message
- **THEN** the message is serialized to bytes via `as_signed_bytes()`
- **AND** the vault's `sign` method is called to produce the signature
- **AND** the result is wrapped in a `BasicSigOf<H>` containing a `BasicSig`
- **AND** the message byte length is recorded as a parameter size metric

#### Scenario: Vault signing error
- **WHEN** the vault's `sign` method returns a `CspBasicSignatureError`
- **THEN** the error is converted to a `CryptoError` and returned

### Requirement: Basic Signature Verification
The `BasicSigVerifier` trait verifies basic signatures against a signer's public key from the registry.

#### Scenario: Verifying a basic signature
- **WHEN** `verify_basic_sig` is called with a signature, message, signer NodeId, and registry version
- **THEN** the signer's node signing public key is retrieved from the registry at the given version
- **AND** the algorithm ID is determined from the public key protobuf
- **AND** the CSP's `verify` method is called with the converted signature, message bytes, algorithm, and public key
- **AND** success or a `CryptoError` is returned

#### Scenario: Signer public key not in registry
- **WHEN** the signer's node signing public key is not found in the registry
- **THEN** a `CryptoError::PublicKeyNotFound` is returned with the node_id, key_purpose, and registry_version

### Requirement: Basic Signature Batch Combining
Individual basic signatures can be combined into a `BasicSignatureBatch`.

#### Scenario: Combining basic signatures
- **WHEN** `combine_basic_sig` is called with a non-empty map of NodeId to BasicSigOf
- **THEN** a `BasicSignatureBatch` is returned containing all signatures
- **AND** the original signatures are cloned into the batch

#### Scenario: Combining with empty signatures
- **WHEN** `combine_basic_sig` is called with an empty map
- **THEN** a `CryptoError::InvalidArgument` is returned with a message indicating at least one signature is needed

### Requirement: Basic Signature Batch Verification
A `BasicSignatureBatch` can be verified efficiently using Ed25519 batch verification.

#### Scenario: Verifying a basic signature batch
- **WHEN** `verify_basic_sig_batch` is called with a non-empty batch, message, and registry version
- **THEN** each signer's public key is retrieved from the registry
- **AND** all public keys must use the Ed25519 algorithm
- **AND** a public random seed is generated from the vault for batch verification
- **AND** `ic_ed25519::PublicKey::batch_verify` is called with all messages, signatures, and keys

#### Scenario: Empty batch verification
- **WHEN** `verify_basic_sig_batch` is called with an empty batch
- **THEN** a `CryptoError::InvalidArgument` is returned

#### Scenario: Non-Ed25519 key in batch
- **WHEN** any signer in the batch has a non-Ed25519 public key algorithm
- **THEN** a `CryptoError::AlgorithmNotSupported` is returned

#### Scenario: Batch verification failure
- **WHEN** the batch verification detects an invalid signature
- **THEN** a `CryptoError::SignatureVerification` is returned

### Requirement: Basic Signature Verification by Public Key
The `BasicSigVerifierByPublicKey` trait verifies a signature using a directly provided `UserPublicKey` rather than looking up the registry.

#### Scenario: Verifying by public key (Ed25519)
- **WHEN** `verify_basic_sig_by_public_key` is called with an Ed25519 public key
- **THEN** the standalone signature verifier is used to verify the signature
- **AND** the algorithm ID from the public key determines the verification algorithm

#### Scenario: Verifying by public key (ECDSA P-256)
- **WHEN** the public key algorithm is `EcdsaP256`
- **THEN** the P-256 ECDSA verification is performed
- **AND** the signature must be exactly 64 bytes

#### Scenario: Verifying by public key (ECDSA secp256k1)
- **WHEN** the public key algorithm is `EcdsaSecp256k1`
- **THEN** the secp256k1 ECDSA verification is performed
- **AND** the signature must be exactly 64 bytes

#### Scenario: Verifying by public key (RSA SHA-256)
- **WHEN** the public key algorithm is `RsaSha256`
- **THEN** RSA PKCS#1 v1.5 verification with SHA-256 hashing is performed

#### Scenario: Unsupported algorithm
- **WHEN** the public key algorithm is not one of Ed25519, EcdsaP256, EcdsaSecp256k1, or RsaSha256
- **THEN** a `CryptoError::AlgorithmNotSupported` is returned

### Requirement: Multi-Signature Signing (BLS12-381)
The `MultiSigner` trait produces BLS12-381 individual multi-signatures using the node's committee signing key.

#### Scenario: Creating a multi-signature share
- **WHEN** `sign_multi` is called with a message, signer NodeId, and registry version
- **THEN** the signer's committee signing public key is retrieved from the registry
- **AND** a `KeyId` is derived from the public key
- **AND** the CSP's `sign` method is called with the committee signing algorithm and message bytes
- **AND** the result is wrapped in an `IndividualMultiSigOf<H>`

### Requirement: Multi-Signature Individual Verification
Individual multi-signatures can be verified independently.

#### Scenario: Verifying an individual multi-signature
- **WHEN** `verify_multi_sig_individual` is called with a signature, message, signer, and registry version
- **THEN** the signer's committee signing public key is retrieved from the registry
- **AND** the CSP verifies the signature against the message and public key

### Requirement: Multi-Signature Combination
Individual multi-signatures can be combined into a single combined multi-signature.

#### Scenario: Combining individual multi-signatures
- **WHEN** `combine_multi_sig_individuals` is called with a non-empty map of NodeId to IndividualMultiSigOf
- **THEN** each signer's public key is retrieved from the registry
- **AND** all algorithm IDs must be consistent (same algorithm for all signers)
- **AND** the CSP's `combine_sigs` method produces a `CombinedMultiSigOf`

#### Scenario: Combining with empty signatures
- **WHEN** `combine_multi_sig_individuals` is called with an empty map
- **THEN** a `CryptoError::InvalidArgument` is returned

#### Scenario: Inconsistent algorithms across signers
- **WHEN** the committee signing public keys of different signers use different algorithms
- **THEN** a `CryptoError::InconsistentAlgorithms` is returned

### Requirement: Combined Multi-Signature Verification
A combined multi-signature can be verified against a set of signers.

#### Scenario: Verifying a combined multi-signature
- **WHEN** `verify_multi_sig_combined` is called with a combined signature, message, non-empty set of signers, and registry version
- **THEN** all signers' committee signing public keys are retrieved from the registry
- **AND** algorithm consistency is checked
- **AND** the CSP's `verify_multisig` method is called

#### Scenario: Empty signers set
- **WHEN** `verify_multi_sig_combined` is called with an empty signers set
- **THEN** a `CryptoError::InvalidArgument` is returned

### Requirement: Threshold Signature Signing (BLS12-381)
The `ThresholdSigner` trait produces threshold signature shares using keys loaded from NI-DKG transcripts.

#### Scenario: Creating a threshold signature share
- **WHEN** `sign_threshold` is called with a message and NI-DKG ID
- **THEN** the public coefficients are retrieved from the threshold sig data store
- **AND** the CSP's `threshold_sign` method produces a threshold signature share
- **AND** the result is a `ThresholdSigShareOf<T>`

#### Scenario: Threshold sig data not found
- **WHEN** the threshold sig data store has no data for the given DKG ID
- **THEN** a `ThresholdSigDataNotFoundError` is returned

#### Scenario: Secret key not found
- **WHEN** the CSP cannot find the secret key for threshold signing
- **THEN** a `ThresholdSignError::SecretKeyNotFound` is returned with the DKG ID

### Requirement: Threshold Signature Share Verification

#### Scenario: Verifying a threshold signature share
- **WHEN** `verify_threshold_sig_share` is called with a share, message, DKG ID, and signer NodeId
- **THEN** the signer's individual public key is lazily computed from the store (or calculated from public coefficients and stored)
- **AND** the CSP's `threshold_verify_individual_signature` is called

#### Scenario: Lazy public key computation
- **WHEN** the individual public key for a node is not yet in the store
- **THEN** it is computed from the public coefficients and the node's index
- **AND** the computed key is inserted into the store for future use
- **AND** concurrent computation by multiple threads produces the same key (no atomicity issue)

#### Scenario: Missing node index
- **WHEN** the signer's node index is not found in the transcript data
- **THEN** a `CryptoError::InvalidArgument` is returned indicating the missing node index

### Requirement: Threshold Signature Share Combination

#### Scenario: Combining threshold signature shares
- **WHEN** `combine_threshold_sig_shares` is called with a non-empty map of shares and a DKG ID
- **THEN** shares are converted to an indexed array based on node indices from the store
- **AND** the CSP's `threshold_combine_signatures` method produces a `CombinedThresholdSigOf`

#### Scenario: Empty shares map
- **WHEN** `combine_threshold_sig_shares` is called with an empty shares map
- **THEN** a `CryptoError::InvalidArgument` is returned

### Requirement: Combined Threshold Signature Verification

#### Scenario: Verifying a combined threshold signature
- **WHEN** `verify_threshold_sig_combined` is called with a combined signature, message, and DKG ID
- **THEN** public coefficients are retrieved from the store
- **AND** the CSP's `threshold_verify_combined_signature` verifies the signature

### Requirement: Combined Threshold Signature Verification by Public Key

#### Scenario: Verifying by subnet public key
- **WHEN** `verify_combined_threshold_sig_by_public_key` is called with a combined signature, message, subnet ID, and registry version
- **THEN** the initial high-threshold NI-DKG transcript for the subnet is fetched from the registry
- **AND** the CSP verifies the signature against the transcript's public coefficients

#### Scenario: Transcript not found in registry
- **WHEN** the registry has no initial DKG transcripts for the subnet
- **THEN** a `CryptoError::DkgTranscriptNotFound` is returned

### Requirement: Threshold Sig Data Store Capacity
The `ThresholdSigDataStoreImpl` limits the number of DKG IDs stored per tag.

#### Scenario: Exceeding store capacity
- **WHEN** data is inserted for more DKG IDs than `CAPACITY_PER_TAG_OR_KEY` for a given tag
- **THEN** the oldest data (by insertion order) for that tag is removed
- **AND** the total capacity is `2*CAPACITY_PER_TAG_OR_KEY + K*CAPACITY_PER_TAG_OR_KEY` where K is the number of distinct `NiDkgMasterPublicKeyId`s
