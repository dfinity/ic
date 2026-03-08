# Verifiable Encrypted Threshold Key Derivation (vetKD)

## Requirements

### Requirement: VetKD Protocol Overview
The `VetKdProtocol` trait implements verifiable encrypted threshold key derivation, allowing nodes to collaboratively derive encryption keys that are encrypted to a user's transport public key. The protocol uses BLS12-381 pairing-based cryptography.

### Requirement: Encrypted Key Share Creation

#### Scenario: Creating an encrypted vetKD key share
- **WHEN** `create_encrypted_key_share` is called with `VetKdArgs`
- **THEN** the public coefficients for the NI-DKG ID are retrieved from the threshold sig data store
- **AND** a `KeyId` is derived from the public coefficients
- **AND** the master public key is extracted as the first coefficient
- **AND** the vault's `create_encrypted_vetkd_key_share` is called with:
  - The key ID
  - The master public key bytes
  - The transport public key
  - The derivation context (caller + context bytes)
  - The input
- **AND** the encrypted key share is signed with the node's basic signing key
- **AND** a `VetKdEncryptedKeyShare` is returned containing the encrypted share and node signature

#### Scenario: Threshold sig data not found
- **WHEN** the threshold sig data store has no data for the given NI-DKG ID
- **THEN** `VetKdKeyShareCreationError::ThresholdSigDataNotFound` is returned

#### Scenario: Invalid encryption public key
- **WHEN** the transport public key is invalid
- **THEN** `VetKdKeyShareCreationError::InvalidArgumentEncryptionPublicKey` is returned

#### Scenario: Secret key missing
- **WHEN** the threshold signing secret key is missing or of the wrong type
- **THEN** `VetKdKeyShareCreationError::InternalError` is returned

#### Scenario: Signing the key share
- **WHEN** the encrypted key share is created successfully
- **THEN** a basic signature is produced over the encrypted key share
- **AND** if signing fails, `VetKdKeyShareCreationError::KeyShareSigningError` is returned

### Requirement: Encrypted Key Share Verification

#### Scenario: Verifying an encrypted key share
- **WHEN** `verify_encrypted_key_share` is called with a signer NodeId, key share, and args
- **THEN** the registry version is retrieved from the threshold sig data store for the NI-DKG ID
- **AND** the node's basic signature on the encrypted key share is verified using `BasicSigVerifierInternal`
- **AND** the verification uses the signer's node signing public key from the registry at the stored registry version

#### Scenario: Signature verification failure
- **WHEN** the basic signature verification fails
- **THEN** `VetKdKeyShareVerificationError::VerificationError` is returned

### Requirement: Encrypted Key Share Combination

#### Scenario: Combining encrypted key shares (all valid)
- **WHEN** `combine_encrypted_key_shares` is called with a map of shares and args
- **THEN** a fail-fast check ensures enough shares are available (at least reconstruction_threshold)
- **AND** the public coefficients and master public key are retrieved from the threshold sig data store
- **AND** the transport public key is deserialized
- **AND** each share is deserialized and mapped by node index
- **AND** `EncryptedKey::combine_all` is called to combine all shares
- **AND** the result is a `VetKdEncryptedKey`

#### Scenario: Combining with invalid shares (fallback)
- **WHEN** `EncryptedKey::combine_all` fails with `InvalidShares`
- **THEN** a fallback to `EncryptedKey::combine_valid_shares` is used
- **AND** individual public keys are lazily computed from the threshold sig data store
- **AND** the valid shares (with their individual public keys) are combined
- **AND** this filters out invalid shares while still meeting the reconstruction threshold

#### Scenario: Insufficient shares
- **WHEN** the number of shares is less than the reconstruction threshold
- **THEN** `VetKdKeyShareCombinationError::UnsatisfiedReconstructionThreshold` is returned with the threshold and share count

#### Scenario: Invalid transport public key
- **WHEN** the transport public key cannot be deserialized
- **THEN** `VetKdKeyShareCombinationError::InvalidArgumentEncryptionPublicKey` is returned

#### Scenario: Invalid encrypted key share
- **WHEN** an individual encrypted key share cannot be deserialized
- **THEN** `VetKdKeyShareCombinationError::InvalidArgumentEncryptedKeyShare` is returned

#### Scenario: Missing node index
- **WHEN** a share's node ID has no index in the threshold sig data store
- **THEN** `VetKdKeyShareCombinationError::InternalError` is returned

### Requirement: Encrypted Key Verification

#### Scenario: Verifying a combined encrypted key
- **WHEN** `verify_encrypted_key` is called with a `VetKdEncryptedKey` and args
- **THEN** the encrypted key is deserialized
- **AND** the master public key is extracted from the threshold sig data store's public coefficients
- **AND** the transport public key is deserialized
- **AND** `encrypted_key.is_valid` is called with the master public key, derivation context, input, and transport public key

#### Scenario: Valid encrypted key
- **WHEN** `is_valid` returns true
- **THEN** `Ok(())` is returned

#### Scenario: Invalid encrypted key
- **WHEN** `is_valid` returns false
- **THEN** `VetKdKeyVerificationError::VerificationError` is returned

#### Scenario: Invalid deserialization
- **WHEN** the encrypted key bytes cannot be deserialized
- **THEN** `VetKdKeyVerificationError::InvalidArgumentEncryptedKey` is returned

### Requirement: VetKD Derivation Context

#### Scenario: Derivation context construction
- **WHEN** a derivation context is used in vetKD operations
- **THEN** it consists of:
  - A `caller` (principal ID as bytes)
  - A `context` (arbitrary byte vector)
- **AND** these together with the `input` determine the derived key

### Requirement: VetKD Master Public Key

#### Scenario: Master public key from coefficients
- **WHEN** the master public key is needed for vetKD
- **THEN** it is the first (constant term) of the BLS12-381 public coefficients from the NI-DKG transcript
- **AND** the coefficients must not be empty
- **AND** the key is deserialized as a `G2Affine` point (with caching for performance)

#### Scenario: Empty public coefficients
- **WHEN** the public coefficients are empty for the given NI-DKG ID
- **THEN** `VetKdKeyShareCreationError::InternalError` or `VetKdKeyShareCombinationError::InternalError` is returned
