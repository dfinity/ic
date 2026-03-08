# ic-crypto-internal-csp Specification

Crate: `ic-crypto-internal-csp`
Path: `rs/crypto/internal/crypto_service_provider/`

The Crypto Service Provider (CSP) is the core cryptographic key storage and operations layer of the Internet Computer replica. It manages secret keys, public keys, and provides cryptographic operations including signing, threshold signatures, NI-DKG, interactive DKG (iDKG), threshold ECDSA/Schnorr, TLS, and vetKD.

---

## Requirements

### Requirement: CSP Instantiation and Configuration
The CSP must be instantiable from configuration and from a vault, supporting both in-replica and remote (Unix socket) vault backends.

#### Scenario: Create CSP from config with in-replica vault
- **WHEN** `Csp::new_from_config` is called with a `CryptoConfig` whose `csp_vault_type` is `InReplica`
- **THEN** a `Csp` is created with a `ProdLocalCspVault` backed by the configured `crypto_root` directory
- **AND** the CSP is ready to perform cryptographic operations

#### Scenario: Create CSP from config with Unix socket vault
- **WHEN** `Csp::new_from_config` is called with a `CryptoConfig` whose `csp_vault_type` is `UnixSocket`
- **AND** a `tokio_runtime_handle` is provided
- **THEN** a `Csp` is created with a `RemoteCspVault` connected to the specified socket
- **AND** the CSP communicates with the vault via tarpc RPC

#### Scenario: Panic on missing runtime handle for Unix socket vault
- **WHEN** `Csp::new_from_config` is called with a `UnixSocket` vault type
- **AND** `tokio_runtime_handle` is `None`
- **THEN** the method panics

#### Scenario: Create CSP from vault directly
- **WHEN** `Csp::new_from_vault` is called with an `Arc<dyn CspVault>`, a logger, and metrics
- **THEN** a `Csp` is created wrapping the provided vault

---

### Requirement: CryptoServiceProvider Trait Composition
The `CryptoServiceProvider` trait is a composite of `CspSigner`, `ThresholdSignatureCspClient`, and `NiDkgCspClient`.

#### Scenario: Blanket implementation for all qualifying types
- **WHEN** a type implements `CspSigner`, `ThresholdSignatureCspClient`, and `NiDkgCspClient`
- **THEN** it automatically implements `CryptoServiceProvider`

---

### Requirement: Basic Signature Operations (CspSigner::sign)
The CSP must support signing messages with Ed25519 and MultiBls12_381 algorithms via the vault.

#### Scenario: Sign with Ed25519
- **WHEN** `sign` is called with `AlgorithmId::Ed25519`, a message, and a key ID
- **THEN** the CSP delegates to `BasicSignatureCspVault::sign` on the vault
- **AND** returns a `CspSignature::Ed25519` on success
- **AND** records a parameter size metric for `MetricsDomain::BasicSignature`

#### Scenario: Sign with MultiBls12_381
- **WHEN** `sign` is called with `AlgorithmId::MultiBls12_381`, a message, and a key ID
- **THEN** the CSP delegates to `MultiSignatureCspVault::multi_sign` on the vault
- **AND** returns a `CspSignature::MultiBls12_381` on success
- **AND** records a parameter size metric for `MetricsDomain::MultiSignature`

#### Scenario: Sign with unsupported algorithm
- **WHEN** `sign` is called with an algorithm other than `Ed25519` or `MultiBls12_381`
- **THEN** `CryptoError::InvalidArgument` is returned with a message indicating the unsupported algorithm

#### Scenario: Sign fails because secret key not found
- **WHEN** `sign` is called and the vault cannot find the secret key for the given key ID
- **THEN** `CryptoError::SecretKeyNotFound` (for multi) or `CryptoError::InternalError` (for basic) is returned

---

### Requirement: Signature Verification (CspSigner::verify)
The CSP must verify signatures for multiple algorithm types without requiring access to secret keys.

#### Scenario: Verify ECDSA P-256 signature
- **WHEN** `verify` is called with `AlgorithmId::EcdsaP256`, a `CspSignature::EcdsaP256`, and a `CspPublicKey::EcdsaP256`
- **THEN** the message is hashed with SHA-256
- **AND** the signature is verified against the hash using the ECDSA P-256 library

#### Scenario: Verify ECDSA secp256k1 signature
- **WHEN** `verify` is called with `AlgorithmId::EcdsaSecp256k1`, a `CspSignature::EcdsaSecp256k1`, and a `CspPublicKey::EcdsaSecp256k1`
- **THEN** the message is hashed with SHA-256
- **AND** the signature is verified against the hash using the ECDSA secp256k1 library

#### Scenario: Verify Ed25519 signature
- **WHEN** `verify` is called with `AlgorithmId::Ed25519`, a `CspSignature::Ed25519`, and a `CspPublicKey::Ed25519`
- **THEN** the full message (not a hash) is passed to the Ed25519 verification library
- **AND** `Ok(())` is returned if the signature is valid

#### Scenario: Verify RSA SHA-256 signature
- **WHEN** `verify` is called with `AlgorithmId::RsaSha256`, a `CspSignature::RsaSha256`, and a `CspPublicKey::RsaSha256`
- **THEN** the signature is verified using `verify_pkcs1_sha256` on the RSA public key

#### Scenario: Verify MultiBls12_381 individual signature
- **WHEN** `verify` is called with `AlgorithmId::MultiBls12_381`, an individual `MultiBls12_381_Signature`, and a `CspPublicKey::MultiBls12_381`
- **THEN** the individual signature is verified using the multi-signature BLS library

#### Scenario: Verify with mismatched algorithm and key/signature types
- **WHEN** `verify` is called with an algorithm ID that does not match the signature or public key variant
- **THEN** `CryptoError::SignatureVerification` is returned with "Unsupported types" as internal error

---

### Requirement: Proof of Possession Verification (CspSigner::verify_pop)
The CSP must verify proofs of possession for committee signing keys.

#### Scenario: Verify MultiBls12_381 PoP
- **WHEN** `verify_pop` is called with `AlgorithmId::MultiBls12_381`, a `CspPop::MultiBls12_381`, and a `CspPublicKey::MultiBls12_381`
- **THEN** the PoP is verified using the multi-signature BLS library

#### Scenario: Verify PoP with unsupported types
- **WHEN** `verify_pop` is called with mismatched algorithm, PoP, or public key types
- **THEN** `CryptoError::PopVerification` is returned with "Unsupported types"

---

### Requirement: Multi-Signature Combining (CspSigner::combine_sigs)
The CSP must combine individual BLS multi-signatures into a combined signature.

#### Scenario: Combine MultiBls12_381 signatures
- **WHEN** `combine_sigs` is called with `AlgorithmId::MultiBls12_381` and a vector of individual signatures
- **THEN** individual signatures are extracted from the `CspSignature::MultiBls12_381(Individual)` variants
- **AND** the combined result is returned as `CspSignature::MultiBls12_381(Combined)`

#### Scenario: Combine with non-multi-sig algorithm
- **WHEN** `combine_sigs` is called with an algorithm other than `MultiBls12_381`
- **THEN** `CryptoError::AlgorithmNotSupported` is returned

#### Scenario: Combine with malformed individual signature
- **WHEN** `combine_sigs` is called and one of the signatures is not an `Individual` BLS multi-signature
- **THEN** `CryptoError::AlgorithmNotSupported` is returned for that signature

---

### Requirement: Multi-Signature Verification (CspSigner::verify_multisig)
The CSP must verify combined multi-signatures against a set of signers.

#### Scenario: Verify combined MultiBls12_381 multi-signature
- **WHEN** `verify_multisig` is called with `AlgorithmId::MultiBls12_381`, a combined signature, signers, and a message
- **THEN** the combined signature is verified against all signers' BLS public keys

#### Scenario: Verify multisig with wrong signer key type
- **WHEN** `verify_multisig` is called and one signer's key is not `MultiBls12_381`
- **THEN** `CryptoError::SignatureVerification` is returned

---

### Requirement: Threshold Signature Operations (ThresholdSignatureCspClient)
The CSP must support BLS12-381 threshold signature operations.

#### Scenario: Threshold sign
- **WHEN** `threshold_sign` is called with `AlgorithmId::ThresBls12_381`, a message, and public coefficients
- **THEN** a `KeyId` is derived from the public coefficients
- **AND** the vault's `threshold_sign` is called with the derived key ID
- **AND** a threshold signature share is returned
- **AND** a parameter size metric is recorded

#### Scenario: Threshold sign with invalid public coefficients
- **WHEN** `threshold_sign` is called and the `KeyId` cannot be derived from the public coefficients
- **THEN** `CspThresholdSignError::KeyIdInstantiationError` is returned

#### Scenario: Combine threshold signatures
- **WHEN** `threshold_combine_signatures` is called with `AlgorithmId::ThresBls12_381` and a sparse vector of optional individual signatures
- **THEN** the signatures are combined using the BLS threshold library
- **AND** a `CspSignature::ThresBls12_381(Combined)` is returned

#### Scenario: Combine threshold signatures with unsupported algorithm
- **WHEN** `threshold_combine_signatures` is called with an algorithm other than `ThresBls12_381`
- **THEN** `CryptoError::InvalidArgument` is returned

#### Scenario: Compute individual public key from coefficients
- **WHEN** `threshold_individual_public_key` is called with `AlgorithmId::ThresBls12_381`, a node index, and public coefficients
- **THEN** the individual public key is derived from the coefficients at the given index
- **AND** a `CspThresholdSigPublicKey::ThresBls12_381` is returned

#### Scenario: Verify individual threshold signature
- **WHEN** `threshold_verify_individual_signature` is called with `AlgorithmId::ThresBls12_381`, a message, signature, and public key
- **THEN** the individual signature is verified against the public key using the BLS library

#### Scenario: Verify combined threshold signature
- **WHEN** `threshold_verify_combined_signature` is called with `AlgorithmId::ThresBls12_381`, a message, signature, and public coefficients
- **THEN** the combined public key is derived from the coefficients
- **AND** the combined signature is verified against it

---

### Requirement: NI-DKG Operations (NiDkgCspClient)
The CSP must support Non-Interactive Distributed Key Generation protocols.

#### Scenario: Update forward-secure epoch
- **WHEN** `update_forward_secure_epoch` is called with an algorithm ID and epoch
- **THEN** the forward-secure decryption key is updated so it cannot decrypt at epochs smaller than the given epoch
- **AND** if the key's epoch is already higher, the key remains unchanged

#### Scenario: Update forward-secure epoch panics on store failure
- **WHEN** `update_forward_secure_epoch` is called and the updated secret key cannot be stored
- **THEN** the method panics

#### Scenario: Create a dealing
- **WHEN** `create_dealing` is called with a valid NI-DKG algorithm, dealer index, threshold, epoch, and receiver keys
- **THEN** a `CspNiDkgDealing` containing encrypted shares for each receiver is returned

#### Scenario: Create dealing with invalid threshold
- **WHEN** `create_dealing` is called with a threshold less than 1 or greater than the number of receivers
- **THEN** `CspDkgCreateDealingError::InvalidThresholdError` is returned

#### Scenario: Create dealing with misnumbered receivers
- **WHEN** `create_dealing` is called and receiver indices are not 0..num_receivers-1
- **THEN** `CspDkgCreateDealingError::MisnumberedReceiverError` is returned

#### Scenario: Create dealing with malformed receiver key
- **WHEN** `create_dealing` is called and one receiver's forward-secure public key is malformed
- **THEN** `CspDkgCreateDealingError::MalformedFsPublicKeyError` is returned

#### Scenario: Create a resharing dealing
- **WHEN** `create_resharing_dealing` is called with resharing public coefficients and a dealer's resharing index
- **THEN** a `CspNiDkgDealing` is generated that reshares the existing threshold key
- **AND** the threshold public key is preserved across the resharing

#### Scenario: Create resharing dealing with missing resharing key
- **WHEN** `create_resharing_dealing` is called and the key to be reshared is not in the secret key store
- **THEN** `CspDkgCreateReshareDealingError::ReshareKeyNotInSecretKeyStoreError` is returned

#### Scenario: Verify a dealing
- **WHEN** `verify_dealing` is called with a dealing, threshold, epoch, and receiver keys
- **THEN** the dealing is verified using zero-knowledge proofs to confirm share correctness
- **AND** `Ok(())` is returned if valid

#### Scenario: Verify dealing with malformed dealing
- **WHEN** `verify_dealing` is called with a malformed dealing
- **THEN** `CspDkgVerifyDealingError::MalformedDealingError` is returned

#### Scenario: Verify a resharing dealing
- **WHEN** `verify_resharing_dealing` is called with a dealing and the previous public coefficients
- **THEN** verification confirms the dealing preserves the public key and shares are correct

#### Scenario: Create a transcript from dealings
- **WHEN** `create_transcript` is called with verified dealings, a threshold, and number of receivers
- **THEN** dealings are assembled into a `CspNiDkgTranscript`
- **AND** the transcript contains sufficient information for receivers to compute their threshold keys

#### Scenario: Create transcript with insufficient dealings
- **WHEN** `create_transcript` is called with fewer dealings than the collection threshold
- **THEN** `CspDkgCreateTranscriptError::InsufficientDealingsError` is returned

#### Scenario: Create a resharing transcript
- **WHEN** `create_resharing_transcript` is called with verified resharing dealings and previous public coefficients
- **THEN** a new `CspNiDkgTranscript` is created preserving the threshold public key

#### Scenario: Load threshold signing key from transcript
- **WHEN** `load_threshold_signing_key` is called with an algorithm, epoch, transcript, and receiver index
- **THEN** the threshold signing key is decrypted from the transcript using the forward-secure key
- **AND** the key is stored in the secret key store with a key ID derived from the public coefficients

#### Scenario: Load threshold signing key with missing FS key
- **WHEN** `load_threshold_signing_key` is called and the forward-secure decryption key is not found
- **THEN** `CspDkgLoadPrivateKeyError::KeyNotFoundError` is returned

#### Scenario: Retain threshold keys
- **WHEN** `retain_threshold_keys_if_present` is called with a set of active public coefficients
- **THEN** threshold keys matching the active set are kept
- **AND** all other threshold keys are removed from the secret key store

#### Scenario: Observe minimum epoch in active transcripts
- **WHEN** `observe_minimum_epoch_in_active_transcripts` is called with an epoch
- **THEN** a metrics observation is recorded

#### Scenario: Observe epoch in loaded transcript
- **WHEN** `observe_epoch_in_loaded_transcript` is called with an epoch
- **THEN** a metrics observation is recorded

---

### Requirement: CspVault Composite Trait
The `CspVault` trait is a composite of all vault sub-traits.

#### Scenario: CspVault blanket implementation
- **WHEN** a type implements `BasicSignatureCspVault`, `MultiSignatureCspVault`, `ThresholdSignatureCspVault`, `NiDkgCspVault`, `IDkgProtocolCspVault`, `ThresholdEcdsaSignerCspVault`, `ThresholdSchnorrSignerCspVault`, `VetKdCspVault`, `SecretKeyStoreCspVault`, `TlsHandshakeCspVault`, `PublicRandomSeedGenerator`, `PublicAndSecretKeyStoreCspVault`, and `PublicKeyStoreCspVault`
- **THEN** it automatically implements `CspVault`

---

### Requirement: Basic Signature Vault Operations (BasicSignatureCspVault)
The vault must generate Ed25519 node signing key pairs and sign messages.

#### Scenario: Generate node signing key pair
- **WHEN** `gen_node_signing_key_pair` is called on the vault
- **THEN** an Ed25519 key pair is generated
- **AND** the secret key is stored in the secret key store
- **AND** the public key is stored in the public key store
- **AND** the `CspPublicKey::Ed25519` is returned

#### Scenario: Generate node signing key pair with duplicate key ID
- **WHEN** `gen_node_signing_key_pair` is called and a key with the derived ID already exists
- **THEN** `CspBasicSignatureKeygenError::DuplicateKeyId` is returned

#### Scenario: Sign a message via vault
- **WHEN** `BasicSignatureCspVault::sign` is called with a message
- **THEN** the node signing secret key is looked up in the secret key store
- **AND** the message is signed with Ed25519
- **AND** the signature is returned as `CspSignature`

#### Scenario: Sign fails with missing public key
- **WHEN** `sign` is called and the node signing public key is not found in the public key store
- **THEN** `CspBasicSignatureError::PublicKeyNotFound` is returned

#### Scenario: Sign fails with wrong secret key type
- **WHEN** `sign` is called and the secret key has an unexpected type
- **THEN** `CspBasicSignatureError::WrongSecretKeyType` is returned

---

### Requirement: Multi-Signature Vault Operations (MultiSignatureCspVault)
The vault must generate BLS12-381 committee signing key pairs with PoP and sign messages.

#### Scenario: Generate committee signing key pair
- **WHEN** `gen_committee_signing_key_pair` is called on the vault
- **THEN** a BLS12-381 key pair and proof of possession are generated
- **AND** the secret key is stored and the public key and PoP are returned

#### Scenario: Multi-sign a message
- **WHEN** `multi_sign` is called with `AlgorithmId::MultiBls12_381`, a message, and a key ID
- **THEN** the secret key is retrieved from the vault
- **AND** the message is signed with BLS12-381
- **AND** a `CspSignature::MultiBls12_381(Individual)` is returned

#### Scenario: Multi-sign with missing secret key
- **WHEN** `multi_sign` is called and the secret key is not found for the given key ID
- **THEN** `CspMultiSignatureError::SecretKeyNotFound` is returned

#### Scenario: Multi-sign with unsupported algorithm
- **WHEN** `multi_sign` is called with an algorithm other than `MultiBls12_381`
- **THEN** `CspMultiSignatureError::UnsupportedAlgorithm` is returned

---

### Requirement: Threshold Signature Vault Operations (ThresholdSignatureCspVault)
The vault must sign messages with threshold secret keys.

#### Scenario: Threshold sign via vault
- **WHEN** `threshold_sign` is called with `AlgorithmId::ThresBls12_381`, a message, and a key ID
- **THEN** the threshold secret key is retrieved from the vault
- **AND** a threshold signature share is computed and returned

#### Scenario: Threshold sign with missing key
- **WHEN** `threshold_sign` is called and the secret key is not found
- **THEN** `CspThresholdSignError::SecretKeyNotFound` is returned

#### Scenario: Threshold sign with unsupported algorithm
- **WHEN** `threshold_sign` is called with an unsupported algorithm
- **THEN** `CspThresholdSignError::UnsupportedAlgorithm` is returned

---

### Requirement: NI-DKG Vault Operations (NiDkgCspVault)
The vault must generate forward-secure encryption keys, create dealings, and load threshold keys.

#### Scenario: Generate dealing encryption key pair
- **WHEN** `gen_dealing_encryption_key_pair` is called with a node ID
- **THEN** a Groth20 forward-secure encryption key pair is generated
- **AND** the secret key is stored in the secret key store
- **AND** the public key and proof of possession are returned as `(CspFsEncryptionPublicKey, CspFsEncryptionPop)`

#### Scenario: Update forward-secure epoch in vault
- **WHEN** `update_forward_secure_epoch` is called with an algorithm, key ID, and epoch
- **THEN** the forward-secure secret key is updated so older epochs cannot be decrypted

#### Scenario: Create dealing in vault
- **WHEN** `create_dealing` is called with valid parameters
- **THEN** a `CspNiDkgDealing` is generated with encrypted shares for each receiver

#### Scenario: Create resharing dealing in vault
- **WHEN** `create_resharing_dealing` is called with a resharing secret key ID
- **THEN** a dealing that reshares the identified secret is produced

#### Scenario: Load threshold signing key in vault
- **WHEN** `load_threshold_signing_key` is called with a transcript and forward-secure key ID
- **THEN** the threshold signing key is decrypted and stored in the secret key store

#### Scenario: Retain threshold keys in vault
- **WHEN** `retain_threshold_keys_if_present` is called with active key IDs
- **THEN** only threshold keys with matching IDs are retained

---

### Requirement: iDKG Protocol Vault Operations (IDkgProtocolCspVault)
The vault must support Interactive DKG protocol operations.

#### Scenario: Create iDKG dealing
- **WHEN** `idkg_create_dealing` is called with algorithm, context data, dealer index, reconstruction threshold, receiver keys, and transcript operation
- **THEN** an `IDkgDealingInternalBytes` is generated

#### Scenario: Create iDKG dealing with malformed receiver key
- **WHEN** `idkg_create_dealing` is called and a receiver key is malformed
- **THEN** `IDkgCreateDealingVaultError::MalformedPublicKey` is returned with the receiver index

#### Scenario: Verify iDKG dealing privately
- **WHEN** `idkg_verify_dealing_private` is called with a dealing and receiver key ID
- **THEN** the dealing is verified using the receiver's secret key

#### Scenario: Load iDKG transcript
- **WHEN** `idkg_load_transcript` is called with dealings, context data, and a receiver key ID
- **THEN** the secret share is computed from the transcript
- **AND** the share is stored in the secret key store
- **AND** any complaints about invalid dealings are returned as a `BTreeMap<NodeIndex, IDkgComplaintInternal>`

#### Scenario: Load iDKG transcript with openings
- **WHEN** `idkg_load_transcript_with_openings` is called with dealings and openings
- **THEN** openings are applied to resolve complaints
- **AND** the corrected secret share is stored

#### Scenario: Generate MEGa encryption key pair
- **WHEN** `idkg_gen_dealing_encryption_key_pair` is called
- **THEN** a secp256k1 MEGa encryption key pair is generated
- **AND** the secret key is stored
- **AND** the `MEGaPublicKey` is returned

#### Scenario: Generate MEGa key pair with duplicate key ID
- **WHEN** `idkg_gen_dealing_encryption_key_pair` is called and a key with the derived ID already exists
- **THEN** `CspCreateMEGaKeyError::DuplicateKeyId` is returned

#### Scenario: Open iDKG dealing
- **WHEN** `idkg_open_dealing` is called with a dealing, dealer index, and opener key ID
- **THEN** a `CommitmentOpening` for the specified dealing is returned

#### Scenario: Retain active iDKG keys
- **WHEN** `idkg_retain_active_keys` is called with active key IDs and the oldest public key
- **THEN** only iDKG keys matching the active set are kept
- **AND** MEGa encryption keys older than the oldest public key are removed

---

### Requirement: Threshold ECDSA Signing (ThresholdEcdsaSignerCspVault)
The vault must generate threshold ECDSA signature shares.

#### Scenario: Create ECDSA signature share
- **WHEN** `create_ecdsa_sig_share` is called with a derivation path, hashed message, nonce, and transcript bytes
- **THEN** a `ThresholdEcdsaSigShareInternal` is computed and returned

#### Scenario: Create ECDSA signature share with missing secret shares
- **WHEN** `create_ecdsa_sig_share` is called and the secret shares for a commitment are not in the key store
- **THEN** `ThresholdEcdsaCreateSigShareError` is returned

---

### Requirement: Threshold Schnorr Signing (ThresholdSchnorrSignerCspVault)
The vault must generate threshold Schnorr signature shares.

#### Scenario: Create Schnorr signature share
- **WHEN** `create_schnorr_sig_share` is called with a derivation path, message, nonce, key transcript, and presignature transcript
- **THEN** a `ThresholdSchnorrSigShareBytes` is computed and returned

#### Scenario: Create Schnorr signature share with optional taproot tree root
- **WHEN** `create_schnorr_sig_share` is called with a `Some(taproot_tree_root)`
- **THEN** the taproot tree root is incorporated into the signature share computation

#### Scenario: Create Schnorr signature share with invalid arguments
- **WHEN** `create_schnorr_sig_share` is called with an invalid algorithm ID
- **THEN** `ThresholdSchnorrCreateSigShareVaultError::InvalidArguments` is returned

---

### Requirement: VetKD Operations (VetKdCspVault)
The vault must generate encrypted vetKD key shares.

#### Scenario: Create encrypted vetKD key share
- **WHEN** `create_encrypted_vetkd_key_share` is called with a key ID, master public key, transport public key, derivation context, and input
- **THEN** a `VetKdEncryptedKeyShareContent` is returned

#### Scenario: VetKD with missing secret key
- **WHEN** `create_encrypted_vetkd_key_share` is called and the secret key is not found
- **THEN** `VetKdEncryptedKeyShareCreationVaultError::SecretKeyMissingOrWrongType` is returned

#### Scenario: VetKD with invalid master public key
- **WHEN** `create_encrypted_vetkd_key_share` is called with an invalid master public key
- **THEN** `VetKdEncryptedKeyShareCreationVaultError::InvalidArgumentMasterPublicKey` is returned

#### Scenario: VetKD with invalid encryption public key
- **WHEN** `create_encrypted_vetkd_key_share` is called with an invalid transport public key
- **THEN** `VetKdEncryptedKeyShareCreationVaultError::InvalidArgumentEncryptionPublicKey` is returned

---

### Requirement: TLS Handshake Operations (TlsHandshakeCspVault)
The vault must generate TLS key material and sign TLS handshake messages.

#### Scenario: Generate TLS key pair
- **WHEN** `gen_tls_key_pair` is called with a node ID
- **THEN** an Ed25519 TLS key pair is generated
- **AND** a self-signed X.509 certificate is created with:
  - A random serial number
  - The CN of subject and issuer set to the `ToString` form of the node ID
  - Validity starting 2 minutes before the current time
  - No well-defined expiration (notAfter set to `99991231235959Z`)
- **AND** the secret key is stored in the key store
- **AND** the `TlsPublicKeyCert` is returned

#### Scenario: Generate TLS key pair with duplicate key
- **WHEN** `gen_tls_key_pair` is called and a key with the derived ID already exists
- **THEN** `CspTlsKeygenError::DuplicateKeyId` is returned

#### Scenario: TLS sign
- **WHEN** `tls_sign` is called with a message and key ID
- **THEN** the TLS secret key is retrieved from the store
- **AND** the message is signed
- **AND** the `CspSignature` is returned

#### Scenario: TLS sign with missing key
- **WHEN** `tls_sign` is called and the secret key is not found
- **THEN** `CspTlsSignError::SecretKeyNotFound` is returned

---

### Requirement: Secret Key Store Operations (SecretKeyStoreCspVault)
The vault must expose a method to check for key presence.

#### Scenario: Check if secret key store contains a key
- **WHEN** `sks_contains` is called with a key ID
- **THEN** `Ok(true)` is returned if the key exists, `Ok(false)` otherwise

#### Scenario: Transient error checking key store
- **WHEN** `sks_contains` encounters a transient error (e.g., RPC failure)
- **THEN** `CspSecretKeyStoreContainsError::TransientInternalError` is returned

---

### Requirement: Public Key Store Operations (PublicKeyStoreCspVault)
The vault must expose methods to query the public key store.

#### Scenario: Get current node public keys
- **WHEN** `current_node_public_keys` is called
- **THEN** a `CurrentNodePublicKeys` is returned containing the latest public keys with timestamps stripped

#### Scenario: Get current node public keys with timestamps
- **WHEN** `current_node_public_keys_with_timestamps` is called
- **THEN** a `CurrentNodePublicKeys` is returned including generation timestamps

#### Scenario: Get iDKG dealing encryption public keys count
- **WHEN** `idkg_dealing_encryption_pubkeys_count` is called
- **THEN** the number of locally stored iDKG dealing encryption public keys is returned

---

### Requirement: Public and Secret Key Store Consistency (PublicAndSecretKeyStoreCspVault)
The vault must validate consistency between public and secret key stores.

#### Scenario: Check pks_and_sks_contains with all keys present
- **WHEN** `pks_and_sks_contains` is called with external public keys that all match locally stored keys
- **THEN** `Ok(())` is returned

#### Scenario: Check pks_and_sks_contains with missing local keys
- **WHEN** `pks_and_sks_contains` is called and some local keys are missing or do not match
- **THEN** `PksAndSksContainsErrors::NodeKeysErrors` is returned with details about which keys have errors

#### Scenario: Validate pks_and_sks with all valid keys
- **WHEN** `validate_pks_and_sks` is called and all public keys are present, valid, and have corresponding secret keys
- **THEN** `Ok(ValidNodePublicKeys)` is returned

#### Scenario: Validate pks_and_sks with empty public key store
- **WHEN** `validate_pks_and_sks` is called and the public key store has no keys
- **THEN** `ValidatePksAndSksError::EmptyPublicKeyStore` is returned

#### Scenario: Validate pks_and_sks with missing secret key
- **WHEN** `validate_pks_and_sks` is called and a secret key corresponding to a public key is missing
- **THEN** a `ValidatePksAndSksKeyPairError::SecretKeyNotFound` error is returned for the affected key type

---

### Requirement: Public Random Seed Generation (PublicRandomSeedGenerator)
The vault must generate public (non-secret) random seeds.

#### Scenario: Generate a public random seed
- **WHEN** `new_public_seed` is called
- **THEN** a `Seed` is returned containing random bytes

#### Scenario: Public seed must not be used for secret operations
- **WHEN** a public seed is generated
- **THEN** it must not be used for cryptographic key generation or any operation requiring secret randomness

#### Scenario: Transient error generating seed
- **WHEN** `new_public_seed` encounters a transient error
- **THEN** `PublicRandomSeedGeneratorError::TransientInternalError` is returned

---

### Requirement: KeyId Derivation and Stability
Key IDs must be deterministically derived from public keys and must remain stable across software versions.

#### Scenario: KeyId from AlgorithmId and bytes (small input)
- **WHEN** a `KeyId` is derived from an `(AlgorithmId, &[u8])` where the byte slice is less than 4 GiB
- **THEN** a domain-separated SHA-256 hash is computed using the "ic-key-id" domain
- **AND** the hash includes the algorithm byte, a 4-byte big-endian length prefix, and the key bytes

#### Scenario: KeyId from AlgorithmId and bytes (large input)
- **WHEN** a `KeyId` is derived from an `(AlgorithmId, &[u8])` where the byte slice is 4 GiB or larger
- **THEN** a domain-separated SHA-256 hash is computed using the "ic-key-id-large" domain
- **AND** the hash includes the algorithm byte, an 8-byte big-endian length prefix, and the key bytes

#### Scenario: KeyId from CspPublicKey
- **WHEN** a `KeyId` is derived from a `&CspPublicKey`
- **THEN** the algorithm ID is inferred from the public key variant
- **AND** the KeyId is computed from `(AlgorithmId, &public_key_bytes)`

#### Scenario: KeyId from MEGaPublicKey
- **WHEN** a `KeyId` is derived from a `&MEGaPublicKey`
- **THEN** the algorithm is determined by the curve type (K256, P256, or Ed25519)
- **AND** the KeyId is computed from the serialized public key

#### Scenario: KeyId from CspFsEncryptionPublicKey
- **WHEN** a `KeyId` is derived from a `&CspFsEncryptionPublicKey`
- **THEN** a domain-separated SHA-256 hash is computed using "KeyId from CspFsEncryptionPublicKey"
- **AND** the variant name and key bytes are included

#### Scenario: KeyId from PolynomialCommitment
- **WHEN** a `KeyId` is derived from a `&PolynomialCommitment`
- **THEN** a domain-separated SHA-256 hash is computed using "ic-key-id-idkg-commitment"
- **AND** the stable representation of the commitment is included with a length prefix

#### Scenario: KeyId from TlsPublicKeyCert
- **WHEN** a `KeyId` is derived from a `&TlsPublicKeyCert`
- **THEN** the KeyId is computed from `(AlgorithmId::Tls, der_bytes)`

#### Scenario: KeyId from CspPublicCoefficients
- **WHEN** a `KeyId` is derived from `&CspPublicCoefficients`
- **THEN** a domain-separated SHA-256 hash is computed using "KeyId from threshold public coefficients"
- **AND** the CBOR serialization of the coefficients is hashed
- **AND** if serialization fails, `KeyIdInstantiationError::InvalidArguments` is returned

#### Scenario: KeyId from hex string
- **WHEN** `KeyId::from_hex` is called with a valid 64-character hex string
- **THEN** a `KeyId` with the corresponding 32 bytes is returned
- **AND** if the hex is invalid or wrong length, an error string is returned

#### Scenario: KeyId stability invariant
- **WHEN** a KeyId is derived from the same input on different software versions
- **THEN** the resulting KeyId must always be identical (this is a critical system invariant)

---

### Requirement: Secret Key Store Trait (SecretKeyStore)
The secret key store must provide CRUD operations for secret key material.

#### Scenario: Insert a secret key
- **WHEN** `insert` is called with a key ID, secret key, and optional scope
- **THEN** the key is stored
- **AND** if a key with the same ID already exists, `SecretKeyStoreInsertionError::DuplicateKeyId` is returned

#### Scenario: Insert or replace a secret key
- **WHEN** `insert_or_replace` is called with a key ID, secret key, and optional scope
- **THEN** the key is stored, replacing any existing key with the same ID

#### Scenario: Get a secret key
- **WHEN** `get` is called with a key ID
- **THEN** the corresponding `CspSecretKey` is returned, or `None` if not found

#### Scenario: Check if key store contains a key
- **WHEN** `contains` is called with a key ID
- **THEN** `true` is returned if the key exists, `false` otherwise

#### Scenario: Remove a secret key
- **WHEN** `remove` is called with a key ID
- **THEN** the key is removed and `Ok(true)` is returned
- **AND** if the key did not exist, `Ok(false)` is returned

#### Scenario: Retain keys by scope and filter
- **WHEN** `retain` is called with a filter function and a scope
- **THEN** only keys in the given scope for which the filter returns `true` are kept
- **AND** all other keys in the scope are deleted

#### Scenario: Check if retain would modify keystore
- **WHEN** `retain_would_modify_keystore` is called with a filter and scope
- **THEN** `true` is returned if calling `retain` would delete any keys, `false` otherwise

---

### Requirement: Public Key Store Trait (PublicKeyStore)
The public key store must provide set-once semantics for node keys and append semantics for iDKG keys.

#### Scenario: Set node signing public key once
- **WHEN** `set_once_node_signing_pubkey` is called
- **THEN** the key is stored
- **AND** if already set, `PublicKeySetOnceError::AlreadySet` is returned

#### Scenario: Set committee signing public key once
- **WHEN** `set_once_committee_signing_pubkey` is called
- **THEN** the key is stored
- **AND** if already set, `PublicKeySetOnceError::AlreadySet` is returned

#### Scenario: Set NI-DKG dealing encryption public key once
- **WHEN** `set_once_ni_dkg_dealing_encryption_pubkey` is called
- **THEN** the key is stored
- **AND** if already set, `PublicKeySetOnceError::AlreadySet` is returned

#### Scenario: Set TLS certificate once
- **WHEN** `set_once_tls_certificate` is called
- **THEN** the certificate is stored
- **AND** if already set, `PublicKeySetOnceError::AlreadySet` is returned

#### Scenario: Add iDKG dealing encryption public key
- **WHEN** `add_idkg_dealing_encryption_pubkey` is called
- **THEN** the key is appended to the list of iDKG dealing encryption keys

#### Scenario: Retain iDKG public keys since a given key
- **WHEN** `retain_idkg_public_keys_since` is called with an oldest key to keep
- **THEN** the largest suffix of keys starting with (and including) the oldest key is kept
- **AND** older keys are deleted
- **AND** `Ok(true)` is returned if the store was modified

#### Scenario: Retain iDKG public keys with unknown oldest key
- **WHEN** `retain_idkg_public_keys_since` is called with a key not present in the store
- **THEN** `PublicKeyRetainError::OldestPublicKeyNotFound` is returned and no keys are deleted

#### Scenario: Get iDKG dealing encryption public keys
- **WHEN** `idkg_dealing_encryption_pubkeys` is called
- **THEN** all iDKG keys are returned in insertion order with timestamps stripped

#### Scenario: Get generation timestamps
- **WHEN** `generation_timestamps` is called
- **THEN** `PublicKeyGenerationTimestamps` is returned with optional timestamps for each key type

---

### Requirement: CspSecretKey Types and Variants
The `CspSecretKey` enum must support all required key types with zeroize-on-drop behavior.

#### Scenario: CspSecretKey enum variants
- **WHEN** a `CspSecretKey` is created
- **THEN** it must be one of: `Ed25519`, `MultiBls12_381`, `ThresBls12_381`, `TlsEd25519`, `FsEncryption`, `MEGaEncryptionK256`, or `IDkgCommitmentOpening`
- **AND** all variants implement `Zeroize` and `ZeroizeOnDrop` to ensure secret key material is erased from memory

#### Scenario: CspSecretKey enum variant name
- **WHEN** `enum_variant()` is called on a `CspSecretKey`
- **THEN** the variant name is returned as a `&'static str` (e.g., "Ed25519", "MultiBls12_381")

---

### Requirement: CspPublicKey Types
The `CspPublicKey` enum must support all required public key types.

#### Scenario: CspPublicKey variants
- **WHEN** a `CspPublicKey` is created
- **THEN** it must be one of: `EcdsaP256`, `EcdsaSecp256k1`, `Ed25519`, `MultiBls12_381`, or `RsaSha256`

#### Scenario: Extract Ed25519 bytes
- **WHEN** `ed25519_bytes()` is called on a `CspPublicKey::Ed25519`
- **THEN** the 32-byte key is returned
- **AND** `None` is returned for other variants

#### Scenario: Extract MultiBls12_381 bytes
- **WHEN** `multi_bls12_381_bytes()` is called on a `CspPublicKey::MultiBls12_381`
- **THEN** the key bytes are returned
- **AND** `None` is returned for other variants

---

### Requirement: CspSignature Algorithm Identification
Each CspSignature variant must correctly identify its algorithm.

#### Scenario: Signature algorithm identification
- **WHEN** `algorithm()` is called on a `CspSignature`
- **THEN** the correct `AlgorithmId` is returned:
  - `EcdsaP256` returns `AlgorithmId::EcdsaP256`
  - `EcdsaSecp256k1` returns `AlgorithmId::EcdsaSecp256k1`
  - `Ed25519` returns `AlgorithmId::Ed25519`
  - `MultiBls12_381` returns `AlgorithmId::MultiBls12_381`
  - `ThresBls12_381` returns `AlgorithmId::ThresBls12_381`
  - `RsaSha256` returns `AlgorithmId::RsaSha256`

---

### Requirement: IDkgTranscriptOperationInternalBytes Conversion
The intermediate bytes type must correctly convert to and from high-level transcript operations.

#### Scenario: Convert from IDkgTranscriptOperation::Random
- **WHEN** an `IDkgTranscriptOperationInternalBytes` is created from `IDkgTranscriptOperation::Random`
- **THEN** `IDkgTranscriptOperationInternalBytes::Random` is produced

#### Scenario: Convert from IDkgTranscriptOperation::ReshareOfMasked
- **WHEN** an `IDkgTranscriptOperationInternalBytes` is created from `IDkgTranscriptOperation::ReshareOfMasked`
- **THEN** the internal transcript raw bytes are wrapped in `IDkgTranscriptOperationInternalBytes::ReshareOfMasked`

#### Scenario: Convert to IDkgTranscriptOperationInternal
- **WHEN** `IDkgTranscriptOperationInternal::try_from` is called on `IDkgTranscriptOperationInternalBytes`
- **THEN** the bytes are deserialized into the corresponding `IDkgTranscriptOperationInternal` variant
- **AND** if deserialization fails, `CanisterThresholdSerializationError` is returned

---

### Requirement: Node Key Error Detection and Reporting
The CSP must detect and report errors in node key consistency.

#### Scenario: NodeKeysErrors with no errors
- **WHEN** all key error fields in `NodeKeysErrors` are `None`
- **THEN** `keys_in_registry_missing_locally` returns `false`

#### Scenario: NodeKeysErrors detects locally missing keys
- **WHEN** a key has no `external_public_key_error` but has a `local_public_key_error` or `secret_key_error`
- **THEN** `keys_in_registry_missing_locally` returns `true`

#### Scenario: NodeKeysErrors to KeyCounts conversion
- **WHEN** `KeyCounts::from` is called on `&NodeKeysErrors`
- **THEN** each key type without errors contributes `KeyCounts::ONE`
- **AND** each key type with errors contributes the `KeyCounts` derived from that `NodeKeysError`

#### Scenario: NodeKeysError to KeyCounts conversion
- **WHEN** `KeyCounts::from` is called on a `&NodeKeysError` with all fields `None`
- **THEN** `KeyCounts::ONE` (i.e., external=1, local=1, secret=1) is returned
- **AND** for each error field that is `Some`, the corresponding count is 0

---

### Requirement: Keygen Protobuf Conversion Utilities
The CSP must convert between internal key types and protobuf representations.

#### Scenario: DKG dealing encryption key to protobuf
- **WHEN** `dkg_dealing_encryption_pk_to_proto` is called with a Groth20 public key and PoP
- **THEN** a `PublicKeyProto` is returned with `Groth20Bls12381` algorithm, raw key bytes, and CBOR-serialized PoP in `proof_data`

#### Scenario: Node signing key to protobuf
- **WHEN** `node_signing_pk_to_proto` is called with an `Ed25519` public key
- **THEN** a `PublicKeyProto` is returned with `Ed25519` algorithm and raw key bytes

#### Scenario: Committee signing key to protobuf
- **WHEN** `committee_signing_pk_to_proto` is called with a BLS public key and PoP pair
- **THEN** a `PublicKeyProto` is returned with `MultiBls12381` algorithm, key bytes, and PoP bytes in `proof_data`

#### Scenario: iDKG dealing encryption key to protobuf
- **WHEN** `idkg_dealing_encryption_pk_to_proto` is called with a `MEGaPublicKey`
- **THEN** a `PublicKeyProto` is returned with `MegaSecp256k1` algorithm and serialized key bytes

#### Scenario: MEGa public key from protobuf
- **WHEN** `mega_public_key_from_proto` is called with a valid `PublicKeyProto` using `MegaSecp256k1`
- **THEN** the `MEGaPublicKey` is deserialized and returned

#### Scenario: MEGa public key from protobuf with unsupported algorithm
- **WHEN** `mega_public_key_from_proto` is called with a non-MEGa algorithm ID
- **THEN** `MEGaPublicKeyFromProtoError::UnsupportedAlgorithm` is returned

#### Scenario: MEGa public key from protobuf with malformed key
- **WHEN** `mega_public_key_from_proto` is called with malformed key bytes
- **THEN** `MEGaPublicKeyFromProtoError::MalformedPublicKey` is returned

---

### Requirement: CspRwLock Metrics Instrumentation
The CSP's internal read-write locks must observe lock acquisition duration.

#### Scenario: Write lock acquisition timing
- **WHEN** `CspRwLock::write()` is called
- **THEN** the time to acquire the write lock is observed via `metrics.observe_lock_acquisition_duration_seconds`
- **AND** the lock name and "write" access type are reported

#### Scenario: Read lock acquisition timing
- **WHEN** `CspRwLock::read()` is called
- **THEN** the time to acquire the read lock is observed
- **AND** the lock name and "read" access type are reported

#### Scenario: Lock names for metrics
- **WHEN** `CspRwLock` instances are created for different purposes
- **THEN** the lock names are: "csprng" for RNG, "secret_key_store" for SKS, "canister_secret_key_store" for CSKS, and "public_key_store" for PKS

---

### Requirement: Canister Threshold Key Scopes
The CSP must define constant scopes for iDKG key isolation.

#### Scenario: IDKG MEGa encryption keys scope
- **WHEN** `IDKG_MEGA_SCOPE` is referenced
- **THEN** it equals `Scope::Const(ConstScope::IDkgMEGaEncryptionKeys)`

#### Scenario: IDKG threshold keys scope
- **WHEN** `IDKG_THRESHOLD_KEYS_SCOPE` is referenced
- **THEN** it equals `Scope::Const(ConstScope::IDkgThresholdKeys)`

---

### Requirement: Forbidden Unsafe Code
The CSP crate must not use unsafe Rust code.

#### Scenario: No unsafe code
- **WHEN** the crate is compiled
- **THEN** the `#![forbid(unsafe_code)]` attribute ensures no `unsafe` blocks exist

---

### Requirement: Clippy Lint Compliance
The CSP crate must deny use of `unwrap`.

#### Scenario: No unwrap calls
- **WHEN** the crate is compiled with clippy
- **THEN** `#![deny(clippy::unwrap_used)]` ensures no `.unwrap()` calls exist in non-test code
