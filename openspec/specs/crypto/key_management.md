# Key Management

## Requirements

### Requirement: Key Types
Each IC node has 5 types of cryptographic keys, each serving a distinct purpose.

#### Scenario: Node signing key (Ed25519)
- **WHEN** a node signing key pair is generated
- **THEN** it uses Ed25519
- **AND** the `NodeId` is derived from the node signing public key
- **AND** it is used for basic signatures (`KeyPurpose::NodeSigning`)

#### Scenario: Committee signing key (BLS12-381)
- **WHEN** a committee signing key pair is generated
- **THEN** it uses BLS12-381 with a proof of possession (PoP)
- **AND** it is used for multi-signatures and committee operations (`KeyPurpose::CommitteeSigning`)

#### Scenario: DKG dealing encryption key (forward-secure)
- **WHEN** a DKG dealing encryption key pair is generated
- **THEN** it uses forward-secure encryption (BLS12-381)
- **AND** a proof of possession is generated
- **AND** it is used for NI-DKG dealing encryption (`KeyPurpose::DkgDealingEncryption`)

#### Scenario: IDKG dealing encryption key (MEGa)
- **WHEN** an IDKG dealing encryption key pair is generated
- **THEN** it uses the MEGa encryption scheme on an elliptic curve
- **AND** it is used for interactive DKG dealing encryption (`KeyPurpose::IDkgMEGaEncryption`)

#### Scenario: TLS certificate
- **WHEN** a TLS certificate is generated for a node
- **THEN** it is a self-signed X.509 certificate with an Ed25519 key
- **AND** the notAfter date indicates no well-defined expiration (per RFC 5280 section 4.1.2.5)

### Requirement: Node Key Generation
Node keys are generated once during node setup via the `generate_node_keys_once` function.

#### Scenario: Generating all node keys
- **WHEN** `generate_node_keys_once` is called with a crypto config
- **THEN** all 5 key types are generated:
  - Node signing key pair
  - Committee signing key pair
  - DKG dealing encryption key pair
  - IDKG dealing encryption key pair
  - TLS certificate
- **AND** secret keys are stored in the vault's secret key store
- **AND** public keys and the TLS certificate are returned

#### Scenario: Node signing key generation
- **WHEN** `generate_node_signing_keys` is called
- **THEN** the vault's `gen_node_signing_key_pair` method is called
- **AND** the public key is converted to protobuf format

#### Scenario: Committee signing key generation
- **WHEN** `generate_committee_signing_keys` is called
- **THEN** the vault's `gen_committee_signing_key_pair` method is called
- **AND** the public key (with PoP) is converted to protobuf format

#### Scenario: DKG dealing encryption key generation
- **WHEN** `generate_dkg_dealing_encryption_keys` is called with a NodeId
- **THEN** the vault's `gen_dealing_encryption_key_pair` method is called with the NodeId
- **AND** the public key and PoP are converted to protobuf format

#### Scenario: IDKG dealing encryption key generation
- **WHEN** `generate_idkg_dealing_encryption_keys` is called
- **THEN** the vault's `idkg_gen_dealing_encryption_key_pair` method is called
- **AND** the public key is converted to protobuf format
- **AND** errors map to `IDkgDealingEncryptionKeysGenerationError`

#### Scenario: TLS key material generation
- **WHEN** TLS key material is generated for a node
- **THEN** a self-signed certificate is created with the node's principal as subject name
- **AND** the secret key is stored in the vault
- **AND** the certificate has no well-defined expiration date

### Requirement: Check Keys with Registry
The `KeyManager::check_keys_with_registry` method verifies that the node's local keys match what is in the registry.

#### Scenario: All keys match
- **WHEN** `check_keys_with_registry` is called with a registry version
- **THEN** all 5 public keys are retrieved from the registry
- **AND** the vault's `pks_and_sks_contains` method verifies that matching public and secret keys exist locally
- **AND** key count metrics are recorded (5 registry keys, 5 public keys, 5 secret keys)
- **AND** `Ok(())` is returned

#### Scenario: Keys missing from registry
- **WHEN** one or more public keys are missing from the registry
- **THEN** metrics are recorded with the number of keys found
- **AND** a `CheckKeysWithRegistryError` wrapping the first `CryptoError` is returned

#### Scenario: Keys in registry but missing locally
- **WHEN** registry keys exist but corresponding local keys are missing
- **THEN** `NodeKeysErrors` details are logged as a warning
- **AND** the `keys_in_registry_missing_locally` metric is observed
- **AND** a `CryptoError::InternalError` is returned

#### Scenario: Transient error checking keys
- **WHEN** a transient error occurs during the `pks_and_sks_contains` check
- **THEN** zero key counts are recorded with an error metric
- **AND** a `CryptoError::TransientInternalError` is returned

### Requirement: Current Node Public Keys

#### Scenario: Retrieving current node public keys
- **WHEN** `current_node_public_keys` is called
- **THEN** the vault's `current_node_public_keys` method is called
- **AND** the result is a `CurrentNodePublicKeys` containing all 5 key types (each as `Option`)

### Requirement: IDKG Dealing Encryption Key Rotation
Keys for IDKG dealing encryption are periodically rotated based on a configurable rotation period.

#### Scenario: Key rotation when enabled
- **WHEN** `rotate_idkg_dealing_encryption_keys` is called and key rotation is enabled for the node's subnet
- **THEN** the current local IDKG dealing encryption key is compared with the registry key
- **AND** if the registry key has no timestamp, a new key is generated
- **AND** if the registry key's timestamp plus the rotation period has elapsed, a new key is generated
- **AND** the new key is returned for registration

#### Scenario: Key rotation not enabled
- **WHEN** key rotation is not enabled for the subnet (no chain key config or empty key configs)
- **THEN** `IDkgDealingEncryptionKeyRotationError::KeyRotationNotEnabled` is returned

#### Scenario: Latest rotation too recent
- **WHEN** the current key's timestamp plus the rotation period has not elapsed
- **THEN** `IDkgKeyRotationResult::LatestRotationTooRecent` is returned

#### Scenario: Local key differs from registry (needs registration)
- **WHEN** the local IDKG key differs from the registry key (already rotated but not yet registered)
- **THEN** `IDkgKeyRotationResult::IDkgDealingEncPubkeyNeedsRegistration` is returned with `KeyNotRotated`
- **AND** if the local key is also too old, `KeyNotRotatedButTooOld` is returned instead

#### Scenario: Registry key missing
- **WHEN** the IDKG key is not found in the registry
- **THEN** `IDkgDealingEncryptionKeyRotationError::RegistryKeyBadOrMissing` is returned

#### Scenario: Key rotation period overflow
- **WHEN** the sum of registration timestamp and rotation period would overflow a u64 of nanoseconds
- **THEN** the key is not considered too old (the overflow implies the rotation period is unreasonably large)
- **AND** a warning is logged about potential misconfiguration

#### Scenario: Key rotation metrics
- **WHEN** key rotation completes (success or error)
- **THEN** appropriate metrics are recorded:
  - `KeyRotated`, `KeyNotRotated`, `KeyNotRotatedButTooOld`, `LatestLocalRotationTooRecent`
  - Or error variants: `KeyGenerationError`, `RegistryError`, `KeyRotationNotEnabled`, `TransientInternalError`, `PublicKeyNotFound`, `RegistryKeyBadOrMissing`

### Requirement: Node Public Key Validation
The `ValidNodePublicKeys` type in `node_key_validation` ensures all public keys for a node are valid before being stored in the registry.

#### Scenario: Validating node signing key
- **WHEN** a node signing key is validated
- **THEN** the key must be present and well-formed
- **AND** the NodeId derived from the key must match the expected node_id
- **AND** the public key must be a valid point on the Ed25519 curve in the correct subgroup

#### Scenario: Validating committee signing key
- **WHEN** a committee signing key is validated
- **THEN** the key must be present and well-formed
- **AND** the proof of possession (PoP) must be valid
- **AND** the public key must be on the BLS12-381 curve in the correct subgroup

#### Scenario: Validating NI-DKG dealing encryption key
- **WHEN** a NI-DKG dealing encryption key is validated
- **THEN** the key must be present and well-formed
- **AND** the proof of possession (PoP) must be valid
- **AND** the public key must be on the curve and in the correct subgroup

#### Scenario: Validating IDKG dealing encryption key
- **WHEN** an IDKG dealing encryption key is validated
- **THEN** the key must be present and well-formed
- **AND** the public key must be a valid point on the curve

#### Scenario: Validating TLS certificate
- **WHEN** a TLS certificate is validated
- **THEN** the certificate must be present
- **AND** it is validated per `ic_crypto_tls_cert_validation::validate_tls_certificate`

### Requirement: Key Retrieval from Registry

#### Scenario: Fetching a key from registry
- **WHEN** `key_from_registry` is called with a registry client, node_id, key_purpose, and registry_version
- **THEN** `get_crypto_key_for_node` is called on the registry
- **AND** if found, the `PublicKeyProto` is returned
- **AND** if not found, `CryptoError::PublicKeyNotFound` is returned

### Requirement: Node ID Derivation

#### Scenario: Deriving NodeId from signing key
- **WHEN** `derive_node_id` is called with a node signing public key protobuf
- **THEN** a deterministic `NodeId` is derived from the public key
- **AND** the derivation is implemented in `ic_crypto_utils_basic_sig::conversions`
