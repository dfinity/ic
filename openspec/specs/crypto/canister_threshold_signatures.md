# Canister Threshold Signatures

## Requirements

### Requirement: Canister Signature Verification (ICCSA)
The `CanisterSigVerifier` trait verifies Internet Computer Canister Signature Algorithm (ICCSA) signatures, which are signatures produced by canisters using certified variables.

#### Scenario: Verifying a canister signature
- **WHEN** `verify_canister_sig` is called with a signature, signed bytes, public key, and root of trust
- **THEN** the public key algorithm must be `AlgorithmId::IcCanisterSignature`
- **AND** the standalone ICCSA verification is performed using `ic_crypto_iccsa::verify`
- **AND** BLS signature cache statistics are observed for metrics

#### Scenario: Wrong algorithm for canister signature
- **WHEN** `verify_canister_sig` is called with a public key whose algorithm is not `IcCanisterSignature`
- **THEN** a `CryptoError::AlgorithmNotSupported` is returned

### Requirement: Threshold ECDSA Signing
The `ThresholdEcdsaSigner` trait creates ECDSA signature shares using canister threshold signature protocols. Supports secp256k1 (K-256) and P-256 curves.

#### Scenario: Creating an ECDSA signature share
- **WHEN** `create_sig_share` is called with `ThresholdEcdsaSigInputs`
- **THEN** the caller must be a receiver in the inputs
- **AND** the vault's `create_ecdsa_sig_share` is called with:
  - The extended derivation path (caller + derivation path)
  - The hashed message
  - The nonce as randomness
  - Key transcript, kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda transcripts
  - The algorithm ID
- **AND** the internal signature share is serialized and returned as `ThresholdEcdsaSigShare`

#### Scenario: Not a receiver
- **WHEN** the node calling `create_sig_share` is not listed as a receiver in the inputs
- **THEN** `ThresholdEcdsaCreateSigShareError::NotAReceiver` is returned

### Requirement: Threshold ECDSA Signature Share Verification

#### Scenario: Verifying an ECDSA signature share
- **WHEN** `verify_sig_share` is called with a signer NodeId, inputs, and share
- **THEN** all relevant transcripts (kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda, key) are deserialized from their internal representations
- **AND** the signature share is deserialized
- **AND** the signer's index in the key transcript is looked up
- **AND** the internal `verify_ecdsa_signature_share` function is called

#### Scenario: Missing signer in transcript
- **WHEN** the signer NodeId is not found in the key transcript's receiver set
- **THEN** `ThresholdEcdsaVerifySigShareError::InvalidArgumentMissingSignerInTranscript` is returned

#### Scenario: Invalid signature share
- **WHEN** the internal verification detects an invalid or inconsistent share
- **THEN** `ThresholdEcdsaVerifySigShareError::InvalidSignatureShare` is returned

### Requirement: Threshold ECDSA Signature Share Combination

#### Scenario: Combining ECDSA signature shares
- **WHEN** `combine_sig_shares` is called with inputs and a map of shares
- **THEN** the number of shares must meet or exceed the reconstruction threshold
- **AND** each share is deserialized and mapped by signer index
- **AND** the internal `combine_ecdsa_signature_shares` function produces a combined signature
- **AND** the combined signature is serialized and returned as `ThresholdEcdsaCombinedSignature`

#### Scenario: Insufficient shares
- **WHEN** the number of shares is less than the reconstruction threshold
- **THEN** `ThresholdEcdsaCombineSigSharesError::UnsatisfiedReconstructionThreshold` is returned with the threshold and share count

#### Scenario: Unauthorized signer
- **WHEN** a share's signer NodeId is not found in the input's signer-to-index mapping
- **THEN** `ThresholdEcdsaCombineSigSharesError::SignerNotAllowed` is returned

### Requirement: Threshold ECDSA Combined Signature Verification

#### Scenario: Verifying a combined ECDSA signature
- **WHEN** `verify_combined_sig` is called with inputs and a combined signature
- **THEN** the kappa_unmasked and key transcripts are deserialized
- **AND** the combined signature is deserialized using the algorithm ID
- **AND** the internal `verify_ecdsa_threshold_signature` function verifies the signature

#### Scenario: Invalid combined signature
- **WHEN** the verification detects an invalid signature
- **THEN** `ThresholdEcdsaVerifyCombinedSignatureError::InvalidSignature` is returned

### Requirement: Master Public Key Extraction (ECDSA)

#### Scenario: Extracting ECDSA master public key from transcript
- **WHEN** `get_master_public_key_from_transcript` is called with an unmasked ECDSA transcript
- **THEN** the internal transcript's constant term (public key point) is extracted
- **AND** the curve type determines the algorithm ID: K-256 maps to `EcdsaSecp256k1`, P-256 maps to `EcdsaP256`
- **AND** a `MasterPublicKey` is returned with the serialized public key

#### Scenario: Extracting from masked transcript
- **WHEN** the transcript type is `Masked`
- **THEN** `MasterPublicKeyExtractionError::CannotExtractFromMasked` is returned

#### Scenario: Unsupported algorithm
- **WHEN** the transcript's algorithm is neither threshold ECDSA nor threshold Schnorr
- **THEN** `MasterPublicKeyExtractionError::UnsupportedAlgorithm` is returned

### Requirement: Threshold Schnorr Signing
The `ThresholdSchnorrSigner` trait creates Schnorr signature shares supporting both BIP-340 (secp256k1) and Ed25519 curves.

#### Scenario: Creating a Schnorr signature share
- **WHEN** `create_sig_share` is called with `ThresholdSchnorrSigInputs`
- **THEN** the caller must be a receiver in the inputs
- **AND** the vault's `create_schnorr_sig_share` is called with:
  - The extended derivation path
  - The message bytes
  - The taproot tree root (optional, for BIP-340)
  - The nonce as randomness
  - Key transcript and presignature (blinder_unmasked) transcript
  - The algorithm ID
- **AND** the result is returned as `ThresholdSchnorrSigShare`

#### Scenario: Not a receiver for Schnorr
- **WHEN** the node is not a receiver in the inputs
- **THEN** `ThresholdSchnorrCreateSigShareError::NotAReceiver` is returned

### Requirement: Threshold Schnorr Signature Share Verification

#### Scenario: Verifying a BIP-340 Schnorr signature share
- **WHEN** `verify_sig_share` is called with algorithm `ThresholdSchnorrBip340`
- **THEN** the share is deserialized as `ThresholdBip340SignatureShareInternal`
- **AND** the internal `verify_bip340_signature_share` function is called with the presignature, key transcript, message, taproot tree root, nonce, and signer index

#### Scenario: Verifying an Ed25519 threshold signature share
- **WHEN** `verify_sig_share` is called with algorithm `ThresholdEd25519`
- **THEN** the share is deserialized as `ThresholdEd25519SignatureShareInternal`
- **AND** the internal `verify_ed25519_signature_share` function is called

#### Scenario: Invalid algorithm for Schnorr verification
- **WHEN** the algorithm ID is neither `ThresholdSchnorrBip340` nor `ThresholdEd25519`
- **THEN** `ThresholdSchnorrVerifySigShareError::InvalidArguments` is returned

### Requirement: Threshold Schnorr Signature Share Combination

#### Scenario: Combining BIP-340 signature shares
- **WHEN** `combine_sig_shares` is called with algorithm `ThresholdSchnorrBip340` and sufficient shares
- **THEN** shares are deserialized as BIP-340 internal shares
- **AND** `combine_bip340_signature_shares` produces a combined signature
- **AND** the result is serialized as `ThresholdSchnorrCombinedSignature`

#### Scenario: Combining Ed25519 threshold signature shares
- **WHEN** `combine_sig_shares` is called with algorithm `ThresholdEd25519` and sufficient shares
- **THEN** shares are deserialized as Ed25519 internal shares
- **AND** `combine_ed25519_signature_shares` produces a combined signature

#### Scenario: Insufficient Schnorr shares
- **WHEN** the number of shares is less than the reconstruction threshold
- **THEN** `ThresholdSchnorrCombineSigSharesError::UnsatisfiedReconstructionThreshold` is returned

### Requirement: Threshold Schnorr Combined Signature Verification

#### Scenario: Verifying a combined BIP-340 signature
- **WHEN** `verify_combined_sig` is called with algorithm `ThresholdSchnorrBip340`
- **THEN** the signature is deserialized as `ThresholdBip340CombinedSignatureInternal`
- **AND** `verify_threshold_bip340_signature` verifies against the key, presignature, message, taproot tree root, nonce, and derivation path

#### Scenario: Verifying a combined Ed25519 threshold signature
- **WHEN** `verify_combined_sig` is called with algorithm `ThresholdEd25519`
- **THEN** the signature is deserialized as `ThresholdEd25519CombinedSignatureInternal`
- **AND** `verify_threshold_ed25519_signature` verifies the signature

#### Scenario: Invalid algorithm for combined Schnorr verification
- **WHEN** the algorithm ID is not a supported Schnorr type
- **THEN** `ThresholdSchnorrVerifyCombinedSigError::InvalidArguments` is returned

### Requirement: Master Public Key Extraction (Schnorr)

#### Scenario: Extracting Schnorr master public key from transcript
- **WHEN** `get_master_public_key_from_transcript` is called with an unmasked Schnorr transcript
- **THEN** the curve type determines the algorithm: K-256 maps to `SchnorrSecp256k1`, Ed25519 maps to `Ed25519`
- **AND** a `MasterPublicKey` is returned

#### Scenario: Unsupported Schnorr curve
- **WHEN** the transcript uses an unsupported curve (e.g., P-256 for Schnorr)
- **THEN** `MasterPublicKeyExtractionError::UnsupportedAlgorithm` is returned

### Requirement: Ingress Signature Verification
The `IngressSigVerifier` super-trait combines verification capabilities for ingress messages.

#### Scenario: Ingress signature verification capabilities
- **WHEN** a type implements `IngressSigVerifier`
- **THEN** it must support:
  - `BasicSigVerifierByPublicKey<WebAuthnEnvelope>`
  - `BasicSigVerifierByPublicKey<MessageId>`
  - `BasicSigVerifierByPublicKey<Delegation>`
  - `CanisterSigVerifier<Delegation>`
  - `CanisterSigVerifier<MessageId>`
- **AND** it must be `Send + Sync`
