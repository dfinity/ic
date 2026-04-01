# Crypto: Canister Threshold Signatures Capability Specification

**Source narrative**: `openspec/specs/crypto/canister_threshold_signatures.md`
**Crates**: `ic-crypto`, `ic-crypto-internal-threshold-sig-ecdsa`, `ic-crypto-internal-threshold-sig-bls12381`
**Key files**: `rs/crypto/src/`, `rs/crypto/internal/`

---

## REQ-THRESH-001: Canister Signature Verification (ICCSA)

The `CanisterSigVerifier` trait MUST verify Internet Computer Canister Signature Algorithm signatures.

### SCENARIO-THRESH-001: Verifying a canister signature
**Given** `verify_canister_sig` is called with a signature, signed bytes, public key, and root of trust
**When** verification runs
**Then** the public key algorithm must be `AlgorithmId::IcCanisterSignature`
**And** standalone ICCSA verification is performed via `ic_crypto_iccsa::verify`

### SCENARIO-THRESH-002: Wrong algorithm for canister signature
**Given** `verify_canister_sig` is called with a key whose algorithm is not `IcCanisterSignature`
**When** verification runs
**Then** `CryptoError::AlgorithmNotSupported` is returned

---

## REQ-THRESH-002: Threshold ECDSA Signing

The `ThresholdEcdsaSigner` trait MUST create ECDSA signature shares using NI-DKG transcript keys.

### SCENARIO-THRESH-003: Creating an ECDSA signature share
**Given** `create_sig_share` is called with `ThresholdEcdsaSigInputs`
**When** signing runs
**Then** the caller must be a receiver in the inputs
**And** the vault's `create_ecdsa_sig_share` is called with derivation path, hashed message, nonce, and all required transcripts
**And** the result is returned as `ThresholdEcdsaSigShare`

### SCENARIO-THRESH-004: Not a receiver for ECDSA
**Given** the calling node is not listed as a receiver in the inputs
**When** signing runs
**Then** `ThresholdEcdsaCreateSigShareError::NotAReceiver` is returned

---

## REQ-THRESH-003: Threshold ECDSA Share Combination

The system MUST combine ECDSA signature shares into a complete signature.

### SCENARIO-THRESH-005: Combining ECDSA signature shares
**Given** `combine_sig_shares` is called with inputs and a map of shares
**When** combining runs
**Then** the number of shares must meet or exceed the reconstruction threshold
**And** the internal `combine_ecdsa_signature_shares` produces a combined signature

### SCENARIO-THRESH-006: Insufficient ECDSA shares
**Given** the number of shares is less than the reconstruction threshold
**When** combining runs
**Then** `ThresholdEcdsaCombineSigSharesError::UnsatisfiedReconstructionThreshold` is returned

---

## REQ-THRESH-004: Master Public Key Extraction

The system MUST extract master public keys from unmasked transcripts.

### SCENARIO-THRESH-007: Extracting ECDSA master public key
**Given** `get_master_public_key_from_transcript` is called with an unmasked ECDSA transcript
**When** extraction runs
**Then** the constant term (public key point) is extracted from the internal transcript
**And** K-256 → `EcdsaSecp256k1`, P-256 → `EcdsaP256`
**And** a `MasterPublicKey` is returned

### SCENARIO-THRESH-008: Extracting from masked transcript
**Given** the transcript type is `Masked`
**When** extraction runs
**Then** `MasterPublicKeyExtractionError::CannotExtractFromMasked` is returned

---

## REQ-THRESH-005: Threshold Schnorr Signing

The `ThresholdSchnorrSigner` trait MUST create Schnorr signature shares for BIP-340 and Ed25519.

### SCENARIO-THRESH-009: Creating a Schnorr signature share
**Given** `create_sig_share` is called with `ThresholdSchnorrSigInputs`
**When** signing runs
**Then** the caller must be a receiver in the inputs
**And** the vault creates the share using derivation path, message, nonce, key transcript, and blinder transcript

### SCENARIO-THRESH-010: Combining BIP-340 signature shares
**Given** `combine_sig_shares` is called with `ThresholdSchnorrBip340` and sufficient shares
**When** combining runs
**Then** shares are deserialized as BIP-340 internal shares
**And** `combine_bip340_signature_shares` produces a combined signature

### SCENARIO-THRESH-011: Combining Ed25519 threshold signature shares
**Given** `combine_sig_shares` is called with `ThresholdEd25519` and sufficient shares
**When** combining runs
**Then** `combine_ed25519_signature_shares` produces a combined signature

### SCENARIO-THRESH-012: Insufficient Schnorr shares
**Given** the number of shares is less than the reconstruction threshold
**When** combining runs
**Then** `ThresholdSchnorrCombineSigSharesError::UnsatisfiedReconstructionThreshold` is returned

---

## REQ-THRESH-006: Ingress Signature Verification

The `IngressSigVerifier` MUST support verification of all ingress message signature types.

### SCENARIO-THRESH-013: Ingress signature verification capabilities
**Given** a type implements `IngressSigVerifier`
**When** verification capabilities are checked
**Then** it supports `BasicSigVerifierByPublicKey<WebAuthnEnvelope>`, `BasicSigVerifierByPublicKey<MessageId>`, `BasicSigVerifierByPublicKey<Delegation>`, `CanisterSigVerifier<Delegation>`, and `CanisterSigVerifier<MessageId>`
**And** it is `Send + Sync`

---

## REQ-THRESH-007: Threshold ECDSA Share Verification

The system MUST verify individual ECDSA signature shares.

### SCENARIO-THRESH-014: Verifying an ECDSA signature share
**Given** `verify_sig_share` is called with a signer NodeId, inputs, and share
**When** verification runs
**Then** all relevant transcripts are deserialized
**And** the signer's index in the key transcript is looked up
**And** the internal `verify_ecdsa_signature_share` function verifies the share

### SCENARIO-THRESH-015: Missing signer in ECDSA transcript
**Given** the signer NodeId is not found in the key transcript's receiver set
**When** verification runs
**Then** `ThresholdEcdsaVerifySigShareError::InvalidArgumentMissingSignerInTranscript` is returned

---

## REQ-THRESH-008: Threshold Schnorr Share Verification

The system MUST verify individual Schnorr signature shares for both BIP-340 and Ed25519.

### SCENARIO-THRESH-016: Verifying a BIP-340 Schnorr signature share
**Given** `verify_sig_share` is called with algorithm `ThresholdSchnorrBip340`
**When** verification runs
**Then** the share is deserialized as `ThresholdBip340SignatureShareInternal`
**And** `verify_bip340_signature_share` is called with presignature, key transcript, message, taproot tree root, nonce, and signer index

### SCENARIO-THRESH-017: Verifying an Ed25519 threshold signature share
**Given** `verify_sig_share` is called with algorithm `ThresholdEd25519`
**When** verification runs
**Then** the share is deserialized as `ThresholdEd25519SignatureShareInternal`
**And** `verify_ed25519_signature_share` is called

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-THRESH-001 | Canister signature (ICCSA) | narrative | rs/crypto/tests/ |
| REQ-THRESH-002 | Threshold ECDSA signing | linked | rs/crypto/tests/integration_test.rs |
| REQ-THRESH-003 | ECDSA share combination | narrative | rs/crypto/tests/ |
| REQ-THRESH-004 | Master public key extraction | narrative | rs/crypto/tests/ |
| REQ-THRESH-005 | Threshold Schnorr signing | linked | rs/crypto/tests/integration_test.rs |
| REQ-THRESH-006 | Ingress signature verification | narrative | rs/crypto/tests/ |
| REQ-THRESH-007 | ECDSA share verification | narrative | rs/crypto/tests/ |
| REQ-THRESH-008 | Schnorr share verification | narrative | rs/crypto/tests/ |
| REQ-THRESH-006 | Ingress signature verification | narrative | rs/crypto/tests/ |
