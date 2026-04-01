# Crypto: Signatures Capability Specification

**Source narrative**: `openspec/specs/crypto/signatures.md`
**Crates**: `ic-crypto`, `ic-crypto-internal-basic-sig-*`, `ic-crypto-internal-threshold-sig-*`
**Key files**: `rs/crypto/src/`, `rs/crypto/internal/`

---

## REQ-SIG-001: Basic Signature Signing (Ed25519)

The `BasicSigner` trait MUST allow nodes to sign messages using their Ed25519 node signing key.

### SCENARIO-SIG-001: Signing a message
**Given** `sign_basic` is called with a `Signable` message
**When** signing runs
**Then** the message is serialized via `as_signed_bytes()`
**And** the vault's `sign` method produces the signature
**And** the result is wrapped in a `BasicSigOf<H>`

---

## REQ-SIG-002: Basic Signature Verification

The `BasicSigVerifier` trait MUST verify basic signatures against a signer's registry public key.

### SCENARIO-SIG-002: Verifying a basic signature
**Given** `verify_basic_sig` is called with a signature, message, signer NodeId, and registry version
**When** verification runs
**Then** the signer's node signing public key is retrieved from the registry
**And** the CSP's `verify` method is called
**And** success or `CryptoError` is returned

### SCENARIO-SIG-003: Signer public key not in registry
**Given** the signer's node signing public key is not found in the registry
**When** verification runs
**Then** `CryptoError::PublicKeyNotFound` is returned

---

## REQ-SIG-003: Basic Signature Verification by Public Key

The `BasicSigVerifierByPublicKey` trait MUST verify signatures using directly provided public keys.

### SCENARIO-SIG-004: Verify by Ed25519 public key
**Given** `verify_basic_sig_by_public_key` is called with an Ed25519 key
**When** verification runs
**Then** the standalone Ed25519 verifier is used

### SCENARIO-SIG-005: Unsupported algorithm
**Given** the public key algorithm is not one of Ed25519, EcdsaP256, EcdsaSecp256k1, or RsaSha256
**When** verification runs
**Then** `CryptoError::AlgorithmNotSupported` is returned

---

## REQ-SIG-004: Multi-Signature (BLS12-381)

The `MultiSigner` trait MUST produce and verify BLS12-381 individual multi-signatures.

### SCENARIO-SIG-006: Creating a multi-signature share
**Given** `sign_multi` is called with a message, signer NodeId, and registry version
**When** signing runs
**Then** the signer's committee signing public key is retrieved
**And** the CSP produces a `ThresholdSigShareOf`

### SCENARIO-SIG-007: Combining individual multi-signatures
**Given** `combine_multi_sig_individuals` is called with a non-empty map
**When** combining runs
**Then** all signers' public keys are retrieved and algorithms verified consistent
**And** the CSP's `combine_sigs` produces a `CombinedMultiSigOf`

### SCENARIO-SIG-008: Inconsistent algorithms across signers
**Given** committee signing public keys of different signers use different algorithms
**When** combining runs
**Then** `CryptoError::InconsistentAlgorithms` is returned

---

## REQ-SIG-005: Threshold Signature (BLS12-381)

The `ThresholdSigner` trait MUST produce threshold signature shares using NI-DKG transcript keys.

### SCENARIO-SIG-009: Creating a threshold signature share
**Given** `sign_threshold` is called with a message and NI-DKG ID
**When** signing runs
**Then** public coefficients are retrieved from the threshold sig data store
**And** the CSP produces a `ThresholdSigShareOf<T>`

### SCENARIO-SIG-010: Combining threshold signature shares
**Given** `combine_threshold_sig_shares` is called with a non-empty map
**When** combining runs
**Then** shares are indexed by node index from the store
**And** the CSP produces a `CombinedThresholdSigOf`

### SCENARIO-SIG-011: Verify combined threshold signature by subnet public key
**Given** `verify_combined_threshold_sig_by_public_key` is called with subnet ID and registry version
**When** verification runs
**Then** the initial NI-DKG transcript for the subnet is fetched from the registry
**And** the CSP verifies the signature against the transcript's public coefficients

---

## REQ-SIG-006: Threshold Sig Data Store Capacity

The `ThresholdSigDataStoreImpl` MUST limit the number of DKG IDs stored per tag.

### SCENARIO-SIG-012: Exceeding store capacity evicts oldest entries
**Given** data is inserted for more DKG IDs than `CAPACITY_PER_TAG_OR_KEY`
**When** the new entry is inserted
**Then** the oldest data for that tag is removed

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-SIG-001 | Basic signing | narrative | rs/crypto/tests/ |
| REQ-SIG-002 | Basic verification | narrative | rs/crypto/tests/ |
| REQ-SIG-003 | Verification by public key | narrative | rs/crypto/tests/ |
| REQ-SIG-004 | Multi-signature | narrative | rs/crypto/tests/ |
| REQ-SIG-005 | Threshold signature | narrative | rs/crypto/tests/ |
| REQ-SIG-006 | Data store capacity | narrative | rs/crypto/tests/ |
