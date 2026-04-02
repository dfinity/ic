# Crypto: VetKD (Verifiable Encrypted Threshold Key Derivation) Capability Specification

**Source narrative**: `openspec/specs/crypto/vetkd.md`
**Crates**: `ic-crypto`
**Key files**: `rs/crypto/src/`, `rs/crypto/internal/`

---

## REQ-VETKD-001: Encrypted Key Share Creation

Nodes MUST be able to create encrypted VetKD key shares using BLS12-381 threshold keys.

### SCENARIO-VETKD-001: Creating an encrypted key share
**Given** `create_encrypted_key_share` is called with `VetKdArgs`
**When** the share is created
**Then** public coefficients for the NI-DKG ID are retrieved from the threshold sig data store
**And** the vault creates the encrypted share using the derivation context (caller + context bytes), transport public key, and input
**And** the share is signed with the node's basic signing key
**And** a `VetKdEncryptedKeyShare` is returned

### SCENARIO-VETKD-002: Invalid transport public key
**Given** the transport public key is invalid
**When** share creation runs
**Then** `VetKdKeyShareCreationError::InvalidArgumentEncryptionPublicKey` is returned

---

## REQ-VETKD-002: Encrypted Key Share Verification

Encrypted key shares MUST be verifiable using the signer's registry public key.

### SCENARIO-VETKD-003: Verifying an encrypted key share
**Given** `verify_encrypted_key_share` is called with a signer NodeId, share, and args
**When** verification runs
**Then** the node's basic signature on the share is verified using the registry public key

---

## REQ-VETKD-003: Encrypted Key Share Combination

Encrypted key shares MUST be combinable into a full encrypted key, with fallback for invalid shares.

### SCENARIO-VETKD-004: Combining all valid shares
**Given** `combine_encrypted_key_shares` is called with sufficient valid shares
**When** combination runs
**Then** `EncryptedKey::combine_all` combines all shares
**And** a `VetKdEncryptedKey` is returned

### SCENARIO-VETKD-005: Combining with invalid shares (fallback)
**Given** `combine_all` fails with `InvalidShares`
**When** fallback runs
**Then** `EncryptedKey::combine_valid_shares` filters out invalid shares using individual public keys
**And** remaining valid shares are combined if they still meet the reconstruction threshold

### SCENARIO-VETKD-006: Insufficient shares
**Given** the number of shares is less than the reconstruction threshold
**When** combination runs
**Then** `VetKdKeyShareCombinationError::UnsatisfiedReconstructionThreshold` is returned

---

## REQ-VETKD-004: Encrypted Key Verification

Combined encrypted keys MUST be verifiable for correctness.

### SCENARIO-VETKD-007: Valid encrypted key
**Given** `verify_encrypted_key` is called with a combined key and args
**When** verification runs
**Then** the encrypted key is checked via `is_valid` with master public key, derivation context, input, and transport public key
**And** `Ok(())` is returned if valid

### SCENARIO-VETKD-008: Invalid encrypted key
**Given** `is_valid` returns false
**When** verification runs
**Then** `VetKdKeyVerificationError::VerificationError` is returned

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-VETKD-001 | Key share creation | narrative | rs/crypto/tests/ |
| REQ-VETKD-002 | Key share verification | narrative | rs/crypto/tests/ |
| REQ-VETKD-003 | Key share combination | narrative | rs/crypto/tests/ |
| REQ-VETKD-004 | Encrypted key verification | narrative | rs/crypto/tests/ |
