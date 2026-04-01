# Crypto: DKG Capability Specification

**Source narrative**: `openspec/specs/crypto/dkg.md`
**Crates**: `ic-crypto`, `ic-crypto-internal-threshold-sig-ni-dkg`, `ic-crypto-internal-multi-sig-bls12-381`
**Key files**: `rs/crypto/src/`, `rs/crypto/internal/`

---

## REQ-DKG-001: NI-DKG Dealing Creation

The `NiDkgAlgorithm` trait MUST allow nodes to create NI-DKG dealings with encrypted shares.

### SCENARIO-DKG-001: Creating an NI-DKG dealing
**Given** `create_dealing` is called with an `NiDkgConfig`
**When** dealing creation runs
**Then** the node creates a dealing containing encrypted shares for all receivers
**And** the dealing uses the node's DKG dealing encryption key
**And** the result is an `NiDkgDealing`

---

## REQ-DKG-002: NI-DKG Dealing Verification

The system MUST verify NI-DKG dealings against the DKG config.

### SCENARIO-DKG-002: Verifying an NI-DKG dealing
**Given** `verify_dealing` is called with a config, dealer NodeId, and dealing
**When** verification runs
**Then** the dealing is verified against the DKG config using the CSP
**And** the dealer's identity is validated

---

## REQ-DKG-003: NI-DKG Transcript Creation

The system MUST combine verified dealings into an NI-DKG transcript.

### SCENARIO-DKG-003: Creating an NI-DKG transcript
**Given** `create_transcript` is called with a config and verified dealings
**When** creation runs
**Then** the dealings are combined into a transcript
**And** the transcript size is observed as a metric
**And** the result is an `NiDkgTranscript`

---

## REQ-DKG-004: NI-DKG Transcript Loading

Nodes MUST be able to load NI-DKG transcripts and store their threshold signing key shares.

### SCENARIO-DKG-004: Loading an NI-DKG transcript
**Given** `load_transcript` is called with an `NiDkgTranscript`
**When** loading runs
**Then** the node decrypts its share using its DKG dealing encryption secret key
**And** the decrypted share is stored in the threshold sig data store (public coefficients + node indices)

---

## REQ-DKG-005: NI-DKG Active Key Retention

The system MUST retain only active NI-DKG keys and garbage collect old ones.

### SCENARIO-DKG-005: Retaining only active keys
**Given** `retain_only_active_keys` is called with a set of `NiDkgTranscript`s
**When** retention runs
**Then** the CSP removes keys not associated with any of the given transcripts
**And** old threshold signing keys are garbage collected

### SCENARIO-DKG-006: Invalid transcript set
**Given** the provided transcripts fail validation (e.g., empty set)
**When** retention runs
**Then** `DkgKeyRemovalError::InputValidationError` is returned

---

## REQ-DKG-006: IDkg Protocol — Dealing Creation

The interactive DKG protocol MUST create dealings with polynomial commitments and encrypted shares.

### SCENARIO-DKG-007: Creating an IDkg dealing
**Given** `create_dealing` is called with `IDkgTranscriptParams`
**When** dealing creation runs
**Then** the dealing contains polynomial commitments (Pedersen for Random, Feldman for ReshareOfMasked)
**And** encrypted shares for all receivers using MEGa encryption
**And** zero-knowledge proofs appropriate for the transcript operation type
**And** the dealing is signed with the node's signing key

### SCENARIO-DKG-008: Public verification of IDkg dealing
**Given** `verify_dealing_public` is called with params and a signed dealing
**When** verification runs
**Then** the dealer's signature is valid
**And** commitment length equals the reconstruction threshold
**And** the proof of possession of the ephemeral key is valid

### SCENARIO-DKG-009: Private verification by receiver
**Given** `verify_dealing_private` is called by a receiver
**When** verification runs
**Then** the receiver decrypts its share using its IDkg dealing encryption secret key
**And** the decrypted share is checked against the polynomial commitment

---

## REQ-DKG-007: IDkg Transcript Management

The system MUST create, verify, load, and maintain IDkg transcripts.

### SCENARIO-DKG-010: Creating an IDkg transcript
**Given** `create_transcript` is called with params and batch-signed dealings
**When** creation runs
**Then** the combined commitment is computed from the dealings
**And** each dealing must have sufficient support (≥ `reconstruction_threshold + f` signatures)
**And** each support signature is verified

### SCENARIO-DKG-011: Loading with decryption failure (complaint)
**Given** a receiver cannot decrypt its shares or shares don't match the commitment
**When** loading runs
**Then** the receiver issues an `IDkgComplaint` against the faulty dealing
**And** the complaint includes a Diffie-Hellman tuple and proof of discrete log equivalence

### SCENARIO-DKG-012: Loading transcript with collected openings
**Given** `load_transcript_with_openings` is called with complaints and openings
**When** loading runs
**Then** for each faulty dealing, openings are used to reconstruct the polynomial via Lagrange interpolation
**And** the complainer computes its own shares from the reconstructed polynomial

---

## REQ-DKG-008: IDkg Transcript Operations

The system MUST support Random, ReshareOfMasked, ReshareOfUnmasked, and UnmaskedTimesMasked operations.

### SCENARIO-DKG-013: Random transcript operation
**Given** the operation is `IDkgTranscriptOperation::Random`
**When** dealers create dealings
**Then** random polynomials with Pedersen commitments are used
**And** the resulting transcript contains a masked secret

### SCENARIO-DKG-014: ReshareOfMasked transcript operation
**Given** the operation is `IDkgTranscriptOperation::ReshareOfMasked`
**When** dealing creation runs
**Then** the master public key `G * secret` is revealed via Lagrange interpolation of constant terms
**And** a proof of equal openings between Pedersen and Feldman commitments is included

---

### SCENARIO-DKG-015: IDkg complaint verification
**Given** `verify_complaint` is called with a transcript, complainer NodeId, and complaint
**When** verification runs
**Then** the proof of discrete log equivalence in the complaint is verified
**And** using the revealed DH tuple, the verifier re-decrypts the complainer's shares and confirms the dealing is faulty

### SCENARIO-DKG-016: IDkg transcript opening
**Given** `open_transcript` is called with a transcript, complainer NodeId, and complaint
**When** opening runs
**Then** the opener decrypts its own shares for the faulty dealing
**And** returns an `IDkgOpening` containing the revealed shares

### SCENARIO-DKG-017: IDkg opening verification
**Given** `verify_opening` is called with a transcript, opener NodeId, opening, and complaint
**When** verification runs
**Then** the opening's shares are verified against the dealing's polynomial commitment

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-DKG-001 | NI-DKG dealing creation | linked | rs/crypto/tests/integration_test.rs |
| REQ-DKG-002 | NI-DKG dealing verification | narrative | rs/crypto/tests/ |
| REQ-DKG-003 | NI-DKG transcript creation | narrative | rs/crypto/tests/ |
| REQ-DKG-004 | NI-DKG transcript loading | linked | rs/crypto/tests/integration_test.rs |
| REQ-DKG-005 | Active key retention | narrative | rs/crypto/tests/ |
| REQ-DKG-006 | IDkg dealing creation | narrative | rs/crypto/tests/ |
| REQ-DKG-007 | IDkg transcript management | narrative | rs/crypto/tests/ |
| REQ-DKG-008 | IDkg transcript operations | narrative | rs/crypto/tests/ |
