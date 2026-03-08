# Distributed Key Generation (DKG)

## Requirements

### Requirement: Non-Interactive DKG (NI-DKG) Dealing Creation
The `NiDkgAlgorithm` trait provides non-interactive distributed key generation operations. NI-DKG uses forward-secure encryption (BLS12-381) for dealing encryption.

#### Scenario: Creating an NI-DKG dealing
- **WHEN** `create_dealing` is called with an `NiDkgConfig`
- **THEN** the node creates a dealing containing encrypted shares for all receivers
- **AND** the dealing is produced using the node's DKG dealing encryption key
- **AND** the result is an `NiDkgDealing`

#### Scenario: Dealing creation error
- **WHEN** dealing creation fails (e.g., missing keys, invalid config)
- **THEN** a `DkgCreateDealingError` is returned

### Requirement: NI-DKG Dealing Verification

#### Scenario: Verifying an NI-DKG dealing
- **WHEN** `verify_dealing` is called with a config, dealer NodeId, and dealing
- **THEN** the dealing is verified against the DKG config using the CSP
- **AND** the dealer's identity is validated
- **AND** success or `DkgVerifyDealingError` is returned

### Requirement: NI-DKG Transcript Creation

#### Scenario: Creating an NI-DKG transcript
- **WHEN** `create_transcript` is called with a config and a map of verified dealings
- **THEN** the dealings are combined into a transcript
- **AND** the transcript size is observed as a parameter metric
- **AND** the result is an `NiDkgTranscript`

### Requirement: NI-DKG Transcript Loading

#### Scenario: Loading an NI-DKG transcript
- **WHEN** `load_transcript` is called with an `NiDkgTranscript`
- **THEN** the node decrypts its share from the transcript using its DKG dealing encryption secret key
- **AND** the decrypted share is stored in the threshold sig data store (public coefficients + node indices)
- **AND** BLS12-381 point cache and G2Prepared cache statistics are observed for metrics
- **AND** the result is a `LoadTranscriptResult`

#### Scenario: Transcript loading error
- **WHEN** transcript loading fails (e.g., decryption failure)
- **THEN** a `DkgLoadTranscriptError` is returned

### Requirement: NI-DKG Active Key Retention

#### Scenario: Retaining only active NI-DKG keys
- **WHEN** `retain_only_active_keys` is called with a set of `NiDkgTranscript`s
- **THEN** the transcripts are wrapped in `TranscriptsToRetain` (which validates they form a valid set)
- **AND** the CSP removes keys not associated with any of the given transcripts
- **AND** this allows garbage collection of old threshold signing keys

#### Scenario: Invalid transcript set
- **WHEN** the provided transcripts fail validation (e.g., empty set)
- **THEN** a `DkgKeyRemovalError::InputValidationError` is returned

---

### Requirement: Interactive DKG (IDkg) Protocol
The `IDkgProtocol` trait implements the interactive distributed key generation protocol used for canister threshold signatures. It tolerates less than 1/3 malicious nodes.

### Requirement: IDkg Dealing Creation

#### Scenario: Creating an IDkg dealing
- **WHEN** `create_dealing` is called with `IDkgTranscriptParams`
- **THEN** the node creates a dealing containing:
  - Polynomial commitments (Pedersen for Random, Feldman for ReshareOfMasked)
  - Encrypted shares for all receivers using MEGa encryption
  - An ephemeral key with proof of possession
  - Zero-knowledge proofs as appropriate for the transcript operation type
- **AND** the dealing is signed with the node's signing key
- **AND** the result is a `SignedIDkgDealing`

### Requirement: IDkg Dealing Public Verification

#### Scenario: Verifying a dealing publicly
- **WHEN** `verify_dealing_public` is called with params and a signed dealing
- **THEN** the following checks are performed:
  - Signature of the dealer is valid
  - Commitment length equals the reconstruction threshold
  - Ciphertext count matches the number of receivers
  - Proof of possession of the ephemeral key is valid
  - Commitment type is correct (Pedersen for Random, Feldman for ReshareOfMasked)
  - For ReshareOfMasked: the proof of equal openings is verified

### Requirement: IDkg Dealing Private Verification

#### Scenario: Verifying a dealing privately
- **WHEN** `verify_dealing_private` is called (only callable by a receiver with the IDKG dealing encryption secret key)
- **THEN** the receiver decrypts its share using its IDKG dealing encryption secret key
- **AND** the decrypted share is checked against the polynomial commitment
- **AND** if verification succeeds, the receiver supports the dealing by signing it

### Requirement: IDkg Initial Dealings Verification

#### Scenario: Verifying initial dealings
- **WHEN** `verify_initial_dealings` is called with params and initial dealings
- **THEN** public verification is performed on all dealings within the initial set
- **AND** the dealings form a valid set for the given parameters

### Requirement: IDkg Transcript Creation

#### Scenario: Creating an IDkg transcript
- **WHEN** `create_transcript` is called with params and batch-signed dealings
- **THEN** the combined commitment is computed from the dealings
- **AND** each dealing must have sufficient support (at least `reconstruction_threshold + f` signatures, where f = max malicious nodes)
- **AND** each support signature is verified
- **AND** the transcript includes the combined commitment, the dealings, and the internal transcript data
- **AND** the internal transcript raw size is observed as a metric

### Requirement: IDkg Transcript Verification

#### Scenario: Verifying an IDkg transcript
- **WHEN** `verify_transcript` is called with params and a transcript
- **THEN** the combined commitment is re-derived from the transcript's dealings and compared
- **AND** the number of dealings is sufficient
- **AND** all support signatures are valid

### Requirement: IDkg Transcript Loading

#### Scenario: Loading an IDkg transcript successfully
- **WHEN** `load_transcript` is called with a transcript
- **THEN** the receiver decrypts its shares from each dealing
- **AND** the combined shares are stored in the canister secret key store (keyed by hash of combined commitment)
- **AND** an empty complaint vector is returned

#### Scenario: Loading with decryption failure (complaint)
- **WHEN** a receiver cannot decrypt its shares from a dealing or the shares do not match the commitment
- **THEN** the receiver issues an `IDkgComplaint` against the faulty dealing
- **AND** the complaint reveals the Diffie-Hellman tuple and a proof of discrete log equivalence
- **AND** the complaint is returned in the result vector

#### Scenario: Key-loss errors during load
- **WHEN** transcript loading fails with `PrivateKeyNotFound`, `InvalidArguments`, `MalformedPublicKey`, `SerializationError`, or `PublicKeyNotFound`
- **THEN** a warning is logged
- **AND** the IDkg load transcript error metric is incremented
- **AND** the error is returned

### Requirement: IDkg Complaint Verification

#### Scenario: Verifying a complaint
- **WHEN** `verify_complaint` is called with a transcript, complainer NodeId, and complaint
- **THEN** the proof of discrete log equivalence in the complaint is verified
- **AND** using the revealed DH tuple, the verifier re-decrypts the complainer's shares and confirms the dealing is indeed faulty

### Requirement: IDkg Transcript Opening

#### Scenario: Opening a transcript for a complaint
- **WHEN** `open_transcript` is called with a transcript, complainer NodeId, and complaint
- **THEN** the opener decrypts its own shares for the faulty dealing
- **AND** returns an `IDkgOpening` containing the revealed shares

### Requirement: IDkg Opening Verification

#### Scenario: Verifying an opening
- **WHEN** `verify_opening` is called with a transcript, opener NodeId, opening, and complaint
- **THEN** the opening's shares are verified against the dealing's polynomial commitment

### Requirement: IDkg Transcript Loading with Openings

#### Scenario: Loading transcript with collected openings
- **WHEN** `load_transcript_with_openings` is called with a transcript and a map of complaints to openings
- **THEN** for each faulty dealing, the openings are used to reconstruct the polynomial via Lagrange interpolation
- **AND** the complainer computes its own shares from the reconstructed polynomial
- **AND** the reconstructed shares are combined with shares from other (non-faulty) dealings
- **AND** the combined shares are stored in the canister secret key store

### Requirement: IDkg Active Transcript Retention

#### Scenario: Retaining keys for active transcripts
- **WHEN** `retain_active_transcripts` is called with a set of active IDkg transcripts
- **THEN** the vault removes canister secret key shares not associated with any active transcript
- **AND** old IDKG dealing encryption key pairs are cleaned up
- **AND** metrics are observed for the operation

### Requirement: IDkg Transcript Operations

#### Scenario: Random transcript operation
- **WHEN** the operation is `IDkgTranscriptOperation::Random`
- **THEN** each dealer creates shares using random polynomials with Pedersen commitments
- **AND** the resulting transcript contains a masked secret (both secret and mask shares)
- **AND** a minimum of `reconstruction_threshold` dealings are required

#### Scenario: ReshareOfMasked transcript operation
- **WHEN** the operation is `IDkgTranscriptOperation::ReshareOfMasked`
- **THEN** each dealer (receiver from the masked transcript) shares its secret share using a new polynomial with Feldman commitments
- **AND** a proof of equal openings (between Pedersen commitment in masked transcript and Feldman commitment) is included
- **AND** the resulting transcript reveals the master public key `G * secret` via Lagrange interpolation of the constant terms

#### Scenario: ReshareOfUnmasked transcript operation
- **WHEN** the operation is `IDkgTranscriptOperation::ReshareOfUnmasked`
- **THEN** unmasked shares are reshared to a new set of receivers
- **AND** Feldman commitments are used

#### Scenario: UnmaskedTimesMasked transcript operation
- **WHEN** the operation is `IDkgTranscriptOperation::UnmaskedTimesMasked`
- **THEN** the protocol computes the product of an unmasked and a masked value in a threshold-shared form

### Requirement: MEGa Encryption for IDkg
The MEGa encryption scheme is used for encrypting shares to receivers.

#### Scenario: Share encryption
- **WHEN** a dealer encrypts shares for receiver `r`
- **THEN** an ephemeral key `EK = G * alpha` is generated
- **AND** a Diffie-Hellman tuple `(IDKG_PK_r, EK, IDKG_PK_r * alpha)` is computed
- **AND** hash-to-scalars `(h_0, h_1) := hash(DH_r, AD)` is computed
- **AND** the shares are encrypted as `(h_0 + p(r), h_1 + q(r))`

#### Scenario: Share decryption
- **WHEN** receiver `r` decrypts shares
- **THEN** the receiver computes `EK * idkg_sk_r` to recover the DH tuple
- **AND** computes the hash and its inverse
- **AND** recovers the shares as `(p(r) - h_0, q(r) - h_1)`
