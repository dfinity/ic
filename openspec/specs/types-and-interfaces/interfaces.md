# Interfaces

**Crates**: `ic-interfaces-adapter-client`, `ic-interfaces-certified-stream-store`, `ic-interfaces-state-manager`

## Requirements

### Requirement: PayloadBuilder Consensus Block Payload Construction
PayloadBuilder is the primary interface for creating and validating the payload included in consensus blocks. It combines ingress, XNet, self-validating, canister HTTP, query stats, and VetKd payloads.

#### Scenario: Payload creation from past payloads
- **WHEN** get_payload(height, past_payloads, context, subnet_records) is called
- **THEN** it produces a BatchPayload valid given the past_payloads and ValidationContext
- **AND** past_payloads contains payloads from all blocks above certified_height in descending order

#### Scenario: Payload validation
- **WHEN** validate_payload(height, proposal_context, payload, past_payloads) is called
- **THEN** it returns Ok(()) if the payload is valid
- **AND** returns PayloadValidationError if invalid or validation fails
- **AND** InvalidPayloadReason for deterministically invalid payloads
- **AND** PayloadValidationFailure for transient validation failures

#### Scenario: Payload size enforcement
- **WHEN** a payload exceeds the maximum block payload size
- **THEN** PayloadTooBig error is returned with expected and received sizes

### Requirement: MessageRouting Deterministic Batch Processing
MessageRouting delivers finalized batches for deterministic state machine execution.

#### Scenario: Batch delivery
- **WHEN** deliver_batch(batch) is called
- **THEN** the batch is enqueued for asynchronous processing
- **AND** the function returns immediately without waiting for execution

#### Scenario: Duplicate batch delivery
- **WHEN** deliver_batch is called with a batch that has already been delivered
- **THEN** MessageRoutingError::Ignored is returned with expected_height and actual_height

#### Scenario: Queue full condition
- **WHEN** the batch processing queue is full
- **THEN** MessageRoutingError::QueueIsFull is returned

#### Scenario: Expected batch height
- **WHEN** expected_batch_height() is called
- **THEN** it returns the height of the next batch to be processed

### Requirement: XNetPayloadBuilder Cross-Subnet Stream Selection
XNetPayloadBuilder selects certified stream slices from other subnets for inclusion in blocks.

#### Scenario: XNet payload construction with size limit
- **WHEN** get_xnet_payload(context, past_payloads, byte_limit) is called
- **THEN** the returned payload does not exceed byte_limit
- **AND** the estimated byte size is returned alongside the payload

#### Scenario: XNet payload validation
- **WHEN** validate_xnet_payload(payload, context, past_payloads) is called
- **THEN** Ok(size) is returned for valid payloads
- **AND** InvalidSlice for permanently invalid payloads
- **AND** StateNotCommittedYet or StateRemoved for transient failures

### Requirement: IngressSelector Ingress Message Selection
IngressSelector builds and validates ingress payloads for consensus blocks, enforcing deduplication and size limits.

#### Scenario: Ingress payload size invariant
- **WHEN** get_ingress_payload(past_ingress, context, byte_limit) is called
- **THEN** the returned payload satisfies count_bytes() <= byte_limit

#### Scenario: Ingress deduplication
- **WHEN** past_ingress is provided
- **THEN** messages already present in past blocks are excluded from the new payload

#### Scenario: Ingress validation reasons
- **WHEN** validate_ingress_payload detects issues
- **THEN** MismatchedMessageId indicates ID doesn't match content
- **AND** IngressExpired indicates the message has expired
- **AND** IngressMessageTooBig indicates message exceeds size limit
- **AND** DuplicatedIngressMessage indicates the message appears twice
- **AND** IngressPayloadTooManyMessages indicates count limit exceeded

#### Scenario: Finalized message purging
- **WHEN** request_purge_finalized_messages(message_ids) is called
- **THEN** the specified messages are eventually removed from the ingress pool

### Requirement: IngressPool Two-Section Artifact Storage
IngressPool stores ingress artifacts in validated and unvalidated sections, supporting lookup by IngressMessageId and range queries by expiry time.

#### Scenario: Pool section lookup
- **WHEN** get(message_id) is called on a PoolSection
- **THEN** it returns Some(&artifact) if present, None otherwise

#### Scenario: Expiry range query
- **WHEN** get_all_by_expiry_range(range) is called
- **THEN** it returns an iterator over all artifacts with expiry times in the given range

#### Scenario: Per-node rate limiting
- **WHEN** exceeds_limit(originator_id) is called
- **THEN** it returns true if the node has too many messages in the pool

#### Scenario: Pool-wide throttling
- **WHEN** IngressPoolThrottler::exceeds_threshold() is called
- **THEN** it returns true if the total number of entries exceeds the configured threshold

### Requirement: ConsensusPool Validated/Unvalidated Artifact Management
ConsensusPool manages consensus artifacts across validated and unvalidated sections with typed change actions.

#### Scenario: Change action types
- **WHEN** AddToValidated is applied
- **THEN** the artifact is added to the validated section with a timestamp
- **WHEN** MoveToValidated is applied
- **THEN** the artifact moves from unvalidated to validated section
- **WHEN** RemoveFromValidated is applied
- **THEN** the artifact is removed from the validated section
- **WHEN** PurgeValidatedBelow(height) is applied
- **THEN** all artifacts strictly below the given height are removed
- **WHEN** HandleInvalid is applied
- **THEN** the invalid artifact is removed from unvalidated with a reason string

#### Scenario: Deduplication of change actions
- **WHEN** dedup_push(action) is called on a Mutations
- **THEN** the action is only added if no content-equal action already exists
- **AND** AddToValidated and MoveToValidated are cross-compared for deduplication

#### Scenario: HEIGHT_CONSIDERED_BEHIND threshold
- **WHEN** a replica's height falls behind by more than HEIGHT_CONSIDERED_BEHIND (20)
- **THEN** it is considered to be behind the network

### Requirement: CertificationPool State Certification Management
CertificationPool stores certification artifacts (full certifications and shares) organized by height.

#### Scenario: Certification lookup
- **WHEN** certification_at_height(height) is called
- **THEN** it returns Some(Certification) if a full certification exists at that height

#### Scenario: Shares iteration
- **WHEN** shares_at_height(height) is called
- **THEN** it returns an iterator over all CertificationShares at that height

#### Scenario: Certification change actions
- **WHEN** AddToValidated is applied
- **THEN** the certification message is added to the validated pool
- **WHEN** RemoveAllBelow(height) is applied
- **THEN** all artifacts below the given height are removed from both sections

### Requirement: Verifier State Hash Authentication
Verifier authenticates state hash certifications from other subnets, used by XNet and StateSync.

#### Scenario: Certification validation
- **WHEN** validate(subnet_id, certification, registry_version) is called
- **THEN** Ok(()) is returned if the certification has a valid signature
- **AND** InvalidCertificationReason::CryptoError if the signature is invalid
- **AND** UnexpectedCertificationHash if the hash doesn't match

### Requirement: DkgPool DKG Message Exchange
DkgPool stores DKG dealing messages for the current DKG interval.

#### Scenario: DKG pool height invariant
- **WHEN** messages are stored in the DkgPool
- **THEN** all messages MUST correspond to a DKG Id with start height equal to get_current_start_height()

#### Scenario: DKG change actions
- **WHEN** AddToValidated, MoveToValidated, RemoveFromUnvalidated, HandleInvalid, or Purge actions are applied
- **THEN** the pool state is updated accordingly

### Requirement: IDkgPool IDKG Artifact Management
IDkgPool manages IDKG artifacts (dealings, dealing supports, signature shares, complaints, openings) across validated and unvalidated sections.

#### Scenario: IDKG pool section operations
- **WHEN** IDkgPoolSection methods are called
- **THEN** signed_dealings() returns all signed dealing artifacts
- **AND** dealing_support() returns all dealing support artifacts
- **AND** ecdsa_signature_shares() returns ECDSA signature shares
- **AND** schnorr_signature_shares() returns Schnorr signature shares
- **AND** vetkd_key_shares() returns VetKd key shares
- **AND** complaints() returns complaint artifacts
- **AND** openings() returns opening artifacts

#### Scenario: IDKG prefix-based filtering
- **WHEN** *_by_prefix methods are called with an IDkgPrefixOf
- **THEN** only artifacts matching the prefix are returned

#### Scenario: IDKG transcript management
- **WHEN** AddTranscript action is applied
- **THEN** the transcript is stored in the transcripts map
- **WHEN** RemoveTranscript action is applied
- **THEN** the transcript is removed from the map

### Requirement: TimeSource Monotonic Time Provider
TimeSource provides both relative time (since epoch) and monotonic instant measurements.

#### Scenario: SysTimeSource monotonicity
- **WHEN** get_relative_time() is called multiple times
- **THEN** each returned Time is >= the previous one
- **AND** this is enforced using AtomicU64::fetch_max

#### Scenario: Origin instant
- **WHEN** get_origin_instant() is called
- **THEN** it returns the Instant captured at construction time (close to replica start)

### Requirement: ValidationError Two-Phase Error Model
ValidationError<Reason, Failure> distinguishes between permanently invalid artifacts (InvalidArtifact) and transient validation failures (ValidationFailed).

#### Scenario: Error classification from ErrorReproducibility
- **WHEN** an error implementing ErrorReproducibility is converted to ValidationError
- **THEN** reproducible errors become InvalidArtifact (permanent)
- **AND** non-reproducible errors become ValidationFailed (transient, retriable)

#### Scenario: Error type mapping
- **WHEN** map(f, g) is called on a ValidationError
- **THEN** InvalidArtifact(p) maps to InvalidArtifact(f(p))
- **AND** ValidationFailed(t) maps to ValidationFailed(g(t))

### Requirement: Crypto Composite Interface
The Crypto trait is a supertrait combining KeyManager, BasicSigner, BasicSigVerifier, MultiSigner, MultiSigVerifier, ThresholdSigner, ThresholdSigVerifier, NiDkgAlgorithm, IDkgProtocol, and threshold ECDSA/Schnorr signer/verifier traits.

#### Scenario: Crypto signing coverage
- **WHEN** the Crypto trait is implemented
- **THEN** it supports signing/verification for BlockMetadata, MessageId, DealingContent, CertificationContent, FinalizationContent, NotarizationContent, SignedIDkgDealing, IDkgDealing, IDkgComplaintContent, IDkgOpeningContent, RandomBeaconContent, RandomTapeContent, CatchUpContent, CanisterHttpResponseMetadata, and WebAuthnEnvelope

### Requirement: P2P Consensus Interface
The P2P consensus interface defines how consensus artifacts are replicated across the network.

#### Scenario: PoolMutationsProducer state change
- **WHEN** on_state_change(pool) is called
- **THEN** it inspects the read-only pool and returns Mutations to be applied
- **AND** the pool is NOT mutated during inspection (read-only reference)

#### Scenario: MutablePool artifact lifecycle
- **WHEN** insert(unvalidated_artifact) is called
- **THEN** the artifact is added to the unvalidated section
- **WHEN** apply(mutations) is called
- **THEN** the mutations are applied and ArtifactTransmits are returned for P2P replication

#### Scenario: ArtifactTransmit delivery modes
- **WHEN** is_latency_sensitive is true
- **THEN** the artifact is pushed directly to all peers
- **WHEN** is_latency_sensitive is false
- **THEN** only the artifact ID is pushed and peers fetch on demand

#### Scenario: Bouncer access control
- **WHEN** a Bouncer function evaluates an artifact ID
- **THEN** it returns Wants (deliver to client), MaybeWantsLater (buffer), or Unwanted (drop)
- **AND** the bouncer is idempotent and non-blocking

#### Scenario: ValidatedPoolReader artifact retrieval
- **WHEN** get(id) is called on ValidatedPoolReader
- **THEN** Some(artifact) is returned if it exists in the validated pool
- **AND** None otherwise

### Requirement: BatchPayloadBuilder Opaque Payload Construction
BatchPayloadBuilder handles variable-size payloads that are opaque to consensus and only meaningful to upper layers.

#### Scenario: Payload building with size limit
- **WHEN** build_payload(height, max_size, past_payloads, context) is called
- **THEN** the returned serialized payload does not exceed max_size

#### Scenario: Payload validation guarantees
- **WHEN** validate_payload returns Ok(())
- **THEN** the corresponding into_messages call MUST be infallible for the same payload

#### Scenario: Past payloads ordering requirement
- **WHEN** past_payloads are provided to build_payload or validate_payload
- **THEN** they MUST be in descending height order

### Requirement: IngressInductionError Message Routing Rejection
IngressInductionError enumerates reasons why Message Routing rejects an ingress message during induction.

#### Scenario: Error to ErrorCode mapping
- **WHEN** CanisterNotFound is returned
- **THEN** it maps to ErrorCode::CanisterNotFound
- **WHEN** CanisterStopped is returned
- **THEN** it maps to ErrorCode::CanisterStopped
- **WHEN** CanisterStopping is returned
- **THEN** it maps to ErrorCode::CanisterStopping
- **WHEN** CanisterOutOfCycles is returned
- **THEN** it maps to ErrorCode::CanisterOutOfCycles
- **WHEN** IngressHistoryFull is returned
- **THEN** it maps to ErrorCode::IngressHistoryFull with a capacity value

### Requirement: StateManagerError State Access Errors
StateManagerError indicates whether a requested state has been removed or not yet committed.

#### Scenario: State removed
- **WHEN** the state at a given height has been garbage collected
- **THEN** StateRemoved(height) is returned

#### Scenario: State not committed
- **WHEN** the state at a given height hasn't been committed yet
- **THEN** StateNotCommittedYet(height) is returned
