# Artifact Management

This specification covers the artifact pool and P2P artifact management subsystems of the Internet Computer replica. It defines the expected behavior of artifact storage (in-memory and persistent), artifact downloading, consensus-based dissemination, peer discovery, state synchronization, and QUIC transport. The relevant crates are `ic-artifact-pool`, `ic-artifact-downloader`, `ic-p2p-artifact-manager`, `ic-consensus-manager`, `ic-peer-manager`, `ic-state-sync-manager`, and `ic-quic-transport`.

---

## Requirements

### Requirement: Consensus Pool Initialization (ic-artifact-pool)

The consensus pool must initialize correctly from configuration, supporting both in-memory (unvalidated) and persistent (validated) storage sections. When a replica version mismatch is detected, the persistent pool directory must be purged and recreated.

#### Scenario: Create consensus pool with matching replica version
- **WHEN** a consensus pool is created and the persistent pool directory contains a `replica_version` file matching the current replica version
- **THEN** the existing pool data is preserved
- **AND** no files are deleted from the persistent pool directory

#### Scenario: Create consensus pool with mismatched replica version
- **WHEN** a consensus pool is created and the persistent pool directory contains a `replica_version` file with a different version
- **THEN** all contents of the persistent pool directory are deleted
- **AND** a new `replica_version` file is written with the current replica version
- **AND** the pool directory is recreated if it does not exist

#### Scenario: Create consensus pool with no existing version file
- **WHEN** a consensus pool is created and no `replica_version` file exists in the persistent pool directory
- **THEN** the pool directory is created if it does not exist
- **AND** a `replica_version` file is written with the current replica version

#### Scenario: Consensus pool initialization with CatchUpPackage
- **WHEN** a `ConsensusPoolImpl` is created with an `ArtifactPoolConfig`
- **THEN** an in-memory `InMemoryPoolSection` is created for the unvalidated section
- **AND** a persistent pool section is created for the validated section using the configured backend (LMDB or RocksDB on macOS)
- **AND** a `ConsensusCacheImpl` is initialized from the persistent pool contents
- **AND** height-indexed lookups are available for all consensus message types (RandomBeacon, BlockProposal, Notarization, Finalization, RandomTape, CatchUpPackage, and their share variants, plus EquivocationProof)

### Requirement: Consensus Pool Section Operations (ic-artifact-pool)

The consensus pool must support insert, remove, purge-below, and purge-type-below operations on both validated and unvalidated sections. Each section is indexed by height and supports queries across all consensus artifact types.

#### Scenario: Insert artifact into in-memory pool section
- **WHEN** a consensus artifact is inserted into an in-memory pool section
- **THEN** the artifact is stored in the BTreeMap keyed by its cryptographic hash
- **AND** the height index for the corresponding artifact type is updated
- **AND** duplicate inserts (same hash) do not overwrite the existing artifact

#### Scenario: Remove artifact from in-memory pool section by message ID
- **WHEN** a consensus artifact is removed from the pool section using its ConsensusMessageId
- **THEN** the artifact is removed from the BTreeMap
- **AND** the height index entry for that artifact is removed
- **AND** the ConsensusMessageId of the removed artifact is returned

#### Scenario: Purge all artifacts below a given height
- **WHEN** a purge-below operation is executed with a target height
- **THEN** all artifacts of every type strictly below that height are removed
- **AND** the ConsensusMessageIds of all purged artifacts are returned
- **AND** the minimum height of the remaining pool is greater than or equal to the target height

#### Scenario: Purge specific artifact type below a given height
- **WHEN** a purge-type-below operation is executed for NotarizationShare, FinalizationShare, or EquivocationProof
- **THEN** only artifacts of the specified type strictly below the target height are removed
- **AND** artifacts of other types are not affected

#### Scenario: Consensus pool mutation via ChangeAction
- **WHEN** a `ChangeAction` is applied to the consensus pool
- **THEN** `Insert` actions add `ValidatedConsensusArtifact` to the validated section
- **AND** `Remove` actions delete artifacts by `ConsensusMessageId` from either section
- **AND** `PurgeBelow(height)` removes all artifacts strictly below the given height
- **AND** `PurgeTypeBelow(type, height)` removes only artifacts of the specified `PurgeableArtifactType` strictly below the given height
- **AND** `MoveToValidated` moves artifacts from the unvalidated to the validated section
- **AND** `HandleInvalid` removes the artifact and logs a warning
- **AND** each mutation is recorded as a `PoolSectionOp` and applied atomically

### Requirement: Height-Indexed Pool Queries (ic-artifact-pool)

All pool sections must support height-indexed queries with correct iteration semantics, even when heights span large ranges.

#### Scenario: Query artifacts by specific height
- **WHEN** `get_by_height` is called with a specific height
- **THEN** all artifacts of the queried type at that exact height are returned

#### Scenario: Query artifacts by height range
- **WHEN** `get_by_height_range` is called with a HeightRange
- **THEN** all artifacts within the inclusive range [min, max] are returned
- **AND** the query completes in bounded time even when min and max heights are far apart (e.g., 1 and u64::MAX)

#### Scenario: Get only artifact at height
- **WHEN** `get_only_by_height` is called and exactly one artifact exists at that height
- **THEN** that artifact is returned as Ok
- **WHEN** no artifacts exist at that height
- **THEN** `NoneAvailable` error is returned
- **WHEN** multiple artifacts exist at that height
- **THEN** `MultipleValues` error is returned

#### Scenario: Get highest artifact
- **WHEN** `get_highest` is called on a non-empty pool section
- **THEN** the artifact at the maximum height is returned
- **AND** if no artifacts exist, `NoneAvailable` error is returned

#### Scenario: Pool size tracking
- **WHEN** `size()` is called on a pool section
- **THEN** the total number of artifacts in the section is returned

### Requirement: Persistent Pool Storage via LMDB (ic-artifact-pool)

The validated consensus pool section must support persistent storage using LMDB (or RocksDB on macOS). Artifacts are stored using three kinds of LMDB databases: an artifacts database mapping IdKey to serialized bytes, per-type index databases mapping HeightKey to sets of IdKeys, and a meta database for CatchUpPackage initialization.

#### Scenario: LMDB persistent pool backend
- **WHEN** the `PersistentPoolBackend` configuration specifies LMDB
- **THEN** an LMDB environment is opened at the configured `persistent_pool_db_path`
- **AND** three kinds of LMDB databases are used: an "artifacts" database mapping `IdKey` to bincode-encoded bytes, per-type index databases mapping `HeightKey` to sets of `IdKey`s, and a "meta" database for min/max height tracking
- **AND** artifacts are keyed by a combination of type, height (big-endian), and crypto hash for ordered access
- **AND** purge operations can efficiently remove all artifacts below a given height

#### Scenario: RocksDB persistent pool backend (macOS only)
- **WHEN** the `PersistentPoolBackend` configuration specifies RocksDB and the replica is running on macOS
- **THEN** a RocksDB-backed persistent pool is used instead of LMDB
- **AND** the same logical structure of type-indexed and height-indexed access is maintained

#### Scenario: Initialize persistent pool with CatchUpPackage
- **WHEN** the persistent pool is initialized with a CUP protobuf
- **THEN** the CUP is stored as the initial state of the validated pool
- **AND** subsequent reads can retrieve the CUP by height

### Requirement: Certification Pool (ic-artifact-pool)

The certification pool stores Certification and CertificationShare artifacts in unvalidated (in-memory) and validated (persistent) sections. It supports the MutablePool trait with change actions: AddToValidated, MoveToValidated, RemoveFromUnvalidated, RemoveAllBelow, and HandleInvalid.

#### Scenario: Insert certification share into unvalidated pool
- **WHEN** a CertificationShare is inserted as an unvalidated artifact
- **THEN** the share is stored in the unvalidated BTreeMap
- **AND** the unvalidated share index is updated at the share's height

#### Scenario: Insert certification into unvalidated pool
- **WHEN** a Certification (non-share) is inserted as an unvalidated artifact
- **THEN** the certification is stored in the unvalidated BTreeMap
- **AND** the unvalidated cert index is updated at the certification's height

#### Scenario: Move certification from unvalidated to validated
- **WHEN** MoveToValidated is applied for a full Certification (non-share)
- **THEN** the artifact is removed from the unvalidated pool
- **AND** the artifact is inserted into the validated persistent pool
- **AND** an ArtifactTransmit::Deliver is emitted for the certification (with `is_latency_sensitive: false`)

#### Scenario: Move certification share from unvalidated to validated
- **WHEN** MoveToValidated is applied for a CertificationShare
- **THEN** the share is moved to the validated pool
- **AND** no ArtifactTransmit::Deliver is emitted (shares are not re-broadcast)

#### Scenario: Add certification directly to validated
- **WHEN** AddToValidated is applied for a certification message
- **THEN** the artifact is added to the validated pool
- **AND** an ArtifactTransmit::Deliver is emitted with `is_latency_sensitive: true`

#### Scenario: Prevent duplicate certifications at the same height
- **WHEN** AddToValidated is applied for a Certification at a height that already has a certification
- **THEN** the existing certification is preserved without duplication
- **AND** the pool still contains exactly one certification at that height

#### Scenario: Remove all certification artifacts below height
- **WHEN** RemoveAllBelow is applied with a target height
- **THEN** all unvalidated artifacts below that height are removed (both shares and certs)
- **AND** all validated artifacts below that height are purged
- **AND** ArtifactTransmit::Abort is emitted for each purged validated artifact

#### Scenario: Handle invalid certification artifact
- **WHEN** HandleInvalid is applied for a certification message
- **THEN** the artifact is removed from the unvalidated pool
- **AND** the invalidated artifacts counter metric is incremented
- **AND** a warning is logged with the reason

#### Scenario: Broadcast validated certifications and shares
- **WHEN** `get_all_for_broadcast` is called on the validated pool reader
- **THEN** for heights with a full Certification, the Certification is returned
- **AND** for heights without a full Certification, only the share signed by this node is returned
- **AND** one artifact per height is returned

#### Scenario: Certification pool metrics update
- **WHEN** the pool is mutated (non-empty change set)
- **THEN** `update_metrics` is called
- **AND** unvalidated and validated min/max heights and counts are updated for both certifications and shares

### Requirement: DKG Pool (ic-artifact-pool)

The DKG pool stores DKG dealing messages in validated and unvalidated in-memory sections. It supports insert, remove, move-to-validated, purge, and handle-invalid operations.

#### Scenario: Insert and retrieve DKG message
- **WHEN** a DKG message is inserted as unvalidated
- **THEN** it can be retrieved via `get_unvalidated`
- **AND** it is not visible in `get_validated`

#### Scenario: Move DKG message to validated
- **WHEN** MoveToValidated is applied for a DKG message
- **THEN** the message is removed from the unvalidated section
- **AND** the message is added to the validated section
- **AND** an ArtifactTransmit::Deliver is emitted with `is_latency_sensitive: false`

#### Scenario: Add DKG message directly to validated
- **WHEN** AddToValidated is applied for a DKG message
- **THEN** the message is added to the validated section
- **AND** an ArtifactTransmit::Deliver is emitted with `is_latency_sensitive: true`

#### Scenario: Purge DKG messages below height
- **WHEN** Purge is applied with a height
- **THEN** all validated and unvalidated messages with height strictly below the target are removed
- **AND** ArtifactTransmit::Abort is emitted for each purged validated message
- **AND** the current_start_height is updated to the purge height

#### Scenario: Handle invalid DKG message
- **WHEN** HandleInvalid is applied for a DKG message
- **THEN** the message is removed from the unvalidated section
- **AND** the invalidated artifacts counter is incremented
- **AND** a warning is logged

#### Scenario: Remove DKG message from unvalidated
- **WHEN** RemoveFromUnvalidated is applied for a DKG message
- **THEN** the message is removed from the unvalidated section
- **AND** a panic occurs if the message was not found

#### Scenario: Check validated contains
- **WHEN** `validated_contains` is called with a DKG message
- **THEN** it returns true if the message's DkgMessageId exists in the validated section

### Requirement: IDKG Pool (ic-artifact-pool)

The IDKG pool stores threshold signature-related messages (dealings, dealing supports, sig shares, complaints, openings, key shares) in in-memory sections organized by IDkgMessageType. Each type has its own IDkgObjectPool with per-type metrics.

#### Scenario: Insert IDKG message into correct object pool
- **WHEN** an IDKG message (e.g., SignedIDkgDealing) is inserted
- **THEN** it is stored in the object pool corresponding to its IDkgMessageType
- **AND** the insert metric counter is incremented
- **AND** inserting a message with a type not matching the object pool panics (assertion)

#### Scenario: Remove IDKG message
- **WHEN** an IDKG message is removed by its IDkgMessageId
- **THEN** the message is removed from the corresponding object pool
- **AND** the remove metric counter is incremented
- **AND** returns true if the message was found, false otherwise

#### Scenario: Iterate IDKG messages with prefix filtering
- **WHEN** iteration is requested with an IDkgPrefixOf pattern
- **THEN** only messages matching the prefix are returned
- **AND** iteration follows the IterationPattern semantics (by transcript ID or dealing)

#### Scenario: IDKG pool persistence support
- **WHEN** ArtifactPoolConfig specifies a persistent backend
- **THEN** the validated IDKG pool section may use LMDB for persistence
- **AND** the unvalidated section remains in-memory

### Requirement: Ingress Pool (ic-artifact-pool)

The ingress pool stores SignedIngress messages in validated and unvalidated BTreeMap sections, with per-peer counters for rate limiting and byte-size tracking.

#### Scenario: Insert ingress message into unvalidated pool
- **WHEN** a SignedIngress message is inserted into the unvalidated pool
- **THEN** the message is stored keyed by IngressMessageId
- **AND** the byte size metrics are updated via `observe_insert`
- **AND** the per-peer counter is incremented for the originating peer
- **AND** the insert operation duration is recorded

#### Scenario: Remove ingress message
- **WHEN** an ingress message is removed from the pool
- **THEN** the byte size metrics are decremented via `observe_remove`
- **AND** the per-peer counter is decremented
- **AND** the remove operation duration is recorded

#### Scenario: Duplicate ingress message insertion
- **WHEN** an ingress message with the same IngressMessageId is inserted again
- **THEN** the previous artifact is replaced
- **AND** the duplicate metric is incremented via `observe_duplicate`
- **AND** the per-peer counter for the old artifact's peer is decremented

#### Scenario: Ingress pool mutation via ChangeAction
- **WHEN** mutations are applied to the ingress pool
- **THEN** `Insert` actions add the ingress message to the unvalidated section with byte-size tracking
- **AND** `Remove` actions delete messages by `IngressMessageId`
- **AND** `PurgeBelowExpiry` removes messages whose expiry is below the given threshold
- **AND** `MoveToValidated` promotes messages from unvalidated to validated

### Requirement: Canister HTTP Pool (ic-artifact-pool)

The canister HTTP pool stores CanisterHttpResponseShare artifacts in validated and unvalidated sections, with a separate content section for full CanisterHttpResponse objects.

#### Scenario: Insert canister HTTP response share
- **WHEN** a CanisterHttpResponseArtifact is inserted as unvalidated
- **THEN** the share is accessible via `get_unvalidated_artifacts`

#### Scenario: Validate canister HTTP response share
- **WHEN** MoveToValidated is applied for a canister HTTP response share
- **THEN** the share is moved from unvalidated to validated
- **AND** the share is accessible via `get_validated_shares`

#### Scenario: Canister HTTP pool change actions
- **WHEN** a `CanisterHttpChangeAction` is applied
- **THEN** `AddToValidated` moves a share from unvalidated to validated
- **AND** `RemoveValidated` removes a validated share
- **AND** `RemoveUnvalidated` removes an unvalidated artifact
- **AND** `RemoveContent` removes a full response from the content section
- **AND** `HandleInvalid` removes an artifact and increments the `invalidated_artifacts` counter

### Requirement: Consensus Pool Backup (ic-artifact-pool)

The backup mechanism writes essential consensus artifacts to disk for disaster recovery. Share artifacts are not backed up.

#### Scenario: Backup consensus artifacts
- **WHEN** new validated consensus artifacts are added to the pool
- **THEN** finalization, notarization, block proposal, random beacon, random tape, and CUP artifacts are written to the backup directory
- **AND** artifacts are organized into groups of configurable size (BACKUP_GROUP_SIZE)
- **AND** artifacts are serialized to protobuf format before writing

#### Scenario: Skip share artifacts during backup
- **WHEN** a share artifact (RandomBeaconShare, NotarizationShare, FinalizationShare, RandomTapeShare, CatchUpPackageShare, EquivocationProof) is validated
- **THEN** it is not written to the backup directory
- **AND** the `TryFrom<ConsensusMessage>` conversion for `BackupArtifact` returns `Err(())` for these types

### Requirement: Consensus Pool Metrics (ic-artifact-pool)

The consensus pool must expose per-type metrics for both validated and unvalidated sections.

#### Scenario: Update pool metrics after mutation
- **WHEN** the consensus pool is mutated (insert, remove, or purge)
- **THEN** min_height and max_height IntGauge metrics are updated for each artifact type
- **AND** the `consensus_pool_size` IntGauge reflects the current count per type
- **AND** the `artifact_pool_consensus_count_per_height` histogram is updated for heights that have been finalized
- **AND** metrics are labeled by pool type (validated/unvalidated) and artifact type

### Requirement: Pool Common Infrastructure (ic-artifact-pool)

The pool subsystem provides shared instrumented data structures used across all pool types.

#### Scenario: Generic PoolSection insert
- **WHEN** `insert` is called on a `PoolSection<K, V>`
- **THEN** the artifact is inserted into the underlying `BTreeMap`
- **AND** the `observe_insert` metric is recorded with the artifact's byte size and label
- **AND** if a duplicate key exists, the old value is replaced and `observe_duplicate` is recorded

#### Scenario: Generic PoolSection remove
- **WHEN** `remove` is called on a `PoolSection<K, V>` with a key
- **THEN** the artifact is removed from the `BTreeMap` if present
- **AND** the `observe_remove` metric is recorded with the removed artifact's byte size and label

---

## P2P Artifact Manager

### Requirement: Artifact Processor Event Loop (ic-p2p-artifact-manager)

The artifact manager runs a dedicated processor thread per artifact type that batches incoming unvalidated artifact mutations, invokes the change set producer, applies mutations to the pool, and emits transmit signals for P2P dissemination.

#### Scenario: Process new unvalidated artifacts
- **WHEN** new unvalidated artifact mutations arrive via the inbound channel
- **THEN** they are batched up to MAX_P2P_IO_CHANNEL_SIZE
- **AND** inserted into the pool via the write lock
- **AND** the change set producer's `on_state_change` is invoked with the pool read lock
- **AND** resulting ArtifactTransmit signals are sent on the outbound channel

#### Scenario: Process changes with no new artifacts
- **WHEN** no new artifact events arrive within the timer duration (ARTIFACT_MANAGER_TIMER_DURATION_MSEC = 200ms)
- **THEN** the change set producer's `on_state_change` is still invoked with an empty batch
- **AND** any resulting pool mutations and transmit signals are processed

#### Scenario: Immediate re-processing when poll_immediately is true
- **WHEN** the change set producer indicates `poll_immediately` in its result
- **THEN** the next batch read uses a zero timeout
- **AND** processing continues immediately without waiting for the timer

#### Scenario: Emit initial artifacts on startup
- **WHEN** the artifact processor is started with `create_artifact_handler`
- **THEN** all existing validated artifacts from `get_all_for_broadcast` are emitted as ArtifactTransmit::Deliver on the outbound channel before regular processing begins
- **AND** initial artifacts have `is_latency_sensitive: false`

#### Scenario: Graceful shutdown via JoinGuard
- **WHEN** an `ArtifactProcessorJoinGuard` is dropped
- **THEN** the `shutdown` AtomicBool is set to true with SeqCst ordering
- **AND** the processing thread's JoinHandle is joined (awaited for completion)
- **AND** the thread exits its processing loop on the next iteration

#### Scenario: Processing time and interval metrics
- **WHEN** the change set producer is invoked
- **THEN** the `artifact_manager_client_processing_time_seconds` histogram records the duration (buckets from 0 to 50 seconds)
- **AND** the `artifact_manager_client_processing_interval_seconds` histogram records the time since the last invocation
- **AND** histograms are labeled by the client name (artifact type)

#### Scenario: Batch read with channel closure
- **WHEN** `read_batch` is called on a channel that has been closed after all items are consumed
- **THEN** `None` is returned, signaling the processor to exit
- **AND** if items remain in the channel, they are returned as `Some(vec![...])` before the channel signals closure
- **AND** if the channel is open but no items arrive within the timeout, `Some(vec![])` is returned (empty batch, processor continues)

### Requirement: Ingress-Specific Processing (ic-p2p-artifact-manager)

The ingress processor handles SignedIngress messages with dedicated insert and remove logic through the IngressProcessor struct.

#### Scenario: Create ingress handlers
- **WHEN** `create_ingress_handlers` is called with a broadcast channel, time source, ingress pool, and ingress handler
- **THEN** an `IngressProcessor` is created wrapping the ingress pool and handler
- **AND** no initial artifacts are broadcast (ingress starts with an empty initial set)
- **AND** the processing loop is started via `run_artifact_processor`

#### Scenario: Process ingress mutations
- **WHEN** unvalidated ingress artifact mutations arrive
- **THEN** Insert mutations create UnvalidatedArtifact with the current relative time
- **AND** Remove mutations remove the artifact by its IngressMessageId
- **AND** the ingress handler's `on_state_change` is invoked afterward
- **AND** the resulting change set is applied to the ingress pool

---

## Artifact Downloader

### Requirement: Artifact Downloading via RPC (ic-artifact-downloader)

The FetchArtifact assembler downloads artifacts from peers using RPC calls over the QUIC transport. It supports exponential backoff retry and bouncer-based filtering.

#### Scenario: FetchArtifact initialization
- **WHEN** `FetchArtifact::new` is called with a logger, runtime handle, pool, bouncer factory, and metrics registry
- **THEN** an Axum router is created to serve artifact RPC requests at `/{artifact_name}/rpc`
- **AND** a bouncer watch channel is initialized from the current pool state
- **AND** a background task periodically refreshes the bouncer at the factory's `refresh_period`
- **AND** a closure is returned that, given a Transport, produces a configured FetchArtifact instance

#### Scenario: Download artifact from a peer
- **WHEN** an artifact ID is received for assembly and the artifact is not already available
- **THEN** a random peer from the available peers is selected
- **AND** an RPC request is sent to the `/<artifact>/rpc` endpoint with the encoded artifact ID
- **AND** the response is decoded into the artifact type

#### Scenario: Artifact already available from push
- **WHEN** an artifact is received along with the assembly request (via push)
- **AND** the bouncer evaluates the artifact as wanted
- **THEN** the artifact is returned directly as AssembleResult::Done without making an RPC call

#### Scenario: Retry with exponential backoff on failure
- **WHEN** an RPC request to a peer fails or returns an error status
- **THEN** the request is retried with exponential backoff (MIN_ARTIFACT_RPC_TIMEOUT = 5s, MAX_ARTIFACT_RPC_TIMEOUT = 120s)
- **AND** a different random peer may be selected for the retry
- **AND** after each wait, the bouncer is re-evaluated; if Unwanted, AssembleResult::Unwanted is returned

#### Scenario: Bouncer-based download scheduling
- **WHEN** the bouncer function returns a value for an artifact ID
- **THEN** if `BouncerValue::Wanted`, the download proceeds immediately
- **AND** if `BouncerValue::MaybeWantsLater`, the artifact (if pushed) is dropped from memory and the task waits for bouncer updates
- **AND** if `BouncerValue::Unwanted`, `AssembleResult::Unwanted` is returned and the download is abandoned

#### Scenario: Serve artifact via RPC handler
- **WHEN** a peer sends an RPC request for an artifact ID to the `/<artifact>/rpc` endpoint
- **THEN** the validated pool is queried for the artifact on a blocking task
- **AND** if found, the artifact is encoded and returned with 200 OK
- **AND** if not found, a NO_CONTENT (204) status is returned
- **AND** if the ID cannot be decoded, BAD_REQUEST (400) is returned
- **AND** the request body size limit is disabled to support large consensus artifacts

### Requirement: Stripped Artifact Download Protocol (ic-artifact-downloader)

For consensus block proposals, a stripped download protocol reduces bandwidth by omitting content already available locally (ingress messages, iDKG dealings).

#### Scenario: FetchStrippedConsensusArtifact initialization
- **WHEN** `FetchStrippedConsensusArtifact` is created
- **THEN** it wraps a `FetchArtifact` for `MaybeStrippedConsensusMessage`
- **AND** Axum routes are registered for ingress RPC at `/block/ingress/rpc` and iDKG dealing RPC at `/block/idkg_dealing/rpc`

#### Scenario: Stripped block proposal assembly
- **WHEN** a stripped consensus block proposal is received
- **THEN** the block is checked for missing ingress messages and iDKG dealings
- **AND** missing ingress messages are fetched from peers via the `/block/ingress/rpc` endpoint
- **AND** missing iDKG dealings are fetched from peers via the `/block/idkg_dealing/rpc` endpoint
- **AND** the original full ConsensusMessage is reassembled from the stripped message and fetched components

#### Scenario: Disassemble message for stripped transmission
- **WHEN** `disassemble_message` is called on a ConsensusMessage
- **THEN** large payloads (ingress, iDKG dealings) are stripped from the message
- **AND** the resulting MaybeStrippedConsensusMessage is smaller for network transmission

---

## Consensus Manager

### Requirement: Slot-Based Artifact Dissemination (ic-consensus-manager)

The consensus manager uses a slot-based protocol for disseminating artifacts. Each artifact is assigned a slot number and commit ID. Small artifacts (below 1KB) are pushed directly; larger artifacts are advertised by ID.

#### Scenario: Send artifact via push (small artifact)
- **WHEN** a locally produced artifact is smaller than ARTIFACT_PUSH_THRESHOLD_BYTES (1KB)
- **THEN** the full artifact is included in the slot update message sent to all peers
- **AND** a slot number is allocated from the available slot set

#### Scenario: Send artifact via advert (large artifact)
- **WHEN** a locally produced artifact is larger than ARTIFACT_PUSH_THRESHOLD_BYTES
- **THEN** only the artifact ID is included in the slot update message
- **AND** peers must fetch the full artifact via RPC

#### Scenario: Abort artifact transmit
- **WHEN** an ArtifactTransmit::Abort is received for a previously advertised artifact
- **THEN** the slot is freed and returned to the available slot set
- **AND** the cancellation token for the slot's transmit task is triggered

#### Scenario: Receive slot update from peer
- **WHEN** a slot update is received from a peer via the `/<artifact>/update` endpoint
- **THEN** the protobuf-encoded SlotUpdate is decoded
- **AND** for full artifacts (Update::Artifact), the artifact is delivered to the inbound channel
- **AND** for IDs (Update::Id), the assembler's `assemble_message` is invoked to fetch the artifact
- **AND** decoding errors return BAD_REQUEST status

#### Scenario: Handle connection changes for peer
- **WHEN** a peer's connection ID changes (reconnection)
- **THEN** all slot entries from the old connection are invalidated
- **AND** new slot updates from the peer use the new connection ID

#### Scenario: Slot table overflow warning
- **WHEN** the slot table grows beyond SLOT_TABLE_THRESHOLD (30,000 entries)
- **THEN** a warning is logged indicating potential issues

#### Scenario: Sender event loop with backoff
- **WHEN** the sender event loop transmits slot updates to peers
- **THEN** exponential backoff is used for retries (MIN_BACKOFF_INTERVAL = 250ms, MAX_BACKOFF_INTERVAL = 60s, BACKOFF_MULTIPLIER = 2.0)

### Requirement: Consensus Manager Channel Setup (ic-consensus-manager)

The AbortableBroadcastChannelBuilder creates paired channels per artifact type and wires up sender and receiver components.

#### Scenario: Create abortable broadcast channel
- **WHEN** `abortable_broadcast_channel` is called for an artifact type
- **THEN** outbound and inbound mpsc channels of MAX_P2P_IO_CHANNEL_SIZE are created
- **AND** an axum router is configured for the `/<artifact>/update` endpoint (using the lowercase artifact name as URI prefix)
- **AND** a StartConsensusManagerFn closure is stored for later initialization

#### Scenario: Start consensus manager
- **WHEN** the builder's `start` method is called with a transport and topology watcher
- **THEN** ConsensusManagerSender and ConsensusManagerReceiver are started for each artifact type
- **AND** Shutdown handles are returned for graceful termination

#### Scenario: URI prefix derivation
- **WHEN** an artifact type is used for routing
- **THEN** the URI prefix is derived as `Artifact::NAME.to_lowercase()`
- **AND** only alphabetic characters are allowed in the prefix (assertion)

---

## Peer Manager

### Requirement: Subnet Peer Discovery (ic-peer-manager)

The peer manager periodically queries the registry to determine the current subnet topology, combining the consensus registry version with the latest local registry version.

#### Scenario: Determine subnet topology from registry
- **WHEN** the peer manager checks the registry
- **THEN** it iterates from min(consensus_registry_version, latest_local_registry_version) to latest_local_registry_version
- **AND** all nodes found across those registry versions are included in the topology
- **AND** later registry versions overwrite earlier entries for the same node (preferring higher version data)

#### Scenario: Publish topology updates via watch channel
- **WHEN** the computed subnet topology differs from the previously published topology
- **THEN** the new topology is sent on the watch channel via `send_if_modified`
- **AND** subscribers (transport, consensus manager) receive the update
- **AND** if the topology is unchanged, no notification is sent

#### Scenario: Topology update interval
- **WHEN** the peer manager is running
- **THEN** it checks the registry every TOPOLOGY_UPDATE_INTERVAL (3 seconds)

#### Scenario: Handle missing or invalid registry data
- **WHEN** the registry returns None or an error for node records at a version
- **THEN** a warning is logged
- **AND** the topology_watcher_errors metric is incremented with the appropriate label (empty_list_of_node_records or error_getting_node_records)
- **AND** the peer manager continues processing other registry versions

#### Scenario: Handle IP address parsing failure
- **WHEN** a node record contains an unparseable IP address
- **THEN** a warning is logged with the peer ID and registry version
- **AND** the topology_watcher_errors metric is incremented with label error_parsing_ip_address
- **AND** the node is excluded from the topology

#### Scenario: Handle missing HTTP endpoint
- **WHEN** a node record's http field is None
- **THEN** a warning is logged
- **AND** the topology_watcher_errors metric is incremented with label http_field_missing
- **AND** the node is excluded from the topology

#### Scenario: Ignore registry versions older than consensus
- **WHEN** the registry has versions older than the consensus registry version
- **THEN** those older versions are not consulted for topology
- **AND** only versions from min(consensus_version, latest_local_version) onward are used

#### Scenario: Handle consensus version newer than local registry
- **WHEN** the consensus registry version is newer than the latest local registry version
- **THEN** the earliest_registry_version falls back to the latest local version
- **AND** the topology reflects only the latest local view of the subnet

#### Scenario: Peer manager metrics
- **WHEN** the peer manager updates the topology
- **THEN** `topology_updates` counter is incremented
- **AND** `earliest_registry_version` and `latest_registry_version` gauges are set
- **AND** `topology_update_duration` and `topology_watcher_update_duration` timers record the durations

---

## State Sync Manager

### Requirement: State Sync Over P2P (ic-state-sync-manager)

The state sync manager coordinates state synchronization between replicas, broadcasting available state adverts and downloading state from peers using a chunk-based protocol.

#### Scenario: Broadcast state adverts periodically
- **WHEN** the state sync manager is running and states are available
- **THEN** state adverts are broadcast to all connected peers every ADVERT_BROADCAST_INTERVAL (5 seconds)
- **AND** each broadcast has a timeout of ADVERT_BROADCAST_TIMEOUT (3 seconds)
- **AND** only one active advertise task runs at a time

#### Scenario: Start state sync on advert receipt
- **WHEN** a state advert is received from a peer and no state sync is ongoing
- **THEN** `maybe_start_state_sync` is called on the state sync client
- **AND** if the client returns a Chunkable object, an ongoing state sync is started
- **AND** the peer that sent the advert is added to the ongoing sync
- **AND** the `state_syncs_total` metric is incremented

#### Scenario: Single active state sync guarantee
- **WHEN** a state sync is already in progress
- **THEN** no additional state syncs are started
- **AND** adverts for different states are ignored
- **AND** adverts for the same state add the peer to the existing sync via try_send (non-blocking)

#### Scenario: Reject peer advertising different state
- **WHEN** a peer advertises a state different from the currently syncing state
- **THEN** the peer is not added to the ongoing state sync
- **AND** the advert is silently dropped

#### Scenario: Clean up completed state sync
- **WHEN** the ongoing state sync's shutdown is completed
- **THEN** the ongoing_state_sync is set to None
- **AND** a log message indicates cleanup
- **AND** subsequent adverts may trigger a new state sync

#### Scenario: Cancel state sync if requested by client
- **WHEN** `cancel_if_running` returns true for the current state sync
- **THEN** the ongoing state sync is cancelled via the shutdown handle

#### Scenario: Serve chunks to peers
- **WHEN** a peer sends a chunk request to the `/chunk` route
- **THEN** the requested chunk is looked up in the local state
- **AND** if found, the chunk data is returned with 200 OK
- **AND** if not found, NOT_FOUND is returned

#### Scenario: Handle adverts via the /advert route
- **WHEN** a peer sends a state advert to the `/advert` route
- **THEN** the advert is deserialized and forwarded to the advert receiver channel
- **AND** the `adverts_received_total` metric is incremented

#### Scenario: State sync metrics
- **WHEN** state adverts are broadcast
- **THEN** `lowest_state_broadcasted` and `highest_state_broadcasted` gauges are set based on available states

#### Scenario: Graceful shutdown
- **WHEN** the cancellation token is triggered
- **THEN** the main event loop exits
- **AND** any outstanding advertise tasks are awaited
- **AND** if an ongoing state sync exists, its shutdown is awaited

---

## QUIC Transport

### Requirement: QUIC Transport Setup and Connectivity (ic-quic-transport)

The QUIC transport provides reliable, multiplexed communication between subnet nodes using the QUIC protocol with TLS mutual authentication.

#### Scenario: Start QUIC transport
- **WHEN** `QuicTransport::start` is called with TLS config, registry client, topology watcher, UDP socket, and axum Router
- **THEN** a connection manager is started that maintains connections to all peers in the topology
- **AND** incoming requests are routed to handlers based on the URI specified in the request

#### Scenario: Maintain connections to topology peers
- **WHEN** the topology watcher emits a new SubnetTopology
- **THEN** the connection manager opens connections to new peers
- **AND** closes connections to peers no longer in the topology
- **AND** each connection uses TLS with mutual authentication via the TlsConfig

#### Scenario: RPC to a connected peer
- **WHEN** `rpc` is called with a peer ID and a request
- **THEN** the connection handle for that peer is looked up from the conn_handles map
- **AND** the request is sent on a new QUIC substream to the peer
- **AND** the response is received on the same substream
- **AND** each RPC is fully decoupled from other concurrent RPCs

#### Scenario: RPC to a disconnected peer
- **WHEN** `rpc` is called for a peer that is not currently connected
- **THEN** a P2PError is returned with the message "Currently not connected to this peer"

#### Scenario: RPC error logging
- **WHEN** an RPC request fails
- **THEN** the error is logged at most once every 5 seconds per peer

#### Scenario: List connected peers
- **WHEN** `peers()` is called
- **THEN** a list of (NodeId, ConnId) pairs for all currently connected peers is returned

#### Scenario: Graceful transport shutdown
- **WHEN** `shutdown()` is called on the QuicTransport
- **THEN** the cancellation token is triggered
- **AND** the task tracker waits for all tasks to complete
- **AND** the connection manager join handle is awaited

### Requirement: QUIC Transport Stream Management (ic-quic-transport)

The transport manages QUIC streams with proper cleanup semantics.

#### Scenario: Stream cancellation on drop
- **WHEN** a ResetStreamOnDrop guard is dropped
- **THEN** a QUIC STREAM_CANCELLED reset frame is sent on the stream (error code 0x80000006)
- **AND** the ongoing_streams gauge metric is decremented

#### Scenario: Stream creation tracking
- **WHEN** a new ResetStreamOnDrop is created
- **THEN** the ongoing_streams gauge metric is incremented

### Requirement: QUIC Transport Message Size (ic-quic-transport)

The transport enforces a maximum message size to prevent out-of-memory conditions.

#### Scenario: Enforce maximum message size
- **WHEN** a message is sent or received
- **THEN** it must not exceed MAX_MESSAGE_SIZE_BYTES (128 MB)
- **AND** this limit is intentionally large to accommodate summary blocks for large subnets (e.g., 40-node subnets with blocks > 5MB)

### Requirement: QUIC Transport Error Handling (ic-quic-transport)

The P2PError type wraps various QUIC and protocol errors without capturing expensive backtraces.

#### Scenario: Handle QUIC connection errors
- **WHEN** a connection error occurs (ConnectError, ConnectionError, WriteError, ReadToEndError, etc.)
- **THEN** it is wrapped in a P2PError via automatic From conversions
- **AND** the original error source is preserved for debugging

#### Scenario: Handle protocol decode errors
- **WHEN** a protobuf decode error or HTTP error occurs
- **THEN** it is wrapped in a P2PError
- **AND** the error message is accessible via Display

#### Scenario: Handle generic string errors
- **WHEN** a string error message is converted to P2PError
- **THEN** it is wrapped in a GenericError struct that implements the Error trait

### Requirement: Subnet Topology Management (ic-quic-transport)

The SubnetTopology struct holds the socket addresses of all peers in a subnet along with registry version metadata.

#### Scenario: Query subnet membership
- **WHEN** `is_member` is called with a NodeId
- **THEN** it returns true if the node is in the topology's subnet_nodes map

#### Scenario: Get peer address
- **WHEN** `get_addr` is called with a NodeId
- **THEN** the SocketAddr for that node is returned if present, or None otherwise

#### Scenario: Track registry version range
- **WHEN** a SubnetTopology is constructed
- **THEN** `earliest_registry_version` returns the minimum registry version considered
- **AND** `latest_registry_version` returns the maximum registry version considered

#### Scenario: Get all subnet nodes
- **WHEN** `get_subnet_nodes` is called
- **THEN** a BTreeSet of all NodeIds in the topology is returned

#### Scenario: Default topology is empty
- **WHEN** a SubnetTopology is created via Default
- **THEN** the subnet_nodes map is empty
- **AND** earliest and latest registry versions are the default RegistryVersion

### Requirement: Message Priority (ic-quic-transport)

The transport supports message prioritization for QUIC streams.

#### Scenario: High priority messages
- **WHEN** a message is sent with MessagePriority::High
- **THEN** the priority is converted to integer value 1

#### Scenario: Low priority messages (default)
- **WHEN** a message is sent with the default MessagePriority
- **THEN** the priority is MessagePriority::Low, converted to integer value 0

### Requirement: Shutdown Primitive (ic-quic-transport)

The Shutdown struct provides controlled cancellation of async tasks with completion tracking.

#### Scenario: Spawn task with cancellation support
- **WHEN** `Shutdown::spawn_on_with_cancellation` is called
- **THEN** a TaskTracker is created and closed (preventing new tasks from being spawned)
- **AND** the provided future is spawned with access to a CancellationToken
- **AND** a Shutdown handle is returned

#### Scenario: Shutdown completion check
- **WHEN** `completed()` is called on a Shutdown handle
- **THEN** it returns true only when the task tracker is both closed and empty
- **AND** this indicates all spawned tasks have finished

#### Scenario: Cancel without awaiting
- **WHEN** `cancel()` is called on a Shutdown handle
- **THEN** the cancellation token is triggered
- **AND** the caller does not wait for task completion
