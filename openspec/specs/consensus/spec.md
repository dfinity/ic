# Consensus Subsystem Specification

**Crates**: `ic-consensus-dkg`, `ic-consensus-utils`

This document provides comprehensive specifications for the Internet Computer consensus subsystem. The consensus protocol establishes distributed agreement on blocks forming a blockchain, using subcomponents for block making, notarization, finalization, random beacon/tape generation, catch-up packages, share aggregation, validation, payload building, artifact priority, pool purging, and batch delivery.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Subcomponent Execution Order](#subcomponent-execution-order)
- [Block Making](#block-making)
- [Notarization](#notarization)
- [Finalization](#finalization)
- [Random Beacon](#random-beacon)
- [Random Tape](#random-tape)
- [Catch-Up Packages](#catch-up-packages)
- [Share Aggregation](#share-aggregation)
- [Validation](#validation)
- [Payload Building](#payload-building)
- [Pool Purging](#pool-purging)
- [Artifact Priority (Bouncer)](#artifact-priority-bouncer)
- [Batch Delivery](#batch-delivery)
- [Consensus Status and Halting](#consensus-status-and-halting)
- [Pool Bounds](#pool-bounds)
- [Membership](#membership)

---

## Architecture Overview

The consensus implementation (`ConsensusImpl`) coordinates nine subcomponents, each responsible for a distinct aspect of the protocol. They share access to the consensus pool, cryptographic services, membership information, and state management. The subcomponents are invoked via a round-robin scheduler that returns the first non-empty mutation set.

### Constants

| Constant | Value | Description |
|---|---|---|
| `ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP` | 70 | Max height gap between notarized and certified height |
| `ACCEPTABLE_NOTARIZATION_CUP_GAP` | 130 | Max height gap between notarized height and next pending CUP |
| `MAX_CONSENSUS_THREADS` | 16 | Max threads for parallel payload creation/validation |
| `MINIMUM_CHAIN_LENGTH` | 50 | Min chain length retained below CUP height for peer catch-up |

---

## Requirements

### Requirement: Subcomponent Execution Order
Consensus subcomponents must be invoked in a specific order to ensure correctness. Finalization must run first to prevent indefinite block production without finalization. The purger runs after aggregation and validation to clean up promptly when heights advance.

#### Scenario: Round-robin invocation returns first non-empty result
- **WHEN** `on_state_change` is called on the consensus pool
- **THEN** each subcomponent is invoked in round-robin order: Finalizer, CatchUpPackageMaker, Aggregator, Purger, Notary, RandomBeaconMaker, RandomTapeMaker, BlockMaker, Validator, Purger
- **AND** the first subcomponent that returns a non-empty `Mutations` causes immediate return
- **AND** the next invocation starts from the subcomponent after the last one that produced output

#### Scenario: DKG key manager runs before subcomponents
- **WHEN** `on_state_change` is called
- **THEN** the DKG key manager's `on_state_change` is invoked first to load new transcripts and remove outdated keys
- **AND** only after that do the consensus subcomponents execute

#### Scenario: Subnet halt by registry record
- **WHEN** the subnet record in the latest registry version has `is_halted` set to true
- **THEN** consensus returns an empty `Mutations` (no progress)
- **AND** no subcomponents are invoked

#### Scenario: Protocol version check
- **WHEN** an artifact's replica version does not match the expected default protocol version
- **THEN** the artifact is rejected with a `ReplicaVersionMismatch` error

#### Scenario: DKG availability check
- **WHEN** DKG transcripts are checked for availability
- **THEN** the node verifies it is listed as a receiver in every current transcript type
- **AND** if the node is not listed in all transcript committees, DKGs are considered unavailable

---

## Block Making

Block making is the process by which elected nodes propose new blocks to extend the blockchain.

### Requirement: Block Maker Election
Each round, a subset of nodes (f+1, where f is the fault tolerance) is elected as block makers, with each assigned a rank derived from a deterministic pseudo-random shuffle seeded by the previous round's random beacon.

#### Scenario: Node is elected as block maker
- **WHEN** a new round begins (notarized height advances)
- **AND** this node's rank from `get_block_maker_rank` is `Some(rank)` (i.e., within the top f+1 nodes in the shuffled ordering)
- **THEN** the node is eligible to propose a block at the next height

#### Scenario: Node is not elected as block maker
- **WHEN** a new round begins
- **AND** this node's position in the shuffled ordering exceeds f (fault tolerance)
- **THEN** `get_block_maker_rank` returns `None`
- **AND** the node does not propose a block

### Requirement: Block Proposal Timing
Block makers must wait a rank-dependent delay before proposing, ensuring lower-ranked (higher priority) block makers have time to propose first.

#### Scenario: Block maker delay calculation
- **WHEN** a block maker has rank `r`
- **THEN** the base delay is `unit_delay * r`
- **AND** a dynamic delay is added if rank > 0 and more than 10 non-rank-0 blocks have been finalized in the last 30 heights

#### Scenario: Time to make block using relative clock
- **WHEN** the relative time since round start exceeds the block maker delay
- **THEN** it is time to propose a block

#### Scenario: Fallback to monotonic clock
- **WHEN** the relative clock appears stalled (not enough time elapsed)
- **AND** the monotonic clock since round start exceeds the block maker delay
- **THEN** it is time to propose a block (safeguard against stalled relative clock)

### Requirement: Block Proposal Uniqueness
A node must not propose more than one block per height.

#### Scenario: Duplicate proposal prevention
- **WHEN** the validated pool already contains a block proposal from this node at the target height
- **THEN** no new block proposal is created

### Requirement: Better Block Suppression
A node should not propose a block if a lower-ranked, non-disqualified proposal already exists.

#### Scenario: Better block already available
- **WHEN** the validated pool contains a non-disqualified block proposal with rank lower than this node's rank
- **THEN** this node does not propose a block

### Requirement: Validation Context Monotonicity
Block proposals must have a strictly increasing validation context compared to the parent block.

#### Scenario: Context is behind parent
- **WHEN** the locally available validation context (certified height, registry version, time) does not strictly exceed the parent's context
- **THEN** no block is proposed
- **AND** a warning is logged

#### Scenario: Stable registry version selection
- **WHEN** constructing a validation context for a new block
- **THEN** the registry version used is the latest version that has been available for at least `POLLING_PERIOD + registry_poll_delay_duration_ms`
- **AND** this ensures the version is available on most replicas

#### Scenario: Block time selection
- **WHEN** computing the block timestamp
- **THEN** the time is set to `max(current_relative_time, parent_time + initial_notary_delay + 1ns)`
- **AND** this ensures strict monotonicity of block timestamps

### Requirement: Block Payload Construction
Blocks contain DKG payloads (summary or data) and optionally batch payloads.

#### Scenario: Summary block at DKG interval boundary
- **WHEN** the block height corresponds to a DKG interval boundary
- **THEN** a summary payload is created containing a DKG summary and optionally an IDKG summary
- **AND** no batch payload is included

#### Scenario: Data block during normal operation
- **WHEN** the consensus status is `Running`
- **THEN** a data payload is created with a batch payload (ingress, xnet, self-validating, canister HTTP, query stats, vetKD), DKG data, and optionally IDKG data

#### Scenario: Empty block during halting
- **WHEN** the consensus status is `Halting`
- **THEN** a data payload is created with an empty batch payload and empty DKG dealings
- **AND** no IDKG data is included

#### Scenario: No block during halted
- **WHEN** the consensus status is `Halted`
- **THEN** no block proposal is created

### Requirement: Block Signing
Block proposals must be cryptographically signed by the proposing node.

#### Scenario: Block proposal signing
- **WHEN** a block is constructed
- **THEN** `BlockMetadata` is derived from the block and subnet ID
- **AND** the metadata is signed using the node's key at the current registry version
- **AND** if signing fails, no proposal is emitted

---

## Notarization

Notarization validates that a group of nodes consider a block proposal valid for a given round. Notarization shares are produced by notary committee members and later aggregated into full notarizations.

### Requirement: Notary Committee Membership
A node only produces notarization shares if it belongs to the notarization committee for the current round.

#### Scenario: Node is a notary
- **WHEN** the node's membership in the notarization committee is confirmed via the random beacon
- **THEN** the node may produce notarization shares

#### Scenario: Node is not a notary
- **WHEN** `node_belongs_to_notarization_committee` returns false or an error
- **THEN** no notarization shares are produced

### Requirement: Notarization Delay
Notarization is delayed based on block rank and system conditions to favor lower-ranked blocks and maintain system health.

#### Scenario: Base notary delay calculation
- **WHEN** computing notarization delay for rank `r`
- **THEN** the delay is `initial_notary_delay + unit_delay * r * 1.5^(finality_gap)`
- **AND** `finality_gap` is the difference between notarized height and finalized height

#### Scenario: Certified height backlog delay
- **WHEN** the finalized height exceeds the certified height by more than `ACCEPTABLE_FINALIZATION_CERTIFICATION_GAP` (1)
- **AND** the subnet is not in a halting/upgrade state
- **THEN** an additional `BACKLOG_DELAY_MILLIS * certified_gap` (2000ms per round of gap) is added to the notarization delay

#### Scenario: No backlog delay during upgrades
- **WHEN** the subnet is halting for an upgrade
- **AND** the certified height lags behind the finalized height
- **THEN** no backlog delay is added (because execution halts at CUP height by design)

### Requirement: Hard Notarization Limits
Notarization must stop entirely when certain gap thresholds are exceeded.

#### Scenario: Notarization-certification gap exceeded
- **WHEN** `notarized_height - certified_height >= ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP` (70)
- **THEN** the notary returns `None` (cannot notarize)
- **AND** a warning is logged every 5 seconds

#### Scenario: Notarization-CUP gap exceeded
- **WHEN** `notarized_height - next_cup_height >= ACCEPTABLE_NOTARIZATION_CUP_GAP` (130)
- **THEN** the notary returns `None` (cannot notarize)
- **AND** a warning is logged every 5 seconds

### Requirement: Lowest Rank Selection
The notary signs the lowest-ranked non-disqualified block proposals available.

#### Scenario: Multiple proposals at different ranks
- **WHEN** multiple non-disqualified block proposals exist at the next height
- **THEN** the notary only considers proposals with the minimum rank
- **AND** notarization shares are created for all proposals at that minimum rank

#### Scenario: Equivocating block maker handling
- **WHEN** multiple blocks exist at the same rank from the same block maker (equivocation)
- **THEN** notarization shares are produced for each distinct block at that rank
- **AND** this ensures liveness despite equivocating block makers

### Requirement: No Duplicate Notarization Shares
A node must not create a notarization share for a proposal it has already signed.

#### Scenario: Duplicate share prevention
- **WHEN** the validated pool contains a notarization share from this node for the same block hash
- **THEN** no new notarization share is created for that proposal

### Requirement: Notarization Share Signing
Notarization shares contain the block height and hash, signed by the notary.

#### Scenario: Creating a notarization share
- **WHEN** a block is selected for notarization
- **THEN** a `NotarizationContent` is created with the block height and hash
- **AND** the content is signed using the node's key at the registry version for that height

---

## Finalization

Finalization determines the canonical block for each round. A finalization share is produced when exactly one block is notarized and the node has not signed conflicting notarization shares.

### Requirement: Finalization Share Conditions
A finalization share is only produced under strict conditions that ensure safety.

#### Scenario: Single notarized block, no conflicting shares
- **WHEN** exactly one fully notarized block exists at height `h`
- **AND** this replica is a member of the notarization committee at height `h`
- **AND** this replica has not created a finalization share for height `h` yet
- **AND** this replica has not created notarization shares for any block other than the single notarized block at height `h`
- **THEN** a finalization share is produced for the notarized block

#### Scenario: Multiple notarized blocks
- **WHEN** more than one fully notarized block exists at height `h`
- **THEN** no finalization share is produced (finality cannot be achieved)

#### Scenario: Conflicting notarization shares exist
- **WHEN** this replica has notarization shares for a different block at height `h`
- **THEN** no finalization share is produced (to preserve safety)

#### Scenario: Already signed finalization share
- **WHEN** this replica has already produced a finalization share at height `h`
- **THEN** no additional finalization share is produced

### Requirement: Batch Delivery on Finalization
The finalizer delivers finalized blocks as batches to message routing.

#### Scenario: Delivering finalized batches
- **WHEN** `on_state_change` is called on the finalizer
- **THEN** finalized blocks are delivered as batches to `MessageRouting` starting from `expected_batch_height`
- **AND** finalization shares are attempted for all heights from `finalized_height + 1` to `notarized_height`

---

## Random Beacon

The random beacon provides verifiable randomness for each round, used to determine committee memberships and block maker rankings.

### Requirement: Random Beacon Share Creation
Threshold committee members create beacon shares for the next height once a block is notarized.

#### Scenario: Creating a beacon share
- **WHEN** a random beacon exists at the notarized height
- **AND** no random beacon exists at `notarized_height + 1`
- **AND** this node belongs to the threshold committee for random beacons
- **AND** this node has not yet created a share for `notarized_height + 1`
- **THEN** a `RandomBeaconShare` is created containing the hash of the current beacon
- **AND** the share is signed using the node's threshold key

#### Scenario: Beacon already exists
- **WHEN** a full random beacon already exists at `notarized_height + 1`
- **THEN** no beacon share is created

#### Scenario: Share already created
- **WHEN** this node has already submitted a beacon share for the target height
- **THEN** no additional share is created

#### Scenario: No notarized block
- **WHEN** no notarized block exists at the current notarized height
- **THEN** no beacon share can be created (beacon depends on notarization)

---

## Random Tape

The random tape provides randomness for canister execution. It is delivered alongside finalized blocks.

### Requirement: Random Tape Share Creation Range
Random tape shares are created for heights from `max(expected_batch_height, cup_height + 1)` up to `finalized_height + 1`, bounded by `RANDOM_TAPE_CHECK_MAX_HEIGHT_RANGE` (16).

#### Scenario: Creating random tape shares
- **WHEN** a height `h` is within the valid range
- **AND** this node belongs to the random beacon threshold committee at height `h` (same committee)
- **AND** no full random tape exists at height `h`
- **AND** this node has not created a share for height `h`
- **THEN** a `RandomTapeShare` is created for height `h`

#### Scenario: Security property - async randomness access
- **WHEN** a canister at height `h` requests randomness
- **THEN** it receives the random tape value from height `h+1`
- **AND** this prevents a malicious block maker from exploiting knowledge of the random tape at height `h` (which may be known before block `h` is finalized)

---

## Catch-Up Packages

Catch-up packages (CUPs) allow nodes to synchronize to a recent state without replaying the entire chain. They are created at DKG summary block heights.

### Requirement: CUP Share Creation Conditions
CUP shares are created when a DKG summary block is finalized and the corresponding state is available.

#### Scenario: Creating a CUP share
- **WHEN** a finalized summary block exists above the current CUP height
- **AND** this node belongs to the CUP threshold committee
- **AND** this node has not yet created a CUP share for this height
- **AND** a random beacon exists at this height
- **AND** the finalized tip's certified height is at least this height
- **AND** the state hash is available from the state manager
- **THEN** a `CatchUpPackageShare` is created

#### Scenario: State not yet committed
- **WHEN** the state manager returns `StateNotCommittedYet` or `HashNotComputedYet`
- **THEN** no CUP share is created (will retry later)

#### Scenario: State removed prematurely
- **WHEN** the state manager returns `StateRemoved`
- **THEN** the node panics (this should never happen)

### Requirement: State Sync Invocation
The CUP maker triggers state synchronization when the local state falls behind the CUP.

#### Scenario: State sync needed
- **WHEN** `expected_batch_height` is below the latest CUP height
- **THEN** `state_manager.fetch_state` is called with the CUP height, state hash, and interval length

### Requirement: State Divergence Detection
The CUP maker detects and reports state divergence.

#### Scenario: State hash mismatch
- **WHEN** the local state hash at the CUP height differs from the CUP's state hash
- **AND** the CUP height is greater than 0 (not genesis)
- **THEN** `state_manager.report_diverged_checkpoint` is called (which deletes diverged states and panics)

### Requirement: IDKG Registry Version in CUP
When IDKG is active, the CUP includes the oldest registry version in use by the replicated state.

#### Scenario: CUP with IDKG payload
- **WHEN** the summary block contains an IDKG payload
- **THEN** the CUP share includes `oldest_registry_version_in_use_by_replicated_state`
- **AND** this version is derived from signature request contexts in the replicated state

---

## Share Aggregation

The share aggregator combines individual shares into complete artifacts using threshold or multi-signature aggregation.

### Requirement: Random Beacon Aggregation
Random beacon shares at `beacon_height + 1` are aggregated into a full random beacon.

#### Scenario: Aggregating beacon shares
- **WHEN** enough random beacon shares exist at the next height
- **THEN** they are combined into a full `RandomBeacon` using the low-threshold NiDKG transcript

### Requirement: Random Tape Aggregation
Random tape shares from `expected_batch_height` to `finalized_height + 1` are aggregated.

#### Scenario: Aggregating tape shares
- **WHEN** enough random tape shares exist at a height where no full tape exists
- **THEN** they are combined into a full `RandomTape`

### Requirement: Notarization Aggregation
Notarization shares at `notarized_height + 1` are aggregated into full notarizations.

#### Scenario: Aggregating notarization shares
- **WHEN** enough notarization shares exist for the same block at the next height
- **THEN** they are combined into a full `Notarization` using multi-signature aggregation

### Requirement: Finalization Aggregation
Finalization shares from `finalized_height + 1` to `notarized_height` are aggregated.

#### Scenario: Aggregating finalization shares
- **WHEN** enough finalization shares exist for the same block
- **THEN** they are combined into a full `Finalization`

### Requirement: CUP Aggregation
CUP shares are aggregated into full catch-up packages, starting from the highest finalized summary block.

#### Scenario: Aggregating CUP shares
- **WHEN** enough CUP shares exist at a summary block height above the current CUP height
- **THEN** they are combined into a full `CatchUpPackage` using the high-threshold NiDKG transcript

---

## Validation

The validator processes unvalidated artifacts from the pool, moving valid ones to the validated section and removing invalid ones.

### Requirement: Block Proposal Validation
Block proposals are validated for correct rank, signature, payload, and context.

#### Scenario: Valid block proposal
- **WHEN** an unvalidated block proposal arrives
- **AND** its signer's rank matches the expected rank from the random beacon
- **AND** the `BlockMetadata` signature is cryptographically valid
- **AND** the validation context is strictly monotonically increasing from the parent
- **AND** the DKG payload is valid
- **AND** the batch payload is valid
- **AND** the protocol version matches
- **THEN** the proposal is moved to the validated pool

#### Scenario: Mismatched rank
- **WHEN** a block proposal's rank does not match the expected rank for its signer
- **THEN** the proposal is permanently invalid and removed

#### Scenario: Non-empty payload past upgrade point
- **WHEN** a block proposal contains a non-empty payload after the upgrade point
- **THEN** the proposal is permanently invalid

### Requirement: Notarization/Finalization Validation
Notarizations and finalizations are validated for correct multi-signatures and committee membership.

#### Scenario: Valid notarization
- **WHEN** an unvalidated notarization has a valid combined multi-signature
- **AND** all signers belong to the notarization committee
- **AND** the referenced block exists in the pool
- **THEN** the notarization is moved to the validated pool

#### Scenario: Valid notarization share
- **WHEN** an unvalidated notarization share has a valid individual multi-signature
- **AND** the signer belongs to the notarization committee
- **THEN** the share is moved to the validated pool

### Requirement: Random Beacon/Tape Validation
Random beacons and tapes (and their shares) are validated using threshold signature verification.

#### Scenario: Valid random beacon
- **WHEN** a random beacon has a valid combined threshold signature
- **AND** the signer NiDKG ID matches the active low-threshold transcript
- **THEN** the beacon is moved to the validated pool

#### Scenario: Valid random beacon share
- **WHEN** a beacon share signer belongs to the threshold committee
- **AND** the threshold signature share is valid
- **THEN** the share is moved to the validated pool

### Requirement: CUP Validation
CUPs are validated by verifying the combined threshold signature against the subnet's public key.

#### Scenario: Valid CUP
- **WHEN** a CUP's combined threshold signature is valid against the subnet public key
- **THEN** the CUP is moved to the validated pool

#### Scenario: Valid CUP share
- **WHEN** a CUP share's threshold signature share is valid
- **AND** the share's block and state hash match the finalized block
- **AND** the signer belongs to the high-threshold committee
- **THEN** the share is moved to the validated pool

### Requirement: Equivocation Proof Validation
Equivocation proofs demonstrate that a block maker proposed two different blocks at the same height.

#### Scenario: Valid equivocation proof
- **WHEN** the proof contains two distinct signed block metadata entries from the same signer at the same height
- **AND** the signer is a block maker at that height
- **AND** both basic signatures are valid
- **THEN** the equivocation proof is moved to the validated pool

### Requirement: Height-Based Validation Bounds
Validation respects the notarization-certification and notarization-CUP gap limits.

#### Scenario: Artifact above gap limit
- **WHEN** a non-CUP artifact's height exceeds the gap limits
- **THEN** the artifact is not validated (deferred for later)

#### Scenario: CUP has no upper height bound
- **WHEN** a CUP artifact arrives at any height
- **THEN** it is always eligible for validation regardless of gap limits

---

## Payload Building

The payload builder constructs and validates the batch payload portions of blocks.

### Requirement: Payload Section Building
The batch payload is built from multiple sections, each handled by a dedicated builder.

#### Scenario: Section builders called in rotation
- **WHEN** a batch payload is constructed for height `h`
- **THEN** the section builders (Ingress, SelfValidating, XNet, CanisterHttp, QueryStats, VetKd) are called in a rotation determined by `h % num_sections`
- **AND** each section is allocated space from the remaining block size budget

### Requirement: Payload Size Limits
Each payload section must respect its allocated byte limit.

#### Scenario: Section exceeds size limit
- **WHEN** a payload section builder returns a payload larger than `max_size`
- **THEN** the section is replaced with an empty default
- **AND** a critical error metric is incremented

#### Scenario: XNet payload size margin
- **WHEN** the XNet payload builder is called
- **THEN** it receives 95% of the available space (to account for Merkle tree size estimation imprecision)
- **AND** payloads up to 2x the limit are tolerated with a warning; payloads beyond 2x trigger a critical error

### Requirement: Payload Self-Validation
After building, each payload section is validated as a safety measure.

#### Scenario: Built payload fails validation
- **WHEN** a section's built payload does not pass its own validation
- **THEN** the section is replaced with an empty default
- **AND** a critical error metric is incremented

### Requirement: Maximum Block Payload Size
The maximum block payload size is determined from the subnet record.

#### Scenario: Payload size from subnet record
- **WHEN** building a payload
- **THEN** the maximum block payload size is obtained from the subnet record's `context_version`
- **AND** fixed allocations for XNet (`MAX_XNET_PAYLOAD_IN_BYTES`) and Bitcoin (`MAX_BITCOIN_PAYLOAD_IN_BYTES`) are subtracted from the remaining budget

---

## Pool Purging

The purger removes old artifacts from the consensus pool and triggers state manager cleanup.

### Requirement: Unvalidated Pool Purging
Unvalidated artifacts below the expected batch height are purged.

#### Scenario: Purge unvalidated pool
- **WHEN** `expected_batch_height` increases
- **AND** `expected_batch_height <= finalized_height + 1`
- **AND** no unprocessed CUPs or CUP shares exist in the height range
- **THEN** unvalidated artifacts below `expected_batch_height - 1` are purged
- **AND** the `-1` offset preserves the random beacon needed for progress

#### Scenario: Skip purge during state sync
- **WHEN** `expected_batch_height > finalized_height + 1` (indicates state sync just completed)
- **THEN** unvalidated pool purging is skipped

### Requirement: Validated Pool Purging
Validated artifacts below the CUP height (minus minimum chain length) are purged.

#### Scenario: Purge validated pool
- **WHEN** the CUP height range's max exceeds `min + MINIMUM_CHAIN_LENGTH`
- **THEN** validated artifacts below `max_cup_height - MINIMUM_CHAIN_LENGTH` are purged

### Requirement: Share Purging
Notarization and finalization shares below the finalized height are purged.

#### Scenario: Purge shares by finalized height
- **WHEN** the finalized height increases
- **THEN** `NotarizationShare` artifacts below `finalized_height + 1` are purged
- **AND** `FinalizationShare` artifacts below `finalized_height + 1` are purged

### Requirement: Equivocation Proof Purging
Equivocation proofs below the finalized height are purged.

#### Scenario: Purge equivocation proofs
- **WHEN** the finalized height increases
- **AND** equivocation proofs exist in the validated pool
- **THEN** equivocation proofs below `finalized_height + 1` are purged

### Requirement: Non-Finalized Block Purging
Non-finalized block proposals and notarizations are removed once their height is finalized.

#### Scenario: Purge non-finalized blocks
- **WHEN** the finalized height increases from `prev` to `new`
- **THEN** for each height in `(prev, new]`, all block proposals and notarizations that do not reference the finalized block's hash are removed from the validated pool

### Requirement: Replicated State Purging
The state manager is instructed to remove states that are no longer needed.

#### Scenario: In-memory state purging
- **WHEN** the certified height or latest state height increases
- **THEN** in-memory states below the finalized tip's certified height are removed
- **AND** states at pending IDKG CUP heights are preserved

#### Scenario: Checkpoint purging
- **WHEN** the CUP height increases or certified height increases
- **THEN** state checkpoints below the CUP height are removed

### Requirement: Pool Bounds Checking
The validated pool size is periodically checked against expected bounds.

#### Scenario: Bounds check every 10 heights
- **WHEN** the finalized height is a multiple of 10
- **THEN** the validated pool artifact counts are compared against theoretical bounds
- **AND** if exceeded, an error is logged and a metric is incremented

---

## Artifact Priority (Bouncer)

The bouncer determines whether incoming consensus artifacts should be fetched, deferred, or dropped.

### Requirement: Height-Based Priority Decisions
Artifact priority depends on the artifact's height relative to key pool heights.

#### Scenario: Artifact below minimum height
- **WHEN** an artifact's height is below both the CUP height and expected batch height
- **THEN** the artifact is `Unwanted`

#### Scenario: Non-CUP artifact beyond CUP gap
- **WHEN** a non-CUP artifact's height exceeds `next_cup_height + ACCEPTABLE_NOTARIZATION_CUP_GAP`
- **THEN** the artifact is `MaybeWantsLater` (stashed, not fetched)

#### Scenario: CUP always wanted
- **WHEN** a CUP artifact arrives at any height
- **THEN** it is always `Wants` (always fetched)

### Requirement: Type-Specific Priority Rules

#### Scenario: Random beacon/share priority
- **WHEN** a random beacon or share height is at or below the beacon height
- **THEN** it is `Unwanted`
- **WHEN** the height is within `beacon_height + LOOK_AHEAD` (10)
- **THEN** it is `Wants`
- **OTHERWISE** it is `MaybeWantsLater`

#### Scenario: Notarization share priority
- **WHEN** a notarization share height is at or below the notarized height
- **THEN** it is `Unwanted`
- **WHEN** the height is within `notarized_height + LOOK_AHEAD`
- **THEN** it is `Wants`

#### Scenario: Block/notarization/finalization priority
- **WHEN** a block, notarization, finalization, finalization share, or equivocation proof height is at or below the finalized height
- **THEN** it is `Unwanted`
- **WHEN** the height is within `notarized_height + LOOK_AHEAD`
- **THEN** it is `Wants`

#### Scenario: Random tape/share priority
- **WHEN** a random tape or share height is below expected batch height
- **THEN** it is `Unwanted`
- **WHEN** the height is within `finalized_height + LOOK_AHEAD`
- **THEN** it is `Wants`

#### Scenario: CUP share priority
- **WHEN** a CUP share height is at or below the CUP height
- **THEN** it is `Unwanted`
- **WHEN** the height is at or below the finalized height
- **THEN** it is `Wants`

---

## Batch Delivery

Batch delivery converts finalized blocks into batches and submits them to message routing for execution.

### Requirement: Sequential Batch Delivery
Batches are delivered sequentially from `expected_batch_height` up to `finalized_height`.

#### Scenario: Delivering a finalized batch
- **WHEN** a finalized block and random tape exist at the target height
- **AND** a DKG summary block can be found for this height
- **THEN** a `Batch` is constructed with:
  - `batch_number`: the height
  - `randomness`: derived from the random tape
  - `registry_version`: from the block's validation context
  - `time`: from the block's validation context
  - `blockmaker_metrics`: the proposer and list of failed (higher-priority) block makers
  - `content`: messages from the block payload
  - `chain_key_data`: IDKG and NiDKG public keys and pre-signatures
  - `consensus_responses`: responses to subnet calls (DKG, signatures, HTTP)
- **AND** the batch is delivered via `message_routing.deliver_batch`

#### Scenario: Missing random tape
- **WHEN** no random tape exists at the delivery height
- **THEN** batch delivery stops and retries later

#### Scenario: Missing finalized block
- **WHEN** no finalized block exists at the delivery height (e.g., during state sync)
- **THEN** batch delivery stops and retries later

### Requirement: Halt-Aware Batch Delivery
Batches are not delivered when the subnet is halting or halted, except for CUP blocks.

#### Scenario: Batch at CUP height during halt
- **WHEN** a finalized block is a summary block (CUP height)
- **THEN** the batch is always delivered regardless of halt status

#### Scenario: Non-CUP batch during halt
- **WHEN** the consensus status is `Halting` or `Halted`
- **AND** the block is not a summary block
- **THEN** the batch is not delivered

### Requirement: Consensus Responses
Responses to system calls are generated from block payloads.

#### Scenario: Remote DKG responses
- **WHEN** a block contains completed remote DKG transcripts
- **THEN** `SetupInitialDKGResponse` or `ReshareChainKeyResponse` payloads are generated
- **AND** rejected responses are generated for failed DKGs

#### Scenario: IDKG signature responses
- **WHEN** a data block contains IDKG payload with completed signatures
- **THEN** signature responses are generated for the corresponding request contexts

#### Scenario: Canister HTTP responses
- **WHEN** a data block contains canister HTTP payload
- **THEN** HTTP responses are extracted and included in consensus responses

---

## Consensus Status and Halting

The consensus status system controls whether the subnet produces blocks and delivers batches during upgrades or administrative halts.

### Requirement: Three-State Status Model

#### Scenario: Running status
- **WHEN** no upgrade is pending
- **AND** the registry does not instruct the subnet to halt at CUP height
- **THEN** the status is `Running`

#### Scenario: Halting status
- **WHEN** an upgrade is pending (different replica version at current registry version) OR the registry instructs halt at CUP height
- **AND** the certified height has not yet reached the halting condition
- **THEN** the status is `Halting`
- **AND** empty blocks are produced but no batches are delivered

#### Scenario: Halted status
- **WHEN** an upgrade is pending or registry instructs halt
- **AND** the certified height has also reached the halting condition
- **THEN** the status is `Halted`
- **AND** no blocks are produced and no batches are delivered

---

## Pool Bounds

The validated pool is bounded to prevent memory exhaustion attacks.

### Requirement: Artifact Count Bounds
The maximum number of each artifact type in the validated pool is bounded by a formula based on node count, DKG interval, and gap constants.

#### Scenario: Maximum artifact counts (example: 40-node subnet, DKG interval 499)
- **WHEN** `n=40`, `k=500`, `f=13`, `g=130`, `d=70`, `e=50`
- **THEN** `l = k + e + g + 1 = 681`
- **AND** `block_proposals <= (f+1)*d + (l-d) + 1 = 14*70 + 611 + 1 = 1592`
- **AND** `notarizations <= (f+1)*d + (l-d) = 1591`
- **AND** `finalization <= l = 681`
- **AND** `random_beacon <= l+1 = 682`
- **AND** `notarization_shares <= d*(f+1)*n = 70*14*40 = 39200`
- **AND** `finalization_shares <= d*n = 70*40 = 2800`

---

## Membership

Membership determines node roles for each consensus round.

### Requirement: Deterministic Committee Selection
Committee membership is derived deterministically from the random beacon.

#### Scenario: Node shuffling
- **WHEN** committee membership is computed for height `h`
- **THEN** all nodes are sorted by ID, then shuffled using a CSPRNG seeded from the previous random beacon and the purpose identifier
- **AND** the shuffle is deterministic across all replicas

### Requirement: Block Maker Selection
Only the top f+1 nodes in the shuffled ordering are eligible block makers.

#### Scenario: Block maker rank assignment
- **WHEN** a node's position in the shuffled ordering is at index `i`
- **AND** `i <= get_faults_tolerated(n)` (where n is the committee size)
- **THEN** the node's rank is `Rank(i)` (lower is better)
- **AND** rank 0 is the primary block maker

#### Scenario: Node not elected
- **WHEN** a node's position exceeds `f` in the shuffled ordering
- **THEN** `get_block_maker_rank` returns `None`

### Requirement: Threshold Committee Membership
Threshold committees (for random beacons, random tapes, CUPs) are determined from DKG transcript receivers.

#### Scenario: Low threshold committee membership
- **WHEN** checking low threshold committee membership at height `h`
- **THEN** the active low-threshold NiDKG transcript receivers at `h` determine committee membership

#### Scenario: High threshold committee membership
- **WHEN** checking high threshold committee membership at height `h`
- **THEN** the active high-threshold NiDKG transcript receivers at `h` determine committee membership

### Requirement: Notarization Committee
All nodes in the subnet are members of the notarization committee.

#### Scenario: Notarization committee membership
- **WHEN** checking if a node belongs to the notarization committee
- **THEN** the result is determined by whether the node is in the subnet's node list at the relevant registry version
