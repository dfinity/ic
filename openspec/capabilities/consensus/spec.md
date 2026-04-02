# Consensus Capability Specification

**Source narrative**: `openspec/specs/consensus/spec.md`
**Crates**: `ic-consensus`, `ic-consensus-dkg`, `ic-consensus-utils`
**Key files**: `rs/consensus/src/`, `rs/consensus/utils/`

---

## REQ-CONS-001: Subcomponent Execution Order

Consensus subcomponents MUST be invoked in a specific round-robin order ensuring correctness.

### SCENARIO-CONS-001: Round-robin invocation returns first non-empty result
**Given** `on_state_change` is called on the consensus pool
**When** subcomponents are invoked
**Then** they are invoked in order: Finalizer, CatchUpPackageMaker, Aggregator, Purger, Notary, RandomBeaconMaker, RandomTapeMaker, BlockMaker, Validator, Purger
**And** the first subcomponent returning non-empty `Mutations` causes immediate return

### SCENARIO-CONS-002: DKG key manager runs first
**Given** `on_state_change` is called
**When** execution begins
**Then** the DKG key manager's `on_state_change` is invoked first to load new transcripts and remove outdated keys

### SCENARIO-CONS-003: Subnet halt by registry record
**Given** the subnet record has `is_halted = true`
**When** `on_state_change` is called
**Then** consensus returns empty `Mutations` (no progress)
**And** no subcomponents are invoked

### SCENARIO-CONS-023: Protocol version check
**Given** an artifact's replica version does not match the expected default protocol version
**When** the artifact is processed
**Then** the artifact is rejected with `ReplicaVersionMismatch`

### SCENARIO-CONS-024: DKG availability check
**Given** `on_state_change` checks DKG transcript availability
**When** the check runs
**Then** the node verifies it is listed as a receiver in every current transcript type
**And** if the node is not listed in all transcript committees, DKGs are considered unavailable

---

## REQ-CONS-002: Block Maker Election

Each round MUST elect a subset of nodes as block makers using a deterministic pseudo-random shuffle.

### SCENARIO-CONS-004: Node elected as block maker
**Given** a new round begins (notarized height advances)
**When** `get_block_maker_rank` is called
**Then** if the node's rank is within the top `f+1` nodes (where `f = max_malicious_nodes` from the subnet registry record), the node is eligible to propose

### SCENARIO-CONS-005: Duplicate proposal prevention
**Given** the validated pool already contains a block proposal from this node at the target height
**When** the block maker checks
**Then** no new block proposal is created

### SCENARIO-CONS-006: Better block suppression
**Given** the validated pool contains a non-disqualified block proposal with lower rank than this node
**When** the block maker checks
**Then** this node does not propose a block

### SCENARIO-CONS-007: Validation context monotonicity
**Given** the locally available validation context does not strictly exceed the parent block's context
**When** the block maker checks
**Then** no block is proposed and a warning is logged

### SCENARIO-CONS-008: Block time monotonicity
**Given** computing the block timestamp
**When** the time is set
**Then** block time = `max(current_relative_time, parent_time + initial_notary_delay + 1ns)`
**And** this ensures strict monotonicity of block timestamps

---

## REQ-CONS-003: Block Proposal Timing

Block makers MUST wait a rank-dependent delay before proposing.

### SCENARIO-CONS-009: Block maker delay calculation
**Given** a block maker has rank `r`
**When** the delay is computed
**Then** the base delay is `unit_delay * r`
**And** a dynamic delay is added if rank > 0 and more than 10 non-rank-0 blocks have been finalized in the last 30 heights

### SCENARIO-CONS-010: Time to make block
**Given** the relative time since round start exceeds the block maker delay
**When** the timing check runs
**Then** it is time to propose a block

---

## REQ-CONS-004: Notarization

Notarization MUST provide subnet-wide agreement that a block proposal is eligible for finalization.

### SCENARIO-CONS-011: Notarization share creation
**Given** a block proposal passes validation and the notarization delay has elapsed
**When** the notary processes the block
**Then** a notarization share is created for the block
**And** the share is added to the validated pool

### SCENARIO-CONS-012: Notarization aggregate creation
**Given** sufficient notarization shares exist for a block
**When** the aggregator runs
**Then** a notarization is created from the shares
**And** the notarized block is available for finalization

---

## REQ-CONS-005: Finalization

Finalization MUST provide irreversible commitment to a single block at each height.

### SCENARIO-CONS-013: Finalization share creation
**Given** exactly one block at a height has been notarized
**When** the finalizer processes the block
**Then** a finalization share is created for the block

### SCENARIO-CONS-014: Finalization aggregate creation
**Given** sufficient finalization shares exist for a block
**When** the aggregator runs
**Then** a finalization is created
**And** the block is irreversibly finalized

---

## REQ-CONS-006: Random Beacon

The random beacon MUST provide unpredictable subnet-level randomness via threshold BLS signatures.

### SCENARIO-CONS-015: Random beacon share creation
**Given** the previous random beacon exists
**When** a node creates a random beacon share
**Then** it signs the previous beacon's height and hash using threshold BLS
**And** the share is added to the validated pool

### SCENARIO-CONS-016: Random beacon aggregate creation
**Given** sufficient random beacon shares exist
**When** the aggregator runs
**Then** a random beacon is created by combining the threshold shares
**And** the beacon is used to seed the next round's block maker election

---

## REQ-CONS-007: Catch-Up Packages (CUP)

CUPs MUST allow nodes to quickly catch up to the current state without replaying all blocks.

### SCENARIO-CONS-017: CUP creation at DKG interval boundary
**Given** a block at a DKG interval boundary is finalized and state is certified
**When** the CUP maker runs
**Then** a CUP is created containing the state hash, random beacon, and DKG summary
**And** the CUP allows new nodes to start from this point

### SCENARIO-CONS-018: Node starts from CUP
**Given** a node receives a CUP
**When** the node initializes
**Then** it starts consensus from the CUP height without replaying earlier blocks

---

## REQ-CONS-008: Block Payload Construction

Blocks MUST contain DKG payloads and optionally batch payloads.

### SCENARIO-CONS-019: Summary block at DKG interval boundary
**Given** a block height corresponds to a DKG interval boundary
**When** the block is created
**Then** a summary payload is created containing a DKG summary and optionally an IDKG summary
**And** no batch payload is included in summary blocks

### SCENARIO-CONS-020: Data block with batch payload
**Given** a block height is within a DKG interval
**When** the block is created
**Then** a data payload is included (containing DKG dealings if available)
**And** a batch payload is included with ingress messages, XNet messages, and canister HTTP responses

---

## REQ-CONS-009: Pool Purging

The consensus pool MUST purge artifacts that are no longer needed.

### SCENARIO-CONS-021: Purge below finalized height
**Given** the finalized height advances
**When** the purger runs
**Then** artifacts at heights below the purge threshold are removed from the pool
**And** the purge threshold is bounded by `MINIMUM_CHAIN_LENGTH` (50) below the current finalized height

---

## REQ-CONS-010: Batch Delivery

Finalized blocks MUST be delivered as batches to the message routing layer.

### SCENARIO-CONS-022: Deliver finalized block as batch
**Given** a block is finalized
**When** batch delivery runs
**Then** the block's payload is delivered as a batch to message routing
**And** batches are delivered in height order without gaps

---

## REQ-CONS-011: Random Tape

The random tape subcomponent MUST generate per-height randomness for canister execution.

### SCENARIO-CONS-025: Random tape share creation
**Given** a node needs to contribute to the random tape at a given height
**When** the random tape maker runs
**Then** the node creates a threshold BLS signature share over the height value
**And** the share is added to the validated pool

### SCENARIO-CONS-026: Random tape aggregate creation
**Given** sufficient random tape shares exist for a height
**When** the aggregator runs
**Then** a random tape is created by combining the threshold shares
**And** the tape value is used as randomness seed for canister execution at that height

---

## REQ-CONS-012: Share Aggregation

The aggregator subcomponent MUST combine threshold shares into full consensus artifacts.

### SCENARIO-CONS-027: Aggregation threshold check
**Given** shares of a given type (notarization, finalization, random beacon, random tape) accumulate in the validated pool
**When** the aggregator checks for completeness
**Then** it waits until the number of shares meets or exceeds the threshold (typically `f+1` for random beacon/tape, or a majority for notarization)
**And** once the threshold is met, a combined artifact is created and added to the pool

### SCENARIO-CONS-028: Share deduplication
**Given** multiple shares from the same node for the same artifact arrive
**When** the aggregator processes them
**Then** only the first valid share from each node is counted
**And** duplicates are discarded

---

## REQ-CONS-013: Artifact Validation

The validator subcomponent MUST verify artifacts before promoting them from unvalidated to validated pool.

### SCENARIO-CONS-029: Block proposal validation
**Given** a block proposal arrives in the unvalidated pool
**When** the validator processes it
**Then** the block's rank is checked against the expected block maker
**And** the parent hash references a known finalized or notarized block
**And** the validation context is monotonically increasing relative to the parent
**And** the payload is validated by all payload building components
**And** if valid, the block is moved to the validated pool

### SCENARIO-CONS-030: Notarization share validation
**Given** a notarization share arrives in the unvalidated pool
**When** the validator processes it
**Then** the share's block hash must match a valid block proposal in the pool
**And** the signer's BLS threshold signature is verified
**And** if valid, the share is moved to the validated pool

### SCENARIO-CONS-031: Invalid artifact rejection
**Given** an artifact fails any validation check
**When** the validator processes it
**Then** the artifact is moved to the invalid section of the pool
**And** a validation error is recorded with the reason

---

## REQ-CONS-014: Pool Bounds

The consensus pool MUST enforce bounds on artifact retention.

### SCENARIO-CONS-032: Unvalidated pool size limit
**Given** the unvalidated pool exceeds its maximum size
**When** new artifacts arrive
**Then** low-priority artifacts are evicted to stay within bounds
**And** the pool size metric is updated

### SCENARIO-CONS-033: Minimum chain length enforcement
**Given** the purger computes the purge threshold
**When** the threshold is calculated
**Then** at least `MINIMUM_CHAIN_LENGTH` (50) heights of artifacts are retained below the finalized height
**And** this ensures peers can catch up without needing a CUP

---

## REQ-CONS-015: Membership

Consensus MUST determine subnet membership from the registry.

### SCENARIO-CONS-034: Membership derived from registry
**Given** a consensus round begins
**When** membership is determined
**Then** it is derived from the subnet record at the appropriate registry version
**And** nodes added to or removed from the subnet are reflected within the consensus latency bound

### SCENARIO-CONS-035: Node verifies own membership
**Given** a node processes a subnet record update
**When** the node checks its own membership
**Then** if the node is no longer in the subnet, it stops participating in consensus
**And** if the node is newly added, it begins participating after loading the appropriate DKG transcripts

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-CONS-001 | Subcomponent order | linked | rs/consensus/tests/integration.rs |
| REQ-CONS-002 | Block maker election | linked | rs/consensus/tests/integration.rs |
| REQ-CONS-003 | Block proposal timing | linked | rs/consensus/tests/integration.rs |
| REQ-CONS-004 | Notarization | linked | rs/consensus/tests/integration.rs |
| REQ-CONS-005 | Finalization | linked | rs/consensus/tests/integration.rs |
| REQ-CONS-006 | Random beacon | narrative | rs/consensus/tests/ |
| REQ-CONS-007 | Catch-up packages | narrative | rs/consensus/tests/ |
| REQ-CONS-008 | Block payload | narrative | rs/consensus/tests/ |
| REQ-CONS-009 | Pool purging | narrative | rs/consensus/tests/ |
| REQ-CONS-010 | Batch delivery | linked | rs/consensus/tests/integration.rs |
| REQ-CONS-011 | Random tape | narrative | rs/consensus/tests/ |
| REQ-CONS-012 | Share aggregation | narrative | rs/consensus/tests/ |
## REQ-CONS-016: Block Signing

Block proposals MUST be cryptographically signed by the proposing node.

### SCENARIO-CONS-036: Block proposal signing
**Given** a block is constructed
**When** signing runs
**Then** `BlockMetadata` is derived from the block and subnet ID
**And** the metadata is signed using the node's key at the current registry version
**And** if signing fails, no proposal is emitted

---

## REQ-CONS-017: Notarization Delay

Notarization MUST be delayed based on block rank and system conditions.

### SCENARIO-CONS-037: Base notary delay
**Given** computing notarization delay for rank `r`
**When** the delay is calculated
**Then** delay = `initial_notary_delay + unit_delay * r * 1.5^(finality_gap)`
**And** `finality_gap` = notarized height - finalized height

### SCENARIO-CONS-038: Certified height backlog delay
**Given** finalized height exceeds certified height by more than `ACCEPTABLE_FINALIZATION_CERTIFICATION_GAP` (1)
**And** the subnet is not halting/upgrading
**When** additional delay is computed
**Then** `BACKLOG_DELAY_MILLIS * certified_gap` (2000ms per round of gap) is added

### SCENARIO-CONS-039: No backlog delay during upgrades
**Given** the subnet is halting for an upgrade
**When** backlog delay is checked
**Then** no backlog delay is added (execution halts at CUP height by design)

---

## REQ-CONS-018: Hard Notarization Limits

Notarization MUST stop entirely when gap thresholds are exceeded.

### SCENARIO-CONS-040: Notarization-certification gap exceeded
**Given** `notarized_height - certified_height >= ACCEPTABLE_NOTARIZATION_CERTIFICATION_GAP` (70)
**When** the notary runs
**Then** it returns `None` (cannot notarize)
**And** a warning is logged every 5 seconds

### SCENARIO-CONS-041: Notarization-CUP gap exceeded
**Given** `notarized_height - next_cup_height >= ACCEPTABLE_NOTARIZATION_CUP_GAP` (130)
**When** the notary runs
**Then** it returns `None` (cannot notarize)

---

## REQ-CONS-019: Finalization Share Conditions

Finalization shares MUST only be produced under strict safety conditions.

### SCENARIO-CONS-042: Single notarized block, no conflicts
**Given** exactly one fully notarized block exists at height `h`
**And** this replica has NOT created notarization shares for any other block at `h`
**And** this replica has NOT yet created a finalization share at `h`
**When** the finalizer runs
**Then** a finalization share is produced for the notarized block

### SCENARIO-CONS-043: Multiple notarized blocks prevents finalization
**Given** more than one fully notarized block exists at height `h`
**When** the finalizer runs
**Then** no finalization share is produced

---

## REQ-CONS-020: CUP Creation Conditions

CUP shares MUST only be created when a summary block is finalized and state is available.

### SCENARIO-CONS-044: CUP share creation
**Given** a finalized summary block exists above the current CUP height
**And** the state hash is available from the state manager
**And** a random beacon exists at this height
**When** the CUP maker runs
**Then** a `CatchUpPackageShare` is created

### SCENARIO-CONS-045: State hash mismatch triggers divergence
**Given** the local state hash at CUP height differs from the CUP's state hash
**And** the CUP height > 0 (not genesis)
**When** divergence is detected
**Then** `state_manager.report_diverged_checkpoint` is called (deletes diverged states and panics)

---

## REQ-CONS-021: Payload Building Sections

The batch payload MUST be built from multiple section builders with rotation and size limits.

### SCENARIO-CONS-046: Section builders called in rotation
**Given** a batch payload is constructed for height `h`
**When** building runs
**Then** section builders (Ingress, SelfValidating, XNet, CanisterHttp, QueryStats, VetKd) are called in rotation `h % num_sections`
**And** each section is allocated space from the remaining block size budget

### SCENARIO-CONS-047: Section exceeds size limit replaced with empty
**Given** a payload section builder returns a payload larger than `max_size`
**When** the size check runs
**Then** the section is replaced with an empty default
**And** a critical error metric is incremented

### SCENARIO-CONS-048: Built payload fails self-validation
**Given** a section's built payload does not pass its own validation
**When** the validation check runs
**Then** the section is replaced with an empty default
**And** a critical error metric is incremented

---

## REQ-CONS-022: Consensus Status and Halting

The consensus status system MUST control block production and batch delivery during upgrades.

### SCENARIO-CONS-049: Running status
**Given** no upgrade is pending and no halt-at-CUP instruction
**When** status is evaluated
**Then** status is `Running`

### SCENARIO-CONS-050: Halting status
**Given** an upgrade is pending OR registry instructs halt at CUP height
**And** the certified height has not yet reached the halting condition
**When** status is evaluated
**Then** status is `Halting` — empty blocks are produced but no batches are delivered

### SCENARIO-CONS-051: Halted status
**Given** an upgrade is pending or registry instructs halt
**And** the certified height HAS reached the halting condition
**When** status is evaluated
**Then** status is `Halted` — no blocks produced and no batches delivered

---

## REQ-CONS-023: Artifact Priority (Bouncer)

The bouncer MUST determine fetch priority for incoming consensus artifacts based on height.

### SCENARIO-CONS-052: Artifact below minimum height is unwanted
**Given** an artifact's height is below both CUP height and expected batch height
**When** the bouncer evaluates it
**Then** the artifact is `Unwanted`

### SCENARIO-CONS-053: CUP always wanted
**Given** a CUP artifact arrives at any height
**When** the bouncer evaluates it
**Then** it is always `Wants` (always fetched)

### SCENARIO-CONS-054: Non-CUP beyond gap is deferred
**Given** a non-CUP artifact's height exceeds `next_cup_height + ACCEPTABLE_NOTARIZATION_CUP_GAP`
**When** the bouncer evaluates it
**Then** the artifact is `MaybeWantsLater` (stashed, not fetched)

---

## REQ-CONS-024: Equivocation Proof Validation

The system MUST validate and use equivocation proofs to detect misbehaving block makers.

### SCENARIO-CONS-055: Valid equivocation proof
**Given** a proof contains two distinct signed block metadata from the same signer at the same height
**And** both basic signatures are valid
**When** validation runs
**Then** the equivocation proof is moved to the validated pool

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-CONS-001 | Subcomponent order | linked | rs/consensus/tests/integration.rs |
| REQ-CONS-002 | Block maker election | linked | rs/consensus/tests/integration.rs |
| REQ-CONS-003 | Block proposal timing | linked | rs/consensus/tests/integration.rs |
| REQ-CONS-004 | Notarization | linked | rs/consensus/tests/integration.rs |
| REQ-CONS-005 | Finalization | linked | rs/consensus/tests/integration.rs |
| REQ-CONS-006 | Random beacon | narrative | rs/consensus/tests/ |
| REQ-CONS-007 | Catch-up packages | narrative | rs/consensus/tests/ |
| REQ-CONS-008 | Block payload | narrative | rs/consensus/tests/ |
| REQ-CONS-009 | Pool purging | narrative | rs/consensus/tests/ |
| REQ-CONS-010 | Batch delivery | linked | rs/consensus/tests/integration.rs |
| REQ-CONS-011 | Random tape | narrative | rs/consensus/tests/ |
| REQ-CONS-012 | Share aggregation | narrative | rs/consensus/tests/ |
| REQ-CONS-013 | Artifact validation | narrative | rs/consensus/tests/ |
| REQ-CONS-014 | Pool bounds | narrative | rs/consensus/tests/ |
| REQ-CONS-015 | Membership | narrative | rs/consensus/tests/ |
| REQ-CONS-016 | Block signing | narrative | rs/consensus/tests/ |
| REQ-CONS-017 | Notarization delay | narrative | rs/consensus/tests/ |
| REQ-CONS-018 | Hard notarization limits | narrative | rs/consensus/tests/ |
| REQ-CONS-019 | Finalization conditions | narrative | rs/consensus/tests/ |
| REQ-CONS-020 | CUP creation conditions | narrative | rs/consensus/tests/ |
| REQ-CONS-021 | Payload building sections | narrative | rs/consensus/tests/ |
| REQ-CONS-022 | Consensus status/halting | narrative | rs/consensus/tests/ |
| REQ-CONS-023 | Artifact priority (bouncer) | narrative | rs/consensus/tests/ |
| REQ-CONS-024 | Equivocation proof | narrative | rs/consensus/tests/ |
