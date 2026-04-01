# Query Stats Capability Specification

**Source narrative**: `openspec/specs/query-stats/spec.md`
**Crates**: `ic-query-stats`
**Key files**: `rs/query_stats/src/`

---

## REQ-QS-001: Query Statistics Collection

The `QueryStatsCollector` MUST collect per-canister query execution statistics on each replica.

### SCENARIO-QS-001: Register query statistics
**Given** a query call is executed on a replica
**When** `register_query_statistics` is called
**Then** the stats (num_calls, num_instructions, ingress_payload_size, egress_payload_size) are accumulated for that canister in the current epoch
**And** accumulation uses `saturating_accumulate` (saturation on overflow)

### SCENARIO-QS-002: Epoch not set — omit stats
**Given** the epoch has not been set yet
**When** statistics would be recorded
**Then** statistics are not recorded
**And** an informational message is logged every 30 seconds

---

## REQ-QS-002: Epoch Management

Query stats MUST operate in epochs, with stats delivered to consensus at epoch transitions.

### SCENARIO-QS-003: Set epoch from height
**Given** `set_epoch_from_height` is called with a block height
**When** the epoch is computed
**Then** epoch = `height / query_stats_epoch_length`

### SCENARIO-QS-004: Epoch transition triggers stats delivery
**Given** the epoch advances to a new value
**When** the transition is processed
**Then** statistics from the previous epoch are sent to the payload builder channel
**And** the current statistics accumulator is reset for the new epoch

### SCENARIO-QS-005: Epoch unchanged — no action
**Given** `set_epoch` is called with an epoch ≤ the current epoch
**When** the call processes
**Then** no stats are sent and no reset occurs

### SCENARIO-QS-006: Payload builder channel full
**Given** the epoch transitions but the payload builder channel is full
**When** the transition is processed
**Then** the previous epoch's stats are dropped
**And** a warning is logged indicating consensus may be starving

---

## REQ-QS-003: Query Stats Payload Building

The payload builder MUST build consensus payloads containing query statistics.

### SCENARIO-QS-007: Build payload with current stats
**Given** `build_payload` is called and current statistics are available
**When** the payload is built
**Then** it contains the node's ID, epoch, and per-canister statistics
**And** statistics already in past payloads or the certified state are excluded

### SCENARIO-QS-008: Respect size limit
**Given** total statistics exceed the maximum payload size
**When** building runs
**Then** the payload is truncated to fit within the size limit
**And** remaining statistics are included in subsequent payloads

### SCENARIO-QS-009: Exclude previously reported canister IDs
**Given** building a payload
**When** deduplication runs
**Then** canister IDs in past payloads (same node and epoch) are excluded
**And** canister IDs in the certified state (same node and epoch) are excluded
**And** canister IDs from other nodes' payloads are NOT excluded (per-node independence)

---

## REQ-QS-004: Query Stats Payload Validation

The payload builder MUST validate payloads proposed by other nodes.

### SCENARIO-QS-010: Empty payload always valid
**Given** an empty payload is submitted for validation
**When** validation runs
**Then** it passes validation

### SCENARIO-QS-011: Non-empty payload when feature disabled
**Given** a non-empty payload is submitted but the feature is disabled
**When** validation runs
**Then** validation fails with `QueryStatsPayloadValidationFailure::Disabled`

### SCENARIO-QS-012: Invalid node ID
**Given** the payload's proposer node ID does not match the expected proposer
**When** validation runs
**Then** validation fails with `InvalidQueryStatsPayloadReason::InvalidNodeId`

### SCENARIO-QS-013: Epoch too high
**Given** the payload's epoch is higher than the maximum valid epoch
**When** validation runs
**Then** validation fails with `InvalidQueryStatsPayloadReason::EpochTooHigh`

### SCENARIO-QS-014: Duplicate canister ID in payload
**Given** a payload contains the same canister ID more than once (or seen in past payloads for same node/epoch)
**When** validation runs
**Then** validation fails with `InvalidQueryStatsPayloadReason::DuplicateCanisterId`

### SCENARIO-QS-015: Different nodes can report same canister
**Given** two different nodes report statistics for the same canister ID in the same epoch
**When** validation runs for both
**Then** both payloads pass validation (per-node deduplication only)

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-QS-001 | Stats collection | narrative | rs/query_stats/tests/ |
| REQ-QS-002 | Epoch management | narrative | rs/query_stats/tests/ |
| REQ-QS-003 | Payload building | narrative | rs/query_stats/tests/ |
| REQ-QS-004 | Payload validation | narrative | rs/query_stats/tests/ |
