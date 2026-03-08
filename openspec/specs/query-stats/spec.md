# Query Stats Specification

**Crates**: `ic-query-stats`

This specification covers the Query Stats subsystem (`rs/query_stats/`), which collects, aggregates, and delivers statistics about query call execution on the Internet Computer.

---

## Requirements

### Requirement: Query Statistics Collection

The `QueryStatsCollector` collects per-canister query execution statistics on each replica node.

#### Scenario: Register query statistics
- **WHEN** a query call is executed on a replica
- **THEN** `register_query_statistics` is called with the canister ID and stats (num_calls, num_instructions, ingress_payload_size, egress_payload_size)
- **AND** the stats are accumulated into the current epoch's statistics for that canister

#### Scenario: Statistics accumulated per canister
- **WHEN** multiple queries are executed for the same canister within an epoch
- **THEN** the statistics are accumulated using `saturating_accumulate` (saturating addition)
- **AND** individual field overflows are handled gracefully via saturation

#### Scenario: Epoch not set - omit stats
- **WHEN** the epoch has not been set yet
- **THEN** statistics are not recorded
- **AND** an informational message is logged every 30 seconds

---

### Requirement: Epoch Management

The query stats system operates in epochs, with statistics being collected per epoch and then delivered to consensus.

#### Scenario: Set epoch from height
- **WHEN** `set_epoch_from_height` is called with a block height
- **THEN** the epoch is computed as `height / query_stats_epoch_length`

#### Scenario: Epoch transition triggers stats delivery
- **WHEN** the epoch advances to a new value
- **THEN** the statistics from the previous epoch are sent to the payload builder channel
- **AND** the current statistics accumulator is reset for the new epoch

#### Scenario: Epoch unchanged or decreased - no action
- **WHEN** `set_epoch` is called with an epoch that is less than or equal to the current epoch
- **THEN** no stats are sent and no reset occurs
- **AND** this handles concurrent query handler threads with different certified states

#### Scenario: Payload builder channel full
- **WHEN** the epoch transitions but the payload builder channel is full
- **THEN** the previous epoch's stats are dropped
- **AND** a warning is logged indicating consensus may be starving

#### Scenario: Payload builder disconnected
- **WHEN** the epoch transitions but the payload builder has been dropped
- **THEN** a warning is logged indicating a bug

---

### Requirement: Query Stats Payload Building

The `QueryStatsPayloadBuilderImpl` builds consensus block payloads containing query statistics.

#### Scenario: Build payload with current stats
- **WHEN** `build_payload` is called
- **AND** current statistics are available
- **THEN** a payload is built containing the node's ID, the epoch, and per-canister statistics
- **AND** statistics already reported in past payloads or in the certified state are excluded

#### Scenario: Respect size limit
- **WHEN** the total statistics exceed the maximum payload size
- **THEN** the payload is truncated to fit within the size limit
- **AND** remaining statistics will be included in subsequent payloads

#### Scenario: Feature disabled - empty payload
- **WHEN** the query stats aggregation feature is disabled
- **THEN** `build_payload` returns an empty byte vector

#### Scenario: Current stats uninitialized
- **WHEN** no query statistics have been received from the collector yet
- **THEN** an empty payload is returned
- **AND** a warning is logged every 30 seconds

#### Scenario: Current epoch too high
- **WHEN** the current epoch is higher than the epoch matching the certified height
- **THEN** an empty payload is returned to avoid submitting future-epoch data

#### Scenario: Exclude previously reported canister IDs
- **WHEN** building a payload
- **THEN** canister IDs that appear in past payloads (for the same node and epoch) are excluded
- **AND** canister IDs that appear in the certified state (for the same node and epoch) are excluded
- **AND** canister IDs from other nodes' payloads are NOT excluded (per-node independence)

---

### Requirement: Query Stats Payload Validation

The payload builder validates payloads proposed by other nodes.

#### Scenario: Empty payload always valid
- **WHEN** an empty payload is submitted for validation
- **THEN** it passes validation

#### Scenario: Non-empty payload when feature disabled
- **WHEN** a non-empty payload is submitted but the feature is disabled
- **THEN** validation fails with `QueryStatsPayloadValidationFailure::Disabled`

#### Scenario: Deserialization failure
- **WHEN** a payload cannot be deserialized
- **THEN** validation fails with `InvalidQueryStatsPayloadReason::DeserializationFailed`

#### Scenario: Invalid node ID
- **WHEN** the payload's proposer node ID does not match the expected proposer
- **THEN** validation fails with `InvalidQueryStatsPayloadReason::InvalidNodeId`

#### Scenario: Epoch too high
- **WHEN** the payload's epoch is higher than the maximum valid epoch (derived from certified height)
- **THEN** validation fails with `InvalidQueryStatsPayloadReason::EpochTooHigh`

#### Scenario: Epoch already aggregated
- **WHEN** the payload's epoch is at or below the highest aggregated epoch in the state
- **THEN** validation fails with `InvalidQueryStatsPayloadReason::EpochAlreadyAggregated`

#### Scenario: Duplicate canister ID within payload
- **WHEN** a payload contains the same canister ID more than once
- **THEN** validation fails with `InvalidQueryStatsPayloadReason::DuplicateCanisterId`

#### Scenario: Duplicate canister ID with past payloads
- **WHEN** a payload contains a canister ID that was already reported by the same node in the same epoch (in past payloads or state)
- **THEN** validation fails with `InvalidQueryStatsPayloadReason::DuplicateCanisterId`

#### Scenario: Different nodes can report same canister
- **WHEN** two different nodes report statistics for the same canister ID in the same epoch
- **THEN** both payloads pass validation (per-node deduplication only)

---

### Requirement: Query Stats State Machine Delivery

The `deliver_query_stats` function aggregates query statistics from consensus blocks into the replicated state.

#### Scenario: Deliver and aggregate stats
- **WHEN** query stats payloads are finalized in consensus blocks
- **THEN** the statistics are delivered to the replicated state for aggregation
- **AND** the highest aggregated epoch is updated accordingly

---

### Requirement: Metrics

The query stats subsystem reports comprehensive metrics.

#### Scenario: Collector metrics
- **WHEN** statistics are collected
- **THEN** metrics are reported for the current epoch, number of tracked canister IDs, and accumulated stats (calls, instructions, payload sizes)

#### Scenario: Payload builder metrics
- **WHEN** payloads are built or validated
- **THEN** duration metrics are recorded for both `build` and `validate` operations
- **AND** metrics are reported for the current epoch and number of canister IDs in the payload
