# Boundary Node Salt Sharing Canister

**Crates:** `salt_sharing`, `salt-sharing-api`, `salt-sharing-canister-integration-tests`

**Source:** `rs/boundary_node/salt_sharing/`

## Overview

The Salt Sharing Canister generates, stores, and distributes a cryptographic salt to authorized API boundary nodes on the Internet Computer. The salt is a 32-byte random value obtained from the management canister's `raw_rand` call, regenerated on a monthly schedule (at the start of each month, UTC). Only API boundary node principals (fetched from the NNS registry) are authorized to retrieve the salt. The salt and its generation timestamp (`salt_id`) are persisted in IC stable memory to survive canister upgrades.

---

## Requirements

### Requirement: Canister Initialization

The canister initializes the salt and sets up recurring tasks on first install or upgrade.

#### Scenario: First installation generates salt if not present
- **WHEN** the canister is installed for the first time with an `InitArg` where `regenerate_now` is `false`
- **THEN** if no salt exists in stable memory, a new 32-byte salt is generated via `raw_rand` on the management canister
- **AND** the salt and current timestamp (`salt_id`) are stored in stable memory
- **AND** a monthly salt regeneration schedule is started based on `salt_generation_strategy`
- **AND** a periodic timer is set to poll the NNS registry for API boundary node IDs at `registry_polling_interval_secs`

#### Scenario: First installation with regenerate_now forces salt generation
- **WHEN** the canister is installed with `InitArg` where `regenerate_now` is `true`
- **THEN** a new salt is generated regardless of whether one already exists
- **AND** the previous salt (if any) is overwritten in stable memory

#### Scenario: Upgrade preserves salt and re-initializes timers
- **WHEN** the canister is upgraded with an `InitArg`
- **THEN** the same initialization logic runs as on first install
- **AND** the existing salt in stable memory persists across upgrades (unless `regenerate_now` is `true`)
- **AND** the `last_canister_change_time` metric is updated

#### Scenario: Salt generation failure is logged
- **WHEN** the call to `raw_rand` on the management canister fails during initialization
- **THEN** a P0 log entry is recorded with the error details
- **AND** the canister continues to operate (the salt may not be available until next successful generation)

---

### Requirement: Monthly Salt Regeneration

The salt is regenerated at the start of each calendar month (UTC).

#### Scenario: Salt regeneration at start of next month
- **WHEN** the `SaltGenerationStrategy::StartOfMonth` strategy is configured
- **THEN** a timer is set to fire at midnight UTC on the 1st of the next month
- **AND** when the timer fires, a new 32-byte salt is generated and stored
- **AND** the `salt_id` is updated to the current timestamp
- **AND** the next monthly regeneration is recursively scheduled

#### Scenario: Delay calculation for next month
- **WHEN** the current date is February 27, 2024 at 11:30 UTC (leap year)
- **THEN** the delay until the next month is 2 days, 12 hours, 30 minutes (until March 1, 00:00 UTC)

#### Scenario: December to January transition
- **WHEN** the current month is December
- **THEN** the next regeneration is scheduled for January 1st of the following year

#### Scenario: Scheduled regeneration failure is logged
- **WHEN** salt regeneration fails during the scheduled monthly timer
- **THEN** a P0 log entry is recorded with `[scheduled_regenerate_salt_failed]`
- **AND** the next monthly regeneration is still scheduled (the recursive schedule continues)

---

### Requirement: Salt Retrieval

Only authorized API boundary node principals can retrieve the salt.

#### Scenario: Authorized API boundary node retrieves salt
- **WHEN** a caller whose principal is in the API boundary node set calls `get_salt`
- **THEN** the response contains the `SaltResponse` with the current `salt` (32 bytes) and `salt_id` (timestamp)

#### Scenario: Salt not yet initialized
- **WHEN** an authorized caller calls `get_salt` before the salt has been generated
- **THEN** the response is `GetSaltError::SaltNotInitialized`

#### Scenario: Unauthorized caller is rejected
- **WHEN** a caller whose principal is not in the API boundary node set calls `get_salt`
- **THEN** the response is `GetSaltError::Unauthorized`

---

### Requirement: Access Control via Ingress Inspection

The canister rejects unauthorized calls at the pre-consensus phase.

#### Scenario: Authorized boundary node calls get_salt
- **WHEN** an API boundary node principal calls the `get_salt` method
- **THEN** the message passes inspection and is accepted for consensus

#### Scenario: Non-boundary-node caller is rejected at inspection
- **WHEN** any principal that is not an API boundary node calls `get_salt`
- **THEN** the message is rejected with "method call is prohibited in the current context"
- **AND** no consensus resources are consumed

#### Scenario: Any method other than get_salt is rejected
- **WHEN** any caller invokes a method other than `get_salt`
- **THEN** the message is rejected at the inspection phase

---

### Requirement: API Boundary Node Registry Polling

The canister periodically polls the NNS registry to maintain the set of authorized principals.

#### Scenario: Successful registry poll
- **WHEN** the periodic timer fires and the registry returns API boundary node records
- **THEN** the `API_BOUNDARY_NODE_PRINCIPALS` set is replaced with the new set of node IDs
- **AND** the `last_successful_registry_poll_time` metric is updated

#### Scenario: Registry poll failure
- **WHEN** the registry canister call fails
- **THEN** the existing set of authorized principals remains unchanged
- **AND** a P0 log entry is recorded
- **AND** the `registry_poll_calls` failure counter metric is incremented

---

### Requirement: Observability

The canister exposes metrics and logs via HTTP endpoints.

#### Scenario: Metrics endpoint
- **WHEN** an HTTP request is made to `/metrics`
- **THEN** Prometheus-formatted metrics are returned including `last_canister_change_time`, `last_successful_registry_poll_time`, and `registry_poll_calls`

#### Scenario: Logs endpoint
- **WHEN** an HTTP request is made to `/logs`
- **THEN** JSON-formatted log entries are returned including P0 and P1 priority entries
- **AND** an optional `time` query parameter filters entries to those at or after the given timestamp

---

### Requirement: Stable Memory Persistence

The salt and its metadata survive canister upgrades.

#### Scenario: Salt survives upgrade
- **WHEN** the canister is upgraded
- **THEN** the `StorableSalt` (containing `salt` and `salt_id`) stored in stable memory via `StableBTreeMap` is preserved
- **AND** the CBOR-serialized format is used for stable memory encoding/decoding

#### Scenario: API boundary node principals are re-fetched after upgrade
- **WHEN** the canister is upgraded
- **THEN** the in-memory `API_BOUNDARY_NODE_PRINCIPALS` set is initially empty (it is not in stable memory)
- **AND** the periodic registry polling timer repopulates the set from the registry
