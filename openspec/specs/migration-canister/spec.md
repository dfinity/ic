# Migration Canister Specification

**Crates**: `ic-migration-canister`

This specification covers the Migration Canister (`rs/migration_canister/`), which enables cross-subnet canister migration by coordinating the renaming, routing table update, and controller restoration of canisters between subnets.

---

## Requirements

### Requirement: Migration Request Validation

The migration canister validates all migration requests before accepting them for processing.

#### Scenario: Successful validation
- **WHEN** a caller submits a migration request with valid migrated and replaced canister IDs
- **AND** both canisters exist in the registry
- **AND** the canisters are on different subnets
- **AND** the caller is a controller of both canisters
- **AND** the migration canister is a controller of both canisters
- **THEN** the request transitions to the `Accepted` state

#### Scenario: Migrations disabled
- **WHEN** migrations are disabled in the canister configuration
- **THEN** the request is rejected with `ValidationError::MigrationsDisabled`

#### Scenario: Rate limited
- **WHEN** the number of active requests plus successes in the past 24 hours reaches the rate limit (50)
- **THEN** the request is rejected with `ValidationError::RateLimited`

#### Scenario: Validation already in progress
- **WHEN** a validation is already in progress for one of the canisters
- **THEN** the request is rejected with `ValidationError::ValidationInProgress`

#### Scenario: Migration already in progress
- **WHEN** a migration is already in progress for one of the canisters
- **THEN** the request is rejected with `ValidationError::MigrationInProgress`

#### Scenario: Canister not found
- **WHEN** either the migrated or replaced canister does not exist in the registry
- **THEN** the request is rejected with `ValidationError::CanisterNotFound`

#### Scenario: Same subnet
- **WHEN** both canisters are on the same subnet
- **THEN** the request is rejected with `ValidationError::SameSubnet`

#### Scenario: Caller not controller
- **WHEN** the caller is not a controller of one of the canisters
- **THEN** the request is rejected with `ValidationError::CallerNotController`

#### Scenario: Migration canister not controller
- **WHEN** the migration canister itself is not a controller of one of the canisters
- **THEN** the request is rejected with `ValidationError::NotController`

#### Scenario: Migrated canister not stopped
- **WHEN** the migrated canister is not in a stopped state
- **THEN** the request is rejected with `ValidationError::MigratedCanisterNotStopped`

#### Scenario: Replaced canister not stopped
- **WHEN** the replaced canister is not in a stopped state
- **THEN** the request is rejected with `ValidationError::ReplacedCanisterNotStopped`

#### Scenario: Replaced canister has snapshots
- **WHEN** the replaced canister has existing snapshots
- **THEN** the request is rejected with `ValidationError::ReplacedCanisterHasSnapshots`

#### Scenario: Insufficient cycles
- **WHEN** the migrated canister does not have sufficient cycles above the freezing threshold
- **THEN** the request is rejected with `ValidationError::MigratedCanisterInsufficientCycles`

---

### Requirement: Migration State Machine

The migration canister processes requests through a series of states, each performing one effectful operation before transitioning.

#### Scenario: Accepted to ControllersChanged
- **WHEN** a request is in the `Accepted` state
- **THEN** the canister calls `update_settings` on both canisters to make itself the sole controller
- **AND** transitions to `ControllersChanged`

#### Scenario: ControllersChanged to StoppedAndReady
- **WHEN** a request is in the `ControllersChanged` state
- **THEN** the canister verifies both canisters are stopped and ready
- **AND** records canister version, history length, and timestamp
- **AND** transitions to `StoppedAndReady`

#### Scenario: StoppedAndReady to RenamedReplacedCanister
- **WHEN** a request is in the `StoppedAndReady` state
- **THEN** the canister calls `rename_canister` to swap the replaced canister's identity
- **AND** transitions to `RenamedReplacedCanister`

#### Scenario: RenamedReplacedCanister to UpdatedRoutingTable
- **WHEN** a request is in the `RenamedReplacedCanister` state
- **THEN** the canister calls `migrate_canisters` on the registry
- **AND** records the new registry version
- **AND** transitions to `UpdatedRoutingTable`

#### Scenario: UpdatedRoutingTable to RoutingTableChangeAccepted
- **WHEN** a request is in the `UpdatedRoutingTable` state
- **THEN** the canister checks that both subnets have learned about the routing table update
- **AND** transitions to `RoutingTableChangeAccepted`

#### Scenario: RoutingTableChangeAccepted to MigratedCanisterDeleted
- **WHEN** a request is in the `RoutingTableChangeAccepted` state
- **THEN** the canister calls `delete_canister` to delete the migrated canister on its original subnet
- **AND** transitions to `MigratedCanisterDeleted`

#### Scenario: MigratedCanisterDeleted to RestoredControllers
- **WHEN** a request is in the `MigratedCanisterDeleted` state
- **AND** at least six minutes have passed since the canisters were stopped (to let pending messages expire)
- **THEN** the canister restores the original controllers on the replaced canister (now addressed with the migrated canister's ID)
- **AND** transitions to `RestoredControllers`

#### Scenario: RestoredControllers to success event
- **WHEN** a request reaches the `RestoredControllers` state
- **THEN** it transitions to a success event in the history without additional work

---

### Requirement: Migration Failure Recovery

The migration canister handles failures gracefully by restoring controllers on both canisters.

#### Scenario: Transition failure triggers recovery
- **WHEN** any state transition fails fatally
- **THEN** the request transitions to the `Failed` state
- **AND** the canister begins restoring original controllers on both the migrated and replaced canisters

#### Scenario: Controller recovery progress tracking
- **WHEN** a request is in the `Failed` state
- **THEN** the canister tracks recovery progress for each canister independently (`NoProgress`, in-progress, `Done`)
- **AND** only records a failure event in history after both controller restorations are complete

---

### Requirement: Rate Limiting

The migration canister enforces a sliding-window rate limit on migrations.

#### Scenario: Rate limit calculation
- **WHEN** checking if the rate limit is reached
- **THEN** the system counts active requests plus successful migrations in the past 24 hours
- **AND** if the count reaches 50 (RATE_LIMIT), new requests are rejected

#### Scenario: Maximum ongoing validations
- **WHEN** the number of ongoing validation operations reaches 200 (MAX_ONGOING_VALIDATIONS)
- **THEN** new validations are deferred to prevent overwhelming the subnet with XNet calls

---

### Requirement: Cycles Cost

Each migration has a cycles cost that must be covered.

#### Scenario: Cycles cost per migration
- **WHEN** a migration is initiated
- **THEN** 10 trillion cycles (CYCLES_COST_PER_MIGRATION) must be available

---

### Requirement: Periodic Processing

The migration canister uses timer-based periodic processing to advance all in-flight requests.

#### Scenario: Timer-based state advancement
- **WHEN** the canister starts
- **THEN** it sets up 1-second interval timers for each request state
- **AND** each timer processes all requests in the corresponding state
- **AND** attempts to advance them to the next state

#### Scenario: Independent state processing
- **WHEN** multiple requests are in different states
- **THEN** each request is advanced independently by its corresponding timer
