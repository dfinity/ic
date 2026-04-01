# Execution: Canister Lifecycle Capability Specification

**Source narrative**: `openspec/specs/execution/canister-lifecycle.md`
**Crates**: `ic-execution-environment`, `ic-canister-manager`
**Key files**: `rs/execution_environment/src/canister_manager.rs`, `rs/execution_environment/src/canister_manager/tests.rs`

---

## REQ-EXEC-001: Canister Creation

The system MUST create canisters via the `create_canister` management canister method.

### SCENARIO-EXEC-001: Successful canister creation
**Given** a controller calls `create_canister` with sufficient cycles
**When** the request is processed
**Then** a new canister is created with a unique `CanisterId`
**And** the canister is in the `Running` state with no installed code
**And** the specified controllers are set (or caller is sole controller if none specified)
**And** the canister creation fee is charged

### SCENARIO-EXEC-002: Canister creation with settings
**Given** `create_canister` is called with optional settings
**When** settings (compute_allocation, memory_allocation, freezing_threshold, controllers, etc.) are provided
**Then** the canister is created with those settings applied
**And** compute allocation is validated against available subnet capacity
**And** memory allocation is validated against available subnet memory

### SCENARIO-EXEC-003: Canister creation via ingress rejected for non-admins
**Given** a user sends an ingress message to `create_canister`
**When** the sender is not a subnet admin
**Then** the request is rejected with `CanisterRejectedMessage`

### SCENARIO-EXEC-004: Provisional canister creation
**Given** `provisional_create_canister_with_cycles` is called on a subnet that allows it
**When** the request is processed
**Then** the canister is created with the specified cycles balance
**And** this is only available on non-production subnets or from whitelisted callers

---

## REQ-EXEC-002: Code Installation (install_code)

The system MUST support installing code via `install_code` in three modes: `install`, `reinstall`, `upgrade`.

### SCENARIO-EXEC-005: Fresh install mode
**Given** `install_code` is called with mode `install` on a canister with no existing code
**When** the installation is processed
**Then** a new execution state is created from the Wasm module
**And** `start()` is called if exported, then `canister_init()` if exported with the provided argument
**And** certified data is cleared, canister logs are cleared, global timer is deactivated
**And** the canister version is bumped and a change record is added

### SCENARIO-EXEC-006: Install fails if code already exists
**Given** `install_code` is called with mode `install` on a canister with installed code
**When** the request is processed
**Then** the operation fails with an error indicating code is already installed

### SCENARIO-EXEC-007: Reinstall mode
**Given** `install_code` is called with mode `reinstall`
**When** the installation is processed
**Then** the existing execution state is replaced entirely (heap and stable memory cleared)
**And** the same post-install steps execute as fresh install

### SCENARIO-EXEC-008: Upgrade mode stages
**Given** `install_code` is called with mode `upgrade`
**When** the upgrade executes
**Then** stages execute in order: validate → `canister_pre_upgrade()` → create new state → `start()` → `canister_post_upgrade()`
**And** stable memory is preserved across the upgrade
**And** heap memory is cleared and re-initialized from the new Wasm

### SCENARIO-EXEC-009: Upgrade with skip_pre_upgrade
**Given** `install_code` is called with mode `upgrade` and `skip_pre_upgrade = true`
**When** the upgrade executes
**Then** `canister_pre_upgrade()` is not called
**And** the upgrade proceeds directly to creating the new execution state

### SCENARIO-EXEC-010: Enhanced orthogonal persistence upgrade
**Given** a canister's Wasm contains the `enhanced-orthogonal-persistence` custom section
**When** the canister is upgraded
**Then** both main memory and stable memory are preserved (Motoko-style persistence)

### SCENARIO-EXEC-011: Install code with DTS
**Given** an `install_code` execution exceeds the slice instruction limit
**When** execution is paused
**Then** the execution is resumed in subsequent rounds
**And** only one long-running `install_code` can be active per canister
**And** other install_code messages for the same canister are blocked

### SCENARIO-EXEC-012: Install code validation
**Given** `install_code` is called
**When** validation runs
**Then** the caller must be a controller of the canister
**And** the Wasm module must pass validation
**And** sufficient cycles must be available

### SCENARIO-EXEC-013: Install from chunk store
**Given** `install_chunked_code` is called with chunk hashes
**When** the installation is processed
**Then** the Wasm module is assembled from previously uploaded chunks
**And** the assembled module hash must match the provided `wasm_module_hash`

---

## REQ-EXEC-003: Canister Uninstallation

`uninstall_code` MUST remove canister code while preserving the canister ID and cycles balance.

### SCENARIO-EXEC-014: Uninstall code
**Given** `uninstall_code` is called by a controller
**When** the uninstallation is processed
**Then** the canister's execution state is removed
**And** all pending messages in queues are rejected
**And** all open call contexts are closed with refunds
**And** certified data is cleared and the canister version is bumped

---

## REQ-EXEC-004: Canister Start and Stop

The system MUST support stopping and starting canisters to control message processing.

### SCENARIO-EXEC-015: Stop canister
**Given** `stop_canister` is called by a controller on a running canister
**When** the stop is processed
**Then** the canister transitions to `Stopping` status
**And** new incoming messages are rejected
**And** outstanding call context responses continue to be processed
**And** once all call contexts are closed, the canister transitions to `Stopped`

### SCENARIO-EXEC-016: Stop already-stopped canister
**Given** `stop_canister` is called on an already stopped canister
**When** the request is processed
**Then** the operation succeeds immediately (AlreadyStopped)

### SCENARIO-EXEC-017: Start canister
**Given** `start_canister` is called on a stopped canister
**When** the start is processed
**Then** the canister transitions to `Running` status and can receive new messages

### SCENARIO-EXEC-018: Start already-running canister
**Given** `start_canister` is called on an already running canister
**When** the request is processed
**Then** the operation succeeds as a no-op

---

## REQ-EXEC-005: Canister Deletion

`delete_canister` MUST permanently remove a stopped canister.

### SCENARIO-EXEC-019: Delete stopped canister
**Given** `delete_canister` is called on a stopped canister by its controller
**When** the deletion is processed
**Then** the canister is permanently removed and its remaining cycles are burned
**And** the canister ID cannot be reused

### SCENARIO-EXEC-020: Delete running canister fails
**Given** `delete_canister` is called on a running or stopping canister
**When** the request is processed
**Then** the operation fails because the canister must be stopped first

---

## REQ-EXEC-006: Canister Settings Updates

`update_settings` MUST allow controllers to modify canister configuration.

### SCENARIO-EXEC-021: Update controllers
**Given** `update_settings` is called to change the controller list
**When** the update is processed
**Then** the new controllers are set (up to the maximum number of controllers)
**And** only existing controllers can modify the controller list

### SCENARIO-EXEC-022: Update compute allocation
**Given** `update_settings` is called with a new compute_allocation
**When** the update is processed
**Then** the allocation (0-100%) is validated against available subnet capacity
**And** the canister's scheduling priority is updated accordingly

### SCENARIO-EXEC-023: Update memory allocation
**Given** `update_settings` is called with a new memory_allocation
**When** the update is processed
**Then** the allocation is validated against available subnet memory
**And** the allocation must be at least as large as current memory usage

### SCENARIO-EXEC-024: Update freezing threshold
**Given** `update_settings` is called with a new freezing_threshold
**When** the update is processed
**Then** the threshold is updated and subsequent cycles operations use the new threshold

### SCENARIO-EXEC-025: Update wasm_memory_limit
**Given** `update_settings` is called with a new wasm_memory_limit
**When** the update is processed
**Then** the Wasm memory limit is updated (max 2^48 bytes)
**And** subsequent Wasm memory growth is bounded by this limit

### SCENARIO-EXEC-026: Update log_visibility
**Given** `update_settings` is called with a new log_visibility
**When** the update is processed
**Then** log access is updated to one of: `Public`, `Controllers`, `AllowedViewers(principals)`

### SCENARIO-EXEC-027: Update reserved_cycles_limit
**Given** `update_settings` is called with a new reserved_cycles_limit
**When** the update is processed
**Then** the limit on cycles that can be moved to the reserved balance is updated

### SCENARIO-EXEC-028: Update environment variables
**Given** `update_settings` is called with environment variables
**When** the update is processed
**Then** the canister's environment variables are set
**And** names and values must respect configured size limits

---

## REQ-EXEC-007: Wasm Chunk Store

Large Wasm modules MUST be uploadable in chunks before installation.

### SCENARIO-EXEC-029: Upload chunk
**Given** `upload_chunk` is called with a data chunk
**When** the upload is processed
**Then** the chunk is stored and its hash is returned
**And** instructions are charged proportional to chunk size

### SCENARIO-EXEC-030: List stored chunks
**Given** `stored_chunks` is called
**When** the request is processed
**Then** all chunk hashes currently in the store are returned

### SCENARIO-EXEC-031: Clear chunk store
**Given** `clear_chunk_store` is called
**When** the request is processed
**Then** all stored chunks are removed

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-EXEC-001 | Canister creation | narrative | canister_manager/tests.rs |
| REQ-EXEC-002 | Code installation | narrative | canister_manager/tests.rs |
| REQ-EXEC-003 | Uninstallation | narrative | canister_manager/tests.rs |
| REQ-EXEC-004 | Start/Stop | narrative | canister_manager/tests.rs |
| REQ-EXEC-005 | Deletion | narrative | canister_manager/tests.rs |
| REQ-EXEC-006 | Settings updates | narrative | canister_manager/tests.rs |
| REQ-EXEC-007 | Chunk store | narrative | canister_manager/tests.rs |
