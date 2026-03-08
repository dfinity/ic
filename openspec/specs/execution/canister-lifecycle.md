# Canister Lifecycle

This specification covers canister creation, code installation, upgrades, uninstallation, start, stop, and deletion.

## Requirements

### Requirement: Canister Creation

Canisters are created via the `create_canister` management canister method.

#### Scenario: Successful canister creation
- **WHEN** a controller calls `create_canister` with sufficient cycles
- **THEN** a new canister is created with a unique `CanisterId`
- **AND** the canister is in the `Running` state with no installed code
- **AND** the specified controllers are set (or the caller is the sole controller if none specified)
- **AND** the canister creation fee is charged

#### Scenario: Canister creation with settings
- **WHEN** `create_canister` is called with optional settings (compute_allocation, memory_allocation, freezing_threshold, controllers, reserved_cycles_limit, log_visibility, wasm_memory_limit)
- **THEN** the canister is created with those settings applied
- **AND** compute allocation is validated against available subnet capacity
- **AND** memory allocation is validated against available subnet memory

#### Scenario: Canister creation via ingress
- **WHEN** a user sends an ingress message to `create_canister`
- **THEN** the request is accepted only if the sender is a subnet admin
- **AND** rejected otherwise with `CanisterRejectedMessage`

#### Scenario: Provisional canister creation
- **WHEN** `provisional_create_canister_with_cycles` is called on a subnet that allows it
- **THEN** the canister is created with the specified cycles balance (or default if not specified)
- **AND** this is only available on non-production subnets or from whitelisted callers

### Requirement: Code Installation (install_code)

Code is installed via the `install_code` management canister method in one of three modes: `install`, `reinstall`, or `upgrade`.

#### Scenario: Fresh install mode
- **WHEN** `install_code` is called with mode `install` on a canister with no existing code
- **THEN** a new execution state is created from the Wasm module
- **AND** the `start()` function is called if exported
- **AND** the `canister_init()` function is called if exported, with the provided argument
- **AND** certified data is cleared, canister logs are cleared, global timer is deactivated
- **AND** the canister version is bumped
- **AND** a canister change record is added

#### Scenario: Install fails if code already exists
- **WHEN** `install_code` is called with mode `install` on a canister that already has installed code
- **THEN** the operation fails with an error indicating code is already installed

#### Scenario: Reinstall mode
- **WHEN** `install_code` is called with mode `reinstall`
- **THEN** the existing execution state is replaced entirely (both heap and stable memory are cleared)
- **AND** the same steps as fresh install are performed (start, canister_init)
- **AND** certified data is cleared, canister logs are cleared, global timer is deactivated

#### Scenario: Upgrade mode
- **WHEN** `install_code` is called with mode `upgrade`
- **THEN** the upgrade follows these stages:
  1. Validate input
  2. Execute `canister_pre_upgrade()` using the old code (if exported and not skipped)
  3. Create new execution state from new Wasm, deactivate global timer, bump version
  4. Execute `start()` if exported by the new code
  5. Execute `canister_post_upgrade()` if exported by the new code
  6. Finalize and refund execution cycles
- **AND** stable memory is preserved across the upgrade (for standard canisters)
- **AND** heap memory is cleared and re-initialized from the new Wasm

#### Scenario: Upgrade with skip_pre_upgrade
- **WHEN** `install_code` is called with mode `upgrade` and `skip_pre_upgrade` option set to true
- **THEN** `canister_pre_upgrade()` is not executed
- **AND** the upgrade proceeds directly to creating the new execution state

#### Scenario: Upgrade with enhanced orthogonal persistence
- **WHEN** a canister's Wasm module contains the `enhanced-orthogonal-persistence` custom section
- **THEN** both main memory and stable memory are preserved during upgrade (Motoko-style persistence)

#### Scenario: Install code with DTS
- **WHEN** an `install_code` execution exceeds the slice instruction limit
- **THEN** the execution is paused and can be resumed in subsequent rounds
- **AND** only one long-running `install_code` can be active per canister at a time
- **AND** other install_code messages for the same canister are blocked until the current one completes

#### Scenario: Install code validation
- **WHEN** `install_code` is called
- **THEN** the caller must be a controller of the canister
- **AND** the Wasm module must pass validation
- **AND** sufficient cycles must be available to pay for compilation and execution

#### Scenario: Install from chunk store
- **WHEN** `install_chunked_code` is called with chunk hashes
- **THEN** the Wasm module is assembled from chunks previously uploaded to the chunk store
- **AND** the assembled module hash must match the provided `wasm_module_hash`

### Requirement: Canister Uninstallation

Uninstalling a canister removes its code but preserves the canister ID and cycles balance.

#### Scenario: Uninstall code
- **WHEN** `uninstall_code` is called by a controller
- **THEN** the canister's execution state is removed
- **AND** all pending messages in input and output queues are rejected
- **AND** all open call contexts are closed with refunds
- **AND** certified data is cleared
- **AND** the canister version is bumped

### Requirement: Canister Start and Stop

Canisters can be started and stopped to control message processing.

#### Scenario: Stop canister
- **WHEN** `stop_canister` is called by a controller
- **THEN** the canister transitions to `Stopping` status
- **AND** the canister rejects new incoming messages
- **AND** the canister continues to process responses to outstanding calls
- **AND** once all outstanding call contexts are closed, the canister transitions to `Stopped`
- **AND** the caller receives a response once the canister is fully stopped

#### Scenario: Stop canister that is already stopped
- **WHEN** `stop_canister` is called on an already stopped canister
- **THEN** the operation succeeds immediately (AlreadyStopped)

#### Scenario: Start canister
- **WHEN** `start_canister` is called on a stopped canister
- **THEN** the canister transitions to `Running` status
- **AND** the canister can receive and process new messages

#### Scenario: Start canister that is already running
- **WHEN** `start_canister` is called on an already running canister
- **THEN** the operation succeeds as a no-op

### Requirement: Canister Deletion

Deleting a canister permanently removes it.

#### Scenario: Delete stopped canister
- **WHEN** `delete_canister` is called on a stopped canister by its controller
- **THEN** the canister is permanently removed
- **AND** its remaining cycles are burned
- **AND** the canister ID cannot be reused

#### Scenario: Delete running canister fails
- **WHEN** `delete_canister` is called on a running or stopping canister
- **THEN** the operation fails because the canister must be stopped first

### Requirement: Canister Settings Updates

Canister settings can be modified via `update_settings`.

#### Scenario: Update controllers
- **WHEN** `update_settings` is called to change the controller list
- **THEN** the new controllers are set (up to the maximum number of controllers)
- **AND** only existing controllers can modify the controller list

#### Scenario: Update compute allocation
- **WHEN** `update_settings` is called with a new compute_allocation
- **THEN** the allocation is validated (0-100%) against available subnet capacity
- **AND** the canister's scheduling priority is updated accordingly

#### Scenario: Update memory allocation
- **WHEN** `update_settings` is called with a new memory_allocation
- **THEN** the allocation is validated against available subnet memory
- **AND** the allocation must be at least as large as the canister's current memory usage

#### Scenario: Update freezing threshold
- **WHEN** `update_settings` is called with a new freezing_threshold
- **THEN** the threshold is updated
- **AND** cycles operations will use the new threshold to determine the freeze limit

#### Scenario: Update wasm memory limit
- **WHEN** `update_settings` is called with a new wasm_memory_limit
- **THEN** the Wasm memory limit is updated (max 2^48 bytes)
- **AND** Wasm memory growth operations will be bounded by this limit

#### Scenario: Update log visibility
- **WHEN** `update_settings` is called with a new log_visibility
- **THEN** log access permissions are updated to one of: `Public`, `Controllers`, or `AllowedViewers(principals)`

#### Scenario: Update reserved cycles limit
- **WHEN** `update_settings` is called with a new reserved_cycles_limit
- **THEN** the limit on cycles that can be moved to the reserved balance is updated

#### Scenario: Update environment variables
- **WHEN** `update_settings` is called with environment variables
- **THEN** the canister's environment variables are set
- **AND** variable names and values must respect configured size limits

### Requirement: Wasm Chunk Store

Large Wasm modules can be uploaded in chunks before installation.

#### Scenario: Upload chunk
- **WHEN** `upload_chunk` is called with a data chunk
- **THEN** the chunk is stored in the canister's chunk store
- **AND** the chunk hash is returned
- **AND** instructions are charged proportional to chunk size

#### Scenario: List stored chunks
- **WHEN** `stored_chunks` is called
- **THEN** all chunk hashes currently in the store are returned

#### Scenario: Clear chunk store
- **WHEN** `clear_chunk_store` is called
- **THEN** all stored chunks are removed
