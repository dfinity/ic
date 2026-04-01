# Execution: Memory Management Capability Specification

**Source narrative**: `openspec/specs/execution/memory-management.md`
**Crates**: `ic-execution-environment`, `ic-replicated-state`, `ic-embedders`
**Key files**: `rs/replicated_state/src/canister_state/system_state.rs`, `rs/execution_environment/src/`

---

## REQ-MEM-001: Wasm Heap Memory

Each canister MUST have Wasm heap memory initialized from data segments and subject to limits.

### SCENARIO-MEM-001: Heap memory initialization on install
**Given** a canister is installed with a Wasm module
**When** the installation completes
**Then** heap memory is initialized from the module's data segments
**And** the initial size is defined by the module's memory declaration

### SCENARIO-MEM-002: Heap memory growth
**Given** a canister calls the `memory.grow` Wasm instruction
**When** the growth is requested
**Then** heap memory grows by the requested number of Wasm pages (64 KiB each)
**And** growth is subject to canister memory allocation and subnet available memory
**And** growth is subject to `wasm_memory_limit` if set

### SCENARIO-MEM-003: Heap memory 32-bit limit
**Given** a canister attempts to grow heap beyond 4 GiB (64K Wasm pages)
**When** `memory.grow` executes
**Then** `memory.grow` returns -1 (failure)

### SCENARIO-MEM-004: Wasm memory limit enforcement
**Given** a canister has a `wasm_memory_limit` configured
**When** memory growth is attempted
**Then** combined Wasm heap memory cannot exceed this limit
**And** the maximum allowed `wasm_memory_limit` is 2^48 bytes

### SCENARIO-MEM-005: Heap memory cleared on install/reinstall
**Given** a canister is installed or reinstalled
**When** the operation completes
**Then** heap memory is cleared and re-initialized from the new module's data segments

### SCENARIO-MEM-006: Heap memory cleared on standard upgrade
**Given** a standard canister is upgraded
**When** the upgrade completes
**Then** heap memory is cleared and re-initialized from the new module
**And** stable memory is preserved

### SCENARIO-MEM-007: Heap memory preserved on enhanced orthogonal persistence upgrade
**Given** a canister with enhanced orthogonal persistence is upgraded
**When** the upgrade completes
**Then** both heap memory and stable memory are preserved

---

## REQ-MEM-002: Stable Memory

Stable memory MUST persist across canister upgrades and be accessible via System API.

### SCENARIO-MEM-008: Stable memory 32-bit API access
**Given** a canister uses `ic0.stable_size`, `ic0.stable_grow`, `ic0.stable_read`, `ic0.stable_write`
**When** these execute
**Then** stable memory is accessed with 32-bit page addressing (max 4 GiB)

### SCENARIO-MEM-009: Stable memory 64-bit API access
**Given** a canister uses `ic0.stable64_size`, `ic0.stable64_grow`, `ic0.stable64_read`, `ic0.stable64_write`
**When** these execute
**Then** stable memory is accessed with 64-bit addressing up to `MAX_STABLE_MEMORY_IN_BYTES`

### SCENARIO-MEM-010: Stable memory growth
**Given** a canister calls `ic0.stable_grow` or `ic0.stable64_grow`
**When** the growth executes
**Then** stable memory grows by the requested number of Wasm pages
**And** growth is subject to subnet available memory and canister memory allocation

### SCENARIO-MEM-011: Stable memory out-of-bounds access
**Given** a canister reads or writes beyond the current stable memory size
**When** the operation executes
**Then** the operation traps with `StableMemoryOutOfBounds`

### SCENARIO-MEM-012: Stable memory too big for 32-bit API
**Given** stable memory exceeds 4 GiB and the canister uses the 32-bit stable API
**When** the 32-bit operation executes
**Then** the operation traps with `StableMemoryTooBigFor32Bit`
**And** the canister must use the 64-bit API instead

### SCENARIO-MEM-013: Stable memory preserved across upgrades
**Given** a canister is upgraded in standard mode
**When** the upgrade completes
**Then** stable memory contents are fully preserved
**And** `canister_pre_upgrade` can write to stable memory and `canister_post_upgrade` can read it

### SCENARIO-MEM-014: Stable memory cleared on install/reinstall
**Given** a canister is installed or reinstalled
**When** the operation completes
**Then** stable memory is cleared (reset to zero size)

---

## REQ-MEM-003: Memory Allocation

Canisters MUST be able to reserve memory via the `memory_allocation` setting.

### SCENARIO-MEM-015: Guaranteed memory allocation
**Given** a canister has `memory_allocation` set to a non-zero value
**When** the canister is running
**Then** the canister is guaranteed that amount of memory
**And** the allocated memory counts against subnet total available memory

### SCENARIO-MEM-016: Best-effort memory
**Given** a canister has default memory allocation (0, best-effort)
**When** the canister grows memory
**Then** it competes for available subnet memory
**And** growth may fail if the subnet runs out

### SCENARIO-MEM-017: Memory allocation validation
**Given** `memory_allocation` is set via `update_settings`
**When** the update is validated
**Then** the allocation must be at least as large as current total memory usage
**And** the allocation must fit within the remaining subnet memory capacity

---

## REQ-MEM-004: Subnet Memory Management

The subnet MUST enforce overall memory capacity limits across multiple pools.

### SCENARIO-MEM-018: Subnet available memory pools
**Given** the subnet available memory is computed
**When** the computation runs
**Then** it accounts for three separate pools:
  1. Execution memory: `subnet_memory_capacity - subnet_memory_reservation - execution_memory_taken`
  2. Guaranteed response message memory: `guaranteed_response_message_memory_capacity - guaranteed_response_message_memory_taken`
  3. Wasm custom sections memory: `subnet_wasm_custom_sections_memory_capacity - wasm_custom_sections_memory_taken`

### SCENARIO-MEM-019: Subnet available memory scaling for threads
**Given** canister execution happens on multiple threads
**When** available memory is allocated per thread
**Then** subnet available memory is divided by the number of scheduler cores
**And** this prevents over-allocation when multiple threads operate concurrently

### SCENARIO-MEM-020: Subnet memory reservation for response handling
**Given** response handlers need to execute
**When** memory is allocated
**Then** a portion is reserved to ensure responses can be processed
**And** this reservation is `subnet_memory_reservation / scheduler_cores` per thread

---

## REQ-MEM-005: Memory Usage Tracking

Canister memory usage MUST be tracked across all dimensions.

### SCENARIO-MEM-021: Total memory usage components
**Given** canister memory usage is computed
**When** the computation runs
**Then** it includes: Wasm heap, stable memory, message memory, Wasm custom sections, canister history, snapshots, Wasm chunk store, log memory store

### SCENARIO-MEM-022: Memory usage for billing
**Given** storage costs are computed
**When** billable memory is determined
**Then** it equals `max(memory_allocation, actual_memory_usage)`
**And** message memory is billed separately

---

## REQ-MEM-006: Dirty Page Tracking

Modified memory pages MUST be tracked for state persistence and rate limiting.

### SCENARIO-MEM-023: Dirty page detection
**Given** a Wasm execution modifies a heap or stable memory page
**When** the execution completes
**Then** the modified page is marked as dirty
**And** the dirty page count contributes to the heap delta

### SCENARIO-MEM-024: Dirty page overhead charging
**Given** dirty pages are detected after execution
**When** overhead is charged
**Then** additional instructions are charged: `dirty_page_count * dirty_page_overhead`
**And** this overhead is added to total instructions used by the execution

### SCENARIO-MEM-025: Heap delta accumulation and rate limiting
**Given** execution produces dirty pages
**When** the heap delta is updated
**Then** the canister's heap delta increases by `dirty_page_count * page_size`
**And** the subnet's heap delta estimate increases accordingly
**And** excessive heap delta triggers rate limiting of the canister

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-MEM-001 | Wasm heap memory | narrative | rs/execution_environment/tests/ |
| REQ-MEM-002 | Stable memory | narrative | rs/execution_environment/tests/ |
| REQ-MEM-003 | Memory allocation | narrative | rs/execution_environment/tests/ |
| REQ-MEM-004 | Subnet memory | narrative | rs/execution_environment/tests/ |
| REQ-MEM-005 | Usage tracking | narrative | rs/execution_environment/tests/ |
| REQ-MEM-006 | Dirty page tracking | narrative | rs/execution_environment/tests/ |
