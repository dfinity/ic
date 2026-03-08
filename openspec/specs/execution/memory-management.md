# Memory Management

This specification covers heap memory, stable memory, memory allocation, and memory limits for canisters.

## Requirements

### Requirement: Wasm Heap Memory

Each canister has a Wasm heap memory that is initialized from the Wasm module's data segments.

#### Scenario: Heap memory initialization on install
- **WHEN** a canister is installed with a Wasm module
- **THEN** heap memory is initialized from the module's data segments
- **AND** the initial memory size is defined by the module's memory declaration

#### Scenario: Heap memory growth
- **WHEN** a canister calls `memory.grow` (Wasm instruction)
- **THEN** the heap memory grows by the requested number of Wasm pages (64 KiB each)
- **AND** the growth is subject to the canister's memory allocation and subnet available memory
- **AND** the growth is subject to the Wasm memory limit if set

#### Scenario: Heap memory limit (32-bit)
- **WHEN** a canister attempts to grow heap memory beyond 4 GiB (64K Wasm pages)
- **THEN** `memory.grow` returns -1 (failure)

#### Scenario: Wasm memory limit enforcement
- **WHEN** a canister has a `wasm_memory_limit` set
- **THEN** the combined Wasm heap memory cannot exceed this limit
- **AND** the maximum allowed `wasm_memory_limit` is 2^48 bytes

#### Scenario: Heap memory cleared on install/reinstall
- **WHEN** a canister is installed or reinstalled
- **THEN** heap memory is cleared and re-initialized from the new module's data segments

#### Scenario: Heap memory cleared on upgrade (standard)
- **WHEN** a standard canister is upgraded
- **THEN** heap memory is cleared and re-initialized from the new module
- **AND** stable memory is preserved

#### Scenario: Heap memory preserved on upgrade (enhanced orthogonal persistence)
- **WHEN** a canister with enhanced orthogonal persistence is upgraded
- **THEN** both heap memory and stable memory are preserved

### Requirement: Stable Memory

Stable memory is a secondary memory area that persists across upgrades.

#### Scenario: Stable memory access (32-bit API)
- **WHEN** a canister uses `ic0.stable_size`, `ic0.stable_grow`, `ic0.stable_read`, `ic0.stable_write`
- **THEN** stable memory is accessed using 32-bit page addressing
- **AND** the maximum addressable stable memory via 32-bit API is 4 GiB (64K Wasm pages)

#### Scenario: Stable memory access (64-bit API)
- **WHEN** a canister uses `ic0.stable64_size`, `ic0.stable64_grow`, `ic0.stable64_read`, `ic0.stable64_write`
- **THEN** stable memory is accessed using 64-bit addressing
- **AND** the maximum stable memory size is defined by `MAX_STABLE_MEMORY_IN_BYTES`

#### Scenario: Stable memory growth
- **WHEN** a canister calls `ic0.stable_grow` or `ic0.stable64_grow`
- **THEN** stable memory grows by the requested number of Wasm pages
- **AND** growth is subject to subnet available memory and canister memory allocation

#### Scenario: Stable memory out of bounds
- **WHEN** a canister attempts to read or write beyond the current stable memory size
- **THEN** the operation traps with `StableMemoryOutOfBounds`

#### Scenario: Stable memory too big for 32-bit API
- **WHEN** stable memory exceeds 4 GiB and the canister uses the 32-bit stable API
- **THEN** the 32-bit API operations trap with `StableMemoryTooBigFor32Bit`
- **AND** the canister must use the 64-bit API instead

#### Scenario: Stable memory preserved across upgrades
- **WHEN** a canister is upgraded (standard mode)
- **THEN** stable memory contents are fully preserved
- **AND** the `canister_pre_upgrade` callback can write final state to stable memory
- **AND** the `canister_post_upgrade` callback can read the preserved state

#### Scenario: Stable memory cleared on install/reinstall
- **WHEN** a canister is installed or reinstalled
- **THEN** stable memory is cleared (reset to zero size)

### Requirement: Memory Allocation

Canisters can reserve memory via the memory_allocation setting.

#### Scenario: Guaranteed memory allocation
- **WHEN** a canister has `memory_allocation` set to a non-zero value
- **THEN** the canister is guaranteed that amount of memory
- **AND** the allocated memory counts against the subnet's total available memory
- **AND** the canister can use up to its allocation without competing for subnet memory

#### Scenario: Best-effort memory (no allocation)
- **WHEN** a canister has default memory allocation (0, best-effort)
- **THEN** the canister competes for available subnet memory
- **AND** memory growth may fail if the subnet runs out of available memory

#### Scenario: Memory allocation validation
- **WHEN** `memory_allocation` is set via `update_settings`
- **THEN** the allocation must be at least as large as the canister's current total memory usage
- **AND** the allocation must fit within the remaining subnet memory capacity

### Requirement: Subnet Memory Management

The subnet has overall memory capacity limits.

#### Scenario: Subnet available memory
- **WHEN** the subnet available memory is computed
- **THEN** it accounts for three separate pools:
  1. Execution memory: `subnet_memory_capacity - subnet_memory_reservation - execution_memory_taken`
  2. Guaranteed response message memory: `guaranteed_response_message_memory_capacity - guaranteed_response_message_memory_taken`
  3. Wasm custom sections memory: `subnet_wasm_custom_sections_memory_capacity - wasm_custom_sections_memory_taken`

#### Scenario: Subnet available memory scaling
- **WHEN** canister execution happens on multiple threads
- **THEN** the subnet available memory is divided by the number of scheduler cores
- **AND** this prevents over-allocation when multiple threads operate concurrently

#### Scenario: Subnet memory reservation for response handling
- **WHEN** response handlers need to execute
- **THEN** a portion of subnet memory is reserved to ensure responses can be processed
- **AND** this reservation is `subnet_memory_reservation / scheduler_cores` per thread

### Requirement: Memory Usage Tracking

Canister memory usage is tracked across multiple dimensions.

#### Scenario: Total memory usage
- **WHEN** canister memory usage is computed
- **THEN** it includes:
  - Wasm heap memory
  - Stable memory
  - Message memory (input and output queues)
  - Wasm custom sections
  - Canister history
  - Snapshots
  - Wasm chunk store
  - Log memory store

#### Scenario: Memory usage for billing
- **WHEN** storage costs are computed
- **THEN** the billable memory is `max(memory_allocation, actual_memory_usage)`
- **AND** message memory is billed separately

### Requirement: Dirty Page Tracking

Modified memory pages are tracked for state persistence.

#### Scenario: Dirty page detection
- **WHEN** a Wasm execution modifies a heap or stable memory page
- **THEN** the page is marked as dirty
- **AND** the number of dirty pages contributes to the heap delta

#### Scenario: Dirty page overhead charging
- **WHEN** dirty pages are detected after execution
- **THEN** additional instructions are charged: `dirty_page_count * dirty_page_overhead`
- **AND** this overhead is added to the total instructions used by the execution

#### Scenario: Heap delta accumulation
- **WHEN** execution produces dirty pages
- **THEN** the canister's heap delta increases by the number of dirty pages * page size
- **AND** the subnet's heap delta estimate increases accordingly
- **AND** excessive heap delta triggers rate limiting of the canister
