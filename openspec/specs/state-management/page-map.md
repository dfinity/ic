# Page Map and Memory Management

The PageMap is a copy-on-write memory abstraction that supports efficient snapshotting, incremental persistence via overlay files, and memory-mapped access. It underlies all memory types in the replicated state: Wasm heap, stable memory, chunk stores, and log memory.

## Requirements

### Requirement: PageMap Structure

A PageMap represents a virtual memory region as a collection of fixed-size pages.

#### Scenario: Page size and indexing
- **WHEN** a PageMap is used
- **THEN** each page is `PAGE_SIZE` (4096) bytes
- **AND** pages are indexed by `PageIndex` (a 64-bit unsigned integer)
- **AND** only pages that have been written to are stored (sparse representation)

#### Scenario: Copy-on-write snapshots
- **WHEN** a PageMap is cloned (for state snapshotting)
- **THEN** the clone shares the same underlying data via a persistent `IntMap`
- **AND** modifications to the clone do not affect the original
- **AND** this enables cheap snapshotting for each canister state

### Requirement: PageDelta Management

Changes to a PageMap are tracked as `PageDelta` layers.

#### Scenario: Tracking modifications
- **WHEN** pages are written to a PageMap
- **THEN** the changes are recorded in an unflushed delta
- **AND** the delta is a persistent map from `PageIndex` to `Page`

#### Scenario: Applying deltas
- **WHEN** a new delta is applied to a PageMap
- **THEN** it is merged with the existing delta using union
- **AND** newer values take precedence over older ones

#### Scenario: Flushing deltas to disk
- **WHEN** a PageMap's delta is flushed
- **THEN** the unflushed pages are written as an overlay file on disk
- **AND** the delta is cleared from memory
- **AND** write metrics (bytes, duration) are recorded

#### Scenario: Empty delta handling
- **WHEN** a PageMap's delta is empty during flush
- **THEN** no overlay file is written
- **AND** the `empty_delta_writes` metric is incremented

### Requirement: Storage Layer (Overlay Files)

PageMap data is persisted using a layered system of base files and overlay files.

#### Scenario: Base file
- **WHEN** a PageMap has a base file
- **THEN** it is a contiguous file containing all pages up to a certain index
- **AND** reading a page not in any overlay falls through to the base file

#### Scenario: Overlay file structure
- **WHEN** an overlay file is created
- **THEN** it contains:
  - Page data for modified pages
  - An index section mapping page indices to offsets in the data section
  - A header with the overlay version
- **AND** overlays are ordered by height (newer overlays take precedence)

#### Scenario: Page resolution order
- **WHEN** a page is read from a PageMap
- **THEN** the resolution order is:
  1. In-memory unflushed delta
  2. Newest overlay file
  3. Older overlay files (in reverse chronological order)
  4. Base file
  5. Zero page (if not found anywhere)

#### Scenario: Overlay file versioning
- **WHEN** overlay files are written
- **THEN** they include a version tag in the header
- **AND** the version determines the format of the index section

### Requirement: Overlay Merging

Overlay files are periodically merged to control file count and disk usage.

#### Scenario: Merge candidate selection
- **WHEN** the merge strategy runs
- **THEN** it examines each PageMap shard's file count and storage overhead
- **AND** shards exceeding the file count hard limit (20 files) are always merged
- **AND** remaining shards are merged in order of storage overhead until the soft budget (250 GiB) is reached

#### Scenario: Merge execution
- **WHEN** a set of overlay files is merged
- **THEN** a new single overlay file is created containing all unique pages
- **AND** newer pages take precedence over older ones
- **AND** the original overlay files are removed
- **AND** write metrics are recorded for the merge operation

#### Scenario: Storage overhead calculation
- **WHEN** a shard's storage overhead is calculated
- **THEN** it is the ratio of total file bytes to unique page bytes
- **AND** higher overhead indicates more redundant data across overlays

### Requirement: Sharding

Large PageMaps are split across multiple shards for parallel I/O.

#### Scenario: Shard structure
- **WHEN** a PageMap's storage is sharded
- **THEN** page indices are distributed across shards
- **AND** each shard has its own set of overlay files and optional base file
- **AND** operations on different shards can proceed in parallel

### Requirement: Page Allocator

Pages are allocated from a centralized allocator for memory efficiency.

#### Scenario: File-backed page allocation
- **WHEN** `PageAllocatorFileDescriptor` is configured for file-backed memory
- **THEN** pages are allocated from a memory-mapped file
- **AND** the file is created in the `page_deltas` directory
- **AND** this allows the OS to page memory to disk under pressure

#### Scenario: Anonymous page allocation
- **WHEN** file-backed allocation is disabled
- **THEN** pages are allocated from anonymous memory (standard heap)

#### Scenario: Page allocator registry
- **WHEN** pages are deserialized (e.g., during checkpoint loading)
- **THEN** the `PageAllocatorRegistry` ensures that pages from the same allocator share the backing store
- **AND** this prevents duplication of memory across page maps

### Requirement: Persistence Errors

Page map persistence operations report errors clearly.

#### Scenario: File system error
- **WHEN** an I/O error occurs during page map persistence
- **THEN** a `PersistenceError::FileSystemError` is returned
- **AND** it includes the file path and error context

#### Scenario: Invalid page map
- **WHEN** a page map file is corrupt or invalid
- **THEN** a `PersistenceError::InvalidPageMap` is returned
- **AND** it includes a descriptive error message

### Requirement: Memory Types

Different memory types in the replicated state use PageMap with type-safe wrappers.

#### Scenario: Wasm heap memory (vmemory_0)
- **WHEN** a canister's Wasm heap memory is accessed
- **THEN** it is backed by a PageMap stored as `vmemory_0` files
- **AND** the memory size in Wasm pages is tracked separately from the PageMap

#### Scenario: Stable memory
- **WHEN** a canister's stable memory is accessed
- **THEN** it is backed by a PageMap stored as `stable_memory` files
- **AND** stable memory survives canister upgrades

#### Scenario: Wasm chunk store
- **WHEN** a canister's Wasm chunk store is accessed
- **THEN** it is backed by a PageMap stored as `wasm_chunk_store` files
- **AND** it stores uploaded Wasm module chunks

#### Scenario: Log memory store
- **WHEN** a canister's log memory is accessed
- **THEN** it is backed by a PageMap stored as `log_memory_store` files

### Requirement: IntMap (Persistent Map)

The underlying data structure for PageDelta is a persistent (immutable) map.

#### Scenario: Persistent union
- **WHEN** two IntMaps are unioned
- **THEN** the result contains all entries from both maps
- **AND** entries from the left map take precedence on key conflict
- **AND** the original maps are not modified

#### Scenario: Efficient lookup
- **WHEN** a page is looked up in the IntMap
- **THEN** the lookup completes in O(log n) time
- **AND** bounds queries (predecessor/successor) are also supported

#### Scenario: Efficient iteration
- **WHEN** pages are iterated in the IntMap
- **THEN** they are yielded in sorted order by page index
