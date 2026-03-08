# Memory Tracker

The `ic-memory-tracker` crate (`rs/memory_tracker/`) provides memory page tracking for the IC execution environment, using signal handlers to intercept memory accesses and manage page-level permissions.

## Requirements

### Requirement: Memory Area Management

The `MemoryArea` struct represents a tracked region of memory.

#### Scenario: Create memory area
- **WHEN** `MemoryArea::new(start, size)` is called
- **THEN** it creates a tracked memory region at the given start address with the given size
- **AND** the start address must be page-aligned
- **AND** the size must be a multiple of `PAGE_SIZE`
- **AND** assertions enforce these alignment requirements

#### Scenario: Address containment check
- **WHEN** `area.contains(address)` is called
- **THEN** it returns `true` if the address falls within `[start, start + size)`
- **AND** returns `false` otherwise

#### Scenario: Page index translation
- **WHEN** `area.page_index_from(addr)` is called
- **THEN** it computes the page index by masking the address to page boundaries
- **AND** subtracting the area start address and dividing by `PAGE_SIZE`

#### Scenario: Page start address computation
- **WHEN** `area.page_start_addr_from(page_index)` is called
- **THEN** it returns the memory address of the start of the specified page

### Requirement: Memory Limits

The `MemoryLimits` structure enforces resource bounds during execution.

#### Scenario: Configure memory limits
- **WHEN** `MemoryLimits` is constructed
- **THEN** it specifies `max_memory_size` (in bytes), `max_accessed_pages` (OS pages), and `max_dirty_pages` (OS pages)
- **AND** the execution environment uses these limits to trap on excessive memory usage

### Requirement: Dirty Page Tracking

The memory tracker distinguishes between read and write accesses for page dirtying.

#### Scenario: Track dirty pages
- **WHEN** `DirtyPageTracking::Track` is active
- **THEN** write accesses are recorded as dirty pages
- **AND** the dirty page set is used to determine which pages need to be persisted after execution

#### Scenario: Ignore dirty pages
- **WHEN** `DirtyPageTracking::Ignore` is active
- **THEN** dirty page tracking overhead is avoided
- **AND** this mode is used for read-only operations like queries

### Requirement: Access Kind Detection

The memory tracker distinguishes between read and write memory accesses.

#### Scenario: Read access
- **WHEN** a signal handler detects `AccessKind::Read`
- **THEN** the page is marked as accessed
- **AND** the page content is loaded from the backing store

#### Scenario: Write access
- **WHEN** a signal handler detects `AccessKind::Write`
- **THEN** the page is marked as both accessed and dirty
- **AND** the page protection is adjusted to allow writes

### Requirement: Page Bitmap

The `PageBitmap` tracks which pages have been accessed during execution.

#### Scenario: Mark and query pages
- **WHEN** `bitmap.mark(page_idx)` is called
- **THEN** the page is recorded as accessed
- **AND** `bitmap.is_marked(page_idx)` returns `true`
- **AND** `bitmap.marked_count()` increments

#### Scenario: Grow bitmap
- **WHEN** `bitmap.grow(delta_pages)` is called
- **THEN** additional pages are added to the bitmap, initially unmarked

#### Scenario: Mark page range
- **WHEN** `bitmap.mark_range(range)` is called
- **THEN** all pages in the range are marked as accessed

### Requirement: Missing Page Handler Variants

Multiple strategies exist for handling page faults.

#### Scenario: Generic handler
- **WHEN** `MissingPageHandlerKind::Generic` is selected
- **THEN** a basic signal handler processes page faults without leveraging access kind information

#### Scenario: Prefetching handler
- **WHEN** `MissingPageHandlerKind::Prefetching` is selected
- **THEN** the handler uses `AccessKind` information
- **AND** prefetches adjacent pages to reduce future faults
- **AND** the `PrefetchingMemoryTracker` provides the `basic_signal_handler` for benchmarking

#### Scenario: Deterministic handler
- **WHEN** `MissingPageHandlerKind::Deterministic` is selected
- **THEN** the `DeterministicMemoryTracker` provides deterministic prefetching behavior
- **AND** works consistently across all platforms

### Requirement: Memory Tracker Metrics

The `MemoryTrackerMetrics` struct collects performance statistics.

#### Scenario: Track signal handler metrics
- **WHEN** memory accesses are processed during execution
- **THEN** the following atomic counters are updated:
  - `read_before_write_count`: number of read-before-write access patterns
  - `direct_write_count`: number of direct write accesses
  - `sigsegv_count`: total number of SIGSEGV signals handled
  - `mmap_count`: number of mmap system calls
  - `mprotect_count`: number of mprotect system calls
  - `copy_page_count`: number of pages copied
  - `sigsegv_handler_duration_nanos`: cumulative time spent in signal handlers

#### Scenario: Query metrics
- **WHEN** metric accessor methods are called (e.g., `metrics.sigsegv_count()`)
- **THEN** the current value is read with `Ordering::Relaxed`
- **AND** `sigsegv_handler_duration()` converts nanos to `Duration`

### Requirement: Checksum Feature (Optional)

The `sigsegv_handler_checksum` feature provides checksumming for determinism verification.

#### Scenario: Record access checksum
- **WHEN** the `sigsegv_handler_checksum` feature is enabled
- **THEN** each memory access records the base address, access address, and access kind into a rolling checksum
- **AND** the checksum uses wrapping multiplication and addition for deterministic computation

#### Scenario: Dump checksum on drop
- **WHEN** the `SigsegChecksum` is dropped
- **THEN** the final checksum value is written to the file specified by the `CHECKSUM_FILE` environment variable
