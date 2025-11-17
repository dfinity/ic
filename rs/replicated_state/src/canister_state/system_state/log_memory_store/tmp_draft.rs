/*
To store large volumes of canister logs directly in the Internet Computer replica,
we use the existing `PageMap` structure, which keeps data on disk and operates on it page by page.
On top of this, a `Buffer` provides a file-like interface for arbitrary byte reading and writing.

A ring buffer for logs needs to be implemented, limited by a maximum size `data_capacity_max`
(module level constant). New records are always appended to the end, and when this limit is reached,
the oldest data is removed. Each log record contains an incremental identifier `idx`,
a timestamp in nanoseconds `timestamp`, the content length `len`, and the content itself `content`.

Storage is allocated within a dedicated memory region defined by `data_offset` and `data_capacity`.
Within this region, the ring buffer is described by the pointers `data_head` and `data_tail`,
which are in the range `[0, data_capacity)`.
The actual read or write address is calculated as `data_offset + data_head|data_tail`.
The `data_size` field tracks the actual number of live bytes in the buffer.

This mechanism allows efficient appending of new records and reading of the oldest records,
but it does not provide fast access to arbitrary positions because the records have variable length.
To support selection by `idx` or `timestamp`, and to enable efficient continued reading,
an additional index structure — `IndexTable` — is used.
It contains `IndexEntry` elements sorted by `idx`, which serve as approximate pointers
to data regions, allowing quick loading of a narrow range into memory for precise filtering.

The maximum size of the data region is defined by `DATA_CAPACITY_MAX` (for example, ~100 MB).
The maximum size of a query response is `RESULT_MAX_SIZE` (module level constant, for example, 2 MB).
Reading is performed via the method `fetch_canister_logs`, which accepts an optional filter:
`ByIdx(Range)` or `ByTimestamp(Range)` where `Range { start, end }`.

If no filter is specified, the newest records are returned, but the total response size
must not exceed `RESULT_MAX_SIZE`. If a filter is specified, the range `[start, end)`
is interpreted as a mandatory start and a best-effort end: records are returned only
as long as their cumulative size remains within the result limit.

The storage file consists of three sequential regions: a header, the index table,
and the data region. It is located in memory starting from a fixed base address.
The header occupies a single OS page (`PAGE_SIZE`, 4 KB) and contains metadata required
to manage the index table and the data region. The remaining regions contain only data —
the array of `IndexEntry` elements and the log records themselves.

The index table follows immediately after the header and occupies `index_table_pages` pages.
It is represented as an array of fixed-size `IndexEntry` elements. Each `IndexEntry` contains
`idx : u64`, `timestamp: u64`, and `position: u64` — the offset of the corresponding
log record within the data region.
Each `IndexEntry` is 24 bytes, so the maximum number of entries is
`(index_table_pages * page_size) / entry_size` and is referred to as `index_entries_max`.
The current number of entries is tracked as `index_entries_count`.

When the file is first read, the index table may be empty, `index_entries_count == 0`.
In this case, a new `IndexTable` is created with all elements initialized to invalid values
(e.g., `idx = u64::MAX`). On the first serialization to file, the full array of
`index_entries_max` elements is written, and `index_entries_count` is updated.
Subsequent reads always use `index_entries_count` regardless of individual entry validity.

The data region `[0, data_capacity)` is divided into equal-sized segments.
The segment size is `segment_size = data_capacity / index_entries_max`.
Each `IndexEntry` corresponds to one segment and should reflect the position
of the newest log record within that segment.

When a new record is appended to the ring buffer, the method `update_last(record, position)`
is called. It computes `segment_index = position / segment_size` and updates the corresponding
entry. Each segment therefore holds either an invalid entry or a pointer to the newest
live record in its range. The `IndexTable` when populated always contains a valid entry
with the maximum `idx`, corresponding to the newest record in the buffer.
The position of the oldest live record is stored separately in the `IndexTable`.

`IndexTable` initialization proceeds as follows: the position of the oldest record (`front`)
is determined via `data_head`. Then the array of entries is loaded from the file,
and the `IndexEntry` corresponding to the front position is stored separately
from the segment entries. For coarse searching, a vector of valid entries is constructed,
sorted by `idx`: only valid `IndexEntry` elements are selected,
entries older than `front.idx` are discarded, and duplicates are removed.
The resulting vector covers the entire range of live data in steps of `segment_size`
and serves as a fast guide for subsequent user queries.
*/

use std::cell::RefCell;
use std::ops::Add;

const DATA_CAPACITY_MAX: MemorySize = MemorySize::new(100 * 1024 * 1024); // 100 MiB
const RESULT_MAX_SIZE: MemorySize = MemorySize::new(2_000_000); // 2 MB
const PAGE_SIZE: usize = 4 * 1024; // 4 KiB

const HEADER_OFFSET: MemoryAddress = MemoryAddress::new(0);
const HEADER_RESERVED_SIZE: MemorySize = MemorySize::new(PAGE_SIZE as u64);
const HEADER_SIZE: MemorySize = MemorySize::new(56);
const MAGIC: [u8; 3] = *b"CLH";

const INDEX_TABLE_OFFSET: MemoryAddress = HEADER_OFFSET.add_size(HEADER_RESERVED_SIZE);
const INDEX_TABLE_PAGES: u16 = 1;
const INDEX_TABLE_SIZE: MemorySize = MemorySize::new(INDEX_TABLE_PAGES as u64 * PAGE_SIZE as u64);
const INDEX_ENTRY_SIZE: MemorySize = MemorySize::new(24);

const DATA_REGION_OFFSET: MemoryAddress = INDEX_TABLE_OFFSET.add_size(INDEX_TABLE_SIZE);

const INVALID_INDEX_ENTRY_IDX: u64 = u64::MAX;

/// Represents a range for fetching canister logs.
#[derive(Debug, Clone)]
pub struct FetchCanisterLogsRange {
    pub start: u64, // Inclusive start of the range.
    pub end: u64,   // Exclusive end of the range. Values below `start` are ignored.
}

/// Filter options for fetching logs.
#[derive(Debug, Clone)]
pub enum Filter {
    ByIdx(FetchCanisterLogsRange),
    ByTimestamp(FetchCanisterLogsRange),
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
pub struct MemoryAddress(u64);

impl MemoryAddress {
    const fn new(v: u64) -> Self {
        Self(v)
    }

    const fn get(&self) -> u64 {
        self.0
    }

    const fn add_size(&self, size: MemorySize) -> Self {
        Self(self.0 + size.0)
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
pub struct MemoryPosition(u64);

impl MemoryPosition {
    const fn new(v: u64) -> Self {
        Self(v)
    }

    const fn get(&self) -> u64 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
pub struct MemorySize(u64);

impl MemorySize {
    const fn new(v: u64) -> Self {
        Self(v)
    }

    const fn get(&self) -> u64 {
        self.0
    }

    const fn saturating_add(&self, other: MemorySize) -> MemorySize {
        MemorySize::new(self.0.saturating_add(other.0))
    }

    const fn saturating_sub(&self, other: MemorySize) -> MemorySize {
        MemorySize::new(self.0.saturating_sub(other.0))
    }
}

// size + size = size
impl Add<MemorySize> for MemorySize {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

/// Header structure at the beginning of the storage file.
/// Holds metadata required for managing the IndexTable and data region.
#[derive(Debug, Clone)]
pub struct Header {
    pub magic: [u8; 3], // Magic bytes for file identification.
    pub version: u8,    // Version of the header format.

    pub index_table_pages: u16, // Number of pages allocated to IndexTable.
    pub index_entries_count: u16, // Current number of valid IndexEntry elements.

    pub data_offset: MemoryAddress, // Offset of the data region in memory.
    pub data_capacity: MemorySize,  // Total capacity of the data region in bytes.
    pub data_head: MemoryPosition,  // Ring buffer head pointer.
    pub data_tail: MemoryPosition,  // Ring buffer tail pointer.
    pub data_size: MemorySize,      // Number of live bytes in the buffer.
    pub next_idx: u64,
}
// TODO: assert header size.

impl Header {
    fn new(data_capacity: usize) -> Self {
        Self {
            version: 1,
            magic: MAGIC,

            index_table_pages: INDEX_TABLE_PAGES,
            index_entries_count: 0,

            data_offset: DATA_REGION_OFFSET,
            data_capacity: MemorySize::new(data_capacity as u64),
            data_head: MemoryPosition::new(0),
            data_tail: MemoryPosition::new(0),
            data_size: MemorySize::new(0),
            next_idx: 0,
        }
    }

    fn advance_position(&self, position: MemoryPosition, distance: MemorySize) -> MemoryPosition {
        MemoryPosition::new((position.get() + distance.get()) % self.data_capacity.get())
    }

    fn index_used_space(&self) -> MemorySize {
        MemorySize::new(self.index_entries_count as u64 * INDEX_ENTRY_SIZE.get())
    }
}

/// A single index entry representing a segment in the data region.
/// Stores the position of the newest log record in its segment.
#[derive(Debug, Clone, Copy)]
pub struct IndexEntry {
    pub idx: u64,                 // Incremental ID of the record.
    pub timestamp: u64,           // Timestamp in nanoseconds.
    pub position: MemoryPosition, // Offset in the data region of the newest record.
}

// TODO: assert IndexEntry size.

impl IndexEntry {
    fn new(position: MemoryPosition, record: &LogRecord) -> Self {
        Self {
            idx: record.idx,
            timestamp: record.timestamp,
            position,
        }
    }

    fn invalid() -> Self {
        Self {
            idx: INVALID_INDEX_ENTRY_IDX,
            timestamp: 0,                     // Not important.
            position: MemoryPosition::new(0), // Not important.
        }
    }

    fn is_valid(&self) -> bool {
        self.idx != INVALID_INDEX_ENTRY_IDX
    }
}

/// Index table structure mapping segments of the data region to IndexEntry elements.
#[derive(Debug)]
pub struct IndexTable {
    pub front: Option<IndexEntry>, // Position of the oldest live record.
    pub entries: Vec<IndexEntry>,  // Array of entries covering all segments.
    pub segment_size: MemorySize,  // Size of each segment in bytes.
}

impl IndexTable {
    /// Creates a new IndexTable with all entries invalid and segment size calculated.
    pub fn new(
        front: Option<IndexEntry>, // front might be empty if there are no log records yet.
        data_capacity: MemorySize,
        index_table_pages: u16,
        bytes: &[u8], // bytes read from IndextTable region that inside the function should be deserialized into an array of entries.
    ) -> Self {
        let total_size_max = index_table_pages as usize * PAGE_SIZE;
        let entry_size = INDEX_ENTRY_SIZE.get() as usize;
        debug_assert!(entry_size > 0);
        let entries_count = total_size_max / entry_size;
        debug_assert!(entries_count > 0);
        let segment_size = data_capacity.get() as usize / entries_count;
        debug_assert!(entries_count * entry_size <= total_size_max);

        let entries = if bytes.is_empty() {
            vec![IndexEntry::invalid(); entries_count]
        } else {
            //to_entries(bytes)
            unimplemented!()
        };
        Self {
            front,
            entries,
            segment_size: MemorySize::new(segment_size as u64),
        }
    }

    /// Updates the last record in the corresponding segment.
    pub fn update(&mut self, position: MemoryPosition, record: &LogRecord) {
        if let Some(index) = self.segment_index(position) {
            self.entries[index] = IndexEntry::new(position, record);
        }
    }

    fn segment_index(&self, position: MemoryPosition) -> Option<usize> {
        let segment_size = self.segment_size.get();
        if segment_size == 0 {
            return None;
        }
        let idx = (position.get() / segment_size) as usize;
        (idx < self.entries.len()).then_some(idx)
    }

    /// Returns a vector of valid entries sorted by idx for coarse searching.
    pub fn get_valid_sorted_entries(&self) -> Vec<IndexEntry> {
        let front = match self.front {
            None => return vec![], // No entries if front is None.
            Some(entry) => entry,
        };
        // Collect entries with idx after front.idx, those are valid buckets.
        let mut valid_entries: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.is_valid() && front.idx < e.idx)
            .cloned()
            .collect();
        valid_entries.push(front);
        valid_entries.sort_by_key(|e| e.idx);
        valid_entries
    }

    pub fn get_coarse_range(&self, filter: Option<FetchCanisterLogsRange>) -> Option<()> {
        unimplemented!()
    }
}

/// Represents a single log record stored in the data region.
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub idx: u64,         // Incremental ID of the log record.
    pub timestamp: u64,   // Timestamp in nanoseconds.
    pub len: u32,         // Length of the content.
    pub content: Vec<u8>, // Log content.
}

impl LogRecord {
    pub fn bytes_len(&self) -> usize {
        8 + 8 + 4 + self.content.len()
    }
}

#[derive(Debug)]
pub struct Buffer {
    bytes: RefCell<Vec<u8>>,
}

impl Buffer {
    pub fn new() -> Self {
        Self {
            bytes: RefCell::new(Vec::new()),
        }
    }

    pub fn read(&self, out: &mut [u8], address: u64) {
        let start = match usize::try_from(address) {
            Ok(s) => s,
            Err(_) => return,
        };
        let buf = self.bytes.borrow();
        if start >= buf.len() {
            return;
        }
        let available = buf.len() - start;
        let read_len = out.len().min(available);
        out[..read_len].copy_from_slice(&buf[start..start + read_len]);
    }

    pub fn write(&self, data: &[u8], address: u64) {
        let start = match usize::try_from(address) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut buf = self.bytes.borrow_mut();
        let end = start.saturating_add(data.len());
        if end > buf.len() {
            buf.resize(end, 0);
        }
        buf[start..end].copy_from_slice(data);
    }
}

#[derive(Debug)]
struct StructIO {
    buffer: Buffer,
}

impl StructIO {
    pub fn new() -> Self {
        Self {
            buffer: Buffer::new(),
        }
    }

    pub fn load_header(&self) -> Header {
        let bytes = self.read_vec(HEADER_OFFSET, HEADER_SIZE);
        // TODO: implement header deserialization.
        unimplemented!()
    }

    pub fn save_header(&self, header: &Header) {
        let bytes = vec![]; // TODO: implement header serialization.
        self.write_bytes(HEADER_OFFSET, &bytes);
        unimplemented!()
    }

    pub fn load_index(&self) -> IndexTable {
        let h = self.load_header();
        let front = self.load_index_entry(h.data_head);
        let index_size = h.index_used_space();
        if index_size.get() == 0 {
            IndexTable::new(front, h.data_capacity, h.index_table_pages, &[])
        } else {
            let bytes = self.read_vec(INDEX_TABLE_OFFSET, index_size);
            IndexTable::new(front, h.data_capacity, h.index_table_pages, &bytes)
        }
    }

    pub fn save_index(&self, index: IndexTable) {
        let bytes = vec![]; // TODO: serialize self.entries into bytes.
        self.write_bytes(INDEX_TABLE_OFFSET, &bytes);
        unimplemented!()
    }

    fn load_index_entry(&self, position: MemoryPosition) -> Option<IndexEntry> {
        let record = self.load_record_without_content(position)?;
        Some(IndexEntry::new(position, &record))
    }

    fn load_record_without_content(&self, position: MemoryPosition) -> Option<LogRecord> {
        // TODO: reading record must read data region with wrapping.
        unimplemented!()
    }

    pub fn load_record(&self, position: MemoryPosition) -> Option<LogRecord> {
        // TODO: reading record must read data region with wrapping.
        unimplemented!()
    }

    pub fn save_record(&self, position: MemoryPosition, record: &LogRecord) {
        // TODO: writing record must write data region with wrapping.
        unimplemented!()
    }

    fn read_vec(&self, address: MemoryAddress, size: MemorySize) -> Vec<u8> {
        let mut bytes = vec![0; size.get() as usize];
        self.buffer.read(&mut bytes, address.get());
        bytes
    }

    fn write_bytes(&self, address: MemoryAddress, bytes: &[u8]) {
        self.buffer.write(bytes, address.get());
    }
}

/// Main storage structure combining header, index table, and data region.
#[derive(Debug)]
pub struct RingBuffer {
    io: StructIO,
}

impl RingBuffer {
    pub fn capacity(&self) -> usize {
        self.io.load_header().data_capacity.get() as usize
    }

    pub fn used_space(&self) -> usize {
        self.io.load_header().data_size.get() as usize
    }

    pub fn append(&mut self, record: LogRecord) {
        let added_size = MemorySize::new(record.bytes_len() as u64);
        let capacity = MemorySize::new(self.capacity() as u64);
        if added_size > capacity {
            return;
        }
        // Free space by popping old records if needed.
        while MemorySize::new(self.used_space() as u64) + added_size > capacity {
            if self.pop_front().is_none() {
                break; // No more records to pop, limit reached.
            }
        }

        // Save the record at the tail position.
        let mut h = self.io.load_header();
        self.io.save_record(h.data_tail, &record);

        // Update header with new tail position, size and next idx.
        let position = h.data_tail;
        h.data_tail = h.advance_position(position, added_size);
        h.data_size = h.data_size.saturating_add(added_size);
        h.next_idx = record.idx + 1;
        self.io.save_header(&h);

        // Update lookup table after writing the record and updating the header.
        self.update_index(position, &record);
    }

    fn pop_front(&mut self) -> Option<LogRecord> {
        let mut h = self.io.load_header();
        let record = self.io.load_record(h.data_head)?;
        let removed_size = MemorySize::new(record.bytes_len() as u64);
        h.data_head = h.advance_position(h.data_head, removed_size);
        h.data_size = h.data_size.saturating_sub(removed_size);
        self.io.save_header(&h);
        Some(record)
    }

    fn update_index(&self, position: MemoryPosition, record: &LogRecord) {
        let mut index = self.io.load_index();
        index.update(position, record);
        self.io.save_index(index);
    }

    /// Fetches canister logs according to the optional filter.
    pub fn fetch_canister_logs(&self, filter: Option<Filter>) -> Vec<LogRecord> {
        // todo: first implement get_coarse_range()
        unimplemented!()
    }
}
