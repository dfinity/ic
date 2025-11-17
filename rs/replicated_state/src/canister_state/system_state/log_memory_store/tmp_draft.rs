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
#![allow(dead_code)] // TODO: don't forget to cleanup.

use std::cell::RefCell;
use std::ops::{Add, Rem, Sub};

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

const INVALID_INDEX_ENTRY: u64 = u64::MAX;

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

// address + position = address
impl Add<MemoryPosition> for MemoryAddress {
    type Output = Self;
    fn add(self, rhs: MemoryPosition) -> Self {
        Self(self.0 + rhs.0)
    }
}

// address + size = address
impl Add<MemorySize> for MemoryAddress {
    type Output = Self;
    fn add(self, rhs: MemorySize) -> Self {
        Self(self.0 + rhs.0)
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

// position + size = position
impl Add<MemorySize> for MemoryPosition {
    type Output = Self;
    fn add(self, rhs: MemorySize) -> Self {
        Self(self.0 + rhs.0)
    }
}

// position % size = position
impl Rem<MemorySize> for MemoryPosition {
    type Output = Self;
    fn rem(self, rhs: MemorySize) -> Self {
        Self(self.0 % rhs.0)
    }
}

// position - position = size
impl Sub<MemoryPosition> for MemoryPosition {
    type Output = MemorySize;
    fn sub(self, rhs: MemoryPosition) -> MemorySize {
        MemorySize(self.0 - rhs.0)
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

// size - size = size
impl Sub<MemorySize> for MemorySize {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

// size - position = size
impl Sub<MemoryPosition> for MemorySize {
    type Output = Self;
    fn sub(self, rhs: MemoryPosition) -> Self {
        Self(self.0 - rhs.0)
    }
}

// size + position = size
impl Add<MemoryPosition> for MemorySize {
    type Output = Self;
    fn add(self, rhs: MemoryPosition) -> Self {
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
        debug_assert!(self.data_capacity.get() > 0);
        debug_assert!(distance.get() > 0);
        (position + distance) % self.data_capacity
    }

    fn is_alive(&self, position: MemoryPosition) -> bool {
        if self.data_head == self.data_tail {
            // If head==tail and size==0, the buffer is empty.
            if self.data_size.get() == 0 {
                return false;
            }
            // if head==tail but size==capacity, the buffer is full.
            if self.data_size.get() == self.data_capacity.get() {
                return true;
            }
        }
        if self.data_head < self.data_tail {
            // No wrap, position is in [head, tail)
            self.data_head <= position && position < self.data_tail
        } else {
            // Wraps around, position is in [0, tail) or [head, capacity)
            position < self.data_tail
                || (self.data_head <= position
                    && position < MemoryPosition::new(self.data_capacity.get()))
        }
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
            idx: INVALID_INDEX_ENTRY,
            timestamp: INVALID_INDEX_ENTRY,
            position: MemoryPosition::new(INVALID_INDEX_ENTRY),
        }
    }

    fn is_valid(&self) -> bool {
        self.idx != INVALID_INDEX_ENTRY
    }
}

/// Index table structure mapping segments of the data region to IndexEntry elements.
#[derive(Debug)]
pub struct IndexTable {
    pub front: Option<IndexEntry>, // Position of the oldest live record.
    pub entries: Vec<IndexEntry>,  // Array of entries covering all segments.
    pub segment_size: MemorySize,  // Size of each segment in bytes.
    pub data_capacity: MemorySize, // Total capacity of the data region.
}

impl IndexTable {
    /// Creates a new IndexTable with all entries invalid and segment size calculated.
    pub fn new(
        front: Option<IndexEntry>, // front might be empty if there are no log records yet.
        data_capacity: MemorySize,
        index_table_pages: u16,
        entries: Vec<IndexEntry>,
    ) -> Self {
        let total_size_max = index_table_pages as usize * PAGE_SIZE;
        let entry_size = INDEX_ENTRY_SIZE.get() as usize;
        debug_assert!(entry_size > 0);
        let entries_count = total_size_max / entry_size;
        debug_assert!(entries_count > 0);
        let segment_size = data_capacity.get() as usize / entries_count;
        debug_assert!(entries_count * entry_size <= total_size_max);

        let entries = if entries.is_empty() {
            vec![IndexEntry::invalid(); entries_count]
        } else {
            entries
        };
        Self {
            front,
            entries,
            segment_size: MemorySize::new(segment_size as u64),
            data_capacity,
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
    pub fn valid_sorted_entries(&self) -> Vec<IndexEntry> {
        let front = match self.front {
            None => return vec![], // No entries if front is None.
            Some(entry) => entry,
        };
        // Collect entries with idx after front.idx, those are valid buckets.
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.is_valid() && front.idx < e.idx)
            .cloned()
            .collect();
        entries.push(front);
        entries.sort_by_key(|e| e.idx);
        entries.dedup_by_key(|e| e.idx);
        entries
    }

    /// Returns the coarse range of index entries [start, end] for the given filter.
    pub fn get_coarse_range(&self, filter: Option<Filter>) -> Option<(IndexEntry, IndexEntry)> {
        let entries = self.valid_sorted_entries();
        if entries.is_empty() {
            return None;
        }

        if entries.len() == 1 {
            // Only one valid entry means only one record (the front) is in the buffer.
            return Some((entries[0], entries[0]));
        }

        // Below this line there's always at least 2 unique entries covering the full valid range
        // from the oldest to the latest log record.

        // Left fallback for start: exact match or previous entry.
        let find_start_by_key = |key: u64, key_fn: fn(&IndexEntry) -> u64| -> IndexEntry {
            match entries.binary_search_by_key(&key, key_fn) {
                Ok(idx) => entries[idx],      // Exact match.
                Err(0) => entries[0],         // Below range, return first.
                Err(idx) => entries[idx - 1], // Left fallback.
            }
        };

        // Right fallback for end: exact match or next entry.
        let find_end_by_key = |key: u64, key_fn: fn(&IndexEntry) -> u64| -> IndexEntry {
            match entries.binary_search_by_key(&key, key_fn) {
                Ok(idx) => entries[idx],                         // Exact match.
                Err(idx) if idx < entries.len() => entries[idx], // Right fallback.
                _ => *entries.last().unwrap(),                   // Above range, return last.
            }
        };

        let filter_by_idx =
            |entries: &Vec<IndexEntry>, start_idx: u64, end_idx: u64| -> Vec<IndexEntry> {
                entries
                    .iter()
                    .filter(|e| start_idx <= e.idx && e.idx <= end_idx)
                    .cloned()
                    .collect()
            };

        let clamp_end_by_size = |entries: &Vec<IndexEntry>, size_limit: MemorySize| -> IndexEntry {
            let start_position = entries.first().unwrap().position;
            for entry in entries {
                if self.distance(start_position, entry.position) >= size_limit {
                    return *entry;
                }
            }
            *entries.last().unwrap()
        };

        let size_limit = RESULT_MAX_SIZE + self.segment_size;
        let (start, end) = match filter {
            Some(Filter::ByIdx(range)) => {
                let start = find_start_by_key(range.start, |e| e.idx);
                let end = find_end_by_key(range.end, |e| e.idx);
                let subset = filter_by_idx(&entries, start.idx, end.idx);
                (start, clamp_end_by_size(&subset, size_limit))
            }
            Some(Filter::ByTimestamp(range)) => {
                let start = find_start_by_key(range.start, |e| e.timestamp);
                let end = find_end_by_key(range.end, |e| e.timestamp);
                let subset = filter_by_idx(&entries, start.idx, end.idx);
                (start, clamp_end_by_size(&subset, size_limit))
            }
            None => {
                let mut start = entries.first().unwrap();
                let end = entries.last().unwrap();
                for entry in entries.iter().rev() {
                    start = entry;
                    if self.distance(entry.position, end.position) >= size_limit {
                        break;
                    }
                }
                (*start, *end)
            }
        };

        Some((start, end))
    }

    /// Calculates the distance between two memory positions in the ring buffer.
    fn distance(&self, from: MemoryPosition, to: MemoryPosition) -> MemorySize {
        if to >= from {
            to - from // no wrap
        } else {
            debug_assert!(self.data_capacity.get() > 0);
            (self.data_capacity + to) - from // wrap
        }
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
        // IMPORTANT: do not check the content length here, as we can only
        // read the record header without loading the full content,
        // but still need to know the full size of the record.
        8 + 8 + 4 + self.len as usize
    }

    pub fn matches(&self, filter: &Filter) -> bool {
        match filter {
            Filter::ByIdx(r) => r.start <= self.idx && self.idx < r.end,
            Filter::ByTimestamp(r) => r.start <= self.timestamp && self.timestamp < r.end,
        }
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
        let (magic, addr) = self.read_raw_bytes::<3>(HEADER_OFFSET);
        let (version, addr) = self.read_raw_u8(addr);
        let (index_table_pages, addr) = self.read_raw_u16(addr);
        let (index_entries_count, addr) = self.read_raw_u16(addr);
        let (data_offset, addr) = self.read_raw_u64(addr);
        let (data_capacity, addr) = self.read_raw_u64(addr);
        let (data_size, addr) = self.read_raw_u64(addr);
        let (data_head, addr) = self.read_raw_u64(addr);
        let (data_tail, addr) = self.read_raw_u64(addr);
        let (next_idx, _addr) = self.read_raw_u64(addr);
        Header {
            magic,
            version,
            index_table_pages,
            index_entries_count,
            data_offset: MemoryAddress::new(data_offset),
            data_capacity: MemorySize::new(data_capacity),
            data_size: MemorySize::new(data_size),
            data_head: MemoryPosition::new(data_head),
            data_tail: MemoryPosition::new(data_tail),
            next_idx,
        }
    }

    pub fn save_header(&self, header: &Header) {
        let mut addr = HEADER_OFFSET;
        addr = self.write_raw_bytes(addr, &header.magic);
        addr = self.write_raw_u8(addr, header.version);
        addr = self.write_raw_u16(addr, header.index_table_pages);
        addr = self.write_raw_u16(addr, header.index_entries_count);
        addr = self.write_raw_u64(addr, header.data_offset.get());
        addr = self.write_raw_u64(addr, header.data_capacity.get());
        addr = self.write_raw_u64(addr, header.data_size.get());
        addr = self.write_raw_u64(addr, header.data_head.get());
        addr = self.write_raw_u64(addr, header.data_tail.get());
        _ = self.write_raw_u64(addr, header.next_idx);
    }

    pub fn load_index(&self) -> IndexTable {
        let h = self.load_header();
        let pos = h.data_head;
        let front = self
            .load_record_without_content(pos)
            .map(|record| IndexEntry::new(pos, &record));
        let entries = if h.index_entries_count == 0 {
            vec![]
        } else {
            let mut entries = Vec::with_capacity(h.index_entries_count as usize);
            let mut addr = INDEX_TABLE_OFFSET;
            for _ in 0..h.index_entries_count {
                let (entry, next_addr) = self.read_index_entry(addr);
                entries.push(entry);
                addr = next_addr;
            }
            entries
        };
        IndexTable::new(front, h.data_capacity, h.index_table_pages, entries)
    }

    pub fn save_index(&self, index: IndexTable) {
        // Save entries.
        let mut addr = INDEX_TABLE_OFFSET;
        for entry in index.entries.iter() {
            addr = self.write_index_entry(addr, entry)
        }
        // Update header with the entries count.
        let mut header = self.load_header();
        header.index_entries_count = index.entries.len() as u16;
        self.save_header(&header);
    }

    fn read_index_entry(&self, addr: MemoryAddress) -> (IndexEntry, MemoryAddress) {
        let (idx, addr) = self.read_raw_u64(addr);
        let (timestamp, addr) = self.read_raw_u64(addr);
        let (position, addr) = self.read_raw_u64(addr);
        (
            IndexEntry {
                idx,
                timestamp,
                position: MemoryPosition::new(position),
            },
            addr,
        )
    }

    fn write_index_entry(&self, addr: MemoryAddress, entry: &IndexEntry) -> MemoryAddress {
        let addr = self.write_raw_u64(addr, entry.idx);
        let addr = self.write_raw_u64(addr, entry.timestamp);
        self.write_raw_u64(addr, entry.position.get())
    }

    fn load_record_header(
        &self,
        position: MemoryPosition,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> (u64, u64, u32, MemoryPosition) {
        let (idx, position) = self.read_wrapped_u64(position, offset, capacity);
        let (timestamp, position) = self.read_wrapped_u64(position, offset, capacity);
        let (len, position) = self.read_wrapped_u32(position, offset, capacity);
        (idx, timestamp, len, position)
    }

    fn load_record_without_content(&self, position: MemoryPosition) -> Option<LogRecord> {
        let h = self.load_header();
        if !h.is_alive(position) {
            return None;
        }
        let (offset, capacity) = (DATA_REGION_OFFSET, h.data_capacity);
        let (idx, timestamp, len, _position) = self.load_record_header(position, offset, capacity);
        Some(LogRecord {
            idx,
            timestamp,
            len,
            content: vec![], // Content is not loaded here.
        })
    }

    pub fn load_record(&self, position: MemoryPosition) -> Option<LogRecord> {
        let h = self.load_header();
        if !h.is_alive(position) {
            return None;
        }
        let (offset, capacity) = (DATA_REGION_OFFSET, h.data_capacity);
        let (idx, timestamp, len, position) = self.load_record_header(position, offset, capacity);
        let (content, _position) =
            self.read_wrapped_vec(position, MemorySize::new(len as u64), offset, capacity);
        Some(LogRecord {
            idx,
            timestamp,
            len,
            content,
        })
    }

    pub fn save_record(&self, position: MemoryPosition, record: &LogRecord) {
        let (offset, capacity) = (DATA_REGION_OFFSET, self.load_header().data_capacity);
        let position = self.write_wrapped_u64(position, record.idx, offset, capacity);
        let position = self.write_wrapped_u64(position, record.timestamp, offset, capacity);
        let position = self.write_wrapped_u32(position, record.len, offset, capacity);
        _ = self.write_wrapped_bytes(position, &record.content, offset, capacity);
    }

    fn read_raw_vec(&self, address: MemoryAddress, len: MemorySize) -> (Vec<u8>, MemoryAddress) {
        let mut bytes = vec![0; len.get() as usize];
        self.buffer.read(&mut bytes, address.get());
        (bytes, address + len)
    }

    fn read_raw_bytes<const N: usize>(&self, address: MemoryAddress) -> ([u8; N], MemoryAddress) {
        let mut bytes = [0; N];
        self.buffer.read(&mut bytes, address.get());
        (bytes, address + MemorySize::new(N as u64))
    }

    fn write_raw_bytes(&self, address: MemoryAddress, bytes: &[u8]) -> MemoryAddress {
        self.buffer.write(bytes, address.get());
        address + MemorySize::new(bytes.len() as u64)
    }

    fn read_wrapped_vec(
        &self,
        position: MemoryPosition,
        len: MemorySize,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> (Vec<u8>, MemoryPosition) {
        let remaining_size = capacity - position;
        let bytes = if len <= remaining_size {
            // No wrap.
            let (bytes, _addr) = self.read_raw_vec(offset + position, len);
            bytes
        } else {
            // Wraps around.
            let (mut bytes, _addr) = self.read_raw_vec(offset + position, remaining_size);
            let second_part_size = len - remaining_size;
            let (mut second_part, _addr) = self.read_raw_vec(offset, second_part_size);
            bytes.append(&mut second_part);
            bytes
        };
        (bytes, (position + len) % capacity)
    }

    fn read_wrapped_bytes<const N: usize>(
        &self,
        position: MemoryPosition,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> ([u8; N], MemoryPosition) {
        let mut result = [0u8; N];
        let len = MemorySize::new(N as u64);
        let remaining = capacity - position;
        if len <= remaining {
            // No wrap.
            let (bytes, _addr) = self.read_raw_vec(offset + position, len);
            result.copy_from_slice(&bytes);
        } else {
            // Wraps around.
            let first_part_size = remaining.get() as usize;
            let (first_part, _addr) = self.read_raw_vec(offset + position, remaining);
            result[..first_part_size].copy_from_slice(&first_part);
            let (second_part, _addr) = self.read_raw_vec(offset, len - remaining);
            result[first_part_size..].copy_from_slice(&second_part);
        }
        (result, (position + len) % capacity)
    }

    fn write_wrapped_bytes(
        &self,
        position: MemoryPosition,
        bytes: &[u8],
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> MemoryPosition {
        let remaining_size = capacity - position;
        let len = MemorySize::new(bytes.len() as u64);
        if len <= remaining_size {
            // No wrap.
            self.write_raw_bytes(offset + position, bytes);
        } else {
            // Wrap around.
            let split = remaining_size.get() as usize;
            self.write_raw_bytes(offset + position, &bytes[..split]);
            self.write_raw_bytes(offset, &bytes[split..]);
        }
        (position + len) % capacity
    }

    fn read_raw_u8(&self, address: MemoryAddress) -> (u8, MemoryAddress) {
        let (bytes, addr) = self.read_raw_bytes::<1>(address);
        (bytes[0], addr)
    }

    fn read_raw_u16(&self, address: MemoryAddress) -> (u16, MemoryAddress) {
        let (bytes, addr) = self.read_raw_bytes::<2>(address);
        (u16::from_le_bytes(bytes), addr)
    }

    fn read_raw_u32(&self, address: MemoryAddress) -> (u32, MemoryAddress) {
        let (bytes, addr) = self.read_raw_bytes::<4>(address);
        (u32::from_le_bytes(bytes), addr)
    }

    fn read_raw_u64(&self, address: MemoryAddress) -> (u64, MemoryAddress) {
        let (bytes, addr) = self.read_raw_bytes::<8>(address);
        (u64::from_le_bytes(bytes), addr)
    }

    fn write_raw_u8(&self, address: MemoryAddress, value: u8) -> MemoryAddress {
        self.write_raw_bytes(address, &value.to_le_bytes())
    }

    fn write_raw_u16(&self, address: MemoryAddress, value: u16) -> MemoryAddress {
        self.write_raw_bytes(address, &value.to_le_bytes())
    }

    fn write_raw_u32(&self, address: MemoryAddress, value: u32) -> MemoryAddress {
        self.write_raw_bytes(address, &value.to_le_bytes())
    }

    fn write_raw_u64(&self, address: MemoryAddress, value: u64) -> MemoryAddress {
        self.write_raw_bytes(address, &value.to_le_bytes())
    }

    fn read_wrapped_u16(
        &self,
        position: MemoryPosition,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> (u16, MemoryPosition) {
        let (bytes, position) = self.read_wrapped_bytes::<2>(position, offset, capacity);
        (u16::from_le_bytes(bytes), position)
    }

    fn read_wrapped_u32(
        &self,
        position: MemoryPosition,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> (u32, MemoryPosition) {
        let (bytes, position) = self.read_wrapped_bytes::<4>(position, offset, capacity);
        (u32::from_le_bytes(bytes), position)
    }

    fn read_wrapped_u64(
        &self,
        position: MemoryPosition,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> (u64, MemoryPosition) {
        let (bytes, position) = self.read_wrapped_bytes::<8>(position, offset, capacity);
        (u64::from_le_bytes(bytes), position)
    }

    fn write_wrapped_u16(
        &self,
        position: MemoryPosition,
        value: u16,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> MemoryPosition {
        self.write_wrapped_bytes(position, &value.to_le_bytes(), offset, capacity)
    }

    fn write_wrapped_u32(
        &self,
        position: MemoryPosition,
        value: u32,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> MemoryPosition {
        self.write_wrapped_bytes(position, &value.to_le_bytes(), offset, capacity)
    }

    fn write_wrapped_u64(
        &self,
        position: MemoryPosition,
        value: u64,
        offset: MemoryAddress,
        capacity: MemorySize,
    ) -> MemoryPosition {
        self.write_wrapped_bytes(position, &value.to_le_bytes(), offset, capacity)
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
            if self.drop_front().is_none() {
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

    fn drop_front(&mut self) -> Option<LogRecord> {
        let mut h = self.io.load_header();
        // No need to read the content of log record being removed.
        let record = self.io.load_record_without_content(h.data_head)?;
        let removed_size = MemorySize::new(record.bytes_len() as u64);
        h.data_head = h.advance_position(h.data_head, removed_size);
        h.data_size = h.data_size.saturating_sub(removed_size);
        self.io.save_header(&h);
        // No need to update the index here since front entry is never
        // stored in the PageMap but rather computed on table load.
        Some(record)
    }

    fn update_index(&self, position: MemoryPosition, record: &LogRecord) {
        // TODO: optimize for loading lots of records in a row.
        let mut index = self.io.load_index();
        index.update(position, record);
        self.io.save_index(index);
    }

    /// Fetches canister logs according to the optional filter.
    pub fn fetch_canister_logs(&self, filter: Option<Filter>) -> Vec<LogRecord> {
        let index = self.io.load_index();
        let (start_inclusive, end_inclusive) = match index.get_coarse_range(filter.clone()) {
            Some(range) => range,
            None => return vec![],
        };

        let header = self.io.load_header();
        let mut records = Vec::new();

        // Walk the coarse range collecting all records in order.
        let mut pos = start_inclusive.position;
        while let Some(record) = self.io.load_record(pos) {
            if record.idx > end_inclusive.idx {
                break; // Reached the end of the range.
            }
            records.push(record.clone());
            pos = header.advance_position(pos, MemorySize::new(record.bytes_len() as u64));
        }

        match filter {
            Some(ref f) => {
                // When a filter is present — keep oldest records (prefix) that match the filter.
                let filtered: Vec<_> = records.into_iter().filter(|r| r.matches(f)).collect();
                take_by_size(&filtered, RESULT_MAX_SIZE, true)
            }
            None => {
                // No filter — return newest records (suffix) up to the size limit.
                take_by_size(&records, RESULT_MAX_SIZE, false)
            }
        }
    }
}

/// Keep a prefix or a suffix of `records` whose total serialized size does not
/// exceed `limit` bytes — prefix keeps oldest-first; suffix keeps newest-first.
/// Returns a Vec<LogRecord> in chronological order (oldest-first).
pub fn take_by_size(records: &[LogRecord], limit: MemorySize, take_prefix: bool) -> Vec<LogRecord> {
    let limit = limit.get() as usize;
    if limit == 0 || records.is_empty() {
        return Vec::new();
    }

    let mut total: usize = 0;
    if take_prefix {
        // Find how many from the front fit.
        let mut end: usize = 0;
        for r in records.iter() {
            let sz = r.bytes_len();
            if total + sz > limit {
                break;
            }
            total += sz;
            end += 1;
        }
        records[..end].to_vec()
    } else {
        // Find start index so that records[start..] (the newest records)
        // fit into the limit — walk backward and then clone that tail.
        let mut start: usize = records.len();
        while start > 0 {
            let sz = records[start - 1].bytes_len();
            if total + sz > limit {
                break;
            }
            total += sz;
            start -= 1;
        }
        records[start..].to_vec()
    }
}

/*
bazel test //rs/replicated_state:replicated_state_test \
  --test_output=streamed \
  --test_arg=--nocapture \
  --test_arg=tmp_draft
*/
