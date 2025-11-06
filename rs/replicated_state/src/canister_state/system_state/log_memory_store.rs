use crate::page_map::{Buffer, PAGE_SIZE, PageAllocatorFileDescriptor, PageIndex, PageMap};
use ic_management_canister_types_private::{CanisterLogRecord, FetchCanisterLogsFilter};
use ic_sys::PageBytes;
use ic_types::CanisterLog;
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::collections::VecDeque;
use std::convert::From;
use std::sync::Arc;

const HEADER_OFFSET: usize = 0;
const V1_HEADER_SIZE: usize = PAGE_SIZE;
const V1_LOOKUP_TABLE_OFFSET: usize = HEADER_OFFSET + V1_HEADER_SIZE;

/// Upper bound on how many delta log sizes is retained.
/// Prevents unbounded growth of `delta_log_sizes`.
const DELTA_LOG_SIZES_CAP: usize = 100;

const TMP_LOG_MEMORY_CAPACITY: usize = 4 * 1024 * 1024; // 4 MiB

#[derive(Debug, PartialEq)]
#[repr(C, packed)]
struct HeaderV1 {
    magic: [u8; 3], // "LMS"
    version: u8,

    // Lookup table metadata.
    lookup_table_pages: u16,
    lookup_slots_count: u16,

    // Data area metadata.
    data_offset: u64,
    data_capacity: u64,
    data_head: u64,
    data_tail: u64,
    data_size: u64,
    next_idx: u64,
}
const V1_PACKED_HEADER_SIZE: usize = 56;
const _: () = assert!(std::mem::size_of::<HeaderV1>() == V1_PACKED_HEADER_SIZE);
type HeaderV1Bytes = [u8; V1_PACKED_HEADER_SIZE];

impl From<&HeaderV1> for HeaderV1Bytes {
    fn from(header: &HeaderV1) -> Self {
        let mut bytes = [0; V1_PACKED_HEADER_SIZE];
        bytes[0..3].copy_from_slice(&header.magic);
        bytes[3] = header.version;
        bytes[4..6].copy_from_slice(&header.lookup_table_pages.to_le_bytes());
        bytes[6..8].copy_from_slice(&header.lookup_slots_count.to_le_bytes());
        bytes[8..16].copy_from_slice(&header.data_offset.to_le_bytes());
        bytes[16..24].copy_from_slice(&header.data_capacity.to_le_bytes());
        bytes[24..32].copy_from_slice(&header.data_head.to_le_bytes());
        bytes[32..40].copy_from_slice(&header.data_tail.to_le_bytes());
        bytes[40..48].copy_from_slice(&header.data_size.to_le_bytes());
        bytes[48..56].copy_from_slice(&header.next_idx.to_le_bytes());
        bytes
    }
}

impl From<&HeaderV1Bytes> for HeaderV1 {
    fn from(bytes: &HeaderV1Bytes) -> Self {
        Self {
            magic: [bytes[0], bytes[1], bytes[2]],
            version: bytes[3],
            lookup_table_pages: u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            lookup_slots_count: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
            data_offset: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            data_capacity: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            data_head: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            data_tail: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            data_size: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            next_idx: u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
        }
    }
}

impl HeaderV1 {
    fn is_wrapped(&self) -> bool {
        if self.data_tail == self.data_head {
            return self.data_size > 0;
        }
        self.data_tail < self.data_head
    }

    fn lookup_capacity(&self) -> usize {
        // We store one extra slot to avoid overlap of head and tail.
        let full_capacity = (self.lookup_table_pages as usize * PAGE_SIZE) / SLOT_SIZE;
        full_capacity - 1
    }

    fn lookup_head(&self) -> usize {
        (self.data_head as usize) / PAGE_SIZE
    }

    fn lookup_pre_tail(&self) -> usize {
        let capacity = self.lookup_capacity();
        let lookup_tail = (self.data_tail as usize) / PAGE_SIZE;
        (capacity + lookup_tail - 1) % capacity
    }
}

#[test]
fn test_header_v1_roundtrip_serialization() {
    let original = HeaderV1 {
        magic: *b"LMS",
        version: 1,
        lookup_table_pages: 2,
        lookup_slots_count: 3,
        data_offset: 4,
        data_capacity: 5,
        data_head: 6,
        data_tail: 7,
        data_size: 8,
        next_idx: 9,
    };
    let bytes = HeaderV1Bytes::from(&original);
    let recovered = HeaderV1::from(&bytes);
    assert_eq!(original, recovered);
}

#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(C, packed)]
struct LookupSlot {
    idx_min: u64,
    ts_nanos_min: u64,
    offset: u64,
}
const SLOT_SIZE: usize = 24;
const _: () = assert!(std::mem::size_of::<LookupSlot>() == SLOT_SIZE);
type LookupSlotBytes = [u8; SLOT_SIZE];

impl From<&LookupSlot> for LookupSlotBytes {
    fn from(slot: &LookupSlot) -> Self {
        let mut bytes = [0; SLOT_SIZE];
        bytes[0..8].copy_from_slice(&slot.idx_min.to_le_bytes());
        bytes[8..16].copy_from_slice(&slot.ts_nanos_min.to_le_bytes());
        bytes[16..24].copy_from_slice(&slot.offset.to_le_bytes());
        bytes
    }
}

impl From<&LookupSlotBytes> for LookupSlot {
    fn from(bytes: &LookupSlotBytes) -> Self {
        Self {
            idx_min: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            ts_nanos_min: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            offset: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        }
    }
}

#[test]
fn test_lookup_slot_serialization() {
    let original = LookupSlot {
        idx_min: 1,
        ts_nanos_min: 2,
        offset: 3,
    };
    let bytes = LookupSlotBytes::from(&original);
    let recovered = LookupSlot::from(&bytes);
    assert_eq!(original, recovered);
}

// define and implement LookupTableIterator that iterates over lookup slots from head to pre_tail, adds extra slot for tail and handles wrapping.
// iterator should start with data from header.lookup_head() and end with header.lookup_pre_tail() handling wrapping around the ring buffer.
// after that the last extra slot for tail should be returned.
struct LookupTableIterator<'a> {
    ring_buffer: &'a RingBuffer,
    capacity: usize,
    current: usize,
    pre_tail: usize,
    done: bool,
}

impl<'a> LookupTableIterator<'a> {
    fn new(ring_buffer: &'a RingBuffer) -> Self {
        let header = ring_buffer.read_header();
        println!("ABC header: {:?}", header);
        Self {
            ring_buffer,
            capacity: header.lookup_capacity(),
            current: header.lookup_head(),
            pre_tail: header.lookup_pre_tail(),
            done: false,
        }
    }
}

impl Iterator for LookupTableIterator<'_> {
    type Item = LookupSlot;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let slot = self
            .ring_buffer
            .read_lookup_slot(self.current, self.capacity)
            .ok()?;
        if self.current == self.pre_tail {
            self.current = self.capacity;
        } else if self.current == self.capacity {
            self.done = true;
        } else {
            self.current = (self.current + 1) % self.capacity;
        }
        Some(slot)
    }
}

struct DataEntry {
    idx: u64,
    ts_nanos: u64,
    len: u32,
    content: Vec<u8>,
}

impl DataEntry {
    fn data_size(&self) -> usize {
        8 + 8 + 4 + self.content.len()
    }
}

impl From<&DataEntry> for Vec<u8> {
    fn from(entry: &DataEntry) -> Self {
        let mut bytes = Vec::with_capacity(entry.data_size());
        bytes.extend_from_slice(&entry.idx.to_le_bytes());
        bytes.extend_from_slice(&entry.ts_nanos.to_le_bytes());
        bytes.extend_from_slice(&entry.len.to_le_bytes());
        bytes.extend_from_slice(&entry.content);
        bytes
    }
}

fn init(data_capacity: usize) -> HeaderV1 {
    let lookup_table_pages = 1;
    let data_offset = V1_LOOKUP_TABLE_OFFSET + lookup_table_pages * PAGE_SIZE;
    HeaderV1 {
        magic: *b"LMS",
        version: 1,
        lookup_table_pages: lookup_table_pages as u16,
        lookup_slots_count: 0,
        data_offset: data_offset as u64,
        data_capacity: data_capacity as u64,
        data_head: 0,
        data_tail: 0,
        data_size: 0,
        next_idx: 0,
    }
}

#[derive(Clone, Eq, PartialEq, Debug, ValidateEq)]
pub struct LogMemoryStore {
    #[validate_eq(Ignore)]
    pub data: PageMap,

    /// (!) No need to preserve across checkpoints.
    /// Tracks the size of each delta log appended during a round.
    /// Multiple logs can be appended in one round (e.g. heartbeat, timers, or message executions).
    /// The collected sizes are used to expose per-round memory usage metrics
    /// and the record is cleared at the end of the round.
    delta_log_sizes: VecDeque<usize>,
}

impl LogMemoryStore {
    pub fn new(fd_factory: Arc<dyn PageAllocatorFileDescriptor>) -> Self {
        Self::new_inner(PageMap::new(fd_factory))
    }

    /// Creates a new `LogMemoryStore` that will use the temp file system for
    /// allocating new pages.
    pub fn new_for_testing() -> Self {
        Self::new_inner(PageMap::new_for_testing())
    }

    pub fn new_inner(page_map: PageMap) -> Self {
        let mut ring_buffer = RingBuffer::new(page_map);
        let header = init(TMP_LOG_MEMORY_CAPACITY);
        ring_buffer.write_header(&header);
        Self {
            data: ring_buffer.into_page_map(),
            delta_log_sizes: VecDeque::new(),
        }
    }

    pub fn from_checkpoint(data: PageMap) -> Self {
        Self {
            data,
            delta_log_sizes: VecDeque::new(),
        }
    }

    pub fn page_map(&self) -> &PageMap {
        &self.data
    }

    pub fn page_map_mut(&mut self) -> &mut PageMap {
        &mut self.data
    }

    pub fn clear(&mut self) {
        // TODO.
    }

    pub fn capacity(&self) -> usize {
        RingBuffer::new(self.data.clone()).capacity()
    }

    pub fn used_space(&self) -> usize {
        RingBuffer::new(self.data.clone()).used_space()
    }

    /// Returns true if the canister log buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.used_space() == 0
    }

    pub fn next_id(&self) -> u64 {
        RingBuffer::new(self.data.clone()).next_id()
    }

    pub fn append_delta_log(&mut self, delta_log: &mut CanisterLog) {
        // Record the size of the appended delta log for metrics.
        self.push_delta_log_size(delta_log.used_space());

        let mut ring_buffer = RingBuffer::new(self.data.clone());
        for record in delta_log.records() {
            ring_buffer.push_back(&DataEntry {
                idx: record.idx,
                ts_nanos: record.timestamp_nanos,
                len: record.content.len() as u32,
                content: record.content.clone(),
            });
        }
        self.data.update(&ring_buffer.dirty_pages());
    }

    /// Records the size of the appended delta log.
    fn push_delta_log_size(&mut self, size: usize) {
        if self.delta_log_sizes.len() >= DELTA_LOG_SIZES_CAP {
            self.delta_log_sizes.pop_front();
        }
        self.delta_log_sizes.push_back(size);
    }

    /// Atomically snapshot and clear the per-round delta_log sizes — use at end of round.
    pub fn take_delta_log_sizes(&mut self) -> Vec<usize> {
        self.delta_log_sizes.drain(..).collect()
    }

    pub fn records(&self, _filter: Option<FetchCanisterLogsFilter>) -> Vec<CanisterLogRecord> {
        vec![] // TODO.
    }
}

struct RingBuffer {
    buffer: Buffer,
    /// In-memory lookup table for efficient filtering.
    /// Each slot represents a range of entries for fast lookup.
    lookup_table: Vec<LookupSlot>,
}

impl RingBuffer {
    pub fn new(page_map: PageMap) -> Self {
        let mut ring_buffer = Self {
            buffer: Buffer::new(page_map),
            lookup_table: Vec::new(),
        };
        // TODO: init lookup table if not created yet.
        ring_buffer.load_lookup_table();
        ring_buffer
    }

    fn dirty_pages(&self) -> Vec<(PageIndex, &PageBytes)> {
        self.buffer.dirty_pages().collect()
    }

    fn into_page_map(self) -> PageMap {
        self.buffer.into_page_map()
    }

    fn read_header(&self) -> HeaderV1 {
        let mut bytes = [0; V1_PACKED_HEADER_SIZE];
        self.buffer.read(&mut bytes, HEADER_OFFSET);
        // TODO: add header validation.
        HeaderV1::from(&bytes)
    }

    fn write_header(&mut self, header: &HeaderV1) {
        self.buffer
            .write(&HeaderV1Bytes::from(header), HEADER_OFFSET);
    }

    pub fn capacity(&self) -> usize {
        self.read_header().data_capacity as usize
    }

    pub fn used_space(&self) -> usize {
        self.read_header().data_size as usize
    }

    pub fn next_id(&self) -> u64 {
        self.read_header().next_idx
    }

    fn read_lookup_slot(&self, slot_index: usize, capacity: usize) -> Result<LookupSlot, &str> {
        // We store one extra slot to avoid overlap of head and tail.
        let capacity_with_tail_slot = capacity + 1;
        if slot_index >= capacity_with_tail_slot {
            return Err("slot_index out of bounds");
        }
        let slot_offset = V1_LOOKUP_TABLE_OFFSET + (slot_index * SLOT_SIZE);
        let mut slot_bytes = [0; SLOT_SIZE];
        self.buffer.read(&mut slot_bytes, slot_offset);
        Ok(LookupSlot::from(&slot_bytes))
    }

    fn iter_slots(&self) -> impl Iterator<Item = LookupSlot> + '_ {
        LookupTableIterator::new(self)
    }

    fn write_lookup_slot(&mut self, slot_index: usize, slot: &LookupSlot) {
        let slot_offset = V1_LOOKUP_TABLE_OFFSET + (slot_index * SLOT_SIZE);
        let slot_bytes = LookupSlotBytes::from(slot);
        self.buffer.write(&slot_bytes, slot_offset);
    }

    fn load_lookup_table(&mut self) {
        self.lookup_table = self.iter_slots().collect();
    }

    fn read_u64(&self, offset: u64) -> u64 {
        let mut bytes = [0; 8];
        self.buffer.read(&mut bytes, offset as usize);
        u64::from_le_bytes(bytes)
    }

    fn read_u32(&self, offset: u64) -> u32 {
        let mut bytes = [0; 4];
        self.buffer.read(&mut bytes, offset as usize);
        u32::from_le_bytes(bytes)
    }

    fn read_bytes(&self, offset: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        self.buffer.read(&mut bytes, offset as usize);
        bytes
    }

    fn get(&self, offset: u64) -> DataEntry {
        let idx = self.read_u64(offset);
        let ts_nanos = self.read_u64(offset + 8);
        let len = self.read_u32(offset + 16);
        let content = self.read_bytes(offset + 20, len as usize);
        DataEntry {
            idx,
            ts_nanos,
            len,
            content,
        }
    }

    fn pop_front(&mut self) -> Option<DataEntry> {
        // TODO: figure out how to update the lookup table when popping entries.
        let mut header = self.read_header();
        if header.data_size == 0 {
            return None;
        }
        let entry = self.get(header.data_offset + header.data_head);
        let removed_size = entry.data_size() as u64;
        header.data_head = (header.data_head + removed_size) % header.data_capacity;
        header.data_size = header.data_size.saturating_sub(removed_size);
        self.write_header(&header);
        Some(entry)
    }

    fn make_free_space_within_limit(&mut self, new_data_size: u64) {
        // Removes old records to make enough free space for new data within the limit.
        while self.used_space() + new_data_size as usize > self.capacity() {
            if self.pop_front().is_none() {
                break; // No more records to pop, limit reached.
            }
        }
    }

    fn push_back(&mut self, entry: &DataEntry) {
        let added_size = entry.data_size() as u64;
        self.make_free_space_within_limit(added_size);
        // writing new entry into the buffer has 2 cases:
        // 1) there is enough space at the end of the buffer
        // 2) we need to wrap around
        let bytes: Vec<u8> = entry.into();
        let mut header = self.read_header();
        let data_tail_offset = (header.data_offset + header.data_tail) as usize;
        if header.data_tail + added_size <= header.data_capacity {
            // case 1
            self.buffer.write(&bytes, data_tail_offset);
        } else {
            // case 2
            let first_part_size = header.data_capacity - header.data_tail;
            self.buffer
                .write(&bytes[..first_part_size as usize], data_tail_offset);
            self.buffer.write(
                &bytes[first_part_size as usize..],
                header.data_offset as usize,
            );
        }
        header.data_tail = (header.data_tail + added_size) % header.data_capacity;
        header.data_size = header.data_size.saturating_add(added_size);
        header.next_idx = entry.idx + 1;
        self.write_header(&header);
    }
}
