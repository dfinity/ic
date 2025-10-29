use crate::page_map::{Buffer, PAGE_SIZE, PageAllocatorFileDescriptor, PageMap};
use ic_management_canister_types_private::{CanisterLogRecord, DataSize, FetchCanisterLogsFilter};
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
const V1_PACKED_HEADER_SIZE: usize = 53;
const _: () = assert!(std::mem::size_of::<HeaderV1>() == V1_PACKED_HEADER_SIZE);
type HeaderV1Bytes = [u8; V1_PACKED_HEADER_SIZE];

impl From<&HeaderV1> for HeaderV1Bytes {
    fn from(header: &HeaderV1) -> Self {
        let mut bytes = [0; V1_PACKED_HEADER_SIZE];
        bytes[0] = header.version;
        bytes[1..3].copy_from_slice(&header.lookup_table_pages.to_le_bytes());
        bytes[3..5].copy_from_slice(&header.lookup_slots_count.to_le_bytes());
        bytes[5..13].copy_from_slice(&header.data_offset.to_le_bytes());
        bytes[13..21].copy_from_slice(&header.data_capacity.to_le_bytes());
        bytes[21..29].copy_from_slice(&header.data_head.to_le_bytes());
        bytes[29..37].copy_from_slice(&header.data_tail.to_le_bytes());
        bytes[37..45].copy_from_slice(&header.data_size.to_le_bytes());
        bytes[45..53].copy_from_slice(&header.next_idx.to_le_bytes());
        bytes
    }
}

impl From<&HeaderV1Bytes> for HeaderV1 {
    fn from(bytes: &HeaderV1Bytes) -> Self {
        Self {
            version: bytes[0],
            lookup_table_pages: u16::from_le_bytes(bytes[1..3].try_into().unwrap()),
            lookup_slots_count: u16::from_le_bytes(bytes[3..5].try_into().unwrap()),
            data_offset: u64::from_le_bytes(bytes[5..13].try_into().unwrap()),
            data_capacity: u64::from_le_bytes(bytes[13..21].try_into().unwrap()),
            data_head: u64::from_le_bytes(bytes[21..29].try_into().unwrap()),
            data_tail: u64::from_le_bytes(bytes[29..37].try_into().unwrap()),
            data_size: u64::from_le_bytes(bytes[37..45].try_into().unwrap()),
            next_idx: u64::from_le_bytes(bytes[45..53].try_into().unwrap()),
        }
    }
}

#[test]
fn test_header_v1_roundtrip_serialization() {
    let original = HeaderV1 {
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

// struct LookupSlot {
//     idx_min: u64,
//     ts_nanos_min: u64,
//     offset: u64,
// }
// const SLOT_SIZE: usize = 24;
//const _: () = assert!(std::mem::size_of::<LookupSlot>() == SLOT_SIZE);

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
        let mut store = Self {
            data: PageMap::new(fd_factory),
            delta_log_sizes: VecDeque::new(),
        };
        let header = init(TMP_LOG_MEMORY_CAPACITY);
        store.write_header(&header);
        store
    }

    /// Creates a new `LogMemoryStore` that will use the temp file system for
    /// allocating new pages.
    pub fn new_for_testing() -> Self {
        let mut store = Self {
            data: PageMap::new_for_testing(),
            delta_log_sizes: VecDeque::new(),
        };
        let header = init(TMP_LOG_MEMORY_CAPACITY);
        store.write_header(&header);
        store
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

    fn read_header(&self) -> HeaderV1 {
        let buffer = Buffer::new(self.data.clone());
        let mut bytes = [0; V1_PACKED_HEADER_SIZE];
        buffer.read(&mut bytes, HEADER_OFFSET);
        HeaderV1::from(&bytes)
    }

    fn write_header(&mut self, header: &HeaderV1) {
        let mut buffer = Buffer::new(self.data.clone());
        buffer.write(&HeaderV1Bytes::from(header), HEADER_OFFSET);
        self.data.update(&buffer.dirty_pages().collect::<Vec<_>>());
    }

    pub fn clear(&mut self) {
        // TODO.
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

    pub fn append_delta_log(&mut self, delta_log: &mut CanisterLog) {
        // Record the size of the appended delta log for metrics.
        self.push_delta_log_size(delta_log.used_space());

        let mut buffer = Buffer::new(self.data.clone());
        let mut header = self.read_header();
        for record in delta_log.records().iter() {
            // Advance the next_idx to one past the appended record.
            header.next_idx = record.idx + 1;

            // TODO: append the record to the log memory store.
        }
        self.write_header(&header);
    }

    pub fn records(&self, _filter: Option<FetchCanisterLogsFilter>) -> Vec<CanisterLogRecord> {
        vec![] // TODO.
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
}

struct RingBuffer {
    buffer: Buffer,
}

impl RingBuffer {
    pub fn new(page_map: PageMap, capacity: usize) -> Self {
        Self {
            buffer: Buffer::new(page_map),
        }
    }

    fn read_header(&self) -> HeaderV1 {
        let mut bytes = [0; V1_PACKED_HEADER_SIZE];
        self.buffer.read(&mut bytes, HEADER_OFFSET);
        HeaderV1::from(&bytes)
    }

    fn write_header(&mut self, header: &HeaderV1) {
        self.buffer
            .write(&HeaderV1Bytes::from(header), HEADER_OFFSET);
    }

    // fn dirty_pages(&self) -> impl Iterator<Item = usize> + '_ {
    //     self.buffer.dirty_pages()
    // }

    pub fn capacity(&self) -> usize {
        self.read_header().data_capacity as usize
    }

    pub fn used_space(&self) -> usize {
        self.read_header().data_size as usize
    }

    pub fn is_empty(&self) -> bool {
        self.used_space() == 0
    }

    pub fn next_id(&self) -> u64 {
        self.read_header().next_idx
    }

    fn get(&self, offset: u64) -> Option<DataEntry> {
        None // TODO.
    }

    fn pop_front(&mut self) -> Option<DataEntry> {
        let mut header = self.read_header();
        let entry = self.get(header.data_head)?;
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
        let data_tail_address = (header.data_offset + header.data_tail) as usize;
        if header.data_tail + added_size <= header.data_capacity {
            // case 1
            self.buffer.write(&bytes, data_tail_address);
        } else {
            // case 2
            let first_part_size = header.data_capacity - header.data_tail;
            self.buffer
                .write(&bytes[..first_part_size as usize], data_tail_address);
            self.buffer.write(
                &bytes[first_part_size as usize..],
                header.data_offset as usize,
            );
        }
        header.data_tail = (header.data_tail + added_size) % header.data_capacity;
        header.data_size = header.data_size.saturating_add(added_size);
        header.next_idx += 1; // It's ok to overflow here, since it's a unique ID for _stored_ logs.
        self.write_header(&header);
    }
}
