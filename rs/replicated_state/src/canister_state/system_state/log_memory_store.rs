use crate::page_map::{Buffer, PAGE_SIZE, PageAllocatorFileDescriptor, PageMap};
use ic_management_canister_types_private::{CanisterLogRecord, FetchCanisterLogsFilter};
use ic_types::CanisterLog;
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::sync::Arc;

const HEADER_OFFSET: usize = 0;
const V1_HEADER_SIZE: usize = PAGE_SIZE;
const V1_LOOKUP_TABLE_OFFSET: usize = HEADER_OFFSET + V1_HEADER_SIZE;

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
        let version = bytes[0];
        let lookup_table_pages = u16::from_le_bytes(bytes[1..3].try_into().unwrap());
        let lookup_slots_count = u16::from_le_bytes(bytes[3..5].try_into().unwrap());
        let data_offset = u64::from_le_bytes(bytes[5..13].try_into().unwrap());
        let data_capacity = u64::from_le_bytes(bytes[13..21].try_into().unwrap());
        let data_head = u64::from_le_bytes(bytes[21..29].try_into().unwrap());
        let data_tail = u64::from_le_bytes(bytes[29..37].try_into().unwrap());
        let data_size = u64::from_le_bytes(bytes[37..45].try_into().unwrap());
        let next_idx = u64::from_le_bytes(bytes[45..53].try_into().unwrap());
        HeaderV1 {
            version,
            lookup_table_pages,
            lookup_slots_count,
            data_offset,
            data_capacity,
            data_head,
            data_tail,
            data_size,
            next_idx,
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

// struct DataEntry {
//     idx: u64,
//     ts_nanos: u64,
//     len: u32,
//     content: Vec<u8>,
// }

fn init(page_map: PageMap, data_capacity: usize) -> PageMap {
    let lookup_table_pages = 1;
    let data_offset = V1_LOOKUP_TABLE_OFFSET + lookup_table_pages * PAGE_SIZE;
    let header = HeaderV1 {
        version: 1,
        lookup_table_pages: lookup_table_pages as u16,
        lookup_slots_count: 0,
        data_offset: data_offset as u64,
        data_capacity: data_capacity as u64,
        data_head: 0,
        data_tail: 0,
        data_size: 0,
        next_idx: 0,
    };
    let bytes = HeaderV1Bytes::from(&header);

    let mut buffer = Buffer::new(page_map.clone());
    buffer.write(&bytes, HEADER_OFFSET);
    buffer.into_page_map()
}

#[derive(Clone, Eq, PartialEq, Debug, ValidateEq)]
pub struct LogMemoryStore {
    #[validate_eq(Ignore)]
    pub data: PageMap,
}

impl LogMemoryStore {
    pub fn new(fd_factory: Arc<dyn PageAllocatorFileDescriptor>) -> Self {
        Self {
            data: init(PageMap::new(fd_factory), TMP_LOG_MEMORY_CAPACITY),
        }
    }

    /// Creates a new `LogMemoryStore` that will use the temp file system for
    /// allocating new pages.
    pub fn new_for_testing() -> Self {
        Self {
            data: init(PageMap::new_for_testing(), TMP_LOG_MEMORY_CAPACITY),
        }
    }

    pub fn from_checkpoint(data: PageMap) -> Self {
        Self { data }
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
        0 // TODO.
    }

    pub fn used_space(&self) -> usize {
        0 // TODO.
    }

    pub fn next_id(&self) -> u64 {
        0 // TODO.
    }

    pub fn records(&self, _filter: Option<FetchCanisterLogsFilter>) -> Vec<CanisterLogRecord> {
        vec![] // TODO.
    }

    pub fn append_delta_log(&mut self, _delta_log: &mut CanisterLog) {
        // TODO: preserve record sizes, advance next_idx, append records.
    }

    // fn push_delta_log_size(&mut self, _size: usize) {
    //     // TODO.
    // }

    // pub fn take_delta_log_sizes(&mut self) -> Vec<usize> {
    //     vec![] // TODO.
    // }
}
