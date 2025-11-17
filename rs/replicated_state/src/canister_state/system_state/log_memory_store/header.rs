use crate::canister_state::system_state::log_memory_store::{
    memory::{MemoryAddress, MemoryPosition, MemorySize},
    ring_buffer::{DATA_REGION_OFFSET, HEADER_SIZE, INDEX_TABLE_PAGES, MAGIC},
};

/// Header structure for the log memory store (version 1).
/// This is the in-memory representation of the header.
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct Header {
    pub magic: [u8; 3],
    pub version: u8,

    // Index table metadata.
    pub index_table_pages: u16,
    pub index_entries_count: u16,

    // Data region metadata.
    pub data_offset: MemoryAddress,
    pub data_capacity: MemorySize,
    pub data_size: MemorySize,
    pub data_head: MemoryPosition,
    pub data_tail: MemoryPosition,
    pub next_idx: u64,
}
const _: () = assert!(std::mem::size_of::<Header>() == HEADER_SIZE.get() as usize);

impl Header {
    pub fn new(data_capacity: MemorySize) -> Self {
        Self {
            version: 1,
            magic: *MAGIC,

            index_table_pages: INDEX_TABLE_PAGES as u16,
            index_entries_count: 0,

            data_offset: DATA_REGION_OFFSET,
            data_capacity,
            data_head: MemoryPosition::new(0),
            data_tail: MemoryPosition::new(0),
            data_size: MemorySize::new(0),
            next_idx: 0,
        }
    }

    pub fn advance_position(
        &self,
        position: MemoryPosition,
        distance: MemorySize,
    ) -> MemoryPosition {
        debug_assert!(self.data_capacity.get() > 0);
        debug_assert!(distance.get() > 0);
        (position + distance) % self.data_capacity
    }

    pub fn is_alive(&self, position: MemoryPosition) -> bool {
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
