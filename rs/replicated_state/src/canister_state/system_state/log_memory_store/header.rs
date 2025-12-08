use crate::canister_state::system_state::log_memory_store::{
    memory::{MemoryAddress, MemoryPosition, MemorySize},
    ring_buffer::{DATA_REGION_OFFSET, INDEX_TABLE_PAGES},
};

pub const MAGIC: &[u8; 3] = b"CLB"; // Canister Log Buffer
pub const NO_MAGIC: &[u8; 3] = b"---"; // This is important in order not to charge uninstalled canister.

/// Header structure for the log memory store (version 1).
/// This is the in-memory representation of the header.
#[derive(Debug, PartialEq, Clone, Copy)]
pub(super) struct Header {
    // Validation and compatibility.
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

    // Monotonicity.
    pub next_idx: u64,
    pub max_timestamp: u64,
}

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
            max_timestamp: 0,
        }
    }

    /// Creates an invalid header.
    pub fn invalid() -> Self {
        Self {
            version: 0,
            magic: *NO_MAGIC, // This is important in order not to charge uninstalled canister.

            index_table_pages: 0,
            index_entries_count: 0,

            data_offset: MemoryAddress::new(0),
            data_capacity: MemorySize::new(0),
            data_head: MemoryPosition::new(0),
            data_tail: MemoryPosition::new(0),
            data_size: MemorySize::new(0),

            next_idx: 0,
            max_timestamp: 0,
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
        let capacity_position = MemoryPosition::new(self.data_capacity.get());
        if position >= capacity_position {
            return false;
        }

        if self.data_head == self.data_tail {
            // If head==tail and size==0, the buffer is empty.
            if self.data_size.get() == 0 {
                return false;
            }
            // if head==tail but size==capacity, the buffer is full.
            if self.data_size == self.data_capacity {
                return true;
            }
        }
        if self.data_head < self.data_tail {
            // No wrap, position is in [head, tail)
            self.data_head <= position && position < self.data_tail
        } else {
            // Wraps around, position is in [0, tail) or [head, capacity)
            position < self.data_tail
                || (self.data_head <= position && position < capacity_position)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_header_sets_defaults() {
        let capacity = MemorySize::new(1024);
        let h = Header::new(capacity);
        assert_eq!(h.magic, *b"CLB");
        assert_eq!(h.version, 1);
        assert_eq!(h.index_table_pages, 1);
        assert_eq!(h.index_entries_count, 0);
        assert_eq!(h.data_capacity, capacity);
        assert_eq!(h.data_head, MemoryPosition::new(0));
        assert_eq!(h.data_tail, MemoryPosition::new(0));
        assert_eq!(h.data_size, MemorySize::new(0));
        assert_eq!(h.next_idx, 0);
        assert_eq!(h.max_timestamp, 0);
    }

    #[test]
    fn advance_position_wraps_correctly() {
        // With capacity 100, advancing 20 from position 90 wraps to 10.
        let capacity = MemorySize::new(100);
        let h = Header::new(capacity);
        let next = h.advance_position(MemoryPosition::new(90), MemorySize::new(20));
        assert_eq!(next, MemoryPosition::new(10));
    }

    #[test]
    fn is_alive_returns_false_when_outside_capacity() {
        // Positions >= capacity are always not alive.
        let mut h = Header::new(MemorySize::new(64));
        h.data_head = MemoryPosition::new(0);
        h.data_tail = MemoryPosition::new(0);
        h.data_size = MemorySize::new(64);
        assert!(!h.is_alive(MemoryPosition::new(64)));
        assert!(!h.is_alive(MemoryPosition::new(65)));
    }

    #[test]
    fn is_alive_returns_false_when_empty() {
        // When head==tail and size==0, buffer is empty, no positions are alive.
        let mut h = Header::new(MemorySize::new(64));
        h.data_head = MemoryPosition::new(0);
        h.data_tail = MemoryPosition::new(0);
        h.data_size = MemorySize::new(0);
        assert!(!h.is_alive(MemoryPosition::new(0)));
        assert!(!h.is_alive(MemoryPosition::new(1)));
    }

    #[test]
    fn is_alive_returns_true_when_full() {
        // When head==tail and size==capacity, buffer is full, all positions are alive.
        let mut h = Header::new(MemorySize::new(16));
        h.data_head = MemoryPosition::new(0);
        h.data_tail = MemoryPosition::new(0);
        h.data_size = MemorySize::new(16);
        assert!(h.is_alive(MemoryPosition::new(0)));
        assert!(h.is_alive(MemoryPosition::new(10)));
        assert!(h.is_alive(MemoryPosition::new(15)));
    }

    #[test]
    fn is_alive_no_wrap_range() {
        // Capacity 100, no wrap, live bytes span [10..50).
        let mut h = Header::new(MemorySize::new(100));
        h.data_head = MemoryPosition::new(10);
        h.data_tail = MemoryPosition::new(50);
        h.data_size = MemorySize::new(40);
        // [10..50)
        assert!(!h.is_alive(MemoryPosition::new(9)));
        assert!(h.is_alive(MemoryPosition::new(10)));
        assert!(h.is_alive(MemoryPosition::new(49)));
        assert!(!h.is_alive(MemoryPosition::new(50)));
    }

    #[test]
    fn is_alive_wraps_around() {
        // Capacity 100, wraps around, live bytes span [80..100) and [0..20).
        let mut h = Header::new(MemorySize::new(100));
        h.data_head = MemoryPosition::new(80);
        h.data_tail = MemoryPosition::new(20);
        h.data_size = MemorySize::new(40);
        // [80..100)
        assert!(!h.is_alive(MemoryPosition::new(79)));
        assert!(h.is_alive(MemoryPosition::new(80)));
        assert!(h.is_alive(MemoryPosition::new(99)));
        assert!(!h.is_alive(MemoryPosition::new(100)));
        // [0..20)
        assert!(h.is_alive(MemoryPosition::new(0)));
        assert!(h.is_alive(MemoryPosition::new(19)));
        assert!(!h.is_alive(MemoryPosition::new(20)));
    }
}
