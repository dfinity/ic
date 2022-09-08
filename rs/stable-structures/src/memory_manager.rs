//! A module for simulating multiple memories within a single memory.
//!
//! The typical way for a canister to have multiple stable structures is by dividing the memory into
//! distinct ranges, dedicating each range to a stable structure. This approach has two problems:
//!
//! 1. The developer needs to put in advance an upper bound on the memory of each stable structure.
//! 2. It wastes the canister's memory allocation. For example, if a canister create twos two stable
//! structures A and B, and gives each one of them a 1GiB region of memory, then writing to B will
//! require growing > 1GiB of memory just to be able to write to it.
//!
//! The [`MemoryManager`] in this module solves both of these problems. It simulates having
//! multiple memories, each being able to grow without bound. That way, a developer doesn't need to
//! put an upper bound to how much stable structures can grow, and the canister's memory allocation
//! becomes less wasteful.
//!
//! Example Usage:
//!
//! ```
//! use stable_structures::{DefaultMemoryImpl, Memory};
//! use stable_structures::memory_manager::{MemoryManager, MemoryId};
//!
//! let mem_mgr = MemoryManager::init(DefaultMemoryImpl::default());
//!
//! // Create different memories, each with a unique ID.
//! let memory_0 = mem_mgr.get(MemoryId::new(0));
//! let memory_1 = mem_mgr.get(MemoryId::new(1));
//!
//! // Each memory can be used independently.
//! memory_0.grow(1);
//! memory_0.write(0, &[1, 2, 3]);
//!
//! memory_1.grow(1);
//! memory_1.write(0, &[4, 5, 6]);
//!
//! let mut bytes = vec![0; 3];
//! memory_0.read(0, &mut bytes);
//! assert_eq!(bytes, vec![1, 2, 3]);
//!
//! let mut bytes = vec![0; 3];
//! memory_1.read(0, &mut bytes);
//! assert_eq!(bytes, vec![4, 5, 6]);
//! ```
use crate::{
    read_struct,
    types::{Address, Bytes},
    write, write_struct, Memory, WASM_PAGE_SIZE,
};
use std::cell::RefCell;
use std::cmp::min;
use std::collections::BTreeMap;
use std::rc::Rc;

const MAGIC: &[u8; 3] = b"MGR";
const LAYOUT_VERSION: u8 = 1;

// The maximum number of memories that can be created.
const MAX_NUM_MEMORIES: u8 = 255;

// The maximum number of buckets the memory manager can handle.
// With a bucket size of 1024 pages this can support up to 2TiB of memory.
const MAX_NUM_BUCKETS: u64 = 32768;

const BUCKET_SIZE_IN_PAGES: u64 = 1024;

// A value used internally to indicate that a bucket is unallocated.
const UNALLOCATED_BUCKET_MARKER: u8 = MAX_NUM_MEMORIES;

// The offset where buckets are in memory.
const BUCKETS_OFFSET_IN_PAGES: u64 = 1;
const BUCKETS_OFFSET_IN_BYTES: u64 = BUCKETS_OFFSET_IN_PAGES * WASM_PAGE_SIZE;

// Reserved bytes in the header for future extensions.
const HEADER_RESERVED_BYTES: usize = 32;

/// A memory manager simulates multiple memories within a single memory.
///
/// The memory manager can return up to 254 unique instances of [`ManagedMemory`], and each can be
/// used independently and can grow up to the bounds of the underlying memory.
///
/// The memory manager divides the memory into "buckets" of 1024 pages. Each [`ManagedMemory`] is
/// internally represented as a list of buckets. Buckets of different memories can be interleaved,
/// but the [`ManagedMemory`] interface gives the illusion of a continuous address space.
///
/// Because a [`ManagedMemory`] is a list of buckets, this implies that internally it grows one
/// bucket at time (1024 pages). This implication makes the memory manager ideal for a small number
/// of memories storing large amounts of data, as opposed to a large number of memories storing
/// small amounts of data.
///
/// The first page of the memory is reserved for the memory manager's own state. The layout for
/// this state is as follows:
///
/// # V1 layout
///
/// ```text
/// -------------------------------------------------- <- Address 0
/// Magic "MGR"                           ↕ 3 bytes
/// --------------------------------------------------
/// Layout version                        ↕ 1 byte
/// --------------------------------------------------
/// Number of allocated buckets           ↕ 2 bytes
/// --------------------------------------------------
/// Max number of buckets = N             ↕ 2 bytes
/// --------------------------------------------------
/// Reserved space                        ↕ 32 bytes
/// --------------------------------------------------
/// Size of memory 0 (in pages)           ↕ 8 bytes
/// --------------------------------------------------
/// Size of memory 1 (in pages)           ↕ 8 bytes
/// --------------------------------------------------
/// ...
/// --------------------------------------------------
/// Size of memory 254 (in pages)         ↕ 8 bytes
/// -------------------------------------------------- <- Bucket allocations
/// Bucket 1                              ↕ 1 byte        (1 byte indicating which memory owns it)
/// --------------------------------------------------
/// Bucket 2                              ↕ 1 byte
/// --------------------------------------------------
/// ...
/// --------------------------------------------------
/// Bucket `MAX_NUM_BUCKETS`              ↕ 1 byte
/// --------------------------------------------------
/// Unallocated space
/// -------------------------------------------------- <- Buckets (Page 1)
/// Bucket 1                              ↕ 1024 pages
/// -------------------------------------------------- <- Page 1025
/// Bucket 2                              ↕ 1024 pages
/// --------------------------------------------------
/// ...
/// -------------------------------------------------- <- Page ((N - 1) * 1024 + 1)
/// Bucket N                              ↕ 1024 pages
/// ```
pub struct MemoryManager<M: Memory> {
    inner: Rc<RefCell<MemoryManagerInner<M>>>,
}

impl<M: Memory> MemoryManager<M> {
    /// Initializes a `MemoryManager` with the given memory.
    pub fn init(memory: M) -> Self {
        Self::init_with_buckets(memory, BUCKET_SIZE_IN_PAGES as u16)
    }

    fn init_with_buckets(memory: M, bucket_size_in_pages: u16) -> Self {
        Self {
            inner: Rc::new(RefCell::new(MemoryManagerInner::init(
                memory,
                bucket_size_in_pages,
            ))),
        }
    }

    /// Returns the memory associated with the given ID.
    pub fn get(&self, id: MemoryId) -> ManagedMemory<M> {
        ManagedMemory {
            id,
            memory_manager: self.inner.clone(),
        }
    }
}

#[repr(packed)]
struct Header {
    magic: [u8; 3],

    version: u8,

    // The number of buckets allocated by the memory manager.
    num_allocated_buckets: u16,

    // The size of a bucket in Wasm pages.
    bucket_size_in_pages: u16,

    // Reserved bytes for future extensions
    _reserved: [u8; HEADER_RESERVED_BYTES],

    // The size of each individual memory that can be created by the memory manager.
    memory_sizes_in_pages: [u64; MAX_NUM_MEMORIES as usize],
}

impl Header {
    fn size() -> Bytes {
        Bytes::new(core::mem::size_of::<Self>() as u64)
    }
}

#[derive(Clone)]
pub struct ManagedMemory<M: Memory> {
    id: MemoryId,
    memory_manager: Rc<RefCell<MemoryManagerInner<M>>>,
}

impl<M: Memory> Memory for ManagedMemory<M> {
    fn size(&self) -> u64 {
        self.memory_manager.borrow().memory_size(self.id)
    }

    fn grow(&self, pages: u64) -> i64 {
        self.memory_manager.borrow_mut().grow(self.id, pages)
    }

    fn read(&self, offset: u64, dst: &mut [u8]) {
        self.memory_manager.borrow().read(self.id, offset, dst)
    }

    fn write(&self, offset: u64, src: &[u8]) {
        self.memory_manager.borrow().write(self.id, offset, src)
    }
}

#[derive(Clone)]
struct MemoryManagerInner<M: Memory> {
    memory: M,

    // The number of buckets that have been allocated.
    allocated_buckets: u16,

    bucket_size_in_pages: u16,

    // An array storing the size (in pages) of each of the managed memories.
    memory_sizes_in_pages: [u64; MAX_NUM_MEMORIES as usize],

    // A map mapping each managed memory to the bucket ids that are allocated to it.
    memory_buckets: BTreeMap<MemoryId, Vec<BucketId>>,
}

impl<M: Memory> MemoryManagerInner<M> {
    fn init(memory: M, bucket_size_in_pages: u16) -> Self {
        if memory.size() == 0 {
            // Memory is empty. Create a new map.
            return Self::new(memory, bucket_size_in_pages);
        }

        // Check if the magic in the memory corresponds to this object.
        let mut dst = vec![0; 3];
        memory.read(0, &mut dst);
        if dst != MAGIC {
            // No memory manager found. Create a new instance.
            MemoryManagerInner::new(memory, bucket_size_in_pages)
        } else {
            // The memory already contains a memory manager. Load it.
            let mem_mgr = MemoryManagerInner::load(memory);

            // Assert that the bucket size passed is the same as the one previously stored.
            assert_eq!(mem_mgr.bucket_size_in_pages, bucket_size_in_pages);
            mem_mgr
        }
    }

    fn new(memory: M, bucket_size_in_pages: u16) -> Self {
        let mem_mgr = Self {
            memory,
            allocated_buckets: 0,
            memory_sizes_in_pages: [0; MAX_NUM_MEMORIES as usize],
            memory_buckets: BTreeMap::new(),
            bucket_size_in_pages,
        };

        mem_mgr.save_header();

        // Mark all the buckets as unallocated.
        write(
            &mem_mgr.memory,
            bucket_allocations_address(BucketId(0)).get(),
            &[UNALLOCATED_BUCKET_MARKER; MAX_NUM_BUCKETS as usize],
        );

        mem_mgr
    }

    fn load(memory: M) -> Self {
        // Read the header from memory.
        let header: Header = read_struct(Address::from(0), &memory);
        assert_eq!(&header.magic, MAGIC, "Bad magic.");
        assert_eq!(header.version, LAYOUT_VERSION, "Unsupported version.");

        let mut buckets = vec![0; MAX_NUM_BUCKETS as usize];
        memory.read(bucket_allocations_address(BucketId(0)).get(), &mut buckets);

        let mut memory_buckets = BTreeMap::new();
        for (bucket_idx, memory) in buckets.into_iter().enumerate() {
            if memory != UNALLOCATED_BUCKET_MARKER {
                memory_buckets
                    .entry(MemoryId(memory))
                    .or_insert_with(Vec::new)
                    .push(BucketId(bucket_idx as u16));
            }
        }

        Self {
            memory,
            allocated_buckets: header.num_allocated_buckets,
            bucket_size_in_pages: header.bucket_size_in_pages,
            memory_sizes_in_pages: header.memory_sizes_in_pages,
            memory_buckets,
        }
    }

    fn save_header(&self) {
        let header = Header {
            magic: *MAGIC,
            version: LAYOUT_VERSION,
            num_allocated_buckets: self.allocated_buckets,
            bucket_size_in_pages: self.bucket_size_in_pages,
            _reserved: [0; HEADER_RESERVED_BYTES],
            memory_sizes_in_pages: self.memory_sizes_in_pages,
        };

        write_struct(&header, Address::from(0), &self.memory);
    }

    // Returns the size of a memory (in pages).
    fn memory_size(&self, id: MemoryId) -> u64 {
        self.memory_sizes_in_pages[id.0 as usize]
    }

    // Grows the memory with the given id by the given number of pages.
    fn grow(&mut self, id: MemoryId, pages: u64) -> i64 {
        // Compute how many additional buckets are needed.
        let old_size = self.memory_size(id);
        let new_size = old_size + pages;
        let current_buckets = self.num_buckets_needed(old_size);
        let required_buckets = self.num_buckets_needed(new_size);
        let new_buckets_needed = required_buckets - current_buckets;

        if new_buckets_needed + self.allocated_buckets as u64 > MAX_NUM_BUCKETS {
            // Exceeded the memory that can be managed.
            return -1;
        }

        // Allocate new buckets as needed.
        for _ in 0..new_buckets_needed {
            let new_bucket_id = BucketId(self.allocated_buckets);

            self.memory_buckets
                .entry(id)
                .or_insert_with(Vec::new)
                .push(new_bucket_id);

            // Write in stable store that this bucket belongs to the memory with the provided `id`.
            write(
                &self.memory,
                bucket_allocations_address(new_bucket_id).get(),
                &[id.0],
            );

            self.allocated_buckets += 1;
        }

        // Grow the underlying memory if necessary.
        let pages_needed = BUCKETS_OFFSET_IN_PAGES
            + self.bucket_size_in_pages as u64 * self.allocated_buckets as u64;
        if pages_needed > self.memory.size() {
            let additional_pages_needed = pages_needed - self.memory.size();
            let prev_pages = self.memory.grow(additional_pages_needed);
            if prev_pages == -1 {
                panic!("{:?}: grow failed", id);
            }
        }

        // Update the memory with the new size.
        self.memory_sizes_in_pages[id.0 as usize] = new_size;

        // Update the header and return the old size.
        self.save_header();
        old_size as i64
    }

    fn write(&self, id: MemoryId, offset: u64, src: &[u8]) {
        if (offset + src.len() as u64) > self.memory_size(id) * WASM_PAGE_SIZE {
            panic!("{:?}: write out of bounds", id);
        }

        let mut bytes_written = 0;
        for Segment { address, length } in self.bucket_iter(id, offset, src.len()) {
            self.memory.write(
                address.get(),
                &src[bytes_written as usize..(bytes_written + length.get()) as usize],
            );

            bytes_written += length.get();
        }
    }

    fn read(&self, id: MemoryId, offset: u64, dst: &mut [u8]) {
        if (offset + dst.len() as u64) > self.memory_size(id) * WASM_PAGE_SIZE {
            panic!("{:?}: read out of bounds", id);
        }

        let mut bytes_read = 0;
        for Segment { address, length } in self.bucket_iter(id, offset, dst.len()) {
            self.memory.read(
                address.get(),
                &mut dst[bytes_read as usize..(bytes_read + length.get()) as usize],
            );

            bytes_read += length.get();
        }
    }

    // Initializes a [`BucketIterator`].
    fn bucket_iter(&self, id: MemoryId, offset: u64, length: usize) -> BucketIterator {
        // Get the buckets allocated to the given memory id.
        let buckets = match self.memory_buckets.get(&id) {
            Some(s) => s.as_slice(),
            None => &[],
        };

        BucketIterator {
            virtual_segment: Segment {
                address: Address::from(offset),
                length: Bytes::from(length as u64),
            },
            buckets,
            bucket_size_in_bytes: self.bucket_size_in_bytes(),
        }
    }

    fn bucket_size_in_bytes(&self) -> Bytes {
        Bytes::from(self.bucket_size_in_pages as u64 * WASM_PAGE_SIZE)
    }

    // Returns the number of buckets needed to accommodate the given number of pages.
    fn num_buckets_needed(&self, num_pages: u64) -> u64 {
        // Ceiling division.
        (num_pages + self.bucket_size_in_pages as u64 - 1) / self.bucket_size_in_pages as u64
    }
}

struct Segment {
    address: Address,
    length: Bytes,
}

// An iterator that maps a segment of virtual memory to segments of real memory.
//
// A segment in virtual memory can map to multiple segments of real memory. Here's an example:
//
// Virtual Memory
// --------------------------------------------------------
//          (A) ---------- SEGMENT ---------- (B)
// --------------------------------------------------------
// ↑               ↑               ↑               ↑
// Bucket 0        Bucket 1        Bucket 2        Bucket 3
//
// The [`ManagedMemory`] is internally divided into fixed-size buckets. In the memory's virtual
// address space, all these buckets are consecutive, but in real memory this may not be the case.
//
// A virtual segment would first be split at the bucket boundaries. The example virtual segment
// above would be split into the following segments:
//
//    (A, end of bucket 0)
//    (start of bucket 1, end of bucket 1)
//    (start of bucket 2, B)
//
// Each of the segments above can then be translated into the real address space by looking up
// the underlying buckets' addresses in real memory.
struct BucketIterator<'a> {
    virtual_segment: Segment,
    buckets: &'a [BucketId],
    bucket_size_in_bytes: Bytes,
}

impl Iterator for BucketIterator<'_> {
    type Item = Segment;

    fn next(&mut self) -> Option<Self::Item> {
        if self.virtual_segment.length == Bytes::from(0u64) {
            return None;
        }

        // Map the virtual segment's address to a real address.
        let bucket_idx =
            (self.virtual_segment.address.get() / self.bucket_size_in_bytes.get()) as usize;
        let bucket_address = self.bucket_address(
            *self
                .buckets
                .get(bucket_idx)
                .expect("bucket idx out of bounds"),
        );

        let real_address = bucket_address
            + Bytes::from(self.virtual_segment.address.get() % self.bucket_size_in_bytes.get());

        // Compute how many bytes are in this real segment.
        let bytes_in_segment = {
            let next_bucket_address = bucket_address + self.bucket_size_in_bytes;

            // Write up to either the end of the bucket, or the end of the segment.
            min(
                Bytes::from(next_bucket_address.get() - real_address.get()),
                self.virtual_segment.length,
            )
        };

        // Update the virtual segment to exclude the portion we're about to return.
        self.virtual_segment.length -= bytes_in_segment;
        self.virtual_segment.address += bytes_in_segment;

        Some(Segment {
            address: real_address,
            length: bytes_in_segment,
        })
    }
}

impl<'a> BucketIterator<'a> {
    // Returns the address of a given bucket.
    fn bucket_address(&self, id: BucketId) -> Address {
        Address::from(BUCKETS_OFFSET_IN_BYTES) + self.bucket_size_in_bytes * Bytes::from(id.0)
    }
}

#[derive(Clone, Copy, Ord, Eq, PartialEq, PartialOrd, Debug)]
pub struct MemoryId(u8);

impl MemoryId {
    pub const fn new(id: u8) -> Self {
        // Any ID can be used except the special value that's used internally to
        // mark a bucket as unallocated.
        assert!(id != UNALLOCATED_BUCKET_MARKER);

        Self(id)
    }
}

// Referring to a bucket.
#[derive(Clone, Copy, Debug, PartialEq)]
struct BucketId(u16);

fn bucket_allocations_address(id: BucketId) -> Address {
    Address::from(0) + Header::size() + Bytes::from(id.0)
}

#[cfg(test)]
mod test {
    use super::*;
    use maplit::btreemap;
    use proptest::prelude::*;

    const MAX_MEMORY_IN_PAGES: u64 = MAX_NUM_BUCKETS * BUCKET_SIZE_IN_PAGES;

    fn make_memory() -> Rc<RefCell<Vec<u8>>> {
        Rc::new(RefCell::new(Vec::new()))
    }

    #[test]
    fn can_get_memory() {
        let mem_mgr = MemoryManager::init(make_memory());
        let memory = mem_mgr.get(MemoryId(0));
        assert_eq!(memory.size(), 0);
    }

    #[test]
    fn can_allocate_and_use_memory() {
        let mem_mgr = MemoryManager::init(make_memory());
        let memory = mem_mgr.get(MemoryId(0));
        assert_eq!(memory.grow(1), 0);
        assert_eq!(memory.size(), 1);

        memory.write(0, &[1, 2, 3]);

        let mut bytes = vec![0; 3];
        memory.read(0, &mut bytes);
        assert_eq!(bytes, vec![1, 2, 3]);

        assert_eq!(
            mem_mgr.inner.borrow().memory_buckets,
            btreemap! {
                MemoryId(0) => vec![BucketId(0)]
            }
        );
    }

    #[test]
    fn can_allocate_and_use_multiple_memories() {
        let mem = make_memory();
        let mem_mgr = MemoryManager::init(mem.clone());
        let memory_0 = mem_mgr.get(MemoryId(0));
        let memory_1 = mem_mgr.get(MemoryId(1));

        assert_eq!(memory_0.grow(1), 0);
        assert_eq!(memory_1.grow(1), 0);

        assert_eq!(memory_0.size(), 1);
        assert_eq!(memory_1.size(), 1);

        assert_eq!(
            mem_mgr.inner.borrow().memory_buckets,
            btreemap! {
                MemoryId(0) => vec![BucketId(0)],
                MemoryId(1) => vec![BucketId(1)],
            }
        );

        memory_0.write(0, &[1, 2, 3]);
        memory_0.write(0, &[1, 2, 3]);
        memory_1.write(0, &[4, 5, 6]);

        let mut bytes = vec![0; 3];
        memory_0.read(0, &mut bytes);
        assert_eq!(bytes, vec![1, 2, 3]);

        let mut bytes = vec![0; 3];
        memory_1.read(0, &mut bytes);
        assert_eq!(bytes, vec![4, 5, 6]);

        // + 1 is for the header.
        assert_eq!(mem.size(), 2 * BUCKET_SIZE_IN_PAGES + 1);
    }

    #[test]
    fn can_be_reinitialized_from_memory() {
        let mem = make_memory();
        let mem_mgr = MemoryManager::init(mem.clone());
        let memory_0 = mem_mgr.get(MemoryId(0));
        let memory_1 = mem_mgr.get(MemoryId(1));

        assert_eq!(memory_0.grow(1), 0);
        assert_eq!(memory_1.grow(1), 0);

        memory_0.write(0, &[1, 2, 3]);
        memory_1.write(0, &[4, 5, 6]);

        let mem_mgr = MemoryManager::init(mem);
        let memory_0 = mem_mgr.get(MemoryId(0));
        let memory_1 = mem_mgr.get(MemoryId(1));

        let mut bytes = vec![0; 3];
        memory_0.read(0, &mut bytes);
        assert_eq!(bytes, vec![1, 2, 3]);

        memory_1.read(0, &mut bytes);
        assert_eq!(bytes, vec![4, 5, 6]);
    }

    #[test]
    fn growing_same_memory_multiple_times_doesnt_increase_underlying_allocation() {
        let mem = make_memory();
        let mem_mgr = MemoryManager::init(mem.clone());
        let memory_0 = mem_mgr.get(MemoryId(0));

        // Grow the memory by 1 page. This should increase the underlying allocation
        // by `BUCKET_SIZE_IN_PAGES` pages.
        assert_eq!(memory_0.grow(1), 0);
        assert_eq!(mem.size(), 1 + BUCKET_SIZE_IN_PAGES);

        // Grow the memory again. This should NOT increase the underlying allocation.
        assert_eq!(memory_0.grow(1), 1);
        assert_eq!(memory_0.size(), 2);
        assert_eq!(mem.size(), 1 + BUCKET_SIZE_IN_PAGES);

        // Grow the memory up to the BUCKET_SIZE_IN_PAGES. This should NOT increase the underlying
        // allocation.
        assert_eq!(memory_0.grow(BUCKET_SIZE_IN_PAGES - 2), 2);
        assert_eq!(memory_0.size(), BUCKET_SIZE_IN_PAGES);
        assert_eq!(mem.size(), 1 + BUCKET_SIZE_IN_PAGES);

        // Grow the memory by one more page. This should increase the underlying allocation.
        assert_eq!(memory_0.grow(1), BUCKET_SIZE_IN_PAGES as i64);
        assert_eq!(memory_0.size(), BUCKET_SIZE_IN_PAGES + 1);
        assert_eq!(mem.size(), 1 + 2 * BUCKET_SIZE_IN_PAGES);
    }

    #[test]
    fn does_not_grow_memory_unnecessarily() {
        let mem = make_memory();
        let initial_size = BUCKET_SIZE_IN_PAGES * 2;

        // Grow the memory manually before passing it into the memory manager.
        mem.grow(initial_size);

        let mem_mgr = MemoryManager::init(mem.clone());
        let memory_0 = mem_mgr.get(MemoryId(0));

        // Grow the memory by 1 page.
        assert_eq!(memory_0.grow(1), 0);
        assert_eq!(mem.size(), initial_size);

        // Grow the memory by BUCKET_SIZE_IN_PAGES more pages, which will cause the underlying
        // allocation to increase.
        assert_eq!(memory_0.grow(BUCKET_SIZE_IN_PAGES), 1);
        assert_eq!(mem.size(), 1 + BUCKET_SIZE_IN_PAGES * 2);
    }

    #[test]
    fn growing_beyond_capacity_fails() {
        let mem = make_memory();
        let mem_mgr = MemoryManager::init(mem);
        let memory_0 = mem_mgr.get(MemoryId(0));

        assert_eq!(memory_0.grow(MAX_MEMORY_IN_PAGES + 1), -1);

        // Try to grow the memory by MAX_MEMORY_IN_PAGES + 1.
        assert_eq!(memory_0.grow(1), 0); // should succeed
        assert_eq!(memory_0.grow(MAX_MEMORY_IN_PAGES), -1); // should fail.
    }

    #[test]
    fn can_write_across_bucket_boundaries() {
        let mem = make_memory();
        let mem_mgr = MemoryManager::init(mem);
        let memory_0 = mem_mgr.get(MemoryId(0));

        assert_eq!(memory_0.grow(BUCKET_SIZE_IN_PAGES + 1), 0);

        memory_0.write(
            mem_mgr.inner.borrow().bucket_size_in_bytes().get() - 1,
            &[1, 2, 3],
        );

        let mut bytes = vec![0; 3];
        memory_0.read(
            mem_mgr.inner.borrow().bucket_size_in_bytes().get() - 1,
            &mut bytes,
        );
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn can_write_across_bucket_boundaries_with_interleaving_memories() {
        let mem = make_memory();
        let mem_mgr = MemoryManager::init(mem);
        let memory_0 = mem_mgr.get(MemoryId(0));
        let memory_1 = mem_mgr.get(MemoryId(1));

        assert_eq!(memory_0.grow(BUCKET_SIZE_IN_PAGES), 0);
        assert_eq!(memory_1.grow(1), 0);
        assert_eq!(memory_0.grow(1), BUCKET_SIZE_IN_PAGES as i64);

        memory_0.write(
            mem_mgr.inner.borrow().bucket_size_in_bytes().get() - 1,
            &[1, 2, 3],
        );
        memory_1.write(0, &[4, 5, 6]);

        let mut bytes = vec![0; 3];
        memory_0.read(WASM_PAGE_SIZE * BUCKET_SIZE_IN_PAGES - 1, &mut bytes);
        assert_eq!(bytes, vec![1, 2, 3]);

        let mut bytes = vec![0; 3];
        memory_1.read(0, &mut bytes);
        assert_eq!(bytes, vec![4, 5, 6]);
    }

    #[test]
    #[should_panic]
    fn reading_out_of_bounds_should_panic() {
        let mem = make_memory();
        let mem_mgr = MemoryManager::init(mem);
        let memory_0 = mem_mgr.get(MemoryId(0));
        let memory_1 = mem_mgr.get(MemoryId(1));

        assert_eq!(memory_0.grow(1), 0);
        assert_eq!(memory_1.grow(1), 0);

        let mut bytes = vec![0; WASM_PAGE_SIZE as usize + 1];
        memory_0.read(0, &mut bytes);
    }

    #[test]
    #[should_panic]
    fn writing_out_of_bounds_should_panic() {
        let mem = make_memory();
        let mem_mgr = MemoryManager::init(mem);
        let memory_0 = mem_mgr.get(MemoryId(0));
        let memory_1 = mem_mgr.get(MemoryId(1));

        assert_eq!(memory_0.grow(1), 0);
        assert_eq!(memory_1.grow(1), 0);

        let bytes = vec![0; WASM_PAGE_SIZE as usize + 1];
        memory_0.write(0, &bytes);
    }

    #[test]
    fn reading_zero_bytes_from_empty_memory_should_not_panic() {
        let mem = make_memory();
        let mem_mgr = MemoryManager::init(mem);
        let memory_0 = mem_mgr.get(MemoryId(0));

        assert_eq!(memory_0.size(), 0);
        let mut bytes = vec![];
        memory_0.read(0, &mut bytes);
    }

    #[test]
    fn writing_zero_bytes_to_empty_memory_should_not_panic() {
        let mem = make_memory();
        let mem_mgr = MemoryManager::init(mem);
        let memory_0 = mem_mgr.get(MemoryId(0));

        assert_eq!(memory_0.size(), 0);
        memory_0.write(0, &[]);
    }

    #[test]
    fn write_and_read_random_bytes() {
        let mem = make_memory();
        let mem_mgr = MemoryManager::init_with_buckets(mem, 1); // very small bucket size.

        let memories: Vec<_> = (0..MAX_NUM_MEMORIES)
            .map(|id| mem_mgr.get(MemoryId(id)))
            .collect();

        proptest!(|(
            num_memories in 0..255usize,
            data in proptest::collection::vec(0..u8::MAX, 0..2*WASM_PAGE_SIZE as usize),
            offset in 0..10*WASM_PAGE_SIZE
        )| {
            for memory in memories.iter().take(num_memories) {
                // Write a random blob into the memory, growing the memory as it needs to.
                write(memory, offset, &data);

                // Verify the blob can be read back.
                let mut bytes = vec![0; data.len()];
                memory.read(offset, &mut bytes);
                assert_eq!(bytes, data);
            }
        });
    }
}
