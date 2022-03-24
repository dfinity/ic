use crate::{
    types::{Address, Bytes, NULL},
    Memory, WASM_PAGE_SIZE,
};

const ALLOCATOR_LAYOUT_VERSION: u8 = 1;
const CHUNK_LAYOUT_VERSION: u8 = 1;

const ALLOCATOR_MAGIC: &[u8; 3] = b"BTA"; // btree allocator
const CHUNK_MAGIC: &[u8; 3] = b"CHK"; // btree allocator

/// A free list constant-size chunk allocator.
///
/// The allocator allocates chunks of size `allocation_size` from the given `memory`.
///
/// # Properties
///
/// * The allocator tries to minimize its memory footprint, growing the memory in
///   size only when all the available memory is allocated.
///
/// * The allocator makes no assumptions on the size of the memory and will
///   continue growing so long as the provided `memory` allows it.
///
/// The allocator divides the memory into "chunks" of equal size. Each chunk contains:
///     a) A `ChunkHeader` with metadata about the chunk.
///     b) A blob of length `allocation_size` that can be used freely by the user.
///
/// # Assumptions:
///
/// * The given memory is not being used by any other data structure.
pub struct Allocator<M: Memory> {
    // The address in memory where the `AllocatorHeader` is stored.
    header_addr: Address,

    // The size of the chunk to allocate in bytes.
    allocation_size: Bytes,

    // The number of chunks currently allocated.
    num_allocated_chunks: u64,

    // A linked list of unallocated chunks.
    free_list_head: Address,

    memory: M,
}

#[repr(packed)]
struct AllocatorHeader {
    magic: [u8; 3],
    version: u8,
    // Empty space to memory-align the following fields.
    _alignment: [u8; 4],
    allocation_size: Bytes,
    num_allocated_chunks: u64,
    free_list_head: Address,
    // Additional space reserved to add new fields without breaking backward-compatibility.
    _buffer: [u8; 16],
}

impl AllocatorHeader {
    fn size() -> Bytes {
        Bytes::from(core::mem::size_of::<Self>() as u64)
    }
}

impl<M: Memory> Allocator<M> {
    /// Initialize an allocator and store it in address `addr`.
    ///
    /// The allocator assumes that all memory from `addr` onwards is free.
    ///
    /// When initialized, the allocator has the following memory layout:
    ///
    /// [   AllocatorHeader       | ChunkHeader ]
    ///      ..   free_list_head  ↑      next
    ///                |__________|       |____ NULL
    ///
    pub fn new(memory: M, addr: Address, allocation_size: Bytes) -> Self {
        let free_list_head = addr + AllocatorHeader::size();

        // Create the initial memory chunk and save it directly after the allocator's header.
        let chunk = ChunkHeader::null();
        chunk.save(free_list_head, &memory);

        let allocator = Self {
            header_addr: addr,
            allocation_size,
            num_allocated_chunks: 0,
            free_list_head,
            memory,
        };

        allocator.save();
        allocator
    }

    /// Load an allocator from memory at the given `addr`.
    pub fn load(memory: M, addr: Address) -> Self {
        let mut header: AllocatorHeader = unsafe { core::mem::zeroed() };
        let header_slice = unsafe {
            core::slice::from_raw_parts_mut(
                &mut header as *mut _ as *mut u8,
                AllocatorHeader::size().into(),
            )
        };

        memory.read(addr.get(), header_slice);

        assert_eq!(&header.magic, ALLOCATOR_MAGIC, "Bad magic.");
        assert_eq!(
            header.version, ALLOCATOR_LAYOUT_VERSION,
            "Unsupported version."
        );

        Self {
            header_addr: addr,
            allocation_size: header.allocation_size,
            num_allocated_chunks: header.num_allocated_chunks,
            free_list_head: header.free_list_head,
            memory,
        }
    }

    /// Allocates a new chunk from memory with size `allocation_size`.
    ///
    /// Internally, there are two cases:
    ///
    /// 1) The list of free chunks (`free_list_head`) has only one element.
    ///    This case happens when we initialize a new allocator, or when
    ///    all of the previously allocated chunks are still in use.
    ///
    ///    Example memory layout:
    ///
    ///    [   AllocatorHeader       | ChunkHeader ]
    ///         ..   free_list_head  ↑      next
    ///                   |__________↑       |____ NULL
    ///
    ///    In this case, the chunk in the free list is allocated to the user
    ///    and a new `ChunkHeader` is appended to the allocator's memory,
    ///    growing the memory if necessary.
    ///
    ///    [   AllocatorHeader       | ChunkHeader | ... | ChunkHeader2 ]
    ///         ..   free_list_head      (allocated)     ↑      next
    ///                   |______________________________↑       |____ NULL
    ///
    /// 2) The list of free chunks (`free_list_head`) has more than one element.
    ///
    ///    Example memory layout:
    ///
    ///    [   AllocatorHeader       | ChunkHeader1 | ... | ChunkHeader2 ]
    ///         ..   free_list_head  ↑       next         ↑       next
    ///                   |__________↑        |___________↑         |____ NULL
    ///
    ///    In this case, the first chunk in the free list is allocated to the
    ///    user, and the head of the list is updated to point to the next free
    ///    block.
    ///
    ///    [   AllocatorHeader       | ChunkHeader1 | ... | ChunkHeader2 ]
    ///         ..   free_list_head      (allocated)      ↑       next
    ///                   |_______________________________↑         |____ NULL
    ///
    pub fn allocate(&mut self) -> Address {
        // Get the next available chunk.
        let chunk_addr = self.free_list_head;
        let mut chunk = ChunkHeader::load(chunk_addr, &self.memory);

        // The available chunk must not be allocated.
        assert!(
            !chunk.allocated,
            "Attempting to allocate an already allocated chunk."
        );

        // Allocate the chunk.
        chunk.allocated = true;
        chunk.save(chunk_addr, &self.memory);

        // Update the head of the free list.
        if chunk.next != NULL {
            // The next chunk becomes the new head of the list.
            self.free_list_head = chunk.next;
        } else {
            // There is no next chunk. Shift everything by chunk size.
            self.free_list_head += self.chunk_size();

            // Write new chunk to that location.
            ChunkHeader::null().save(self.free_list_head, &self.memory);
        }

        self.num_allocated_chunks += 1;
        self.save();

        // Return the chunk's address offset by the chunk's header.
        chunk_addr + ChunkHeader::size()
    }

    /// Deallocates a previously allocated chunk.
    pub fn deallocate(&mut self, address: Address) {
        let chunk_addr = address - ChunkHeader::size();

        let mut chunk = ChunkHeader::load(chunk_addr, &self.memory);

        assert!(chunk.allocated);

        chunk.allocated = false;
        chunk.next = self.free_list_head;

        chunk.save(chunk_addr, &self.memory);

        self.free_list_head = chunk_addr;

        self.num_allocated_chunks -= 1;
        self.save();
    }

    /// Save the allocator to memory.
    pub fn save(&self) {
        let header = AllocatorHeader {
            magic: *ALLOCATOR_MAGIC, //b"BTA",
            version: ALLOCATOR_LAYOUT_VERSION,
            _alignment: [0; 4],
            num_allocated_chunks: self.num_allocated_chunks,
            allocation_size: self.allocation_size,
            free_list_head: self.free_list_head,
            _buffer: [0; 16],
        };

        let header_slice = unsafe {
            core::slice::from_raw_parts(
                &header as *const _ as *const u8,
                core::mem::size_of::<AllocatorHeader>(),
            )
        };

        write(&self.memory, self.header_addr.get(), header_slice)
    }

    // The full size of a chunk, which is the size of the header + the `allocation_size` that's
    // available to the user.
    fn chunk_size(&self) -> Bytes {
        self.allocation_size + ChunkHeader::size()
    }
}

#[derive(Debug)]
#[repr(packed)]
struct ChunkHeader {
    magic: [u8; 3],
    version: u8,
    allocated: bool,
    // Empty space to memory-align the following fields.
    _alignment: [u8; 3],
    next: Address,
}

impl ChunkHeader {
    // Initializes an unallocated chunk that doesn't point to another chunk.
    fn null() -> Self {
        Self {
            magic: *CHUNK_MAGIC,
            version: CHUNK_LAYOUT_VERSION,
            allocated: false,
            _alignment: [0; 3],
            next: NULL,
        }
    }

    fn save<M: Memory>(&self, address: Address, memory: &M) {
        let chunk_slice = unsafe {
            core::slice::from_raw_parts(self as *const _ as *const u8, Self::size().into())
        };

        write(memory, address.get(), chunk_slice);
    }

    fn load(address: Address, memory: &impl Memory) -> Self {
        let mut header: ChunkHeader = unsafe { core::mem::zeroed() };
        let header_slice = unsafe {
            core::slice::from_raw_parts_mut(
                &mut header as *mut _ as *mut u8,
                core::mem::size_of::<ChunkHeader>(),
            )
        };

        memory.read(address.get(), header_slice);

        assert_eq!(&header.magic, CHUNK_MAGIC, "Bad magic.");
        assert_eq!(header.version, CHUNK_LAYOUT_VERSION, "Unsupported version.");

        header
    }

    fn size() -> Bytes {
        Bytes::from(core::mem::size_of::<Self>() as u64)
    }
}

fn write<M: Memory>(memory: &M, offset: u64, bytes: &[u8]) {
    let last_byte = offset
        .checked_add(bytes.len() as u64)
        .expect("Address space overflow");
    let size_pages = memory.size();
    let size_bytes = size_pages
        .checked_mul(WASM_PAGE_SIZE)
        .expect("Address space overflow");
    if size_bytes < last_byte {
        let diff_bytes = last_byte - size_bytes;
        let diff_pages = diff_bytes
            .checked_add(WASM_PAGE_SIZE - 1)
            .expect("Address space overflow")
            / WASM_PAGE_SIZE;
        assert!(
            memory.grow(diff_pages) != -1,
            "Failed to grow memory from {} pages to {} pages (delta = {} pages).",
            size_pages,
            size_pages + diff_pages,
            diff_pages
        );
    }
    memory.write(offset, bytes);
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Memory, WASM_PAGE_SIZE};
    use std::cell::RefCell;
    use std::rc::Rc;

    fn make_memory() -> Rc<RefCell<Vec<u8>>> {
        Rc::new(RefCell::new(Vec::new()))
    }

    #[test]
    fn new_and_load() {
        let mem = make_memory();
        let allocator_addr = Address::from(0);
        let allocation_size = Bytes::from(16);

        // Create a new allocator.
        Allocator::new(mem.clone(), allocator_addr, allocation_size);

        // Load it from memory.
        let allocator = Allocator::load(mem.clone(), allocator_addr);

        assert_eq!(allocator.allocation_size, allocation_size);
        assert_eq!(
            allocator.free_list_head,
            allocator_addr + AllocatorHeader::size()
        );

        // Load the first memory chunk.
        let chunk = ChunkHeader::load(allocator.free_list_head, &mem);
        assert_eq!(chunk.next, NULL);
    }

    #[test]
    fn allocate() {
        let mem = make_memory();
        let allocation_size = Bytes::from(16);

        let mut allocator = Allocator::new(mem, Address::from(0), allocation_size);

        let original_free_list_head = allocator.free_list_head;

        // Each allocation should push the `head` by `chunk_size`.
        for i in 1..=3 {
            allocator.allocate();
            assert_eq!(
                allocator.free_list_head,
                original_free_list_head + allocator.chunk_size() * i
            );
        }
    }

    #[test]
    fn allocate_large() {
        // Allocate large chunks to verify that we are growing the memory.
        let mem = make_memory();
        assert_eq!(mem.size(), 0);
        let allocator_addr = Address::from(0);
        let allocation_size = Bytes::from(WASM_PAGE_SIZE);

        let mut allocator = Allocator::new(mem.clone(), allocator_addr, allocation_size);
        assert_eq!(mem.size(), 1);

        allocator.allocate();
        assert_eq!(mem.size(), 2);

        allocator.allocate();
        assert_eq!(mem.size(), 3);

        allocator.allocate();
        assert_eq!(mem.size(), 4);

        // Each allocation should push the `head` by `chunk_size`.
        assert_eq!(
            allocator.free_list_head,
            allocator_addr + AllocatorHeader::size() + allocator.chunk_size() * 3
        );
        assert_eq!(allocator.num_allocated_chunks, 3);

        // Load and reload to verify that the data is the same.
        let allocator = Allocator::load(mem, Address::from(0));
        assert_eq!(
            allocator.free_list_head,
            allocator_addr + AllocatorHeader::size() + allocator.chunk_size() * 3
        );
        assert_eq!(allocator.num_allocated_chunks, 3);
    }

    #[test]
    fn allocate_then_deallocate() {
        let mem = make_memory();
        let allocation_size = Bytes::from(16);
        let allocator_addr = Address::from(0);

        let mut allocator = Allocator::new(mem.clone(), allocator_addr, allocation_size);

        let chunk_addr = allocator.allocate();

        assert_eq!(
            allocator.free_list_head,
            allocator_addr + AllocatorHeader::size() + allocator.chunk_size()
        );
        allocator.deallocate(chunk_addr);
        assert_eq!(
            allocator.free_list_head,
            allocator_addr + AllocatorHeader::size()
        );
        assert_eq!(allocator.num_allocated_chunks, 0);

        // Load and reload to verify that the data is the same.
        let allocator = Allocator::load(mem, allocator_addr);
        assert_eq!(
            allocator.free_list_head,
            allocator_addr + AllocatorHeader::size()
        );
        assert_eq!(allocator.num_allocated_chunks, 0);
    }

    #[test]
    fn allocate_deallocate_2() {
        let mem = make_memory();
        let allocation_size = Bytes::from(16);

        let mut allocator = Allocator::new(mem, Address::from(0), allocation_size);

        let _chunk_addr_1 = allocator.allocate();
        let chunk_addr_2 = allocator.allocate();

        assert_eq!(allocator.free_list_head, chunk_addr_2 + allocation_size);
        allocator.deallocate(chunk_addr_2);
        assert_eq!(allocator.free_list_head, chunk_addr_2 - ChunkHeader::size());

        let chunk_addr_3 = allocator.allocate();
        assert_eq!(chunk_addr_3, chunk_addr_2);
        assert_eq!(allocator.free_list_head, chunk_addr_3 + allocation_size);
    }

    #[test]
    #[should_panic]
    fn deallocate_free_chunk() {
        let mem = make_memory();
        let allocation_size = 16;

        let mut allocator = Allocator::new(mem, Address::from(0), Bytes::from(allocation_size));

        let chunk_addr = allocator.allocate();
        allocator.deallocate(chunk_addr);

        // Try deallocating the free chunk - should panic.
        allocator.deallocate(chunk_addr);
    }
}
