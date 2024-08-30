use bytes::{buf::UninitSlice, Buf, BufMut};
use ic_stable_structures::Memory;
use std::cmp::min;

/// This is not exported from stable structures so we must redefine it
const STABLE_STRUCTURES_WASM_PAGE_SIZE: u32 = 65_536;

// Forward compatible with u64 memory capacity
// This is the length of bytes stored to say how large the written object is.f
const OBJECT_SIZE_BYTES_RESERVED: u8 = 8;

/// Magic byte to identify the storage encoding implementation
const STORAGE_ENCODING_BYTES_RESERVED: u8 = 1;

/// For forwards compatibility we write a magic byte to allow for the storage implementation to evolve.
/// We keep the implementation private, and expose methods that take Memory and some payload.
/// The currently exposed methods take protobuf.
#[derive(Debug, PartialEq, Eq)]
enum StorageEncoding {
    Unknown = 0,
    SizeAware = 1,
}

impl StorageEncoding {
    fn write_byte(&self, memory: &impl Memory) {
        let byte = match self {
            StorageEncoding::Unknown => 0,
            StorageEncoding::SizeAware => 1,
        };

        safe_write_or_panic(memory, 0, &[byte]);
    }

    fn type_from_memory(memory: &impl Memory) -> Self {
        // First read the special code
        let mut stored = [0];
        let byte = if memory.size() > 0 {
            memory.read(0, &mut stored);
            *stored
                .first()
                .expect("No bytes found in storage, despite memory size being > 0.")
        } else {
            0
        };

        match byte {
            1 => Self::SizeAware,
            _ => Self::Unknown,
        }
    }
}

/// Store a protobuf into a [ic_stable_structures::Memory] that can be retrieved with [load_protobuf]
pub fn store_protobuf<M: Memory>(
    memory: &M,
    protobuf: &impl prost::Message,
) -> Result<(), std::io::Error> {
    let mut writer = SizeAwareWriter::new(
        memory,
        STABLE_STRUCTURES_WASM_PAGE_SIZE,
        STORAGE_ENCODING_BYTES_RESERVED as u64,
    );

    StorageEncoding::SizeAware.write_byte(memory);
    protobuf
        .encode(&mut writer)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::OutOfMemory, e))
}

/// Read a protobuf from a [ic_stable_structures::Memory] that was stored with [store_protobuf]
pub fn load_protobuf<M: Memory, T: prost::Message + Default>(
    memory: &M,
) -> Result<T, std::io::Error> {
    // This allows us to encode in a new way, but still read from the old way.  Eventually, we can
    // retire old ways of encoding/decoding, after the necessary deployments have happened.
    match StorageEncoding::type_from_memory(memory) {
        StorageEncoding::Unknown => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Unknown storage encoding",
        )),
        StorageEncoding::SizeAware => {
            let mut reader = SizeAwareReader::new(
                memory,
                STABLE_STRUCTURES_WASM_PAGE_SIZE,
                STORAGE_ENCODING_BYTES_RESERVED as u64,
            );
            T::decode(&mut reader)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }
    }
}

fn read_size_bytes<M: Memory>(memory: &M, offset: u64) -> u64 {
    let mut size_bytes = [0; OBJECT_SIZE_BYTES_RESERVED as usize];
    memory.read(offset, &mut size_bytes);
    u64::from_le_bytes(size_bytes)
}

fn safe_write_or_panic(memory: &impl Memory, offset: u64, to_write: &[u8]) {
    let last_byte = offset
        .checked_add(to_write.len() as u64)
        .expect("Address space overflow");

    let size_pages = memory.size();
    let size_bytes = size_pages
        .checked_mul(STABLE_STRUCTURES_WASM_PAGE_SIZE as u64)
        .expect("Address space overflow");

    if size_bytes < last_byte {
        let diff_bytes = last_byte - size_bytes;
        let diff_pages = diff_bytes
            .checked_add(STABLE_STRUCTURES_WASM_PAGE_SIZE as u64 - 1)
            .expect("Address space overflow")
            .checked_div(STABLE_STRUCTURES_WASM_PAGE_SIZE as u64)
            .expect("Unsafe division");
        // Assert grow works.  If this fails, we cannot recover and need to roll back.
        assert_ne!(memory.grow(diff_pages), -1, "Memory grow failed");
    }

    memory.write(offset, to_write);
}

struct SizeAwareWriter<'a, M: Memory> {
    memory: &'a M,
    /// In-memory buffer
    buffer: Vec<u8>,

    /// Current offset in `buffer`, in bytes
    buffer_offset: usize,

    /// Current offset in stable memory, in bytes. Next `write` will write to
    /// this offset.
    stable_mem_offset: u64,

    /// Number of bytes reserved in memory by something other than this writer.
    reserved_bytes: u64,
}

impl<M: Memory> Drop for SizeAwareWriter<'_, M> {
    fn drop(&mut self) {
        self.flush();
    }
}
impl<'a, M: Memory> SizeAwareWriter<'a, M> {
    /// Create a buffered writer with the given buffer size.
    pub fn new(memory: &'a M, buffer_size: u32, reserved_bytes: u64) -> Self {
        Self {
            buffer: vec![
                0;
                buffer_size
                    .try_into()
                    .expect("Buffer size overflowed on your architecture")
            ],
            buffer_offset: 0,
            stable_mem_offset: reserved_bytes
                .checked_add(OBJECT_SIZE_BYTES_RESERVED as u64)
                .expect("Address space overflow"),
            memory,
            reserved_bytes,
        }
    }

    /// Write the buffer contents to stable memory.
    pub fn flush(&mut self) {
        let data_ready_to_write = &self.buffer[0..self.buffer_offset];
        safe_write_or_panic(self.memory, self.stable_mem_offset, data_ready_to_write);

        // Update stable memory offset with just-written data
        let buffer_offset_u64 =
            u64::try_from(self.buffer_offset).expect("Buffer offset overflowed u64");
        self.stable_mem_offset = self
            .stable_mem_offset
            .checked_add(buffer_offset_u64)
            .expect("Stable_mem_offset overflowed u64.  Cannot write to stable memory.");

        // update recorded size stored in stable memory
        self.update_size_bytes();
        self.buffer_offset = 0;
    }

    /// Write the recorded bytes to stable memory.
    fn update_size_bytes(&self) {
        // We already check that reserved_bytes + STORED_OBJECT_SIZE_BYTES_LEN does not overflow in new()
        let size =
            self.stable_mem_offset.checked_sub(self.reserved_bytes + OBJECT_SIZE_BYTES_RESERVED as u64)
                .expect("Illegal stable_mem_offset, cannot be less than reserved_bytes + STORED_OBJECT_SIZE_BYTES_LEN");
        let size_bytes = size.to_le_bytes();
        safe_write_or_panic(self.memory, self.reserved_bytes, &size_bytes);
    }
}

// Unsafe implementation required by BufMut
unsafe impl<'a, M: Memory> BufMut for SizeAwareWriter<'a, M> {
    fn remaining_mut(&self) -> usize {
        // This function needs to return the number of bytes that can be written, not just to the
        // internal buffer, but to the underlying memory.
        // Unfortunately, we do not have any way of determining how much space is left, as we can
        // always attempt to "grow" memory, and we do not know when that will fail because we do not
        // know what other VirtualMemory's are taking space.
        (u64::MAX - self.stable_mem_offset) as usize
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        let new_len = self.buffer_offset + cnt;
        assert!(
            new_len <= self.buffer.len(),
            "new_len = {}; buffer_len = {}",
            new_len,
            self.buffer.len(),
        );
        self.buffer_offset = new_len;
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        // The mutable chunk returned is directly written to by the caller.
        // If it is full, the caller should be given an empty buffer after we write buffer contents.
        if self.buffer_offset == self.buffer.len() {
            self.flush();
        }
        let len = self.buffer_offset;
        let cap = self.buffer.len();
        let ptr = self.buffer.as_mut_ptr();

        unsafe { &mut UninitSlice::from_raw_parts_mut(ptr, cap)[len..] }
    }
}

struct SizeAwareReader<'a, M: Memory> {
    memory: &'a M,
    /// In-memory buffer
    buffer: Vec<u8>,

    /// Current offset in `buffer`, in bytes
    buffer_offset: usize,

    /// Current offset in stable memory, in bytes. Next `read` will read from
    /// this offset.
    stable_mem_offset: u64,

    /// Number of bytes reserved in memory by something other than this reader.  Must match
    /// the value used by the corresponding writer, or the read will be incorrect
    reserved_bytes: u64,
}

impl<'a, M: Memory> SizeAwareReader<'a, M> {
    /// Reserved bytes must be the same between the reader and writer in order for this to correctly
    /// read the size.
    pub fn new(memory: &'a M, buffer_size: u32, reserved_bytes: u64) -> Self {
        let mut reader = Self {
            memory,
            buffer: vec![
                0;
                buffer_size
                    .try_into()
                    .expect("Buffer size overflowed on your architecture")
            ],
            buffer_offset: 0,
            stable_mem_offset: reserved_bytes
                .checked_add(OBJECT_SIZE_BYTES_RESERVED as u64)
                .expect("Address space overflow"),
            reserved_bytes,
        };
        reader.read();
        reader
    }

    /// Fill up the buffer with the next segment of data from stable memory.
    fn read(&mut self) {
        // Clear existing data in buffer
        self.buffer.clear();
        let stable_mem_len = self.memory_used();
        // Number of bytes to read: minimum of buffer size and remaining amount
        let n_bytes = min(
            self.buffer.capacity() as u64, // cast works as the initialization argument is u32
            stable_mem_len.saturating_sub(self.stable_mem_offset),
        );
        // This is needed to only read a set portion of the buffer after we clear it above
        unsafe {
            self.buffer.set_len(n_bytes as usize);
        }

        self.memory
            .read(self.stable_mem_offset, &mut self.buffer[..n_bytes as usize]);

        self.buffer_offset = 0;
        // n_bytes cannot be greater than memory used minus stable_mem_offset, which are both u64.  This cannot overflow.
        self.stable_mem_offset = self
            .stable_mem_offset
            .checked_add(n_bytes)
            .expect("Tried to read more bytes than can be in stable memory.");
    }

    /// Returns the amount of memory that is being used by the data written by the invocation of
    /// the writer, which stores its bytes
    /// to the size bytes stored in the first 8 bytes of the memory segment.  These bytes are
    /// written by the Writer.
    ///
    /// If other objects were written previously that were larger than the most recent write,
    /// this does not account for that size.
    fn memory_used(&self) -> u64 {
        let object_size = read_size_bytes(self.memory, self.reserved_bytes);
        object_size + self.reserved_bytes + OBJECT_SIZE_BYTES_RESERVED as u64
    }
}

impl<'a, M: Memory> Buf for SizeAwareReader<'a, M> {
    fn remaining(&self) -> usize {
        // Our implementation only reads from stable memory up until the size indicated by size bytes
        let total_written_memory = self.memory_used();

        let remaining_to_be_read_from_memory = total_written_memory
            .checked_sub(self.stable_mem_offset)
            .expect("Stable_mem_offset was greater than total_written_memory.  Failing");

        let remaining_to_be_read_from_buffer = self.buffer.len().saturating_sub(self.buffer_offset);

        let remaining = remaining_to_be_read_from_memory
            .checked_add(remaining_to_be_read_from_buffer as u64)
            .expect("Overflow, could not calculate remaining");

        remaining as usize
    }

    fn chunk(&self) -> &[u8] {
        &self.buffer[self.buffer_offset..]
    }

    fn advance(&mut self, cnt: usize) {
        let remaining = self.remaining();
        assert!(
            cnt <= remaining,
            "Trying to advance {} bytes while only {} bytes remaining",
            cnt,
            remaining
        );

        // Why below is correct:
        //
        // Definition 1: the absolute address of the cursor is the address of
        // `self.buffer[self.buffer_offset]` within the entire `Buf`, which can also be expressed as
        // `self.stable_mem_offset - self.buffer.len() + self.buffer_offset`.
        //
        // Definition 2: the absolute address of the buffer start is the address of `self.buffer[0]`
        // within the entire `Buf`.
        //
        // The intended effect of this method is to change the state(`self.buffer`,
        // `self.buffer_offset`, `self.stable_mem_offset`) so that the absolute address it
        // represents is `cnt` larger than its current state, while maintaining the invariant that
        // `self.buffer_offset < self.buffer.len()`.
        //
        // Without considering the invariant, we can simply increment `self.buffer_offset` by `cnt`.
        // However, to maintain the invariant:
        //
        // Every `read()` increases the absolute address of the buffer start by `buffer_size` (note
        // that it does not always increase the buffer end by `buffer_size` because the last
        // `read()` could read fewer than `buffer_size`). At the same time, if we decrease
        // `self.buffer_offset` by `buffer_size`, the combined effect is that the absolute address
        // of the cursor would be unchanged. Therefore, if we do the 2 things any number of times,
        // we can still keep the absolute address of the cursor unchanged.
        //
        // Given the `checked_div_mod` arithmetic, we know that `self.buffer_offset + cnt =
        // num_buffers_to_advance * buffer_size + new_buffer_offset`.
        //
        // Doing the above-mentioned 2 things `num_buffers_to_advance` times will result in: (1)
        // calling read() `num_buffers_to_advance` times (2) set `self.buffer_offset =
        // self.buffer_offset + cnt - num_buffers_to_advance * buffer_size = new_buffer_offset`.
        let (num_buffers_to_advance, new_buffer_offset) = crate::checked_div_mod(
            self.buffer_offset
                .checked_add(cnt)
                .expect("Tried to advance buffer beyond maximum offset"),
            self.buffer.capacity(),
        );

        for _ in 0..num_buffers_to_advance {
            self.read();
        }
        self.buffer_offset = new_buffer_offset;
    }
}

#[cfg(test)]
mod test {
    use crate::{
        assert_is_err,
        memory_manager_upgrade_storage::{
            load_protobuf, read_size_bytes, store_protobuf, SizeAwareReader, SizeAwareWriter,
            StorageEncoding, OBJECT_SIZE_BYTES_RESERVED, STABLE_STRUCTURES_WASM_PAGE_SIZE,
            STORAGE_ENCODING_BYTES_RESERVED,
        },
    };
    use bytes::{Buf, BufMut};
    use ic_nns_governance_api::pb::v1::{Governance, NetworkEconomics, Neuron};
    use ic_stable_structures::{vec_mem::VectorMemory, Memory};
    use prost::Message;

    fn allocate_governance(num_neurons: u64) -> Governance {
        let mut gov = Governance {
            economics: Some(NetworkEconomics::with_default_values()),
            ..Default::default()
        };

        for i in 0..num_neurons {
            gov.neurons.insert(i, Neuron::default());
        }

        gov
    }

    #[test]
    fn test_size_aware_writer() {
        let memory = VectorMemory::default();

        // Make memory with 1 page of memory.
        memory
            .borrow_mut()
            .append(&mut vec![0u8; STABLE_STRUCTURES_WASM_PAGE_SIZE as usize]);

        // Make a writer that will allocate a large buffer so we can fill up the memory.
        let mut writer = SizeAwareWriter::new(
            &memory,
            STABLE_STRUCTURES_WASM_PAGE_SIZE - OBJECT_SIZE_BYTES_RESERVED as u32,
            0,
        );

        let x = writer.chunk_mut();
        x.copy_from_slice(
            &[1; STABLE_STRUCTURES_WASM_PAGE_SIZE as usize - OBJECT_SIZE_BYTES_RESERVED as usize],
        );
        let bytes_to_write_length =
            STABLE_STRUCTURES_WASM_PAGE_SIZE as usize - OBJECT_SIZE_BYTES_RESERVED as usize;
        unsafe { writer.advance_mut(bytes_to_write_length) }

        writer.flush();

        // We expect the size of the data stored to be 1024, but the size of the total memory to be
        // that plus the reserved bytes.
        let size_written = read_size_bytes(&memory, 0);
        assert_eq!(bytes_to_write_length as u64, size_written);
        // We expect that no memory was allocated at this point.
        assert_eq!(
            STABLE_STRUCTURES_WASM_PAGE_SIZE as usize,
            memory.borrow().len()
        );

        let x = writer.chunk_mut();

        x.write_byte(0, 1);

        unsafe { writer.advance_mut(1) }
        writer.flush();

        // We expect one more byte to be recorded as written.
        let size_written = read_size_bytes(&memory, 0);
        assert_eq!((bytes_to_write_length + 1) as u64, size_written);
        // We expect one additional page of memory to have been allocated.
        assert_eq!(
            2 * STABLE_STRUCTURES_WASM_PAGE_SIZE as usize,
            memory.borrow().len()
        );
    }

    #[test]
    fn test_size_aware_reader() {
        let memory = VectorMemory::default();

        let gov = allocate_governance(10);
        let mut vec = vec![];

        gov.encode(&mut vec).expect("encoding failed");
        let mut size = vec.len().to_le_bytes().to_vec();

        // Make memory with 1 page of memory.
        memory.borrow_mut().append(&mut size);
        memory.borrow_mut().append(&mut vec);

        let mut reader = SizeAwareReader::new(&memory, 100, 0);
        let decoded = Governance::decode(&mut reader).expect("Decode failed");
        assert_eq!(gov, decoded);
    }

    #[test]
    fn test_size_aware_reader_advance_as_buf() {
        // We should be able to call `Buf::advance(cnt)` as long as `cnt < self.remaining()`. More
        // specifically, we try to advance past one buffer size (100).
        let memory = VectorMemory::default();

        let mut vec: Vec<_> = (0u8..=255).collect();
        let mut size = vec.len().to_le_bytes().to_vec();

        memory.borrow_mut().append(&mut size);
        memory.borrow_mut().append(&mut vec);

        // There will be 3 pages (256 bytes with 100 per page).
        let mut reader = SizeAwareReader::new(&memory, 100, 0);

        // Advancing 36 times will get to byte 252.
        for i in 1..=36 {
            // Advance in a way that cannot align with the buffer size 100, and advance() should not panic.
            reader.advance(7);
            assert_eq!(reader.remaining(), (256 - 7 * i) as usize);
            assert_eq!(reader.chunk()[0], (7 * i) as u8);
        }
    }

    #[test]
    #[should_panic]
    fn test_size_aware_reader_should_panic_when_advancing_past_end() {
        let memory = VectorMemory::default();

        let mut vec = [1u8; 1000].to_vec();
        let mut size = vec.len().to_le_bytes().to_vec();

        memory.borrow_mut().append(&mut size);
        memory.borrow_mut().append(&mut vec);

        let mut reader = SizeAwareReader::new(&memory, 100, 0);
        reader.advance(1001);
    }

    #[test]
    fn tiny_buffer_value() {
        let memory = VectorMemory::default();

        let gov1 = allocate_governance(1_893);
        {
            let mut writer = SizeAwareWriter::new(&memory, 1, 100);
            gov1.encode(&mut writer).unwrap();
        }

        let reader = SizeAwareReader::new(&memory, 1, 100);
        let decoded: Governance = Governance::decode(reader).unwrap();
        assert_eq!(gov1, decoded);
    }

    #[test]
    fn test_size_recording_writer_and_size_aware_reader() {
        let memory = VectorMemory::default();

        let gov1 = allocate_governance(1_893);
        {
            let mut writer = SizeAwareWriter::new(&memory, 40, 0);
            gov1.encode(&mut writer).unwrap();
        }

        let reader = SizeAwareReader::new(&memory, 1_000, 0);
        let decoded: Governance = Governance::decode(reader).unwrap();
        assert_eq!(gov1, decoded);

        let gov2 = allocate_governance(397);
        {
            let mut writer = SizeAwareWriter::new(&memory, 40, 0);
            gov2.encode(&mut writer).unwrap();
        }

        let reader = SizeAwareReader::new(&memory, 1_000, 0);
        let decoded: Governance = Governance::decode(reader).unwrap();
        assert_eq!(gov2, decoded);
    }

    #[test]
    fn test_store_and_load_protobuf() {
        let gov = allocate_governance(1);
        let memory = VectorMemory::default();

        store_protobuf(&memory, &gov).expect("Storing failed in test");
        let decoded: Governance = load_protobuf(&memory).expect("Loading failed in test");

        assert_eq!(gov, decoded);
    }

    #[derive(::prost::Message)]
    pub struct TestMessageWithoutSubMessage {
        #[prost(fixed32, repeated, tag = "1")]
        pub x: ::prost::alloc::vec::Vec<u32>,
    }
    #[derive(::prost::Message)]
    pub struct TestMessageWithSubMessage {
        #[prost(fixed32, repeated, tag = "1")]
        pub x: ::prost::alloc::vec::Vec<u32>,
        #[prost(message, optional, tag = "2")]
        pub sub: ::core::option::Option<TestSubMessage>,
    }
    #[derive(::prost::Message)]
    pub struct TestSubMessage {
        #[prost(fixed32, repeated, tag = "1")]
        pub y: ::prost::alloc::vec::Vec<u32>,
    }

    #[test]
    fn test_store_and_load_protobuf_with_missing_field() {
        // The 'missing field' `sub` needs to be larger than 64KB, and 20000 * 4B > 64KB.
        let m2 = TestMessageWithSubMessage {
            x: (0..1000).collect(),
            sub: Some(TestSubMessage {
                y: (0..20000).collect(),
            }),
        };
        let memory = VectorMemory::default();

        store_protobuf(&memory, &m2).expect("Storing failed in test");
        let _: TestMessageWithoutSubMessage =
            load_protobuf(&memory).expect("Loading failed in test");
    }

    #[test]
    fn test_multiple_writes_results_in_safe_read() {
        let gov1 = allocate_governance(3);
        let memory = VectorMemory::default();

        store_protobuf(&memory, &gov1).expect("Storing failed in test");
        store_protobuf(&memory, &gov1).expect("Storing failed in test");

        let decoded: Governance = load_protobuf(&memory).expect("Loading failed in test");

        assert_eq!(gov1, decoded);

        let gov2 = allocate_governance(1);
        store_protobuf(&memory, &gov2).expect("Storing failed in test");

        let decoded: Governance = load_protobuf(&memory).expect("Loading failed in test");

        assert_eq!(gov2, decoded);

        let size = read_size_bytes(&memory, STORAGE_ENCODING_BYTES_RESERVED as u64);
        let reserved = (OBJECT_SIZE_BYTES_RESERVED + STORAGE_ENCODING_BYTES_RESERVED) as usize;
        let decoded =
            Governance::decode(&memory.borrow().as_slice()[reserved..(reserved + size as usize)])
                .expect("Loading failed in test");

        assert_eq!(gov2, decoded);
    }

    #[test]
    fn test_read_fails_with_unknown_magic_byte() {
        let memory = VectorMemory::default();

        let gov = allocate_governance(1_893);

        store_protobuf(&memory, &gov).expect("Storing failed in test");

        // Currently this is an unknown value for StorageEncoding
        memory.write(0, &[254]);

        assert_is_err!(load_protobuf::<_, Governance>(&memory));
    }

    #[test]
    fn type_from_memory_succeeds_even_with_empty_memory() {
        let memory = VectorMemory::default();
        assert_eq!(
            StorageEncoding::type_from_memory(&memory),
            StorageEncoding::Unknown
        );
    }
}
