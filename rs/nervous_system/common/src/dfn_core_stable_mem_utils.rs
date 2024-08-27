//! Implements `BufferedStableMemWriter` and `BufferedStableMemReader` types for
//! buffered serialization and deserialization to/from stable memory.

use bytes::{buf::UninitSlice, Buf, BufMut};
use dfn_core::stable;
#[cfg(test)]
use std::sync::{Arc, Mutex};
use std::{cmp::min, convert::TryFrom};

/// A trait for stable memory operations, to allow testing.
trait StableMemory {
    /// Write `content` to `offset` in stable memory
    fn write(&mut self, content: &[u8], offset: u32);

    /// Read `size` bytes from `offset` in stable memory
    fn read(&mut self, offset: u32, size: u32) -> Vec<u8>;

    /// Size of the stable memory, in bytes
    ///
    /// (Note: that IC stable memory API does not keep track of this.
    /// `dfn_core::stable` uses 4 bytes at the beginning of the stable memory
    /// for length)
    fn length(&self) -> u32;

    /// Sets the size of the stable memory, in bytes
    fn set_length(&mut self, len: u32);
}

struct StableMemoryImplementation;

impl StableMemory for StableMemoryImplementation {
    fn write(&mut self, content: &[u8], offset: u32) {
        stable::write(content, offset)
    }

    fn read(&mut self, offset: u32, size: u32) -> std::vec::Vec<u8> {
        stable::read(offset, size)
    }

    fn length(&self) -> u32 {
        stable::length()
    }

    fn set_length(&mut self, len: u32) {
        stable::set_length(len);
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct FakeStableMemory(Arc<Mutex<Vec<u8>>>);

#[cfg(test)]
impl StableMemory for FakeStableMemory {
    fn write(&mut self, content: &[u8], offset: u32) {
        let mut vec = self.0.lock().unwrap();
        let offset = offset as usize;
        let range_end = offset + content.len();
        if range_end > vec.len() {
            vec.resize(range_end, 0);
        }
        vec[offset..range_end].copy_from_slice(content)
    }

    fn read(&mut self, offset: u32, size: u32) -> Vec<u8> {
        let vec = self.0.lock().unwrap();
        vec[offset as usize..(offset + size) as usize].to_vec()
    }

    fn length(&self) -> u32 {
        let vec = self.0.lock().unwrap();
        vec.len() as u32
    }

    fn set_length(&mut self, length: u32) {
        self.0.lock().unwrap().resize(length as usize, 0);
    }
}

/// An implementation of `BufMut` that writes to stable memory in chunks. Chunk
/// size is specified on initialization, in `BufferedStableMemWriter::new`.
///
/// Note that you need to drop this, or call `flush()`, after using the `BufMut`
/// methods, to write the buffer contents into the stable memory.
pub struct BufferedStableMemWriter {
    /// In-memory buffer
    buffer: Vec<u8>,

    /// Current offset in `buffer`, in bytes
    buffer_offset: usize,

    /// Current offset in stable memory, in bytes. Next write will write to this
    /// offset in stable memory.
    stable_mem_offset: u32,

    /// Stable memory implementation. A field to allow testing.
    stable_mem: Box<dyn StableMemory>,
}

impl Drop for BufferedStableMemWriter {
    fn drop(&mut self) {
        self.flush()
    }
}

impl BufferedStableMemWriter {
    /// Create a buffered writer with the given buffer size.
    pub fn new(buffer_size_bytes: u32) -> Self {
        Self {
            buffer: vec![0; buffer_size_bytes as usize],
            buffer_offset: 0,
            stable_mem_offset: 0,
            stable_mem: Box::new(StableMemoryImplementation),
        }
    }

    /// Create a test instance that uses a vector as stable memory.
    #[cfg(test)]
    fn new_test(buffer_size_bytes: u32, memory: Arc<Mutex<Vec<u8>>>) -> Self {
        let test_mem = FakeStableMemory(memory);
        Self {
            buffer: vec![0; buffer_size_bytes as usize],
            buffer_offset: 0,
            stable_mem_offset: 0,
            stable_mem: Box::new(test_mem),
        }
    }

    /// Write the buffer contents to stable memory.
    pub fn flush(&mut self) {
        self.stable_mem
            .write(&self.buffer[0..self.buffer_offset], self.stable_mem_offset);
        self.stable_mem_offset += u32::try_from(self.buffer_offset).unwrap();
        self.buffer_offset = 0;
        self.stable_mem.set_length(self.stable_mem_offset);
    }
}

unsafe impl BufMut for BufferedStableMemWriter {
    fn remaining_mut(&self) -> usize {
        usize::MAX - self.buffer.len()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        let new_len = self.buffer_offset + cnt;
        assert!(
            new_len <= self.buffer.len(),
            "new_len = {}; capacity = {}",
            new_len,
            self.buffer.len(),
        );
        self.buffer_offset = new_len;
    }

    // https://github.com/tokio-rs/bytes/blob/2428c152a67c06057a98d9d29b08389cb3429c1f/src/buf/buf_mut.rs#L1046-L1057
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        if self.buffer_offset == self.buffer.len() {
            self.stable_mem
                .write(self.buffer.as_slice(), self.stable_mem_offset);

            self.stable_mem_offset += u32::try_from(self.buffer.len()).unwrap();
            self.buffer_offset = 0;
        }

        let len = self.buffer_offset;
        let cap = self.buffer.len();
        let ptr = self.buffer.as_mut_ptr();

        unsafe { &mut UninitSlice::from_raw_parts_mut(ptr, cap)[len..] }
    }
}

/// An implementation of `Buf` that reads from stable memory in chunks. Chunk
/// size is specified on initialization, in `BufferedStableReader::new`.
pub struct BufferedStableMemReader {
    /// In-memory buffer
    buffer: Vec<u8>,

    /// Current offset in `buffer`, in bytes
    buffer_offset: usize,

    /// Current offset in stable memory, in bytes. Next `read` will read from
    /// this offset.
    stable_mem_offset: u32,

    /// Stable memory implementation. A field to allow testing.
    stable_mem: Box<dyn StableMemory>,
}

impl BufferedStableMemReader {
    /// Create a buffered reader with the given buffer size.
    pub fn new(buffer_size_bytes: u32) -> Self {
        let mut reader = Self {
            buffer: Vec::with_capacity(buffer_size_bytes as usize),
            buffer_offset: 0,
            stable_mem_offset: 0,
            stable_mem: Box::new(StableMemoryImplementation),
        };
        reader.read();
        reader
    }

    /// Create a test instance that uses the given vector as the stable memory.
    #[cfg(test)]
    fn new_test(buffer_size_bytes: u32, contents: Vec<u8>) -> Self {
        let test_mem = FakeStableMemory(Arc::new(Mutex::new(contents)));
        let mut reader = Self {
            buffer: Vec::with_capacity(buffer_size_bytes as usize),
            buffer_offset: 0,
            stable_mem_offset: 0,
            stable_mem: Box::new(test_mem),
        };
        reader.read();
        reader
    }

    /// Read the next chunk from the stable memory
    fn read(&mut self) {
        self.buffer.clear();
        let stable_mem_len = self.stable_mem.length();
        // Number of bytes to read: minimum of buffer size and remaining amount
        let n_bytes = min(
            self.buffer.capacity() as u32, // cast works as the initialization argument is u32
            stable_mem_len - self.stable_mem_offset,
        );
        self.buffer = self.stable_mem.read(self.stable_mem_offset, n_bytes);
        self.buffer_offset = 0;
        self.stable_mem_offset += n_bytes;
    }
}

impl Buf for BufferedStableMemReader {
    fn remaining(&self) -> usize {
        let total_size = self.stable_mem.length() as usize;
        total_size - (self.stable_mem_offset as usize) + (self.buffer.len() - self.buffer_offset)
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
    use super::*;
    use bytes::Buf;
    use ic_nns_governance_api::pb::v1::{Governance, NetworkEconomics, Neuron};
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
    fn test_size_aware_reader_advance_as_buf() {
        // We should be able to call `Buf::advance(cnt)` as long as `cnt < self.remaining()`. More
        // specifically, we try to advance past one buffer size (100).
        let mut reader = BufferedStableMemReader::new_test(100, (0u8..=255).collect());

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
        let mut reader = BufferedStableMemReader::new_test(100, [1u8; 1000].to_vec());
        reader.advance(1001);
    }

    #[test]
    fn test_buffered_stable_mem_writer() {
        let gov = allocate_governance(7821);
        let memory = Arc::new(Mutex::new(vec![]));
        let mut writer = BufferedStableMemWriter::new_test(1024, memory.clone());

        gov.encode(&mut writer).unwrap();
        writer.flush();

        let decoded: Governance = Governance::decode(memory.lock().unwrap().as_slice()).unwrap();

        assert_eq!(gov, decoded);
    }

    #[test]
    fn test_write_large_then_small() {
        let memory = Arc::new(Mutex::new(vec![]));

        let gov1 = allocate_governance(1893);
        {
            let mut writer = BufferedStableMemWriter::new_test(40, memory.clone());
            gov1.encode(&mut writer).unwrap();
        }

        let gov2 = allocate_governance(397);
        {
            let mut writer = BufferedStableMemWriter::new_test(40, memory.clone());
            gov2.encode(&mut writer).unwrap();
        }

        let decoded: Governance = Governance::decode(memory.lock().unwrap().as_slice()).unwrap();

        assert_eq!(gov2, decoded);
    }

    #[test]
    fn test_buffered_stable_mem_reader() {
        let gov = allocate_governance(530);

        let mut serialized = Vec::new();
        gov.encode(&mut serialized).unwrap();

        let reader = BufferedStableMemReader::new_test(1024, serialized);

        let decoded = Governance::decode(reader).unwrap();

        assert_eq!(decoded, gov);
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
    fn test_encode_and_decode_protobuf_with_missing_field() {
        // The 'missing field' `sub` needs to be larger than 1KB, and 300 * 4B > 1KB.
        let m2 = TestMessageWithSubMessage {
            x: (0..100).collect(),
            sub: Some(TestSubMessage {
                y: (0..300).collect(),
            }),
        };
        let mut serialized = Vec::new();
        m2.encode(&mut serialized).expect("Encoding failed in test");

        let reader = BufferedStableMemReader::new_test(1024, serialized);
        TestMessageWithoutSubMessage::decode(reader).expect("Decoding failed in test");
    }

    const TEST_DATA_SIZE: usize = 1024; // 1KiB

    #[test]
    fn test_buffer_sizes() {
        let mut data = Vec::with_capacity(TEST_DATA_SIZE);
        let mut i: u8 = 0;
        for _ in 0..TEST_DATA_SIZE {
            data.push(i);
            i = i.wrapping_add(1);
        }

        let data = data; // make it immutable

        for buffer_size in 1..=TEST_DATA_SIZE + 1 {
            // Test writer correctness
            {
                let memory = Arc::new(Mutex::new(vec![]));
                let mut writer =
                    BufferedStableMemWriter::new_test(buffer_size as u32, memory.clone());
                data.encode(&mut writer).unwrap();
                writer.flush();

                let decoded: Vec<u8> = Vec::decode(memory.lock().unwrap().as_slice()).unwrap();
                assert_eq!(decoded, data);
            }

            // Test reader correctness
            {
                let mut encoded = vec![];
                data.encode(&mut encoded).unwrap();
                let mut reader = BufferedStableMemReader::new_test(buffer_size as u32, encoded);
                let decoded = Vec::decode(&mut reader).unwrap();
                assert_eq!(decoded, data);
            }
        }
    }
}
