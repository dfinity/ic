//! Implements `BufferedStableMemWriter` and `BufferedStableMemReader` types for
//! buffered serialization and deserialization to/from stable memory.

use std::cmp::min;
use std::convert::TryFrom;

#[cfg(test)]
use std::sync::{Arc, Mutex};

use bytes::buf::UninitSlice;
use bytes::{Buf, BufMut};

use dfn_core::stable;

/// A trait for stable memory operations, to allow testing.
trait StableMemory {
    /// Write `content` to `offset` in stable memory
    fn write(&mut self, content: &[u8], offset: u32);

    /// Read `size` bytes from `offset` in stable memory
    fn read(&mut self, offset: u32, size: u32) -> Vec<u8>;

    /// Size of the stable memory, in bytes
    ///
    /// (Note: that IC stable memroy API does not keep track of this.
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
        (&mut vec[offset..range_end]).copy_from_slice(content)
    }

    fn read(&mut self, offset: u32, size: u32) -> Vec<u8> {
        let vec = self.0.lock().unwrap();
        (&vec[offset as usize..(offset + size) as usize]).to_vec()
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
        &self.buffer[self.buffer_offset as usize..]
    }

    fn advance(&mut self, cnt: usize) {
        self.buffer_offset += cnt;
        assert!(self.buffer_offset <= self.buffer.len());

        if self.buffer_offset == self.buffer.len() {
            self.read();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pb::v1::{Governance, NetworkEconomics, Neuron};
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

    const TEST_DATA_SIZE: usize = 1024; // 1KiB

    #[test]
    fn test_buffer_sizes() {
        let mut data = Vec::with_capacity(TEST_DATA_SIZE as usize);
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
