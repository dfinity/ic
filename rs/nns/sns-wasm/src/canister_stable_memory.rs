use ic_cdk::api::stable::{
    stable_grow, stable_read, stable_size, stable_write, StableMemory, StableMemoryError,
};
use std::sync::{Arc, Mutex};

/// Provides a `StableMemory` implementation backed by ic_cdk
#[derive(Copy, Clone, Default)]
pub struct CanisterStableMemory {}

impl StableMemory for CanisterStableMemory {
    fn stable_size(&self) -> u64 {
        stable_size()
    }

    fn stable_grow(&self, new_pages: u64) -> Result<u64, StableMemoryError> {
        stable_grow(new_pages)
    }

    fn stable_write(&self, offset: u64, buf: &[u8]) {
        stable_write(offset, buf)
    }

    fn stable_read(&self, offset: u64, buf: &mut [u8]) {
        stable_read(offset, buf)
    }
}

const WASM_PAGE_SIZE_IN_BYTES: usize = 64 * 1024;

/// Provides a test implementation of `StableMemory` (backed by a Vec<u8>)
#[derive(Clone, Default)]
pub struct TestCanisterStableMemory {
    memory: Arc<Mutex<Vec<u8>>>,
}

impl StableMemory for TestCanisterStableMemory {
    fn stable_size(&self) -> u64 {
        let memory = self.memory.lock().unwrap();
        (memory.len() / WASM_PAGE_SIZE_IN_BYTES) as u64
    }

    fn stable_grow(&self, new_pages: u64) -> Result<u64, StableMemoryError> {
        let size = self.stable_size();
        let mut memory = self.memory.lock().unwrap();
        let old_len = memory.len();
        memory.resize(
            old_len + ((new_pages as usize) * WASM_PAGE_SIZE_IN_BYTES),
            0,
        );
        Ok(size)
    }

    fn stable_write(&self, offset: u64, buf: &[u8]) {
        let offset = offset as usize;
        let range_end = offset + buf.len();
        let mut memory = self.memory.lock().unwrap();
        (&mut memory)[offset..range_end].copy_from_slice(buf)
    }

    fn stable_read(&self, offset: u64, buf: &mut [u8]) {
        let offset = offset as usize;
        let range_end = offset + buf.len();
        let memory = self.memory.lock().unwrap();
        buf.copy_from_slice(&memory[offset..range_end])
    }
}