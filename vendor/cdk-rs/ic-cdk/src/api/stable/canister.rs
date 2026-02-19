use super::*;

/// A standard implementation of [`StableMemory`].
///
/// Useful for creating [`StableWriter`] and [`StableReader`].
#[derive(Default, Debug, Copy, Clone)]
pub struct CanisterStableMemory {}

impl StableMemory for CanisterStableMemory {
    fn stable_size(&self) -> u64 {
        ic0::stable64_size()
    }

    fn stable_grow(&self, new_pages: u64) -> Result<u64, StableMemoryError> {
        match ic0::stable64_grow(new_pages) {
            u64::MAX => Err(StableMemoryError::OutOfMemory),
            x => Ok(x),
        }
    }

    fn stable_write(&self, offset: u64, buf: &[u8]) {
        ic0::stable64_write(buf, offset);
    }

    fn stable_read(&self, offset: u64, buf: &mut [u8]) {
        ic0::stable64_read(buf, offset);
    }
}
