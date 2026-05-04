use std::io::{Result, Write};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct SharedBuffer {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl SharedBuffer {
    /// Resets the buffer to empty returning the existing data.
    pub fn reset(&self) -> Vec<u8> {
        std::mem::take(&mut self.inner.lock().unwrap())
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.inner.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
