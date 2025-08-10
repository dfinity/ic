#[cfg(test)]
mod tests;

use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
use std::convert::AsRef;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// `ScopedMmap` contains a memory region that is automatically
/// unmapped when the value is dropped.
pub struct ScopedMmap {
    // it's only `mut` because `munmap` wants `mut` pointers.
    addr: *mut std::ffi::c_void,
    len: usize,
}

// It's safe to access the mapping from multiple threads because it's read-only.
unsafe impl Sync for ScopedMmap {}
unsafe impl Send for ScopedMmap {}

impl ScopedMmap {
    /// Creates a new mapping from a file descriptor, length (in bytes) and offset (in bytes).
    pub fn from_readonly_file_with_offset<FD: AsRawFd>(
        fd: &FD,
        len: usize,
        offset: i64,
    ) -> io::Result<Self> {
        // mmap fails on 0-size requests, which is extremely annoying in
        // practice, so we construct a bogus 0-sized mapping instead.
        if len == 0 {
            return Ok(Self {
                addr: std::ptr::null_mut(),
                len,
            });
        }

        // It's not clear why mmap-ing a file is considered unsafe.  Using the
        // address is indeed unsafe, but mmap itself doesn't do anything bad.
        let addr = unsafe {
            mmap(
                std::ptr::null_mut(),
                len,
                ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED,
                fd.as_raw_fd(),
                offset,
            )
        }?;
        Ok(Self { addr, len })
    }

    /// Creates a new mapping from a file descriptor and length.
    pub fn from_readonly_file<FD: AsRawFd>(fd: &FD, len: usize) -> io::Result<Self> {
        Self::from_readonly_file_with_offset(fd, len, 0)
    }

    /// Creates a new mapping for a file at specified `path`.
    pub fn from_path<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::mmap_file_readonly(std::fs::File::open(path)?)
    }

    /// Creates a full read-only mapping for the specified file.
    pub fn mmap_file_readonly(f: std::fs::File) -> io::Result<Self> {
        let len = f.metadata()?.len() as usize;
        Self::from_readonly_file(&f, len)
    }

    /// Returns start address of the memory mapping.
    /// Prefer using `as_slice` whenever possible.
    pub fn addr(&self) -> *const u8 {
        self.addr as *const u8
    }

    /// Returns the length of the allocated region in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the memory region has zero length.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns a byte slice view of the memory mapping.
    pub fn as_slice(&self) -> &[u8] {
        // A precondition for `from_raw_parts` is that the pointer must be non-null.
        // Otherwise a panic will occur.
        if self.addr().is_null() {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.addr(), self.len()) }
    }
}

impl Drop for ScopedMmap {
    fn drop(&mut self) {
        if self.len > 0 {
            unsafe { munmap(self.addr, self.len) }.expect("Failed to unmap");
        }
    }
}

impl AsRef<[u8]> for ScopedMmap {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
