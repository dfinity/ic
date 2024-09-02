use std::collections::HashMap;
use std::io::Error;
use std::ops::Deref;
use std::ptr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use anyhow::bail;
use ic_sys::PAGE_SIZE;
use ic_types::MAX_STABLE_MEMORY_IN_BYTES;
use libc::c_void;
use libc::MAP_FAILED;
use libc::{mmap, munmap};
use libc::{MAP_ANON, MAP_PRIVATE, PROT_NONE};
use wasmtime::{LinearMemory, MemoryType};
use wasmtime_environ::WASM32_MAX_SIZE;

use crate::MIN_GUARD_REGION_SIZE;

const WASM_PAGE_SIZE: u32 = wasmtime_environ::Memory::DEFAULT_PAGE_SIZE;

pub fn round_up_to_page_size(size: usize, page_size: usize) -> usize {
    (size + (page_size - 1)) & !(page_size - 1)
}

fn is_multiple_of_page_size(size: usize) -> bool {
    size == round_up_to_page_size(size, PAGE_SIZE)
}

#[derive(Hash, PartialEq, Eq)]
pub(crate) struct MemoryStart(pub(crate) usize);

pub(crate) struct MemoryPageSize(Arc<AtomicUsize>);

impl Deref for MemoryPageSize {
    type Target = Arc<AtomicUsize>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct WasmtimeMemoryCreator {
    created_memories: Arc<Mutex<HashMap<MemoryStart, MemoryPageSize>>>,
}

impl WasmtimeMemoryCreator {
    pub(crate) fn new(created_memories: Arc<Mutex<HashMap<MemoryStart, MemoryPageSize>>>) -> Self {
        Self { created_memories }
    }
}

unsafe impl wasmtime::MemoryCreator for WasmtimeMemoryCreator {
    fn new_memory(
        &self,
        ty: MemoryType,
        _minimum: usize,
        _maximum: Option<usize>,
        reserved_size_in_bytes: Option<usize>,
        guard_size: usize,
    ) -> Result<Box<dyn LinearMemory>, String> {
        let max_pages = if ty.is_64() {
            MAX_STABLE_MEMORY_IN_BYTES / (WASM_PAGE_SIZE as u64)
        } else {
            WASM32_MAX_SIZE / (WASM_PAGE_SIZE as u64)
        };
        let min = ty.minimum().min(max_pages) as usize;
        let max = ty.maximum().unwrap_or(max_pages).min(max_pages) as usize;

        let Some(reserved_size) = reserved_size_in_bytes else {
            panic!(
                "Wasmtime issued request to create a memory without specifying a reserved size."
            );
        };
        assert!(
            reserved_size <= MAX_STABLE_MEMORY_IN_BYTES as usize,
            "Reserved bytes for wasm memory {} exceeds the maximum expected {}",
            reserved_size,
            MAX_STABLE_MEMORY_IN_BYTES
        );

        assert!(
            reserved_size >= max * WASM_PAGE_SIZE as usize,
            "Reserved size {} in bytes is smaller than expected max size {} in wasm pages",
            reserved_size,
            max
        );

        let mem = MmapMemory::new(reserved_size, guard_size);

        match self.created_memories.lock() {
            Err(err) => Err(format!("Error locking map of created memories: {:?}", err)),
            Ok(mut created_memories) => {
                let new_memory = WasmtimeMemory::new(mem, min, max);
                created_memories.insert(
                    MemoryStart(LinearMemory::as_ptr(&new_memory) as usize),
                    MemoryPageSize(Arc::clone(&new_memory.used)),
                );
                Ok(Box::new(new_memory))
            }
        }
    }
}

/// Represents Wasm memory together with its prologue and epilogue guard regions:
/// `[prologue guard region][Wasm memory][epilogue guard region]`.
/// The guard regions are unmapped and catch out-of-bounds accesses. Note that
/// the prologue guard region is not necessary for correctness, we use as a
/// safety measure to improve security.
pub struct MmapMemory {
    // The address of the prologue guard region.
    start: *mut c_void,
    // The size of the entire region including all guard regions.
    size_in_bytes: usize,
    // The start of the actual memory exposed to Wasm.
    wasm_memory: *mut c_void,
}

/// SAFETY: This type is not actually Send/Sync but this it is only used
/// internally by `wasmtime` where they should be synchronizing access to the
/// pointers themselves.
unsafe impl Send for MmapMemory {}
unsafe impl Sync for MmapMemory {}

impl MmapMemory {
    pub fn new(mem_size_in_bytes: usize, guard_size_in_bytes: usize) -> Self {
        assert!(
            guard_size_in_bytes >= MIN_GUARD_REGION_SIZE,
            "Requested guard size {} is smaller than required size {}",
            guard_size_in_bytes,
            MIN_GUARD_REGION_SIZE
        );
        assert!(
            is_multiple_of_page_size(guard_size_in_bytes),
            "Requested guard size {} is not a multiple of the page size.",
            guard_size_in_bytes
        );
        assert!(
            is_multiple_of_page_size(mem_size_in_bytes),
            "Requested memory size {} is not a multiple of the page size.",
            mem_size_in_bytes
        );

        let prologue_guard_size_in_bytes = guard_size_in_bytes;
        let epilogue_guard_size_in_bytes = guard_size_in_bytes;
        let size_in_bytes =
            prologue_guard_size_in_bytes + mem_size_in_bytes + epilogue_guard_size_in_bytes;

        // SAFETY: These are valid arguments to `mmap`. Only `mem_size` is non-constant,
        // but any `usize` will result in a valid call.
        //
        // It is important to reserve the memory with PROT_NONE. Otherwise,
        // depending on the overcommit strategy configured in the kernel, the
        // call to mmap may fail. See:
        // https://www.kernel.org/doc/Documentation/vm/overcommit-accounting
        let start = unsafe {
            mmap(
                ptr::null_mut(),
                size_in_bytes,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(
            start,
            MAP_FAILED,
            "mmap failed: size={} {}",
            size_in_bytes,
            Error::last_os_error()
        );

        // SAFETY: The allocated region includes the prologue guard region.
        let wasm_memory =
            unsafe { (start as *mut u8).add(prologue_guard_size_in_bytes) as *mut c_void };

        Self {
            start,
            size_in_bytes,
            wasm_memory,
        }
    }

    fn as_ptr(&self) -> *mut c_void {
        self.wasm_memory
    }

    fn wasm_accessible(&self) -> std::ops::Range<usize> {
        let start = self.wasm_memory as usize;
        start..start + self.size_in_bytes
    }
}

impl Drop for MmapMemory {
    fn drop(&mut self) {
        let result = unsafe { munmap(self.start, self.size_in_bytes) };
        assert_eq!(result, 0, "munmap failed: {}", Error::last_os_error());
    }
}

pub struct WasmtimeMemory {
    mem: MmapMemory,
    max_size_in_pages: usize,
    used: MemoryPageSize,
}

impl WasmtimeMemory {
    fn new(mem: MmapMemory, min_size_in_pages: usize, max_size_in_pages: usize) -> Self {
        Self {
            mem,
            max_size_in_pages,
            used: MemoryPageSize(Arc::new(AtomicUsize::new(min_size_in_pages))),
        }
    }
}

fn convert_pages_to_bytes(pages: usize) -> usize {
    let (result, overflow) = pages.overflowing_mul(WASM_PAGE_SIZE as usize);
    if overflow {
        panic!("Unable to convert memory page size {} to bytes", pages)
    }
    result
}

unsafe impl LinearMemory for WasmtimeMemory {
    /// Returns the number of allocated wasm pages.
    fn byte_size(&self) -> usize {
        convert_pages_to_bytes(self.used.load(Ordering::SeqCst))
    }

    fn maximum_byte_size(&self) -> Option<usize> {
        Some(convert_pages_to_bytes(self.max_size_in_pages))
    }

    fn grow_to(&mut self, new_size: usize) -> anyhow::Result<()> {
        if new_size % WASM_PAGE_SIZE as usize != 0 {
            bail!(
                "Requested wasm page size increase wasn't a multiple of the wasm page size: {}",
                new_size
            )
        }
        let new_pages = new_size / WASM_PAGE_SIZE as usize;
        match self
            .used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |prev_pages| {
                if new_pages <= prev_pages || new_pages > self.max_size_in_pages {
                    None
                } else {
                    Some(new_pages)
                }
            }) {
            Ok(_) => Ok(()),
            Err(prev_pages) => bail!(
                "Unable to grow wasm memory from {} pages to {} pages",
                prev_pages,
                new_pages
            ),
        }
    }

    fn as_ptr(&self) -> *mut u8 {
        self.mem.as_ptr() as *mut _
    }

    fn wasm_accessible(&self) -> std::ops::Range<usize> {
        self.mem.wasm_accessible()
    }
}
