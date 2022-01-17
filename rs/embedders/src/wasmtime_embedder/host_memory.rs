use anyhow::bail;
use wasmtime::MemoryType;
use wasmtime_environ::{WASM32_MAX_PAGES, WASM_PAGE_SIZE};

use crate::ICMemoryCreator;
use crate::LinearMemory;

use ic_sys::PAGE_SIZE;

use libc::c_void;
use libc::MAP_FAILED;
use libc::{mmap, munmap};
use libc::{MAP_ANON, MAP_PRIVATE, PROT_NONE};

use std::collections::HashMap;
use std::io::Error;
use std::ops::Deref;
use std::ptr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

pub fn round_up_to_page_size(size: usize, page_size: usize) -> usize {
    (size + (page_size - 1)) & !(page_size - 1)
}

fn round_up_to_os_page_size(size: usize) -> usize {
    round_up_to_page_size(size, PAGE_SIZE)
}

fn wasm_max_mem_size_in_bytes() -> usize {
    WASM32_MAX_PAGES as usize * WASM_PAGE_SIZE as usize
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

pub struct WasmtimeMemoryCreator<C: ICMemoryCreator>
where
    <C as ICMemoryCreator>::Mem: 'static,
{
    raw_creator: C,
    created_memories: Arc<Mutex<HashMap<MemoryStart, MemoryPageSize>>>,
}

impl<C: ICMemoryCreator> WasmtimeMemoryCreator<C> {
    pub(crate) fn new(
        raw_creator: C,
        created_memories: Arc<Mutex<HashMap<MemoryStart, MemoryPageSize>>>,
    ) -> Self {
        Self {
            raw_creator,
            created_memories,
        }
    }
}

unsafe impl<C: ICMemoryCreator + Send + Sync> wasmtime::MemoryCreator for WasmtimeMemoryCreator<C>
where
    C::Mem: Send + Sync,
{
    fn new_memory(
        &self,
        ty: MemoryType,
        _minimum: usize,
        _maximum: Option<usize>,
        reserved_size_in_bytes: Option<usize>,
        guard_size: usize,
    ) -> Result<Box<dyn wasmtime::LinearMemory>, String> {
        // Wasmtime 'guarantees' that these values are <= WASM_MAX_PAGES
        // and has asserts for that in its Memory implementation
        // but let's just clip to that without panicking in case they change
        // something...
        let min = std::cmp::min(ty.minimum(), WASM32_MAX_PAGES) as usize;
        let max =
            std::cmp::min(ty.maximum().unwrap_or(WASM32_MAX_PAGES), WASM32_MAX_PAGES) as usize;

        let mem_size = reserved_size_in_bytes.unwrap_or_else(wasm_max_mem_size_in_bytes);

        let mem = self
            .raw_creator
            .new_memory(mem_size, guard_size, 0, min, Some(max));

        match self.created_memories.lock() {
            Err(err) => Err(format!("Error locking map of created memories: {:?}", err)),
            Ok(mut created_memories) => {
                let new_memory = WasmtimeMemory::<C::Mem>::new(mem, min, max);
                created_memories.insert(
                    MemoryStart(wasmtime::LinearMemory::as_ptr(&new_memory) as usize),
                    MemoryPageSize(Arc::clone(&new_memory.used)),
                );
                Ok(Box::new(new_memory))
            }
        }
    }
}

pub(crate) struct MmapMemoryCreator {}

impl ICMemoryCreator for MmapMemoryCreator {
    type Mem = MmapMemory;
    fn new_memory(
        &self,
        mem_size: usize,
        guard_size: usize,
        _instance_heap_offset: usize,
        _min_pages: usize,
        _max_pages: Option<usize>,
    ) -> MmapMemory {
        MmapMemory::new(mem_size, guard_size)
    }
}

pub struct MmapMemory {
    mem: *mut c_void,
    mem_size: usize,
}

/// SAFETY: This type is not actually Send/Sync but this it is only used
/// internally by `wasmtime` where they should be synchronizing access to the
/// pointers themselves.
unsafe impl Send for MmapMemory {}
unsafe impl Sync for MmapMemory {}

impl MmapMemory {
    pub fn new(mem_size_in_bytes: usize, guard_size_in_bytes: usize) -> Self {
        let mem_size = round_up_to_os_page_size(mem_size_in_bytes + guard_size_in_bytes);

        // SAFETY: These are valid arguments to `mmap`. Only `mem_size` is non-constant,
        // but any `usize` will result in a valid call.
        //
        // It is important to reserve the memory with PROT_NONE. Otherwise,
        // depending on the overcommit strategy configured in the kernel, the
        // call to mmap may fail. See:
        // https://www.kernel.org/doc/Documentation/vm/overcommit-accounting
        let mem = unsafe {
            mmap(
                ptr::null_mut(),
                mem_size,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(
            mem,
            MAP_FAILED,
            "mmap failed: size={} {}",
            mem_size,
            Error::last_os_error()
        );

        Self { mem, mem_size }
    }
}

impl LinearMemory for MmapMemory {
    fn as_ptr(&self) -> *mut c_void {
        self.mem
    }
}

impl Drop for MmapMemory {
    fn drop(&mut self) {
        let result = unsafe { munmap(self.mem, self.mem_size) };
        assert_eq!(result, 0, "munmap failed: {}", Error::last_os_error());
    }
}

pub struct WasmtimeMemory<M: LinearMemory> {
    mem: M,
    maximum: usize,
    used: MemoryPageSize,
}

impl<M: LinearMemory + Send> WasmtimeMemory<M> {
    fn new(mem: M, min: usize, maximum: usize) -> Self {
        Self {
            mem,
            maximum,
            used: MemoryPageSize(Arc::new(AtomicUsize::new(min))),
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

unsafe impl<M: LinearMemory + Send + Sync + 'static> wasmtime::LinearMemory for WasmtimeMemory<M> {
    /// Returns the number of allocated wasm pages.
    fn byte_size(&self) -> usize {
        convert_pages_to_bytes(self.used.load(Ordering::SeqCst))
    }

    fn maximum_byte_size(&self) -> Option<usize> {
        Some(convert_pages_to_bytes(self.maximum))
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
                if new_pages <= prev_pages || new_pages > self.maximum {
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
}
