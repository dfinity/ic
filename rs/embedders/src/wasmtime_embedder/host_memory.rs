use wasmtime::MemoryType;
use wasmtime_environ::{WASM_MAX_PAGES, WASM_PAGE_SIZE};

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
    atomic::{AtomicU32, Ordering},
    Arc, Mutex,
};

pub fn round_up_to_page_size(size: usize, page_size: usize) -> usize {
    (size + (page_size - 1)) & !(page_size - 1)
}

fn round_up_to_os_page_size(size: usize) -> usize {
    round_up_to_page_size(size, PAGE_SIZE)
}

fn wasm_max_mem_size_in_bytes() -> usize {
    WASM_MAX_PAGES as usize * WASM_PAGE_SIZE as usize
}

#[derive(Hash, PartialEq, Eq)]
pub(crate) struct MemoryStart(pub(crate) usize);

pub(crate) struct MemoryPageSize(Arc<AtomicU32>);

impl Deref for MemoryPageSize {
    type Target = Arc<AtomicU32>;

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
        reserved_size_in_bytes: Option<u64>,
        guard_size: u64,
    ) -> Result<Box<dyn wasmtime::LinearMemory>, String> {
        //Wasmtime 'guarantees' that these values are <= WASM_MAX_PAGES
        //and has asserts for that in its Memory implementation
        //but let's just clip to that without panicking in case they change
        // something...
        let min = std::cmp::min(ty.limits().min(), WASM_MAX_PAGES);
        let max = ty.limits().max().unwrap_or(WASM_MAX_PAGES);
        let max = std::cmp::min(max, WASM_MAX_PAGES);

        let mem_size =
            reserved_size_in_bytes.unwrap_or(wasm_max_mem_size_in_bytes() as u64) as usize;
        let guard_size = guard_size as usize;

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
        _min_pages: u32,
        _max_pages: Option<u32>,
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
    maximum: u32,
    used: MemoryPageSize,
}

impl<M: LinearMemory + Send> WasmtimeMemory<M> {
    fn new(mem: M, min: u32, maximum: u32) -> Self {
        Self {
            mem,
            maximum,
            used: MemoryPageSize(Arc::new(AtomicU32::new(min))),
        }
    }
}

unsafe impl<M: LinearMemory + Send + Sync + 'static> wasmtime::LinearMemory for WasmtimeMemory<M> {
    /// Returns the number of allocated wasm pages.
    fn size(&self) -> u32 {
        self.used.load(Ordering::SeqCst)
    }

    fn maximum(&self) -> Option<u32> {
        Some(self.maximum)
    }

    fn grow(&mut self, delta: u32) -> Option<u32> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |prev_pages| {
                let new_pages = match prev_pages.checked_add(delta) {
                    Some(x) => x,
                    None => return None,
                };

                if new_pages > self.maximum {
                    None
                } else {
                    Some(new_pages)
                }
            })
            .ok()
    }

    fn as_ptr(&self) -> *mut u8 {
        self.mem.as_ptr() as *mut _
    }
}
