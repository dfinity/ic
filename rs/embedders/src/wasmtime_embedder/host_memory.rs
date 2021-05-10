use wasmtime::MemoryType;
use wasmtime_environ::{WASM_MAX_PAGES, WASM_PAGE_SIZE};

use crate::ICMemoryCreator;
use crate::LinearMemory;

use ic_sys::PAGE_SIZE;

use libc::c_void;
use libc::MAP_FAILED;
use libc::{mmap, munmap};
use libc::{MAP_ANON, MAP_PRIVATE, PROT_NONE};

use std::cell::RefCell;
use std::io::Error;
use std::ptr;

pub fn round_up_to_page_size(size: usize, page_size: usize) -> usize {
    (size + (page_size - 1)) & !(page_size - 1)
}

fn round_up_to_os_page_size(size: usize) -> usize {
    round_up_to_page_size(size, *PAGE_SIZE)
}

fn wasm_max_mem_size_in_bytes() -> usize {
    WASM_MAX_PAGES as usize * WASM_PAGE_SIZE as usize
}

#[derive(Default)]
pub struct WasmtimeMemoryCreator<C: ICMemoryCreator>
where
    <C as ICMemoryCreator>::Mem: 'static,
{
    raw_creator: C,
}

impl<C: ICMemoryCreator> WasmtimeMemoryCreator<C> {
    pub fn new(raw_creator: C) -> Self {
        Self { raw_creator }
    }
}

unsafe impl<C: ICMemoryCreator + Send + Sync> wasmtime::MemoryCreator for WasmtimeMemoryCreator<C> {
    fn new_memory(
        &self,
        ty: MemoryType,
        reserved_size_in_bytes: Option<u64>,
        guard_size: u64,
    ) -> Result<Box<dyn wasmtime::LinearMemory>, String> {
        unsafe {
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

            Ok(Box::new(WasmtimeMemory::new(mem, min, max)))
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
        unsafe { MmapMemory::new(mem_size, guard_size) }
    }
}

pub struct MmapMemory {
    mem: *mut c_void,
    mem_size: usize,
}

unsafe impl Send for MmapMemory {}

impl MmapMemory {
    /// # Safety
    /// It calls libc::mmap is if arguments don't make sense it can fail
    pub unsafe fn new(mem_size_in_bytes: usize, guard_size_in_bytes: usize) -> Self {
        let mem_size = round_up_to_os_page_size(mem_size_in_bytes + guard_size_in_bytes);

        // It is important to reserve the memory with PROT_NONE. Otherwise,
        // depending on the overcommit strategy configured in the kernel, the
        // call to mmap may fail. See:
        // https://www.kernel.org/doc/Documentation/vm/overcommit-accounting
        let mem = mmap(
            ptr::null_mut(),
            mem_size,
            PROT_NONE,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        );
        assert_ne!(
            mem,
            MAP_FAILED,
            "mmap failed: size={} {}",
            mem_size,
            Error::last_os_error()
        );

        Self { mem, mem_size }
    }

    pub fn from_raw(mem: *mut c_void, mem_size: usize) -> Self {
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
    pub mem: RefCell<M>,
    maximum: u32,
    used: RefCell<u32>,
}

impl<M: LinearMemory> WasmtimeMemory<M> {
    unsafe fn new(mem: M, min: u32, maximum: u32) -> Self {
        Self {
            mem: RefCell::new(mem),
            maximum,
            used: RefCell::new(min),
        }
    }
}

unsafe impl<M: LinearMemory> wasmtime::LinearMemory for WasmtimeMemory<M> {
    /// Returns the number of allocated wasm pages.
    fn size(&self) -> u32 {
        *self.used.borrow()
    }

    fn grow(&self, delta: u32) -> Option<u32> {
        let prev_pages: u32 = *self.used.borrow();
        let new_pages = match prev_pages.checked_add(delta) {
            Some(x) => x,
            None => return None,
        };

        if new_pages > self.maximum {
            return None;
        }

        self.mem.borrow().grow_mem_to(new_pages);

        *self.used.borrow_mut() = new_pages;
        Some(prev_pages)
    }

    fn as_ptr(&self) -> *mut u8 {
        let mem = self.mem.borrow_mut();
        mem.as_ptr() as *mut u8
    }
}

impl<M: LinearMemory> LinearMemory for WasmtimeMemory<M> {
    fn as_ptr(&self) -> *mut c_void {
        <Self as wasmtime::LinearMemory>::as_ptr(&self) as *mut c_void
    }
}
