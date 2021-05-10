use ic_cow_state::{MappedState, MappedStateImpl};
use std::sync::{Arc, Mutex};

pub struct CowMemoryCreator {
    heap_base: u64,
}

impl CowMemoryCreator {
    pub fn new(mapped_state: &MappedStateImpl) -> Self {
        Self {
            heap_base: mapped_state.get_heap_base() as u64,
        }
    }

    pub fn new_uninitialized() -> Self {
        Self { heap_base: 0 }
    }
}

impl crate::ICMemoryCreator for CowMemoryCreator {
    type Mem = MappedStateMemory;

    fn new_memory(
        &self,
        _total_memory_size: usize,
        _guard_size: usize,
        instance_heap_offset: usize,
        _mem_pages_min: u32,
        _mem_pages_max: Option<u32>,
    ) -> Self::Mem {
        assert!(
            instance_heap_offset == 0,
            "CowMemoryCreator can't handle non zero heap offset yet"
        );
        MappedStateMemory {
            base_addr: self.heap_base as *mut libc::c_void,
        }
    }
}

pub struct MappedStateMemory {
    base_addr: *mut libc::c_void,
}

unsafe impl Send for MappedStateMemory {}

impl crate::LinearMemory for MappedStateMemory {
    fn as_ptr(&self) -> *mut libc::c_void {
        self.base_addr
    }
}

// In Wasmtime MemoryCreator is set in the Config when the Engine is created.
// Since we are caching the Module, we are also (implicitly) caching the
// Engine. Yet, we want to retain the API that allows setting the MemoryCreator
// for each Instance created from the cached Module. To this end we use a proxy
// struct with interior mutability. This struct simply dispatches to the
// internal MemoryCreator it currently contains
#[derive(Clone)]
pub(crate) struct CowMemoryCreatorProxy {
    pub memory_creator: Arc<Mutex<Arc<CowMemoryCreator>>>,
    pub memory_creator_lock: Arc<Mutex<()>>,
}

impl CowMemoryCreatorProxy {
    pub(crate) fn new(memory_creator: Arc<CowMemoryCreator>) -> Self {
        Self {
            memory_creator: Arc::new(Mutex::new(memory_creator)),
            memory_creator_lock: Arc::new(Mutex::new(())),
        }
    }

    pub(crate) fn replace(&self, memory_creator: Arc<CowMemoryCreator>) {
        *self.memory_creator.lock().unwrap() = memory_creator;
    }
}

impl crate::ICMemoryCreator for CowMemoryCreatorProxy {
    type Mem = crate::cow_memory_creator::MappedStateMemory;
    fn new_memory(
        &self,
        mem_size: usize,
        guard_size: usize,
        instance_heap_offset: usize,
        min_pages: u32,
        max_pages: Option<u32>,
    ) -> MappedStateMemory {
        self.memory_creator.lock().unwrap().new_memory(
            mem_size,
            guard_size,
            instance_heap_offset,
            min_pages,
            max_pages,
        )
    }
}
