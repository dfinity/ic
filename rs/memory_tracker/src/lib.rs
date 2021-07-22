use bit_vec::BitVec;
use ic_logger::{debug, ReplicaLogger};
use ic_sys::PAGE_SIZE;
use nix::sys::mman::{mprotect, ProtFlags};
use std::cell::{Cell, RefCell};

// Represents a memory area: address + size. Address must be page-aligned and
// size must be a multiple of PAGE_SIZE.
#[derive(Clone)]
pub struct MemoryArea {
    // base address of the tracked memory area
    addr: *const libc::c_void,
    // size of the tracked memory area
    size: Cell<usize>,
}

impl MemoryArea {
    pub fn new(addr: *const libc::c_void, size: usize) -> Self {
        assert!(addr as usize % *PAGE_SIZE == 0, "address is page-aligned");
        assert!(size % *PAGE_SIZE == 0, "size is a multiple of page size");
        let size = Cell::new(size);
        MemoryArea { addr, size }
    }

    #[inline]
    pub fn is_within(&self, a: *const libc::c_void) -> bool {
        (self.addr <= a) && (a < unsafe { self.addr.add(self.size.get()) })
    }

    #[inline]
    pub fn addr(&self) -> *const libc::c_void {
        self.addr
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.size.get()
    }

    #[inline]
    pub fn page_addr(&self, page_num: usize) -> *const libc::c_void {
        assert!(
            page_num < self.size.get() / *PAGE_SIZE,
            "page({}) is not within memory area addr={:?}, size={}",
            page_num,
            self.addr,
            self.size.get()
        );
        unsafe { self.addr.add(page_num * *PAGE_SIZE) }
    }
}

type PageNum = usize;

pub struct SigsegvMemoryTracker {
    memory_area: MemoryArea,
    accessed_pages: RefCell<BitVec>,
    dirty_pages: RefCell<Vec<*const libc::c_void>>,
}

impl SigsegvMemoryTracker {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn new(addr: *mut libc::c_void, size: usize, log: ReplicaLogger) -> nix::Result<Self> {
        let num_pages = size / *PAGE_SIZE;
        debug!(
            log,
            "SigsegvMemoryTracker::new: addr={:?}, size={}, num_pages={}", addr, size, num_pages
        );

        let memory_area = MemoryArea::new(addr, size);

        // make memory inaccessible so we can track it with SIGSEGV
        unsafe { mprotect(addr, size, ProtFlags::PROT_NONE)? };

        let accessed_pages = RefCell::new(BitVec::from_elem(num_pages, false));
        let dirty_pages = RefCell::new(Vec::new());
        Ok(SigsegvMemoryTracker {
            memory_area,
            accessed_pages,
            dirty_pages,
        })
    }

    pub fn handle_sigsegv<'b, F>(&self, page_init: F, fault_address: *mut libc::c_void) -> bool
    where
        F: Fn(PageNum) -> Option<&'b [u8]>,
    {
        sigsegv_fault_handler(self, &page_init, fault_address)
    }

    pub fn area(&self) -> &MemoryArea {
        &self.memory_area
    }

    pub fn expand(&self, delta: usize) {
        let old_size = self.area().size.get();
        self.area().size.set(old_size + delta);
        self.accessed_pages.borrow_mut().grow(delta, false);
    }

    pub fn dirty_pages(&self) -> Vec<*const libc::c_void> {
        self.dirty_pages.borrow().clone()
    }

    pub fn num_accessed_pages(&self) -> usize {
        self.accessed_pages.borrow().iter().filter(|x| *x).count()
    }

    pub fn num_dirty_pages(&self) -> usize {
        self.dirty_pages.borrow().len()
    }
}

// It is not possible to use a logger from within the signal handler. Hence, for
// debugging, we use an ordinary `eprintln!` hidden behind a feature gate. To
// enable:
// ic-execution-environment = { ..., features = [ "sigsegv_handler_debug" ] }

pub fn sigsegv_fault_handler<'a>(
    tracker: &SigsegvMemoryTracker,
    page_init: &dyn Fn(PageNum) -> Option<&'a [u8]>,
    fault_address: *mut libc::c_void,
) -> bool {
    // We need to handle page faults in units of pages(!). So, round faulting
    // address down to page boundary
    let fault_address_page_boundary = fault_address as usize & !(*PAGE_SIZE as usize - 1);

    let page_num = (fault_address_page_boundary - tracker.memory_area.addr() as usize) / *PAGE_SIZE;

    #[cfg(feature = "sigsegv_handler_debug")]
    eprintln!(
        "> Thread: {:?} sigsegv_fault_handler: base_addr = 0x{:x}, page_size = 0x{:x}, fault_address = 0x{:x}, fault_address_page_boundary = 0x{:x}, page = {}",
        std::thread::current().id(),
        tracker.memory_area.addr() as u64,
        *PAGE_SIZE,
        fault_address as u64,
        fault_address_page_boundary,
        page_num
    );

    // Ensure `fault_address` falls within tracked memory area
    if !tracker.memory_area.is_within(fault_address) {
        #[cfg(feature = "sigsegv_handler_debug")]
        eprintln!(
            "fault address {:?} outside of tracked memory area",
            fault_address
        );
        return false;
    };

    if tracker
        .accessed_pages
        .borrow()
        .get(page_num)
        .expect("page_num not found in accessed_pages")
    {
        // This page has already been accessed, hence this fault must be for writing.
        // Upgrade its protection to read+write.
        #[cfg(feature = "sigsegv_handler_debug")]
        eprintln!(
            "> sigsegv_fault_handler: page({}) is already faulted: mprotect(addr=0x{:x}, len=0x{:x}, prot=PROT_READ|PROT_WRITE)",
            page_num,
            fault_address_page_boundary, *PAGE_SIZE
        );
        unsafe {
            nix::sys::mman::mprotect(
                fault_address_page_boundary as *mut libc::c_void,
                *PAGE_SIZE,
                nix::sys::mman::ProtFlags::PROT_READ | nix::sys::mman::ProtFlags::PROT_WRITE,
            )
            .unwrap()
        };
        tracker
            .dirty_pages
            .borrow_mut()
            .push(fault_address_page_boundary as *const libc::c_void);
    } else {
        // This page has not been accessed yet.
        // The fault could be for reading or writing.
        // Load the contents of the page and enable just reading.
        // If the fault was for writing, then another fault will occur right away.
        #[cfg(feature = "sigsegv_handler_debug")]
        eprintln!(
            "> sigsegv_fault_handler: page({}) has not been faulted: mprotect(addr=0x{:x}, len=0x{:x}, prot=PROT_READ)",
            page_num,
            fault_address_page_boundary,
            *PAGE_SIZE
        );
        // Temporarily allow writes to the page, to populate contents with the right
        // data
        unsafe {
            nix::sys::mman::mprotect(
                fault_address_page_boundary as *mut libc::c_void,
                *PAGE_SIZE,
                nix::sys::mman::ProtFlags::PROT_READ | nix::sys::mman::ProtFlags::PROT_WRITE,
            )
            .unwrap()
        };
        // Page contents initialization is optional. For example, if the memory tracker
        // is set up for a memory area mmap-ed to a file, the contents of each
        // page will be initialized by the kernel from that file.
        if let Some(page) = page_init(page_num) {
            #[cfg(feature = "sigsegv_handler_debug")]
            eprintln!(
                "> sigsegv_fault_handler: setting page({}) contents to {}",
                page_num,
                show_bytes_compact(&page)
            );
            unsafe {
                std::ptr::copy_nonoverlapping(
                    page.as_ptr(),
                    fault_address_page_boundary as *mut u8,
                    *PAGE_SIZE,
                )
            };
        }
        // Now reduce the access privileges to read-only
        unsafe {
            nix::sys::mman::mprotect(
                fault_address_page_boundary as *mut libc::c_void,
                *PAGE_SIZE,
                nix::sys::mman::ProtFlags::PROT_READ,
            )
            .unwrap()
        };
        tracker.accessed_pages.borrow_mut().set(page_num, true);
    }
    true
}

#[allow(dead_code)]
#[cfg(feature = "sigsegv_handler_debug")]
pub(crate) fn show_bytes_compact(bytes: &[u8]) -> String {
    let mut result = String::new();
    let mut count = 1;
    let mut current = None;
    result += "[";
    for &b in bytes.iter() {
        match current {
            Some(x) if x == b => {
                count += 1;
            }
            Some(x) => {
                result += &format!("{}x{:x} ", count, x);
                count = 1;
            }
            None => (),
        }
        current = Some(b);
    }
    if let Some(x) = current {
        result += &format!("{}x{:x}", count, x)
    }
    result += "]";
    result
}
