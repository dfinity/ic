use ic_logger::ReplicaLogger;
use ic_replicated_state::{PageIndex, PageMap};
use ic_sys::PageBytes;
use ic_types::NumBytes;
use nix::errno::Errno;
use std::time::Duration;

use crate::prefetching::PrefetchingMemoryTracker;

pub mod prefetching;

/// Specifies whether the currently running message execution needs to know
/// which pages were dirtied or not. Dirty page tracking comes with a large
/// performance overhead.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum DirtyPageTracking {
    Ignore,
    Track,
}

/// Specifies whether the memory access that caused the signal was a read access
/// or a write access.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum AccessKind {
    Read,
    Write,
}

/// Memory tracker interface.
pub trait MemoryTracker {
    /// Creates a new memory tracker.
    fn new(
        start: *mut libc::c_void,
        size: NumBytes,
        log: ReplicaLogger,
        dirty_page_tracking: DirtyPageTracking,
        page_map: PageMap,
    ) -> nix::Result<Self>
    where
        Self: Sized;

    /// Handles missing page signal (SIGSEGV or SIGBUS).
    fn handle_sigsegv(
        &self,
        access_kind: Option<AccessKind>,
        fault_address: *mut libc::c_void,
    ) -> bool;

    /// Returns `true` if `address` is contained in the memory tracker.
    fn contains(&self, address: *const libc::c_void) -> bool;

    /// Returns the start address of the tracked memory area.
    fn start(&self) -> usize;

    /// Returns the size of the tracked memory area.
    fn size(&self) -> NumBytes;

    /// Expands the tracked memory area.
    fn expand(&self, delta: NumBytes);

    /// Returns a number of accessed pages.
    fn num_accessed_pages(&self) -> usize;

    /// Returns a list of accessed page indexes.
    fn take_accessed_pages(&self) -> Vec<PageIndex>;

    /// Returns a list of dirty page indexes.
    fn take_dirty_pages(&self) -> Vec<PageIndex>;

    /// Returns a list of speculatively dirty page indexes.
    fn take_speculatively_dirty_pages(&self) -> Vec<PageIndex>;

    /// Returns None if a speculatively dirty page was not modified.
    fn validate_speculatively_dirty_page(&self, page_idx: PageIndex) -> Option<PageIndex>;

    /// Returns `true` if a specified page was marked as accessed.
    fn is_accessed(&self, page_idx: PageIndex) -> bool;

    /// Returns a reference to the specified page map OS page content.
    fn get_page(&self, page_idx: PageIndex) -> &PageBytes;

    /// The number of pages that first had a read access and then a write access.
    fn read_before_write_count(&self) -> usize;

    /// The number of pages that had an initial write access.
    fn direct_write_count(&self) -> usize;

    /// The number of calls to `handle_sigsegv`.
    fn sigsegv_count(&self) -> usize;

    /// The number of calls to `mmap`.
    fn mmap_count(&self) -> usize;

    /// The number of calls to `mprotect`.
    fn mprotect_count(&self) -> usize;

    /// The number of pages copied as part of memory instructions.
    fn copy_page_count(&self) -> usize;

    /// The total time spent in signal handler.
    fn sigsegv_handler_duration(&self) -> Duration;

    /// Add the total time spent in signal handler.
    fn add_sigsegv_handler_duration(&self, elapsed: Duration);
}

/// Dynamic dispatch is used to minimize code changes.
/// Remove this dispatch mechanism once we have fully switched to
/// the deterministic memory tracker.
pub type SigsegvMemoryTracker = Box<dyn MemoryTracker + Send>;

pub fn new(
    start: *mut libc::c_void,
    size: NumBytes,
    log: ReplicaLogger,
    dirty_page_tracking: DirtyPageTracking,
    page_map: PageMap,
) -> nix::Result<SigsegvMemoryTracker> {
    Ok(Box::new(PrefetchingMemoryTracker::new(
        start,
        size,
        log,
        dirty_page_tracking,
        page_map,
    )?))
}

/// Prints a help message on ENOMEM error.
pub(crate) fn print_enomem_help(errno: Errno) -> Errno {
    if let Errno::ENOMEM = errno {
        eprintln!(
            "This failure is likely caused by the `vm.max_map_count` limit.\n\
             Try increasing the limit: `sudo sysctl -w vm.max_map_count=2097152`."
        );
    }
    errno
}

/// Returns the access kind (read or write) and the faulting address based on
/// the provided `siginfo` and `ucontext` pointers.
///
/// # Safety
///
/// Both `siginfo_ptr` and `ucontext_ptr` must be valid, non-null pointers to
/// `libc::siginfo_t` and (on supported platforms) `libc::ucontext_t`.
pub unsafe fn signal_access_kind_and_address(
    siginfo_ptr: *const libc::siginfo_t,
    ucontext_ptr: *const libc::c_void,
) -> (Option<AccessKind>, *mut libc::c_void) {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let access_kind = {
        let ucontext_ptr = ucontext_ptr as *const libc::ucontext_t;
        let error_register = libc::REG_ERR as usize;
        let error_code = unsafe { (*ucontext_ptr).uc_mcontext.gregs[error_register] };
        // The second least-significant bit distinguishes between read and write
        // accesses. See https://git.io/JEQn3.
        if error_code & 0x2 == 0 {
            Some(AccessKind::Read)
        } else {
            Some(AccessKind::Write)
        }
    };
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    let access_kind: Option<AccessKind> = {
        // Prevent a warning about unused parameter.
        let _use_ucontext_ptr = ucontext_ptr;
        None
    };

    let (_si_signo, _si_errno, _si_code, si_addr) = unsafe {
        let s = *siginfo_ptr;
        (s.si_signo, s.si_errno, s.si_code, s.si_addr())
    };
    (access_kind, si_addr)
}
