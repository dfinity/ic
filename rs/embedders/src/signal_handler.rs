use crate::wasmtime_embedder::host_memory::MemoryPageSize;

use libc::c_void;
use memory_tracker::{signal_access_kind_and_address, SigsegvMemoryTracker};
use std::convert::TryFrom;
use std::sync::MutexGuard;
use std::sync::{atomic::Ordering, Arc, Mutex};

const WASM_PAGE_SIZE: u32 = wasmtime_environ::Memory::DEFAULT_PAGE_SIZE;

/// Helper function to create a memory tracking SIGSEGV handler function.
pub(crate) fn sigsegv_memory_tracker_handler(
    memories: Vec<(Arc<Mutex<SigsegvMemoryTracker>>, MemoryPageSize)>,
) -> impl Fn(i32, *const libc::siginfo_t, *const libc::c_void) -> bool + Send + Sync {
    let mut memories: Vec<_> = memories
        .into_iter()
        .map(|(t, size)| {
            let base = t.lock().unwrap().area().addr();
            (base, t, size)
        })
        .collect();

    memories.sort_by_key(|(base, _, _)| *base);

    let check_if_expanded =
        move |tracker: &mut MutexGuard<SigsegvMemoryTracker>,
              si_addr: *mut c_void,
              current_size_in_pages: &MemoryPageSize| unsafe {
            let page_count = current_size_in_pages.load(Ordering::SeqCst);
            let heap_size = page_count * (WASM_PAGE_SIZE as usize);
            let heap_start = tracker.area().addr() as *mut libc::c_void;
            if (heap_start <= si_addr) && (si_addr < { heap_start.add(heap_size) }) {
                Some(heap_size)
            } else {
                None
            }
        };

    move |signum: i32, siginfo_ptr: *const libc::siginfo_t, ucontext_ptr: *const libc::c_void| {
        use nix::sys::signal::Signal;

        let signal = Signal::try_from(signum).expect("signum is a valid signal");
        let expected_signal =
            // Mac OS raises SIGBUS instead of SIGSEGV
            if cfg!(target_os = "macos") {
                Signal::SIGBUS
            } else {
                Signal::SIGSEGV
            };

        if signal != expected_signal {
            return false;
        }

        // SAFETY: When the signal handler is invoked, `siginfo_ptr` will always
        // be valid.
        let (access_kind, si_addr) =
            unsafe { signal_access_kind_and_address(siginfo_ptr, ucontext_ptr) };

        // Find the last memory with base address below the signal address and
        // just take the first memory if none is found.
        //
        // This will not introduce non-determinism because wasmtime will not
        // generate accesses extending beyond the guard pages on either end of
        // each memory. So any access within a given memory range is guaranteed
        // to be an access that was intended for that memory.
        let (_, memory_tracker, memory_page_size) = memories
            .iter()
            .rev()
            .find(|(base, _, _)| *base as *mut c_void <= si_addr)
            .unwrap_or(&memories[0]);

        let mut memory_tracker = memory_tracker.lock().unwrap();

        // We handle SIGSEGV from the Wasm module heap ourselves.
        if memory_tracker.area().is_within(si_addr) {
            // Returns true if the signal has been handled by our handler which indicates
            // that the instance should continue.
            memory_tracker.handle_sigsegv(access_kind, si_addr)
        // The heap has expanded. Update tracked memory area.
        } else if let Some(heap_size) =
            check_if_expanded(&mut memory_tracker, si_addr, memory_page_size)
        {
            let delta = heap_size - memory_tracker.area().size();
            memory_tracker.expand(delta);
            true
        } else {
            false
        }
    }
}
