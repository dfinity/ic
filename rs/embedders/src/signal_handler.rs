use memory_tracker::{AccessKind, SigsegvMemoryTracker};
use std::convert::TryFrom;

/// Helper function to create a memory tracking SIGSEGV handler function.
pub fn sigsegv_memory_tracker_handler(
    sigsegv_memory_tracker: std::rc::Rc<SigsegvMemoryTracker>,
    current_heap_size: impl Fn() -> usize,
    default_handler: impl Fn() -> bool,
    handler_succeeded: impl Fn() -> bool,
    handler_failed: impl Fn() -> bool,
) -> impl Fn(i32, *const libc::siginfo_t, *const libc::c_void) -> bool {
    move |signum: i32, siginfo_ptr: *const libc::siginfo_t, ucontext_ptr: *const libc::c_void| {
        use nix::sys::signal::Signal;

        #[cfg(target_os = "linux")]
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
        #[cfg(not(target_os = "linux"))]
        let access_kind: Option<AccessKind> = {
            // Prevent a warning about unused parameter.
            let _use_ucontext_ptr = ucontext_ptr;
            None
        };

        let signal = Signal::try_from(signum).expect("signum is a valid signal");
        let (_si_signo, _si_errno, _si_code, si_addr) = unsafe {
            let s = *siginfo_ptr;
            (s.si_signo, s.si_errno, s.si_code, s.si_addr())
        };
        #[cfg(feature = "sigsegv_handler_debug")]
        eprintln!(
            "> instance signal handler: signal = {}, si_signo = {}, si_errno = {}, si_code = {}, si_addr = {:?}",
            signal, _si_signo, _si_errno, _si_code, si_addr
        );

        let check_if_expanded = || unsafe {
            let heap_size = current_heap_size();
            let heap_start = sigsegv_memory_tracker.area().addr() as *mut libc::c_void;
            if (heap_start <= si_addr) && (si_addr < { heap_start.add(heap_size) }) {
                Some(heap_size)
            } else {
                None
            }
        };

        let expected_signal =
            // Mac OS raises SIGBUS instead of SIGSEGV
            if cfg!(target_os = "macos") {
                Signal::SIGBUS
            } else {
                Signal::SIGSEGV
            };

        if signal != expected_signal {
            return default_handler();
        }
        // We handle SIGSEGV from the Wasm module heap ourselves.
        if sigsegv_memory_tracker.area().is_within(si_addr) {
            #[cfg(feature = "sigsegv_handler_debug")]
            eprintln!("> instance signal handler: calling memory tracker signal handler");
            // Returns true if the signal has been handled by our handler which indicates
            // that the instance should continue.
            let handled = sigsegv_memory_tracker.handle_sigsegv(access_kind, si_addr);
            if handled {
                handler_succeeded()
            } else {
                handler_failed()
            }
        // The heap has expanded. Update tracked memory area.
        } else if let Some(heap_size) = check_if_expanded() {
            let delta = heap_size - sigsegv_memory_tracker.area().size();
            #[cfg(feature = "sigsegv_handler_debug")]
            eprintln!(
                "> instance signal handler: expanding memory area by {}",
                delta
            );
            sigsegv_memory_tracker.expand(delta);
            handler_succeeded()
        } else {
            default_handler()
        }
    }
}
