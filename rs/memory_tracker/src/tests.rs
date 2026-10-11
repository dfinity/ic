use std::io::Write;

use crate::signal_mutex::SignalMutex;
use ic_logger::replica_logger::no_op_logger;
use ic_replicated_state::{NumWasmPages, canister_state::WASM_PAGE_SIZE_IN_BYTES};
use ic_replicated_state::{
    PageIndex, PageMap,
    page_map::{TestPageAllocatorFileDescriptorImpl, test_utils::base_only_storage_layout},
};
use ic_sys::{PAGE_SIZE, PageBytes};
use ic_types::{NumBytes, NumOsPages};
use libc::c_void;
use nix::sys::mman::{MapFlags, ProtFlags, mmap_anonymous};
use rstest::rstest;
use std::num::NonZeroUsize;
use std::ops::Range;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::ops::{Deref, DerefMut};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use crate::{
    AccessKind, DeterministicMemoryTracker, DirtyPageTracking, MemoryLimits, SigsegvOutcome,
    conversions::OS_PAGES_IN_WASM_PAGE,
};

/// Sets up the memory tracker to track accesses to a region of memory. Returns:
/// 1. The tracker.
/// 2. A PageMap with the memory contents.
/// 3. A pointer to the tracked region.
/// 4. A regular vector with the same initial contents as the PageMap.
fn setup(
    checkpoint_pages: usize,
    memory_pages: usize,
    page_delta: Vec<PageIndex>,
    dirty_page_tracking: DirtyPageTracking,
) -> (DeterministicMemoryTracker, PageMap, *mut c_void, Vec<u8>) {
    setup_with_accessed_page_limit(
        checkpoint_pages,
        memory_pages,
        page_delta,
        dirty_page_tracking,
        None,
        Arc::new(SignalMutex::new(|| {})),
    )
}

/// Like `setup`, but limits the number of Wasm pages that may be accessed and
/// installs a callback that is invoked for every newly accessed Wasm page.
fn setup_with_accessed_page_limit(
    checkpoint_pages: usize,
    memory_pages: usize,
    page_delta: Vec<PageIndex>,
    dirty_page_tracking: DirtyPageTracking,
    max_accessed_wasm_pages: Option<NumWasmPages>,
    on_wasm_page_accessed: Arc<SignalMutex<dyn FnMut() + Send>>,
) -> (DeterministicMemoryTracker, PageMap, *mut c_void, Vec<u8>) {
    let mut vec = vec![0_u8; memory_pages * PAGE_SIZE];
    let tmpfile = tempfile::Builder::new().prefix("test").tempfile().unwrap();
    for page in 0..checkpoint_pages {
        tmpfile
            .as_file()
            .write_all(&[(page % 256) as u8; PAGE_SIZE])
            .unwrap();
        vec[page * PAGE_SIZE..(page + 1) * PAGE_SIZE]
            .copy_from_slice(&[(page % 256) as u8; PAGE_SIZE]);
    }
    tmpfile.as_file().sync_all().unwrap();
    let mut page_map = PageMap::open(
        Box::new(base_only_storage_layout(tmpfile.path().to_path_buf())),
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
    )
    .unwrap();
    let pages: Vec<(PageIndex, PageBytes)> = page_delta
        .into_iter()
        .map(|i| (i, [(i.get() % 256) as u8; PAGE_SIZE]))
        .collect();
    let pages: Vec<(PageIndex, &PageBytes)> = pages.iter().map(|(i, a)| (*i, a)).collect();
    for (page, contents) in pages.iter() {
        let page = page.get() as usize;
        vec[page * PAGE_SIZE..(page + 1) * PAGE_SIZE].copy_from_slice(&contents[..]);
    }
    page_map.update(&pages);

    let memory = unsafe {
        mmap_anonymous(
            None,
            NonZeroUsize::new(memory_pages * PAGE_SIZE).expect("mmap length must be non-zero"),
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE,
        )
        .unwrap()
    }
    .as_ptr();

    let tracker = DeterministicMemoryTracker::new(
        memory,
        NumBytes::new((memory_pages * PAGE_SIZE) as u64),
        no_op_logger(),
        dirty_page_tracking,
        page_map.clone(),
        MemoryLimits {
            max_memory_size: NumBytes::new((memory_pages * PAGE_SIZE) as u64),
            max_dirty_pages: NumOsPages::new(memory_pages as u64),
            max_accessed_wasm_pages,
        },
        /* page_overhead not relevant in these tests */ 1,
        Arc::new(SignalMutex::new(|_| {})),
        on_wasm_page_accessed,
    )
    .unwrap();

    (tracker, page_map, memory, vec)
}

fn with_setup<F>(
    checkpoint_pages: usize,
    memory_pages: usize,
    page_delta: Vec<PageIndex>,
    dirty_page_tracking: DirtyPageTracking,
    f: F,
) where
    F: FnOnce(DeterministicMemoryTracker, PageMap),
{
    let (tracker, page_map, _memory, _vec) = setup(
        checkpoint_pages,
        memory_pages,
        page_delta,
        dirty_page_tracking,
    );
    f(tracker, page_map);
}

fn sigsegv(
    tracker: &DeterministicMemoryTracker,
    page_index: PageIndex,
    access_kind: AccessKind,
) -> SigsegvOutcome {
    let memory = tracker.memory_area().start as *mut u8;
    let page_addr = memory.wrapping_add(page_index.get() as usize * PAGE_SIZE);
    tracker.handle_sigsegv(Some(access_kind), page_addr as *mut c_void)
}

/// Signals an access to the first OS page of the specified Wasm page.
fn sigsegv_wasm_page(
    tracker: &DeterministicMemoryTracker,
    wasm_page_index: usize,
    access_kind: AccessKind,
) -> SigsegvOutcome {
    sigsegv(
        tracker,
        PageIndex::new((wasm_page_index * OS_PAGES_IN_WASM_PAGE) as u64),
        access_kind,
    )
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod random_ops {
    use crate::signal_access_kind_and_address;

    use super::*;

    use std::{cell::RefCell, collections::BTreeSet, io, mem, rc::Rc};

    use proptest::prelude::*;

    thread_local! {
        static TRACKER: RefCell<Option<DeterministicMemoryTracker>> = const { RefCell::new(None) };
    }

    fn with_registered_handler_setup<F, G>(
        checkpoint_pages: usize,
        memory_pages: usize,
        page_delta: Vec<PageIndex>,
        dirty_page_tracking: DirtyPageTracking,
        memory_operations: F,
        final_tracker_checks: G,
    ) where
        F: FnOnce(&mut [u8], Vec<u8>),
        G: FnOnce(DeterministicMemoryTracker),
    {
        let (tracker, _page_map, memory, vec) = setup(
            checkpoint_pages,
            memory_pages,
            page_delta,
            dirty_page_tracking,
        );
        let mut handler = unsafe { RegisteredHandler::new(tracker) };
        let memory =
            unsafe { std::slice::from_raw_parts_mut(memory as *mut u8, memory_pages * PAGE_SIZE) };
        memory_operations(memory, vec);
        final_tracker_checks(handler.take_tracker().unwrap());
    }

    static PREV_SIGSEGV: Mutex<libc::sigaction> = Mutex::new(unsafe { std::mem::zeroed() });

    struct RegisteredHandler();

    impl RegisteredHandler {
        unsafe fn new(tracker: DeterministicMemoryTracker) -> Self {
            unsafe {
                TRACKER.with(|cell| {
                    let previous = cell.replace(Some(tracker));
                    assert!(previous.is_none());
                });

                let mut handler: libc::sigaction = mem::zeroed();

                // Flags copied from wasmtime:
                // https://github.com/bytecodealliance/wasmtime/blob/0e9ce4c231b4b88ce79a1639fbbb5e8bd672d3c3/crates/runtime/src/traphandlers/unix.rs#LL35C1-L35C1
                handler.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER | libc::SA_ONSTACK;
                handler.sa_sigaction = sigsegv_handler as *const () as usize;
                libc::sigemptyset(&mut handler.sa_mask);
                if libc::sigaction(
                    libc::SIGSEGV,
                    &handler,
                    PREV_SIGSEGV.lock().unwrap().deref_mut(),
                ) != 0
                {
                    panic!(
                        "unable to install signal handler: {}",
                        io::Error::last_os_error(),
                    );
                }

                RegisteredHandler()
            }
        }

        fn take_tracker(&mut self) -> Option<DeterministicMemoryTracker> {
            TRACKER.with(|cell| {
                let previous = cell.replace(None);
                unsafe {
                    if libc::sigaction(
                        libc::SIGSEGV,
                        PREV_SIGSEGV.lock().unwrap().deref(),
                        std::ptr::null_mut(),
                    ) != 0
                    {
                        panic!(
                            "unable to unregister signal handler: {}",
                            io::Error::last_os_error(),
                        );
                    }
                };
                previous
            })
        }
    }

    impl Drop for RegisteredHandler {
        fn drop(&mut self) {
            self.take_tracker();
        }
    }

    unsafe extern "C" fn sigsegv_handler(
        signum: libc::c_int,
        siginfo_ptr: *mut libc::siginfo_t,
        ucontext_ptr: *mut libc::c_void,
    ) {
        TRACKER.with(|tracker| {
            assert_eq!(signum, libc::SIGSEGV);
            let tracker = tracker.borrow();
            let tracker = tracker.as_ref().unwrap();

            let (access_kind, si_addr) =
                unsafe { signal_access_kind_and_address(siginfo_ptr, ucontext_ptr) };

            let outcome = tracker.handle_sigsegv(access_kind, si_addr);

            unsafe {
                if outcome != SigsegvOutcome::Handled {
                    let previous = *PREV_SIGSEGV.lock().unwrap().deref();
                    if previous.sa_flags & libc::SA_SIGINFO != 0 {
                        mem::transmute::<
                            usize,
                            extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void),
                        >(previous.sa_sigaction)(
                            signum, siginfo_ptr, ucontext_ptr
                        )
                    } else if previous.sa_sigaction == libc::SIG_DFL
                        || previous.sa_sigaction == libc::SIG_IGN
                    {
                        libc::sigaction(signum, &previous, std::ptr::null_mut());
                    } else {
                        mem::transmute::<usize, extern "C" fn(libc::c_int)>(previous.sa_sigaction)(
                            signum,
                        )
                    }
                }
            }
        })
    }

    #[derive(Clone, Debug)]
    enum Op {
        Read { offset: usize, length: usize },
        Write { offset: usize, contents: Vec<u8> },
    }

    const PAGE_COUNT: usize = 128;

    fn arb_offset_length(mem_length: usize) -> impl Strategy<Value = (usize, usize)> {
        (0..mem_length).prop_flat_map(move |offset| {
            (
                Just(offset),
                (0..std::cmp::min(10 * PAGE_SIZE, mem_length - offset)),
            )
        })
    }

    fn arb_read(mem_length: usize) -> impl Strategy<Value = Op> {
        arb_offset_length(mem_length)
            .prop_flat_map(|(offset, length)| Just(Op::Read { offset, length }))
    }

    fn arb_write(mem_length: usize) -> impl Strategy<Value = Op> {
        arb_offset_length(mem_length)
            .prop_flat_map(|(offset, length)| {
                (Just(offset), prop::collection::vec(any::<u8>(), length))
            })
            .prop_map(|(offset, contents)| Op::Write { offset, contents })
    }

    fn arb_op(mem_length: usize) -> impl Strategy<Value = Op> {
        prop_oneof![arb_read(mem_length), arb_write(mem_length)]
    }

    fn run_random_ops_result_tracking(ops: Vec<Op>) {
        with_registered_handler_setup(
            50,
            PAGE_COUNT,
            (25..75).map(PageIndex::new).collect(),
            DirtyPageTracking::Track,
            |memory, mut vec_memory| {
                for op in ops {
                    match op {
                        Op::Read { offset, length } => {
                            assert_eq!(
                                memory[offset..offset + length],
                                vec_memory[offset..offset + length]
                            );
                        }
                        Op::Write { offset, contents } => {
                            memory[offset..offset + contents.len()].copy_from_slice(&contents);
                            vec_memory[offset..offset + contents.len()].copy_from_slice(&contents);
                        }
                    }
                }
                assert_eq!(memory, vec_memory);
            },
            |_tracker| {},
        )
    }

    fn run_random_ops_result_ignoring(ops: Vec<Op>) {
        with_registered_handler_setup(
            50,
            PAGE_COUNT,
            (25..75).map(PageIndex::new).collect(),
            DirtyPageTracking::Ignore,
            |memory, mut vec_memory| {
                for op in ops {
                    match op {
                        Op::Read { offset, length } => {
                            assert_eq!(
                                memory[offset..offset + length],
                                vec_memory[offset..offset + length]
                            );
                        }
                        Op::Write { offset, contents } => {
                            memory[offset..offset + contents.len()].copy_from_slice(&contents);
                            vec_memory[offset..offset + contents.len()].copy_from_slice(&contents);
                        }
                    }
                }
                assert_eq!(memory, vec_memory);
            },
            |_tracker| {},
        )
    }

    fn run_random_ops_accessed_tracking(ops: Vec<Op>) {
        let accessed = Rc::new(RefCell::new(BTreeSet::new()));
        let dirty = Rc::new(RefCell::new(BTreeSet::new()));
        let accessed_clone = accessed.clone();
        let dirty_clone = dirty.clone();
        with_registered_handler_setup(
            50,
            PAGE_COUNT,
            (25..75).map(PageIndex::new).collect(),
            DirtyPageTracking::Track,
            |memory, mut vec_memory| {
                let copy = vec_memory.clone();
                for op in ops {
                    match op {
                        Op::Read { offset, length } => {
                            if length > 0 {
                                let start_page = offset / PAGE_SIZE;
                                let end_page = (offset + length - 1) / PAGE_SIZE;
                                accessed.borrow_mut().extend(start_page..=end_page);
                                assert_eq!(
                                    memory[offset..offset + length],
                                    vec_memory[offset..offset + length]
                                );
                            }
                        }
                        Op::Write { offset, contents } => {
                            memory[offset..offset + contents.len()].copy_from_slice(&contents);
                            vec_memory[offset..offset + contents.len()].copy_from_slice(&contents);
                        }
                    }
                }
                for i in 0..PAGE_COUNT {
                    if copy[i * PAGE_SIZE..(i + 1) * PAGE_SIZE]
                        != vec_memory[i * PAGE_SIZE..(i + 1) * PAGE_SIZE]
                    {
                        dirty.borrow_mut().insert(i);
                    }
                }
            },
            |tracker| {
                for page in accessed_clone.borrow().iter() {
                    assert!(tracker.is_accessed(PageIndex::new(*page as u64)));
                }
                let tracker_dirty = tracker
                    .take_dirty_pages()
                    .into_iter()
                    .collect::<BTreeSet<_>>();
                for page in dirty_clone.borrow().iter() {
                    assert!(tracker_dirty.contains(&PageIndex::new(*page as u64)));
                }
            },
        )
    }

    fn run_random_ops_accessed_ignoring(ops: Vec<Op>) {
        let accessed = Rc::new(RefCell::new(BTreeSet::new()));
        let accessed_clone = accessed.clone();
        with_registered_handler_setup(
            50,
            PAGE_COUNT,
            (25..75).map(PageIndex::new).collect(),
            DirtyPageTracking::Track,
            |memory, mut vec_memory| {
                for op in ops {
                    match op {
                        Op::Read { offset, length } => {
                            if length > 0 {
                                let start_page = offset / PAGE_SIZE;
                                let end_page = (offset + length - 1) / PAGE_SIZE;
                                accessed.borrow_mut().extend(start_page..=end_page);
                                assert_eq!(
                                    memory[offset..offset + length],
                                    vec_memory[offset..offset + length]
                                );
                            }
                        }
                        Op::Write { offset, contents } => {
                            if !contents.is_empty() {
                                let start_page = offset / PAGE_SIZE;
                                let end_page = (offset + contents.len() - 1) / PAGE_SIZE;
                                accessed.borrow_mut().extend(start_page..=end_page);
                                memory[offset..offset + contents.len()].copy_from_slice(&contents);
                                vec_memory[offset..offset + contents.len()]
                                    .copy_from_slice(&contents);
                            }
                        }
                    }
                }
            },
            |tracker| {
                println!("accessed: {:?}", accessed_clone.borrow());
                for page in accessed_clone.borrow().iter() {
                    assert!(tracker.is_accessed(PageIndex::new(*page as u64)));
                }
            },
        )
    }

    proptest! {
        /// Check that the region controlled by the signal handler behaves the
        /// same as a regular slice with respect to reads/writes (when dirty
        /// page tracking is enabled).
        #[test]
        fn random_ops_result_tracking(ops in prop::collection::vec(arb_op(PAGE_COUNT * PAGE_SIZE), 30)) {
            run_random_ops_result_tracking(ops);
        }

        /// Check that the region controlled by the signal handler behaves the
        /// same as a regular slice with respect to reads/writes (when dirty
        /// page tracking is disabled).
        #[test]
        fn random_ops_result_ignoring(ops in prop::collection::vec(arb_op(PAGE_COUNT * PAGE_SIZE), 30)) {
            run_random_ops_result_ignoring(ops);
        }

        /// Check that the tracker marks every accessed/dirty page as
        /// accessed/dirty when dirty page tracking is enabled.
        #[test]
        fn random_ops_accessed_tracking(ops in prop::collection::vec(arb_op(PAGE_COUNT * PAGE_SIZE), 30)) {
            run_random_ops_accessed_tracking(ops);
        }

        /// Check that accessed pages are always marked as accessed when dirty
        /// page tracking is disabled.
        #[test]
        fn random_ops_accessed_ignoring(ops in prop::collection::vec(arb_op(PAGE_COUNT * PAGE_SIZE), 30)) {
            run_random_ops_accessed_ignoring(ops);
        }
    }
}

#[rstest]
fn deterministic_memory_tracker_correctly_count_access_and_dirty_pages(
    #[values(DirtyPageTracking::Ignore, DirtyPageTracking::Track)]
    dirty_page_tracking: DirtyPageTracking,
    #[values(AccessKind::Read, AccessKind::Write)] first_access_kind: AccessKind,
    #[values(0, 5, 16, 26, 33, 76)] page_index: u64,
    #[values(AccessKind::Read, AccessKind::Write)] second_access_kind: AccessKind,
    #[values(0, OS_PAGES_IN_WASM_PAGE, OS_PAGES_IN_WASM_PAGE * 2)] second_access_offset: usize,
) {
    if second_access_offset == 0
        && (first_access_kind != AccessKind::Read
            || second_access_kind != AccessKind::Write
            || dirty_page_tracking != DirtyPageTracking::Track)
    {
        // We can access the same page twice only in the case of a write after a read.
        return;
    }

    with_setup(
        50,
        128,
        (25..75).map(PageIndex::new).collect(),
        dirty_page_tracking,
        |tracker, _| {
            use crate::conversions::OS_PAGES_IN_WASM_PAGE;

            assert_eq!(tracker.num_accessed_pages(), 0);

            // First access.
            sigsegv(&tracker, PageIndex::new(page_index), first_access_kind);
            assert_eq!(tracker.num_accessed_pages(), OS_PAGES_IN_WASM_PAGE);
            if first_access_kind == AccessKind::Write
                && dirty_page_tracking == DirtyPageTracking::Track
            {
                assert_eq!(tracker.take_dirty_pages().len(), OS_PAGES_IN_WASM_PAGE);
            } else {
                assert_eq!(tracker.take_dirty_pages().len(), 0);
            }

            // Second access.
            sigsegv(
                &tracker,
                PageIndex::new(page_index + second_access_offset as u64),
                second_access_kind,
            );
            assert_eq!(
                tracker.num_accessed_pages(),
                OS_PAGES_IN_WASM_PAGE * if second_access_offset == 0 { 1 } else { 2 }
            );
            if second_access_kind == AccessKind::Write
                && dirty_page_tracking == DirtyPageTracking::Track
            {
                // As we took the previous dirty pages, we should see
                // just one dirty page again.
                assert_eq!(tracker.take_dirty_pages().len(), OS_PAGES_IN_WASM_PAGE);
            } else {
                assert_eq!(tracker.take_dirty_pages().len(), 0);
            }
        },
    );
}

/// Number of OS pages in the memory used by the accessed page limit tests.
const LIMIT_TEST_OS_PAGES: usize = 8 * OS_PAGES_IN_WASM_PAGE;

/// Runs `f` with a tracker over `LIMIT_TEST_OS_PAGES` OS pages and the given
/// accessed page limit. The second argument of `f` counts how often the
/// tracker reported a newly accessed Wasm page via its callback.
fn with_accessed_page_limit<F>(
    dirty_page_tracking: DirtyPageTracking,
    max_accessed_wasm_pages: Option<usize>,
    f: F,
) where
    F: FnOnce(DeterministicMemoryTracker, Arc<AtomicUsize>),
{
    let accessed_callbacks = Arc::new(AtomicUsize::new(0));
    let on_wasm_page_accessed = {
        let accessed_callbacks = Arc::clone(&accessed_callbacks);
        Arc::new(SignalMutex::new(move || {
            accessed_callbacks.fetch_add(1, Ordering::Relaxed);
        }))
    };
    let (tracker, _page_map, _memory, _vec) = setup_with_accessed_page_limit(
        50,
        LIMIT_TEST_OS_PAGES,
        (25..75).map(PageIndex::new).collect(),
        dirty_page_tracking,
        max_accessed_wasm_pages.map(NumWasmPages::new),
        on_wasm_page_accessed,
    );
    f(tracker, accessed_callbacks);
}

fn wasm_page_byte_range(wasm_pages: Range<usize>) -> Range<u64> {
    (wasm_pages.start * WASM_PAGE_SIZE_IN_BYTES) as u64
        ..(wasm_pages.end * WASM_PAGE_SIZE_IN_BYTES) as u64
}

#[rstest]
fn accessed_page_limit_refuses_the_page_after_the_limit(
    #[values(DirtyPageTracking::Ignore, DirtyPageTracking::Track)]
    dirty_page_tracking: DirtyPageTracking,
    #[values(AccessKind::Read, AccessKind::Write)] access_kind: AccessKind,
) {
    with_accessed_page_limit(
        dirty_page_tracking,
        Some(2),
        |tracker, accessed_callbacks| {
            let flag = tracker.page_limit_exceeded_flag().clone();

            assert_eq!(
                sigsegv_wasm_page(&tracker, 0, access_kind),
                SigsegvOutcome::Handled
            );
            assert_eq!(
                sigsegv_wasm_page(&tracker, 5, access_kind),
                SigsegvOutcome::Handled
            );
            assert_eq!(tracker.num_accessed_pages(), 2 * OS_PAGES_IN_WASM_PAGE);
            assert_eq!(accessed_callbacks.load(Ordering::Relaxed), 2);
            assert!(!flag.load(Ordering::Relaxed));
            assert_eq!(tracker.metrics().sigsegv_refused_count(), 0);

            // The third distinct page is refused and nothing changes.
            assert_eq!(
                sigsegv_wasm_page(&tracker, 3, access_kind),
                SigsegvOutcome::Refused
            );
            assert_eq!(tracker.num_accessed_pages(), 2 * OS_PAGES_IN_WASM_PAGE);
            assert_eq!(accessed_callbacks.load(Ordering::Relaxed), 2);
            assert!(!tracker.is_accessed(PageIndex::new((3 * OS_PAGES_IN_WASM_PAGE) as u64)));
            assert!(flag.load(Ordering::Relaxed));
            assert_eq!(tracker.metrics().sigsegv_refused_count(), 1);
            assert_eq!(tracker.metrics().sigsegv_count(), 3);

            // The refused page is still not mapped, so the same access is refused again.
            assert_eq!(
                sigsegv_wasm_page(&tracker, 3, access_kind),
                SigsegvOutcome::Refused
            );
            assert_eq!(tracker.metrics().sigsegv_refused_count(), 2);
            assert_eq!(accessed_callbacks.load(Ordering::Relaxed), 2);
        },
    );
}

#[test]
fn accessed_page_limit_allows_writes_to_accessed_pages_at_the_limit() {
    with_accessed_page_limit(
        DirtyPageTracking::Track,
        Some(2),
        |tracker, accessed_callbacks| {
            assert_eq!(
                sigsegv_wasm_page(&tracker, 0, AccessKind::Read),
                SigsegvOutcome::Handled
            );
            assert_eq!(
                sigsegv_wasm_page(&tracker, 1, AccessKind::Read),
                SigsegvOutcome::Handled
            );
            assert_eq!(tracker.take_dirty_pages().len(), 0);
            assert_eq!(accessed_callbacks.load(Ordering::Relaxed), 2);

            // The limit is reached, but a write to an accessed page only lifts the
            // write-protection and does not map a new page.
            assert_eq!(
                sigsegv_wasm_page(&tracker, 1, AccessKind::Write),
                SigsegvOutcome::Handled
            );
            assert_eq!(tracker.take_dirty_pages().len(), OS_PAGES_IN_WASM_PAGE);
            assert_eq!(tracker.num_accessed_pages(), 2 * OS_PAGES_IN_WASM_PAGE);
            assert!(!tracker.page_limit_exceeded_flag().load(Ordering::Relaxed));
            // Lifting the write protection is not a new access.
            assert_eq!(accessed_callbacks.load(Ordering::Relaxed), 2);

            // Without the access kind the tracker first tries to write-protect
            // an accessed page, which also succeeds at the limit.
            let memory = tracker.memory_area().start as *mut c_void;
            assert_eq!(
                tracker.handle_sigsegv(None, memory),
                SigsegvOutcome::Handled
            );
            assert_eq!(tracker.take_dirty_pages().len(), OS_PAGES_IN_WASM_PAGE);
            assert_eq!(accessed_callbacks.load(Ordering::Relaxed), 2);

            // A write to a new page is refused.
            assert_eq!(
                sigsegv_wasm_page(&tracker, 2, AccessKind::Write),
                SigsegvOutcome::Refused
            );
            assert_eq!(tracker.take_dirty_pages().len(), 0);
            assert_eq!(accessed_callbacks.load(Ordering::Relaxed), 2);
        },
    );
}

#[rstest]
fn accessed_callback_fires_once_per_newly_accessed_wasm_page(
    #[values(DirtyPageTracking::Ignore, DirtyPageTracking::Track)]
    dirty_page_tracking: DirtyPageTracking,
    #[values(None, Some(8))] max_accessed_wasm_pages: Option<usize>,
) {
    with_accessed_page_limit(
        dirty_page_tracking,
        max_accessed_wasm_pages,
        |tracker, accessed_callbacks| {
            for (expected_callbacks, wasm_page) in (1..).zip([3, 0, 7, 4]) {
                assert_eq!(
                    sigsegv_wasm_page(&tracker, wasm_page, AccessKind::Read),
                    SigsegvOutcome::Handled
                );
                if dirty_page_tracking == DirtyPageTracking::Track {
                    // The page was mapped read-only, so a write faults again
                    // and only lifts the write protection.
                    assert_eq!(
                        sigsegv_wasm_page(&tracker, wasm_page, AccessKind::Write),
                        SigsegvOutcome::Handled
                    );
                }
                assert_eq!(
                    accessed_callbacks.load(Ordering::Relaxed),
                    expected_callbacks
                );
                assert_eq!(
                    tracker.num_accessed_pages(),
                    expected_callbacks * OS_PAGES_IN_WASM_PAGE
                );
            }

            // Faults outside the tracked memory are not accesses either.
            let outside = unsafe {
                (tracker.memory_area().start as *mut u8)
                    .add(LIMIT_TEST_OS_PAGES * PAGE_SIZE + PAGE_SIZE)
            } as *mut c_void;
            assert_eq!(
                tracker.handle_sigsegv(Some(AccessKind::Read), outside),
                SigsegvOutcome::NotTracked
            );
            assert_eq!(accessed_callbacks.load(Ordering::Relaxed), 4);
        },
    );
}

#[rstest]
fn no_accessed_page_limit_maps_every_page(
    #[values(DirtyPageTracking::Ignore, DirtyPageTracking::Track)]
    dirty_page_tracking: DirtyPageTracking,
) {
    with_accessed_page_limit(dirty_page_tracking, None, |tracker, accessed_callbacks| {
        for wasm_page in 0..8 {
            assert_eq!(
                sigsegv_wasm_page(&tracker, wasm_page, AccessKind::Read),
                SigsegvOutcome::Handled
            );
        }
        assert_eq!(tracker.num_accessed_pages(), LIMIT_TEST_OS_PAGES);
        assert_eq!(accessed_callbacks.load(Ordering::Relaxed), 8);
        assert!(!tracker.page_limit_exceeded_flag().load(Ordering::Relaxed));
        assert!(tracker.check_range_fits(wasm_page_byte_range(0..1_000_000)));
    });
}

#[test]
fn addresses_outside_the_tracked_memory_are_not_tracked() {
    with_accessed_page_limit(DirtyPageTracking::Track, Some(1), |tracker, _| {
        let outside = tracker
            .memory_area()
            .start
            .wrapping_add(LIMIT_TEST_OS_PAGES * PAGE_SIZE) as *mut c_void;
        assert_eq!(
            tracker.handle_sigsegv(Some(AccessKind::Read), outside),
            SigsegvOutcome::NotTracked
        );
        assert_eq!(tracker.num_accessed_pages(), 0);
        assert!(!tracker.page_limit_exceeded_flag().load(Ordering::Relaxed));
    });
}

#[test]
fn check_range_fits_counts_only_unaccessed_pages() {
    with_accessed_page_limit(DirtyPageTracking::Track, Some(3), |tracker, _| {
        // Accessed Wasm pages: {0, 2}.
        sigsegv_wasm_page(&tracker, 0, AccessKind::Read);
        sigsegv_wasm_page(&tracker, 2, AccessKind::Read);

        // Empty ranges always fit.
        assert!(tracker.check_range_fits(0..0));
        assert!(tracker.check_range_fits(wasm_page_byte_range(7..7)));

        // Already accessed pages do not count.
        assert!(tracker.check_range_fits(wasm_page_byte_range(0..1)));
        assert!(tracker.check_range_fits(wasm_page_byte_range(2..3)));

        // One new page fits (2 + 1 <= 3), even in a range spanning accessed pages.
        assert!(tracker.check_range_fits(wasm_page_byte_range(1..2)));
        assert!(tracker.check_range_fits(wasm_page_byte_range(0..3)));
        // A range ending on the first byte of a page does not touch that page.
        assert!(tracker.check_range_fits(
            (WASM_PAGE_SIZE_IN_BYTES - 1) as u64..(2 * WASM_PAGE_SIZE_IN_BYTES) as u64
        ));

        // Two new pages do not fit (2 + 2 > 3).
        assert!(!tracker.check_range_fits(wasm_page_byte_range(0..4)));
        assert!(!tracker.check_range_fits(wasm_page_byte_range(3..5)));
        // Touching a single byte of each of two new pages is enough.
        assert!(!tracker.check_range_fits(
            (2 * WASM_PAGE_SIZE_IN_BYTES - 1) as u64..(3 * WASM_PAGE_SIZE_IN_BYTES + 1) as u64
        ));

        // Checking does not change the tracker state.
        assert_eq!(tracker.num_accessed_pages(), 2 * OS_PAGES_IN_WASM_PAGE);
        assert!(!tracker.page_limit_exceeded_flag().load(Ordering::Relaxed));

        // After accessing the third page, only accessed pages fit.
        assert_eq!(
            sigsegv_wasm_page(&tracker, 1, AccessKind::Read),
            SigsegvOutcome::Handled
        );
        assert!(tracker.check_range_fits(wasm_page_byte_range(0..3)));
        assert!(!tracker.check_range_fits(wasm_page_byte_range(0..4)));
        assert!(!tracker.check_range_fits(wasm_page_byte_range(7..8)));
    });
}

#[test]
fn check_range_fits_beyond_the_tracked_memory() {
    with_accessed_page_limit(DirtyPageTracking::Track, Some(3), |tracker, _| {
        sigsegv_wasm_page(&tracker, 7, AccessKind::Read);
        // Pages beyond the tracked memory count as unaccessed (1 + 2 <= 3).
        assert!(tracker.check_range_fits(wasm_page_byte_range(7..9)));
        assert!(tracker.check_range_fits(wasm_page_byte_range(8..10)));
        assert!(tracker.check_range_fits(wasm_page_byte_range(7..10)));
        assert!(!tracker.check_range_fits(wasm_page_byte_range(7..11)));
        assert!(!tracker.check_range_fits(wasm_page_byte_range(8..11)));
        assert!(!tracker.check_range_fits(wasm_page_byte_range(100..103)));
    });
}

mod count_unaccessed_wasm_pages {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    /// Enough Wasm pages for the bitmap to span several `u32` blocks.
    const WASM_PAGES: usize = 100;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        /// The block-wise popcount agrees with counting page by page, also for
        /// ranges that extend beyond the bitmap.
        #[test]
        fn matches_counting_page_by_page(
            accessed in prop::collection::btree_set(0..WASM_PAGES, 0..WASM_PAGES),
            (start, end) in (0..WASM_PAGES + 40)
                .prop_flat_map(|start| (Just(start), start..=WASM_PAGES + 40)),
        ) {
            run_matches_counting_page_by_page(accessed, start..end);
        }
    }

    fn run_matches_counting_page_by_page(accessed: BTreeSet<usize>, wasm_pages: Range<usize>) {
        let (tracker, _page_map, _memory, _vec) = setup_with_accessed_page_limit(
            0,
            WASM_PAGES * OS_PAGES_IN_WASM_PAGE,
            vec![],
            DirtyPageTracking::Ignore,
            None,
            Arc::new(SignalMutex::new(|| {})),
        );
        for page in &accessed {
            assert_eq!(
                sigsegv_wasm_page(&tracker, *page, AccessKind::Read),
                SigsegvOutcome::Handled
            );
        }
        let expected = wasm_pages
            .clone()
            .filter(|page| !accessed.contains(page))
            .count();
        assert_eq!(tracker.count_unaccessed_wasm_pages(wasm_pages), expected);
    }
}
