use std::io::Write;

use crate::signal_mutex::SignalMutex;
use ic_logger::replica_logger::no_op_logger;
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
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

use crate::{
    AbortReason, AccessKind, DeterministicMemoryTracker, DirtyPageTracking, MemoryLimits,
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
    let (tracker, page_map, memory, vec, _aborts) = setup_with_access_limit(
        checkpoint_pages,
        memory_pages,
        page_delta,
        dirty_page_tracking,
        // Effectively unlimited: the whole tracked region may be accessed.
        NumOsPages::new(memory_pages as u64),
    );
    (tracker, page_map, memory, vec)
}

/// Like `setup`, but with an explicit per-message access limit. Also returns the
/// list of abort reasons the tracker reported, in order.
#[allow(clippy::type_complexity)]
fn setup_with_access_limit(
    checkpoint_pages: usize,
    memory_pages: usize,
    page_delta: Vec<PageIndex>,
    dirty_page_tracking: DirtyPageTracking,
    max_accessed_pages: NumOsPages,
) -> (
    DeterministicMemoryTracker,
    PageMap,
    *mut c_void,
    Vec<u8>,
    Arc<Mutex<Vec<AbortReason>>>,
) {
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

    let aborts = Arc::new(Mutex::new(Vec::new()));
    let recorded_aborts = Arc::clone(&aborts);

    let tracker = DeterministicMemoryTracker::new(
        memory,
        NumBytes::new((memory_pages * PAGE_SIZE) as u64),
        no_op_logger(),
        dirty_page_tracking,
        page_map.clone(),
        MemoryLimits {
            max_memory_size: NumBytes::new((memory_pages * PAGE_SIZE) as u64),
            max_dirty_pages: NumOsPages::new(memory_pages as u64),
            max_accessed_pages,
        },
        /* page_overhead not relevant in these tests */ 1,
        Arc::new(SignalMutex::new(|_| {})),
        Arc::new(SignalMutex::new(move |reason: AbortReason| {
            recorded_aborts.lock().unwrap().push(reason);
        })),
    )
    .unwrap();

    (tracker, page_map, memory, vec, aborts)
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

fn sigsegv(tracker: &DeterministicMemoryTracker, page_index: PageIndex, access_kind: AccessKind) {
    let memory = tracker.memory_area().start as *mut u8;
    let page_addr = unsafe { memory.add(page_index.get() as usize * PAGE_SIZE) };
    tracker.handle_sigsegv(Some(access_kind), page_addr as *mut c_void);
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

            let handled = tracker.handle_sigsegv(access_kind, si_addr);

            unsafe {
                if !handled {
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

/// Accessing exactly the limit must not abort: the default limit is the whole
/// heap, so a message touching all of it has to keep working.
#[rstest]
fn access_limit_is_not_exceeded_at_the_limit(
    #[values(DirtyPageTracking::Ignore, DirtyPageTracking::Track)]
    dirty_page_tracking: DirtyPageTracking,
    #[values(AccessKind::Read, AccessKind::Write)] access_kind: AccessKind,
) {
    let wasm_pages = 4;
    let memory_pages = wasm_pages * OS_PAGES_IN_WASM_PAGE;
    let (tracker, _page_map, _memory, _vec, aborts) = setup_with_access_limit(
        0,
        memory_pages,
        vec![],
        dirty_page_tracking,
        NumOsPages::new(memory_pages as u64),
    );

    for wasm_page in 0..wasm_pages {
        sigsegv(
            &tracker,
            PageIndex::new((wasm_page * OS_PAGES_IN_WASM_PAGE) as u64),
            access_kind,
        );
    }

    assert_eq!(tracker.num_accessed_pages(), memory_pages);
    assert_eq!(*aborts.lock().unwrap(), vec![]);
}

/// Both reads and writes count towards the single access limit, and the
/// violation is reported once, when the limit is first exceeded.
#[rstest]
fn access_limit_exceeded_aborts_once(
    #[values(DirtyPageTracking::Ignore, DirtyPageTracking::Track)]
    dirty_page_tracking: DirtyPageTracking,
    #[values(AccessKind::Read, AccessKind::Write)] access_kind: AccessKind,
) {
    // Allow two Wasm pages worth of OS pages, then access four Wasm pages.
    let allowed_wasm_pages = 2;
    let wasm_pages = 4;
    let memory_pages = wasm_pages * OS_PAGES_IN_WASM_PAGE;
    let (tracker, _page_map, _memory, _vec, aborts) = setup_with_access_limit(
        0,
        memory_pages,
        vec![],
        dirty_page_tracking,
        NumOsPages::new((allowed_wasm_pages * OS_PAGES_IN_WASM_PAGE) as u64),
    );

    for wasm_page in 0..allowed_wasm_pages {
        sigsegv(
            &tracker,
            PageIndex::new((wasm_page * OS_PAGES_IN_WASM_PAGE) as u64),
            access_kind,
        );
    }
    assert_eq!(*aborts.lock().unwrap(), vec![]);

    // The next Wasm page crosses the limit.
    sigsegv(
        &tracker,
        PageIndex::new((allowed_wasm_pages * OS_PAGES_IN_WASM_PAGE) as u64),
        access_kind,
    );
    assert_eq!(
        *aborts.lock().unwrap(),
        vec![AbortReason::WasmPagesAccessLimitExceeded]
    );

    // Faults after the violation report it again; the embedder keeps only the
    // first one, so the reported error does not depend on how many follow.
    sigsegv(
        &tracker,
        PageIndex::new(((allowed_wasm_pages + 1) * OS_PAGES_IN_WASM_PAGE) as u64),
        access_kind,
    );
    assert_eq!(
        *aborts.lock().unwrap(),
        vec![
            AbortReason::WasmPagesAccessLimitExceeded,
            AbortReason::WasmPagesAccessLimitExceeded
        ]
    );
}
