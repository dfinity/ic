use ic_logger::replica_logger::no_op_logger;
use ic_replicated_state::{
    PageIndex, PageMap,
    page_map::{TestPageAllocatorFileDescriptorImpl, test_utils::base_only_storage_layout},
};
use ic_sys::{PAGE_SIZE, PageBytes};
use ic_types::{Height, NumBytes};
use libc::c_void;
use nix::sys::mman::{MapFlags, ProtFlags, mmap};
use rstest::rstest;
use std::io::Write;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::sync::Mutex;

use crate::{
    AccessKind, DirtyPageTracking, OS_PAGES_TO_MAP, SigsegvMemoryTracker,
    new_signal_handler_available, range_from_faulting_page,
};

/// Sets up the SigsegvMemoryTracker to track accesses to a region of memory. Returns:
/// 1. The tracker.
/// 2. A PageMap with the memory contents.
/// 3. A pointer to the tracked region.
/// 4. A regular vector with the same initial contents as the PageMap.
fn setup(
    checkpoint_pages: usize,
    memory_pages: usize,
    page_delta: Vec<PageIndex>,
    dirty_page_tracking: DirtyPageTracking,
) -> (SigsegvMemoryTracker, PageMap, *mut c_void, Vec<u8>) {
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
        Height::new(0),
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
        mmap(
            std::ptr::null_mut(),
            memory_pages * PAGE_SIZE,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON,
            -1,
            0,
        )
        .unwrap()
    };

    let tracker = SigsegvMemoryTracker::new(
        memory,
        NumBytes::new((memory_pages * PAGE_SIZE) as u64),
        no_op_logger(),
        dirty_page_tracking,
        page_map.clone(),
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
    F: FnOnce(SigsegvMemoryTracker, PageMap),
{
    let (tracker, page_map, _memory, _vec) = setup(
        checkpoint_pages,
        memory_pages,
        page_delta,
        dirty_page_tracking,
    );
    f(tracker, page_map);
}

fn sigsegv(tracker: &SigsegvMemoryTracker, page_index: PageIndex, access_kind: AccessKind) {
    let memory = tracker.memory_area.addr as *mut u8;
    let page_addr = unsafe { memory.add(page_index.get() as usize * PAGE_SIZE) };
    tracker.handle_sigsegv(Some(access_kind), page_addr as *mut c_void);
}

#[rstest]
fn correctly_count_access_and_dirty_pages(
    #[values(DirtyPageTracking::Ignore, DirtyPageTracking::Track)]
    dirty_page_tracking: DirtyPageTracking,
    #[values(0, 5, 16, 26, 33, 76)] page_index: u64,
    #[values(0, OS_PAGES_TO_MAP, OS_PAGES_TO_MAP * 2)] second_access_offset: u64,
    #[values(AccessKind::Read, AccessKind::Write)] first_access_kind: AccessKind,
    #[values(AccessKind::Read, AccessKind::Write)] second_access_kind: AccessKind,
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
            assert_eq!(tracker.num_accessed_pages(), 0);

            // First access.
            sigsegv(&tracker, PageIndex::new(page_index), first_access_kind);
            if new_signal_handler_available() {
                assert_eq!(tracker.num_accessed_pages(), OS_PAGES_TO_MAP as usize);
                if first_access_kind == AccessKind::Write
                    && dirty_page_tracking == DirtyPageTracking::Track
                {
                    assert_eq!(tracker.take_dirty_pages().len(), 1);
                    assert_eq!(
                        tracker.take_speculatively_dirty_pages().len(),
                        OS_PAGES_TO_MAP as usize - 1
                    );
                } else {
                    assert_eq!(tracker.take_dirty_pages().len(), 0);
                    assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
                }
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
                if first_access_kind == AccessKind::Write
                    && dirty_page_tracking == DirtyPageTracking::Track
                {
                    assert_eq!(tracker.take_dirty_pages().len(), 1);
                    assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
                } else {
                    assert_eq!(tracker.take_dirty_pages().len(), 0);
                    assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
                }
            }

            // Second access.
            sigsegv(
                &tracker,
                PageIndex::new(page_index + second_access_offset),
                second_access_kind,
            );
            if new_signal_handler_available() {
                assert_eq!(
                    tracker.num_accessed_pages(),
                    OS_PAGES_TO_MAP as usize * if second_access_offset == 0 { 1 } else { 2 }
                );
                if second_access_kind == AccessKind::Write
                    && dirty_page_tracking == DirtyPageTracking::Track
                {
                    // As we took the previous dirty pages, we should see
                    // just one dirty page again.
                    assert_eq!(tracker.take_dirty_pages().len(), 1);
                    assert_eq!(
                        tracker.take_speculatively_dirty_pages().len(),
                        OS_PAGES_TO_MAP as usize - 1
                    );
                } else {
                    assert_eq!(tracker.take_dirty_pages().len(), 0);
                    assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
                }
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(
                    tracker.num_accessed_pages(),
                    if second_access_offset == 0 { 1 } else { 2 }
                );
                if second_access_kind == AccessKind::Write
                    && dirty_page_tracking == DirtyPageTracking::Track
                {
                    assert_eq!(tracker.take_dirty_pages().len(), 1);
                    assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
                } else {
                    assert_eq!(tracker.take_dirty_pages().len(), 0);
                    assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
                }
            }
        },
    );
}

#[test]
fn range_from_faulting_page_works() {
    for i in 0..OS_PAGES_TO_MAP {
        assert_eq!(
            range_from_faulting_page(PageIndex::new(i)),
            PageIndex::new(0)..PageIndex::new(OS_PAGES_TO_MAP)
        );
    }
    assert_eq!(
        range_from_faulting_page(PageIndex::new(OS_PAGES_TO_MAP)),
        PageIndex::new(OS_PAGES_TO_MAP)..PageIndex::new(OS_PAGES_TO_MAP * 2)
    );
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod random_ops {
    use crate::signal_access_kind_and_address;

    use super::*;

    use std::{cell::RefCell, collections::BTreeSet, io, mem, rc::Rc};

    use proptest::prelude::*;

    thread_local! {
        static TRACKER: RefCell<Option<SigsegvMemoryTracker>> = const { RefCell::new(None) };
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
        G: FnOnce(SigsegvMemoryTracker),
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
        unsafe fn new(tracker: SigsegvMemoryTracker) -> Self {
            unsafe {
                TRACKER.with(|cell| {
                    let previous = cell.replace(Some(tracker));
                    assert!(previous.is_none());
                });

                let mut handler: libc::sigaction = mem::zeroed();

                // Flags copied from wasmtime:
                // https://github.com/bytecodealliance/wasmtime/blob/0e9ce4c231b4b88ce79a1639fbbb5e8bd672d3c3/crates/runtime/src/traphandlers/unix.rs#LL35C1-L35C1
                handler.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER | libc::SA_ONSTACK;
                handler.sa_sigaction = sigsegv_handler as usize;
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

        fn take_tracker(&mut self) -> Option<SigsegvMemoryTracker> {
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

    // Page count should be a multiple of 16 (64 KiB / 4 KiB = 16).
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

    proptest! {
        /// Check that the region controlled by the signal handler behaves the
        /// same as a regular slice with respect to reads/writes (when dirty
        /// page tracking is enabled).
        #[test]
        fn random_ops_result_tracking(ops in prop::collection::vec(arb_op(PAGE_COUNT * PAGE_SIZE), 30)) {
            with_registered_handler_setup(
                50,
                PAGE_COUNT,
                (25..75).map(PageIndex::new).collect(),
                DirtyPageTracking::Track,
                |memory, mut vec_memory| {
                    for op in ops {
                        match op {
                            Op::Read { offset, length } => {
                                assert_eq!(memory[offset..offset + length], vec_memory[offset..offset + length]);
                            }
                            Op::Write { offset, contents } => {
                                memory[offset..offset + contents.len()].copy_from_slice(&contents);
                                vec_memory[offset..offset + contents.len()].copy_from_slice(&contents);
                            }
                        }
                    }
                    assert_eq!(memory, vec_memory);
                },
                |_tracker: SigsegvMemoryTracker| {}
            )
        }

        /// Check that the region controlled by the signal handler behaves the
        /// same as a regular slice with respect to reads/writes (when dirty
        /// page tracking is disabled).
        #[test]
        fn random_ops_result_ignoring(ops in prop::collection::vec(arb_op(PAGE_COUNT * PAGE_SIZE), 30)) {
            with_registered_handler_setup(
                50,
                PAGE_COUNT,
                (25..75).map(PageIndex::new).collect(),
                DirtyPageTracking::Ignore,
                |memory, mut vec_memory| {
                    for op in ops {
                        match op {
                            Op::Read { offset, length } => {
                                assert_eq!(memory[offset..offset + length], vec_memory[offset..offset + length]);
                            }
                            Op::Write { offset, contents } => {
                                memory[offset..offset + contents.len()].copy_from_slice(&contents);
                                vec_memory[offset..offset + contents.len()].copy_from_slice(&contents);
                            }
                        }
                    }
                    assert_eq!(memory, vec_memory);
                },
                |_tracker: SigsegvMemoryTracker| {}
            )
        }

        /// Check that the tracker marks every accessed/dirty page as
        /// accessed/dirty when dirty page tracking is enabled.
        #[test]
        fn random_ops_accessed_tracking(ops in prop::collection::vec(arb_op(PAGE_COUNT * PAGE_SIZE), 30)) {
            let accessed = Rc::new(RefCell::new(BTreeSet::new()));
            let dirty = Rc::new(RefCell::new(BTreeSet::new()));
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
                                    assert_eq!(memory[offset..offset + length], vec_memory[offset..offset + length]);
                                }
                            }
                            Op::Write { offset, contents } => {
                                memory[offset..offset + contents.len()].copy_from_slice(&contents);
                                vec_memory[offset..offset + contents.len()].copy_from_slice(&contents);
                            }
                        }
                    }
                    for i in 0..PAGE_COUNT {
                        if copy[i * PAGE_SIZE..(i + 1) * PAGE_SIZE] != vec_memory[i * PAGE_SIZE..(i + 1) * PAGE_SIZE] {
                            dirty.borrow_mut().insert(i);
                        }
                    }
                },
                |tracker: SigsegvMemoryTracker| {
                    let tracker_accessed = tracker.accessed_pages().borrow();
                    for page in accessed.borrow().iter() {
                        assert!(tracker_accessed.is_marked(PageIndex::new(*page as u64)));
                    }
                    let tracker_dirty = tracker.take_dirty_pages().into_iter().collect::<BTreeSet<_>>();
                    let tracker_speculative = tracker.take_speculatively_dirty_pages().into_iter().collect::<BTreeSet<_>>();
                    for page in dirty.borrow().iter() {
                        assert!(tracker_dirty.contains(&PageIndex::new(*page as u64))
                            || tracker_speculative.contains(&PageIndex::new(*page as u64)));
                    }
                }
            )
        }

        /// Check that accessed pages are always marked as accessed when dirty
        /// page tracking is disabled.
        #[test]
        fn random_ops_accessed_ignoring(ops in prop::collection::vec(arb_op(PAGE_COUNT * PAGE_SIZE), 30)) {
            let accessed = Rc::new(RefCell::new(BTreeSet::new()));
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
                                    assert_eq!(memory[offset..offset + length], vec_memory[offset..offset + length]);
                                }
                            }
                            Op::Write { offset, contents } => {
                                if !contents.is_empty() {
                                    let start_page = offset / PAGE_SIZE;
                                    let end_page = (offset + contents.len() - 1) / PAGE_SIZE;
                                    accessed.borrow_mut().extend(start_page..=end_page);
                                    memory[offset..offset + contents.len()].copy_from_slice(&contents);
                                    vec_memory[offset..offset + contents.len()].copy_from_slice(&contents);
                                }
                            }
                        }
                    }
                },
                |tracker: SigsegvMemoryTracker| {
                    let tracker_accessed = tracker.accessed_pages().borrow();
                    for page in accessed.borrow().iter() {
                        assert!(tracker_accessed.is_marked(PageIndex::new(*page as u64)));
                    }
                }
            )
        }
    }
}
