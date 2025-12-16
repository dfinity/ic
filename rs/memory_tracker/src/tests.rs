<<<<<<< HEAD
use std::io::Write;

use ic_logger::replica_logger::no_op_logger;
use ic_replicated_state::{
    PageIndex, PageMap,
    page_map::{TestPageAllocatorFileDescriptorImpl, test_utils::base_only_storage_layout},
};
use ic_sys::{PAGE_SIZE, PageBytes};
use ic_types::{Height, NumBytes};
use libc::c_void;
use nix::sys::mman::{MapFlags, ProtFlags, mmap};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::sync::Mutex;

use crate::{
    AccessKind, DirtyPageTracking, MemoryTracker,
    prefetching::{PrefetchingMemoryTracker, prefetching_signal_handler_available},
};

/// Sets up the PrefetchingMemoryTracker to track accesses to a region of memory. Returns:
/// 1. The tracker.
/// 2. A PageMap with the memory contents.
/// 3. A pointer to the tracked region.
/// 4. A regular vector with the same initial contents as the PageMap.
fn setup(
    checkpoint_pages: usize,
    memory_pages: usize,
    page_delta: Vec<PageIndex>,
    dirty_page_tracking: DirtyPageTracking,
) -> (PrefetchingMemoryTracker, PageMap, *mut c_void, Vec<u8>) {
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

    let tracker = PrefetchingMemoryTracker::new(
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
    F: FnOnce(PrefetchingMemoryTracker, PageMap),
{
    let (tracker, page_map, _memory, _vec) = setup(
        checkpoint_pages,
        memory_pages,
        page_delta,
        dirty_page_tracking,
    );
    f(tracker, page_map);
}

fn sigsegv(tracker: &PrefetchingMemoryTracker, page_index: PageIndex, access_kind: AccessKind) {
    let memory = tracker.start() as *mut u8;
    let page_addr = unsafe { memory.add(page_index.get() as usize * PAGE_SIZE) };
    tracker.handle_sigsegv(Some(access_kind), page_addr as *mut c_void);
}

#[test]
fn prefetch_for_read_checkpoint_forward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(5), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Faulting at page 5 prefetches pages 0-24 since pages 25..75 are dirty.
                assert_eq!(tracker.num_accessed_pages(), 25);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_read_checkpoint_backward() {
    with_setup(
        50,
        100,
        (0..5).chain(25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(20), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Faulting at page 20 prefetches pages 5-24 since pages
                // 0..5 and 25..75 are dirty.
                assert_eq!(tracker.num_accessed_pages(), 20);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_read_zeros_forward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(80), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // We prefetch to the end of the memory region at most, so faulting at page 80
                // prefetches pages 75..100.
                assert_eq!(tracker.num_accessed_pages(), 25);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_read_zeros_backward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(95), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // We prefetch to the end of the memory region at most, so faulting at page 95
                // prefetches pages 75..100.
                assert_eq!(tracker.num_accessed_pages(), 25);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_read_page_delta_single_page() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 1);
        },
    );
}

#[test]
fn prefetch_for_read_page_delta_different_pages() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(20), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Faulting at page 20 prefetches pages 0..25.
                assert_eq!(tracker.num_accessed_pages(), 25);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // There are no accessed pages immediately before or after the faulting page.
                assert_eq!(tracker.num_accessed_pages(), 25 + 1);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 2);
            }
        },
    );
}

#[test]
fn prefetch_for_read_page_delta_contiguous_forward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(26), AccessKind::Read);
            // Faulting at page 26 prefetches only page 26.
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(27), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Faulting at page 27 prefetches pages 27..29 because of the previously
                // accessed page 26.
                assert_eq!(tracker.num_accessed_pages(), 3);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 2);
            }
            sigsegv(&tracker, PageIndex::new(29), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Because the previous 3 pages have been accessed, we prefetch
                // at least that much again, plus 1 for the actually accessed page.
                assert_eq!(tracker.num_accessed_pages(), 7);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 3);
            }
        },
    );
}

#[test]
fn prefetch_for_read_page_delta_contiguous_backward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Read);
            // Faulting at page 50 prefetches only page 50.
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(49), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Faulting at page 49 prefetches pages 48..50 because of the previously
                // accessed page 50.
                assert_eq!(tracker.num_accessed_pages(), 3);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 2);
            }
            sigsegv(&tracker, PageIndex::new(47), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Because the previous 3 pages have been accessed, we prefetch
                // at least that much again, plus 1 for the actually accessed page.
                assert_eq!(tracker.num_accessed_pages(), 7);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 3);
            }
        },
    );
}

#[test]
fn prefetch_for_write_checkpoint_ignore_dirty() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Ignore,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(5), AccessKind::Write);
            if prefetching_signal_handler_available() {
                // Faulting at page 5 prefetches pages 0..25.
                assert_eq!(tracker.num_accessed_pages(), 25);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_write_zeros_ignore_dirty() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Ignore,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(80), AccessKind::Write);
            if prefetching_signal_handler_available() {
                // There are no dirty pages so pages 75..100 are mapped.
                assert_eq!(tracker.num_accessed_pages(), 25);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_write_page_delta_single_page_ignore_dirty() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Ignore,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            // There are no accessed pages immediately before the faulting page.
            // So only the minimum should be fetched
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.num_accessed_pages(), 1);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_write_page_delta_different_pages_ignore_dirty() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Ignore,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(50 + 2), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 2);
        },
    );
}

#[test]
fn prefetch_for_write_page_delta_contiguous_ignore_dirty() {
    with_setup(
        50,
        100,
        (25..95).map(PageIndex::new).collect(),
        DirtyPageTracking::Ignore,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(50 + 1), AccessKind::Write);
            if prefetching_signal_handler_available() {
                // One page was accessed immediately before the faulting page, so that many
                // additional pages should be prefetched.
                let prefetched = 1 + 1;
                assert_eq!(tracker.num_accessed_pages(), 1 + prefetched);
                sigsegv(
                    &tracker,
                    PageIndex::new((50 + 1 + prefetched) as u64),
                    AccessKind::Write,
                );
                let prefetched_at_last = 1 + prefetched + 1;
                assert_eq!(
                    tracker.num_accessed_pages(),
                    1 + prefetched + prefetched_at_last
                );
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 2);
            }
        },
    );
}

#[test]
fn prefetch_for_write_checkpoint() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(5), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.take_dirty_pages().len(), 1);
            } else {
                // The old signal handler detects dirty pages on the second signal.
                assert_eq!(tracker.take_dirty_pages().len(), 0);
            }
        },
    );
}

#[test]
fn prefetch_for_write_zeros() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(80), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.take_dirty_pages().len(), 1);
            } else {
                // The old signal handler detects dirty pages on the second signal.
                assert_eq!(tracker.take_dirty_pages().len(), 0);
            }
        },
    );
}

#[test]
fn prefetch_for_write_page_delta_single_page() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.take_dirty_pages().len(), 1);
            } else {
                // The old signal handler detects dirty pages on the second signal.
                assert_eq!(tracker.take_dirty_pages().len(), 0);
            }
        },
    );
}

#[test]
fn prefetch_for_write_page_delta_different_pages() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 2);
            assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.take_dirty_pages().len(), 2);
            } else {
                // The old signal handler detects dirty pages on the second signal.
                assert_eq!(tracker.take_dirty_pages().len(), 0);
            }
        },
    );
}

#[test]
fn prefetch_for_write_page_delta_contiguous() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            if prefetching_signal_handler_available() {
                let prefetched_at_51 = 2;
                assert_eq!(tracker.num_accessed_pages(), 1 + prefetched_at_51);
                sigsegv(
                    &tracker,
                    PageIndex::new(51 + prefetched_at_51 as u64),
                    AccessKind::Write,
                );
                let prefetched_at_last = 1 + prefetched_at_51 + 1;
                assert_eq!(
                    tracker.num_accessed_pages(),
                    1 + prefetched_at_51 + prefetched_at_last
                );
                assert_eq!(
                    tracker.take_speculatively_dirty_pages().len(),
                    prefetched_at_51 + prefetched_at_last - 2
                );
                assert_eq!(tracker.take_dirty_pages().len(), 3);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 2);
            }
        },
    );
}

#[test]
fn prefetch_for_write_after_read_stop_at_dirty_forward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            // Access pages 51..=55.
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Read);
            // Write to the last page to set it as the boundary for write prefetching.
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            // Page 53 should be prefetched now.
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);
            if prefetching_signal_handler_available() {
                // Only page 53 is speculatively dirty, other pages are dirty.
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 1);
            } else {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            }
            assert_eq!(tracker.take_dirty_pages().len(), 4);
        },
    );
}

#[test]
fn prefetch_for_write_after_read_stop_at_dirty_backward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            // Access pages 51..=55.
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Read);
            // Write to the first page to set it as the boundary for write prefetching.
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);
            // Page 53 should be prefetched now.
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            if prefetching_signal_handler_available() {
                // Only page 53 is speculatively dirty, other pages are dirty.
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 1);
            } else {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            }
            assert_eq!(tracker.take_dirty_pages().len(), 4);
        },
    );
}

#[test]
fn prefetch_for_write_after_read_stop_at_unaccessed_forward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            // Access page 55 t prevent prefetching after this page.
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Read);
            // Access pages 51..=54.
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Read);

            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            // This should prefetch page 53.
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            // The following should prefetch only page 55 because it is the last accessed page.
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 2);
            } else {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            }
            assert_eq!(tracker.take_dirty_pages().len(), 3);
        },
    );
}

#[test]
fn prefetch_for_write_after_read_stop_at_unaccessed_backward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            // Access pages 51..=55.
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Read);

            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            // This should prefetch page 53.
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);
            // The following should prefetch only page 51 because it is the first accessed page.
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 2);
            } else {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            }
            assert_eq!(tracker.take_dirty_pages().len(), 3);
        },
    );
}

#[test]
fn prefetch_for_write_with_other_dirty_pages_forward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);

            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            // This should prefetch page 52.
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            // This should prefetch only 54, and not 55.
            sigsegv(&tracker, PageIndex::new(53), AccessKind::Write);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.num_accessed_pages(), 1 + 5);
                // Only pages 52 and 54 are speculatively dirty, other pages are dirty.
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 2);
                assert_eq!(tracker.take_dirty_pages().len(), 4);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 4);
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
                // The old signal handler considered the last writes as read.
                assert_eq!(tracker.take_dirty_pages().len(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_write_with_other_dirty_pages_backward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);

            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            // This should prefetch page 53.
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);
            // This should prefetch only 51, and not 50.
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.num_accessed_pages(), 1 + 5);
                // Only pages 53 and 51 are speculatively dirty, other pages are dirty.
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 2);
                assert_eq!(tracker.take_dirty_pages().len(), 4);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 4);
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
                // The old signal handler considered the last writes as read.
                assert_eq!(tracker.take_dirty_pages().len(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_write_after_read_unordered() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            // The following access pattern doesn't allow for any prefetching beyond the bare minimum.
            assert_eq!(tracker.num_accessed_pages(), 0);
            let next = PageIndex::new(26);
            sigsegv(&tracker, next, AccessKind::Read);
            sigsegv(&tracker, next, AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            let next = PageIndex::new(26 + 2);
            sigsegv(&tracker, next, AccessKind::Read);
            sigsegv(&tracker, next, AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 2);
            let next = PageIndex::new(26 + 2 * 2);
            sigsegv(&tracker, next, AccessKind::Read);
            sigsegv(&tracker, next, AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 3);
            let next = PageIndex::new(26 + 3 * 2);
            sigsegv(&tracker, next, AccessKind::Read);
            sigsegv(&tracker, next, AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 4);
            // We only ever use min_prefetch_range for marking writeable, so in this case
            // this only marks the actually written pages as writeable
            assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            assert_eq!(tracker.take_dirty_pages().len(), 4);
        },
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
        static TRACKER: RefCell<Option<PrefetchingMemoryTracker>> = const { RefCell::new(None) };
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
        G: FnOnce(PrefetchingMemoryTracker),
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
        unsafe fn new(tracker: PrefetchingMemoryTracker) -> Self {
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

        fn take_tracker(&mut self) -> Option<PrefetchingMemoryTracker> {
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

    const PAGE_COUNT: usize = 100;

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
                |_tracker: PrefetchingMemoryTracker| {}
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
                |_tracker: PrefetchingMemoryTracker| {}
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
                |tracker: PrefetchingMemoryTracker| {
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
                |tracker: PrefetchingMemoryTracker| {
                    let tracker_accessed = tracker.accessed_pages().borrow();
                    for page in accessed.borrow().iter() {
                        assert!(tracker_accessed.is_marked(PageIndex::new(*page as u64)));
                    }
                }
            )
        }
    }
}
||||||| parent of 9569b2afa19 (feat(DSM-58): Refactoring for Deterministic Memory Tracker)
=======
use std::io::Write;

use ic_logger::replica_logger::no_op_logger;
use ic_replicated_state::{
    PageIndex, PageMap,
    page_map::{TestPageAllocatorFileDescriptorImpl, test_utils::base_only_storage_layout},
};
use ic_sys::{PAGE_SIZE, PageBytes};
use ic_types::{Height, NumBytes, NumOsPages};
use libc::c_void;
use nix::sys::mman::{MapFlags, ProtFlags, mmap};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::sync::Mutex;

use crate::{
    AccessKind, DirtyPageTracking, MemoryLimits, MemoryTracker,
    prefetching::{PageBitmap, PrefetchingMemoryTracker, prefetching_signal_handler_available},
};

/// Sets up the PrefetchingMemoryTracker to track accesses to a region of memory. Returns:
/// 1. The tracker.
/// 2. A PageMap with the memory contents.
/// 3. A pointer to the tracked region.
/// 4. A regular vector with the same initial contents as the PageMap.
fn setup(
    checkpoint_pages: usize,
    memory_pages: usize,
    page_delta: Vec<PageIndex>,
    dirty_page_tracking: DirtyPageTracking,
) -> (Box<dyn MemoryTracker>, PageMap, *mut c_void, Vec<u8>) {
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

    let tracker = Box::new(
        PrefetchingMemoryTracker::new(
            memory,
            NumBytes::new((memory_pages * PAGE_SIZE) as u64),
            no_op_logger(),
            dirty_page_tracking,
            page_map.clone(),
            MemoryLimits {
                max_memory_size: NumBytes::new((memory_pages * PAGE_SIZE) as u64),
                max_accessed_pages: NumOsPages::new(memory_pages as u64),
                max_dirty_pages: NumOsPages::new(memory_pages as u64),
            },
        )
        .unwrap(),
    );
    (tracker, page_map, memory, vec);
}

fn with_setup<F>(
    checkpoint_pages: usize,
    memory_pages: usize,
    page_delta: Vec<PageIndex>,
    dirty_page_tracking: DirtyPageTracking,
    f: F,
) where
    F: FnOnce(Box<dyn MemoryTracker>, PageMap),
{
    let (tracker, page_map, _memory, _vec) = setup(
        checkpoint_pages,
        memory_pages,
        page_delta,
        dirty_page_tracking,
    );
    f(tracker, page_map);
}

fn sigsegv(tracker: &Box<dyn MemoryTracker>, page_index: PageIndex, access_kind: AccessKind) {
    let memory = tracker.memory_area().start as *mut u8;
    let page_addr = unsafe { memory.add(page_index.get() as usize * PAGE_SIZE) };
    tracker.handle_sigsegv(Some(access_kind), page_addr as *mut c_void);
}

#[test]
fn prefetch_for_read_checkpoint_forward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(5), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Faulting at page 5 prefetches pages 0-24 since pages 25..75 are dirty.
                assert_eq!(tracker.num_accessed_pages(), 25);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_read_checkpoint_backward() {
    with_setup(
        50,
        100,
        (0..5).chain(25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(20), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Faulting at page 20 prefetches pages 5-24 since pages
                // 0..5 and 25..75 are dirty.
                assert_eq!(tracker.num_accessed_pages(), 20);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_read_zeros_forward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(80), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // We prefetch to the end of the memory region at most, so faulting at page 80
                // prefetches pages 75..100.
                assert_eq!(tracker.num_accessed_pages(), 25);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_read_zeros_backward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(95), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // We prefetch to the end of the memory region at most, so faulting at page 95
                // prefetches pages 75..100.
                assert_eq!(tracker.num_accessed_pages(), 25);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_read_page_delta_single_page() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 1);
        },
    );
}

#[test]
fn prefetch_for_read_page_delta_different_pages() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(20), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Faulting at page 20 prefetches pages 0..25.
                assert_eq!(tracker.num_accessed_pages(), 25);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // There are no accessed pages immediately before or after the faulting page.
                assert_eq!(tracker.num_accessed_pages(), 25 + 1);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 2);
            }
        },
    );
}

#[test]
fn prefetch_for_read_page_delta_contiguous_forward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(26), AccessKind::Read);
            // Faulting at page 26 prefetches only page 26.
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(27), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Faulting at page 27 prefetches pages 27..29 because of the previously
                // accessed page 26.
                assert_eq!(tracker.num_accessed_pages(), 3);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 2);
            }
            sigsegv(&tracker, PageIndex::new(29), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Because the previous 3 pages have been accessed, we prefetch
                // at least that much again, plus 1 for the actually accessed page.
                assert_eq!(tracker.num_accessed_pages(), 7);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 3);
            }
        },
    );
}

#[test]
fn prefetch_for_read_page_delta_contiguous_backward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Read);
            // Faulting at page 50 prefetches only page 50.
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(49), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Faulting at page 49 prefetches pages 48..50 because of the previously
                // accessed page 50.
                assert_eq!(tracker.num_accessed_pages(), 3);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 2);
            }
            sigsegv(&tracker, PageIndex::new(47), AccessKind::Read);
            if prefetching_signal_handler_available() {
                // Because the previous 3 pages have been accessed, we prefetch
                // at least that much again, plus 1 for the actually accessed page.
                assert_eq!(tracker.num_accessed_pages(), 7);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 3);
            }
        },
    );
}

#[test]
fn prefetch_for_write_checkpoint_ignore_dirty() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Ignore,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(5), AccessKind::Write);
            if prefetching_signal_handler_available() {
                // Faulting at page 5 prefetches pages 0..25.
                assert_eq!(tracker.num_accessed_pages(), 25);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_write_zeros_ignore_dirty() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Ignore,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(80), AccessKind::Write);
            if prefetching_signal_handler_available() {
                // There are no dirty pages so pages 75..100 are mapped.
                assert_eq!(tracker.num_accessed_pages(), 25);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_write_page_delta_single_page_ignore_dirty() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Ignore,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            // There are no accessed pages immediately before the faulting page.
            // So only the minimum should be fetched
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.num_accessed_pages(), 1);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_write_page_delta_different_pages_ignore_dirty() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Ignore,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(50 + 2), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 2);
        },
    );
}

#[test]
fn prefetch_for_write_page_delta_contiguous_ignore_dirty() {
    with_setup(
        50,
        100,
        (25..95).map(PageIndex::new).collect(),
        DirtyPageTracking::Ignore,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(50 + 1), AccessKind::Write);
            if prefetching_signal_handler_available() {
                // One page was accessed immediately before the faulting page, so that many
                // additional pages should be prefetched.
                let prefetched = 1 + 1;
                assert_eq!(tracker.num_accessed_pages(), 1 + prefetched);
                sigsegv(
                    &tracker,
                    PageIndex::new((50 + 1 + prefetched) as u64),
                    AccessKind::Write,
                );
                let prefetched_at_last = 1 + prefetched + 1;
                assert_eq!(
                    tracker.num_accessed_pages(),
                    1 + prefetched + prefetched_at_last
                );
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 2);
            }
        },
    );
}

#[test]
fn prefetch_for_write_checkpoint() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(5), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.take_dirty_pages().len(), 1);
            } else {
                // The old signal handler detects dirty pages on the second signal.
                assert_eq!(tracker.take_dirty_pages().len(), 0);
            }
        },
    );
}

#[test]
fn prefetch_for_write_zeros() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(80), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.take_dirty_pages().len(), 1);
            } else {
                // The old signal handler detects dirty pages on the second signal.
                assert_eq!(tracker.take_dirty_pages().len(), 0);
            }
        },
    );
}

#[test]
fn prefetch_for_write_page_delta_single_page() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.take_dirty_pages().len(), 1);
            } else {
                // The old signal handler detects dirty pages on the second signal.
                assert_eq!(tracker.take_dirty_pages().len(), 0);
            }
        },
    );
}

#[test]
fn prefetch_for_write_page_delta_different_pages() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 2);
            assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.take_dirty_pages().len(), 2);
            } else {
                // The old signal handler detects dirty pages on the second signal.
                assert_eq!(tracker.take_dirty_pages().len(), 0);
            }
        },
    );
}

#[test]
fn prefetch_for_write_page_delta_contiguous() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            if prefetching_signal_handler_available() {
                let prefetched_at_51 = 2;
                assert_eq!(tracker.num_accessed_pages(), 1 + prefetched_at_51);
                sigsegv(
                    &tracker,
                    PageIndex::new(51 + prefetched_at_51 as u64),
                    AccessKind::Write,
                );
                let prefetched_at_last = 1 + prefetched_at_51 + 1;
                assert_eq!(
                    tracker.num_accessed_pages(),
                    1 + prefetched_at_51 + prefetched_at_last
                );
                assert_eq!(
                    tracker.take_speculatively_dirty_pages().len(),
                    prefetched_at_51 + prefetched_at_last - 2
                );
                assert_eq!(tracker.take_dirty_pages().len(), 3);
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 2);
            }
        },
    );
}

#[test]
fn prefetch_for_write_after_read_stop_at_dirty_forward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            // Access pages 51..=55.
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Read);
            // Write to the last page to set it as the boundary for write prefetching.
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            // Page 53 should be prefetched now.
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);
            if prefetching_signal_handler_available() {
                // Only page 53 is speculatively dirty, other pages are dirty.
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 1);
            } else {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            }
            assert_eq!(tracker.take_dirty_pages().len(), 4);
        },
    );
}

#[test]
fn prefetch_for_write_after_read_stop_at_dirty_backward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            // Access pages 51..=55.
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Read);
            // Write to the first page to set it as the boundary for write prefetching.
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);
            // Page 53 should be prefetched now.
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            if prefetching_signal_handler_available() {
                // Only page 53 is speculatively dirty, other pages are dirty.
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 1);
            } else {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            }
            assert_eq!(tracker.take_dirty_pages().len(), 4);
        },
    );
}

#[test]
fn prefetch_for_write_after_read_stop_at_unaccessed_forward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            // Access page 55 t prevent prefetching after this page.
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Read);
            // Access pages 51..=54.
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Read);

            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            // This should prefetch page 53.
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            // The following should prefetch only page 55 because it is the last accessed page.
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 2);
            } else {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            }
            assert_eq!(tracker.take_dirty_pages().len(), 3);
        },
    );
}

#[test]
fn prefetch_for_write_after_read_stop_at_unaccessed_backward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            // Access pages 51..=55.
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Read);

            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            // This should prefetch page 53.
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);
            // The following should prefetch only page 51 because it is the first accessed page.
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 2);
            } else {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            }
            assert_eq!(tracker.take_dirty_pages().len(), 3);
        },
    );
}

#[test]
fn prefetch_for_write_with_other_dirty_pages_forward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);

            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            // This should prefetch page 52.
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            // This should prefetch only 54, and not 55.
            sigsegv(&tracker, PageIndex::new(53), AccessKind::Write);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.num_accessed_pages(), 1 + 5);
                // Only pages 52 and 54 are speculatively dirty, other pages are dirty.
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 2);
                assert_eq!(tracker.take_dirty_pages().len(), 4);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 4);
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
                // The old signal handler considered the last writes as read.
                assert_eq!(tracker.take_dirty_pages().len(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_write_with_other_dirty_pages_backward() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);

            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            // This should prefetch page 53.
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);
            // This should prefetch only 51, and not 50.
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            if prefetching_signal_handler_available() {
                assert_eq!(tracker.num_accessed_pages(), 1 + 5);
                // Only pages 53 and 51 are speculatively dirty, other pages are dirty.
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 2);
                assert_eq!(tracker.take_dirty_pages().len(), 4);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 4);
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
                // The old signal handler considered the last writes as read.
                assert_eq!(tracker.take_dirty_pages().len(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_write_after_read_unordered() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            // The following access pattern doesn't allow for any prefetching beyond the bare minimum.
            assert_eq!(tracker.num_accessed_pages(), 0);
            let next = PageIndex::new(26);
            sigsegv(&tracker, next, AccessKind::Read);
            sigsegv(&tracker, next, AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            let next = PageIndex::new(26 + 2);
            sigsegv(&tracker, next, AccessKind::Read);
            sigsegv(&tracker, next, AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 2);
            let next = PageIndex::new(26 + 2 * 2);
            sigsegv(&tracker, next, AccessKind::Read);
            sigsegv(&tracker, next, AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 3);
            let next = PageIndex::new(26 + 3 * 2);
            sigsegv(&tracker, next, AccessKind::Read);
            sigsegv(&tracker, next, AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 4);
            // We only ever use min_prefetch_range for marking writeable, so in this case
            // this only marks the actually written pages as writeable
            assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            assert_eq!(tracker.take_dirty_pages().len(), 4);
        },
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
        static TRACKER: RefCell<Option<Box<dyn MemoryTracker>>> = const { RefCell::new(None) };
    }

    fn with_registered_handler_setup<F, G>(
        checkpoint_pages: usize,
        memory_pages: usize,
        page_delta: Vec<PageIndex>,
        dirty_page_tracking: DirtyPageTracking,
        handler_kind: MissingPageHandlerKind,
        memory_operations: F,
        final_tracker_checks: G,
    ) where
        F: FnOnce(&mut [u8], Vec<u8>),
        G: FnOnce(Box<dyn MemoryTracker>),
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
        unsafe fn new(tracker: Box<dyn MemoryTracker>) -> Self {
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

        fn take_tracker(&mut self) -> Option<Box<dyn MemoryTracker>> {
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
            handler_kind,
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
            handler_kind,
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
            handler_kind,
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
                let tracker_speculative = tracker
                    .take_speculatively_dirty_pages()
                    .into_iter()
                    .collect::<BTreeSet<_>>();
                for page in dirty_clone.borrow().iter() {
                    assert!(
                        tracker_dirty.contains(&PageIndex::new(*page as u64))
                            || tracker_speculative.contains(&PageIndex::new(*page as u64))
                    );
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
            handler_kind,
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
        /// page tracking is enabled) - Prefetching tracker.
        #[test]
        fn random_ops_result_tracking_prefetching(ops in prop::collection::vec(arb_op(PAGE_COUNT * PAGE_SIZE), 30)) {
            run_random_ops_result_tracking(ops);
        }

        /// Check that the region controlled by the signal handler behaves the
        /// same as a regular slice with respect to reads/writes (when dirty
        /// page tracking is disabled) - Prefetching tracker.
        #[test]
        fn random_ops_result_ignoring_prefetching(ops in prop::collection::vec(arb_op(PAGE_COUNT * PAGE_SIZE), 30)) {
            run_random_ops_result_ignoring(ops);
        }

        /// Check that the tracker marks every accessed/dirty page as
        /// accessed/dirty when dirty page tracking is enabled - Prefetching tracker.
        #[test]
        fn random_ops_accessed_tracking_prefetching(ops in prop::collection::vec(arb_op(PAGE_COUNT * PAGE_SIZE), 30)) {
            run_random_ops_accessed_tracking(ops);
        }

        /// Check that accessed pages are always marked as accessed when dirty
        /// page tracking is disabled - Prefetching tracker.
        #[test]
        fn random_ops_accessed_ignoring_prefetching(ops in prop::collection::vec(arb_op(PAGE_COUNT * PAGE_SIZE), 30)) {
            run_random_ops_accessed_ignoring(ops);
        }
    }
}
>>>>>>> 9569b2afa19 (feat(DSM-58): Refactoring for Deterministic Memory Tracker)
