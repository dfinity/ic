use std::{io::Write, ops::Range};

use ic_logger::replica_logger::no_op_logger;
use ic_replicated_state::{
    page_map::{test_utils::base_only_storage_layout, TestPageAllocatorFileDescriptorImpl},
    PageIndex, PageMap,
};
use ic_sys::{PageBytes, PAGE_SIZE};
use ic_types::Height;
use libc::c_void;
use nix::sys::mman::{mmap, MapFlags, ProtFlags};
use std::sync::Arc;

use crate::{
    new_signal_handler_available, AccessKind, DirtyPageTracking, PageBitmap, SigsegvMemoryTracker,
    MAX_PAGES_TO_MAP,
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
        &base_only_storage_layout(tmpfile.path().to_path_buf()),
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
        memory_pages * PAGE_SIZE,
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

#[test]
fn prefetch_for_read_checkpoint() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(5), AccessKind::Read);
            if new_signal_handler_available() {
                // There are no dirty pages so no prefetching
                assert_eq!(tracker.num_accessed_pages(), MAX_PAGES_TO_MAP.min(20));
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
        },
    );
}

#[test]
fn prefetch_for_read_zeros() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(80), AccessKind::Read);
            if new_signal_handler_available() {
                // We prefetch to the end of the memory region at most
                assert_eq!(tracker.num_accessed_pages(), MAX_PAGES_TO_MAP.min(20));
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
            if new_signal_handler_available() {
                // Deltas start at 25, and we prefetch until we have MAX_MEMORY_INSTRUCTIONS deltas
                assert_eq!(tracker.num_accessed_pages(), 5);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 1);
            }
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Read);
            if new_signal_handler_available() {
                // There are no accessed pages immediately before the faulting page, so we fetch until
                // we have another MAX_MEMORY_INSTRUCTIONS deltas
                assert_eq!(tracker.num_accessed_pages(), 6);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 2);
            }
        },
    );
}

#[test]
fn prefetch_for_read_page_delta_contiguous() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(25), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(26), AccessKind::Read);
            if new_signal_handler_available() {
                assert_eq!(tracker.num_accessed_pages(), 2 + 1);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 2);
            }
            sigsegv(&tracker, PageIndex::new(25 + 2 + 1), AccessKind::Read);
            if new_signal_handler_available() {
                // Because the previous 2*MAX_MEMORY_INSTRUCTIONS + 1 pages have been accessed, we prefetch at least that much again, plus 1 for the actually acced page
                assert_eq!(tracker.num_accessed_pages(), 2 * (2 + 1) + 1);
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
            if new_signal_handler_available() {
                // Prefetch until we have MAX_MEMORY_INSTRUCTIONS deltas
                assert_eq!(tracker.num_accessed_pages(), MAX_PAGES_TO_MAP.min(20));
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
            if new_signal_handler_available() {
                // There are no dirty pages so no prefetching to the end of the memory
                assert_eq!(tracker.num_accessed_pages(), MAX_PAGES_TO_MAP.min(20));
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
            if new_signal_handler_available() {
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
            if new_signal_handler_available() {
                // MAX_MEMORY_INSTRUCTIONS pages were accessed immediately before the faulting page, so that many additional
                // pages should be prefetched.
                let prefetched = MAX_PAGES_TO_MAP.min(1 + 1);
                assert_eq!(tracker.num_accessed_pages(), 1 + prefetched);
                sigsegv(
                    &tracker,
                    PageIndex::new((50 + 1 + prefetched) as u64),
                    AccessKind::Write,
                );
                let prefetched_at_last = MAX_PAGES_TO_MAP.min(1 + prefetched + 1);
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
            if new_signal_handler_available() {
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
            if new_signal_handler_available() {
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
            if new_signal_handler_available() {
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
            if new_signal_handler_available() {
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
            if new_signal_handler_available() {
                let prefetched_at_51 = std::cmp::min(2, MAX_PAGES_TO_MAP);
                assert_eq!(tracker.num_accessed_pages(), 1 + prefetched_at_51);
                sigsegv(
                    &tracker,
                    PageIndex::new(51 + prefetched_at_51 as u64),
                    AccessKind::Write,
                );
                let prefetched_at_last = std::cmp::min(1 + prefetched_at_51 + 1, MAX_PAGES_TO_MAP);
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
fn prefetch_for_write_after_read_stop_at_dirty() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            // Access the pages in the reverse order to prevent prefetching for reading.
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 2);
            sigsegv(&tracker, PageIndex::new(53), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 3);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 4);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 5);
            // Write to the last page to set it as the boundary for write prefetching.
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            // Page 53 should be prefetched now.
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);
            if new_signal_handler_available() {
                // Only page 53 is speculatively dirty, other pages are dirty.
                assert_eq!(
                    tracker.take_speculatively_dirty_pages().len(),
                    MAX_PAGES_TO_MAP.min(2) - 1
                );
            } else {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            }
            assert_eq!(tracker.take_dirty_pages().len(), 4);
        },
    );
}

#[test]
fn prefetch_for_write_after_read_stop_at_unaccessed() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            // Access the pages in the reverse order to prevent prefetching for reading.
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 2);
            sigsegv(&tracker, PageIndex::new(53), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 3);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 4);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 5);

            let last_accessed = 55;

            // Write to some pages in the reverse order to prevent prefetching for writing.
            sigsegv(
                &tracker,
                PageIndex::new(last_accessed - 2),
                AccessKind::Write,
            );
            sigsegv(
                &tracker,
                PageIndex::new(last_accessed - 3),
                AccessKind::Write,
            );
            sigsegv(
                &tracker,
                PageIndex::new(last_accessed - 4),
                AccessKind::Write,
            );
            // The following should prefetch only last_accessed because it is the last accessed page.
            sigsegv(
                &tracker,
                PageIndex::new(last_accessed - 1),
                AccessKind::Write,
            );
            if new_signal_handler_available() {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 1);
            } else {
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            }
            assert_eq!(tracker.take_dirty_pages().len(), 4);
        },
    );
}

#[test]
fn prefetch_for_write_with_other_dirty_pages() {
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

            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 2);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 3);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 4);
            // This should prefetch only 54, and not 55.
            sigsegv(&tracker, PageIndex::new(53), AccessKind::Write);
            if new_signal_handler_available() {
                assert_eq!(tracker.num_accessed_pages(), 1 + 5);
                // Only page 54 is speculatively dirty, other pages are dirty.
                assert_eq!(
                    tracker.take_speculatively_dirty_pages().len(),
                    MAX_PAGES_TO_MAP.min(2) - 1
                );
                assert_eq!(tracker.take_dirty_pages().len(), 5);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 5);
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
            let next = PageIndex::new(25);
            sigsegv(&tracker, next, AccessKind::Read);
            sigsegv(&tracker, next, AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            let next = PageIndex::new(25 + 2);
            sigsegv(&tracker, next, AccessKind::Read);
            sigsegv(&tracker, next, AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 2);
            let next = PageIndex::new(25 + 2 * 2);
            sigsegv(&tracker, next, AccessKind::Read);
            sigsegv(&tracker, next, AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 3);
            let next = PageIndex::new(25 + 3 * 2);
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

#[test]
fn page_bitmap_restrict_to_unaccessed() {
    let mut bitmap = PageBitmap::new(10);
    bitmap.mark(PageIndex::new(5));
    assert_eq!(
        Range {
            start: PageIndex::new(0),
            end: PageIndex::new(5),
        },
        bitmap.restrict_range_to_unmarked(bitmap.page_range()),
    );
    assert_eq!(
        Range {
            start: PageIndex::new(5),
            end: PageIndex::new(5),
        },
        bitmap.restrict_range_to_unmarked(Range {
            start: PageIndex::new(5),
            end: PageIndex::new(15)
        }),
    );
    assert_eq!(
        Range {
            start: PageIndex::new(6),
            end: PageIndex::new(10),
        },
        bitmap.restrict_range_to_unmarked(Range {
            start: PageIndex::new(6),
            end: PageIndex::new(15)
        }),
    );
}

#[test]
fn page_bitmap_restrict_to_predicted() {
    let mut bitmap = PageBitmap::new(10);
    bitmap.mark(PageIndex::new(5));
    assert_eq!(
        Range {
            start: PageIndex::new(0),
            end: PageIndex::new(1),
        },
        bitmap.restrict_range_to_predicted(bitmap.page_range()),
    );
    assert_eq!(
        Range {
            start: PageIndex::new(5),
            end: PageIndex::new(6),
        },
        bitmap.restrict_range_to_predicted(Range {
            start: PageIndex::new(5),
            end: PageIndex::new(15)
        }),
    );
    assert_eq!(
        Range {
            start: PageIndex::new(6),
            end: PageIndex::new(8),
        },
        bitmap.restrict_range_to_predicted(Range {
            start: PageIndex::new(6),
            end: PageIndex::new(15)
        }),
    );
}

#[test]
fn page_bitmap_restrict_to_predicted_stops_at_end() {
    let mut bitmap = PageBitmap::new(10);
    bitmap.mark(PageIndex::new(0));
    bitmap.mark(PageIndex::new(1));
    bitmap.mark(PageIndex::new(2));
    bitmap.mark(PageIndex::new(3));
    bitmap.mark(PageIndex::new(4));
    bitmap.mark(PageIndex::new(5));
    assert_eq!(
        Range {
            start: PageIndex::new(6),
            end: PageIndex::new(10),
        },
        bitmap.restrict_range_to_predicted(Range {
            start: PageIndex::new(6),
            end: PageIndex::new(15)
        }),
    );
}

#[test]
fn page_bitmap_restrict_to_predicted_stops_at_start() {
    let mut bitmap = PageBitmap::new(10);
    bitmap.mark(PageIndex::new(0));
    bitmap.mark(PageIndex::new(1));
    bitmap.mark(PageIndex::new(2));
    assert_eq!(
        Range {
            start: PageIndex::new(3),
            end: PageIndex::new(6),
        },
        bitmap.restrict_range_to_predicted(Range {
            start: PageIndex::new(3),
            end: PageIndex::new(15)
        }),
    );
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod random_ops {
    use crate::signal_access_kind_and_address;

    use super::*;

    use std::{
        cell::RefCell,
        collections::BTreeSet,
        io,
        mem::{self, MaybeUninit},
        rc::Rc,
    };

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

    static mut PREV_SIGSEGV: MaybeUninit<libc::sigaction> = MaybeUninit::uninit();

    struct RegisteredHandler();

    impl RegisteredHandler {
        unsafe fn new(tracker: SigsegvMemoryTracker) -> Self {
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
            if libc::sigaction(libc::SIGSEGV, &handler, PREV_SIGSEGV.as_mut_ptr()) != 0 {
                panic!(
                    "unable to install signal handler: {}",
                    io::Error::last_os_error(),
                );
            }

            RegisteredHandler()
        }

        fn take_tracker(&mut self) -> Option<SigsegvMemoryTracker> {
            TRACKER.with(|cell| {
                let previous = cell.replace(None);
                unsafe {
                    if libc::sigaction(libc::SIGSEGV, PREV_SIGSEGV.as_ptr(), std::ptr::null_mut())
                        != 0
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

    extern "C" fn sigsegv_handler(
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
                    let previous = *PREV_SIGSEGV.as_ptr();
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
