use std::{io::Write, ops::Range};

use ic_config::embedders::PersistenceType;
use ic_logger::replica_logger::no_op_logger;
use ic_replicated_state::{PageIndex, PageMap};
use ic_sys::{PageBytes, PAGE_SIZE};
use libc::c_void;
use nix::sys::mman::{mmap, MapFlags, ProtFlags};

use crate::{
    new_signal_handler_available, AccessKind, DirtyPageTracking, PageBitmap, SigsegvMemoryTracker,
    MAX_PAGES_TO_COPY, MAX_PAGES_TO_MAP,
};

fn with_setup<F>(
    checkpoint_pages: usize,
    memory_pages: usize,
    page_delta: Vec<PageIndex>,
    dirty_page_tracking: DirtyPageTracking,
    f: F,
) where
    F: FnOnce(SigsegvMemoryTracker, PageMap),
{
    let tmpfile = tempfile::Builder::new().prefix("test").tempfile().unwrap();
    for page in 0..checkpoint_pages {
        tmpfile
            .as_file()
            .write_all(&[(page % 256) as u8; PAGE_SIZE])
            .unwrap();
    }
    tmpfile.as_file().sync_all().unwrap();
    let mut page_map = PageMap::open(tmpfile.path(), None).unwrap();
    let pages: Vec<(PageIndex, PageBytes)> = page_delta
        .into_iter()
        .map(|i| (i, [i.get() as u8; PAGE_SIZE]))
        .collect();
    let pages: Vec<(PageIndex, &PageBytes)> = pages.iter().map(|(i, a)| (*i, a)).collect();
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
        PersistenceType::Sigsegv,
        memory,
        memory_pages * PAGE_SIZE,
        no_op_logger(),
        dirty_page_tracking,
        Some(page_map.clone()),
    )
    .unwrap();
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
                // The checkpoint range is [0..25). Starting from 5 there are only 20 pages.
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
                // The zero range is [75..100). Starting from 80, there are only 20 pages.
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
            // There are no accessed pages immediately before the faulting page.
            // So only the faulting page should be fetched.
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
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Read);
            // There are no accessed pages immediately before the faulting page.
            // So only the faulting page should be fetched.
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            // There are no accessed pages immediately before the faulting page.
            // So only the faulting page should be fetched.
            assert_eq!(tracker.num_accessed_pages(), 2);
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
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            if new_signal_handler_available() {
                // One page was accessed immediately before the faulting page, so one additional
                // page should be prefetched.
                let prefetched_at_51 = MAX_PAGES_TO_COPY.min(2);
                assert_eq!(tracker.num_accessed_pages(), 1 + prefetched_at_51);
                sigsegv(
                    &tracker,
                    PageIndex::new(51 + prefetched_at_51 as u64),
                    AccessKind::Read,
                );
                let prefetched_at_last = MAX_PAGES_TO_COPY.min(1 + prefetched_at_51 + 1);
                assert_eq!(
                    tracker.num_accessed_pages(),
                    1 + prefetched_at_51 + prefetched_at_last
                );
            } else {
                // The old signal handler does not have prefetching.
                assert_eq!(tracker.num_accessed_pages(), 2);
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
                // The checkpoint range is [0..25). Starting from 5 there are only 20 pages.
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
                // The zero range is [75..100). Starting from 80, there are only 20 pages.
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
            // So only the faulting page should be fetched.
            assert_eq!(tracker.num_accessed_pages(), 1);
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
            // There are no accessed pages immediately before the faulting page.
            // So only the faulting page should be fetched.
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            // There are no accessed pages immediately before the faulting page.
            // So only the faulting page should be fetched.
            assert_eq!(tracker.num_accessed_pages(), 2);
        },
    );
}

#[test]
fn prefetch_for_write_page_delta_contiguous_ignore_dirty() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Ignore,
        |tracker, _| {
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(50), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            if new_signal_handler_available() {
                // One page was accessed immediately before the faulting page, so one additional
                // page should be prefetched.
                let prefetched_at_51 = MAX_PAGES_TO_COPY.min(2);
                assert_eq!(tracker.num_accessed_pages(), 1 + prefetched_at_51);
                sigsegv(
                    &tracker,
                    PageIndex::new(51 + prefetched_at_51 as u64),
                    AccessKind::Write,
                );
                let prefetched_at_last = MAX_PAGES_TO_COPY.min(1 + prefetched_at_51 + 1);
                assert_eq!(
                    tracker.num_accessed_pages(),
                    1 + prefetched_at_51 + prefetched_at_last
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
                let prefetched_at_51 = std::cmp::min(2, MAX_PAGES_TO_COPY);
                assert_eq!(tracker.num_accessed_pages(), 1 + prefetched_at_51);
                sigsegv(
                    &tracker,
                    PageIndex::new(51 + prefetched_at_51 as u64),
                    AccessKind::Write,
                );
                let prefetched_at_last = std::cmp::min(1 + prefetched_at_51 + 1, MAX_PAGES_TO_COPY);
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
                    MAX_PAGES_TO_COPY.min(2) - 1
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
            // Write to 51 - 53 in the reverse order to prevent prefetching for writing.
            sigsegv(&tracker, PageIndex::new(53), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            // The following should prefetch only 55 because it is the last accessed page.
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);
            if new_signal_handler_available() {
                assert_eq!(
                    tracker.take_speculatively_dirty_pages().len(),
                    MAX_PAGES_TO_COPY.min(2) - 1
                );
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
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 2);
            // Set up page 55 as the boundary for prefetching.
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 3);
            // This should prefetch only 54, and not 55.
            sigsegv(&tracker, PageIndex::new(53), AccessKind::Write);
            if new_signal_handler_available() {
                assert_eq!(tracker.num_accessed_pages(), 3 + MAX_PAGES_TO_COPY.min(2));
                // Only page 55 is speculatively dirty, other pages are dirty.
                assert_eq!(
                    tracker.take_speculatively_dirty_pages().len(),
                    MAX_PAGES_TO_COPY.min(2) - 1
                );
                assert_eq!(tracker.take_dirty_pages().len(), 4);
            } else {
                assert_eq!(tracker.num_accessed_pages(), 4);
                assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
                // The old signal handler considered the last write as read.
                assert_eq!(tracker.take_dirty_pages().len(), 3);
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
            // The follow access pattern doesn't allow for any prefetching.
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(53), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(53), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 2);
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 3);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 4);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Read);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);
            assert_eq!(tracker.num_accessed_pages(), 5);
            assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            assert_eq!(tracker.take_dirty_pages().len(), 5);
        },
    );
}

#[test]
fn prefetch_for_writes_after_reads_unordered() {
    with_setup(
        50,
        100,
        (25..75).map(PageIndex::new).collect(),
        DirtyPageTracking::Track,
        |tracker, _| {
            // The follow access pattern doesn't allow for any prefetching.
            assert_eq!(tracker.num_accessed_pages(), 0);
            sigsegv(&tracker, PageIndex::new(51), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 1);
            sigsegv(&tracker, PageIndex::new(53), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 2);
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 3);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 4);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Read);
            assert_eq!(tracker.num_accessed_pages(), 5);

            sigsegv(&tracker, PageIndex::new(51), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(53), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(55), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(52), AccessKind::Write);
            sigsegv(&tracker, PageIndex::new(54), AccessKind::Write);

            assert_eq!(tracker.take_speculatively_dirty_pages().len(), 0);
            assert_eq!(tracker.take_dirty_pages().len(), 5);
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
