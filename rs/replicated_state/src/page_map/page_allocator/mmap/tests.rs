use std::sync::Arc;

use crate::page_map::page_allocator::PageAllocatorInner;
use ic_sys::{PAGE_SIZE, PageIndex};

#[test]
fn test_page_validation_zero_page() {
    let page_allocator = Arc::new(PageAllocatorInner::new_for_testing());
    let contents = [0u8; PAGE_SIZE];
    let pages = PageAllocatorInner::allocate(&page_allocator, &[(PageIndex::new(0), &contents)]);
    assert_eq!(pages[0].1.0.validation.non_zero_word_index, 0);
    assert_eq!(pages[0].1.0.validation.non_zero_word_value, 0);
}

#[test]
fn test_page_validation_non_zero_first_byte() {
    let page_allocator = Arc::new(PageAllocatorInner::new_for_testing());
    let mut contents = [0u8; PAGE_SIZE];
    contents[0] = 42;
    let pages = PageAllocatorInner::allocate(&page_allocator, &[(PageIndex::new(0), &contents)]);
    assert_eq!(pages[0].1.0.validation.non_zero_word_index, 0);
    assert_eq!(pages[0].1.0.validation.non_zero_word_value, 42);
}

#[test]
fn test_page_validation_non_zero_second_byte() {
    let page_allocator = Arc::new(PageAllocatorInner::new_for_testing());
    let mut contents = [0u8; PAGE_SIZE];
    contents[1] = 42;
    let pages = PageAllocatorInner::allocate(&page_allocator, &[(PageIndex::new(0), &contents)]);
    assert_eq!(pages[0].1.0.validation.non_zero_word_index, 0);
    assert_eq!(pages[0].1.0.validation.non_zero_word_value, 42 * 256);
}

#[test]
fn test_page_validation_non_zero_last_byte() {
    let page_allocator = Arc::new(PageAllocatorInner::new_for_testing());
    let mut contents = [0u8; PAGE_SIZE];
    contents[PAGE_SIZE - 1] = 42;
    let pages = PageAllocatorInner::allocate(&page_allocator, &[(PageIndex::new(0), &contents)]);
    assert_eq!(
        pages[0].1.0.validation.non_zero_word_index,
        ((PAGE_SIZE - 1) / 2) as u16
    );
    assert_eq!(pages[0].1.0.validation.non_zero_word_value, 42 * 256);
}

#[test]
fn test_page_validation_non_zero_middle_byte() {
    let page_allocator = Arc::new(PageAllocatorInner::new_for_testing());
    let mut contents = [0u8; PAGE_SIZE];
    contents[PAGE_SIZE / 2 - 1] = 42;
    let pages = PageAllocatorInner::allocate(&page_allocator, &[(PageIndex::new(0), &contents)]);
    assert_eq!(
        pages[0].1.0.validation.non_zero_word_index,
        ((PAGE_SIZE / 2 - 1) / 2) as u16
    );
    assert_eq!(pages[0].1.0.validation.non_zero_word_value, 42 * 256);
}

#[test]
fn test_page_allocator_allocate_fastpath() {
    // Create an allocator and allocate 4 pages using the slow path.
    const N_PAGES: usize = 100;
    let page_allocator = Arc::new(PageAllocatorInner::new_for_testing());
    let contents_slow = [13u8; PAGE_SIZE * N_PAGES];
    let pages_slow = PageAllocatorInner::allocate(
        &page_allocator,
        &[
            (
                PageIndex::new(0),
                &contents_slow[0..PAGE_SIZE].try_into().unwrap(),
            ),
            (
                PageIndex::new(1),
                &contents_slow[PAGE_SIZE..2 * PAGE_SIZE].try_into().unwrap(),
            ),
            (
                PageIndex::new(2),
                &contents_slow[2 * PAGE_SIZE..3 * PAGE_SIZE]
                    .try_into()
                    .unwrap(),
            ),
            (
                PageIndex::new(3),
                &contents_slow[3 * PAGE_SIZE..4 * PAGE_SIZE]
                    .try_into()
                    .unwrap(),
            ),
        ],
    );

    // Create another allocator and allocate 4 pages using the fast path.
    let page_allocator = Arc::new(PageAllocatorInner::new_for_testing());
    let contents_fast = [13u8; PAGE_SIZE * N_PAGES];
    let pages_fast = PageAllocatorInner::allocate_fastpath(
        &page_allocator,
        &[
            (
                PageIndex::new(0),
                &contents_fast[0..PAGE_SIZE].try_into().unwrap(),
            ),
            (
                PageIndex::new(1),
                &contents_fast[PAGE_SIZE..2 * PAGE_SIZE].try_into().unwrap(),
            ),
            (
                PageIndex::new(2),
                &contents_fast[2 * PAGE_SIZE..3 * PAGE_SIZE]
                    .try_into()
                    .unwrap(),
            ),
            (
                PageIndex::new(3),
                &contents_fast[3 * PAGE_SIZE..4 * PAGE_SIZE]
                    .try_into()
                    .unwrap(),
            ),
        ],
    );

    // Check that the pages are the same.
    assert_eq!(pages_slow.len(), pages_fast.len());
    for (page_slow, page_fast) in pages_slow.iter().zip(pages_fast.iter()) {
        let contents_slow = page_slow.1.0.contents();
        let contents_fast = page_fast.1.0.contents();
        assert_eq!(contents_slow, contents_fast);
    }
}
