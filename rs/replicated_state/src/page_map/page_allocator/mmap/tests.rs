use std::sync::Arc;

use super::MmapBasedPageAllocator;
use crate::page_map::page_allocator::PageAllocatorInner;
use ic_sys::{PageIndex, PAGE_SIZE};

#[test]
fn test_page_validation_zero_page() {
    let page_allocator = Arc::new(MmapBasedPageAllocator::default());
    let contents = [0u8; PAGE_SIZE];
    let pages =
        MmapBasedPageAllocator::allocate(&page_allocator, &[(PageIndex::new(0), &contents)]);
    assert_eq!(pages[0].1 .0.validation.non_zero_word_index, 0);
    assert_eq!(pages[0].1 .0.validation.non_zero_word_value, 0);
}

#[test]
fn test_page_validation_non_zero_first_byte() {
    let page_allocator = Arc::new(MmapBasedPageAllocator::default());
    let mut contents = [0u8; PAGE_SIZE];
    contents[0] = 42;
    let pages =
        MmapBasedPageAllocator::allocate(&page_allocator, &[(PageIndex::new(0), &contents)]);
    assert_eq!(pages[0].1 .0.validation.non_zero_word_index, 0);
    assert_eq!(pages[0].1 .0.validation.non_zero_word_value, 42);
}

#[test]
fn test_page_validation_non_zero_second_byte() {
    let page_allocator = Arc::new(MmapBasedPageAllocator::default());
    let mut contents = [0u8; PAGE_SIZE];
    contents[1] = 42;
    let pages =
        MmapBasedPageAllocator::allocate(&page_allocator, &[(PageIndex::new(0), &contents)]);
    assert_eq!(pages[0].1 .0.validation.non_zero_word_index, 0);
    assert_eq!(pages[0].1 .0.validation.non_zero_word_value, 42 * 256);
}

#[test]
fn test_page_validation_non_zero_last_byte() {
    let page_allocator = Arc::new(MmapBasedPageAllocator::default());
    let mut contents = [0u8; PAGE_SIZE];
    contents[PAGE_SIZE - 1] = 42;
    let pages =
        MmapBasedPageAllocator::allocate(&page_allocator, &[(PageIndex::new(0), &contents)]);
    assert_eq!(
        pages[0].1 .0.validation.non_zero_word_index,
        ((PAGE_SIZE - 1) / 2) as u16
    );
    assert_eq!(pages[0].1 .0.validation.non_zero_word_value, 42 * 256);
}

#[test]
fn test_page_validation_non_zero_middle_byte() {
    let page_allocator = Arc::new(MmapBasedPageAllocator::default());
    let mut contents = [0u8; PAGE_SIZE];
    contents[PAGE_SIZE / 2 - 1] = 42;
    let pages =
        MmapBasedPageAllocator::allocate(&page_allocator, &[(PageIndex::new(0), &contents)]);
    assert_eq!(
        pages[0].1 .0.validation.non_zero_word_index,
        ((PAGE_SIZE / 2 - 1) / 2) as u16
    );
    assert_eq!(pages[0].1 .0.validation.non_zero_word_value, 42 * 256);
}
