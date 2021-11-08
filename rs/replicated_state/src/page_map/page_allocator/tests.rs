use super::PageAllocator;
use ic_sys::{PageIndex, PAGE_SIZE};

#[test]
fn test_page_allocation() {
    let mut page_allocator = PageAllocator::default();
    let page_0 = (PageIndex::new(0), &[0u8; PAGE_SIZE]);
    let page_1 = (PageIndex::new(1), &[1u8; PAGE_SIZE]);
    let page_2 = (PageIndex::new(2), &[2u8; PAGE_SIZE]);
    let pages = page_allocator.allocate(&[page_0, page_1, page_2]);
    assert_eq!(pages[0].0, page_0.0);
    assert_eq!(pages[0].1.contents(&page_allocator), page_0.1);
    assert_eq!(pages[1].0, page_1.0);
    assert_eq!(pages[1].1.contents(&page_allocator), page_1.1);
    assert_eq!(pages[2].0, page_2.0);
    assert_eq!(pages[2].1.contents(&page_allocator), page_2.1);
}

#[test]
fn test_multiple_page_allocators() {
    let mut page_allocator_1 = PageAllocator::default();
    let mut page_allocator_2 = PageAllocator::default();
    let page = (PageIndex::new(1), &[1u8; PAGE_SIZE]);
    let pages_1 = page_allocator_1.allocate(&[page]);
    let pages_2 = page_allocator_2.allocate(&[page]);
    assert_eq!(pages_1[0].0, page.0);
    assert_eq!(pages_1[0].1.contents(&page_allocator_1), page.1);
    assert_eq!(pages_2[0].0, page.0);
    assert_eq!(pages_2[0].1.contents(&page_allocator_2), page.1);
}
