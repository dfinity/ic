use crate::page_map::{
    FileDescriptor, page_allocator::page_allocator_registry::PageAllocatorRegistry,
};

use super::{PageAllocator, PageAllocatorSerialization, PageSerialization};
use ic_sys::{PAGE_SIZE, PageIndex};
use nix::unistd::dup;

fn duplicate_file_descriptors(
    page_allocator: PageAllocatorSerialization,
) -> PageAllocatorSerialization {
    PageAllocatorSerialization {
        id: page_allocator.id,
        fd: FileDescriptor {
            fd: dup(page_allocator.fd.fd).unwrap(),
        },
    }
}

#[test]
fn test_page_allocation() {
    let page_allocator: PageAllocator = PageAllocator::new_for_testing();
    let page_0 = (PageIndex::new(0), &[0u8; PAGE_SIZE]);
    let page_1 = (PageIndex::new(1), &[1u8; PAGE_SIZE]);
    let page_2 = (PageIndex::new(2), &[2u8; PAGE_SIZE]);
    let pages = page_allocator.allocate(&[page_0, page_1, page_2]);
    assert_eq!(pages[0].0, page_0.0);
    assert_eq!(pages[0].1.contents(), page_0.1);
    assert_eq!(pages[1].0, page_1.0);
    assert_eq!(pages[1].1.contents(), page_1.1);
    assert_eq!(pages[2].0, page_2.0);
    assert_eq!(pages[2].1.contents(), page_2.1);
}

#[test]
fn test_multiple_page_allocators() {
    let page_allocator_1: PageAllocator = PageAllocator::new_for_testing();
    let page_allocator_2: PageAllocator = PageAllocator::new_for_testing();
    let page = (PageIndex::new(1), &[1u8; PAGE_SIZE]);
    let pages_1 = page_allocator_1.allocate(&[page]);
    let pages_2 = page_allocator_2.allocate(&[page]);
    assert_eq!(pages_1[0].0, page.0);
    assert_eq!(pages_1[0].1.contents(), page.1);
    assert_eq!(pages_2[0].0, page.0);
    assert_eq!(pages_2[0].1.contents(), page.1);
}

#[test]
fn test_page_serialization() {
    let page = PageSerialization {
        index: PageIndex::new(42),
        bytes: [123u8; PAGE_SIZE],
    };
    let serialized = serde_cbor::to_vec(&page).unwrap();
    let mut deserializer = serde_cbor::Deserializer::from_slice(&serialized);
    let result: PageSerialization = serde::de::Deserialize::deserialize(&mut deserializer).unwrap();
    assert_eq!(page.index, result.index);
    assert_eq!(page.bytes, result.bytes);
}

#[test]
fn test_page_deserialize_twice() {
    let registry = PageAllocatorRegistry::new();
    let page_allocator: PageAllocator = PageAllocator::new_for_testing();
    let page = (PageIndex::new(1), &[1u8; PAGE_SIZE]);
    page_allocator.allocate(&[page]);

    let serialized1 = duplicate_file_descriptors(page_allocator.serialize());
    let serialized2 = duplicate_file_descriptors(page_allocator.serialize());

    let deserialized1 = PageAllocator::deserialize(serialized1, &registry);
    let deserialized2 = PageAllocator::deserialize(serialized2, &registry);

    assert_eq!(deserialized1.serialize().id, deserialized2.serialize().id);
    assert_eq!(
        deserialized1.serialize().fd.fd,
        deserialized2.serialize().fd.fd
    );
}
