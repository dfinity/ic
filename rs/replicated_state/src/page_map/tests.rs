use super::{
    checkpoint::{Checkpoint, MappingSerialization},
    page_allocator::PageAllocatorSerialization,
    Buffer, FileDescriptor, PageIndex, PageMap,
};
use ic_sys::PAGE_SIZE;
use nix::unistd::dup;
use std::fs::OpenOptions;

fn assert_equal_page_maps(page_map1: &PageMap, page_map2: &PageMap) {
    assert_eq!(page_map1.num_host_pages(), page_map2.num_host_pages());
    for i in 0..page_map1.num_host_pages() {
        assert_eq!(
            page_map1.get_page(PageIndex::new(i as u64)),
            page_map2.get_page(PageIndex::new(i as u64))
        );
    }
}

#[test]
fn can_debug_display_a_page_map() {
    let page_map = PageMap::new();
    assert_eq!(format!("{:?}", page_map), "{}");
}

#[test]
fn can_create_an_empty_checkpoint() {
    let checkpoint = Checkpoint::empty();
    let empty_page = vec![0; PAGE_SIZE];
    let first_page = checkpoint.get_page(PageIndex::new(1));
    assert_eq!(&empty_page[..], first_page);
}

#[test]
fn empty_page_map_returns_zeroed_pages() {
    let page_map = PageMap::new();
    let page = page_map.get_page(PageIndex::new(1));
    assert_eq!(page.len(), PAGE_SIZE);
    assert!(page.iter().all(|b| *b == 0));
}

#[test]
fn can_update_a_page_map() {
    let mut page_map = PageMap::new();
    let ones = [1u8; PAGE_SIZE];
    let twos = [2u8; PAGE_SIZE];

    let delta = [(PageIndex::new(1), &ones), (PageIndex::new(2), &twos)];

    page_map.update(&delta);

    for (num, contents) in &[(1, 1), (2, 2), (3, 0)] {
        assert!(page_map
            .get_page(PageIndex::new(*num))
            .iter()
            .all(|b| *b == *contents));
    }
}

#[test]
fn new_delta_wins_on_update() {
    let mut page_map = PageMap::new();
    let page_1 = [1u8; PAGE_SIZE];
    let page_2 = [2u8; PAGE_SIZE];

    let pages_1 = &[(PageIndex::new(1), &page_1)];
    let pages_2 = &[(PageIndex::new(1), &page_2)];

    page_map.update(pages_1);
    page_map.update(pages_2);

    assert_eq!(page_map.get_page(PageIndex::new(1)), &page_2);
}

#[test]
fn persisted_map_is_equivalent_to_the_original() {
    let tmp = tempfile::Builder::new()
        .prefix("checkpoints")
        .tempdir()
        .unwrap();
    let heap_file = tmp.path().join("heap");

    let page_1 = [1u8; PAGE_SIZE];
    let page_3 = [3u8; PAGE_SIZE];

    let pages = &[(PageIndex::new(1), &page_1), (PageIndex::new(3), &page_3)];

    let mut original_map = PageMap::default();
    original_map.update(pages);

    original_map.persist_delta(&heap_file).unwrap();
    let persisted_map = PageMap::open(&heap_file, None).unwrap();

    assert_eq!(persisted_map, original_map);
}

#[test]
fn can_persist_and_load_an_empty_page_map() {
    let tmp = tempfile::Builder::new()
        .prefix("checkpoints")
        .tempdir()
        .unwrap();
    let heap_file = tmp.path().join("heap");

    let original_map = PageMap::default();
    original_map.persist_delta(&heap_file).unwrap();
    let persisted_map =
        PageMap::open(&heap_file, None).expect("opening an empty page map must succeed");

    assert_eq!(original_map, persisted_map);
}

#[test]
fn returns_an_error_if_file_size_is_not_a_multiple_of_page_size() {
    use std::io::Write;

    let tmp = tempfile::Builder::new()
        .prefix("checkpoints")
        .tempdir()
        .unwrap();
    let heap_file = tmp.path().join("heap");
    OpenOptions::new()
        .write(true)
        .create(true)
        .open(&heap_file)
        .unwrap()
        .write_all(&vec![1; PAGE_SIZE / 2])
        .unwrap();

    match PageMap::open(&heap_file, None) {
        Err(err) => assert!(
            err.is_invalid_heap_file(),
            "Expected invalid heap file error, got {:?}",
            err
        ),
        Ok(_) => panic!("Expected a invalid heap file error, got Ok(_)"),
    }
}

#[test]
fn can_use_buffer_to_modify_page_map() {
    let page_1 = [1u8; PAGE_SIZE];
    let page_3 = [3u8; PAGE_SIZE];
    let pages = &[(PageIndex::new(1), &page_1), (PageIndex::new(3), &page_3)];
    let mut page_map = PageMap::default();
    page_map.update(pages);

    let n = 4 * PAGE_SIZE;
    let mut vec_buf = vec![0u8; n];
    vec_buf[PAGE_SIZE..2 * PAGE_SIZE].copy_from_slice(&page_1);
    vec_buf[3 * PAGE_SIZE..4 * PAGE_SIZE].copy_from_slice(&page_3);

    let mut buf = Buffer::new(page_map);

    let mut read_buf = vec![0u8; n];

    buf.read(&mut read_buf[..], 0);
    assert_eq!(read_buf, vec_buf);

    for offset in 0..n {
        let mut len = 1;
        while (offset + len) < n {
            let b = ((offset + len) % 15) as u8;
            for dst in vec_buf.iter_mut().skip(offset).take(len) {
                *dst = b;
            }
            buf.write(&vec_buf[offset..offset + len], offset);
            buf.read(&mut read_buf[..], 0);
            assert_eq!(read_buf, vec_buf);
            len *= 2;
        }
    }
}

#[test]
fn serialize_empty_page_map() {
    let original_page_map = PageMap::default();
    let serialized_page_map = original_page_map.serialize();
    let deserialized_page_map = PageMap::deserialize(serialized_page_map).unwrap();
    assert_equal_page_maps(&original_page_map, &deserialized_page_map);
}

#[test]
fn serialize_page_map() {
    let page_1 = [1u8; PAGE_SIZE];
    let page_3 = [3u8; PAGE_SIZE];
    let page_7 = [7u8; PAGE_SIZE];
    let pages = &[(PageIndex::new(1), &page_1), (PageIndex::new(3), &page_3)];
    let mut original_page_map = PageMap::default();
    original_page_map.update(pages);
    original_page_map.strip_round_delta();
    original_page_map.update(&[(PageIndex::new(7), &page_7)]);

    let mut serialized_page_map = original_page_map.serialize();
    // Since the test runs in the same process, we need to duplicate all file
    // descriptors so that both page maps can close them.
    serialized_page_map.checkpoint.mapping =
        serialized_page_map
            .checkpoint
            .mapping
            .map(|mapping| MappingSerialization {
                file_descriptor: FileDescriptor {
                    fd: dup(mapping.file_descriptor.fd).unwrap(),
                },
                ..mapping
            });
    serialized_page_map.page_allocator = match serialized_page_map.page_allocator {
        PageAllocatorSerialization::Mmap(file_descriptor) => {
            PageAllocatorSerialization::Mmap(FileDescriptor {
                fd: dup(file_descriptor.fd).unwrap(),
            })
        }
        _ => serialized_page_map.page_allocator,
    };
    let deserialized_page_map = PageMap::deserialize(serialized_page_map).unwrap();
    assert_equal_page_maps(&original_page_map, &deserialized_page_map);
}
