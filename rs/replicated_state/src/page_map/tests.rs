use super::{allocate_pages, checkpoint::Checkpoint, Buffer, PageDelta, PageIndex, PageMap};
use ic_sys::PAGE_SIZE;
use std::fs::OpenOptions;

#[test]
fn can_debug_display_a_page_map() {
    let page_map = PageMap::new();
    assert_eq!(format!("{:?}", page_map), "{}");
}

#[test]
fn can_create_an_empty_checkpoint() {
    let checkpoint = Checkpoint::empty();
    let empty_page = vec![0; *PAGE_SIZE];
    let first_page = checkpoint.get_page(PageIndex::from(1));
    assert_eq!(&empty_page[..], first_page);
}

#[test]
fn empty_page_map_returns_zeroed_pages() {
    let page_map = PageMap::new();
    let page = page_map.get_page(PageIndex::from(1));
    assert_eq!(page.len(), *PAGE_SIZE);
    assert!(page.iter().all(|b| *b == 0));
}

#[test]
fn can_update_a_page_map() {
    let mut page_map = PageMap::new();
    let ones = vec![1u8; *PAGE_SIZE];
    let twos = vec![2u8; *PAGE_SIZE];

    let delta = PageDelta::from(
        &[
            (PageIndex::from(1), &ones[..]),
            (PageIndex::from(2), &twos[..]),
        ][..],
    );

    page_map.update(delta);

    for (num, contents) in &[(1, 1), (2, 2), (3, 0)] {
        assert!(page_map
            .get_page(PageIndex::from(*num))
            .iter()
            .all(|b| *b == *contents));
    }
}

#[test]
fn can_allocate_pages() {
    let page = vec![5; *PAGE_SIZE];
    let tracked_pages = allocate_pages(&[&page[..]]);
    assert_eq!(tracked_pages.len(), 1);
    assert_eq!(tracked_pages[0].contents(), page.as_slice());
}

#[test]
fn can_make_page_deltas() {
    let page = vec![5u8; *PAGE_SIZE];
    let page_delta = PageDelta::from(&[(PageIndex::from(5), &page[..])][..]);
    assert_eq!(page_delta.len(), 1);
    assert_eq!(page_delta.get_page(PageIndex::from(5)).unwrap(), &page[..])
}

#[test]
fn left_delta_wins_in_extend() {
    let page_1 = vec![1u8; *PAGE_SIZE];
    let page_2 = vec![2u8; *PAGE_SIZE];

    let delta_1 = PageDelta::from(&[(PageIndex::from(1), &page_1[..])][..]);
    let delta_2 = PageDelta::from(&[(PageIndex::from(1), &page_2[..])][..]);

    let union_12 = delta_1.extend(delta_2);

    assert_eq!(union_12.len(), 1);
    assert_eq!(union_12.get_page(PageIndex::from(1)).unwrap(), &page_1[..]);
}

#[test]
fn persisted_map_is_equivalent_to_the_original() {
    let tmp = tempfile::Builder::new()
        .prefix("checkpoints")
        .tempdir()
        .unwrap();
    let heap_file = tmp.path().join("heap");

    let page_1 = vec![1u8; *PAGE_SIZE];
    let page_3 = vec![3u8; *PAGE_SIZE];

    let delta = PageDelta::from(
        &[
            (PageIndex::from(1), &page_1[..]),
            (PageIndex::from(3), &page_3[..]),
        ][..],
    );

    let mut original_map = PageMap::default();
    original_map.update(delta);

    original_map.persist_delta(&heap_file).unwrap();
    let persisted_map = PageMap::open(&heap_file).unwrap();

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
    let persisted_map = PageMap::open(&heap_file).expect("opening an empty page map must succeed");

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
        .write_all(&vec![1; *PAGE_SIZE / 2])
        .unwrap();

    match PageMap::open(&heap_file) {
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
    let page_1 = vec![1u8; *PAGE_SIZE];
    let page_3 = vec![3u8; *PAGE_SIZE];
    let delta = PageDelta::from(
        &[
            (PageIndex::from(1), &page_1[..]),
            (PageIndex::from(3), &page_3[..]),
        ][..],
    );
    let mut page_map = PageMap::default();
    page_map.update(delta);

    let n = 4 * *PAGE_SIZE;
    let mut vec_buf = vec![0u8; n];
    vec_buf[*PAGE_SIZE..2 * *PAGE_SIZE].copy_from_slice(&page_1);
    vec_buf[3 * *PAGE_SIZE..4 * *PAGE_SIZE].copy_from_slice(&page_3);

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
